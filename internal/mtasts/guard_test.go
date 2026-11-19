package mtasts

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// A line, a policy file weaker than it and one equal to it.
const (
	grdLine = "mta-sts enforce 604800 mail.corp.test."
	grdWeak = "version: STSv1\nmode: testing\nmx: mail.corp.test\nmax_age: 604800\n"
	grdSame = "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmax_age: 604800\n"
)

func grdPrefixes(s ...string) []netip.Prefix {
	var ps []netip.Prefix
	for _, x := range s {
		ps = append(ps, netip.MustParsePrefix(x))
	}
	return ps
}

// grdServe is mtsServe on ip and port ("0": any port), with the certificate
// of cfg (nil: that of httptest); a nil h serves grdSame. It gives nil when
// nothing can listen there, as on a host without IPv6.
func grdServe(t *testing.T, ip, port string, cfg *tls.Config, h http.HandlerFunc) *mtsServer {
	t.Helper()
	l, err := net.Listen("tcp", net.JoinHostPort(ip, port))
	if err != nil {
		return nil
	}
	if h == nil {
		h = func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, grdSame) }
	}
	s := &mtsServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		h(w, r)
	}))
	_ = s.Listener.Close()
	s.Listener = l
	s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	// Refused handshakes are the point of some rows; their log is noise.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = cfg
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

func grdMustServe(t *testing.T, ip, port string, cfg *tls.Config, h http.HandlerFunc) *mtsServer {
	t.Helper()
	s := grdServe(t, ip, port, cfg, h)
	if s == nil {
		t.Fatalf("cannot listen on %s port %s", ip, port)
	}
	return s
}

func grdPort(s *mtsServer) string {
	_, port, _ := net.SplitHostPort(s.Listener.Addr().String())
	return port
}

// grdURL is the policy URL at host and port; an IPv6 host gets brackets.
func grdURL(host, port string) string {
	return "https://" + net.JoinHostPort(host, port) + "/.well-known/mta-sts.txt"
}

// grdFetch fetches the policy of corp.test. from rawURL with the extra
// ranges given.
func grdFetch(t *testing.T, rawURL string, extra []netip.Prefix, roots *x509.CertPool) obs.Answer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	return fetch(ctx, mtsKey(t, mtsName(t, "corp.test.")), extra, roots, func(string) string { return rawURL }, time.Now)
}

// grdWantRefused: the failure of a host with no permitted address, which
// names the first refused address and nothing else, with nothing sent and
// no address in the proof.
func grdWantRefused(t *testing.T, name string, a obs.Answer, first string) {
	t.Helper()
	mtsWantFailure(t, name, a, obs.ReasonNotPermitted, "network: no permitted address ("+first+")")
	if !a.Sent.IsZero() || a.Received.IsZero() || a.Server.Addr.IsValid() || !a.Server.Name.Equal(mtsName(t, "mta-sts.corp.test.")) {
		t.Errorf("%s: sent %v, received %v, server %v %v; want nothing sent, a time of the end, the policy host and no address",
			name, a.Sent, a.Received, a.Server.Name, a.Server.Addr)
	}
}

// grdFirst is the first address that host leads to, as the fetch looks it
// up, in the form that a refusal names.
func grdFirst(t *testing.T, host string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil || len(addrs) == 0 {
		t.Fatalf("%s has no address here: %v", host, err)
	}
	return addrs[0].Unmap().String()
}

func grdConns(servers ...*mtsServer) int64 {
	var n int64
	for _, s := range servers {
		if s != nil {
			n += s.conns.Load()
		}
	}
	return n
}

// Each address that a DNS check would not ask is refused before any
// connection, and the failure names the first refused address in the form
// that is dialled. Where a listener can stand at the address, it counts zero
// connections, and the same fetch under an extra range that holds the
// address reaches it, so the zero is not that of a listener out of reach.
func TestGrdRefusedHostsGetNoConnection(t *testing.T) {
	for _, r := range []struct {
		name, host string
		first      string         // the address that the failure names
		at         []string       // where a connection to host lands
		reach      []netip.Prefix // an extra range under which the fetch reaches host
	}{
		{"127.0.0.1", "127.0.0.1", "127.0.0.1", []string{"127.0.0.1"}, grdPrefixes("127.0.0.1/32")},
		{"another address of 127/8", "127.45.6.7", "127.45.6.7", []string{"127.45.6.7"}, grdPrefixes("127.45.6.7/32")},
		{"localhost", "localhost", grdFirst(t, "localhost"), []string{"127.0.0.1", "::1"}, grdPrefixes("127.0.0.0/8", "::1/128")},
		{"::1", "::1", "::1", []string{"::1"}, grdPrefixes("::1/128")},
		{"0.0.0.0, which is this machine", "0.0.0.0", "0.0.0.0", []string{"127.0.0.1"}, grdPrefixes("0.0.0.0/32")},
		// A lookup of :: gives :: and then 0.0.0.0.
		{"::, which is this machine", "::", "::", []string{"::1"}, grdPrefixes("::/128")},
		{"IPv4-mapped loopback", "::ffff:127.0.0.1", "127.0.0.1", []string{"127.0.0.1"}, grdPrefixes("127.0.0.0/8")},
	} {
		var traps []*mtsServer
		port := "0"
		for _, ip := range r.at {
			if s := grdServe(t, ip, port, nil, nil); s != nil {
				traps = append(traps, s)
				port = grdPort(s)
			}
		}
		if len(traps) == 0 {
			// Nothing listens, so a dial would fail with another text: the
			// text of the refusal shows that no dial was tried.
			t.Logf("%s: nothing can listen at %v here; only the failure is checked", r.name, r.at)
			grdWantRefused(t, r.name, grdFetch(t, grdURL(r.host, "443"), nil, nil), r.first)
			continue
		}
		grdWantRefused(t, r.name, grdFetch(t, grdURL(r.host, port), nil, nil), r.first)
		if n := grdConns(traps...); n != 0 {
			t.Errorf("%s: the listeners at %v got %d connections; want none", r.name, r.at, n)
		}
		grdFetch(t, grdURL(r.host, port), r.reach, nil)
		if grdConns(traps...) == 0 {
			t.Errorf("%s: under the extra range %v no listener at %v was reached, so the zero above proves nothing", r.name, r.reach, r.at)
		}
	}

	// No listener can stand at these addresses. Without a network a dial to
	// one fails at once with another text, so the text of the refusal shows
	// that no dial was tried. It names an IPv4-mapped address in its IPv4
	// form, which is where a dial would go.
	for _, s := range []string{
		"10.0.0.1", "10.255.255.255", "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255",
		"169.254.169.254", "169.254.0.1", "168.63.129.16", "100.64.0.1", "100.127.255.255", "224.0.0.1", "239.255.255.250",
		"255.255.255.255", "192.0.2.1", "198.51.100.7", "203.0.113.9", "2001:db8::1", "fc00::1", "fd12:3456::1",
		"fe80::1", "ff02::1", "::ffff:10.0.0.1", "::ffff:169.254.169.254", "64:ff9b::a9fe:a9fe", "2002:a9fe:a9fe::1",
	} {
		a := netip.MustParseAddr(s)
		if observe.Permitted(a, nil) || observe.Permitted(a.Unmap(), nil) {
			t.Errorf("%s is permitted", s)
		}
		grdWantRefused(t, s, grdFetch(t, grdURL(s, "443"), nil, nil), a.Unmap().String())
	}

	// An address with a zone is refused with its URL, before any lookup, and
	// no extra range permits it.
	zoned := netip.MustParseAddr("fe80::1%lo")
	if observe.Permitted(zoned, grdPrefixes("fe80::/10")) {
		t.Errorf("%v is permitted by fe80::/10", zoned)
	}
	a := grdFetch(t, "https://[fe80::1%25lo]:443/.well-known/mta-sts.txt", grdPrefixes("fe80::/10"), nil)
	mtsWantFailure(t, "a zone", a, obs.ReasonNotPermitted, mtsBadURL)
	if !a.Sent.IsZero() {
		t.Errorf("a zone: sent at %v; want nothing sent", a.Sent)
	}
}

// An extra range permits exactly its own addresses: the lab reaches its
// policy host on loopback that way, and nothing outside the range opens.
func TestGrdExtraRanges(t *testing.T) {
	srv := grdMustServe(t, "127.0.0.1", "0", nil, nil)
	port := grdPort(srv)
	next := grdMustServe(t, "127.0.0.2", port, nil, nil)
	for _, r := range []struct {
		name, host string
		extra      []netip.Prefix
		reach      bool
	}{
		{"the lab: loopback", "127.0.0.1", grdPrefixes("127.0.0.0/8"), true},
		{"loopback of both families", "127.0.0.1", mtsLoopback, true},
		{"exactly the address", "127.0.0.1", grdPrefixes("127.0.0.1/32"), true},
		{"the next address", "127.0.0.2", grdPrefixes("127.0.0.1/32"), false},
		{"the address before", "127.0.0.1", grdPrefixes("127.0.0.2/32"), false},
		{"a lab range elsewhere", "127.0.0.1", grdPrefixes("10.53.7.0/24"), false},
		{"IPv6 loopback only", "127.0.0.1", grdPrefixes("::1/128"), false},
		{"an empty list", "127.0.0.1", []netip.Prefix{}, false},
		{"no list", "127.0.0.1", nil, false},
	} {
		before, requests := grdConns(srv, next), srv.requests.Load()
		a := grdFetch(t, grdURL(r.host, port), r.extra, srv.pool())
		if r.reach {
			if s := mtsMatch(a.Result); s.which != "records" || srv.requests.Load() != requests+1 {
				t.Errorf("%s: %s %+v; want the policy file of the server", r.name, s.which, s.failure)
			}
			continue
		}
		grdWantRefused(t, r.name, a, r.host)
		if n := grdConns(srv, next) - before; n != 0 {
			t.Errorf("%s: %d connections; want none", r.name, n)
		}
	}
}

// localhost has an address of each family. Under an extra range of one
// family only that address gets a connection, whatever order the resolver
// gives; with no range neither does.
func TestGrdMixedHostUnderTheRule(t *testing.T) {
	ca := mtsNewCA(t)
	cfg := ca.leaf(t, time.Now().Add(time.Hour), []string{"localhost"})
	v4 := grdMustServe(t, "127.0.0.1", "0", cfg, nil)
	port := grdPort(v4)
	v6 := grdServe(t, "::1", port, cfg, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", "localhost")
	has6 := v6 != nil && err == nil && slices.Contains(addrs, netip.IPv6Loopback())
	t.Logf("localhost is %v here (%v); a listener on ::1: %v", addrs, err, v6 != nil)
	var only6 *mtsServer
	if has6 {
		only6 = v6
	}
	for _, r := range []struct {
		name  string
		extra []netip.Prefix
		to    *mtsServer // nil: refused
	}{
		{"IPv4 loopback permitted", grdPrefixes("127.0.0.0/8"), v4},
		{"IPv6 loopback permitted", grdPrefixes("::1/128"), only6},
		{"no range", nil, nil},
	} {
		before := map[*mtsServer]int64{v4: v4.conns.Load()}
		if v6 != nil {
			before[v6] = v6.conns.Load()
		}
		a := grdFetch(t, grdURL("localhost", port), r.extra, ca.pool)
		if r.to == nil {
			grdWantRefused(t, r.name, a, grdFirst(t, "localhost"))
		} else if s := mtsMatch(a.Result); s.which != "records" {
			t.Errorf("%s: %s %+v; want the policy file", r.name, s.which, s.failure)
		}
		for s, n := range before {
			want := n
			if s == r.to {
				want++
			}
			if got := s.conns.Load(); got != want {
				t.Errorf("%s: the listener at %s got %d connections; want %d", r.name, s.Listener.Addr(), got-n, want-n)
			}
		}
	}
}

// A policy host that answers with a redirect gets one request, and the
// target gets no connection, even where the extra range permits it (RFC
// 8461 section 3.3): an address, an internal name, the same URL.
func TestGrdRedirectsAreNotFollowed(t *testing.T) {
	ca := mtsNewCA(t)
	later := time.Now().Add(time.Hour)
	target := grdMustServe(t, "127.0.0.1", "0", ca.leaf(t, later, nil, net.IPv4(127, 0, 0, 1)), nil)
	named := grdMustServe(t, "127.0.0.1", "0", ca.leaf(t, later, []string{"localhost"}), nil)
	policy := grdMustServe(t, "127.0.0.2", "0", ca.leaf(t, later, nil, net.IPv4(127, 0, 0, 2)), func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(r.URL.Query().Get("code"))
		if err != nil {
			t.Error(err)
			return
		}
		to := r.URL.Query().Get("to")
		if to == "" {
			to = "https://" + r.Host + r.URL.RequestURI()
		}
		w.Header().Set("Location", to)
		w.WriteHeader(code)
	})
	extra := grdPrefixes("127.0.0.0/8")
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, to := range []string{
			"https://127.0.0.1:" + grdPort(target) + "/.well-known/mta-sts.txt",
			"https://localhost:" + grdPort(named) + "/.well-known/mta-sts.txt",
			"", // the URL that was asked
		} {
			name := strconv.Itoa(code) + " to " + to
			before := policy.requests.Load()
			u := grdURL("127.0.0.2", grdPort(policy)) + "?code=" + strconv.Itoa(code) + "&to=" + url.QueryEscape(to)
			a := grdFetch(t, u, extra, ca.pool)
			mtsWantFailure(t, name, a, obs.ReasonBadAnswer, "HTTP status "+strconv.Itoa(code))
			if n := policy.requests.Load() - before; n != 1 {
				t.Errorf("%s: the policy host got %d requests; want one", name, n)
			}
		}
	}
	if n := grdConns(target, named); n != 0 {
		t.Errorf("the targets of the redirects got %d connections; want none", n)
	}
}

// A refused fetch is a failure, never a policy and never its absence: it
// shows nothing and leaves an open policy alert as it is. The control: the
// same server under an extra range that permits it ends the alert.
func TestGrdRefusalLeavesTheAlertOpen(t *testing.T) {
	srv := grdMustServe(t, "127.0.0.1", "0", nil, func(w http.ResponseWriter, r *http.Request) {
		body := grdSame
		if r.URL.Path == "/weak" {
			body = grdWeak
		}
		_, _ = io.WriteString(w, body)
	})
	base := "https://" + srv.Listener.Addr().String()
	k := mtsKey(t, mtsName(t, "corp.test."))
	f, err := expect.Parse([]byte("domain corp.test.\n" + grdLine + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	of := func(a obs.Answer) obs.Observation { return obs.Observation{Key: k, Answers: []obs.Answer{a}} }
	open := decide.Findings(f, of(grdFetch(t, base+"/weak", mtsLoopback, srv.pool())))
	if len(open) != 1 || open[0].Rule != decide.RuleMTASTS {
		t.Fatalf("the weaker policy gives %+v; want one mta-sts finding", open)
	}
	before := srv.conns.Load()
	refused := grdFetch(t, base+"/", nil, srv.pool())
	grdWantRefused(t, "the refused fetch", refused, "127.0.0.1")
	if n := srv.conns.Load() - before; n != 0 {
		t.Errorf("the refused fetch opened %d connections", n)
	}
	if got := decide.Findings(f, of(refused)); len(got) != 0 {
		t.Errorf("the refused fetch gives the findings %+v; want none", got)
	}
	now := time.Now()
	if got := decide.Decide(decide.Input{Expect: f, Open: open, Observation: of(refused), Now: now}); len(got) != 0 {
		t.Errorf("the refused fetch changes the open alert: %+v", got)
	}
	good := of(grdFetch(t, base+"/", mtsLoopback, srv.pool()))
	if got := decide.Decide(decide.Input{Expect: f, Open: open, Observation: good, Now: now}); len(got) != 1 || got[0].Op != decide.OpResolve {
		t.Errorf("the permitted fetch of the same file: %+v; want the alert resolved", got)
	}
}
