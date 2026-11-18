package mtasts

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The text that a refused key gives, and the one of a URL that the client refuses.
const (
	mtsRefused = "not a policy check"
	mtsBadURL  = "not an https URL with a host and no user name"
	mtsSecret  = "mtssecret"
)

func mtsName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// mtsLabels makes a name of raw label octets, so that a label can hold any
// octet, a dot included.
func mtsLabels(t *testing.T, labels ...string) dnswire.Name {
	t.Helper()
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func mtsKey(t *testing.T, domain dnswire.Name) obs.Key {
	t.Helper()
	k, ok := obs.PolicyKey(domain)
	if !ok {
		t.Fatalf("PolicyKey(%v): not ok", domain)
	}
	return k
}

// mtsClock is a clock that moves one second at each reading, so that the
// order of the readings and of a request shows in the times.
type mtsClock struct{ n atomic.Int64 }

var mtsT0 = time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)

func (c *mtsClock) now() time.Time  { return mtsT0.Add(time.Duration(c.n.Add(1)) * time.Second) }
func (c *mtsClock) peek() time.Time { return mtsT0.Add(time.Duration(c.n.Load()) * time.Second) }

// mtsServer is a TLS test server that counts its connections and requests and
// notes the clock when the last request arrived.
type mtsServer struct {
	*httptest.Server
	conns, requests atomic.Int64
	at              atomic.Int64 // UnixNano of the clock at the last request
}

// mtsServe starts h; a nil cfg serves the certificate of httptest.
func mtsServe(t *testing.T, clock *mtsClock, cfg *tls.Config, h http.HandlerFunc) *mtsServer {
	t.Helper()
	s := &mtsServer{}
	s.Server = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		if clock != nil {
			s.at.Store(clock.peek().UnixNano())
		}
		h(w, r)
	}))
	s.Config.ConnState = func(_ net.Conn, st http.ConnState) {
		if st == http.StateNew {
			s.conns.Add(1)
		}
	}
	// Refused handshakes are the point of some tests; their log is noise.
	s.Config.ErrorLog = log.New(io.Discard, "", 0)
	s.TLS = cfg
	s.StartTLS()
	t.Cleanup(s.Close)
	return s
}

// pool trusts the certificate that s serves.
func (s *mtsServer) pool() *x509.CertPool {
	p := x509.NewCertPool()
	p.AddCert(s.Certificate())
	return p
}

func (s *mtsServer) addr(t *testing.T) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(s.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

func (s *mtsServer) lastAt() time.Time { return time.Unix(0, s.at.Load()).UTC() }

// mtsTo is a url function that sends every fetch to one URL and keeps the
// hosts it was given.
type mtsTo struct {
	to    string
	hosts []string
}

func (u *mtsTo) url(host string) string {
	u.hosts = append(u.hosts, host)
	return u.to
}

func mtsFetch(k obs.Key, roots *x509.CertPool, url func(string) string, clock *mtsClock) obs.Answer {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return fetch(ctx, k, roots, url, clock.now)
}

// mtsSeen is the case of a Result, as Match gives it.
type mtsSeen struct {
	which   string
	set     []dnswire.Record
	failure obs.Failure
}

func mtsMatch(r obs.Result) mtsSeen {
	return obs.Match(r,
		func(v obs.Records) mtsSeen { return mtsSeen{which: "records", set: v.Set} },
		func(obs.NoData) mtsSeen { return mtsSeen{which: "nodata"} },
		func(obs.NoName) mtsSeen { return mtsSeen{which: "noname"} },
		func(f obs.Failure) mtsSeen { return mtsSeen{which: "failure", failure: f} })
}

// mtsWantFailure: a failure, never records or a negative answer, with reason
// and exactly detail.
func mtsWantFailure(t *testing.T, name string, a obs.Answer, reason obs.Reason, detail string) {
	t.Helper()
	s := mtsMatch(a.Result)
	if s.which != "failure" || s.failure.Reason != reason || s.failure.Detail != detail {
		t.Errorf("%s: %s %v %q (%d records); want failure %v %q", name, s.which, s.failure.Reason, s.failure.Detail, len(s.set), reason, detail)
	}
	if strings.Contains(s.failure.Detail, mtsSecret) {
		t.Errorf("%s: the failure text holds octets of the answer: %q", name, s.failure.Detail)
	}
}

// mtsWantProof checks the proof of a fetch that was sent: the policy host,
// the address when addr is not nil, the question, the times around the
// request when at is set, no wire, TCP.
func mtsWantProof(t *testing.T, name string, a obs.Answer, k obs.Key, addr *netip.AddrPort, at time.Time) {
	t.Helper()
	if !a.Server.Name.Equal(k.Name) || addr != nil && a.Server.Addr != *addr {
		t.Errorf("%s: server %v %v; want %v at %v", name, a.Server.Name, a.Server.Addr, k.Name, addr)
	}
	if !a.Question.Name.Equal(k.Name) || a.Question.Type != dnswire.TypeTXT || a.Question.Class != dnswire.ClassINET {
		t.Errorf("%s: question %v %v %v; want %v TXT IN", name, a.Question.Name, a.Question.Type, a.Question.Class, k.Name)
	}
	if a.Wire != nil || !a.TCP {
		t.Errorf("%s: wire %d octets, TCP %v; want no wire, TCP", name, len(a.Wire), a.TCP)
	}
	if a.Sent.IsZero() || !a.Received.After(a.Sent) {
		t.Errorf("%s: sent %v, received %v; want both, received after sent", name, a.Sent, a.Received)
	}
	if !at.IsZero() && (at.Before(a.Sent) || !a.Received.After(at)) {
		t.Errorf("%s: sent %v, request at %v, received %v; want the request between", name, a.Sent, at, a.Received)
	}
}

// mtsWantRefused: a refusal before any request, whose proof names the key.
func mtsWantRefused(t *testing.T, name string, a obs.Answer, k obs.Key) {
	t.Helper()
	mtsWantFailure(t, name, a, obs.ReasonNotPermitted, mtsRefused)
	if !a.Server.Name.Equal(k.Name) || a.Server.Addr.IsValid() || !a.Question.Name.Equal(k.Name) ||
		a.Question.Type != dnswire.TypeTXT || a.Question.Class != dnswire.ClassINET {
		t.Errorf("%s: proof %v %v %v %v; want %v, no address, %v TXT", name, a.Server.Name, a.Server.Addr, a.Question.Name, a.Question.Type, k.Name, k.Name)
	}
	if !a.Sent.IsZero() || a.Received.IsZero() || a.Wire != nil || !a.TCP {
		t.Errorf("%s: sent %v, received %v, wire %d, TCP %v; want nothing sent, a time of the end, no wire, TCP",
			name, a.Sent, a.Received, len(a.Wire), a.TCP)
	}
}

// mtsBody is n octets in which every octet value occurs, CR, LF and NUL too.
func mtsBody(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i) ^ byte(i>>8)
	}
	return b
}

// mtsCA is a certificate authority of a test and a pool that trusts it alone.
type mtsCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pool *x509.CertPool
}

func mtsNewCA(t *testing.T) *mtsCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "osk test authority"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return &mtsCA{cert: cert, key: key, pool: pool}
}

// leaf is a server certificate of ca for the names and addresses given,
// valid until notAfter.
func (ca *mtsCA) leaf(t *testing.T, notAfter time.Time, names []string, ips ...net.IP) *tls.Config {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "osk test server"},
		NotBefore:    time.Now().Add(-2 * time.Hour),
		NotAfter:     notAfter,
		DNSNames:     names,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}
}

// The host is mta-sts.<domain> with port 443, in lower case, without the
// trailing dot (RFC 8461 section 3.3). A name with an octet that could change
// a URL, the root and a name over 255 octets have no host.
func TestHost(t *testing.T) {
	a, b, c := strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63)
	for _, tc := range []struct {
		name   string
		domain dnswire.Name
		want   string
		ok     bool
	}{
		{"plain", mtsName(t, "corp.test."), "mta-sts.corp.test:443", true},
		{"upper case", mtsName(t, "Corp.TEST."), "mta-sts.corp.test:443", true},
		{"no trailing dot in the text", mtsName(t, "corp.test"), "mta-sts.corp.test:443", true},
		{"three labels", mtsName(t, "mail.Corp.test."), "mta-sts.mail.corp.test:443", true},
		{"hyphen, underscore and digits", mtsName(t, "_A-1.xn--bcher-kva.test."), "mta-sts._a-1.xn--bcher-kva.test:443", true},
		{"slash", mtsLabels(t, "a/b", "test"), "", false},
		{"colon", mtsLabels(t, "a:1", "test"), "", false},
		{"a port in the last label", mtsLabels(t, "corp", "test:443"), "", false},
		{"question mark", mtsLabels(t, "a?b", "test"), "", false},
		{"number sign", mtsLabels(t, "a#b", "test"), "", false},
		{"percent", mtsLabels(t, "a%41b", "test"), "", false},
		{"at sign", mtsLabels(t, "u@evil", "test"), "", false},
		{"brackets", mtsLabels(t, "[::1]", "test"), "", false},
		{"space", mtsLabels(t, "a b", "test"), "", false},
		{"not ASCII", mtsLabels(t, "bücher", "test"), "", false},
		{"a dot inside a label", mtsLabels(t, "corp.test"), "", false},
		{"the root", dnswire.Name{}, "", false},
		{"a policy name of 255 octets", mtsLabels(t, a, b, c, strings.Repeat("d", 53)),
			"mta-sts." + a + "." + b + "." + c + "." + strings.Repeat("d", 53) + ":443", true},
		{"a policy name of 256 octets", mtsLabels(t, a, b, c, strings.Repeat("d", 54)), "", false},
		{"a domain of 255 octets", mtsLabels(t, a, b, c, strings.Repeat("d", 61)), "", false},
	} {
		if got, ok := Host(tc.domain); got != tc.want || ok != tc.ok {
			t.Errorf("%s: Host(%v) = %q, %v; want %q, %v", tc.name, tc.domain, got, ok, tc.want, tc.ok)
		}
	}

	// A label may hold exactly the letters, the digits, "-" and "_", in the
	// first label and in the last.
	for o := range 256 {
		octet := string([]byte{byte(o)})
		allowed := 'a' <= o && o <= 'z' || 'A' <= o && o <= 'Z' || '0' <= o && o <= '9' || o == '-' || o == '_'
		for _, labels := range [][]string{{"a" + octet + "b", "test"}, {"corp", "test" + octet}} {
			want := ""
			if allowed {
				want = "mta-sts." + strings.ToLower(labels[0]+"."+labels[1]) + ":443"
			}
			if got, ok := Host(mtsLabels(t, labels...)); got != want || ok != allowed {
				t.Errorf("octet %#02x in %q: Host = %q, %v; want %q, %v", o, labels, got, ok, want, allowed)
			}
		}
	}
}

// The URL of the policy file is fixed: https, the host without its port, the
// well-known path, no query (RFC 8461 section 3.3). Its host is the host.
func TestPolicyURL(t *testing.T) {
	for _, c := range []struct{ domain, want string }{
		{"corp.test.", "https://mta-sts.corp.test/.well-known/mta-sts.txt"},
		{"Mail.CORP.test.", "https://mta-sts.mail.corp.test/.well-known/mta-sts.txt"},
		{"_x.corp.test.", "https://mta-sts._x.corp.test/.well-known/mta-sts.txt"},
	} {
		host, ok := Host(mtsName(t, c.domain))
		got := policyURL(host)
		back, err := httpclient.HostOf(got)
		if !ok || got != c.want || err != nil || back != host {
			t.Errorf("%s: URL %q of host %q, whose host is %q, %v; want %q", c.domain, got, host, back, err, c.want)
		}
	}
}

// A label that would make the URL name another host is refused before
// anything is sent: the host would be one that no configured domain names.
func TestFetchRefusesNamesThatChangeTheURL(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "version: STSv1\n") })
	for _, tc := range []struct {
		name   string
		domain dnswire.Name
	}{
		{"slash", mtsLabels(t, "a/b", "test")},
		{"slash at the end", mtsLabels(t, "corp", "test/")},
		{"colon", mtsLabels(t, "a:1", "test")},
		{"port 443 in the last label", mtsLabels(t, "corp", "test:443")},
		{"port 8443 in the last label", mtsLabels(t, "corp", "test:8443")},
		{"question mark", mtsLabels(t, "a?b", "test")},
		{"number sign", mtsLabels(t, "a#b", "test")},
		{"percent escape of ASCII", mtsLabels(t, "a%41b", "test")},
		{"percent escape of percent", mtsLabels(t, "a%25b", "test")},
		{"space", mtsLabels(t, "a b", "test")},
		{"not ASCII", mtsLabels(t, "bücher", "test")},
		{"a dot inside a label", mtsLabels(t, "corp.test")},
		{"backslash", mtsLabels(t, `a\b`, "test")},
	} {
		k := mtsKey(t, tc.domain)
		to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}
		mtsWantRefused(t, tc.name, mtsFetch(k, srv.pool(), to.url, clock), k)
	}
	if n := srv.conns.Load(); n != 0 {
		t.Errorf("refused keys opened %d connections", n)
	}

	// Names that keep the URL on their host are fetched, from that host.
	for _, tc := range []struct{ domain, host string }{
		{"Corp.TEST.", "mta-sts.corp.test:443"},
		{"_x.corp.test.", "mta-sts._x.corp.test:443"},
		{"xn--bcher-kva.test.", "mta-sts.xn--bcher-kva.test:443"},
	} {
		k := mtsKey(t, mtsName(t, tc.domain))
		to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}
		a := mtsFetch(k, srv.pool(), to.url, clock)
		if s := mtsMatch(a.Result); s.which != "records" || !slices.Equal(to.hosts, []string{tc.host}) {
			t.Errorf("%s: %s %+v, url asked for %q; want records, from %q", tc.domain, s.which, s.failure, to.hosts, tc.host)
		}
	}
}

// The fetch refuses, before any connection, exactly the names whose labels
// hold an octet other than a letter, a digit, "-" or "_". Every other name
// asks the URL for its own host, and that URL names exactly that host, the
// path of the policy file and nothing else.
func TestFetchHostOfAnyOctet(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "version: STSv1\n") })
	for o := range 256 {
		octet := string([]byte{byte(o)})
		allowed := 'a' <= o && o <= 'z' || 'A' <= o && o <= 'Z' || '0' <= o && o <= '9' || o == '-' || o == '_'
		for _, labels := range [][]string{{"a" + octet + "b", "test"}, {"corp", "test" + octet}} {
			k := mtsKey(t, mtsLabels(t, labels...))
			name := fmt.Sprintf("octet %#02x in %q", o, labels)
			to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}
			before := srv.conns.Load()
			a := mtsFetch(k, srv.pool(), to.url, clock)
			if !allowed {
				mtsWantRefused(t, name, a, k)
				if srv.conns.Load() != before || len(to.hosts) != 0 {
					t.Errorf("%s: refused, but url was asked for %q or a connection was opened", name, to.hosts)
				}
				continue
			}
			host := "mta-sts." + strings.ToLower(labels[0]+"."+labels[1]) + ":443"
			if s := mtsMatch(a.Result); s.which != "records" || !slices.Equal(to.hosts, []string{host}) {
				t.Errorf("%s: %s %+v, url asked for %q; want records from %q", name, s.which, s.failure, to.hosts, host)
				continue
			}
			u, err := url.Parse(policyURL(host))
			if err != nil || u.Scheme != "https" || u.User != nil || u.Host+":443" != host || u.Path != "/.well-known/mta-sts.txt" ||
				u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
				t.Errorf("%s: the URL %q does not name only the host %q and the path", name, policyURL(host), host)
			}
		}
	}
}

// Only the policy key of its domain is fetched: any other key would send the
// request to a host that its domain does not fix.
func TestFetchRefusesOtherKeys(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "version: STSv1\n") })
	corp := mtsName(t, "corp.test.")
	k := mtsKey(t, corp)
	a, b, c := strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63)
	long := mtsLabels(t, a, b, c, strings.Repeat("d", 61))
	with := func(f func(*obs.Key)) obs.Key { x := k; f(&x); return x }
	for _, tc := range []struct {
		name string
		key  obs.Key
	}{
		{"the zero key", obs.Key{}},
		{"kind records", with(func(x *obs.Key) { x.Kind = obs.KindRecords })},
		{"kind 0", with(func(x *obs.Key) { x.Kind = 0 })},
		{"kind certificates", obs.CertificatesKey(corp)},
		{"the domain as Name", with(func(x *obs.Key) { x.Name = corp })},
		{"the host of another domain", with(func(x *obs.Key) { x.Name = mtsName(t, "mta-sts.evil.test.") })},
		{"a name under the host", with(func(x *obs.Key) { x.Name = mtsName(t, "x.mta-sts.corp.test.") })},
		{"another domain with this host", with(func(x *obs.Key) { x.Domain = mtsName(t, "evil.test.") })},
		{"type A", with(func(x *obs.Key) { x.Type = dnswire.TypeA })},
		{"a domain whose host is too long", obs.Key{Kind: obs.KindPolicy, Domain: long, Name: long, Type: dnswire.TypeTXT}},
		{"the policy key of the root", obs.Key{Kind: obs.KindPolicy, Name: mtsName(t, "mta-sts."), Type: dnswire.TypeTXT}},
	} {
		to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}
		mtsWantRefused(t, tc.name, mtsFetch(tc.key, srv.pool(), to.url, clock), tc.key)
	}
	if n := srv.conns.Load(); n != 0 {
		t.Errorf("refused keys opened %d connections", n)
	}

	// The names of a key are compared without case; the host comes from the
	// domain, in lower case.
	for _, key := range []obs.Key{
		with(func(x *obs.Key) { x.Name = mtsName(t, "MTA-STS.Corp.TEST.") }),
		{Kind: obs.KindPolicy, Domain: mtsName(t, "CORP.test."), Name: mtsName(t, "mta-sts.corp.Test."), Type: dnswire.TypeTXT},
	} {
		to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}
		a := mtsFetch(key, srv.pool(), to.url, clock)
		if s := mtsMatch(a.Result); s.which != "records" || !slices.Equal(to.hosts, []string{"mta-sts.corp.test:443"}) {
			t.Errorf("key %v: %s %+v, url asked for %q; want records from mta-sts.corp.test:443", key, s.which, s.failure, to.hosts)
		}
	}

	// Fetch refuses the same way, before any lookup.
	start := time.Now()
	for _, bad := range []obs.Key{
		with(func(x *obs.Key) { x.Name = corp }),
		{Kind: obs.KindPolicy, Name: mtsName(t, "mta-sts."), Type: dnswire.TypeTXT},
	} {
		mtsWantRefused(t, "Fetch of "+bad.String(), Fetch(context.Background(), bad), bad)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("Fetch of a refused key took %v", d)
	}
}

// A 200 gives one TXT record at the policy host: the body cut every 255
// octets, joined back exactly, whatever octets it holds; an empty body is one
// empty string, never an empty set. A body of MaxPolicy octets is whole.
func TestFetchBody(t *testing.T) {
	clock := &mtsClock{}
	data := mtsBody(httpclient.MaxPolicy)
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("n"))
		if err != nil {
			t.Error(err)
			return
		}
		if r.URL.Query().Get("chunked") == "1" {
			for off := 0; off < n; off += 1000 {
				_, _ = w.Write(data[off:min(off+1000, n)])
				w.(http.Flusher).Flush()
			}
			return
		}
		w.Header().Set("Content-Length", strconv.Itoa(n))
		_, _ = w.Write(data[:n])
	})
	addr := srv.addr(t)
	k := mtsKey(t, mtsName(t, "corp.test."))
	for _, tc := range []struct{ n, strings int }{
		{0, 1}, {1, 1}, {254, 1}, {255, 1}, {256, 2}, {509, 2}, {510, 2}, {511, 3}, {4096, 17}, {65535, 257}, {65536, 258},
	} {
		for _, chunked := range []string{"0", "1"} {
			name := fmt.Sprintf("body of %d octets, chunked %s", tc.n, chunked)
			to := &mtsTo{to: fmt.Sprintf("%s/.well-known/mta-sts.txt?n=%d&chunked=%s", srv.URL, tc.n, chunked)}
			a := mtsFetch(k, srv.pool(), to.url, clock)
			mtsWantProof(t, name, a, k, &addr, srv.lastAt())
			s := mtsMatch(a.Result)
			if s.which != "records" || len(s.set) != 1 {
				t.Errorf("%s: %s %+v with %d records; want one record", name, s.which, s.failure, len(s.set))
				continue
			}
			r := s.set[0]
			txt, ok := r.Data.(dnswire.TXT)
			if !r.Name.Equal(k.Name) || r.Class != dnswire.ClassINET || r.TTL != 0 || !ok {
				t.Errorf("%s: record %v class %v TTL %d data %T; want %v IN TTL 0 TXT", name, r.Name, r.Class, r.TTL, r.Data, k.Name)
				continue
			}
			want := []string{""}
			if tc.n > 0 {
				want = nil
				for off := 0; off < tc.n; off += 255 {
					want = append(want, string(data[off:min(off+255, tc.n)]))
				}
			}
			if len(txt.Strings) != tc.strings || !slices.Equal(txt.Strings, want) || strings.Join(txt.Strings, "") != string(data[:tc.n]) {
				t.Errorf("%s: %d strings; want %d strings of 255 octets, the last shorter, that join to the body", name, len(txt.Strings), tc.strings)
			}
		}
	}
}

// A body over MaxPolicy octets is a failure, never a body cut short that
// could read as another policy; also with another status.
func TestFetchTooLarge(t *testing.T) {
	clock := &mtsClock{}
	data := []byte(strings.Repeat(mtsSecret+"\n", 1<<17))
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		n, err := strconv.Atoi(q.Get("n"))
		status, err2 := strconv.Atoi(q.Get("s"))
		if err != nil || err2 != nil {
			t.Error(err, err2)
			return
		}
		w.WriteHeader(status)
		if q.Get("chunked") == "1" {
			for off := 0; off < n; off += 1000 {
				// The client stops reading.
				_, _ = w.Write(data[off:min(off+1000, n)])
				w.(http.Flusher).Flush()
			}
			return
		}
		_, _ = w.Write(data[:n])
	})
	k := mtsKey(t, mtsName(t, "corp.test."))
	for _, n := range []int{httpclient.MaxPolicy + 1, 1 << 20} {
		for _, status := range []int{200, 404} {
			for _, chunked := range []string{"0", "1"} {
				name := fmt.Sprintf("body of %d octets, status %d, chunked %s", n, status, chunked)
				to := &mtsTo{to: fmt.Sprintf("%s/.well-known/mta-sts.txt?n=%d&s=%d&chunked=%s", srv.URL, n, status, chunked)}
				a := mtsFetch(k, srv.pool(), to.url, clock)
				mtsWantFailure(t, name, a, obs.ReasonBadAnswer, "the policy file is larger than 65536 octets")
				mtsWantProof(t, name, a, k, nil, srv.lastAt())
			}
		}
	}
}

// Only 200 is a policy (RFC 8461 section 3.3): every other status is a
// failure that names the status and nothing of the answer, from the address
// that answered.
func TestFetchStatusNot200(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Location", "https://"+mtsSecret+".test/")
		w.Header().Set("X-Reason", mtsSecret)
		w.WriteHeader(code)
		// 204 and 304 carry no body; the write fails there.
		_, _ = io.WriteString(w, "version: STSv1\nmode: enforce\n"+mtsSecret)
	})
	addr := srv.addr(t)
	k := mtsKey(t, mtsName(t, "corp.test."))
	for _, code := range []int{201, 202, 203, 204, 206, 299, 300, 301, 302, 303, 304, 307, 308,
		400, 401, 403, 404, 410, 418, 429, 500, 502, 503, 504, 599, 999} {
		name := fmt.Sprintf("status %d", code)
		to := &mtsTo{to: srv.URL + "/" + strconv.Itoa(code)}
		a := mtsFetch(k, srv.pool(), to.url, clock)
		mtsWantFailure(t, name, a, obs.ReasonBadAnswer, "HTTP status "+strconv.Itoa(code))
		mtsWantProof(t, name, a, k, &addr, srv.lastAt())
	}
}

// A redirect is not followed (RFC 8461 section 3.3): neither another host,
// which never gets a connection, nor another path of the same host.
func TestFetchRedirectNotFollowed(t *testing.T) {
	clock := &mtsClock{}
	other := mtsServe(t, nil, nil, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "version: STSv1\n") })
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/elsewhere" {
			return
		}
		code, err := strconv.Atoi(r.URL.Query().Get("code"))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Location", r.URL.Query().Get("to"))
		w.WriteHeader(code)
	})
	k := mtsKey(t, mtsName(t, "corp.test."))
	sent := 0
	for _, code := range []int{301, 302, 303, 307, 308} {
		for _, target := range []string{other.URL + "/.well-known/mta-sts.txt", "/elsewhere"} {
			name := fmt.Sprintf("%d to %s", code, target)
			to := &mtsTo{to: srv.URL + "/.well-known/mta-sts.txt?code=" + strconv.Itoa(code) + "&to=" + url.QueryEscape(target)}
			// The pool trusts the other server too: only the client's rule stops the redirect.
			a := mtsFetch(k, srv.pool(), to.url, clock)
			sent++
			mtsWantFailure(t, name, a, obs.ReasonBadAnswer, "HTTP status "+strconv.Itoa(code))
		}
	}
	if n := other.conns.Load(); n != 0 {
		t.Errorf("the target host of the redirects got %d connections", n)
	}
	if n := srv.requests.Load(); n != int64(sent) {
		t.Errorf("the policy host got %d requests for %d fetches; a redirect to its other path was followed", n, sent)
	}
}

// A server that does not answer before the check's deadline gives a timeout,
// soon after it.
func TestFetchTimeout(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	held := make(chan net.Conn, 4)
	go func() {
		for {
			c, err := silent.Accept()
			if err != nil {
				return
			}
			held <- c
		}
	}()
	t.Cleanup(func() {
		_ = silent.Close()
		for {
			select {
			case c := <-held:
				_ = c.Close()
			default:
				return
			}
		}
	})
	clock := &mtsClock{}
	release := make(chan struct{})
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/stall" {
			w.Header().Set("Content-Length", "100")
			_, _ = io.WriteString(w, "version: ")
			w.(http.Flusher).Flush()
		}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	k := mtsKey(t, mtsName(t, "corp.test."))
	for _, c := range []struct {
		name, url string
		pool      *x509.CertPool
	}{
		{"no TLS handshake", "https://" + silent.Addr().String() + "/.well-known/mta-sts.txt", srv.pool()},
		{"no answer", srv.URL + "/.well-known/mta-sts.txt", srv.pool()},
		{"a body that stops", srv.URL + "/stall", srv.pool()},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		start := time.Now()
		a := fetch(ctx, k, c.pool, (&mtsTo{to: c.url}).url, clock.now)
		took := time.Since(start)
		cancel()
		mtsWantFailure(t, c.name, a, obs.ReasonTimeout, "timeout")
		mtsWantProof(t, c.name, a, k, nil, time.Time{})
		if took > 3*time.Second {
			t.Errorf("%s: the fetch took %v after a deadline of 300ms", c.name, took)
		}
	}
}

// The certificate must be trusted and name the host of the URL. A server
// whose certificate fails either never gets the request.
func TestFetchCertificates(t *testing.T) {
	ca := mtsNewCA(t)
	loopback := net.IPv4(127, 0, 0, 1)
	k := mtsKey(t, mtsName(t, "corp.test."))
	later := time.Now().Add(time.Hour)
	for _, c := range []struct {
		name    string
		cfg     *tls.Config // nil: the certificate of httptest
		roots   func(*mtsServer) *x509.CertPool
		trusted bool
	}{
		{"right name, trusted", ca.leaf(t, later, nil, loopback), func(*mtsServer) *x509.CertPool { return ca.pool }, true},
		{"another name", ca.leaf(t, later, []string{"mta-sts.evil.test", "evil.test"}), func(*mtsServer) *x509.CertPool { return ca.pool }, false},
		{"the policy name, not the host asked", ca.leaf(t, later, []string{"mta-sts.corp.test"}), func(*mtsServer) *x509.CertPool { return ca.pool }, false},
		{"another address", ca.leaf(t, later, nil, net.IPv4(127, 0, 0, 2)), func(*mtsServer) *x509.CertPool { return ca.pool }, false},
		{"expired", ca.leaf(t, time.Now().Add(-time.Hour), nil, loopback), func(*mtsServer) *x509.CertPool { return ca.pool }, false},
		{"httptest, trusted", nil, (*mtsServer).pool, true},
		{"httptest, a pool without it", nil, func(*mtsServer) *x509.CertPool { return ca.pool }, false},
		{"httptest, the system store", nil, func(*mtsServer) *x509.CertPool { return nil }, false},
	} {
		clock := &mtsClock{}
		srv := mtsServe(t, clock, c.cfg, func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "version: STSv1\n") })
		a := mtsFetch(k, c.roots(srv), (&mtsTo{to: srv.URL + "/.well-known/mta-sts.txt"}).url, clock)
		if c.trusted {
			if s := mtsMatch(a.Result); s.which != "records" {
				t.Errorf("%s: %s %+v; want records", c.name, s.which, s.failure)
			}
			continue
		}
		mtsWantFailure(t, c.name, a, obs.ReasonNetwork, "network: certificate not trusted")
		zero := netip.AddrPort{}
		mtsWantProof(t, c.name, a, k, &zero, time.Time{})
		if n := srv.requests.Load(); n != 0 {
			t.Errorf("%s: the server got %d requests", c.name, n)
		}
	}
}

// Every other failure of the network gives its fixed text, never octets of
// the answer.
func TestFetchNetworkErrors(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/big-header" {
			w.Header().Set("X-Big", mtsSecret+strings.Repeat("a", 20000))
			return
		}
		answers := map[string]string{
			"/status-line": "HTTP/1.1 2000 " + mtsSecret + "\r\n\r\n",
			"/header-line": "HTTP/1.1 200 OK\r\nX" + mtsSecret + "\r\n\r\n",
			"/short":       "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\nversion: STSv1\n" + mtsSecret,
		}
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = io.WriteString(conn, answers[r.URL.Path])
		_ = conn.Close()
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	k := mtsKey(t, mtsName(t, "corp.test."))
	zero := netip.AddrPort{}
	a := mtsFetch(k, srv.pool(), (&mtsTo{to: "https://" + closed + "/.well-known/mta-sts.txt"}).url, clock)
	mtsWantFailure(t, "refused connection", a, obs.ReasonNetwork, "network: cannot connect")
	mtsWantProof(t, "refused connection", a, k, &zero, time.Time{})
	for _, path := range []string{"/status-line", "/header-line", "/short", "/big-header"} {
		a := mtsFetch(k, srv.pool(), (&mtsTo{to: srv.URL + path}).url, clock)
		mtsWantFailure(t, path, a, obs.ReasonNetwork, "network: no usable answer")
		mtsWantProof(t, path, a, k, nil, time.Time{})
	}
}

// A URL that the client refuses is not permitted, sends nothing and opens no
// connection. Through the real URL no fetch gets here: the key is refused
// first.
func TestFetchURLNotPermitted(t *testing.T) {
	clock := &mtsClock{}
	srv := mtsServe(t, clock, nil, func(http.ResponseWriter, *http.Request) {})
	host := strings.TrimPrefix(srv.URL, "https://")
	k := mtsKey(t, mtsName(t, "corp.test."))
	for _, u := range []string{
		"http://" + host + "/.well-known/mta-sts.txt",
		"https://u:" + mtsSecret + "@" + host + "/.well-known/mta-sts.txt",
		"https:///" + mtsSecret,
		"https://bücher.test/" + mtsSecret,
		srv.URL + "/" + mtsSecret + "%zz",
		mtsSecret,
		"",
	} {
		a := mtsFetch(k, srv.pool(), (&mtsTo{to: u}).url, clock)
		mtsWantFailure(t, u, a, obs.ReasonNotPermitted, mtsBadURL)
		if !a.Server.Name.Equal(k.Name) || a.Server.Addr.IsValid() || a.Wire != nil || !a.TCP || !a.Sent.IsZero() || a.Received.IsZero() {
			t.Errorf("%q: proof %v %v, wire %d, TCP %v, sent %v, received %v; want %v, no address, no wire, TCP, nothing sent, a time of the end",
				u, a.Server.Name, a.Server.Addr, len(a.Wire), a.TCP, a.Sent, a.Received, k.Name)
		}
	}
	if n := srv.conns.Load(); n != 0 {
		t.Errorf("refused URLs opened %d connections", n)
	}
}

// The request is a GET of the fixed path that asks for text, with no cookie,
// no client certificate and no header beyond those of Go: nothing of the
// operator reaches the policy host, which the DNS of the domain chooses.
func TestFetchRequest(t *testing.T) {
	type request struct {
		method, uri string
		header      http.Header
		body        int
		certs       int
	}
	got := make(chan request, 2)
	clock := &mtsClock{}
	srv := mtsServe(t, clock, &tls.Config{ClientAuth: tls.RequestClientCert}, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- request{r.Method, r.RequestURI, r.Header.Clone(), len(body), len(r.TLS.PeerCertificates)}
		http.SetCookie(w, &http.Cookie{Name: "mts", Value: mtsSecret, Path: "/"})
		_, _ = io.WriteString(w, "version: STSv1\n")
	})
	k := mtsKey(t, mtsName(t, "Corp.TEST."))
	// The URL of the policy host, with the test server in place of the host.
	var hosts []string
	toServer := func(host string) string {
		hosts = append(hosts, host)
		return srv.URL + strings.TrimPrefix(policyURL(host), "https://"+strings.TrimSuffix(host, ":443"))
	}
	for i := range 2 {
		a := mtsFetch(k, srv.pool(), toServer, clock)
		if s := mtsMatch(a.Result); s.which != "records" {
			t.Fatalf("fetch %d: %s %+v; want records", i, s.which, s.failure)
		}
		r := <-got
		if r.method != http.MethodGet || r.uri != "/.well-known/mta-sts.txt" || r.body != 0 || r.certs != 0 {
			t.Errorf("fetch %d: %s %s, body %d octets, %d client certificates; want GET /.well-known/mta-sts.txt and nothing else",
				i, r.method, r.uri, r.body, r.certs)
		}
		if !slices.Equal(r.header["Accept"], []string{"text/plain"}) {
			t.Errorf("fetch %d: Accept %q, want text/plain", i, r.header["Accept"])
		}
		for name, v := range r.header {
			switch {
			case name == "Accept":
			case name == "Connection" && slices.Equal(v, []string{"close"}):
			// The name of the client that Go gives, the same for every user.
			case strings.HasPrefix(name, "User-") && slices.Equal(v, []string{"Go-http-client/1.1"}):
			default:
				t.Errorf("fetch %d: the request carries the header %s: %q", i, name, v)
			}
		}
	}
	if !slices.Equal(hosts, []string{"mta-sts.corp.test:443", "mta-sts.corp.test:443"}) {
		t.Errorf("url asked for %q; want mta-sts.corp.test:443 twice", hosts)
	}
}
