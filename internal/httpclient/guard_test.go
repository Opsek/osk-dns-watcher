package httpclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"
)

// grdDNS answers every name lookup of this test binary, so that a test
// chooses the addresses of a name and sees each question asked.
var grdDNS = &grdResolver{names: map[string]*grdName{}}

func init() {
	// guardedDial reads net.DefaultResolver and has no other seam. A dial
	// that a cancelled request leaves behind may still read it, so it is set
	// before any test runs and never put back. /etc/hosts is read as before;
	// a name that no test set has no address.
	net.DefaultResolver = &net.Resolver{PreferGo: true, Dial: grdDNS.dial}
}

type grdResolver struct {
	mu    sync.Mutex
	names map[string]*grdName
	log   []string // the name of every question, in order
}

// grdName holds the answers of a name: lookup i gets answers[i], and every
// lookup after the last answer gets the last answer again.
type grdName struct {
	answers [][]netip.Addr
	a, aaaa int // the A and AAAA questions asked
}

var grdCount atomic.Int64

// grdHost gives a new name whose lookups give answers.
func grdHost(answers ...[]netip.Addr) (string, *grdName) {
	host := fmt.Sprintf("h%d.grd.test", grdCount.Add(1))
	return host, grdDNS.set(host, answers...)
}

func (r *grdResolver) set(host string, answers ...[]netip.Addr) *grdName {
	n := &grdName{answers: answers}
	r.mu.Lock()
	defer r.mu.Unlock()
	r.names[host] = n
	return n
}

func (r *grdResolver) asked(n *grdName) (a, aaaa int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return n.a, n.aaaa
}

// mark and since give the names of the questions asked after a mark.
func (r *grdResolver) mark() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.log)
}

func (r *grdResolver) since(mark int) []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.log[mark:])
}

func (r *grdResolver) dial(context.Context, string, string) (net.Conn, error) {
	client, server := net.Pipe()
	go r.serve(server)
	return client, nil
}

// serve answers one query. On a connection that is not a PacketConn the
// resolver uses the framing of DNS over TCP: a length of two octets first.
func (r *grdResolver) serve(c net.Conn) {
	defer func() { _ = c.Close() }()
	var size [2]byte
	if _, err := io.ReadFull(c, size[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(size[:]))
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	if a := r.answer(q); a != nil {
		_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
	}
}

// answer is the reply to the query q: the addresses of the asked family of
// a name that a test set, NXDOMAIN for any other name.
func (r *grdResolver) answer(q []byte) []byte {
	var labels []string
	i := 12
	for i < len(q) && q[i] != 0 {
		n := int(q[i])
		if i+1+n >= len(q) {
			return nil
		}
		labels = append(labels, string(q[i+1:i+1+n]))
		i += 1 + n
	}
	if i+5 > len(q) {
		return nil
	}
	qtype := binary.BigEndian.Uint16(q[i+1:])
	addrs, known := r.lookup(strings.ToLower(strings.Join(labels, ".")), qtype)
	rcode := byte(3)
	if known {
		rcode = 0
	}
	// The ID of the query; a response, authoritative, recursion desired and
	// available; the question, then the answers.
	msg := []byte{q[0], q[1], 0x85, 0x80 | rcode, 0, 1}
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(addrs)))
	msg = append(msg, 0, 0, 0, 0)
	msg = append(msg, q[12:i+5]...)
	for _, a := range addrs {
		ip := a.AsSlice()
		// Owner: a pointer to the name of the question; class IN; TTL 60.
		msg = append(msg, 0xc0, 12, byte(qtype>>8), byte(qtype), 0, 1, 0, 0, 0, 60, 0, byte(len(ip)))
		msg = append(msg, ip...)
	}
	return msg
}

func (r *grdResolver) lookup(host string, qtype uint16) ([]netip.Addr, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.log = append(r.log, host)
	n, ok := r.names[host]
	if !ok {
		return nil, false
	}
	var i int
	switch qtype {
	case 1:
		i, n.a = n.a, n.a+1
	case 28:
		i, n.aaaa = n.aaaa, n.aaaa+1
	default:
		return nil, true
	}
	var out []netip.Addr
	for _, a := range n.answers[min(i, len(n.answers)-1)] {
		if a.Is4() == (qtype == 1) {
			out = append(out, a)
		}
	}
	return out, true
}

// grdOneLookup fails the test unless the name was looked up once: one A
// question and at most one AAAA question.
func grdOneLookup(t *testing.T, row string, n *grdName) {
	t.Helper()
	if a, aaaa := grdDNS.asked(n); a != 1 || aaaa > 1 {
		t.Errorf("%s: %d A and %d AAAA questions; want one lookup", row, a, aaaa)
	}
}

// grdPermit permits exactly allow and notes each address that it is asked
// about, in order.
type grdPermit struct {
	mu    sync.Mutex
	allow []netip.Addr
	asked []netip.Addr
}

func (p *grdPermit) permit(a netip.Addr) bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.asked = append(p.asked, a)
	return slices.Contains(p.allow, a)
}

func (p *grdPermit) seen() []netip.Addr {
	p.mu.Lock()
	defer p.mu.Unlock()
	return slices.Clone(p.asked)
}

// grdAddrs reads addresses.
func grdAddrs(s ...string) []netip.Addr {
	var as []netip.Addr
	for _, x := range s {
		as = append(as, netip.MustParseAddr(x))
	}
	return as
}

// Loopback addresses whose first 29 bits are those of 127.0.0.1, the source
// of a connection to them, so that the address sort of the resolver (RFC
// 6724) keeps the order of the answer. Nothing listens on grdDead.
var (
	grdL1   = netip.MustParseAddr("127.0.0.4")
	grdL2   = netip.MustParseAddr("127.0.0.5")
	grdL3   = netip.MustParseAddr("127.0.0.6")
	grdDead = netip.MustParseAddr("127.0.0.7")
)

// grdNo is the failure of a host whose first refused address is a.
func grdNo(a string) string {
	return "network: no permitted address (" + a + ")"
}

// grdCert is a self-signed server certificate for the names and addresses,
// and a pool that trusts it alone.
func grdCert(t *testing.T, names []string, ips ...net.IP) (*tls.Config, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "osk test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
		IPAddresses:  ips,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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
	return &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}, pool
}

// grdListen listens on each address, all on one port, and tries another
// port when the first one is taken on a later address.
func grdListen(t *testing.T, addrs []string) []net.Listener {
	t.Helper()
	for range 5 {
		port := "0"
		var ls []net.Listener
		for _, a := range addrs {
			l, err := net.Listen("tcp", net.JoinHostPort(a, port))
			if err != nil {
				break
			}
			ls = append(ls, l)
			port = strconv.Itoa(int(grdPortOf(l)))
		}
		if len(ls) == len(addrs) {
			return ls
		}
		for _, l := range ls {
			_ = l.Close()
		}
	}
	t.Fatalf("cannot listen on one port of each of %v", addrs)
	return nil
}

func grdPortOf(l net.Listener) uint16 {
	return uint16(l.Addr().(*net.TCPAddr).Port)
}

// grdServer counts the connections that a server accepts and the requests
// it answers, and keeps the Host header and the TLS server name of the last.
type grdServer struct {
	conns, requests atomic.Int64
	mu              sync.Mutex
	host, name      string
}

func (s *grdServer) last() (host, name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.host, s.name
}

// grdServe starts a TLS server with the certificate of cfg on each address,
// all on one port, and gives that port and the servers by address.
func grdServe(t *testing.T, cfg *tls.Config, addrs ...string) (uint16, map[string]*grdServer) {
	t.Helper()
	ls := grdListen(t, addrs)
	return grdPortOf(ls[0]), grdServeOn(t, cfg, ls)
}

func grdServeOn(t *testing.T, cfg *tls.Config, ls []net.Listener) map[string]*grdServer {
	t.Helper()
	servers := map[string]*grdServer{}
	for _, l := range ls {
		s := &grdServer{}
		srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.requests.Add(1)
			s.mu.Lock()
			s.host, s.name = r.Host, r.TLS.ServerName
			s.mu.Unlock()
			_, _ = io.WriteString(w, "ok")
		}))
		_ = srv.Listener.Close()
		srv.Listener = l
		srv.Config.ConnState = func(_ net.Conn, st http.ConnState) {
			if st == http.StateNew {
				s.conns.Add(1)
			}
		}
		// Refused handshakes are the point of some rows; their log is noise.
		srv.Config.ErrorLog = log.New(io.Discard, "", 0)
		srv.TLS = cfg
		srv.StartTLS()
		t.Cleanup(srv.Close)
		servers[l.Addr().(*net.TCPAddr).AddrPort().Addr().Unmap().String()] = s
	}
	return servers
}

func grdConns(servers map[string]*grdServer) map[string]int64 {
	m := map[string]int64{}
	for a, s := range servers {
		m[a] = s.conns.Load()
	}
	return m
}

// grdOnlyTo fails the test unless the server at to, and no other, got one
// more connection than before; to may be zero for none.
func grdOnlyTo(t *testing.T, row string, servers map[string]*grdServer, before map[string]int64, to netip.Addr) {
	t.Helper()
	for a, n := range grdConns(servers) {
		want := before[a]
		if to.IsValid() && a == to.String() {
			want++
		}
		if n != want {
			t.Errorf("%s: %s got %d connections; want %d", row, a, n-before[a], want-before[a])
		}
	}
}

// grdGetIn asks https://host:port/x through a guarded client that trusts
// pool, within d.
func grdGetIn(d time.Duration, host string, port uint16, pool *x509.CertPool, permit func(netip.Addr) bool) (Response, error) {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	defer cancel()
	hp := net.JoinHostPort(host, strconv.Itoa(int(port)))
	return NewGuarded([]string{hp}, pool, permit).Get(ctx, "https://"+hp+"/x", 100)
}

func grdGet(host string, port uint16, pool *x509.CertPool, permit func(netip.Addr) bool) (Response, error) {
	return grdGetIn(5*time.Second, host, port, pool, permit)
}

// grdWant checks the outcome of a Get: status 200 from to, or, when to is
// zero, an error of exactly the text want. A refusal is also ErrNotPermitted.
func grdWant(t *testing.T, row string, resp Response, err error, port uint16, to netip.Addr, want string) {
	t.Helper()
	if to.IsValid() {
		if from := netip.AddrPortFrom(to, port); err != nil || resp.Status != http.StatusOK || resp.Addr != from {
			t.Errorf("%s: status %d from %v, %v; want 200 from %v", row, resp.Status, resp.Addr, err, from)
		}
		return
	}
	refusal := strings.HasPrefix(want, ErrNotPermitted.Error())
	if err == nil || err.Error() != want || errors.Is(err, ErrNotPermitted) != refusal || resp.Addr.IsValid() {
		t.Errorf("%s: %v, address %v; want %q and no address", row, err, resp.Addr, want)
	}
}

// grdClientGoroutines counts the goroutines of the client side of net/http
// and of guardedDial.
func grdClientGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "net/http.(*Transport)") || strings.Contains(g, "persistConn") || strings.Contains(g, "httpclient.guardedDial") {
			n++
		}
	}
	return n
}

// grdNoneLeft fails the test when goroutines of the client are still there
// two seconds after a request ended.
func grdNoneLeft(t *testing.T, row string, before int) {
	t.Helper()
	n := grdClientGoroutines()
	for deadline := time.Now().Add(2 * time.Second); n > before && time.Now().Before(deadline); n = grdClientGoroutines() {
		time.Sleep(10 * time.Millisecond)
	}
	if n > before {
		t.Errorf("%s: %d goroutines of the client after the request, %d before", row, n, before)
	}
}

// The client dials only the addresses that permit accepts, in the order of
// the lookup, and stops at the first that answers. A refused address gets no
// connection, also after a permitted one failed; a permitted address that
// does not answer gives a failed connection, not "no permitted address".
// With no permitted address the failure names the first refused one.
func TestGrdDialsOnlyPermittedAddressesInOrder(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	port, servers := grdServe(t, cfg, grdL1.String(), grdL2.String(), grdL3.String())
	l1, l2, l3, dead := grdL1, grdL2, grdL3, grdDead
	type addrs = []netip.Addr
	for _, r := range []struct {
		name          string
		answer, allow addrs
		asked         addrs      // the addresses that permit is asked about, in order
		to            netip.Addr // the server that gets the request; zero for none
		err           string
	}{
		{"refused, then permitted", addrs{l1, l2}, addrs{l2}, addrs{l1, l2}, l2, ""},
		{"permitted, then refused", addrs{l2, l1}, addrs{l2}, addrs{l2}, l2, ""},
		{"all refused", addrs{l1, l3}, nil, addrs{l1, l3}, netip.Addr{}, grdNo("127.0.0.4")},
		{"all refused, the other order", addrs{l3, l1}, nil, addrs{l3, l1}, netip.Addr{}, grdNo("127.0.0.6")},
		{"permitted without answer, then refused", addrs{dead, l1}, addrs{dead}, addrs{dead, l1}, netip.Addr{}, errConnect.Error()},
		{"refused, then permitted without answer", addrs{l1, dead}, addrs{dead}, addrs{l1, dead}, netip.Addr{}, errConnect.Error()},
		{"permitted without answer, permitted, refused", addrs{dead, l2, l1}, addrs{dead, l2}, addrs{dead, l2}, l2, ""},
		{"two permitted", addrs{l2, l3}, addrs{l2, l3}, addrs{l2}, l2, ""},
		{"refused and permitted in turn", addrs{l1, dead, l3, l2}, addrs{dead, l2}, addrs{l1, dead, l3, l2}, l2, ""},
	} {
		host, name := grdHost(r.answer)
		p := &grdPermit{allow: r.allow}
		before := grdConns(servers)
		resp, err := grdGet(host, port, pool, p.permit)
		grdWant(t, r.name, resp, err, port, r.to, r.err)
		if got := p.seen(); !slices.Equal(got, r.asked) {
			t.Errorf("%s: permit was asked about %v; want %v", r.name, got, r.asked)
		}
		grdOnlyTo(t, r.name, servers, before, r.to)
		grdOneLookup(t, r.name, name)
	}
}

// The address that permit accepts is the address that is dialled: the name
// is looked up once, so a later answer of the resolver, which a second
// lookup would get, changes nothing.
func TestGrdLooksUpOnce(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	port, servers := grdServe(t, cfg, grdL1.String(), grdL2.String())
	for _, r := range []struct {
		name  string
		allow []netip.Addr
		to    netip.Addr
	}{
		{"the later answer is permitted too", []netip.Addr{grdL1, grdL2}, grdL1},
		{"the later answer is refused", []netip.Addr{grdL1}, grdL1},
		{"only the later answer is permitted", []netip.Addr{grdL2}, netip.Addr{}},
	} {
		host, name := grdHost([]netip.Addr{grdL1}, []netip.Addr{grdL2})
		p := &grdPermit{allow: r.allow}
		before := grdConns(servers)
		resp, err := grdGet(host, port, pool, p.permit)
		grdWant(t, r.name, resp, err, port, r.to, grdNo("127.0.0.4"))
		if got := p.seen(); !slices.Equal(got, []netip.Addr{grdL1}) {
			t.Errorf("%s: permit was asked about %v; want only the first answer %v", r.name, got, grdL1)
		}
		grdOnlyTo(t, r.name, servers, before, r.to)
		grdOneLookup(t, r.name, name)
	}
}

// The resolver gives an IPv4 address in the IPv4-mapped form. permit judges
// the IPv4 address, which is where the connection goes and which a refusal
// names: for an A answer, for an AAAA answer of the mapped form and for a
// literal of either form. An address with a zone is dialled and named
// without it.
func TestGrdJudgesTheAddressItDials(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	port, servers := grdServe(t, cfg, grdL1.String())
	mapped := netip.AddrFrom16(grdL1.As16())
	for _, r := range []struct {
		name   string
		answer netip.Addr
		allow  []netip.Addr
		to     netip.Addr
	}{
		{"an A answer", grdL1, []netip.Addr{grdL1}, grdL1},
		{"an AAAA answer of the mapped form", mapped, []netip.Addr{grdL1}, grdL1},
		{"an AAAA answer of the mapped form, refused", mapped, nil, netip.Addr{}},
	} {
		host, name := grdHost([]netip.Addr{r.answer})
		p := &grdPermit{allow: r.allow}
		before := grdConns(servers)
		resp, err := grdGet(host, port, pool, p.permit)
		grdWant(t, r.name, resp, err, port, r.to, grdNo("127.0.0.4"))
		if got := p.seen(); !slices.Equal(got, []netip.Addr{grdL1}) {
			t.Errorf("%s: permit was asked about %v; want %v", r.name, got, grdL1)
		}
		grdOnlyTo(t, r.name, servers, before, r.to)
		grdOneLookup(t, r.name, name)
	}
	for _, literal := range []netip.Addr{grdL1, mapped} {
		p := &grdPermit{allow: []netip.Addr{grdL1}}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		c, err := guardedDial(p.permit)(ctx, "tcp", net.JoinHostPort(literal.String(), strconv.Itoa(int(port))))
		cancel()
		if err != nil {
			t.Errorf("a dial of the literal %v: %v", literal, err)
			continue
		}
		if got := c.RemoteAddr().String(); got != netip.AddrPortFrom(grdL1, port).String() {
			t.Errorf("a dial of the literal %v went to %s", literal, got)
		}
		_ = c.Close()
		if got := p.seen(); !slices.Equal(got, []netip.Addr{grdL1}) {
			t.Errorf("a dial of the literal %v: permit was asked about %v; want %v", literal, got, grdL1)
		}
	}
	for _, c := range []struct{ literal, want string }{
		{"::ffff:10.0.0.1", "10.0.0.1"},
		{"fe80::1%lo", "fe80::1"},
		{"fe80::1%eth0", "fe80::1"},
	} {
		p := &grdPermit{}
		_, err := guardedDial(p.permit)(context.Background(), "tcp", net.JoinHostPort(c.literal, "443"))
		if err == nil || err.Error() != grdNo(c.want) || !errors.Is(err, ErrNotPermitted) {
			t.Errorf("a refused dial of the literal %s: %v; want %q", c.literal, err, grdNo(c.want))
		}
		if got := p.seen(); len(got) != 1 || got[0].String() != c.want {
			t.Errorf("a refused dial of the literal %s: permit was asked about %v; want %s", c.literal, got, c.want)
		}
	}
}

// The TLS check stays on the name of the URL, whatever address the name led
// to: a certificate for another name, or for the address alone, fails, and
// its server gets no request.
func TestGrdTLSNameStaysTheHost(t *testing.T) {
	const host = "mta-sts.corp.test"
	grdDNS.set(host, []netip.Addr{grdL1})
	permit := func(a netip.Addr) bool { return a == grdL1 }
	for _, r := range []struct {
		name  string
		names []string
		ips   []net.IP
		ok    bool
	}{
		{"a certificate for the host", []string{host}, nil, true},
		{"a certificate for another name", []string{"mta-sts.evil.test"}, nil, false},
		{"a certificate for the address alone", nil, []net.IP{grdL1.AsSlice()}, false},
	} {
		cfg, pool := grdCert(t, r.names, r.ips...)
		port, servers := grdServe(t, cfg, grdL1.String())
		resp, err := grdGet(host, port, pool, permit)
		got := servers[grdL1.String()].requests.Load()
		if r.ok && (err != nil || resp.Status != http.StatusOK || got != 1) {
			t.Errorf("%s: status %d, %v, %d requests; want 200 and one request", r.name, resp.Status, err, got)
		}
		if !r.ok && (!errors.Is(err, errCert) || resp.Addr.IsValid() || got != 0) {
			t.Errorf("%s: %v, address %v, %d requests; want %q, no address and no request", r.name, err, resp.Addr, got, errCert)
		}
	}
}

// A name with a dot is asked as it is, never with a domain of the search
// list after it. The Host header and the TLS server name keep the name of
// the URL, without the final dot. An IP literal is no question at all, and
// a name of one label is found in /etc/hosts as before.
func TestGrdLooksUpTheNameAsItIs(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test", "localhost"}, grdL1.AsSlice())
	port, servers := grdServe(t, cfg, grdL1.String(), "127.0.0.1")
	allow := &grdPermit{allow: []netip.Addr{grdL1, netip.MustParseAddr("127.0.0.1")}}

	host, _ := grdHost([]netip.Addr{grdL1})
	mark := grdDNS.mark()
	resp, err := grdGet(host, port, pool, allow.permit)
	grdWant(t, "a name", resp, err, port, grdL1, "")
	if got := grdDNS.since(mark); len(got) == 0 || slices.ContainsFunc(got, func(n string) bool { return n != host }) {
		t.Errorf("a name: the questions asked %q; want only %s", got, host)
	}
	hp := net.JoinHostPort(host, strconv.Itoa(int(port)))
	if h, name := servers[grdL1.String()].last(); h != hp || name != host {
		t.Errorf("a name: Host %q, TLS server name %q; want %q and %q", h, name, hp, host)
	}

	// A name with no address is asked once more by a resolver that uses a
	// search list; the guard asks for it as it is.
	missing := fmt.Sprintf("nx%d.grd.test", grdCount.Add(1))
	mark = grdDNS.mark()
	_, err = grdGet(missing, port, pool, allow.permit)
	if err == nil || err.Error() != errLookup.Error() {
		t.Errorf("a name with no address: %v; want %q", err, errLookup)
	}
	if got := grdDNS.since(mark); len(got) == 0 || slices.ContainsFunc(got, func(n string) bool { return n != missing }) {
		t.Errorf("a name with no address: the questions asked %q; want only %s", got, missing)
	}
	control := fmt.Sprintf("nx%d.grd.test", grdCount.Add(1))
	mark = grdDNS.mark()
	_, _ = net.DefaultResolver.LookupNetIP(context.Background(), "ip", control)
	t.Logf("a lookup of %s without the final dot asks %q here", control, grdDNS.since(mark))

	// The error of the resolver names the host as it was given: a name with
	// a dot gets one final dot, a name of one label none.
	dotted := fmt.Sprintf("nx%d.grd.test", grdCount.Add(1))
	single := fmt.Sprintf("nx%d", grdCount.Add(1))
	for _, c := range []struct{ host, asked string }{{dotted, dotted + "."}, {single, single}} {
		_, err := guardedDial(allow.permit)(context.Background(), "tcp", net.JoinHostPort(c.host, "443"))
		var dnsErr *net.DNSError
		if !errors.As(err, &dnsErr) || dnsErr.Name != c.asked {
			t.Errorf("a dial of %s: %v; want a failed lookup of %q", c.host, err, c.asked)
		}
	}

	mark = grdDNS.mark()
	resp, err = grdGet(grdL1.String(), port, pool, allow.permit)
	grdWant(t, "an IP literal", resp, err, port, grdL1, "")
	if got := grdDNS.since(mark); len(got) != 0 {
		t.Errorf("an IP literal: the questions asked %q; want none", got)
	}

	resp, err = grdGet("localhost", port, pool, allow.permit)
	grdWant(t, "localhost", resp, err, port, netip.MustParseAddr("127.0.0.1"), "")
	lp := net.JoinHostPort("localhost", strconv.Itoa(int(port)))
	if h, name := servers["127.0.0.1"].last(); h != lp || name != "localhost" {
		t.Errorf("localhost: Host %q, TLS server name %q; want %q and localhost", h, name, lp)
	}
}

// Only a TCP dial is made; any other network is refused before the lookup
// and before permit is asked.
func TestGrdDialsOnlyTCP(t *testing.T) {
	cfg, _ := grdCert(t, []string{"*.grd.test"})
	port, _ := grdServe(t, cfg, grdL1.String())
	ports := strconv.Itoa(int(port))
	for _, network := range []string{"udp", "udp4", "udp6", "ip", "ip4", "ip4:tcp", "unix", "unixgram", "unixpacket", "", "TCP", "tcp "} {
		host, name := grdHost([]netip.Addr{grdL1})
		p := &grdPermit{allow: []netip.Addr{grdL1}}
		c, err := guardedDial(p.permit)(context.Background(), network, net.JoinHostPort(host, ports))
		if err == nil {
			_ = c.Close()
			t.Errorf("network %q: a connection; want a refusal", network)
		}
		if a, aaaa := grdDNS.asked(name); a+aaaa != 0 || len(p.seen()) != 0 {
			t.Errorf("network %q: %d questions, permit asked about %v; want neither", network, a+aaaa, p.seen())
		}
	}
	v6 := netip.IPv6Loopback()
	v6port := uint16(0)
	if ls, err := net.Listen("tcp", "[::1]:0"); err == nil {
		v6port = grdPortOf(ls)
		go func() {
			for {
				c, err := ls.Accept()
				if err != nil {
					return
				}
				_ = c.Close()
			}
		}()
		t.Cleanup(func() { _ = ls.Close() })
	}
	for _, r := range []struct {
		network string
		to      netip.Addr
		port    uint16
	}{
		{"tcp", grdL1, port},
		{"tcp4", grdL1, port},
		{"tcp6", v6, v6port},
	} {
		if r.port == 0 {
			t.Logf("%s: nothing can listen on ::1 here", r.network)
			continue
		}
		host, _ := grdHost([]netip.Addr{r.to})
		p := &grdPermit{allow: []netip.Addr{r.to}}
		c, err := guardedDial(p.permit)(context.Background(), r.network, net.JoinHostPort(host, strconv.Itoa(int(r.port))))
		if err != nil {
			t.Errorf("network %s: %v; want a connection", r.network, err)
			continue
		}
		if got := c.RemoteAddr().String(); got != netip.AddrPortFrom(r.to, r.port).String() {
			t.Errorf("network %s: a connection to %s", r.network, got)
		}
		_ = c.Close()
	}
}

// At most four permitted addresses are dialled; refused addresses do not
// count, as they get no packet. permit is not asked about the addresses
// after the fourth dial.
func TestGrdDialsAtMostFour(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	// 127.0.0.16 to 127.0.0.31 share their first 27 bits with 127.0.0.1, so
	// the resolver keeps their order; 16 to 19 and 25 to 29 have no server.
	port, servers := grdServe(t, cfg, "127.0.0.20", "127.0.0.21", "127.0.0.22", "127.0.0.23", "127.0.0.24")
	dead := grdAddrs("127.0.0.25", "127.0.0.26", "127.0.0.27", "127.0.0.28", "127.0.0.29")
	refused := grdAddrs("127.0.0.21", "127.0.0.22", "127.0.0.23", "127.0.0.24")
	deadThenLive := grdAddrs("127.0.0.16", "127.0.0.17", "127.0.0.18", "127.0.0.19", "127.0.0.20")
	for _, r := range []struct {
		name          string
		answer, allow []netip.Addr
		asked         []netip.Addr
	}{
		{"five permitted that refuse", dead, dead, dead[:4]},
		{"four refused, then five permitted that refuse", slices.Concat(refused, dead), dead, slices.Concat(refused, dead[:4])},
		{"four permitted that refuse, then one that answers", deadThenLive, deadThenLive, deadThenLive[:4]},
	} {
		host, name := grdHost(r.answer)
		p := &grdPermit{allow: r.allow}
		before := grdConns(servers)
		resp, err := grdGet(host, port, pool, p.permit)
		grdWant(t, r.name, resp, err, port, netip.Addr{}, errConnect.Error())
		if got := p.seen(); !slices.Equal(got, r.asked) {
			t.Errorf("%s: permit was asked about %v; want %v", r.name, got, r.asked)
		}
		grdOnlyTo(t, r.name, servers, before, netip.Addr{})
		grdOneLookup(t, r.name, name)
	}
}

// grdMany is a thousand addresses of 127.b.0.0/16.
func grdMany(b byte) []netip.Addr {
	var as []netip.Addr
	for i := range 1000 {
		as = append(as, netip.AddrFrom4([4]byte{127, b, byte(i >> 8), byte(i)}))
	}
	return as
}

// grdOnceEach reports whether each address of sub is one of of, and no
// address is in sub twice.
func grdOnceEach(sub, of []netip.Addr) bool {
	s := slices.Clone(sub)
	slices.SortFunc(s, netip.Addr.Compare)
	return len(slices.Compact(s)) == len(sub) && !slices.ContainsFunc(sub, func(a netip.Addr) bool { return !slices.Contains(of, a) })
}

// Work is bounded by the answer: a thousand refused addresses end at once
// with no connection and name the first of them, and of a thousand
// permitted addresses that refuse the connection four are dialled. No
// goroutine of the request outlives it.
func TestGrdBoundsOfALargeAnswer(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	refused, closed := grdMany(1), grdMany(2)
	port, servers := grdServe(t, cfg, refused[0].String(), refused[999].String())
	for _, r := range []struct {
		name   string
		answer []netip.Addr
		allow  []netip.Addr
		asked  int
		within time.Duration
	}{
		{"a thousand refused addresses", refused, nil, 1000, 3 * time.Second},
		{"a thousand permitted addresses that refuse the connection", closed, closed, 4, 3 * time.Second},
	} {
		host, name := grdHost(r.answer)
		p := &grdPermit{allow: r.allow}
		before, goroutines := grdConns(servers), grdClientGoroutines()
		start := time.Now()
		resp, err := grdGet(host, port, pool, p.permit)
		if took := time.Since(start); took > r.within {
			t.Errorf("%s: took %v; want at most %v", r.name, took, r.within)
		}
		got := p.seen()
		if len(got) != r.asked || !grdOnceEach(got, r.answer) {
			t.Errorf("%s: permit was asked about %d addresses; want %d of the answer, each once", r.name, len(got), r.asked)
		}
		want := errConnect.Error()
		if r.allow == nil && len(got) > 0 {
			want = grdNo(got[0].String())
		}
		grdWant(t, r.name, resp, err, port, netip.Addr{}, want)
		grdOnlyTo(t, r.name, servers, before, netip.Addr{})
		grdOneLookup(t, r.name, name)
		grdNoneLeft(t, r.name, goroutines)
	}
}

// grdFill gives each listener an accept queue that one connection fills,
// and never accepts: the kernel then drops each later SYN, so a dial there
// neither opens nor fails until it is given up. It skips the test where the
// kernel does not drop them.
func grdFill(t *testing.T, ls []net.Listener) {
	t.Helper()
	for _, l := range ls {
		t.Cleanup(func() { _ = l.Close() })
		raw, err := l.(*net.TCPListener).SyscallConn()
		if err != nil {
			t.Fatal(err)
		}
		var lerr error
		// A second listen sets the length of the queue; zero holds one.
		if err := raw.Control(func(fd uintptr) { lerr = syscall.Listen(int(fd), 0) }); err != nil || lerr != nil {
			t.Fatal(err, lerr)
		}
		if c, err := net.DialTimeout("tcp", l.Addr().String(), 100*time.Millisecond); err == nil {
			t.Cleanup(func() { _ = c.Close() })
		}
	}
	if c, err := net.DialTimeout("tcp", ls[0].Addr().String(), 100*time.Millisecond); err == nil {
		_ = c.Close()
		t.Skip("this kernel opens a connection to a listener whose queue is full")
	}
}

// Permitted addresses that never answer end the request when its context
// ends, and the dial stops with it: no goroutine of the request outlives it.
func TestGrdBoundsWhenNothingAnswers(t *testing.T) {
	ips := []string{"127.0.0.8", "127.0.0.9", "127.0.0.10", "127.0.0.11"}
	ls := grdListen(t, ips)
	grdFill(t, ls)
	host, name := grdHost(grdAddrs(ips...))
	hp := net.JoinHostPort(host, strconv.Itoa(int(grdPortOf(ls[0]))))
	goroutines := grdClientGoroutines()
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := NewGuarded([]string{hp}, nil, func(netip.Addr) bool { return true }).Get(ctx, "https://"+hp+"/x", 100)
	if took := time.Since(start); !errors.Is(err, ErrTimeout) || took > 2*time.Second {
		t.Errorf("%v after %v; want %q soon after 300ms", err, took, ErrTimeout)
	}
	grdOneLookup(t, "silent addresses", name)
	grdNoneLeft(t, "silent addresses", goroutines)
}

// A first address that never answers is given up after addrTimeout, and the
// next one gets the request: the dead one does not take the whole request.
func TestGrdBoundPerAddress(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	// Both share their first 28 bits with 127.0.0.1; the resolver keeps their order.
	ls := grdListen(t, []string{"127.0.0.8", "127.0.0.9"})
	grdFill(t, ls[:1])
	servers := grdServeOn(t, cfg, ls[1:])
	port := grdPortOf(ls[0])
	host, _ := grdHost(grdAddrs("127.0.0.8", "127.0.0.9"))
	p := &grdPermit{allow: grdAddrs("127.0.0.8", "127.0.0.9")}
	start := time.Now()
	resp, err := grdGetIn(20*time.Second, host, port, pool, p.permit)
	took := time.Since(start)
	grdWant(t, "a dead first address", resp, err, port, netip.MustParseAddr("127.0.0.9"), "")
	if took < addrTimeout-500*time.Millisecond || took > addrTimeout+2*time.Second {
		t.Errorf("the request took %v; want about %v", took, addrTimeout)
	}
	if n := servers["127.0.0.9"].requests.Load(); n != 1 {
		t.Errorf("the second address got %d requests; want one", n)
	}
}

// HostOf takes a host that reads back the same: a name of letters, digits,
// "-", "_" and "." with no empty label, or an IP address without a zone, in
// brackets exactly when it is IPv6. A name whose last label is all digits
// is refused, as some resolvers read it as an IPv4 address. A trailing dot
// is an empty label, so it is refused; Host never puts one in the policy
// URL. The port is not judged: a dial to a port above 65535 fails. A refused
// URL fails a guarded Get before any lookup.
func TestGrdHostOfPlainHosts(t *testing.T) {
	for _, c := range []struct{ url, want string }{ // want "": refused
		{"https://[mta-sts.corp.test]/x", ""},
		{"https://[127.0.0.1]/x", ""},
		{"https://[127.0.0.1]:443/x", ""},
		{"https://127.0.0.1/x", "127.0.0.1:443"},
		{"https://1.2.3.4/x", "1.2.3.4:443"},
		{"https://127.1/x", ""},
		{"https://2130706433/x", ""},
		{"https://0x7f.1/x", ""},
		{"https://1.2.3/x", ""},
		{"https://a.1/x", ""},
		{"https://a.b1/x", "a.b1:443"},
		{"https://a.1b/x", "a.1b:443"},
		{"https://[::1]/x", "[::1]:443"},
		{"https://[::ffff:127.0.0.1]/x", "[::ffff:127.0.0.1]:443"},
		{"https://::1/x", ""},
		{"https://2001:db8::1/x", ""},
		{"https://[]/x", ""},
		{"https://[fe80::1%25eth0]/x", ""},
		{"https://[::1%25lo]:8443/x", ""},
		{"https://a%25b.test/x", ""},
		{"https://a%2Db.test/x", ""},
		{"https://a b.test/x", ""},
		{"https://a\x01b.test/x", ""},
		{"https://a\x7fb.test/x", ""},
		{"https://a*b.test/x", ""},
		{"https://a~b.test/x", ""},
		{"https://a..b.test/x", ""},
		{"https://.corp.test/x", ""},
		{"https://mta-sts.corp.test./x", ""},
		{"https://mta-sts.corp.test/x", "mta-sts.corp.test:443"},
		{"https://-x.corp.test/x", "-x.corp.test:443"},
		{"https://mta-sts._x.corp.test/x", "mta-sts._x.corp.test:443"},
		{"https://MTA-STS.Corp.TEST/x", "mta-sts.corp.test:443"},
		{"https://h.test:0/x", "h.test:0"},
		{"https://h.test:65535/x", "h.test:65535"},
		{"https://h.test:65536/x", "h.test:65536"},
		{"https://h.test:/x", "h.test:443"},
	} {
		got, err := HostOf(c.url)
		if c.want != "" {
			if err != nil || got != c.want {
				t.Errorf("HostOf(%q) = %q, %v; want %q", c.url, got, err, c.want)
			}
			continue
		}
		if !errors.Is(err, ErrURL) || got != "" {
			t.Errorf("HostOf(%q) = %q, %v; want ErrURL", c.url, got, err)
		}
		p := &grdPermit{}
		_, err = NewGuarded([]string{"mta-sts.corp.test:443"}, nil, p.permit).Get(context.Background(), c.url, 100)
		if !errors.Is(err, ErrURL) || len(p.seen()) != 0 {
			t.Errorf("a guarded Get of %q: %v, permit asked about %v; want ErrURL before any lookup", c.url, err, p.seen())
		}
	}
}

// New makes the client of the Slack channel, the webhooks, the heartbeat
// and the certificate source. Their hosts are the ones the operator wrote,
// so it connects wherever they lead, loopback included. Only the policy
// fetch, whose host the zone of a watched domain chooses, uses NewGuarded.
func TestGrdOtherClientsAreNotGuarded(t *testing.T) {
	cfg, pool := grdCert(t, []string{"*.grd.test"})
	port, servers := grdServe(t, cfg, grdL1.String())
	host, _ := grdHost([]netip.Addr{grdL1})
	hp := net.JoinHostPort(host, strconv.Itoa(int(port)))
	resp, err := New([]string{hp}, pool).Get(context.Background(), "https://"+hp+"/x", 100)
	if err != nil || resp.Status != http.StatusOK {
		t.Errorf("New to a loopback address: status %d, %v; want 200", resp.Status, err)
	}
	_, err = NewGuarded([]string{hp}, pool, func(netip.Addr) bool { return false }).Get(context.Background(), "https://"+hp+"/x", 100)
	if !errors.Is(err, ErrNotPermitted) {
		t.Errorf("NewGuarded refusing every address: %v; want %q", err, ErrNotPermitted)
	}
	if n := servers[grdL1.String()].requests.Load(); n != 1 {
		t.Errorf("the server got %d requests; want the one of New", n)
	}
	if New(nil, nil).http.Transport.(*http.Transport).DialContext != nil {
		t.Error("New dials through a guard")
	}
}
