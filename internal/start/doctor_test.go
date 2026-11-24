package start

import (
	"bytes"
	"cmp"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// The tests run doctor against a fake root server and fake webhook services
// on 127.0.0.1, which a config in a private folder names. They run one at a
// time: each sets doctorRoots, the trust store of doctor, for its services.

// The lines that hold for every run, as doctor prints them.
const (
	docFilesOK = "ok   files: no other user can change the config or the expectations, or read the secrets or the state"
	docProxy   = "FAIL dns: The network between this machine and the DNS root servers answers DNS queries itself " +
		"(a VPN, router or provider does this). osk-dns-watcher must reach the root servers directly on port 53, over UDP and TCP. " +
		"Run osk-dns-watcher on another network or machine."
	docClockSkip = "skip clock: no webhook answered, so there is no outside time to compare with"
	docUsage     = "usage: osk-dns-watcher doctor --config <file> [--json]"
	docFrom      = "from      osk-dns-watcher doctor"
)

func docDNSOK(domain string) string {
	return "ok   dns " + domain + ": its parent zone answers; osk-dns-watcher found it from the root servers, without this machine's resolver"
}

func docDNSFail(domain, words string) string {
	return "FAIL dns " + domain + ": no answer from the root servers or its parent zone (" + words +
		"). osk-dns-watcher asks them itself on port 53, over UDP and TCP: allow that traffic to the internet."
}

func docSent(channel, host string) string {
	return "ok   webhook " + channel + ": " + host + " answered 200; a test message from osk-dns-watcher doctor was sent"
}

// docAnswered is the line of a channel whose service answered with a status
// other than 2xx; status holds the error word of the answer when it shows.
func docAnswered(channel, host, status, where string) string {
	return "FAIL webhook " + channel + ": " + host + " answered " + status + ". Check the URL in " + where +
		": a deleted or revoked webhook answers like this."
}

func docNoAnswer(channel, host, reason string) string {
	return "FAIL webhook " + channel + ": no answer from " + host + ": " + reason +
		". Check that this machine can reach " + host + " over HTTPS."
}

// docClockFail is the line of a clock that is off; <d> stands for the
// difference, which docSettleClock checks.
func docClockFail(direction, host string) string {
	return "FAIL clock: this machine is <d> " + direction + " " + host +
		". Set its clock, for example with NTP: webhook signatures and alert times depend on it."
}

func docClockOK(host string) string { return "ok   clock: <d> from the time of " + host }

func docWritable(path string) string {
	return "FAIL files: other users can change " + path + ". Run: chmod go-w " + path
}

func docReadable(path string) string {
	return "FAIL files: other users can read or change " + path + ", which holds a secret. Run: chmod 600 " + path
}

func docOpenState(dir string) string {
	return "FAIL files: " + dir + " is open to other users. Run: chmod 700 " + dir
}

func docSummary(problems int) string {
	switch problems {
	case 0:
		return "doctor: no problems"
	case 1:
		return "doctor: 1 problem"
	}
	return "doctor: " + strconv.Itoa(problems) + " problems"
}

// docCert is the certificate of the trusted test services, and docRoots a
// trust store that holds it alone.
var docCert, docRoots = docNewCert()

func docNewCert() (tls.Certificate, *x509.CertPool) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	now := time.Now()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "osk-dns-watcher doctor test"},
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(24 * time.Hour),
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// docDNS is a fake DNS server on one port of 127.0.0.1, the only root server
// of a test. It answers for the root with authority, as a root server does,
// and with authority for corp.test. and shop.test., so that the walk of a
// check ends at it and never reaches their glue, which nothing answers.
type docDNS struct {
	addr   string
	proxy  string // how it answers for the root as a DNS proxy would; "" as a root server
	refuse string // a domain it refuses
	mu     sync.Mutex
	asked  []string // "<name> <type>" of each query, the name in lower case
}

// The proxies: the root's NS set with recursion available, without
// authority, an answer of authority without that set, and no TCP.
var docProxies = []string{"recursion", "no-authority", "no-root-ns", "tcp-closed"}

const (
	docQR      = 0x8000
	docAA      = 0x0400
	docRA      = 0x0080
	docRefused = 5
)

func docStartDNS(t *testing.T, proxy, refuse string) *docDNS {
	t.Helper()
	d := &docDNS{proxy: proxy, refuse: refuse}
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if proxy == "tcp-closed" {
			break
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close()
	}
	if proxy != "tcp-closed" && ln == nil {
		t.Fatal("no port of 127.0.0.1 is free for both UDP and TCP")
	}
	d.addr = pc.LocalAddr().String()
	t.Cleanup(func() {
		_ = pc.Close()
		if ln != nil {
			_ = ln.Close()
		}
	})
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if a := d.answer(buf[:n]); a != nil {
				_, _ = pc.WriteTo(a, from)
			}
		}
	}()
	if ln != nil {
		go func() {
			for {
				c, err := ln.Accept()
				if err != nil {
					return
				}
				d.serveTCP(c)
			}
		}()
	}
	return d
}

func (d *docDNS) serveTCP(c net.Conn) {
	defer func() { _ = c.Close() }()
	var n [2]byte
	if _, err := io.ReadFull(c, n[:]); err != nil {
		return
	}
	q := make([]byte, binary.BigEndian.Uint16(n[:]))
	if _, err := io.ReadFull(c, q); err != nil {
		return
	}
	if a := d.answer(q); a != nil {
		_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
	}
}

func (d *docDNS) answer(raw []byte) []byte {
	m, err := dnswire.Parse(raw)
	if err != nil || len(m.Question) != 1 {
		return nil
	}
	q := m.Question[0]
	name := strings.ToLower(q.Name.String())
	d.mu.Lock()
	d.asked = append(d.asked, name+" "+q.Type.String())
	d.mu.Unlock()
	switch {
	case name == "." && q.Type == dnswire.TypeNS:
		flags, set := uint16(docQR|docAA), []dnswire.Record{docRR(".", dnswire.NS{Host: docName("root-ns.test.")})}
		switch d.proxy {
		case "recursion":
			flags |= docRA
		case "no-authority":
			flags = docQR
		case "no-root-ns":
			set = nil
		}
		return docDNSAnswer(raw, q, flags, set, nil)
	case name == d.refuse:
	case (name == "corp.test." || name == "shop.test.") && q.Type == dnswire.TypeNS:
		ns := []dnswire.Record{
			docRR(name, dnswire.NS{Host: docName("ns1." + name)}),
			docRR(name, dnswire.NS{Host: docName("ns2." + name)}),
		}
		glue := []dnswire.Record{
			docRR("ns1."+name, dnswire.A{Addr: netip.MustParseAddr("192.0.2.11")}),
			docRR("ns2."+name, dnswire.A{Addr: netip.MustParseAddr("192.0.2.12")}),
		}
		return docDNSAnswer(raw, q, docQR|docAA, ns, glue)
	}
	return docDNSAnswer(raw, q, docQR|docRefused, nil, nil)
}

// docAsked gives the queries the server received.
func (d *docDNS) docAsked() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return slices.Clone(d.asked)
}

func docName(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func docRR(owner string, data dnswire.RData) dnswire.Record {
	return dnswire.Record{Name: docName(owner), Class: dnswire.ClassINET, TTL: 3600, Data: data}
}

// docDNSAnswer is the answer to the query raw with these flags, whose lowest
// four bits are the rcode.
func docDNSAnswer(raw []byte, q dnswire.Question, flags uint16, answer, additional []dnswire.Record) []byte {
	be := binary.BigEndian
	b := be.AppendUint16(nil, be.Uint16(raw))
	b = be.AppendUint16(b, flags)
	for _, n := range []int{1, len(answer), 0, len(additional)} {
		b = be.AppendUint16(b, uint16(n))
	}
	b = q.Name.AppendWire(b)
	b = be.AppendUint16(b, uint16(q.Type))
	b = be.AppendUint16(b, uint16(q.Class))
	for _, r := range slices.Concat(answer, additional) {
		b = dnswire.AppendRecord(b, r)
	}
	return b
}

// docHook is a fake webhook service: a TLS server on 127.0.0.1 that keeps
// each request and answers as its reply says.
type docHook struct {
	url, host string
	reply     docReply
	conns     atomic.Int32
	mu        sync.Mutex
	got       []docRequest
}

type docRequest struct {
	method, path string
	header       http.Header
	body         []byte
}

// docReply is how a docHook answers. Its Date is the time when it answers,
// moved by clock.
type docReply struct {
	status  int // 0: 200
	body    string
	clock   time.Duration
	noDate  bool
	badDate string
	silent  bool // answers only after the client gave up
	foreign bool // shows a certificate that doctor does not trust
	closed  bool // no service: its port refuses connections
}

func docStartHook(t *testing.T, reply docReply) *docHook {
	t.Helper()
	h := &docHook{reply: reply}
	if reply.closed {
		l, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		h.host = l.Addr().String()
		if err := l.Close(); err != nil {
			t.Fatal(err)
		}
		h.url = "https://" + h.host
		return h
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(h.serve))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			h.conns.Add(1)
		}
	}
	if !reply.foreign {
		srv.TLS = &tls.Config{Certificates: []tls.Certificate{docCert}}
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)
	h.url = srv.URL
	h.host = strings.TrimPrefix(srv.URL, "https://")
	return h
}

func (h *docHook) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	h.got = append(h.got, docRequest{r.Method, r.URL.Path, r.Header.Clone(), body})
	h.mu.Unlock()
	if h.reply.silent {
		// The client leaves at its own limit, which ends this request too;
		// Close of the server waits for every request.
		select {
		case <-r.Context().Done():
		case <-time.After(httpclient.Timeout + 5*time.Second):
		}
		return
	}
	switch {
	case h.reply.noDate:
		// Without this the server adds a Date of its own.
		w.Header()["Date"] = nil
	case h.reply.badDate != "":
		w.Header().Set("Date", h.reply.badDate)
	default:
		w.Header().Set("Date", time.Now().Add(h.reply.clock).UTC().Format(http.TimeFormat))
	}
	w.WriteHeader(cmp.Or(h.reply.status, http.StatusOK))
	_, _ = io.WriteString(w, h.reply.body)
}

func (h *docHook) requests() []docRequest {
	h.mu.Lock()
	defer h.mu.Unlock()
	return slices.Clone(h.got)
}

// docWorld is what a test changes in docStart.
type docWorld struct {
	slack, siem docReply
	proxy       string
	refuse      string
	slackEnv    bool // the Slack URL is in the variable OSK_SLACK_URL, not in a file
}

// docSetup is a config in a private folder: two domains, Slack, the webhook
// siem and a heartbeat, the fake root and services that it names, and its
// secrets, each with a marker of its own.
type docSetup struct {
	dir, config, state string
	expect             [2]string // of corp.test. and shop.test.
	slackFile          string    // "" when OSK_SLACK_URL holds the URL
	siemURLFile        string
	siemKeyFile        string
	beatFile           string
	dns                *docDNS
	slack, siem, beat  *docHook
	markers            []string // in the Slack URL, the siem URL, the siem key and the heartbeat URL
	key                []byte
	from, to           time.Time // around the last run
}

const docConfig = `{
  "state": "state",
  "domains": [
    {"name": "corp.test.", "expect": "corp.test.expect"},
    {"name": "shop.test.", "expect": "shop.test.expect"}
  ],
  "slack": {"url": %s},
  "webhooks": [{"name": "siem", "url": {"file": "siem-url"}, "key": {"file": "siem-key"}}],
  "heartbeat": {"url": {"file": "beat-url"}},
  "network": {"root_servers": [%q], "extra_ranges": ["127.0.0.0/8"]}
}
`

func docStart(t *testing.T, w docWorld) *docSetup {
	t.Helper()
	old := doctorRoots
	doctorRoots = docRoots
	t.Cleanup(func() { doctorRoots = old })
	s := &docSetup{dir: t.TempDir()}
	if err := os.Chmod(s.dir, 0o700); err != nil {
		t.Fatal(err)
	}
	s.dns = docStartDNS(t, w.proxy, w.refuse)
	s.slack, s.siem, s.beat = docStartHook(t, w.slack), docStartHook(t, w.siem), docStartHook(t, docReply{})
	for range 4 {
		s.markers = append(s.markers, docMarker())
	}
	s.key = []byte(s.markers[2] + strings.Repeat("k", 40-len(s.markers[2])))
	slackURL := s.slack.url + "/slack/T0/B0/" + s.markers[0]
	slackSecret := `{"env": "OSK_SLACK_URL"}`
	if w.slackEnv {
		t.Setenv("OSK_SLACK_URL", slackURL)
	} else {
		s.slackFile = s.write(t, "slack-url", slackURL+"\n")
		slackSecret = `{"file": "slack-url"}`
	}
	s.siemURLFile = s.write(t, "siem-url", s.siem.url+"/hook/"+s.markers[1]+"\n")
	s.siemKeyFile = s.write(t, "siem-key", string(s.key))
	s.beatFile = s.write(t, "beat-url", s.beat.url+"/beat/"+s.markers[3]+"\n")
	for i, d := range []string{"corp.test.", "shop.test."} {
		s.expect[i] = s.write(t, d+"expect", "domain "+d+"\n"+d+" NS ns1."+d+" | ns2."+d+"\n"+d+" DS none\n")
	}
	s.state = filepath.Join(s.dir, "state")
	if err := os.Mkdir(s.state, 0o700); err != nil {
		t.Fatal(err)
	}
	docChmod(t, s.state, 0o700)
	s.config = s.write(t, "config.json", fmt.Sprintf(docConfig, slackSecret, s.dns.addr))
	return s
}

// docMarker is a word of lower case letters, as a service's error word may
// be one.
func docMarker() string {
	b := []byte("doc")
	for range 12 {
		b = append(b, byte('a'+mrand.IntN(26)))
	}
	return string(b)
}

// write puts text in a file of the folder, which only its owner may read.
func (s *docSetup) write(t *testing.T, name, text string) string {
	t.Helper()
	path := filepath.Join(s.dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	docChmod(t, path, 0o600)
	return path
}

// docChmod sets the mode as given: the umask only takes bits away at create.
func docChmod(t *testing.T, path string, mode os.FileMode) {
	t.Helper()
	if err := os.Chmod(path, mode); err != nil {
		t.Fatal(err)
	}
}

// edit replaces old by new in the config.
func (s *docSetup) edit(t *testing.T, old, new string) {
	t.Helper()
	data, err := os.ReadFile(s.config)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(data, []byte(old)) {
		t.Fatalf("the config holds no %q", old)
	}
	s.write(t, "config.json", strings.Replace(string(data), old, new, 1))
}

// docDoctor runs doctor and gives its exit code, standard output and
// standard error.
func docDoctor(args ...string) (int, string, string) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	var out, errOut bytes.Buffer
	code := Doctor(ctx, args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// run runs doctor on the config with args. It fails the test when an output
// holds a secret or doctor writes to standard error, and gives the exit code
// and the lines of standard output.
func (s *docSetup) run(t *testing.T, args ...string) (int, []string) {
	t.Helper()
	s.from = time.Now()
	code, out, errOut := docDoctor(append([]string{"--config", s.config}, args...)...)
	s.to = time.Now()
	docNoSecret(t, out+errOut, s.markers)
	if errOut != "" {
		t.Errorf("standard error %q, want nothing", errOut)
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("the output %q does not end with a line end", out)
	}
	return code, strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// check runs doctor as run does and compares its lines with want, the time
// of the clock line as docSettleClock leaves it.
func (s *docSetup) check(t *testing.T, want []string, args ...string) {
	t.Helper()
	code, lines := s.run(t, args...)
	docSame(t, code, docSettleClock(t, lines, s.planted()), want)
}

// planted gives how far the Date of each channel's service runs ahead.
func (s *docSetup) planted() map[string]time.Duration {
	return map[string]time.Duration{s.slack.host: s.slack.reply.clock, s.siem.host: s.siem.reply.clock}
}

func docNoSecret(t *testing.T, text string, markers []string) {
	t.Helper()
	for _, m := range markers {
		if strings.Contains(strings.ToLower(text), m) {
			t.Errorf("the output holds the secret marked %s:\n%s", m, strings.ReplaceAll(text, m, "[marker]"))
		}
	}
}

// docSettleClock checks the difference in the clock line of lines against
// the Date that the host of the line planted, and puts <d> in its place. A
// Date has whole seconds, and doctor compares it with the middle of the time
// the answer took, so the difference shown may be off by up to 2 seconds.
func docSettleClock(t *testing.T, lines []string, planted map[string]time.Duration) []string {
	t.Helper()
	settled := slices.Clone(lines)
	for i, l := range settled {
		var prefix, rest, value, host string
		var ok bool
		if rest, ok = strings.CutPrefix(l, "ok   clock: "); ok {
			prefix = "ok   clock: "
			value, host, _ = strings.Cut(rest, " from the time of ")
		} else if rest, ok = strings.CutPrefix(l, "FAIL clock: this machine is "); ok {
			prefix = "FAIL clock: this machine is "
			var after string
			value, after, _ = strings.Cut(rest, " ")
			after = strings.TrimPrefix(strings.TrimPrefix(after, "ahead of "), "behind ")
			host, _, _ = strings.Cut(after, ". Set its clock")
		} else {
			continue
		}
		want, known := planted[host]
		d, err := time.ParseDuration(value)
		if !known || err != nil || (d-want.Abs()).Abs() > 2*time.Second {
			t.Errorf("clock line %q: want a difference within 2s of %v, from a host that sent a Date", l, want.Abs())
			continue
		}
		settled[i] = prefix + "<d>" + strings.TrimPrefix(rest, value)
	}
	return settled
}

// want gives the lines of a run in which every check passes, but for those
// that change names: each key is the words of a check before its colon, each
// value its lines in place of the passing one, "" for none.
func (s *docSetup) want(t *testing.T, change map[string]string) []string {
	t.Helper()
	c, problems := config.Read(s.config)
	if len(problems) > 0 {
		t.Fatalf("the config of the test has problems: %v", problems)
	}
	var warn []string
	for _, w := range c.Warnings() {
		warn = append(warn, "warn config: "+w)
	}
	if len(warn) != 2 {
		t.Fatalf("the config of the test gives the warnings %q, want two", warn)
	}
	return docLines(t, [][2]string{
		{"config", "ok   config: 2 domains, channels slack,siem"},
		{"warnings", strings.Join(warn, "\n")},
		{"files", docFilesOK},
		{"dns corp.test.", docDNSOK("corp.test.")},
		{"dns shop.test.", docDNSOK("shop.test.")},
		{"webhook slack", docSent("slack", s.slack.host)},
		{"webhook siem", docSent("siem", s.siem.host)},
		{"clock", docClockOK(s.slack.host)},
	}, change)
}

// docLines gives the passing line of each check, or the lines of change,
// then the summary, which counts the FAIL lines.
func docLines(t *testing.T, pass [][2]string, change map[string]string) []string {
	t.Helper()
	var lines []string
	problems := 0
	for _, p := range pass {
		text, ok := change[p[0]]
		if !ok {
			text = p[1]
		}
		if text == "" {
			continue
		}
		for _, l := range strings.Split(text, "\n") {
			lines = append(lines, l)
			if strings.HasPrefix(l, "FAIL ") {
				problems++
			}
		}
	}
	for k := range change {
		if !slices.ContainsFunc(pass, func(p [2]string) bool { return p[0] == k }) {
			t.Fatalf("no check %q to change", k)
		}
	}
	return append(lines, docSummary(problems))
}

// docSame compares the exit code and the lines with want, whose summary
// tells the exit code: 0 only without a problem.
func docSame(t *testing.T, code int, got, want []string) {
	t.Helper()
	wantCode := 1
	if want[len(want)-1] == docSummary(0) {
		wantCode = 0
	}
	if code != wantCode || !slices.Equal(got, want) {
		t.Errorf("exit code %d, lines:\n%s\nwant exit code %d, lines:\n%s",
			code, strings.Join(got, "\n"), wantCode, strings.Join(want, "\n"))
	}
}

// docOnly checks that the service got one connection with one request: a
// JSON POST on path. It gives the request.
func docOnly(t *testing.T, h *docHook, path string) docRequest {
	t.Helper()
	got := h.requests()
	if n := h.conns.Load(); n != 1 || len(got) != 1 {
		t.Fatalf("the service at %s got %d connections and %d requests, want one of each", h.host, n, len(got))
	}
	r := got[0]
	if r.method != http.MethodPost || r.path != path || r.header.Get("Content-Type") != "application/json" {
		t.Errorf("the service at %s got %s %s of %q, want a POST of application/json on the path of its URL",
			h.host, r.method, strings.ReplaceAll(r.path, path, "[the path of the URL]"), r.header.Get("Content-Type"))
	}
	return r
}

// docNoticeAt is the test notice that doctor sends, made at the time at.
func docNoticeAt(at time.Time) store.Notice {
	return store.Notice{Kind: store.NoticeTest, Lines: []string{docFrom}, At: at}
}

func docStrict(data []byte, v any) error {
	d := json.NewDecoder(bytes.NewReader(data))
	d.DisallowUnknownFields()
	return d.Decode(v)
}

// docInRun checks that at, a time in whole seconds, falls in the run from
// from to to.
func docInRun(t *testing.T, at, from, to time.Time) {
	t.Helper()
	if at.Before(from.Truncate(time.Second)) || at.After(to) {
		t.Errorf("the notice was made at %v, not during the run from %v to %v", at, from, to)
	}
}

// checkSlack checks that Slack got one test notice of doctor, made in the
// last run.
func (s *docSetup) checkSlack(t *testing.T) {
	t.Helper()
	r := docOnly(t, s.slack, "/slack/T0/B0/"+s.markers[0])
	docSlackNotice(t, r.body, s.from, s.to)
}

// checkWebhook checks that siem got one signed test notice of doctor, made
// in the last run.
func (s *docSetup) checkWebhook(t *testing.T) {
	t.Helper()
	r := docOnly(t, s.siem, "/hook/"+s.markers[1])
	docWebhookNotice(t, r.body, r.header, s.key, s.from, s.to)
}

// docSlackNotice checks that body is the Slack body of the test notice of
// doctor, made between from and to.
func docSlackNotice(t *testing.T, body []byte, from, to time.Time) {
	t.Helper()
	var m struct {
		Text string `json:"text"`
	}
	if err := docStrict(body, &m); err != nil {
		t.Errorf("the Slack body %q is not an object with a text alone: %v", body, err)
		return
	}
	_, clock, _ := strings.Cut(m.Text, "\n:clock3: ")
	clock, _, _ = strings.Cut(clock, "\n")
	at, err := time.Parse("15:04:05 · 2 Jan 2006 UTC", clock)
	if err != nil {
		t.Errorf("the Slack text has no time line:\n%s", m.Text)
		return
	}
	docInRun(t, at, from, to)
	if want := deliver.NoticeText(docNoticeAt(at)); m.Text != want {
		t.Errorf("the Slack text:\n%s\nwant the test notice:\n%s", m.Text, want)
	}
}

// docWebhookNotice checks that body is the webhook body of the test notice
// of doctor, made between from and to, and signed with key.
func docWebhookNotice(t *testing.T, body []byte, header http.Header, key []byte, from, to time.Time) {
	t.Helper()
	var m struct {
		Schema int      `json:"schema"`
		Type   string   `json:"type"`
		ID     string   `json:"id"`
		At     string   `json:"at"`
		Notice string   `json:"notice"`
		Domain string   `json:"domain"`
		Lines  []string `json:"lines"`
		Text   string   `json:"text"`
	}
	if err := docStrict(body, &m); err != nil {
		t.Errorf("the webhook body %q is not a notice: %v", body, err)
		return
	}
	at, err := time.Parse("2006-01-02T15:04:05Z", m.At)
	if err != nil {
		t.Errorf("the webhook body has the time %q", m.At)
		return
	}
	docInRun(t, at, from, to)
	id, err := hex.DecodeString(m.ID)
	if m.Schema != 1 || m.Type != "notice" || m.Notice != "test" || m.Domain != "" || !slices.Equal(m.Lines, []string{docFrom}) ||
		m.Text != deliver.NoticeText(docNoticeAt(at)) || err != nil || len(id) != 16 || m.ID != strings.ToLower(m.ID) {
		t.Errorf("the webhook body %s is not the test notice of doctor", body)
	}
	if !docVerify(key, body, header, time.Now()) {
		t.Errorf("the signature of the webhook body does not verify: %q, %q",
			header.Get("Osk-Timestamp"), header.Get("Osk-Signature"))
	}
}

// docVerify is what a receiver of the webhook runs.
func docVerify(key, body []byte, h http.Header, now time.Time) bool {
	ts := h.Get("Osk-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec < now.Unix()-300 || sec > now.Unix()+300 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(h.Get("Osk-Signature")))
}

// docFromJSON reads the lines of doctor --json as the lines of its text
// output, after it checks that each is an object of the listed keys alone,
// in their order.
func docFromJSON(t *testing.T, lines []string) []string {
	t.Helper()
	type check struct {
		Type   string `json:"type"`
		Result string `json:"result"`
		Check  string `json:"check"`
		Text   string `json:"text"`
	}
	type total struct {
		Type     string `json:"type"`
		Problems int    `json:"problems"`
	}
	var text []string
	for i, l := range lines {
		var v any = &check{}
		if i == len(lines)-1 {
			v = &total{}
		}
		if err := docStrict([]byte(l), v); err != nil {
			t.Errorf("JSON line %q: %v", l, err)
			continue
		}
		if again, _ := json.Marshal(v); string(again) != l {
			t.Errorf("JSON line %q: want the keys as in %s", l, again)
		}
		switch v := v.(type) {
		case *check:
			if v.Type != "check" {
				t.Errorf("JSON line %q: want type check", l)
			}
			text = append(text, fmt.Sprintf("%-4s %s: %s", v.Result, v.Check, v.Text))
		case *total:
			if v.Type != "result" {
				t.Errorf("JSON line %q: want type result", l)
			}
			text = append(text, docSummary(v.Problems))
		}
	}
	return text
}

// When every check passes, doctor says so in one line each, exits 0, and
// puts exactly one test notice in each channel through its own code, signed
// for the webhook. It posts no heartbeat: that would tell the outside
// service that osk-dns-watcher run is healthy.
func TestDoctorAllPassSendsOneTestNoticePerChannel(t *testing.T) {
	s := docStart(t, docWorld{slackEnv: true})
	s.check(t, s.want(t, nil))
	s.checkSlack(t)
	s.checkWebhook(t)
	if n := s.beat.conns.Load(); n != 0 {
		t.Errorf("the heartbeat service got %d connections, want none", n)
	}
	asked := s.dns.docAsked()
	for _, q := range []string{". NS", "corp.test. NS", "shop.test. NS"} {
		if !slices.Contains(asked, q) {
			t.Errorf("the root server was not asked %q; it got %q", q, asked)
		}
	}
}

// A network that answers for the root servers gives one FAIL dns line, before
// the lines of the channels. No domain line follows, as no answer can be
// trusted; every other check still runs.
func TestDoctorProxyFailsDNSAndSkipsTheDomains(t *testing.T) {
	for _, proxy := range docProxies {
		t.Run(proxy, func(t *testing.T) {
			s := docStart(t, docWorld{proxy: proxy})
			code, lines := s.run(t)
			at, channels := slices.Index(lines, docProxy), slices.Index(lines, docSent("slack", s.slack.host))
			if at < 0 || at != slices.IndexFunc(lines, func(l string) bool { return strings.HasPrefix(l, "FAIL dns") }) ||
				channels >= 0 && at > channels {
				t.Errorf("want one proxy line, before the lines of the channels:\n%s", strings.Join(lines, "\n"))
			}
			// Its place before the channels is open; the rest is not.
			without := func(lines []string) []string {
				return slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return l == docProxy })
			}
			want := s.want(t, map[string]string{"dns corp.test.": docProxy, "dns shop.test.": ""})
			docSame(t, code, without(docSettleClock(t, lines, s.planted())), without(want))
			s.checkSlack(t)
			s.checkWebhook(t)
		})
	}
}

// docConfigProblems gives the FAIL config lines of the config at path, from
// the config reader: those of reading it, else those of its secrets and of
// each expectations file.
func docConfigProblems(t *testing.T, path string) []string {
	t.Helper()
	c, problems := config.Read(path)
	if len(problems) == 0 {
		_, problems = c.Secrets(os.LookupEnv)
		for _, d := range c.Domains {
			_, p := d.Read()
			problems = append(problems, p...)
		}
	}
	var lines []string
	for _, p := range problems {
		lines = append(lines, "FAIL config: "+p.String())
	}
	return lines
}

// A problem of the config is shown as the config reader names it, and then
// nothing else is checked: no channel is posted to and no domain is asked.
func TestDoctorConfigProblemStopsEveryOtherCheck(t *testing.T) {
	cases := []struct {
		name     string
		problems int
		spoil    func(t *testing.T, s *docSetup)
	}{
		{"unknown key", 1, func(t *testing.T, s *docSetup) { s.edit(t, `"state": "state",`, `"state": "state", "slak": 1,`) }},
		{"empty variable", 1, func(t *testing.T, _ *docSetup) { t.Setenv("OSK_SLACK_URL", "") }},
		{"expectations of another domain", 1, func(t *testing.T, s *docSetup) {
			s.write(t, "shop.test.expect", "domain corp.test.\ncorp.test. DS none\n")
		}},
		{"two problems", 2, func(t *testing.T, s *docSetup) {
			t.Setenv("OSK_SLACK_URL", "")
			s.write(t, "corp.test.expect", "domain shop.test.\nshop.test. DS none\n")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := docStart(t, docWorld{slackEnv: true})
			c.spoil(t, s)
			want := docConfigProblems(t, s.config)
			if len(want) != c.problems {
				t.Fatalf("the config reader finds %q, want %d problems", want, c.problems)
			}
			code, lines := s.run(t)
			docSame(t, code, lines, append(want, docSummary(c.problems)))
			s.checkedNothing(t)
		})
	}
}

// A root server that the config takes but the observer refuses is a problem
// of the config, which names it and the observer's reason.
func TestDoctorRootServerThatCannotBeAskedIsAConfigProblem(t *testing.T) {
	s := docStart(t, docWorld{})
	s.edit(t, fmt.Sprintf("%q", s.dns.addr), `"0.0.0.0"`)
	c, problems := config.Read(s.config)
	if len(problems) > 0 {
		t.Fatalf("the config reader refuses 0.0.0.0: %v", problems)
	}
	_, err := observe.New(observe.Config{RootServers: c.RootServers, ExtraRanges: c.ExtraRanges})
	if err == nil {
		t.Fatal("the observer takes the root server 0.0.0.0")
	}
	code, lines := s.run(t)
	docSame(t, code, lines, []string{"FAIL config: " + s.config + ": network.root_servers: " + err.Error(), docSummary(1)})
	s.checkedNothing(t)
}

// checkedNothing fails when a service got a connection or the root server a
// query about a domain.
func (s *docSetup) checkedNothing(t *testing.T) {
	t.Helper()
	for _, h := range []*docHook{s.slack, s.siem, s.beat} {
		if n := h.conns.Load(); n != 0 {
			t.Errorf("the service at %s got %d connections, want none", h.host, n)
		}
	}
	for _, q := range s.dns.docAsked() {
		if q != ". NS" {
			t.Errorf("the root server was asked %q, want no question about a domain", q)
		}
	}
}

// Each file that other users can change, each secret file that they can
// read, and a state folder that they can enter gives its own line, with the
// command that fixes it, and fails alone; several give a line each, in the
// order config, expectations, secrets, state.
func TestDoctorFilesOpenToOtherUsersFailAlone(t *testing.T) {
	cases := []struct {
		name  string
		spoil func(t *testing.T, s *docSetup)
		lines func(s *docSetup) string
	}{
		{"config 0664", func(t *testing.T, s *docSetup) { docChmod(t, s.config, 0o664) },
			func(s *docSetup) string { return docWritable(s.config) }},
		{"config 0602", func(t *testing.T, s *docSetup) { docChmod(t, s.config, 0o602) },
			func(s *docSetup) string { return docWritable(s.config) }},
		{"expectations 0620", func(t *testing.T, s *docSetup) { docChmod(t, s.expect[0], 0o620) },
			func(s *docSetup) string { return docWritable(s.expect[0]) }},
		{"Slack URL 0640", func(t *testing.T, s *docSetup) { docChmod(t, s.slackFile, 0o640) },
			func(s *docSetup) string { return docReadable(s.slackFile) }},
		{"webhook key 0604", func(t *testing.T, s *docSetup) { docChmod(t, s.siemKeyFile, 0o604) },
			func(s *docSetup) string { return docReadable(s.siemKeyFile) }},
		{"heartbeat URL 0610", func(t *testing.T, s *docSetup) { docChmod(t, s.beatFile, 0o610) },
			func(s *docSetup) string { return docReadable(s.beatFile) }},
		{"state 0750", func(t *testing.T, s *docSetup) { docChmod(t, s.state, 0o750) },
			func(s *docSetup) string { return docOpenState(s.state) }},
		{"state 0701", func(t *testing.T, s *docSetup) { docChmod(t, s.state, 0o701) },
			func(s *docSetup) string { return docOpenState(s.state) }},
		{"state not a folder", func(t *testing.T, s *docSetup) {
			if err := os.Remove(s.state); err != nil {
				t.Fatal(err)
			}
			s.write(t, "state", "")
		}, func(s *docSetup) string { return "FAIL files: " + s.state + " is not a folder" }},
		{"all at once", func(t *testing.T, s *docSetup) {
			docChmod(t, s.state, 0o755)
			docChmod(t, s.siemURLFile, 0o644)
			docChmod(t, s.expect[1], 0o666)
			docChmod(t, s.config, 0o664)
		}, func(s *docSetup) string {
			return strings.Join([]string{docWritable(s.config), docWritable(s.expect[1]), docReadable(s.siemURLFile),
				docOpenState(s.state)}, "\n")
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := docStart(t, docWorld{})
			c.spoil(t, s)
			s.check(t, s.want(t, map[string]string{"files": c.lines(s)}))
		})
	}
}

// The config and the expectations hold no secret, so others may read them,
// and a state folder that does not exist yet is no problem.
func TestDoctorFilesReadableConfigAndNoStatePass(t *testing.T) {
	s := docStart(t, docWorld{})
	for _, path := range []string{s.config, s.expect[0], s.expect[1]} {
		docChmod(t, path, 0o644)
	}
	if err := os.Remove(s.state); err != nil {
		t.Fatal(err)
	}
	s.check(t, s.want(t, nil))
}

// A domain whose parent zone gives no answer fails alone, with the reason of
// the answer; the other domain passes.
func TestDoctorDNSFailsAloneForThatDomain(t *testing.T) {
	s := docStart(t, docWorld{refuse: "shop.test."})
	s.check(t, s.want(t, map[string]string{"dns shop.test.": docDNSFail("shop.test.", "refused")}))
}

// One warning counts each address of every domain that this machine has no
// route to, once. A domain with no usable answer fails on its own line, and
// a network failure is no lack of route, so neither adds to the count.
func TestDoctorWarnsOnceOfAddressesWithNoRoute(t *testing.T) {
	ns := iniRecords("example.com.", dnswire.TypeNS, "ns1.example.net.")
	noRoute := func(addr string) obs.Answer { return iniAt("a.gtld.example.", addr, iniFail(obs.ReasonNoRoute)) }
	com := obs.Observation{Answers: []obs.Answer{iniAt("a.gtld.example.", "192.0.2.1:53", ns), noRoute(iniNS1v6Addr), noRoute(iniNS2v6Addr)}}
	org := obs.Observation{Answers: []obs.Answer{iniAt("a.gtld.example.", "192.0.2.1:53", ns), noRoute(iniNS1v6Addr)}}
	v4 := obs.Observation{Answers: []obs.Answer{iniAt("a.gtld.example.", "192.0.2.1:53", ns), noRoute("192.0.2.9:53")}}
	dead := obs.Observation{Answers: []obs.Answer{noRoute("[2001:db8::99]:53")}}
	network := obs.Observation{Answers: []obs.Answer{iniAt("a.gtld.example.", "192.0.2.1:53", ns),
		iniAt("a.gtld.example.", "[2001:db8::98]:53", iniFail(obs.ReasonNetwork))}}
	warn := func(count string) string {
		return "this machine has no route to " + count + " of the servers. osk-dns-watcher cannot ask them. " +
			"A check counts as OK when the other servers answer."
	}
	for _, c := range []struct {
		name         string
		observations []obs.Observation
		want         string // "" for no warning
	}{
		{"two domains share an address", []obs.Observation{com, org, dead, network}, warn("2 IPv6 addresses")},
		{"one address", []obs.Observation{org}, warn("1 IPv6 address")},
		{"an IPv4 address too", []obs.Observation{com, v4}, warn("3 addresses")},
		{"no usable answer", []obs.Observation{dead}, ""},
		{"a network failure", []obs.Observation{network}, ""},
	} {
		res, ok := noRouteResult(c.observations)
		switch {
		case c.want == "" && ok:
			t.Errorf("%s: %+v, want no warning", c.name, res)
		case c.want != "" && (!ok || res != newResult("warn", "dns", c.want)):
			t.Errorf("%s: %+v (%v), want the warning %q", c.name, res, ok, c.want)
		}
	}
}

// A service that answers with a status other than 2xx fails its channel
// alone. The line shows the body only when it is one of Slack's error words,
// and names where the URL is set.
func TestDoctorWebhookAnswerFailsAlone(t *testing.T) {
	cases := []struct {
		name        string
		slack, siem docReply
		line        func(s *docSetup) (check, line string)
	}{
		{"error word", docReply{status: 404, body: "no_service"}, docReply{}, func(s *docSetup) (string, string) {
			return "webhook slack", docAnswered("slack", s.slack.host, `404 "no_service"`, "file "+s.slackFile)
		}},
		{"error word and line end", docReply{status: 403, body: "invalid_token\n"}, docReply{}, func(s *docSetup) (string, string) {
			return "webhook slack", docAnswered("slack", s.slack.host, `403 "invalid_token"`, "file "+s.slackFile)
		}},
		{"no body", docReply{status: 500}, docReply{}, func(s *docSetup) (string, string) {
			return "webhook slack", docAnswered("slack", s.slack.host, "500", "file "+s.slackFile)
		}},
		{"page", docReply{status: 404, body: "<html>no such hook</html>"}, docReply{}, func(s *docSetup) (string, string) {
			return "webhook slack", docAnswered("slack", s.slack.host, "404", "file "+s.slackFile)
		}},
		{"redirect", docReply{status: 302}, docReply{}, func(s *docSetup) (string, string) {
			return "webhook slack", docAnswered("slack", s.slack.host, "302", "file "+s.slackFile)
		}},
		{"webhook gone", docReply{}, docReply{status: 410, body: "gone"}, func(s *docSetup) (string, string) {
			return "webhook siem", docAnswered("siem", s.siem.host, "410", "file "+s.siemURLFile)
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := docStart(t, docWorld{slack: c.slack, siem: c.siem})
			check, line := c.line(s)
			s.check(t, s.want(t, map[string]string{check: line}))
			docOnly(t, s.slack, "/slack/T0/B0/"+s.markers[0])
			docOnly(t, s.siem, "/hook/"+s.markers[1])
		})
	}
}

// A service that echoes the secret word of its URL as its error word does not
// get it into the output.
func TestDoctorWebhookAnswerHidesTheWordOfTheURL(t *testing.T) {
	s := docStart(t, docWorld{slack: docReply{status: 404}})
	s.slack.reply.body = s.markers[0]
	s.check(t, s.want(t, map[string]string{
		"webhook slack": docAnswered("slack", s.slack.host, "404", "file "+s.slackFile),
	}))
}

// A Slack URL from a variable is named by the variable.
func TestDoctorWebhookAnswerNamesTheVariable(t *testing.T) {
	s := docStart(t, docWorld{slackEnv: true, slack: docReply{status: 404, body: "no_service"}})
	s.check(t, s.want(t, map[string]string{
		"webhook slack": docAnswered("slack", s.slack.host, `404 "no_service"`, "the variable OSK_SLACK_URL"),
	}))
}

// A channel whose service gives no answer fails alone with the reason, and
// the clock takes the Date of the next channel.
func TestDoctorWebhookNoAnswerFailsAlone(t *testing.T) {
	cases := []struct {
		name   string
		slack  docReply
		reason string
		conns  int32
	}{
		{"refused", docReply{closed: true}, "network: cannot connect", 0},
		{"untrusted certificate", docReply{foreign: true}, "network: certificate not trusted", 1},
		{"silent", docReply{silent: true}, "timeout", 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := docStart(t, docWorld{slack: c.slack})
			s.check(t, s.want(t, map[string]string{
				"webhook slack": docNoAnswer("slack", s.slack.host, c.reason),
				"clock":         docClockOK(s.siem.host),
			}))
			if n := s.slack.conns.Load(); n != c.conns {
				t.Errorf("the Slack service got %d connections, want %d", n, c.conns)
			}
			s.checkWebhook(t)
		})
	}
}

// The clock is compared with the Date of the first channel whose service
// answered with any status and a valid Date; doctor contacts no other host
// for the time, and posts nothing to the heartbeat.
func TestDoctorClockUsesTheFirstAnswerWithADate(t *testing.T) {
	cases := []struct {
		name        string
		slack, siem docReply
		change      func(s *docSetup) map[string]string
	}{
		{"behind", docReply{clock: 10 * time.Minute}, docReply{}, func(s *docSetup) map[string]string {
			return map[string]string{"clock": docClockFail("behind", s.slack.host)}
		}},
		{"ahead", docReply{clock: -10 * time.Minute}, docReply{}, func(s *docSetup) map[string]string {
			return map[string]string{"clock": docClockFail("ahead of", s.slack.host)}
		}},
		{"first has no Date", docReply{noDate: true}, docReply{clock: 10 * time.Minute}, func(s *docSetup) map[string]string {
			return map[string]string{"clock": docClockFail("behind", s.siem.host)}
		}},
		{"first has a bad Date", docReply{badDate: "yesterday"}, docReply{clock: -10 * time.Minute}, func(s *docSetup) map[string]string {
			return map[string]string{"clock": docClockFail("ahead of", s.siem.host)}
		}},
		{"refusal with a Date", docReply{status: 404, body: "no_service", clock: 10 * time.Minute}, docReply{},
			func(s *docSetup) map[string]string {
				return map[string]string{
					"webhook slack": docAnswered("slack", s.slack.host, `404 "no_service"`, "file "+s.slackFile),
					"clock":         docClockFail("behind", s.slack.host),
				}
			}},
		{"first gave no answer", docReply{closed: true}, docReply{clock: 10 * time.Minute}, func(s *docSetup) map[string]string {
			return map[string]string{
				"webhook slack": docNoAnswer("slack", s.slack.host, "network: cannot connect"),
				"clock":         docClockFail("behind", s.siem.host),
			}
		}},
		{"no Date", docReply{noDate: true}, docReply{badDate: "Mon, 32 Nov 2026 10:04:05 GMT"}, func(*docSetup) map[string]string {
			return map[string]string{"clock": docClockSkip}
		}},
		{"no answer", docReply{closed: true}, docReply{closed: true}, func(s *docSetup) map[string]string {
			return map[string]string{
				"webhook slack": docNoAnswer("slack", s.slack.host, "network: cannot connect"),
				"webhook siem":  docNoAnswer("siem", s.siem.host, "network: cannot connect"),
				"clock":         docClockSkip,
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := docStart(t, docWorld{slack: c.slack, siem: c.siem})
			s.check(t, s.want(t, c.change(s)))
			for _, h := range []*docHook{s.slack, s.siem} {
				want := int32(1)
				if h.reply.closed {
					want = 0
				}
				if n := h.conns.Load(); n != want {
					t.Errorf("the service at %s got %d connections, want %d", h.host, n, want)
				}
			}
			if n := s.beat.conns.Load(); n != 0 {
				t.Errorf("the heartbeat service got %d connections, want none", n)
			}
		})
	}
}

// The clock passes up to 30 seconds from the middle of the time the answer
// took, rounded to whole seconds, and fails from 31 seconds on.
func TestClockCheckLimitIsThirtySeconds(t *testing.T) {
	const host = "hooks.example.test:443"
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	cases := []struct {
		name    string
		took    time.Duration // t1 - t0
		date    time.Duration // the Date - t0
		want    string
		failing bool
	}{
		{"30s behind", 2 * time.Second, 31 * time.Second, "30s from the time of " + host, false},
		{"30s ahead", 2 * time.Second, -29 * time.Second, "30s from the time of " + host, false},
		{"31s behind", 2 * time.Second, 32 * time.Second, "this machine is 31s behind " + host, true},
		{"31s ahead", 2 * time.Second, -30 * time.Second, "this machine is 31s ahead of " + host, true},
		{"30.4s rounds down", 1200 * time.Millisecond, 31 * time.Second, "30s from the time of " + host, false},
		{"30.6s rounds up", 800 * time.Millisecond, 31 * time.Second, "this machine is 31s behind " + host, true},
		{"same time", 2 * time.Second, time.Second, "0s from the time of " + host, false},
	}
	// The fields of the result are open, so its print is searched for the
	// text; the tests of Doctor pin each text to its result.
	for _, c := range cases {
		got := fmt.Sprint(clockCheck([]sent{{host: host, t0: t0, t1: t0.Add(c.took),
			outcome: deliver.Outcome{Status: http.StatusOK, Date: t0.Add(c.date)}}}))
		if !strings.Contains(got, c.want) || strings.Contains(got, "this machine is") != c.failing {
			t.Errorf("%s: %s; want %q", c.name, got, c.want)
		}
		if c.failing && !strings.Contains(got, ". Set its clock, for example with NTP: webhook signatures and alert times depend on it.") {
			t.Errorf("%s: %s; want what to do", c.name, got)
		}
	}
}

// Only an answer with a status and a Date counts; without one there is
// nothing to compare with.
func TestClockCheckSkipsSendsWithoutStatusOrDate(t *testing.T) {
	t0 := time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)
	t1 := t0.Add(2 * time.Second)
	none := []sent{
		{host: "a.test:443", t0: t0, t1: t1, outcome: deliver.Outcome{Err: "timeout"}},
		{host: "b.test:443", t0: t0, t1: t1, outcome: deliver.Outcome{Status: http.StatusOK}},
		{host: "c.test:443", t0: t0, t1: t1, outcome: deliver.Outcome{Err: "timeout", Date: t0.Add(time.Hour)}},
	}
	used := append(slices.Clone(none),
		sent{host: "d.test:443", t0: t0, t1: t1, outcome: deliver.Outcome{Status: http.StatusNotFound, Date: t0.Add(5*time.Minute + time.Second)}},
		sent{host: "e.test:443", t0: t0, t1: t1, outcome: deliver.Outcome{Status: http.StatusOK, Date: t0.Add(time.Second)}})
	skip := "no webhook answered, so there is no outside time to compare with"
	for _, c := range []struct {
		name  string
		sends []sent
		want  string
	}{
		{"none", nil, skip},
		{"no status or no Date", none, skip},
		{"the first with both", used, "this machine is 5m0s behind d.test:443"},
	} {
		got := fmt.Sprint(clockCheck(c.sends))
		if !strings.Contains(got, c.want) || strings.Contains(got, "this machine is") != (c.want != skip) {
			t.Errorf("%s: %s; want %q", c.name, got, c.want)
		}
	}
}

// Failures of several checks are each shown; none stops or hides another.
func TestDoctorEveryFailureShownTogether(t *testing.T) {
	s := docStart(t, docWorld{refuse: "shop.test.",
		slack: docReply{status: 404, body: "no_service", clock: 10 * time.Minute}, siem: docReply{closed: true}})
	docChmod(t, s.state, 0o755)
	s.check(t, s.want(t, map[string]string{
		"files":          docOpenState(s.state),
		"dns shop.test.": docDNSFail("shop.test.", "refused"),
		"webhook slack":  docAnswered("slack", s.slack.host, `404 "no_service"`, "file "+s.slackFile),
		"webhook siem":   docNoAnswer("siem", s.siem.host, "network: cannot connect"),
		"clock":          docClockFail("behind", s.slack.host),
	}))
}

// --json gives the results of the text output, one object per line, then
// the number of problems.
func TestDoctorJSONGivesTheSameResults(t *testing.T) {
	for _, w := range []docWorld{{}, {refuse: "shop.test.", slack: docReply{status: 404, body: "no_service"}}} {
		s := docStart(t, w)
		code, text := s.run(t)
		text = docSettleClock(t, text, s.planted())
		jsonCode, lines := s.run(t, "--json")
		docSame(t, jsonCode, docSettleClock(t, docFromJSON(t, lines), s.planted()), text)
		if code != jsonCode {
			t.Errorf("exit code %d with --json, %d without", jsonCode, code)
		}
	}
}

// Wrong use exits 2 with the reason and the usage, and checks nothing.
func TestDoctorWrongUseChecksNothing(t *testing.T) {
	s := docStart(t, docWorld{})
	for _, args := range [][]string{
		{},
		{"--config"},
		{"--config", ""},
		{"--json"},
		{"--config", s.config, "extra"},
		{"--other", "--config", s.config},
		{"--json=maybe", "--config", s.config},
	} {
		code, out, errOut := docDoctor(args...)
		lines := strings.Split(strings.TrimSuffix(errOut, "\n"), "\n")
		if code != 2 || out != "" || len(lines) != 2 || !strings.HasPrefix(lines[0], "osk-dns-watcher doctor: ") || lines[1] != docUsage {
			t.Errorf("doctor %q: exit code %d, output %q, errors %q; want 2, nothing, and the reason and %q",
				args, code, out, errOut, docUsage)
		}
	}
	s.checkedNothing(t)
	if asked := s.dns.docAsked(); len(asked) != 0 {
		t.Errorf("the root server was asked %q, want nothing", asked)
	}
}

// The channels are Slack, when set, then each webhook in config order, as
// osk-dns-watcher run builds them: their names, minimum severities and notice bodies.
func TestChannelsGivesSlackThenEachWebhook(t *testing.T) {
	const withSlack = `{"state": "state", "domains": [{"name": "corp.test.", "expect": "corp.test.expect"}],
	  "slack": {"url": {"env": "A"}, "min_severity": "high"},
	  "webhooks": [{"name": "siem", "url": {"env": "B"}, "key": {"env": "C"}, "min_severity": "critical"},
	               {"name": "audit", "url": {"env": "D"}, "key": {"env": "E"}}]}`
	withoutSlack := strings.Replace(withSlack, `"slack": {"url": {"env": "A"}, "min_severity": "high"},`, "", 1)
	key := []byte(strings.Repeat("k", 32))
	n := docNoticeAt(time.Date(2026, 11, 16, 10, 4, 5, 0, time.UTC))
	slackBody, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{deliver.NoticeText(n)})
	path := filepath.Join(t.TempDir(), "config.json")
	for _, c := range []struct {
		data   string
		values config.Values
		names  []string
		mins   []decide.Severity
	}{
		{withSlack, config.Values{SlackURL: "https://a.test/s", WebhookURLs: []string{"https://b.test/h", "https://d.test/h"},
			WebhookKeys: [][]byte{key, key}}, []string{"slack", "siem", "audit"},
			[]decide.Severity{decide.SeverityHigh, decide.SeverityCritical, decide.SeverityLow}},
		{withoutSlack, config.Values{WebhookURLs: []string{"https://b.test/h", "https://d.test/h"}, WebhookKeys: [][]byte{key, key}},
			[]string{"siem", "audit"}, []decide.Severity{decide.SeverityCritical, decide.SeverityLow}},
	} {
		cfg, problems := config.Parse(path, []byte(c.data))
		if len(problems) > 0 {
			t.Fatalf("the config of the test has problems: %v", problems)
		}
		channels := Channels(cfg, c.values, httpclient.New(c.values.Hosts(), nil))
		var names []string
		var mins []decide.Severity
		for _, ch := range channels {
			names = append(names, ch.Name())
			mins = append(mins, ch.MinSeverity())
		}
		if !slices.Equal(names, c.names) || !slices.Equal(mins, c.mins) {
			t.Errorf("channels %q with minimums %v, want %q with %v", names, mins, c.names, c.mins)
			continue
		}
		for i, ch := range channels {
			want := deliver.WebhookNotice(n)
			if c.names[i] == "slack" {
				want = slackBody
			}
			if got := ch.Notice(n); !bytes.Equal(got, want) {
				t.Errorf("channel %s gives the notice body %s, want %s", c.names[i], got, want)
			}
		}
	}
}
