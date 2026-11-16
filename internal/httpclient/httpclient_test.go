package httpclient_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/httpclient"
)

// hclProxyConns counts the connections to a proxy that the environment of
// every test of this package names. Go reads the proxy variables once in a
// process, so they are set here, before any test runs.
var hclProxyConns atomic.Int64

func TestMain(m *testing.M) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			hclProxyConns.Add(1)
			_ = c.Close()
		}
	}()
	for name, value := range map[string]string{
		"HTTPS_PROXY": "http://" + l.Addr().String(), "https_proxy": "http://" + l.Addr().String(),
		"HTTP_PROXY": "http://" + l.Addr().String(), "http_proxy": "http://" + l.Addr().String(),
		"NO_PROXY": "", "no_proxy": "",
	} {
		if err := os.Setenv(name, value); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	}
	code := m.Run()
	_ = l.Close()
	os.Exit(code)
}

// The client never uses a proxy from the environment. Go never sends a
// loopback address through a proxy, so the target is an address of the
// documentation range, which nothing answers.
func TestPostIgnoresProxyEnvironment(t *testing.T) {
	c := httpclient.New([]string{"192.0.2.1:443"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	before := hclProxyConns.Load()
	_, err := c.Post(ctx, "https://192.0.2.1/hook/hclsecret", "application/json", []byte("{}"))
	if err == nil || errors.Is(err, httpclient.ErrURL) || errors.Is(err, httpclient.ErrHost) {
		t.Errorf("Post: error %v, want a failed connection", err)
	}
	if n := hclProxyConns.Load() - before; n != 0 {
		t.Errorf("the proxy of the environment got %d connections", n)
	}
	before = hclProxyConns.Load()

	// The control: a transport that reads the environment reaches the proxy
	// for the same target, so the check above can fail.
	tr := &http.Transport{Proxy: http.ProxyFromEnvironment}
	defer tr.CloseIdleConnections()
	ctx, cancel = context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://192.0.2.1/hook/hclsecret", nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp, err := tr.RoundTrip(req); err == nil {
		_ = resp.Body.Close()
	}
	if hclProxyConns.Load() == before {
		t.Error("the control transport did not reach the proxy of the environment")
	}
}

func TestHostOf(t *testing.T) {
	if httpclient.ErrURL.Error() != "not an https URL with a host and no user name" ||
		httpclient.ErrHost.Error() != "host not allowed" || httpclient.ErrTimeout.Error() != "timeout" {
		t.Errorf("error texts %q, %q, %q", httpclient.ErrURL, httpclient.ErrHost, httpclient.ErrTimeout)
	}
	if httpclient.Timeout != 10*time.Second || httpclient.MaxBody != 4096 {
		t.Errorf("Timeout %v, MaxBody %d; want 10s, 4096", httpclient.Timeout, httpclient.MaxBody)
	}
	for _, c := range []struct{ url, want string }{
		{"https://hooks.slack.com/services/T0/B0/x", "hooks.slack.com:443"},
		{"https://Hooks.Slack.COM/services/T0/B0/X", "hooks.slack.com:443"},
		{"HTTPS://hooks.slack.com/x", "hooks.slack.com:443"},
		{"https://hooks.lab.test:444/dead", "hooks.lab.test:444"},
		{"https://127.0.0.1:8443", "127.0.0.1:8443"},
		{"https://[::1]/x", "[::1]:443"},
		{"https://[::1]:8443/x", "[::1]:8443"},
		{"https://hooks.slack.com/x?a=b#c", "hooks.slack.com:443"},
	} {
		if got, err := httpclient.HostOf(c.url); err != nil || got != c.want {
			t.Errorf("HostOf(%q) = %q, %v; want %q", c.url, got, err, c.want)
		}
	}
	for _, url := range []string{
		"", "hooks.slack.com/x", "//hooks.slack.com/x", "http://hooks.slack.com/x", "ftp://hooks.slack.com/x",
		"https:///x", "https://", "https:hooks.slack.com/x", "https://u@hooks.slack.com/x", "https://u:p@hooks.slack.com/x",
		"https://hooks.slack.com/%zz", "https://hooks.slack.com:8x/x", "https://hooks.slack.com/\n", "://x",
	} {
		if got, err := httpclient.HostOf(url); !errors.Is(err, httpclient.ErrURL) {
			t.Errorf("HostOf(%q) = %q, %v; want ErrURL", url, got, err)
		}
	}
}

// A host name with an octet outside ASCII is refused: in lower case it can
// equal a listed name, while the lookup asks for another host.
func TestHostOfRefusesNonASCIIHost(t *testing.T) {
	c := httpclient.New([]string{"link.test:443"}, nil)
	for _, u := range []string{"https://lİnk.test/x", "https://lİnk.test:443/x", "https://bücher.test/x", "https://link.test\xff/x"} {
		if got, err := httpclient.HostOf(u); !errors.Is(err, httpclient.ErrURL) {
			t.Errorf("HostOf(%q) = %q, %v; want ErrURL", u, got, err)
		}
		if _, err := c.Post(context.Background(), u, "application/json", nil); !errors.Is(err, httpclient.ErrURL) {
			t.Errorf("Post(%q): %v; want ErrURL before any I/O", u, err)
		}
	}
}

// hclServer is a TLS test server, its host as HostOf gives it, and a pool
// that trusts it.
func hclServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, string, *x509.CertPool) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	return srv, strings.TrimPrefix(srv.URL, "https://"), pool
}

// hclNoSecret fails the test if the error text holds the secret.
func hclNoSecret(t *testing.T, err error, secret string) {
	t.Helper()
	if err != nil && strings.Contains(err.Error(), secret) {
		t.Errorf("the error holds the secret of the URL: %v", err)
	}
}

func TestOnlyListedHostsProperty(t *testing.T) {
	var requests, conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
	}))
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	port := strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port)
	server := "127.0.0.1:" + port
	forms := []string{server, "127.0.0.1:443", "127.0.0.2:" + port}
	// One client for each subset of the forms; bit i of the index lists form i.
	var clients []*httpclient.Client
	for set := range 8 {
		var hosts []string
		for i, f := range forms {
			if set&(1<<i) != 0 {
				hosts = append(hosts, f)
			}
		}
		clients = append(clients, httpclient.New(hosts, pool))
	}

	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 13))
	for i := range 1000 {
		set := rng.IntN(8)
		scheme := []string{"https://", "HTTPS://", "http://", "ftp://", "//", ""}[rng.IntN(6)]
		user := []string{"", "u@", "u:p@"}[rng.IntN(3)]
		host := []string{"127.0.0.1", "127.0.0.2", "[::1]"}[rng.IntN(3)]
		p := []string{port, "", "1"}[rng.IntN(3)]
		secret := fmt.Sprintf("hclsecret%d", i)
		url := scheme + user + host
		if p != "" {
			url += ":" + p
		}
		url += "/services/" + secret + "?key=" + secret

		// What HostOf must give, from how the URL was built.
		valid := (scheme == "https://" || scheme == "HTTPS://") && user == ""
		want := host + ":" + p
		if p == "" {
			want = host + ":443"
		}
		listed := false
		for b, f := range forms {
			listed = listed || set&(1<<b) != 0 && f == want
		}
		got, err := httpclient.HostOf(url)
		if valid && (err != nil || got != want) || !valid && !errors.Is(err, httpclient.ErrURL) {
			t.Fatalf("seed %d: HostOf(%q) = %q, %v; want %q, valid %v", seed, url, got, err, want, valid)
		}

		before, beforeConns := requests.Load(), conns.Load()
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		resp, err := clients[set].Post(ctx, url, "application/json", []byte("{}"))
		cancel()
		hclNoSecret(t, err, secret)
		reached := requests.Load() != before
		if reached != (valid && listed && want == server) {
			t.Fatalf("seed %d: Post(%q) with hosts of set %d: the server got a request: %v; error %v", seed, url, set, reached, err)
		}
		switch {
		case !valid && !errors.Is(err, httpclient.ErrURL):
			t.Fatalf("seed %d: Post(%q): error %v, want ErrURL", seed, url, err)
		case valid && !listed && !errors.Is(err, httpclient.ErrHost):
			t.Fatalf("seed %d: Post(%q) with hosts of set %d: error %v, want ErrHost", seed, url, set, err)
		case (!valid || !listed) && conns.Load() != beforeConns:
			t.Fatalf("seed %d: Post(%q) with hosts of set %d opened a connection to the server", seed, url, set)
		case reached && (err != nil || resp.Status != http.StatusOK):
			t.Fatalf("seed %d: Post(%q): %+v, %v; want status 200", seed, url, resp, err)
		}
	}
}

// The request carries the body and only the header that the client sets, and
// asks for no compression.
func TestPostSendsOnlyContentType(t *testing.T) {
	type request struct {
		method, path string
		header       http.Header
		body         []byte
	}
	got := make(chan request, 1)
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- request{r.Method, r.URL.RequestURI(), r.Header.Clone(), body}
		w.WriteHeader(http.StatusCreated)
		if _, err := io.WriteString(w, "done"); err != nil {
			t.Error(err)
		}
	})
	c := httpclient.New([]string{host}, pool)
	resp, err := c.Post(context.Background(), srv.URL+"/services/T0?x=1", "application/json", []byte(`{"text":"hi"}`))
	if err != nil || resp.Status != http.StatusCreated || string(resp.Body) != "done" || resp.RetryAfter != 0 {
		t.Fatalf("Post: %+v, %v; want status 201 and body done", resp, err)
	}
	r := <-got
	if r.method != http.MethodPost || r.path != "/services/T0?x=1" || string(r.body) != `{"text":"hi"}` {
		t.Errorf("the server got %s %s with body %q", r.method, r.path, r.body)
	}
	if r.header.Get("Content-Type") != "application/json" {
		t.Errorf("Content-Type %q", r.header.Get("Content-Type"))
	}
	// Content-Length, the name of the client and Connection: close, as the
	// client keeps no connection, come from the Go transport.
	for name := range r.header {
		if name != "Content-Type" && name != "Content-Length" && !strings.HasPrefix(name, "User-") &&
			(name != "Connection" || r.header.Get(name) != "close") {
			t.Errorf("the request carries the header %s: %q", name, r.header[name])
		}
	}
}

// A redirect comes back as the answer; its target, an allowed host, gets
// nothing, also for the codes that would send the body again.
func TestPostNeverFollowsRedirects(t *testing.T) {
	var target atomic.Int64
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			target.Add(1)
			return
		}
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/from/"))
		if err != nil {
			t.Error(err)
		}
		w.Header().Set("Location", "https://"+r.Host+"/target")
		w.WriteHeader(code)
	})
	c := httpclient.New([]string{host}, pool)
	for _, code := range []int{301, 302, 303, 307, 308} {
		resp, err := c.Post(context.Background(), srv.URL+"/from/"+strconv.Itoa(code), "application/json", []byte("{}"))
		if err != nil || resp.Status != code {
			t.Errorf("Post answered %d: %+v, %v; want the %d itself", code, resp, err, code)
		}
	}
	if n := target.Load(); n != 0 {
		t.Errorf("the target of the redirects got %d requests", n)
	}
}

// A server that accepts but never answers gives ErrTimeout when the context
// ends, well before the handshake timeout.
func TestPostTimesOutWithContext(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = silent.Close() })
	held := make(chan net.Conn, 16)
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
		for {
			select {
			case c := <-held:
				_ = c.Close()
			default:
				return
			}
		}
	})
	// The server does not see a client leave while it reads nothing, so the
	// handler waits for the end of the test too.
	release := make(chan struct{})
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	for _, c := range []struct {
		name, url string
		client    *httpclient.Client
	}{
		{"no TLS handshake", "https://" + silent.Addr().String() + "/hclsecret", httpclient.New([]string{silent.Addr().String()}, pool)},
		{"no answer to the request", srv.URL + "/hclsecret", httpclient.New([]string{host}, pool)},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		start := time.Now()
		_, err := c.client.Post(ctx, c.url, "application/json", []byte("{}"))
		cancel()
		if took := time.Since(start); !errors.Is(err, httpclient.ErrTimeout) || took > 4*time.Second {
			t.Errorf("%s: error %v after %v, want ErrTimeout after about 1s", c.name, err, took)
		}
		hclNoSecret(t, err, "hclsecret")
	}
}

// The body of an answer is cut to MaxBody octets.
func TestPostCutsTheBody(t *testing.T) {
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte(i % 251)
	}
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(r.URL.Query().Get("n"))
		if err != nil {
			t.Error(err)
		}
		w.WriteHeader(http.StatusBadRequest)
		// The client stops reading, so the write may fail.
		_, _ = w.Write(data[:n])
	})
	c := httpclient.New([]string{host}, pool)
	// The path and the query appear nowhere in the data, so nothing of it is
	// hidden.
	for _, n := range []int{0, 1, 4095, 4096, 4097, 1 << 20} {
		resp, err := c.Post(context.Background(), srv.URL+"/body?n="+strconv.Itoa(n), "application/json", nil)
		if want := data[:min(n, 4096)]; err != nil || resp.Status != http.StatusBadRequest || !bytes.Equal(resp.Body, want) {
			t.Errorf("a body of %d octets: status %d, %d octets, %v; want 400 and the first %d octets", n, resp.Status, len(resp.Body), err, len(want))
		}
	}
}

// hclClientGoroutines counts the goroutines of the client side of net/http,
// which an idle connection keeps alive.
func hclClientGoroutines() int {
	buf := make([]byte, 1<<20)
	buf = buf[:runtime.Stack(buf, true)]
	n := 0
	for _, g := range strings.Split(string(buf), "\n\n") {
		if strings.Contains(g, "net/http.(*Transport)") || strings.Contains(g, "persistConn") {
			n++
		}
	}
	return n
}

// Alerts are rare, so the client keeps no connection after a Post: an idle
// one would hold goroutines of net/http after the work is done.
func TestPostKeepsNoConnection(t *testing.T) {
	srv, host, pool := hclServer(t, func(http.ResponseWriter, *http.Request) {})
	before := hclClientGoroutines()
	if _, err := httpclient.New([]string{host}, pool).Post(context.Background(), srv.URL+"/x", "application/json", nil); err != nil {
		t.Fatal(err)
	}
	after := hclClientGoroutines()
	for deadline := time.Now().Add(2 * time.Second); after > before && time.Now().Before(deadline); after = hclClientGoroutines() {
		time.Sleep(10 * time.Millisecond)
	}
	if after > before {
		t.Errorf("%d goroutines of the net/http client after a Post, %d before", after, before)
	}
}

// The text of a Go error can hold octets of the answer, such as a bad header
// line or a Location, so each failure gives one fixed text instead.
func TestPostErrorsAreFixedTexts(t *testing.T) {
	answers := map[string]string{
		"/location": "HTTP/1.1 302 Found\r\nLocation: %zzhclsecret\r\nContent-Length: 0\r\n\r\n",
		"/header":   "HTTP/1.1 200 OK\r\nXhclsecret\r\n\r\n",
	}
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_, err = io.WriteString(conn, answers[r.URL.Path])
		if err := errors.Join(err, conn.Close()); err != nil {
			t.Error(err)
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	trusting := httpclient.New([]string{host}, pool)
	cases := []struct {
		name, url string
		client    *httpclient.Client
		want      string
	}{
		{"refused", "https://" + closed + "/hclsecret", httpclient.New([]string{closed}, pool), "network: cannot connect"},
		{"untrusted", srv.URL + "/hclsecret", httpclient.New([]string{host}, x509.NewCertPool()), "network: certificate not trusted"},
		{"no such name", "https://hcl-nohost.invalid/hclsecret", httpclient.New([]string{"hcl-nohost.invalid:443"}, pool),
			"network: name lookup failed"},
		{"bad Location", srv.URL + "/location", trusting, "network: no usable answer"},
		{"bad header line", srv.URL + "/header", trusting, "network: no usable answer"},
	}
	for _, c := range cases {
		if _, err := c.client.Post(context.Background(), c.url, "application/json", nil); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v; want %q", c.name, err, c.want)
		}
	}
}

func TestPostReadsRetryAfter(t *testing.T) {
	cases := []struct {
		value string
		want  time.Duration
	}{
		{"0", 0},
		{"1", time.Second},
		{"120", 120 * time.Second},
		{"86400", 86400 * time.Second},
		{"000120", 120 * time.Second},
		{"000000", 0},
		{"86401", 0},
		{"999999", 0},
		{"0000120", 0},
		{"1234567", 0},
		{"", 0},
		{"-1", 0},
		{"+5", 0},
		{"1.5", 0},
		{"12a", 0},
		{"0x10", 0},
		{"Wed, 21 Oct 2015 07:28:00 GMT", 0},
		{"Fri, 13 Nov 2026 10:00:00 GMT", 0},
	}
	// The path names the case whose value the server sends; "/none" sends no
	// Retry-After.
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		if i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/")); err == nil {
			w.Header()["Retry-After"] = []string{cases[i].value}
		}
		w.WriteHeader(http.StatusTooManyRequests)
	})
	c := httpclient.New([]string{host}, pool)
	for i, tc := range cases {
		resp, err := c.Post(context.Background(), srv.URL+"/"+strconv.Itoa(i), "application/json", nil)
		if err != nil || resp.Status != http.StatusTooManyRequests || resp.RetryAfter != tc.want {
			t.Errorf("Retry-After %q: %+v, %v; want %v", tc.value, resp, err, tc.want)
		}
	}
	resp, err := c.Post(context.Background(), srv.URL+"/none", "application/json", nil)
	if err != nil || resp.RetryAfter != 0 {
		t.Errorf("no Retry-After: %+v, %v; want 0", resp, err)
	}
}

// A certificate that the roots do not trust, a refused connection and
// response headers over 16 KiB each end with a network error that does not
// quote the URL.
func TestPostNetworkErrors(t *testing.T) {
	var got atomic.Int64
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		got.Add(1)
		if n, err := strconv.Atoi(r.URL.Query().Get("header")); err == nil {
			w.Header().Set("X-Big", strings.Repeat("a", n))
		}
	})
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name, url string
		client    *httpclient.Client
	}{
		{"system roots", srv.URL + "/hclsecret", httpclient.New([]string{host}, nil)},
		{"empty pool", srv.URL + "/hclsecret", httpclient.New([]string{host}, x509.NewCertPool())},
		{"refused", "https://" + closed + "/hclsecret", httpclient.New([]string{closed}, pool)},
		{"big headers", srv.URL + "/hclsecret?header=20000", httpclient.New([]string{host}, pool)},
	}
	for _, c := range cases {
		resp, err := c.client.Post(context.Background(), c.url, "application/json", []byte("{}"))
		if err == nil || !strings.HasPrefix(err.Error(), "network: ") || resp.Status != 0 {
			t.Errorf("%s: %+v, %v; want status 0 and an error that starts with network:", c.name, resp, err)
		}
		hclNoSecret(t, err, "hclsecret")
	}
	if n := got.Load(); n != 1 {
		t.Errorf("the server got %d requests, want only the one with big headers", n)
	}
	resp, err := httpclient.New([]string{host}, pool).Post(context.Background(), srv.URL+"/?header=8000", "application/json", nil)
	if err != nil || resp.Status != http.StatusOK {
		t.Errorf("headers of 8000 octets: %+v, %v; want status 200", resp, err)
	}
}

// A URL that does not parse is refused before any I/O, and its text, which
// the parser would quote, is not in the error.
func TestPostBadURLs(t *testing.T) {
	var conns atomic.Int64
	srv := httptest.NewUnstartedServer(http.NotFoundHandler())
	srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			conns.Add(1)
		}
	}
	srv.StartTLS()
	defer srv.Close()
	host := strings.TrimPrefix(srv.URL, "https://")
	c := httpclient.New([]string{host, "127.0.0.1:443"}, nil)
	for _, url := range []string{
		srv.URL + "/hclsecret%zz",
		srv.URL + "/hclsecret\n",
		srv.URL + "/hclsecret\x7f",
		"https://127.0.0.1:8x/hclsecret",
		"https://u:hclsecret@" + host + "/x",
		"http://" + host + "/hclsecret",
		"https:" + host + "/hclsecret",
		"https:///hclsecret",
	} {
		_, err := c.Post(context.Background(), url, "application/json", nil)
		if !errors.Is(err, httpclient.ErrURL) {
			t.Errorf("Post(%q): error %v, want ErrURL", url, err)
		}
		hclNoSecret(t, err, "hclsecret")
	}
	_, err := c.Post(context.Background(), "https://127.0.0.2:443/hclsecret", "application/json", nil)
	if !errors.Is(err, httpclient.ErrHost) {
		t.Errorf("a host not listed: error %v, want ErrHost", err)
	}
	hclNoSecret(t, err, "hclsecret")
	if n := conns.Load(); n != 0 {
		t.Errorf("the server got %d connections", n)
	}
}
