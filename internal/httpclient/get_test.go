package httpclient_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
)

func TestGetConstants(t *testing.T) {
	if httpclient.GetTimeout != 30*time.Second {
		t.Errorf("GetTimeout %v, want 30s", httpclient.GetTimeout)
	}
	if httpclient.ErrTooLarge.Error() != "answer too large" {
		t.Errorf("ErrTooLarge text %q", httpclient.ErrTooLarge)
	}
	if errors.Is(httpclient.ErrTooLarge, httpclient.ErrTimeout) || errors.Is(httpclient.ErrTooLarge, httpclient.ErrHost) {
		t.Error("ErrTooLarge is not a distinct error")
	}
}

// The request is a GET of the exact path and query, with Accept and nothing
// else that the transport does not add; each extra header is set after
// Accept, so the last one of a name wins.
func TestGetSendsOnlyAcceptAndTheHeaders(t *testing.T) {
	type request struct {
		method, uri string
		header      http.Header
		body        []byte
	}
	got := make(chan request, 1)
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- request{r.Method, r.URL.RequestURI(), r.Header.Clone(), body}
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, "[]")
	})
	c := httpclient.New([]string{host}, pool)
	allowed := func(h http.Header, want map[string][]string) {
		t.Helper()
		for name, v := range want {
			if !reflect.DeepEqual(h[name], v) {
				t.Errorf("header %s is %q, want %q", name, h[name], v)
			}
		}
		for name := range h {
			if _, ok := want[name]; !ok && name != "Content-Length" && !strings.HasPrefix(name, "User-") &&
				(name != "Connection" || h.Get(name) != "close") {
				t.Errorf("the request carries the header %s: %q", name, h[name])
			}
		}
	}

	resp, err := c.Get(context.Background(), srv.URL+"/v1/issuances?domain=a.test&expand=x&expand=y", 100)
	if err != nil || resp.Status != http.StatusAccepted || string(resp.Body) != "[]" {
		t.Fatalf("Get: %+v, %v; want status 202 and body []", resp, err)
	}
	r := <-got
	if r.method != http.MethodGet || r.uri != "/v1/issuances?domain=a.test&expand=x&expand=y" || len(r.body) != 0 {
		t.Errorf("the server got %s %s with body %q", r.method, r.uri, r.body)
	}
	allowed(r.header, map[string][]string{"Accept": {"application/json"}})

	_, err = c.Get(context.Background(), srv.URL+"/x", 100,
		httpclient.Header{Name: "Authorization", Value: "Bearer k1"},
		httpclient.Header{Name: "X-One", Value: "1"},
		httpclient.Header{Name: "Authorization", Value: "Bearer k2"})
	if err != nil {
		t.Fatal(err)
	}
	allowed((<-got).header, map[string][]string{
		"Accept": {"application/json"}, "Authorization": {"Bearer k2"}, "X-One": {"1"},
	})

	_, err = c.Get(context.Background(), srv.URL+"/x", 100, httpclient.Header{Name: "Accept", Value: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	allowed((<-got).header, map[string][]string{"Accept": {"text/plain"}})
}

// A URL that is not https, or whose host is not listed, fails before any
// I/O, and its text is not in the error.
func TestGetRefusesBadURLsAndUnlistedHosts(t *testing.T) {
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
	c := httpclient.New([]string{host}, nil)
	for _, url := range []string{
		srv.URL + "/hclsecret%zz",
		"https://u:hclsecret@" + host + "/x",
		"http://" + host + "/hclsecret",
		"https:///hclsecret",
		"hclsecret",
		"",
		"https://lİnk.test/hclsecret",
	} {
		_, err := c.Get(context.Background(), url, 100)
		if !errors.Is(err, httpclient.ErrURL) {
			t.Errorf("Get(%q): error %v, want ErrURL", url, err)
		}
		hclNoSecret(t, err, "hclsecret")
	}
	for _, url := range []string{"https://127.0.0.2:443/hclsecret", "https://" + host + "0/hclsecret", "https://hclsecret.test/x"} {
		_, err := c.Get(context.Background(), url, 100)
		if !errors.Is(err, httpclient.ErrHost) {
			t.Errorf("Get(%q): error %v, want ErrHost", url, err)
		}
		hclNoSecret(t, err, "hclsecret")
	}
	if n := conns.Load(); n != 0 {
		t.Errorf("the server got %d connections", n)
	}
	// The control: a listed host is let through to the network, whose
	// certificate the system roots do not trust.
	if _, err := c.Get(context.Background(), srv.URL+"/x", 100); err == nil || errors.Is(err, httpclient.ErrHost) || errors.Is(err, httpclient.ErrURL) {
		t.Errorf("a listed host: error %v, want a network error", err)
	}
}

// A redirect comes back as the answer; the target gets nothing.
func TestGetNeverFollowsRedirects(t *testing.T) {
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
		resp, err := c.Get(context.Background(), srv.URL+"/from/"+strconv.Itoa(code), 100)
		if err != nil || resp.Status != code {
			t.Errorf("Get answered %d: %+v, %v; want the %d itself", code, resp, err, code)
		}
	}
	if n := target.Load(); n != 0 {
		t.Errorf("the target of the redirects got %d requests", n)
	}
}

// A body of exactly the limit is read whole; one octet more gives
// ErrTooLarge and no body, with a known length and with chunks.
func TestGetBodyLimit(t *testing.T) {
	data := make([]byte, 1<<20)
	for i := range data {
		data[i] = byte('a' + i%26)
	}
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		n, err := strconv.Atoi(q.Get("n"))
		if err != nil {
			t.Error(err)
		}
		status, _ := strconv.Atoi(q.Get("s"))
		w.WriteHeader(status)
		if q.Get("chunked") == "1" {
			for off := 0; off < n; off += 500 {
				// The client may stop reading.
				_, _ = w.Write(data[off:min(off+500, n)])
				w.(http.Flusher).Flush()
			}
			return
		}
		_, _ = w.Write(data[:n])
	})
	c := httpclient.New([]string{host}, pool)
	cases := []struct {
		limit int64
		n     int
	}{
		{10, 0}, {10, 1}, {10, 9}, {10, 10}, {10, 11}, {10, 5000}, {10, 1 << 20},
		{5000, 4097}, {5000, 5000}, {5000, 5001},
		{100000, 100000}, {100000, 100001},
	}
	for _, status := range []int{200, 429, 500} {
		for _, chunked := range []string{"0", "1"} {
			for _, tc := range cases {
				url := fmt.Sprintf("%s/b?n=%d&s=%d&chunked=%s", srv.URL, tc.n, status, chunked)
				resp, err := c.Get(context.Background(), url, tc.limit)
				if tc.n <= int(tc.limit) {
					if err != nil || resp.Status != status || !bytes.Equal(resp.Body, data[:tc.n]) {
						t.Errorf("limit %d, body %d, status %d, chunked %s: status %d, %d octets, %v; want the whole body",
							tc.limit, tc.n, status, chunked, resp.Status, len(resp.Body), err)
					}
					continue
				}
				if !errors.Is(err, httpclient.ErrTooLarge) || len(resp.Body) != 0 {
					t.Errorf("limit %d, body %d, status %d, chunked %s: %d octets, %v; want ErrTooLarge and no body",
						tc.limit, tc.n, status, chunked, len(resp.Body), err)
				}
			}
		}
	}
}

// A body that ends before its announced length, or that stalls until the
// context ends, is an error and gives no body: a cut text is never read.
func TestGetCutBodyIsAnError(t *testing.T) {
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/short":
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_, _ = io.WriteString(conn, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\n\r\n0123456789")
			_ = conn.Close()
		case "/stall":
			w.Header().Set("Content-Length", "100")
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, "0123456789")
			w.(http.Flusher).Flush()
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}
	})
	c := httpclient.New([]string{host}, pool)
	resp, err := c.Get(context.Background(), srv.URL+"/short", 1000)
	if err == nil || len(resp.Body) != 0 {
		t.Errorf("a body shorter than its length: %d octets, %v; want an error and no body", len(resp.Body), err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	start := time.Now()
	resp, err = c.Get(ctx, srv.URL+"/stall", 1000)
	if took := time.Since(start); err == nil || len(resp.Body) != 0 || took > 4*time.Second {
		t.Errorf("a stalled body: %d octets, %v after %v; want an error and no body after about 1s", len(resp.Body), err, took)
	}
}

// A server that accepts but never answers gives ErrTimeout when the context
// ends.
func TestGetTimesOutWithContext(t *testing.T) {
	silent, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
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
		_, err := c.client.Get(ctx, c.url, 100)
		cancel()
		if took := time.Since(start); !errors.Is(err, httpclient.ErrTimeout) || took > 4*time.Second {
			t.Errorf("%s: error %v after %v, want ErrTimeout after about 1s", c.name, err, took)
		}
		hclNoSecret(t, err, "hclsecret")
	}
}

// Get is not bound by the 10 s of Post: an answer that takes 11 s arrives.
func TestGetWaitsLongerThanPost(t *testing.T) {
	t.Parallel()
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-time.After(11 * time.Second):
			_, _ = io.WriteString(w, "late")
		case <-r.Context().Done():
		}
	})
	c := httpclient.New([]string{host}, pool)
	resp, err := c.Get(context.Background(), srv.URL+"/slow", 100)
	if err != nil || resp.Status != http.StatusOK || string(resp.Body) != "late" {
		t.Errorf("a slow answer: %+v, %v; want status 200 and body late", resp, err)
	}
}

func TestGetReadsRetryAfterAndDate(t *testing.T) {
	cases := []struct {
		retry  []string // nil: no header
		date   []string
		status int
		wantRA time.Duration
		wantD  time.Time
	}{
		{[]string{"0"}, nil, 429, 0, time.Time{}},
		{[]string{"1"}, nil, 429, time.Second, time.Time{}},
		{[]string{"3600"}, nil, 200, time.Hour, time.Time{}},
		{[]string{"86400"}, nil, 429, 86400 * time.Second, time.Time{}},
		{[]string{"86401"}, nil, 429, 0, time.Time{}},
		{[]string{"-1"}, nil, 429, 0, time.Time{}},
		{[]string{"1.5"}, nil, 429, 0, time.Time{}},
		{[]string{"Wed, 21 Oct 2015 07:28:00 GMT"}, nil, 429, 0, time.Time{}},
		{nil, nil, 200, 0, time.Time{}},
		{nil, []string{"Tue, 17 Nov 2026 12:34:22 GMT"}, 200, 0, time.Date(2026, 11, 17, 12, 34, 22, 0, time.UTC)},
		{[]string{"3600"}, []string{"Tue, 17 Nov 2026 12:34:31 GMT"}, 200, time.Hour, time.Date(2026, 11, 17, 12, 34, 31, 0, time.UTC)},
		{nil, []string{"yesterday"}, 200, 0, time.Time{}},
	}
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Errorf("path %q names no case", r.URL.Path)
			return
		}
		w.Header()["Retry-After"] = cases[i].retry
		w.Header()["Date"] = cases[i].date
		w.WriteHeader(cases[i].status)
		_, _ = io.WriteString(w, "[]")
	})
	c := httpclient.New([]string{host}, pool)
	for i, tc := range cases {
		resp, err := c.Get(context.Background(), srv.URL+"/"+strconv.Itoa(i), 10)
		if err != nil || resp.Status != tc.status || resp.RetryAfter != tc.wantRA || !resp.Date.Equal(tc.wantD) || string(resp.Body) != "[]" {
			t.Errorf("Retry-After %q, Date %q: %+v, %v; want status %d, wait %v, date %v",
				tc.retry, tc.date, resp, err, tc.status, tc.wantRA, tc.wantD)
		}
	}
}

// The client reads no compression, whatever the server says: the body is
// handed over as it came.
func TestGetDoesNotDecodeTheBody(t *testing.T) {
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Accept-Encoding") != "" {
			t.Errorf("the request asks for %q", r.Header.Get("Accept-Encoding"))
		}
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = io.WriteString(w, "not gzip at all")
	})
	resp, err := httpclient.New([]string{host}, pool).Get(context.Background(), srv.URL+"/x", 100)
	if err != nil || string(resp.Body) != "not gzip at all" {
		t.Errorf("Get: %+v, %v; want the octets as sent", resp, err)
	}
}

// Each failure of the network gives one fixed text, never the URL or octets
// of the answer.
func TestGetErrorsAreFixedTexts(t *testing.T) {
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
	for _, c := range []struct {
		name, url string
		client    *httpclient.Client
		want      string
	}{
		{"refused", "https://" + closed + "/hclsecret", httpclient.New([]string{closed}, pool), "network: cannot connect"},
		{"untrusted", srv.URL + "/hclsecret", httpclient.New([]string{host}, x509.NewCertPool()), "network: certificate not trusted"},
		{"bad Location", srv.URL + "/location", trusting, "network: no usable answer"},
		{"bad header line", srv.URL + "/header", trusting, "network: no usable answer"},
	} {
		if _, err := c.client.Get(context.Background(), c.url, 100); err == nil || err.Error() != c.want {
			t.Errorf("%s: %v; want %q", c.name, err, c.want)
		}
	}
}

// The client never uses a proxy from the environment, which TestMain sets.
func TestGetIgnoresProxyEnvironment(t *testing.T) {
	c := httpclient.New([]string{"192.0.2.1:443"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	before := hclProxyConns.Load()
	_, err := c.Get(ctx, "https://192.0.2.1/hclsecret", 100)
	if err == nil || errors.Is(err, httpclient.ErrURL) || errors.Is(err, httpclient.ErrHost) {
		t.Errorf("Get: error %v, want a failed connection", err)
	}
	if n := hclProxyConns.Load() - before; n != 0 {
		t.Errorf("the proxy of the environment got %d connections", n)
	}
}

// The client keeps no connection after a Get.
func TestGetKeepsNoConnection(t *testing.T) {
	srv, host, pool := hclServer(t, func(http.ResponseWriter, *http.Request) {})
	before := hclClientGoroutines()
	if _, err := httpclient.New([]string{host}, pool).Get(context.Background(), srv.URL+"/x", 100); err != nil {
		t.Fatal(err)
	}
	after := hclClientGoroutines()
	for deadline := time.Now().Add(2 * time.Second); after > before && time.Now().Before(deadline); after = hclClientGoroutines() {
		time.Sleep(10 * time.Millisecond)
	}
	if after > before {
		t.Errorf("%d goroutines of the net/http client after a Get, %d before", after, before)
	}
}
