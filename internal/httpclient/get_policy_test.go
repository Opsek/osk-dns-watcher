package httpclient_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
)

// mtsCert is a self-signed server certificate for names and a pool that
// trusts it alone.
func mtsCert(t *testing.T, names ...string) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "osk-dns-watcher test server"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		DNSNames:     names,
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
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, pool
}

// mtsAddr is the address that a test server listens on.
func mtsAddr(t *testing.T, srv *httptest.Server) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddrPort(srv.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// RFC 8461 section 3.3 suggests 64 kilobytes as the largest policy file.
func TestMaxPolicy(t *testing.T) {
	if httpclient.MaxPolicy != 65536 {
		t.Errorf("MaxPolicy = %d, want 65536", httpclient.MaxPolicy)
	}
	data := bytes.Repeat([]byte("mx: mail.corp.test\n"), 4000)
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Error(err)
			return
		}
		_, _ = w.Write(data[:n])
	})
	c := httpclient.New([]string{host}, pool)
	resp, err := c.Get(context.Background(), srv.URL+"/65536", httpclient.MaxPolicy)
	if err != nil || !bytes.Equal(resp.Body, data[:65536]) {
		t.Errorf("a body of 65536 octets: %d octets, %v; want it whole", len(resp.Body), err)
	}
	resp, err = c.Get(context.Background(), srv.URL+"/65537", httpclient.MaxPolicy)
	if !errors.Is(err, httpclient.ErrTooLarge) || len(resp.Body) != 0 {
		t.Errorf("a body of 65537 octets: %d octets, %v; want ErrTooLarge and no body", len(resp.Body), err)
	}
}

// Get gives the address that answered, whatever the status, a redirect
// included. Post never gives one.
func TestGetAddr(t *testing.T) {
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Error(err)
			return
		}
		w.Header().Set("Location", "https://192.0.2.1/elsewhere")
		w.WriteHeader(code)
	})
	want := mtsAddr(t, srv)
	c := httpclient.New([]string{host}, pool)
	for _, code := range []int{200, 204, 302, 404, 500} {
		resp, err := c.Get(context.Background(), srv.URL+"/"+strconv.Itoa(code), 100)
		if err != nil || resp.Status != code || resp.Addr != want {
			t.Errorf("Get answered %d: status %d, address %v, %v; want %v", code, resp.Status, resp.Addr, err, want)
		}
	}
	resp, err := c.Post(context.Background(), srv.URL+"/200", "text/plain", nil)
	if err != nil || resp.Status != http.StatusOK || resp.Addr.IsValid() {
		t.Errorf("Post: status %d, address %v, %v; want 200 and no address", resp.Status, resp.Addr, err)
	}
}

func TestGetAddrIPv6(t *testing.T) {
	l, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("no IPv6 loopback: %v", err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	_ = srv.Listener.Close()
	srv.Listener = l
	srv.StartTLS()
	defer srv.Close()
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	host := strings.TrimPrefix(srv.URL, "https://")
	resp, err := httpclient.New([]string{host}, pool).Get(context.Background(), srv.URL+"/x", 100)
	if want := mtsAddr(t, srv); err != nil || resp.Addr != want || !resp.Addr.Addr().Is6() {
		t.Errorf("Get over IPv6: address %v, %v; want %v", resp.Addr, err, want)
	}
}

// The address comes from the connection, not from the URL: a URL that names
// its host by a name gives the address that the name led to.
func TestGetAddrOfANamedHost(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if addrs, err := net.DefaultResolver.LookupHost(ctx, "localhost"); err != nil || len(addrs) == 0 {
		t.Skipf("localhost has no address here: %v", err)
	}
	cert, pool := mtsCert(t, "localhost")
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	srv.StartTLS()
	defer srv.Close()
	want := mtsAddr(t, srv)
	host := "localhost:" + strconv.Itoa(int(want.Port()))
	resp, err := httpclient.New([]string{host}, pool).Get(context.Background(), "https://"+host+"/x", 100)
	if err != nil || resp.Addr != want {
		t.Errorf("Get of https://%s/x: address %v, %v; want %v", host, resp.Addr, err, want)
	}
}

// No address is given when no server answered: a refused connection, a
// refused URL or host, a certificate that is not trusted, no TLS handshake.
func TestGetAddrZeroWithoutAnswer(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	closed := l.Addr().String()
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
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
	srv, host, pool := hclServer(t, func(http.ResponseWriter, *http.Request) {})
	for _, c := range []struct {
		name, url string
		client    *httpclient.Client
	}{
		{"refused connection", "https://" + closed + "/x", httpclient.New([]string{closed}, pool)},
		{"no TLS handshake", "https://" + silent.Addr().String() + "/x", httpclient.New([]string{silent.Addr().String()}, pool)},
		{"untrusted certificate", srv.URL + "/x", httpclient.New([]string{host}, x509.NewCertPool())},
		{"host not listed", srv.URL + "/x", httpclient.New([]string{"127.0.0.2:443"}, pool)},
		{"not https", "http://" + host + "/x", httpclient.New([]string{host}, pool)},
	} {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		resp, err := c.client.Get(ctx, c.url, 100)
		cancel()
		if err == nil || resp.Addr.IsValid() {
			t.Errorf("%s: address %v, %v; want an error and no address", c.name, resp.Addr, err)
		}
	}
}
