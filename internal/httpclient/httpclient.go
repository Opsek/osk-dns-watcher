// Package httpclient is the one HTTPS client of osk. It sends requests only
// to hosts fixed when the client is made, never follows a redirect and uses
// no proxy, so no data that it handles can send a request elsewhere. A
// webhook URL carries its secret in the path, so no error holds the URL or
// any text of the answer. The body of an answer may repeat the URL.
package httpclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
)

// Timeout bounds one Post: connect, TLS, send, headers and body.
const Timeout = 10 * time.Second

// GetTimeout bounds one Get: connect, TLS, send, headers and body. A search
// of the certificates of a domain may take the 15 s that the source allows
// itself, so the 10 s of Post would cut it.
const GetTimeout = 30 * time.Second

// MaxBody is the most octets of a response body that Post reads.
const MaxBody = 4096

// MaxPolicy is the largest MTA-STS policy file that a caller of Get takes
// (RFC 8461 section 3.3 suggests 64 kilobytes).
const MaxPolicy = 65536

var ErrURL = errors.New("not an https URL with a host and no user name")
var ErrHost = errors.New("host not allowed")
var ErrTimeout = errors.New("timeout")

// ErrTooLarge: the body is longer than the limit of the call.
var ErrTooLarge = errors.New("answer too large")

// ErrNotPermitted: a client of NewGuarded found no address of the host that
// it may connect to, and so connected nowhere. The error of the request
// wraps it and names the first address refused.
var ErrNotPermitted = errors.New("network: no permitted address")

type Client struct {
	hosts []string
	http  *http.Client
	get   *http.Client // the same transport, with the timeout of Get
}

type Response struct {
	Status     int
	RetryAfter time.Duration  // 0 when absent or not a number of seconds
	Date       time.Time      // the server's clock; zero when the header is absent or not valid
	Body       []byte         // as the server sent it: of Post the first MaxBody octets, of Get the whole body
	Addr       netip.AddrPort // of Get only: the address that answered; zero when not known
}

// HostOf gives "host:port" of an https URL, the host in lower case and port
// 443 when the URL names none: the form that New takes.
func HostOf(rawURL string) (string, error) {
	u, err := parse(rawURL)
	if err != nil {
		return "", err
	}
	return hostPort(u), nil
}

// parse never returns the error of url.Parse, whose text holds the URL.
func parse(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.User != nil || u.Opaque != "" || !plainHost(u) {
		return nil, ErrURL
	}
	return u, nil
}

// plainHost reports whether the host of u is a name of letters, digits, "-",
// "_" and "." with no empty label, or an IP address without a zone, in
// brackets exactly when it is IPv6. Only such a host reads back the same from
// the form that hostPort gives. A host outside ASCII is refused too: in lower
// case it can equal a listed host, while the lookup asks for another one. A
// name whose last label is all digits, such as 127.1, is refused: some
// resolvers read it as an IPv4 address.
func plainHost(u *url.URL) bool {
	h := u.Hostname()
	bracketed := strings.HasPrefix(u.Host, "[")
	if a, err := netip.ParseAddr(h); err == nil {
		return a.Zone() == "" && a.Is6() == bracketed
	}
	labels := strings.Split(h, ".")
	if bracketed || strings.Trim(labels[len(labels)-1], "0123456789") == "" {
		return false
	}
	for _, label := range labels {
		if label == "" || strings.ContainsFunc(label, notNameOctet) {
			return false
		}
	}
	return true
}

func notNameOctet(r rune) bool {
	return !('a' <= r && r <= 'z' || 'A' <= r && r <= 'Z' || '0' <= r && r <= '9' || r == '-' || r == '_')
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// New makes a client that sends only to hosts, each in the form HostOf gives.
// No method adds a host later. A nil roots means the trust store of the system.
func New(hosts []string, roots *x509.CertPool) *Client {
	return newClient(hosts, roots, nil)
}

// NewGuarded is New for a host whose addresses come from data that osk
// watches: the client connects only to an address that permit accepts, and
// fails with ErrNotPermitted when the host has none.
func NewGuarded(hosts []string, roots *x509.CertPool, permit func(netip.Addr) bool) *Client {
	return newClient(hosts, roots, guardedDial(permit))
}

// newClient makes the client; a nil dial is the dialer of net/http.
func newClient(hosts []string, roots *x509.CertPool, dial func(ctx context.Context, network, addr string) (net.Conn, error)) *Client {
	transport := &http.Transport{
		DialContext:            dial,
		Proxy:                  nil, // a proxy is one more host that would see every request
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    5 * time.Second,
		MaxResponseHeaderBytes: 16384,
		DisableCompression:     true,
		// Requests are rare, and an idle connection would outlive the service's stop.
		DisableKeepAlives: true,
	}
	// A redirect may name any host; the 3xx itself is the answer.
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{
		hosts: slices.Clone(hosts),
		http:  &http.Client{Transport: transport, Timeout: Timeout, CheckRedirect: noRedirect},
		get:   &http.Client{Transport: transport, Timeout: GetTimeout, CheckRedirect: noRedirect},
	}
}

// Header is one more header of a request.
type Header struct{ Name, Value string }

// Post sends body to rawURL. A URL that is not https or whose host is not
// listed fails before any I/O. Each header is set after Content-Type.
func (c *Client) Post(ctx context.Context, rawURL, contentType string, body []byte, headers ...Header) (Response, error) {
	first := Header{Name: "Content-Type", Value: contentType}
	resp, err := c.send(ctx, c.http, http.MethodPost, rawURL, bytes.NewReader(body), append([]Header{first}, headers...))
	if err != nil {
		return Response{}, err
	}
	// The status is the answer. A body cut short by a failure only shortens
	// it; turning a 2xx into an error would send it twice.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	_ = resp.Body.Close()
	return answer(resp, data), nil
}

// Get asks rawURL. A URL that is not https or whose host is not listed fails
// before any I/O. At most limit octets of the body are read; a longer body
// gives ErrTooLarge and no body, so that a cut text is never read. Each
// header is set after "Accept: application/json".
func (c *Client) Get(ctx context.Context, rawURL string, limit int64, headers ...Header) (Response, error) {
	// The transport calls GotConn on this goroutine, before Do returns, and
	// only once the TLS handshake has checked the certificate.
	var addr netip.AddrPort
	trace := &httptrace.ClientTrace{GotConn: func(info httptrace.GotConnInfo) {
		addr, _ = netip.ParseAddrPort(info.Conn.RemoteAddr().String())
	}}
	first := Header{Name: "Accept", Value: "application/json"}
	resp, err := c.send(httptrace.WithClientTrace(ctx, trace), c.get, http.MethodGet, rawURL, nil, append([]Header{first}, headers...))
	if err != nil {
		return Response{}, err
	}
	// The octet after the limit tells a body of exactly the limit from a
	// longer one. Unlike Post, a failure while reading is an error: the
	// caller reads the body whole or not at all.
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	_ = resp.Body.Close()
	switch {
	case err != nil:
		return Response{}, doError(err)
	case int64(len(data)) > limit:
		return Response{}, ErrTooLarge
	}
	r := answer(resp, data)
	r.Addr = addr
	return r, nil
}

// send makes one request through hc, with the headers set in order, and
// gives the answer with its body still to read. A URL that is not https or
// whose host is not listed fails before any I/O.
func (c *Client) send(ctx context.Context, hc *http.Client, method, rawURL string, body io.Reader, headers []Header) (*http.Response, error) {
	u, err := parse(rawURL)
	if err != nil {
		return nil, err
	}
	if !slices.Contains(c.hosts, hostPort(u)) {
		return nil, ErrHost
	}
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, ErrURL
	}
	for _, h := range headers {
		req.Header.Set(h.Name, h.Value)
	}
	resp, err := hc.Do(req)
	if err != nil {
		// net/http lets the dial of a cut request go on, for a later request
		// to use. This client keeps no connection, so the dial would only
		// outlive the work, a stop of the service included.
		hc.CloseIdleConnections()
		return nil, doError(err)
	}
	return resp, nil
}

func answer(resp *http.Response, body []byte) Response {
	return Response{
		Status:     resp.StatusCode,
		RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		Date:       date(resp.Header.Get("Date")),
		Body:       body,
	}
}

func date(v string) time.Time {
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// The failures of a request other than ErrURL, ErrHost, ErrTimeout and
// ErrNotPermitted. The text of a Go error can hold the URL or octets of the
// answer, such as a bad header line, so none is passed on.
var (
	errLookup  = errors.New("network: name lookup failed")
	errCert    = errors.New("network: certificate not trusted")
	errConnect = errors.New("network: cannot connect")
	errAnswer  = errors.New("network: no usable answer")
)

func doError(err error) error {
	var timeout interface{ Timeout() bool }
	var lookup *net.DNSError
	var cert *tls.CertificateVerificationError
	var op *net.OpError
	var refused errRefused
	switch {
	case errors.As(err, &refused):
		return refused
	case errors.Is(err, context.DeadlineExceeded) || errors.As(err, &timeout) && timeout.Timeout():
		return ErrTimeout
	case errors.As(err, &lookup):
		return errLookup
	case errors.As(err, &cert):
		return errCert
	case errors.As(err, &op) && op.Op == "dial":
		return errConnect
	}
	return errAnswer
}

// retryAfter reads Retry-After in seconds, at most one day. The HTTP-date
// form counts as absent: it depends on the clocks of both sides.
func retryAfter(v string) time.Duration {
	if len(v) < 1 || len(v) > 6 || strings.ContainsFunc(v, func(r rune) bool { return r < '0' || r > '9' }) {
		return 0
	}
	n, err := strconv.Atoi(v)
	if err != nil || n > 86400 {
		return 0
	}
	return time.Duration(n) * time.Second
}
