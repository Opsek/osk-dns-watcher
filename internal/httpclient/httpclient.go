// Package httpclient is the one HTTPS client of osk. It posts only to hosts
// fixed when the client is made, never follows a redirect and uses no proxy,
// so no data that it handles can send a request elsewhere. A webhook URL
// carries its secret in the path, so no error holds the URL or any text of
// the answer. The body of an answer may repeat the URL.
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
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"
)

// Timeout bounds one request: connect, TLS, send, headers and body.
const Timeout = 10 * time.Second

// MaxBody is the most octets of a response body that Post reads.
const MaxBody = 4096

var ErrURL = errors.New("not an https URL with a host and no user name")
var ErrHost = errors.New("host not allowed")
var ErrTimeout = errors.New("timeout")

type Client struct {
	hosts []string
	http  *http.Client
}

type Response struct {
	Status     int
	RetryAfter time.Duration // 0 when absent or not a number of seconds
	Date       time.Time     // the server's clock; zero when the header is absent or not valid
	Body       []byte        // at most MaxBody octets, as the server sent them
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

// parse never returns the error of url.Parse, whose text holds the URL. A
// host outside ASCII is refused: in lower case it can equal a listed host,
// while the lookup asks for another one.
func parse(rawURL string) (*url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.Opaque != "" ||
		strings.ContainsFunc(u.Hostname(), func(r rune) bool { return r >= utf8.RuneSelf }) {
		return nil, ErrURL
	}
	return u, nil
}

func hostPort(u *url.URL) string {
	port := u.Port()
	if port == "" {
		port = "443"
	}
	return net.JoinHostPort(strings.ToLower(u.Hostname()), port)
}

// New makes a client that posts only to hosts, each in the form HostOf gives.
// No method adds a host later. A nil roots means the trust store of the system.
func New(hosts []string, roots *x509.CertPool) *Client {
	transport := &http.Transport{
		Proxy:                  nil, // a proxy is one more host that would see every request
		TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots},
		TLSHandshakeTimeout:    5 * time.Second,
		MaxResponseHeaderBytes: 16384,
		DisableCompression:     true,
		// Alerts are rare, and an idle connection would outlive the service's stop.
		DisableKeepAlives: true,
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   Timeout,
		// A redirect may name any host; the 3xx itself is the answer.
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	return &Client{hosts: slices.Clone(hosts), http: client}
}

// Header is one more header of a request.
type Header struct{ Name, Value string }

// Post sends body to rawURL. A URL that is not https or whose host is not
// listed fails before any I/O. Each header is set after Content-Type.
func (c *Client) Post(ctx context.Context, rawURL, contentType string, body []byte, headers ...Header) (Response, error) {
	u, err := parse(rawURL)
	if err != nil {
		return Response{}, err
	}
	if !slices.Contains(c.hosts, hostPort(u)) {
		return Response{}, ErrHost
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return Response{}, ErrURL
	}
	req.Header.Set("Content-Type", contentType)
	for _, h := range headers {
		req.Header.Set(h.Name, h.Value)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		// net/http lets the dial of a cut request go on, for a later request
		// to use. This client keeps no connection, so the dial would only
		// outlive the work, a stop of the service included.
		c.http.CloseIdleConnections()
		return Response{}, doError(err)
	}
	// The status is the answer. A body cut short by a failure only shortens
	// it; turning a 2xx into an error would send it twice.
	data, _ := io.ReadAll(io.LimitReader(resp.Body, MaxBody))
	_ = resp.Body.Close()
	return Response{
		Status:     resp.StatusCode,
		RetryAfter: retryAfter(resp.Header.Get("Retry-After")),
		Date:       date(resp.Header.Get("Date")),
		Body:       data,
	}, nil
}

func date(v string) time.Time {
	t, err := http.ParseTime(v)
	if err != nil {
		return time.Time{}
	}
	return t
}

// The failures of Post other than ErrURL, ErrHost and ErrTimeout. The text
// of a Go error can hold the URL or octets of the answer, such as a bad
// header line, so none is passed on.
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
	switch {
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
