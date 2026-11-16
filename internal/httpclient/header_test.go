package httpclient_test

import (
	"context"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/httpclient"
)

// Extra headers reach the server with their names and values, beside the
// content type, and bring no other header with them.
func TestPostSendsExtraHeaders(t *testing.T) {
	got := make(chan http.Header, 1)
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) { got <- r.Header.Clone() })
	sig := "sha256=" + strings.Repeat("0f", 32)
	resp, err := httpclient.New([]string{host}, pool).Post(context.Background(), srv.URL+"/hook", "application/json", []byte("{}"),
		httpclient.Header{Name: "Osk-Timestamp", Value: "1794405727"},
		httpclient.Header{Name: "Osk-Signature", Value: sig})
	if err != nil || resp.Status != http.StatusOK {
		t.Fatalf("Post: %+v, %v; want status 200", resp, err)
	}
	h := <-got
	for name, want := range map[string][]string{
		"Content-Type": {"application/json"}, "Osk-Timestamp": {"1794405727"}, "Osk-Signature": {sig},
	} {
		if !reflect.DeepEqual(h[name], want) {
			t.Errorf("%s %q, want %q", name, h[name], want)
		}
	}
	for name := range h {
		switch name {
		case "Content-Type", "Content-Length", "Osk-Timestamp", "Osk-Signature", "Connection":
		default:
			if !strings.HasPrefix(name, "User-") {
				t.Errorf("the request carries the header %s: %q", name, h[name])
			}
		}
	}
}

// Each header is set after the content type, so a header of that name
// replaces it rather than adding a second value.
func TestPostHeaderSetAfterContentType(t *testing.T) {
	got := make(chan http.Header, 1)
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) { got <- r.Header.Clone() })
	_, err := httpclient.New([]string{host}, pool).Post(context.Background(), srv.URL+"/hook", "application/json", nil,
		httpclient.Header{Name: "Content-Type", Value: "text/plain"})
	if err != nil {
		t.Fatal(err)
	}
	if h := <-got; !reflect.DeepEqual(h["Content-Type"], []string{"text/plain"}) {
		t.Errorf("Content-Type %q, want only text/plain", h["Content-Type"])
	}
}
