package deliver_test

import (
	"context"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
)

// Both channels pass on the Date of the answer, also of a refusal, and the
// zero time when the answer has none or no answer came.
func TestSendPassesOnTheDateOfTheAnswer(t *testing.T) {
	date := time.Date(2026, 11, 16, 10, 4, 5, 0, time.UTC)
	srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/none":
			// Without this the server adds a Date of its own.
			w.Header()["Date"] = nil
		case "/gone":
			w.Header().Set("Date", date.Format(http.TimeFormat))
			w.WriteHeader(http.StatusNotFound)
		default:
			w.Header().Set("Date", date.Format(http.TimeFormat))
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
	unreachable := httpclient.New([]string{closed}, nil)
	key := []byte("0123456789abcdef0123456789abcdef")
	channels := func(c *httpclient.Client, url string) []deliver.Channel {
		return []deliver.Channel{
			deliver.NewSlack(c, url, decide.SeverityLow),
			deliver.NewWebhook(c, "siem", url, key, decide.SeverityLow),
		}
	}
	cases := []struct {
		name   string
		client *httpclient.Client
		url    string
		status int
		date   time.Time
	}{
		{"sent", client, srv.URL + "/ok", http.StatusOK, date},
		{"refused", client, srv.URL + "/gone", http.StatusNotFound, date},
		{"no date", client, srv.URL + "/none", http.StatusOK, time.Time{}},
		{"no answer", unreachable, "https://" + closed + "/x", 0, time.Time{}},
	}
	for _, c := range cases {
		for _, ch := range channels(c.client, c.url) {
			o := ch.Send(context.Background(), []byte("{}"))
			if o.Status != c.status || !o.Date.Equal(c.date) || (c.status == 0) != (o.Err != "") {
				t.Errorf("%s, channel %s: %+v; want status %d and Date %v", c.name, ch.Name(), o, c.status, c.date)
			}
		}
	}
}
