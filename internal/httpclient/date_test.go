package httpclient_test

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
)

// The Date of an answer is read in each of the three forms that HTTP allows,
// whatever the status. An answer without one, or with one that is not an
// HTTP date, gives the zero time and is still an answer.
func TestPostGivesTheDateZeroWhenAbsentOrBad(t *testing.T) {
	date := time.Date(2026, 11, 16, 10, 4, 5, 0, time.UTC)
	cases := []struct {
		value  []string // nil: no Date header at all
		status int
		want   time.Time
	}{
		{[]string{"Mon, 16 Nov 2026 10:04:05 GMT"}, http.StatusOK, date},
		{[]string{"Monday, 16-Nov-26 10:04:05 GMT"}, http.StatusOK, date},
		{[]string{"Mon Nov 16 10:04:05 2026"}, http.StatusOK, date},
		{[]string{"Mon, 16 Nov 2026 10:04:05 GMT"}, http.StatusNotFound, date},
		{[]string{"Mon, 16 Nov 2026 10:04:05 GMT"}, http.StatusTooManyRequests, date},
		{nil, http.StatusOK, time.Time{}},
		{nil, http.StatusNotFound, time.Time{}},
		{[]string{""}, http.StatusOK, time.Time{}},
		{[]string{"yesterday"}, http.StatusOK, time.Time{}},
		{[]string{"2026-11-16T10:04:05Z"}, http.StatusOK, time.Time{}},
		{[]string{"Mon, 16 Nov 2026 10:04:05"}, http.StatusOK, time.Time{}},
		{[]string{"Mon, 32 Nov 2026 10:04:05 GMT"}, http.StatusOK, time.Time{}},
		{[]string{"1794823445"}, http.StatusOK, time.Time{}},
	}
	// The path names the case. Without a Date of the handler's own, the
	// server adds one, so a nil value removes it.
	srv, host, pool := hclServer(t, func(w http.ResponseWriter, r *http.Request) {
		i, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
		if err != nil {
			t.Errorf("path %q names no case", r.URL.Path)
			return
		}
		w.Header()["Date"] = cases[i].value
		w.WriteHeader(cases[i].status)
	})
	c := httpclient.New([]string{host}, pool)
	for i, tc := range cases {
		resp, err := c.Post(context.Background(), srv.URL+"/"+strconv.Itoa(i), "application/json", []byte("{}"))
		if err != nil || resp.Status != tc.status || !resp.Date.Equal(tc.want) {
			t.Errorf("Date %q with status %d: %+v, %v; want status %d and Date %v",
				tc.value, tc.status, resp, err, tc.status, tc.want)
		}
	}
}
