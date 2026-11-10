// Command receiver is the webhook receiver of the DNS lab.
//
// It answers every request on HTTPS port 443 and stores it. A plain HTTP control
// interface on port 8080, reachable only inside the lab network, serves labctl.
package main

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

type request struct {
	Time    string      `json:"time"`
	Method  string      `json:"method"`
	Path    string      `json:"path"`
	Headers http.Header `json:"headers"`
	Body    string      `json:"body"`
	Status  int         `json:"status"`
}

// reply is how the receiver answers the next count requests.
type reply struct {
	status int
	header http.Header
	delay  time.Duration
	body   string
	count  int
}

type receiver struct {
	mu       sync.Mutex
	requests []request
	next     reply
}

func (rc *receiver) hook(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	rp := reply{status: http.StatusOK}
	if rc.next.count > 0 {
		rp = rc.next
		rc.next.count--
	}
	rc.requests = append(rc.requests, request{
		Time:    time.Now().UTC().Format(time.RFC3339Nano),
		Method:  r.Method,
		Path:    r.URL.RequestURI(),
		Headers: r.Header,
		Body:    string(body),
		Status:  rp.status,
	})
	rc.mu.Unlock()
	time.Sleep(rp.delay)
	for name, values := range rp.header {
		for _, v := range values {
			w.Header().Add(name, v)
		}
	}
	w.WriteHeader(rp.status)
	// A failed write means that the client left; the request is stored.
	_, _ = io.WriteString(w, rp.body)
}

func (rc *receiver) list(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	defer rc.mu.Unlock()
	enc := json.NewEncoder(w)
	for _, req := range rc.requests {
		if err := enc.Encode(req); err != nil {
			return
		}
	}
}

func (rc *receiver) clear(w http.ResponseWriter, r *http.Request) {
	rc.mu.Lock()
	rc.requests = nil
	rc.mu.Unlock()
}

// setReply takes the form fields status, count, delay (seconds), body and
// headers ("Name: value" lines).
func (rc *receiver) setReply(w http.ResponseWriter, r *http.Request) {
	// A 1xx status would only be sent ahead of a final 200.
	status, err1 := strconv.Atoi(r.FormValue("status"))
	count, err2 := strconv.Atoi(r.FormValue("count"))
	delay, err3 := time.ParseDuration(r.FormValue("delay") + "s")
	if err1 != nil || err2 != nil || err3 != nil || status < 200 || status > 599 || count < 0 || delay < 0 {
		http.Error(w, "want status 200 to 599, count 0 or more and delay 0 or more", http.StatusBadRequest)
		return
	}
	header := http.Header{}
	for line := range strings.Lines(r.FormValue("headers")) {
		name, value, ok := strings.Cut(line, ":")
		if !ok || strings.TrimSpace(name) == "" {
			http.Error(w, "want headers as Name: value lines", http.StatusBadRequest)
			return
		}
		header.Add(strings.TrimSpace(name), strings.TrimSpace(value))
	}
	rc.mu.Lock()
	rc.next = reply{
		status: status,
		header: header,
		delay:  delay,
		body:   r.FormValue("body"),
		count:  count,
	}
	rc.mu.Unlock()
}

func main() {
	rc := &receiver{}
	control := http.NewServeMux()
	control.HandleFunc("GET /requests", rc.list)
	control.HandleFunc("POST /clear", rc.clear)
	control.HandleFunc("POST /reply", rc.setReply)
	go func() { log.Fatal(http.ListenAndServe(":8080", control)) }()
	log.Fatal(http.ListenAndServeTLS(":443", "/lab/hooks.pem", "/lab/hooks.key", http.HandlerFunc(rc.hook)))
}
