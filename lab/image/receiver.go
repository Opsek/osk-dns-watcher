// Command receiver is the webhook receiver of the DNS lab.
//
// It answers every request on HTTPS port 443 and stores it. A plain HTTP control
// interface on port 8080, reachable only inside the lab network, serves labctl.
package main

import (
	"cmp"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"slices"
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

// issuance is one entry of the set that stands in for a certificate log. The
// receiver reads only what it needs to page the set and keeps the rest as sent.
type issuance struct {
	id    uint64
	names []string
	raw   json.RawMessage
}

// certFail is how the stand-in answers the next count lookups.
type certFail struct {
	status int
	retry  int
	count  int
}

// certPage is the number of issuances in one page; it is small so that every
// listing needs several pages.
const certPage = 2

type receiver struct {
	mu        sync.Mutex
	requests  []request
	next      reply
	issuances []issuance
	failing   certFail
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

// lookup serves the stand-in of a certificate log: the issuances of the set
// that name the domain or a name below it, with an id above after, at most
// certPage of them in id order. Its requests are not stored with the webhook
// requests, which the scenarios count.
func (rc *receiver) lookup(w http.ResponseWriter, r *http.Request) {
	domain := strings.TrimSuffix(strings.ToLower(r.FormValue("domain")), ".")
	var after uint64
	if r.FormValue("after") != "" {
		var err error
		if after, err = strconv.ParseUint(r.FormValue("after"), 10, 64); err != nil {
			http.Error(w, "want after as digits", http.StatusBadRequest)
			return
		}
	}
	if domain == "" {
		http.Error(w, "want a domain", http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	defer rc.mu.Unlock()
	if rc.failing.count > 0 {
		rc.failing.count--
		if rc.failing.retry > 0 {
			w.Header().Set("Retry-After", strconv.Itoa(rc.failing.retry))
		}
		w.WriteHeader(rc.failing.status)
		return
	}
	page := []json.RawMessage{}
	for _, is := range rc.issuances {
		if is.id > after && namesUnder(is.names, domain) && len(page) < certPage {
			page = append(page, is.raw)
		}
	}
	if len(page) == 0 {
		w.Header().Set("Retry-After", "1")
	}
	w.Header().Set("Content-Type", "application/json")
	// A failed write means that the client left.
	_ = json.NewEncoder(w).Encode(page)
}

func namesUnder(names []string, domain string) bool {
	for _, n := range names {
		n = strings.ToLower(n)
		if n == domain || strings.HasSuffix(n, "."+domain) {
			return true
		}
	}
	return false
}

// setIssuances replaces the set with the JSON array of the body. Each element
// needs a numeric id and may have dns_names; the stand-in checks nothing else,
// so that a test can also store a malformed entry on purpose.
func (rc *receiver) setIssuances(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	var raws []json.RawMessage
	if err == nil {
		err = json.Unmarshal(body, &raws)
	}
	if err != nil {
		http.Error(w, "want a JSON array of issuances", http.StatusBadRequest)
		return
	}
	set := make([]issuance, 0, len(raws))
	for _, raw := range raws {
		var is struct {
			ID       string   `json:"id"`
			DNSNames []string `json:"dns_names"`
		}
		if json.Unmarshal(raw, &is) != nil {
			http.Error(w, "want each issuance as an object with dns_names as strings", http.StatusBadRequest)
			return
		}
		id, err := strconv.ParseUint(is.ID, 10, 64)
		if err != nil {
			http.Error(w, "want each issuance with an id of digits and dns_names as strings", http.StatusBadRequest)
			return
		}
		set = append(set, issuance{id: id, names: is.DNSNames, raw: raw})
	}
	slices.SortFunc(set, func(a, b issuance) int { return cmp.Compare(a.id, b.id) })
	rc.mu.Lock()
	rc.issuances = set
	rc.mu.Unlock()
}

// failIssuances takes the form fields status, count and retry (seconds).
func (rc *receiver) failIssuances(w http.ResponseWriter, r *http.Request) {
	status, err1 := strconv.Atoi(r.FormValue("status"))
	count, err2 := strconv.Atoi(r.FormValue("count"))
	retry, err3 := strconv.Atoi(r.FormValue("retry"))
	if r.FormValue("retry") == "" {
		retry, err3 = 0, nil
	}
	if err1 != nil || err2 != nil || err3 != nil || status < 200 || status > 599 || count < 0 || retry < 0 {
		http.Error(w, "want status 200 to 599, count 0 or more and retry 0 or more", http.StatusBadRequest)
		return
	}
	rc.mu.Lock()
	rc.failing = certFail{status: status, retry: retry, count: count}
	rc.mu.Unlock()
}

func main() {
	rc := &receiver{}
	tls := http.NewServeMux()
	tls.HandleFunc("GET /v1/issuances", rc.lookup)
	tls.HandleFunc("/", rc.hook)
	control := http.NewServeMux()
	control.HandleFunc("POST /issuances", rc.setIssuances)
	control.HandleFunc("POST /issuances/fail", rc.failIssuances)
	control.HandleFunc("GET /requests", rc.list)
	control.HandleFunc("POST /clear", rc.clear)
	control.HandleFunc("POST /reply", rc.setReply)
	go func() { log.Fatal(http.ListenAndServe(":8080", control)) }()
	log.Fatal(http.ListenAndServeTLS(":443", "/lab/hooks.pem", "/lab/hooks.key", tls))
}
