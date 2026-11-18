package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// These tests run the service against a source of certificates that is one
// local HTTPS server. The service trusts it through SSL_CERT_FILE, which the
// system roots read once for the whole process, so TestMain starts the server
// and loads the roots before any test can make an HTTPS request.

const (
	crtKeyEnv   = "OSK_CRT_KEY"
	crtKeyValue = "crtkeysecret"
	crtGood     = "ca.test"
	crtBad      = "evil.test"

	// crtFile permits one authority by an issuer line. Its names are all
	// "corp.test.", which the file knows, so a certificate for it that comes
	// from crtGood gives no alert of any rule.
	crtFile = "domain corp.test.\nissuer ca.test\ncorp.test. DS none\n"

	crtCheck = "checked certificates certificates corp.test. "
	crtTail  = " certificates corp.test."

	crtIssuerOpen    = "alert open high issuer certificates corp.test."
	crtIssuerResolve = "alert resolve high issuer certificates corp.test."
	crtFailingOpen   = "alert open medium check-failing certificates corp.test."
	crtFailingEnd    = "alert resolve medium check-failing certificates corp.test."

	// The words of the Slack message that tell an open from a resolve.
	crtOpenWords    = "a certificate for a name of"
	crtResolveWords = "no valid certificate for a name of"
)

// crtQuery is what a request of the first page must ask, and crtQueryRE
// every request.
const crtQuery = "domain=corp.test&include_subdomains=true&expand=dns_names&expand=issuer&expand=issuer.caa_domains"

var crtQueryRE = regexp.MustCompile(`^` + regexp.QuoteMeta(crtQuery) + `(&after=[1-9][0-9]*)?$`)

// ---- The source ----

type crtReq struct{ method, path, query, auth string }

type crtReply struct {
	status int
	retry  string // Retry-After; none when empty
	body   string
}

// crtSource answers like the real source: the issuances with an id above
// after, in id order, pageSize at most; an empty page with Retry-After when
// none is left.
type crtSource struct {
	mu       sync.Mutex
	list     []map[string]any
	pageSize int
	retry    string              // Retry-After of an empty page
	failure  *crtReply           // when set, the answer to every request
	ignore   bool                // the source does not follow after: every page starts at the first issuance
	gate     func(*http.Request) // called before each answer, holds the request until it returns
	reqs     []crtReq
}

func (s *crtSource) set(list ...map[string]any) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.list = list
}

func (s *crtSource) fail(status int, retry, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = &crtReply{status, retry, body}
}

func (s *crtSource) recover() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failure = nil
}

func (s *crtSource) requests() []crtReq {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]crtReq(nil), s.reqs...)
}

func (s *crtSource) serve(w http.ResponseWriter, r *http.Request) {
	s.mu.Lock()
	s.reqs = append(s.reqs, crtReq{r.Method, r.URL.Path, r.URL.RawQuery, r.Header.Get("Authorization")})
	list, failure, retry, size, ignore, gate := s.list, s.failure, s.retry, s.pageSize, s.ignore, s.gate
	s.mu.Unlock()
	if gate != nil {
		gate(r)
	}
	if failure != nil {
		if failure.retry != "" {
			w.Header().Set("Retry-After", failure.retry)
		}
		w.WriteHeader(failure.status)
		_, _ = io.WriteString(w, failure.body)
		return
	}
	after, _ := strconv.Atoi(r.URL.Query().Get("after"))
	if ignore {
		after = 0
	}
	page := []map[string]any{}
	for _, it := range list {
		if id, _ := strconv.Atoi(it["id"].(string)); id > after && len(page) < size {
			page = append(page, it)
		}
	}
	if len(page) == 0 && retry != "" {
		w.Header().Set("Retry-After", retry)
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(page)
}

// crtIssuance is one issuance in the form of the source, valid for 90 days.
func crtIssuance(id int, authority string, names ...string) map[string]any {
	now := time.Now().UTC()
	return map[string]any{
		"id":         strconv.Itoa(id),
		"tbs_sha256": fmt.Sprintf("%064x", id),
		"not_before": now.Add(-time.Hour).Format(time.RFC3339),
		"not_after":  now.Add(90 * 24 * time.Hour).Format(time.RFC3339),
		"dns_names":  names,
		"issuer":     map[string]any{"friendly_name": "Lab CA", "caa_domains": []string{authority}},
	}
}

func crtClean(id int) map[string]any { return crtIssuance(id, crtGood, "corp.test") }
func crtEvil(id int) map[string]any  { return crtIssuance(id, crtBad, "corp.test") }

// crtActive is the source of the test that runs; the one server serves them
// one after the other.
var crtActive struct {
	mu  sync.Mutex
	src *crtSource
}

var crtSlack struct {
	mu     sync.Mutex
	bodies []string
}

func crtHandle(w http.ResponseWriter, r *http.Request) {
	if strings.HasPrefix(r.URL.Path, "/x/") {
		body, _ := io.ReadAll(r.Body)
		crtSlack.mu.Lock()
		crtSlack.bodies = append(crtSlack.bodies, string(body))
		crtSlack.mu.Unlock()
		_, _ = io.WriteString(w, "ok")
		return
	}
	crtActive.mu.Lock()
	src := crtActive.src
	crtActive.mu.Unlock()
	if src == nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	src.serve(w, r)
}

// crtSlackDistinct counts the different messages that hold one of words. A
// send that the stop cut after the server took it is tried again at the next
// start with the same stored body, so across a restart the same message may
// arrive twice; a second alert would have a body of its own.
func crtSlackDistinct(words ...string) int {
	crtSlack.mu.Lock()
	defer crtSlack.mu.Unlock()
	seen := map[string]bool{}
	for _, b := range crtSlack.bodies {
		for _, w := range words {
			if strings.Contains(b, w) {
				seen[b] = true
			}
		}
	}
	return len(seen)
}

func crtSlackCount(words string) int {
	crtSlack.mu.Lock()
	defer crtSlack.mu.Unlock()
	n := 0
	for _, b := range crtSlack.bodies {
		if strings.Contains(b, words) {
			n++
		}
	}
	return n
}

// crtWaitSlack waits until n messages hold words.
func crtWaitSlack(t *testing.T, words string, n int) {
	t.Helper()
	deadline := time.Now().Add(runPatience)
	for crtSlackCount(words) < n {
		if time.Now().After(deadline) {
			t.Fatalf("fewer than %d Slack messages with %q by the deadline", n, words)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// crtTLS is set by TestMain; a set-up error fails each test that needs the
// server instead of stopping the package.
var crtTLS struct {
	srv *httptest.Server
	err error
}

// crtBase gives the address of the one server.
func crtBase(t *testing.T) string {
	t.Helper()
	if crtTLS.err != nil {
		t.Fatal(crtTLS.err)
	}
	return crtTLS.srv.URL
}

func crtListen(dir string) (*httptest.Server, error) {
	srv := httptest.NewTLSServer(http.HandlerFunc(crtHandle))
	roots := filepath.Join(dir, "roots.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		return nil, err
	}
	old, had := os.LookupEnv("SSL_CERT_FILE")
	if err := os.Setenv("SSL_CERT_FILE", roots); err != nil {
		return nil, err
	}
	defer func() {
		if had {
			_ = os.Setenv("SSL_CERT_FILE", old)
		} else {
			_ = os.Unsetenv("SSL_CERT_FILE")
		}
	}()
	// Asking for the pool loads the system roots now, with the file above.
	pool, err := x509.SystemCertPool()
	if err == nil {
		_, err = srv.Certificate().Verify(x509.VerifyOptions{Roots: pool})
	}
	if err != nil {
		srv.Close()
		return nil, errors.New("the system roots do not trust the test source (they were loaded before the test, or this system does not read SSL_CERT_FILE): " + err.Error())
	}
	return srv, nil
}

// ---- The service ----

type crtCfgCerts struct {
	URL      string     `json:"url"`
	Key      *runSecret `json:"key,omitempty"`
	Interval string     `json:"interval"`
}

type crtCfg struct {
	runCfg
	Certificates *crtCfgCerts `json:"certificates,omitempty"`
}

// crtSetup is a service to start, and start again, on one state folder.
type crtSetup struct {
	src   *crtSource
	args  []string
	state string
}

// crtNew makes a config of the domain corp.test. with the one file, Slack at
// the test server, and the certificates source at the test server too, every
// 5 s, with a key when key is not empty. Every other check runs once.
func crtNew(t *testing.T, file, key string) *crtSetup {
	t.Helper()
	return crtNewFor(t, key, runCfgDomain{Name: "corp.test.", Expect: expFile(t, file)})
}

// crtNewFor is crtNew for any domains, each with its own file.
func crtNewFor(t *testing.T, key string, domains ...runCfgDomain) *crtSetup {
	t.Helper()
	base := crtBase(t)
	src := &crtSource{pageSize: 2}
	crtActive.mu.Lock()
	crtActive.src = src
	crtActive.mu.Unlock()
	crtSlack.mu.Lock()
	crtSlack.bodies = nil
	crtSlack.mu.Unlock()
	// A cleanup runs after those registered later, so the source stays until
	// the service of the test returned.
	t.Cleanup(func() {
		crtActive.mu.Lock()
		crtActive.src = nil
		crtActive.mu.Unlock()
	})

	t.Setenv("OSK_SLACK_URL", base+"/x/"+runMarker)
	certs := &crtCfgCerts{URL: base + "/v1/issuances", Interval: "5s"}
	if key != "" {
		t.Setenv(crtKeyEnv, key)
		certs.Key = &runSecret{Env: crtKeyEnv}
	}
	state := filepath.Join(t.TempDir(), "state")
	dns := transportStart(t, expWorld)
	base0 := runLocalCfg(dns, state, runIntervals("1h", "1h", "1h", "1h"), domains...)
	base0.Slack.MinSeverity = "high"
	text, err := json.MarshalIndent(crtCfg{base0, certs}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := runConfigText(t, string(text)+"\n")
	if _, problems := config.Parse(path, text); len(problems) > 0 {
		t.Fatalf("the test wrote a config that is not valid: %v", problems)
	}
	return &crtSetup{src: src, args: []string{"--config", path}, state: state}
}

// ---- Lines ----

// crtRest reads a line of a certificates run: its start and what follows it.
func crtRest(text string) (start time.Time, rest string, ok bool) {
	tail, ok := strings.CutPrefix(text, crtCheck)
	if !ok {
		return time.Time{}, "", false
	}
	at, rest, _ := strings.Cut(tail, " ")
	start, err := time.Parse(runLineLayout, at)
	return start, rest, err == nil && start.Format(runLineLayout) == at
}

// crtRun accepts the line of a run that ends exactly with rest.
func crtRun(rest string) func(string) bool {
	return func(text string) bool {
		_, got, ok := crtRest(text)
		return ok && got == rest
	}
}

// crtWaitRun waits for the next run line that ends with rest.
func crtWaitRun(t *testing.T, svc *runService, from int, rest string) (runLine, int) {
	t.Helper()
	return svc.wait(t, "a certificates run: "+rest, from, time.Now().Add(runPatience), crtRun(rest))
}

func crtWaitLine(t *testing.T, svc *runService, from int, text string) (runLine, int) {
	t.Helper()
	return svc.wait(t, text, from, time.Now().Add(runPatience), runIs(text))
}

// crtAlerts gives the alert lines of the certificates check, in order.
func crtAlerts(lines []runLine) []string {
	var out []string
	for _, l := range lines {
		if l.event == "alert" && strings.HasSuffix(l.text, crtTail) {
			out = append(out, l.text)
		}
	}
	return out
}

// crtNoAlert fails on an alert line of the certificates check among the lines
// before index to.
func crtNoAlert(t *testing.T, what string, lines []runLine, to int) {
	t.Helper()
	if got := crtAlerts(lines[:to]); len(got) > 0 {
		t.Errorf("%s: alert lines %q, want none", what, got)
	}
}

// crtRequests checks every request that the source got: a GET of the path
// with the query that the source takes and the header that the config gives.
func crtRequests(t *testing.T, src *crtSource, auth string) []crtReq {
	t.Helper()
	reqs := src.requests()
	for i, r := range reqs {
		if r.method != "GET" || r.path != "/v1/issuances" || !crtQueryRE.MatchString(r.query) || r.auth != auth {
			t.Errorf("request %d: %s %s?%s with Authorization %q; want GET /v1/issuances?%s[&after=<id>] with %q",
				i+1, r.method, r.path, r.query, r.auth, crtQuery, auth)
		}
	}
	return reqs
}

// crtOpenAlerts reads the open alerts of the certificates check from the state
// folder. Call it only after every service on the folder returned.
func crtOpenAlerts(t *testing.T, state string) []alert.Alert {
	t.Helper()
	s, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	}()
	alerts, err := s.OpenAlerts(obs.CertificatesKey(cliName("corp.test.")))
	if err != nil {
		t.Fatal(err)
	}
	return alerts
}

// crtIssuerAlert checks the alert that crtEvil makes, as read back from the
// store: its line has no server, no address and no TTL.
func crtIssuerAlert(t *testing.T, alerts []alert.Alert) {
	t.Helper()
	if len(alerts) != 1 {
		t.Fatalf("%d open alerts in the store, want 1: %+v", len(alerts), alerts)
	}
	a := alerts[0]
	const seen = "corp.test. from evil.test"
	if a.Rule != decide.RuleIssuer || a.Severity != decide.SeverityHigh || a.Expected != "issuer ca.test" || a.Value != seen {
		t.Errorf("the open alert is %s %s expected %q value %q; want issuer high, %q and %q",
			a.Rule, a.Severity, a.Expected, a.Value, "issuer ca.test", seen)
	}
	if len(a.Lines) != 1 || a.Lines[0].Text != seen || a.Lines[0].Server.Name.LabelCount() != 0 ||
		a.Lines[0].Server.Addr.IsValid() || a.Lines[0].TTL != 0 || a.Lines[0].Received.IsZero() {
		t.Errorf("the lines of the open alert are %+v, want one with the text %q, no server, no TTL and a time", a.Lines, seen)
	}
}

// ---- Tests ----

func TestCrtPlanLineAndCleanFirstRun(t *testing.T) {
	c := crtNew(t, crtFile, crtKeyValue)
	c.src.set(crtClean(1))
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "ok 1 valid")
	crtWaitRun(t, svc, i+1, "ok 1 valid")
	lines := svc.stop(t)

	var plans []string
	for _, l := range lines {
		if l.event == "plan" {
			plans = append(plans, l.text)
		}
		if _, _, ok := crtRest(l.text); ok && l.domain != "corp.test." {
			t.Errorf("the line %q names the domain %q, want corp.test.", l.text, l.domain)
		}
	}
	if len(plans) != 5 || plans[4] != "plan certificates every 5s 1 checks" {
		t.Errorf("the plan lines are %q, want five, the last being %q", plans, "plan certificates every 5s 1 checks")
	}
	cfg, problems := config.Read(c.args[1])
	if cfg == nil {
		t.Fatalf("the config: %v", problems)
	}
	head := []string{"config " + c.args[1] + ": 1 domains, channels slack"}
	for _, w := range cfg.Warnings() {
		head = append(head, "warning "+w)
	}
	var got []string
	for _, l := range lines {
		if l.event == "start" {
			break
		}
		got = append(got, l.text)
	}
	if strings.Join(got, "\n") != strings.Join(head, "\n") {
		t.Errorf("the start began with:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(head, "\n"))
	}
	if n := svcCount(lines, "start corp.test. 4 checks, state "+c.state); n != 1 {
		t.Errorf("the start line with 4 checks (three of the DNS and the certificates) printed %d times, want 1:\n%s", n, runDump(lines))
	}
	if got := crtAlerts(lines); len(got) > 0 {
		t.Errorf("a source that holds one clean issuance gave alerts %q, want none", got)
	}

	// The first run asks for the first page and the empty one after the last
	// id; the next run starts after that id.
	reqs := crtRequests(t, c.src, "Bearer "+crtKeyValue)
	want := []string{crtQuery, crtQuery + "&after=1", crtQuery + "&after=1"}
	for i, w := range want {
		if i >= len(reqs) || reqs[i].query != w {
			t.Errorf("request %d: want the query %q; the source got %+v", i+1, w, reqs)
			break
		}
	}
	svcNoMarker(t, c.state, []string{runMarker, crtKeyValue}, svc.out.String(), svc.errOut.String())
}

func TestCrtListingTakesSeveralRunsAndIsSilentUntilComplete(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.pageSize = 1
	var list []map[string]any
	for id := 1; id <= 12; id++ {
		list = append(list, crtClean(id))
	}
	// The unpermitted authority is known in the first run, and still silent.
	list[2] = crtEvil(3)
	c.src.set(list...)
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "ok 10 valid (listing)")
	_, j := crtWaitRun(t, svc, i+1, "ok 12 valid")
	crtWaitLine(t, svc, j+1, crtIssuerOpen)
	lines := svc.stop(t)

	if len(crtAlerts(lines)) != 1 {
		t.Errorf("the alerts were %q, want %q once, after the run that completed the list", crtAlerts(lines), crtIssuerOpen)
	}
	crtNoAlert(t, "while the listing was partial", lines, j)

	// Ten pages in the first run; the cursor goes on in the second, which
	// ends with the empty page.
	reqs := crtRequests(t, c.src, "")
	if len(reqs) < 13 {
		t.Fatalf("%d requests, want at least 13: %+v", len(reqs), reqs)
	}
	for n, r := range reqs[:13] {
		want := crtQuery
		if n > 0 {
			want += "&after=" + strconv.Itoa(n)
		}
		if r.query != want {
			t.Errorf("request %d asked %q, want %q", n+1, r.query, want)
		}
	}
}

func TestCrtIssuerFromAnUnpermittedAuthorityOpensOnce(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.set(crtClean(1))
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "ok 1 valid")
	c.src.set(crtClean(1), crtEvil(2))
	_, j := crtWaitRun(t, svc, i+1, "ok 2 valid")
	_, k := crtWaitLine(t, svc, j+1, crtIssuerOpen)
	crtWaitSlack(t, crtOpenWords, 1)

	// A renewal has a new id and the same names and authority: no news.
	c.src.set(crtClean(1), crtEvil(2), crtEvil(3))
	_, m := crtWaitRun(t, svc, k+1, "ok 3 valid")
	crtWaitRun(t, svc, m+1, "ok 3 valid")
	lines := svc.stop(t)

	if got := crtAlerts(lines); len(got) != 1 || got[0] != crtIssuerOpen {
		t.Errorf("the alerts were %q, want %q once", got, crtIssuerOpen)
	}
	crtNoAlert(t, "before the unpermitted issuance", lines, i)
	if n := crtSlackCount(crtOpenWords); n != 1 {
		t.Errorf("Slack got %d messages for the alert, want 1", n)
	}
	crtRequests(t, c.src, "")
}

func TestCrtRunsSayHowManyNamesCouldNotBeRead(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.set(crtIssuance(1, crtGood, "corp.test", "a_b.corp.test", "\u00fc.corp.test"))
	svc := runStart(t, c.args...)
	crtWaitRun(t, svc, 0, "ok 1 valid, 2 names not read")
	lines := svc.stop(t)
	if got := crtAlerts(lines); len(got) > 0 {
		t.Errorf("names that cannot be read gave alerts %q, want none", got)
	}
}

func TestCrtRunInsideAWaitMakesNoRequestAndRecordsNoCleanTime(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.retry = "3600"
	c.src.set(crtClean(1))
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "ok 1 valid")
	asked := len(c.src.requests())
	const notAsked = "ok 1 valid (not asked: the source said to wait)"
	second, j := crtWaitRun(t, svc, i+1, notAsked)
	if n := len(c.src.requests()); n != asked {
		t.Errorf("the run inside the wait made %d requests, want none", n-asked)
	}
	crtWaitRun(t, svc, j+1, notAsked)
	lines := svc.stop(t)
	if n := len(c.src.requests()); n != asked {
		t.Errorf("the source got %d requests, want the %d of the first run", n, asked)
	}
	if got := crtAlerts(lines); len(got) > 0 {
		t.Errorf("alerts %q, want none", got)
	}

	// The run that read the source recorded a clean time; the runs that did
	// not read it recorded none.
	s, err := store.Open(c.state)
	if err != nil {
		t.Fatal(err)
	}
	clean, err := s.LastClean(obs.CertificatesKey(cliName("corp.test.")))
	if cerr := s.Close(); err != nil || cerr != nil {
		t.Fatal(err, cerr)
	}
	start, _, _ := crtRest(second.text)
	if clean.IsZero() || !clean.Before(start) {
		t.Errorf("the last clean time is %s, want a time before %s, the start of the first run that did not ask", clean.UTC(), start.UTC())
	}
}

// A failure is unknown: it opens and ends none of the three rules, and only
// a series of them for the fail limit (three intervals) opens check-failing.
func TestCrtFailureKeepsAnOpenAlertAndTheSeriesReachesCheckFailing(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.set(crtClean(1), crtEvil(2))
	svc := runStart(t, c.args...)
	_, i := crtWaitLine(t, svc, 0, crtIssuerOpen)
	crtWaitSlack(t, crtOpenWords, 1)

	// The certificate is no longer in the source, but the failure says
	// nothing about that.
	c.src.set(crtClean(1))
	c.src.fail(503, "", "")
	_, j := crtWaitLine(t, svc, i+1, crtFailingOpen)
	for _, l := range svc.out.all()[i+1 : j] {
		if _, rest, ok := crtRest(l.text); ok && rest != "failed status 503" {
			t.Errorf("the line %q came while every answer was 503, want only \"failed status 503\"", l.text)
		}
	}
	c.src.recover()
	_, k := crtWaitLine(t, svc, j+1, crtFailingEnd)
	// The known issuances stay through a failure, so the run after it still
	// holds the certificate that the source no longer lists.
	crtWaitRun(t, svc, k+1, "ok 2 valid")
	lines := svc.stop(t)

	want := []string{crtIssuerOpen, crtFailingOpen, crtFailingEnd}
	if got := crtAlerts(lines); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the alerts were:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestCrtFailuresAreNamedAndGiveNoAlertOfTheThreeRules(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.fail(503, "", "")
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "failed status 503")
	c.src.fail(200, "", `{"id": "1"}`)
	_, j := crtWaitRun(t, svc, i+1, "failed malformed")
	c.src.fail(429, "", "")
	crtWaitRun(t, svc, j+1, "failed rate-limited")
	lines := svc.stop(t)
	for _, a := range crtAlerts(lines) {
		if !strings.Contains(a, "check-failing") {
			t.Errorf("a failure gave %q, want no alert of the three rules and no resolve", a)
		}
	}
}

func TestCrtRunInsideARateLimitMakesNoRequestAndFails(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.fail(429, "30", "")
	svc := runStart(t, c.args...)
	_, i := crtWaitRun(t, svc, 0, "failed rate-limited")
	asked := len(c.src.requests())
	crtWaitRun(t, svc, i+1, "failed rate-limited")
	svc.stop(t)
	if n := len(c.src.requests()); n != asked {
		t.Errorf("the source got %d requests, want the %d before the limit's wait of 30 s", n, asked)
	}
}

// A restart starts a new listing, and no alert is sent twice, while
// the listing is partial and after it is complete. The open alert stays.
func TestCrtRestartSendsNoAlertTwice(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.pageSize = 1
	var list []map[string]any
	for id := 1; id <= 12; id++ {
		list = append(list, crtClean(id))
	}
	list[2] = crtEvil(3)
	c.src.set(list...)

	first := runStart(t, c.args...)
	crtWaitLine(t, first, 0, crtIssuerOpen)
	crtWaitSlack(t, crtOpenWords, 1)
	first.stop(t)

	second := runStart(t, c.args...)
	_, i := crtWaitRun(t, second, 0, "ok 10 valid (listing)")
	_, j := crtWaitRun(t, second, i+1, "ok 12 valid")
	crtWaitRun(t, second, j+1, "ok 12 valid")
	lines := second.stop(t)

	if got := crtAlerts(lines); len(got) > 0 {
		t.Errorf("the restart printed alerts %q for a difference that stands, want none", got)
	}
	if n := crtSlackDistinct(crtOpenWords, crtResolveWords); n != 1 {
		t.Errorf("Slack got %d different messages about the certificates, want the 1 of before the restart", n)
	}
	crtIssuerAlert(t, crtOpenAlerts(t, c.state))
	runNoSecret(t, c.state, first.out.String(), second.out.String())
}

// The line of an alert has no server. It goes into the store, comes back
// after a restart and is ended by a complete list that no longer holds the
// certificate.
func TestCrtStoredAlertIsReadBackAndResolved(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.set(crtEvil(1), crtClean(2))

	first := runStart(t, c.args...)
	crtWaitLine(t, first, 0, crtIssuerOpen)
	crtWaitSlack(t, crtOpenWords, 1)
	first.stop(t)
	crtIssuerAlert(t, crtOpenAlerts(t, c.state))

	c.src.set(crtClean(2))
	second := runStart(t, c.args...)
	crtWaitLine(t, second, 0, crtIssuerResolve)
	crtWaitSlack(t, crtResolveWords, 1)
	lines := second.stop(t)

	if got := crtAlerts(lines); len(got) != 1 || got[0] != crtIssuerResolve {
		t.Errorf("the second service printed alerts %q, want %q once", got, crtIssuerResolve)
	}
	if open := crtOpenAlerts(t, c.state); len(open) != 0 {
		t.Errorf("%d alerts open after the resolve, want none: %+v", len(open), open)
	}
	runNoSecret(t, c.state, first.out.String(), second.out.String())
}

// A line that loses its check is said at the start of the service.
func TestCrtWarnsOfLinesThatNoCheckJudges(t *testing.T) {
	const warning = "warning corp.test.: the issuer and certname lines are not judged: certificates is not set in the config"
	for _, c := range []struct {
		name, file string
		warned     bool
	}{
		{"issuer", "domain corp.test.\nissuer ca.test\ncorp.test. DS none\n", true},
		{"certname", "domain corp.test.\ncertname *.corp.test.\ncorp.test. DS none\n", true},
		{"none", runFile, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := transportStart(t, expWorld)
			t.Setenv("OSK_SLACK_URL", runDeadURL)
			state := filepath.Join(t.TempDir(), "state")
			svc := runStart(t, runLocal(t, s, expFile(t, c.file), state, runIntervals("1h", "1h", "1h", "1h"))...)
			svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runSerialKey))
			lines := svc.stop(t)
			warned := 0
			for _, l := range lines {
				switch {
				case l.text == warning:
					warned++
				case strings.HasPrefix(l.text, "warning corp.test."):
					t.Errorf("the line %q is a warning that the contract does not give", l.text)
				}
			}
			if want := map[bool]int{true: 1, false: 0}[c.warned]; warned != want {
				t.Errorf("the warning printed %d times, want %d:\n%s", warned, want, runDump(lines))
			}
		})
	}
}

// At most two certificate runs go at one time; the others wait in the
// service, DNS checks go on, and a stop does not wait for the source.
func TestCrtAtMostTwoRunsAtOnce(t *testing.T) {
	var domains []runCfgDomain
	var names []string
	for i := 1; i <= 4; i++ {
		name := fmt.Sprintf("d%d.test.", i)
		names = append(names, name)
		domains = append(domains, runCfgDomain{Name: name, Expect: expFile(t, "domain "+name+"\n"+name+" DS none\n")})
	}
	c := crtNewFor(t, "", domains...)
	// An empty source: the first page is the empty one, so a released request
	// ends its run.
	c.src.set()
	arrived := make(chan string, 64)
	release := make(chan struct{})
	var mu sync.Mutex
	flying, most := 0, 0
	c.src.gate = func(r *http.Request) {
		mu.Lock()
		flying++
		most = max(most, flying)
		mu.Unlock()
		arrived <- r.URL.Query().Get("domain") + "."
		select {
		case <-release:
		case <-r.Context().Done():
		}
		mu.Lock()
		flying--
		mu.Unlock()
	}
	next := func() string {
		select {
		case d := <-arrived:
			return d
		case <-time.After(runPatience):
			t.Fatal("no request reached the source")
			return ""
		}
	}
	svc := runStart(t, c.args...)
	first := []string{next(), next()}
	for _, n := range names {
		k := "serial " + n + " " + n + " SOA"
		svc.wait(t, "the serial check of "+n+" while two requests are held", 0, time.Now().Add(runPatience), runRunOf(k))
	}
	if len(arrived) != 0 {
		t.Errorf("a third request reached the source while two were held")
	}

	// A place that falls free goes to the check that waited longest: the
	// domains are taken in the order of the file.
	release <- struct{}{}
	third := next()
	release <- struct{}{}
	fourth := next()
	slices.Sort(first)
	if got, want := []string{first[0], first[1], third, fourth}, names; !slices.Equal(got, want) {
		t.Errorf("the requests came for %q, want the first two to be %q and %q then %q", got, first, names[2], names[3])
	}
	mu.Lock()
	if most != 2 {
		t.Errorf("the source saw %d requests in flight at most, want 2", most)
	}
	mu.Unlock()
	svc.stopWithin(t, 2*time.Second)
}

// A source that ignores the cursor is a changed form: the run fails, no
// alert of the three rules opens, and the series reaches check-failing.
func TestCrtSourceThatIgnoresTheCursorFailsMalformed(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.ignore = true
	c.src.set(crtEvil(1), crtEvil(2), crtEvil(3))
	svc := runStart(t, c.args...)
	crtWaitRun(t, svc, 0, "failed malformed")
	crtWaitLine(t, svc, 0, crtFailingOpen)
	lines := svc.stop(t)
	if got := crtAlerts(lines); len(got) != 1 || got[0] != crtFailingOpen {
		t.Errorf("the alerts were %q, want only %q", got, crtFailingOpen)
	}
	for _, l := range lines {
		if _, rest, ok := crtRest(l.text); ok && rest != "failed malformed" {
			t.Errorf("the line %q, want only failed malformed", l.text)
		}
	}
}

// A listing that is not whole records no clean time; a run that ends at the
// empty page does.
func TestCrtPartialListingRecordsNoCleanTime(t *testing.T) {
	c := crtNew(t, crtFile, "")
	c.src.pageSize = 1
	var list []map[string]any
	for id := 1; id <= 25; id++ {
		list = append(list, crtClean(id))
	}
	c.src.set(list...)
	key := obs.CertificatesKey(cliName("corp.test."))
	lastClean := func() time.Time {
		s, err := store.Open(c.state)
		if err != nil {
			t.Fatal(err)
		}
		at, err := s.LastClean(key)
		if cerr := s.Close(); err != nil || cerr != nil {
			t.Fatal(err, cerr)
		}
		return at
	}

	first := runStart(t, c.args...)
	_, i := crtWaitRun(t, first, 0, "ok 10 valid (listing)")
	crtWaitRun(t, first, i+1, "ok 20 valid (listing)")
	first.stop(t)
	if at := lastClean(); !at.IsZero() {
		t.Errorf("two partial runs recorded the clean time %s, want none", at.UTC())
	}

	c.src.set(list[:12]...)
	second := runStart(t, c.args...)
	_, j := crtWaitRun(t, second, 0, "ok 10 valid (listing)")
	crtWaitRun(t, second, j+1, "ok 12 valid")
	second.stop(t)
	if lastClean().IsZero() {
		t.Error("the run that ended at the empty page recorded no clean time")
	}
}
