package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// runMarker ends the Slack URL of these tests. The URL is a secret, so the
// marker may show up in no output, in no file of the state folder and in no
// test log line.
const runMarker = "runsecret"

// runPatience is how long a test waits for the first event of a service that
// it started: a slow machine delays a start by seconds, and a test that
// waits for less measures the machine, not the service.
const runPatience = 60 * time.Second

// Nothing listens on port 1, so every send fails at once.
const runDeadURL = "https://127.0.0.1:1/x/" + runMarker

const runLineLayout = "2006-01-02T15:04:05.000Z"

// runSecondLayout is the layout of the times that a line gives to the second.
const runSecondLayout = "2006-01-02T15:04:05Z"

const runSynopsis = "osk-dns-watcher run --config <file>"

var runTiers = []string{"serial", "parent", "fast", "other"}

func runShow(s string) string {
	return strings.ReplaceAll(s, runMarker, "[marker]")
}

// runLine is one log line of the service.
type runLine struct {
	at                   time.Time
	level, event, domain string
	text                 string
	raw                  string
}

var runFileChanged = regexp.MustCompile(`^file .+ changed: \d+ checks$`)

// runLevel is the level that a line of this text must have.
func runLevel(text string) string {
	f := strings.Fields(text)
	switch {
	case len(f) == 0:
		return "info"
	case f[0] == "error":
		return "error"
	case f[0] == "warning", f[0] == "down", f[0] == "down:":
		return "warning"
	case f[0] == "file" && !runFileChanged.MatchString(text):
		return "warning"
	case f[0] == "delivery" && len(f) > 3 && (f[2] == "failed" || f[2] == "given" && f[3] == "up"):
		return "warning"
	case strings.HasPrefix(text, "heartbeat failed"), strings.HasPrefix(text, "heartbeat skipped"),
		strings.HasPrefix(text, "test-alert ignored"):
		return "warning"
	}
	return "info"
}

// runParseLine reads one log line: one JSON object whose keys are time,
// level, event, domain and text, in this order, each a string; domain is
// left out when the line is about no domain.
func runParseLine(raw string) (runLine, error) {
	l := runLine{raw: raw, text: raw}
	bad := func(why string) (runLine, error) {
		return l, fmt.Errorf("the line %q: %s", runShow(raw), why)
	}
	dec := json.NewDecoder(strings.NewReader(raw))
	if tok, err := dec.Token(); err != nil || tok != json.Delim('{') {
		return bad("not a JSON object")
	}
	var keys []string
	values := map[string]string{}
	for dec.More() {
		k, err := dec.Token()
		v, verr := dec.Token()
		key, _ := k.(string)
		s, ok := v.(string)
		if err != nil || verr != nil || !ok {
			return bad("every value must be a string")
		}
		keys = append(keys, key)
		values[key] = s
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('}') {
		return bad("not one JSON object")
	}
	if _, err := dec.Token(); err != io.EOF {
		return bad("more than one JSON value")
	}
	want := []string{"time", "level", "event", "domain", "text"}
	domain, hasDomain := values["domain"]
	if !hasDomain {
		want = slices.Delete(want, 3, 4)
	}
	if !slices.Equal(keys, want) {
		return bad(fmt.Sprintf("the keys are %q, want %q", keys, want))
	}
	l.text, l.level, l.event, l.domain = values["text"], values["level"], values["event"], domain
	at, err := time.Parse(runLineLayout, values["time"])
	if err != nil || at.Format(runLineLayout) != values["time"] {
		return bad("time is not in the form " + runLineLayout + " UTC")
	}
	l.at = at
	if first, _, _ := strings.Cut(l.text, " "); l.event != first {
		return bad("event is not the first word of text")
	}
	if want := runLevel(l.text); l.level != want {
		return bad("level is " + l.level + ", want " + want)
	}
	if hasDomain && (domain == "" || domain != strings.ToLower(domain) || !strings.HasSuffix(domain, ".")) {
		return bad("domain is not a name in lower case with its trailing dot")
	}
	return l, nil
}

// runOutput collects the lines of a service as they come. strict is for a
// service in this process, whose every Write must be one whole line written
// at the time it names; the pipe from a child cuts and joins writes.
type runOutput struct {
	mu      sync.Mutex
	strict  bool
	broken  bool // every Write fails, after its line is kept
	partial []byte
	lines   []runLine
	faults  []string
}

func (o *runOutput) Write(p []byte) (int, error) {
	now := time.Now()
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.strict && (len(p) == 0 || bytes.IndexByte(p, '\n') != len(p)-1) {
		o.faults = append(o.faults, fmt.Sprintf("a write is not one whole line: %q", runShow(string(p))))
	}
	o.partial = append(o.partial, p...)
	for {
		i := bytes.IndexByte(o.partial, '\n')
		if i < 0 {
			break
		}
		o.add(string(o.partial[:i]), now)
		o.partial = o.partial[i+1:]
	}
	if o.broken {
		return 0, errors.New("run output closed")
	}
	return len(p), nil
}

func (o *runOutput) add(raw string, now time.Time) {
	l, err := runParseLine(raw)
	switch {
	case err != nil:
		o.faults = append(o.faults, err.Error())
	case o.strict && (l.at.After(now) || now.Sub(l.at) > time.Second):
		o.faults = append(o.faults, fmt.Sprintf("the line %q was written at %s, not at the time it names",
			runShow(raw), now.UTC().Format(runLineLayout)))
	}
	o.lines = append(o.lines, l)
}

func (o *runOutput) all() []runLine {
	o.mu.Lock()
	defer o.mu.Unlock()
	return slices.Clone(o.lines)
}

func (o *runOutput) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	var b strings.Builder
	for _, l := range o.lines {
		b.WriteString(l.raw + "\n")
	}
	return b.String() + string(o.partial)
}

func (o *runOutput) check(t *testing.T) {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, f := range o.faults {
		t.Error(f)
	}
	if len(o.partial) > 0 {
		t.Errorf("the output ends without a newline: %q", runShow(string(o.partial)))
	}
}

// runBuffer is standard error; a service may write it from any goroutine.
type runBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *runBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *runBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// runService is a running service: in this process through serve, or a
// child process.
type runService struct {
	out    *runOutput
	errOut *runBuffer
	done   chan struct{} // closed when the service has returned
	code   int           // the exit code, once done is closed
	cancel context.CancelFunc
	before int // goroutines of this process before the service started
}

// runStart runs a service in this process with the arguments that follow
// the word run.
func runStart(t *testing.T, args ...string) *runService {
	t.Helper()
	return runStartTo(t, &runOutput{strict: true}, args...)
}

func runStartTo(t *testing.T, out *runOutput, args ...string) *runService {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	s := &runService{out: out, errOut: &runBuffer{}, done: make(chan struct{}), cancel: cancel, before: runtime.NumGoroutine()}
	go func() {
		defer close(s.done)
		s.code = serve(ctx, args, s.out, s.errOut)
	}()
	// A test that stopped early must not leave a service that holds its
	// folder and asks the servers.
	t.Cleanup(func() {
		cancel()
		select {
		case <-s.done:
		case <-time.After(10 * time.Second):
			t.Error("the service did not return within 10 s of the cancel")
		}
	})
	return s
}

func runDump(lines []runLine) string {
	var b strings.Builder
	for _, l := range lines {
		b.WriteString(runShow(l.raw) + "\n")
	}
	return b.String()
}

// wait gives the first line, from index from on, that match accepts, and its
// index. It fails at once when the service returns, and at the deadline.
func (s *runService) wait(t *testing.T, what string, from int, deadline time.Time, match func(string) bool) (runLine, int) {
	t.Helper()
	for {
		lines := s.out.all()
		for i := from; i < len(lines); i++ {
			if match(lines[i].text) {
				return lines[i], i
			}
		}
		select {
		case <-s.done:
			t.Fatalf("waiting for %s: the service returned %d, errors %q; output:\n%s",
				what, s.code, runShow(s.errOut.String()), runDump(s.out.all()))
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s by %s; output:\n%s", what, deadline.UTC().Format(runLineLayout), runDump(lines))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func runIs(text string) func(string) bool {
	return func(s string) bool { return s == text }
}

func runPrefix(prefix string) func(string) bool {
	return func(s string) bool { return strings.HasPrefix(s, prefix) }
}

// runRunOf accepts a checked line of the check with the key k.
func runRunOf(k string) func(string) bool {
	return func(s string) bool {
		c, ok, _ := runParse(s)
		return ok && c.key == k
	}
}

// stop cancels a service in this process. It must return 0 within 5 s,
// with stop as its last line, nothing on standard error and no goroutine
// left behind.
func (s *runService) stop(t *testing.T) []runLine {
	t.Helper()
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(5 * time.Second):
		t.Fatalf("the service did not return within 5 s of the cancel; output:\n%s", runDump(s.out.all()))
	}
	lines := s.out.all()
	if s.code != 0 || len(lines) == 0 || lines[len(lines)-1].text != "stop" || s.errOut.String() != "" {
		t.Errorf("after the cancel: exit code %d, errors %q; output:\n%s\nwant 0, none and the line stop last",
			s.code, runShow(s.errOut.String()), runDump(lines))
	}
	s.out.check(t)
	runNoLeak(t, s.before)
	return lines
}

// runNoLeak fails when more goroutines run than before the service started.
// A cancelled query or send may need a moment to end.
func runNoLeak(t *testing.T, before int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for runtime.NumGoroutine() > before {
		if time.Now().After(deadline) {
			buf := make([]byte, 1<<20)
			t.Errorf("%d goroutines run after the service returned, %d ran before it started:\n%s",
				runtime.NumGoroutine(), before, runShow(string(buf[:runtime.Stack(buf, true)])))
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// runRefused calls serve for a use that it must refuse at once. A service
// that starts instead is stopped after 5 s.
func runRefused(t *testing.T, args ...string) (code int, out, errOut string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	o, e := &runBuffer{}, &runBuffer{}
	code = serve(ctx, args, o, e)
	if ctx.Err() != nil {
		t.Errorf("osk-dns-watcher run %s ran until it was stopped instead of ending at once", runShow(strings.Join(args, " ")))
	}
	return code, o.String(), e.String()
}

// runChecked is a checked line: a check that ended, with its start.
type runChecked struct {
	tier, key string
	start     time.Time
	result    string // "ok", or "failed" and the reasons
}

// runParse reads a checked line; ok is false for any other line.
func runParse(text string) (c runChecked, ok bool, err error) {
	f := strings.Fields(text)
	if len(f) == 0 || f[0] != "checked" {
		return runChecked{}, false, nil
	}
	if len(f) < 8 || f[7] == "ok" && len(f) != 8 || f[7] == "failed" && len(f) != 9 || f[7] != "ok" && f[7] != "failed" {
		return runChecked{}, false, fmt.Errorf("the line %q is not \"checked <tier> <check> <start> ok\" or \"... failed <reasons>\"", text)
	}
	start, err := time.Parse(runLineLayout, f[6])
	if err != nil || start.Format(runLineLayout) != f[6] {
		return runChecked{}, false, fmt.Errorf("the line %q: the start %q is not in the form %s", text, f[6], runLineLayout)
	}
	return runChecked{tier: f[1], key: strings.Join(f[2:6], " "), start: start, result: strings.Join(f[7:], " ")}, true, nil
}

// runRuns gives the checked lines of each check, in order.
func runRuns(t *testing.T, lines []runLine) map[string][]runChecked {
	t.Helper()
	runs := map[string][]runChecked{}
	for _, l := range lines {
		c, ok, err := runParse(l.text)
		if err != nil {
			t.Error(runShow(err.Error()))
		}
		if ok {
			runs[c.key] = append(runs[c.key], c)
		}
	}
	return runs
}

// runCount checks how often each check started, and its tier.
func runCount(t *testing.T, runs map[string][]runChecked, tier string, want int, keys ...string) {
	t.Helper()
	for _, k := range keys {
		if len(runs[k]) != want {
			t.Errorf("%s started %d times, want %d", k, len(runs[k]), want)
		}
		for _, c := range runs[k] {
			if c.tier != tier {
				t.Errorf("%s ran as tier %s, want %s", k, c.tier, tier)
			}
		}
	}
}

// runGaps checks that the starts of one check lie one interval apart: not
// early beyond the grain of the clock, and less than 1 s late.
func runGaps(t *testing.T, key string, runs []runChecked, interval time.Duration) {
	t.Helper()
	for i := 1; i < len(runs); i++ {
		if gap := runs[i].start.Sub(runs[i-1].start); gap < interval-10*time.Millisecond || gap >= interval+time.Second {
			t.Errorf("%s: start %d came %v after start %d, want %v to %v", key, i+1, gap, i, interval, interval+time.Second)
		}
	}
}

// runHead gives the start, plan and fast lines that a service printed before
// its loops started, and its down line apart (zero when there is none).
func runHead(t *testing.T, lines []runLine) (head []string, down runLine) {
	t.Helper()
	ended := false
	for _, l := range lines {
		switch l.event {
		case "checked", "moved", "alert", "delivery", "file", "stop":
			ended = true
		case "start", "plan", "fast":
			if !ended {
				head = append(head, l.text)
			}
		case "down", "down:":
			if down.text != "" {
				t.Errorf("two down lines: %q and %q", down.text, l.text)
			}
			down = l
		}
	}
	return head, down
}

// runPlan is the head of a service: its start line, the four plan lines
// ("<interval> <count>" each) and a fast line for each name that owns no line
// of the file.
func runPlan(domain, state string, checks int, plans [4]string, unused ...string) []string {
	head := []string{"start " + domain + " " + strconv.Itoa(checks) + " checks, state " + state}
	for i, p := range plans {
		head = append(head, "plan "+runTiers[i]+" every "+p+" checks")
	}
	for _, n := range unused {
		head = append(head, "fast "+n+" has no line in the file")
	}
	return head
}

// runDown reads "down since <time> for <duration>"; the duration is rounded
// to the second.
func runDown(t *testing.T, text string) (since time.Time, d time.Duration) {
	t.Helper()
	f := strings.Fields(text)
	if len(f) != 5 || f[0] != "down" || f[1] != "since" || f[3] != "for" {
		t.Fatalf("the line %q is not \"down since <time> for <duration>\"", text)
	}
	since, err := time.Parse(runSecondLayout, f[2])
	d, derr := time.ParseDuration(f[4])
	if err != nil || since.Format(runSecondLayout) != f[2] || derr != nil || d%time.Second != 0 || d.String() != f[4] {
		t.Fatalf("the line %q: want a time like %s and a duration rounded to 1s", text, runSecondLayout)
	}
	return since, d
}

// runNextTry gives the next try of a failed delivery line whose reason is a
// network error.
func runNextTry(t *testing.T, text string) time.Time {
	t.Helper()
	_, rest, _ := strings.Cut(text, ": no answer ")
	reason, err := strconv.QuotedPrefix(rest)
	detail, _ := strconv.Unquote(reason)
	next, ok := strings.CutPrefix(rest[len(reason):], "; next try ")
	at, terr := time.Parse(runSecondLayout, next)
	if err != nil || !strings.HasPrefix(detail, "network: ") || !ok || terr != nil || at.Format(runSecondLayout) != next {
		t.Fatalf("the line %q does not end \": no answer \"network: ...\"; next try <time>\"", runShow(text))
	}
	return at
}

// runNoSecret fails when an output, or any byte of any file in the state
// folder, holds the marker. The folder must hold a store, so that an empty
// folder cannot pass. Call it only after every service on the folder
// returned: opening a file of the folder drops the lock of a service in this
// process.
func runNoSecret(t *testing.T, state string, outputs ...string) {
	t.Helper()
	svcNoMarker(t, state, []string{runMarker}, outputs...)
}

// svcNoMarker fails when an output or a file of the state folder holds one
// of the markers.
func svcNoMarker(t *testing.T, state string, markers []string, outputs ...string) {
	t.Helper()
	hide := func(s string) string {
		for _, m := range markers {
			s = strings.ReplaceAll(s, m, "[marker]")
		}
		return s
	}
	for _, o := range outputs {
		for _, m := range markers {
			if strings.Contains(o, m) {
				t.Errorf("an output holds a secret marker:\n%s", hide(o))
			}
		}
	}
	size := 0
	err := filepath.WalkDir(state, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		for _, m := range markers {
			if err == nil && bytes.Contains(data, []byte(m)) {
				t.Errorf("%s holds a secret marker", path)
			}
		}
		size += len(data)
		return err
	})
	if _, serr := os.Stat(filepath.Join(state, "state.db")); err != nil || serr != nil || size == 0 {
		t.Errorf("the state folder holds no store: %v, %v, %d octets read", err, serr, size)
	}
}

// ---- The config of a test service ----

type runSecret struct {
	Env  string `json:"env,omitempty"`
	File string `json:"file,omitempty"`
}

type runCfgDomain struct {
	Name   string   `json:"name"`
	Expect string   `json:"expect"`
	Fast   []string `json:"fast,omitempty"`
}

type runCfgSlack struct {
	URL         runSecret `json:"url"`
	MinSeverity string    `json:"min_severity,omitempty"`
}

type runCfgHook struct {
	Name        string    `json:"name"`
	URL         runSecret `json:"url"`
	Key         runSecret `json:"key"`
	MinSeverity string    `json:"min_severity,omitempty"`
}

type runCfgBeat struct {
	URL      runSecret `json:"url"`
	Interval string    `json:"interval,omitempty"`
}

type runCfgNet struct {
	RootServers []string `json:"root_servers,omitempty"`
	ExtraRanges []string `json:"extra_ranges,omitempty"`
}

type runCfg struct {
	State       string            `json:"state"`
	Domains     []runCfgDomain    `json:"domains"`
	Intervals   map[string]string `json:"intervals,omitempty"`
	Slack       *runCfgSlack      `json:"slack,omitempty"`
	Webhooks    []runCfgHook      `json:"webhooks,omitempty"`
	Heartbeat   *runCfgBeat       `json:"heartbeat,omitempty"`
	HistoryDays int               `json:"history_days,omitempty"`
	Network     *runCfgNet        `json:"network,omitempty"`
}

// runCfgText gives the config as the file holds it, one key on each line.
func runCfgText(t *testing.T, c runCfg) string {
	t.Helper()
	data, err := json.MarshalIndent(c, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(data) + "\n"
}

// runConfigText writes text as a config file in a new folder and gives its
// path.
func runConfigText(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// runConfig writes c and gives the arguments of osk-dns-watcher run. The config must be
// valid: a test must not pass or fail for a config it wrote wrong.
func runConfig(t *testing.T, c runCfg) []string {
	t.Helper()
	text := runCfgText(t, c)
	path := runConfigText(t, text)
	if _, problems := config.Parse(path, []byte(text)); len(problems) > 0 {
		var lines []string
		for _, p := range problems {
			lines = append(lines, p.String())
		}
		t.Fatalf("the test wrote a config that is not valid:\n%s", strings.Join(lines, "\n"))
	}
	return []string{"--config", path}
}

// runIntervals gives the intervals of the config; an empty value leaves the
// default.
func runIntervals(serial, parent, fast, other string) map[string]string {
	iv := map[string]string{}
	for i, v := range []string{serial, parent, fast, other} {
		if v != "" {
			iv[runTiers[i]] = v
		}
	}
	return iv
}

// runLocalCfg is the config of a service that starts from the fake root
// server s, watches the domains given and sends to Slack only, at the URL
// in OSK_SLACK_URL.
func runLocalCfg(s *transportServer, state string, iv map[string]string, domains ...runCfgDomain) runCfg {
	return runCfg{State: state, Domains: domains, Intervals: iv, Slack: &runCfgSlack{URL: runSecret{Env: "OSK_SLACK_URL"}},
		Network: &runCfgNet{RootServers: []string{s.addr}, ExtraRanges: []string{"127.0.0.0/8"}}}
}

// runLocal gives the arguments of a service of the one domain corp.test.,
// with its file and its fast names.
func runLocal(t *testing.T, s *transportServer, file, state string, iv map[string]string, fast ...string) []string {
	t.Helper()
	return runConfig(t, runLocalCfg(s, state, iv, runCfgDomain{Name: "corp.test.", Expect: file, Fast: fast}))
}

// runReplace changes the file at once: a service that reads it while
// it is written must see the old or the new text, never a part.
func runReplace(t *testing.T, path, text string) {
	t.Helper()
	tmp := path + ".new"
	if err := os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(tmp, path); err != nil {
		t.Fatal(err)
	}
}

// runSet gives a period of the service another value until the test ends.
// A cleanup runs after those registered later, so calling it before
// runStart puts the period back only once the service returned.
func runSet[T any](t *testing.T, p *T, v T) {
	t.Helper()
	old := *p
	*p = v
	t.Cleanup(func() { *p = old })
}

// runReadEvery makes the service read the files more often, so that a test
// of several changes takes seconds.
func runReadEvery(t *testing.T, d time.Duration) {
	t.Helper()
	runSet(t, &readEvery, d)
}

// runFile has no NS line, so the fake root shows the delegation as a medium
// finding that is not covered.
const runFile = "domain corp.test.\ncorp.test. DS none\n"

const runNotCovered = "open medium not-covered delegation corp.test. NS"

const (
	runSerialKey     = "serial corp.test. corp.test. SOA"
	runDelegationKey = "delegation corp.test. corp.test. NS"
	runDSKey         = "ds corp.test. corp.test. DS"
)

func TestRunUsageLine(t *testing.T) {
	found := slices.ContainsFunc(strings.Split(usage, "\n"), func(l string) bool {
		return strings.HasPrefix(l, " ") && strings.TrimLeft(l, " ") == runSynopsis
	})
	if !found {
		t.Errorf("the usage lacks the line\n       %s\nusage:\n%s", runSynopsis, usage)
	}
	if strings.Contains(usage, "osk-dns-watcher run [") || strings.Contains(usage, "--expect <file> --state") {
		t.Errorf("the usage still holds the flags of osk-dns-watcher run before the config:\n%s", usage)
	}
}

// The loops of the service read the files every 5 s, store a beat every 10 s
// and start a delivery pass 1 s after the last one ended.
func TestRunPeriodsAreFiveTenAndOneSeconds(t *testing.T) {
	if readEvery != 5*time.Second || beatEvery != 10*time.Second || passPause != time.Second {
		t.Errorf("file read every %v, beat every %v, pause between passes %v; want 5s, 10s and 1s", readEvery, beatEvery, passPause)
	}
	if readSettle != 30*time.Second {
		t.Errorf("a file that is not valid is taken after %v, want 30s", readSettle)
	}
}

// runWrongUse checks a refusal: exit code 2, nothing on standard output,
// "osk-dns-watcher run: " and one of msgs, then the usage. A message that ends in "..."
// stands for its start.
func runWrongUse(t *testing.T, what string, code int, out, errOut string, msgs ...string) {
	t.Helper()
	first, rest, _ := strings.Cut(errOut, "\n")
	msg, ok := strings.CutPrefix(first, "osk-dns-watcher run: ")
	known := slices.ContainsFunc(msgs, func(m string) bool {
		start, cut := strings.CutSuffix(m, "...")
		return msg == m || cut && strings.HasPrefix(msg, start)
	})
	if code != 2 || out != "" || !ok || !known || !strings.Contains(rest, runSynopsis) {
		t.Errorf("%s: exit code %d, output %q, errors:\n%s\nwant 2, nothing, \"osk-dns-watcher run: \" and one of %q, then the usage",
			what, code, runShow(out), runShow(errOut), msgs)
	}
}

// runCfgProblem names a problem of a config: the line of the first
// occurrence of at in the file, the key path and the text.
type runCfgProblem struct {
	at, path, text string
}

func runLineOf(t *testing.T, text, at string) int {
	t.Helper()
	i := strings.Index(text, at)
	if i < 0 {
		t.Fatalf("the config holds no %q:\n%s", at, text)
	}
	return 1 + strings.Count(text[:i], "\n")
}

// runProblemLines gives the lines that osk-dns-watcher run prints on standard error for
// the problems of the config file at path.
func runProblemLines(t *testing.T, path, text string, problems ...runCfgProblem) string {
	t.Helper()
	var b strings.Builder
	for _, p := range problems {
		b.WriteString(config.Problem{File: path, Line: runLineOf(t, text, p.at), Path: p.path, Text: p.text}.String())
		b.WriteString("\n")
	}
	return strings.ReplaceAll("osk-dns-watcher: "+strings.TrimSuffix(b.String(), "\n"), "\n", "\nosk-dns-watcher: ") + "\n"
}

// Wrong use is found before the config is read, and a config with a problem
// stops the start before an expectations file is read, before the store is
// opened and before anything is sent. The server, which answers, must get
// no query.
func TestRunWrongUseReadsOpensAndSendsNothing(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.json")
	state := filepath.Join(dir, "state")
	invalid := func(flag, value, why string) string {
		return fmt.Sprintf("invalid value %q for flag -%s: %s", value, flag, why)
	}
	// The config does not exist, so reading it would give exit code 1.
	for _, c := range []struct {
		name string
		args []string
		msgs []string
	}{
		{"no config", nil, []string{"--config is required"}},
		{"config twice", []string{"--config", missing, "--config", missing},
			[]string{"given more than once", invalid("config", missing, "given more than once")}},
		{"an argument", []string{"--config", missing, "corp.test."}, []string{"takes no arguments: the file gives the domains and the sets"}},
		{"expect flag", []string{"--config", missing, "--expect", missing}, []string{"flag provided but not defined: -expect"}},
		{"state flag", []string{"--state", state, "--config", missing}, []string{"flag provided but not defined: -state"}},
		{"root server flag", []string{"--root-server", s.addr, "--config", missing},
			[]string{"flag provided but not defined: -root-server"}},
		{"interval flag", []string{"--fast-interval", "5s", "--config", missing},
			[]string{"flag provided but not defined: -fast-interval"}},
		{"timeout flag", []string{"--timeout", "2s", "--config", missing}, []string{"flag provided but not defined: -timeout"}},
	} {
		code, out, errOut := runRefused(t, c.args...)
		runWrongUse(t, c.name, code, out, errOut, c.msgs...)
	}

	// The command word reaches the service through run.
	code, out, errOut := transportRun("run")
	runWrongUse(t, "osk-dns-watcher run", code, out, errOut, "--config is required")

	file := expFile(t, runFile)
	base := func() runCfg {
		return runLocalCfg(s, state, nil, runCfgDomain{Name: "corp.test.", Expect: file})
	}
	type problemCase struct {
		name  string
		cfg   runCfg
		url   string // "unset": the variable is not set
		edit  func(string) string
		probs []runCfgProblem
	}
	var cases []problemCase
	add := func(name string, change func(*runCfg), url string, probs ...runCfgProblem) {
		c := base()
		change(&c)
		cases = append(cases, problemCase{name: name, cfg: c, url: url, probs: probs})
	}
	setRoot := func(v string) func(*runCfg) { return func(c *runCfg) { c.Network.RootServers = []string{v} } }
	add("root server not an address", setRoot("ns1.corp.test"), runDeadURL,
		runCfgProblem{`"ns1.corp.test"`, "network.root_servers[0]", `"ns1.corp.test" is not an IP address with an optional port`})
	add("root server bad port", setRoot("127.0.0.1:99999"), runDeadURL,
		runCfgProblem{`"127.0.0.1:99999"`, "network.root_servers[0]", `"127.0.0.1:99999" is not an IP address with an optional port`})
	add("extra range not a prefix", func(c *runCfg) { c.Network.ExtraRanges = []string{"10.0.0.1"} }, runDeadURL,
		runCfgProblem{`"10.0.0.1"`, "network.extra_ranges[0]", `bad prefix "10.0.0.1"`})
	add("severity unknown", func(c *runCfg) { c.Slack.MinSeverity = "urgent" }, runDeadURL,
		runCfgProblem{`"urgent"`, "slack.min_severity", "want low, medium, high or critical"})
	add("no domain", func(c *runCfg) { c.Domains = []runCfgDomain{} }, runDeadURL,
		runCfgProblem{`"domains"`, "domains", "want 1 to 100 domains"})
	_, nameErr := dnswire.ParseName("a..b.")
	if nameErr == nil {
		t.Fatal("a..b. reads as a name")
	}
	add("fast without trailing dot", func(c *runCfg) { c.Domains[0].Fast = []string{"mail.corp.test"} }, runDeadURL,
		runCfgProblem{`"mail.corp.test"`, "domains[0].fast[0]", `"mail.corp.test" has no trailing dot`})
	add("fast not a name", func(c *runCfg) { c.Domains[0].Fast = []string{"a..b."} }, runDeadURL,
		runCfgProblem{`"a..b."`, "domains[0].fast[0]", `bad name "a..b.": ` + nameErr.Error()})
	add("no URL", func(*runCfg) {}, "unset",
		runCfgProblem{`"url"`, "slack.url", "the environment variable is not set"})
	add("empty URL", func(*runCfg) {}, "",
		runCfgProblem{`"url"`, "slack.url", "the environment variable is not set"})
	for _, url := range []string{
		"http://hooks.example/" + runMarker,
		"hooks.example/" + runMarker,
		"https:///" + runMarker,
		"https://u@hooks.example/" + runMarker,
		"https://u:" + runMarker + "@hooks.example/x",
	} {
		add("URL "+runShow(url), func(*runCfg) {}, url,
			runCfgProblem{`"url"`, "slack.url", "the value is not an https URL with a host and no user name"})
	}
	// A problem of the config stops the start before the secrets are read.
	add("interval before URL", func(c *runCfg) { c.Intervals = runIntervals("", "", "4s", "") }, "unset",
		runCfgProblem{`"fast": "4s"`, "intervals.fast", "4s is below the floor of 5s"})
	for _, tier := range runTiers {
		add(tier+" not a duration", func(c *runCfg) { c.Intervals = map[string]string{tier: "soon"} }, runDeadURL,
			runCfgProblem{`"soon"`, "intervals." + tier, `"soon" is not a duration`})
		for _, v := range []string{"4s", "4.999s", "0s", "-5s", "25h", "24h0m1s"} {
			d, err := time.ParseDuration(v)
			if err != nil {
				t.Fatal(err)
			}
			text := fmt.Sprintf("%v is below the floor of 5s", d)
			if d > 5*time.Second {
				text = fmt.Sprintf("%v is above 24h0m0s", d)
			}
			add(tier+" "+v, func(c *runCfg) { c.Intervals = map[string]string{tier: v} }, runDeadURL,
				runCfgProblem{`"` + tier + `": "` + v + `"`, "intervals." + tier, text})
		}
	}
	// No such setting: the query timeout is fixed.
	cases = append(cases, problemCase{name: "timeout", cfg: base(), url: runDeadURL,
		edit:  func(s string) string { return strings.Replace(s, "{\n", "{\n  \"timeout\": \"2s\",\n", 1) },
		probs: []runCfgProblem{{`"timeout"`, "", `unknown key "timeout"`}}})
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("OSK_SLACK_URL", c.url)
			if c.url == "unset" {
				if err := os.Unsetenv("OSK_SLACK_URL"); err != nil {
					t.Fatal(err)
				}
			}
			text := runCfgText(t, c.cfg)
			if c.edit != nil {
				text = c.edit(text)
			}
			path := runConfigText(t, text)
			code, out, errOut := runRefused(t, "--config", path)
			if want := runProblemLines(t, path, text, c.probs...); code != 1 || out != "" || errOut != want {
				t.Errorf("exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s", code, runShow(out), runShow(errOut), runShow(want))
			}
			if strings.Contains(errOut, runMarker) {
				t.Errorf("the errors echo the value of OSK_SLACK_URL")
			}
			slkNotThere(t, state)
		})
	}

	// observe refuses a root server that the config accepts; the config
	// keeps a missing port as 0. The variable is read first, and every
	// problem is told.
	unspecified := base()
	unspecified.Network.RootServers = []string{"0.0.0.0"}
	args := runConfig(t, unspecified)
	const refusedRoot = "osk-dns-watcher: observe: invalid root server 0.0.0.0:0\n"
	code, out, errOut = runRefused(t, args...)
	if code != 1 || out != "" || errOut != refusedRoot {
		t.Errorf("a root server that observe refuses: exit code %d, output %q, errors %q; want 1, nothing and %q",
			code, runShow(out), runShow(errOut), refusedRoot)
	}
	if err := os.Unsetenv("OSK_SLACK_URL"); err != nil {
		t.Fatal(err)
	}
	code, _, errOut = runRefused(t, args...)
	first, second, _ := strings.Cut(errOut, "\n")
	if want := ": slack.url: the environment variable is not set"; code != 1 || !strings.HasPrefix(first, "osk-dns-watcher: ") ||
		!strings.HasSuffix(first, want) || second != refusedRoot {
		t.Errorf("no URL and a root server that observe refuses: exit code %d, errors %q; want 1, the problem of the URL, then %q", code, errOut, refusedRoot)
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// A file with problems stops the start: its lines go to standard error as
// osk-dns-watcher check prints them, after "osk-dns-watcher: ", and the store is never opened. The
// problems of every domain are printed.
func TestRunFileProblemsStopTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	bad := expFile(t, "domain corp.test.\nmail.corp.test A 10.53.0.82\n")
	empty := expFile(t, "# only a comment\n")
	shop := expFile(t, "# shop\ndomain shop.test.\n")
	for _, c := range []struct{ file, want string }{
		{bad, "osk-dns-watcher: " + bad + `:2: "mail.corp.test" has no trailing dot` + "\n"},
		{empty, "osk-dns-watcher: " + empty + ": no domain line\n"},
		{shop, "osk-dns-watcher: " + shop + ":2: the file is for shop.test., not corp.test.\n"},
	} {
		code, out, errOut := runRefused(t, runLocal(t, s, c.file, state, nil)...)
		if code != 1 || out != "" || errOut != c.want {
			t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, runShow(out), runShow(errOut), c.want)
		}
		slkNotThere(t, state)
	}
	gone := filepath.Join(dir, "missing")
	code, out, errOut := runRefused(t, runLocal(t, s, gone, state, nil)...)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk-dns-watcher: "+gone+": cannot be read: ") || strings.Count(errOut, "\n") != 1 ||
		!strings.HasSuffix(errOut, "\n") {
		t.Errorf("a missing file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk-dns-watcher: %s: cannot be read: ...\"",
			code, runShow(out), runShow(errOut), gone)
	}
	two := runConfig(t, runLocalCfg(s, state, nil, runCfgDomain{Name: "corp.test.", Expect: bad},
		runCfgDomain{Name: "other.test.", Expect: empty}))
	code, out, errOut = runRefused(t, two...)
	if want := "osk-dns-watcher: " + bad + `:2: "mail.corp.test" has no trailing dot` + "\nosk-dns-watcher: " + empty + ": no domain line\n"; code != 1 || out != "" ||
		errOut != want {
		t.Errorf("two domains with bad files: exit code %d, output %q, errors %q; want 1, nothing and %q", code, runShow(out), runShow(errOut), want)
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// A store that cannot be opened stops the start before any check runs.
func TestRunStoreErrorsStopTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)

	busy := filepath.Join(t.TempDir(), "state")
	held, err := store.Open(busy)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runRefused(t, runLocal(t, s, file, busy, nil)...)
	if err := held.Close(); err != nil {
		t.Error(err)
	}
	if want := "osk-dns-watcher: store: " + busy + " is in use by another osk-dns-watcher process\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("a store in use: exit code %d, output %q, errors %q; want 1, nothing and %q", code, runShow(out), runShow(errOut), want)
	}

	// A folder cannot be made under a regular file.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runRefused(t, runLocal(t, s, file, filepath.Join(plain, "state"), nil)...)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk-dns-watcher: ") || strings.Count(errOut, "\n") != 1 || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("a folder under a file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk-dns-watcher: ...\"",
			code, runShow(out), runShow(errOut))
	}
	expNoQueries(t, s)
}

// The start prints the plan of the file; every check runs at once, and each
// check then runs again one interval of its tier after its last start. The
// floor and the ceiling themselves are accepted.
func TestRunStartsEveryCheckAtOnceThenEachInterval(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile+"corp.test. MX 10 mail.corp.test.\nmail.example. A 192.0.2.81\nwww.example. A 192.0.2.80\n")
	state := filepath.Join(t.TempDir(), "state")
	begin := time.Now()
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("", "24h", "5s", ""), "nothere.example.", "www.example.", "gone.corp.test.")...)

	mx, www := "records corp.test. corp.test. MX", "records corp.test. www.example. A"
	deadline := begin.Add(8 * time.Second)
	for _, k := range []string{mx, www} {
		_, i := svc.wait(t, "the first run of "+k, 0, deadline, runRunOf(k))
		svc.wait(t, "the second run of "+k, i+1, deadline, runRunOf(k))
	}
	lines := svc.stop(t)

	head, down := runHead(t, lines)
	want := runPlan("corp.test.", state, 6, [4]string{"15s 1", "24h0m0s 2", "5s 2", "5m0s 1"}, "nothere.example.", "gone.corp.test.")
	if !slices.Equal(head, want) || down.text != "" {
		t.Errorf("the start printed:\n%s\n%s\nwant:\n%s\nand no down line", strings.Join(head, "\n"), down.text, strings.Join(want, "\n"))
	}
	runs := runRuns(t, lines)
	runCount(t, runs, "serial", 1, runSerialKey)
	runCount(t, runs, "parent", 1, runDelegationKey, runDSKey)
	runCount(t, runs, "other", 1, "records corp.test. mail.example. A")
	runCount(t, runs, "fast", 2, mx, www)
	for k, rs := range runs {
		if rs[0].start.Before(begin.Truncate(time.Millisecond)) || rs[0].start.After(begin.Add(2*time.Second)) {
			t.Errorf("%s first started at %s, want within 2 s of the start at %s", k, rs[0].start, begin.UTC())
		}
		runGaps(t, k, rs, 5*time.Second)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A run fails only when no answer of it is usable: a check whose second
// root server never answers still sees the zone, and prints ok.
func TestRunCheckedLineFailsOnlyWithNoUsableAnswer(t *testing.T) {
	s, silent := transportStart(t, expWorld), transportStart(t, nil)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile+"www.shop.example. A 192.0.2.1\n")
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: file})
	c.Network.RootServers = []string{s.addr, silent.addr}
	svc := runStart(t, runConfig(t, c)...)
	// A query to the silent server waits the fixed query timeout of 2 s.
	deadline := time.Now().Add(10 * time.Second)
	delegation, _ := svc.wait(t, "the delegation check", 0, deadline, runRunOf(runDelegationKey))
	shop, _ := svc.wait(t, "the check of www.shop.example.", 0, deadline, runRunOf("records corp.test. www.shop.example. A"))
	svc.stop(t)
	if c, _, _ := runParse(delegation.text); c.result != "ok" || c.tier != "parent" {
		t.Errorf("the delegation, answered by one root server of two: %q, want tier parent and ok", delegation.text)
	}
	cs, _, _ := runParse(shop.text)
	reasons, ok := strings.CutPrefix(cs.result, "failed ")
	words := strings.Split(reasons, ",")
	if !ok || cs.tier != "other" || !slices.Contains(words, obs.ReasonNotPermitted.String()) ||
		len(slices.Compact(slices.Sorted(slices.Values(words)))) != len(words) {
		t.Errorf("the check of a name whose server may not be asked: %q, want tier other, failed and distinct reasons with not-permitted", shop.text)
	}
}

// Every few seconds the service reads the file again. A changed line is
// used once two reads agree; a file that is not valid, or of another domain, or that
// cannot be read, keeps the last valid file in force and opens the
// invalid-file alert; a valid file resolves it.
func TestRunReadsTheFileAgain(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 300*time.Millisecond)
	v1 := runFile + "www.example. A 192.0.2.80\n"
	v2 := runFile + "www.example. A 192.0.2.99\n"
	file := expFile(t, v1)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	www := "records corp.test. www.example. A"
	keys := []string{runSerialKey, runDelegationKey, runDSKey, www}
	for _, k := range keys {
		svc.wait(t, "the first run of "+k, 0, time.Now().Add(runPatience), runRunOf(k))
	}
	soon := func() time.Time { return time.Now().Add(3 * time.Second) }
	const invalidOpen, invalidResolve = "alert open medium invalid-file corp.test.", "alert resolve medium invalid-file corp.test."
	changed := "file " + file + " changed: 4 checks"

	// The new expectation judges the next run, which starts at once, as
	// every check does after a change.
	runReplace(t, file, v2)
	at, i := svc.wait(t, "the changed file", 0, soon(), runIs(changed))
	svc.wait(t, "the record-set alert of the new line", i, soon(), runIs("alert open high record-set records www.example. A"))
	for _, k := range keys {
		svc.wait(t, "a new run of "+k, i, soon(), func(text string) bool {
			c, ok, _ := runParse(text)
			return ok && c.key == k && !c.start.Before(at.at)
		})
	}

	// The last valid file stays in force: a valid file with its content
	// changes nothing then.
	runReplace(t, file, runFile+"www.example A 192.0.2.99\n")
	_, i = svc.wait(t, "the problem of the file", i, soon(), runIs("file "+file+`:3: "www.example" has no trailing dot`))
	_, i = svc.wait(t, "the invalid-file alert", i, soon(), runIs(invalidOpen))
	runReplace(t, file, "# the same expectations\n"+v2)
	_, i = svc.wait(t, "the resolve of the invalid-file alert", i, soon(), runIs(invalidResolve))

	runReplace(t, file, "domain other.test.\nother.test. DS none\n")
	_, i = svc.wait(t, "the refusal of another domain", i, soon(), func(text string) bool {
		return strings.HasPrefix(text, "file "+file) && strings.HasSuffix(text, ": the file is for other.test., not corp.test.; fix the file or the config")
	})
	_, i = svc.wait(t, "the invalid-file alert", i, soon(), runIs(invalidOpen))

	runReplace(t, file, v1)
	_, resolved := svc.wait(t, "the resolve of the invalid-file alert", i, soon(), runIs(invalidResolve))
	_, i = svc.wait(t, "the change back to the first file", i, soon(), runIs(changed))
	svc.wait(t, "the resolve of the record-set alert", i, soon(), runIs("alert resolve high record-set records www.example. A"))
	i = max(i, resolved)

	// A read error gives one line, not one at each read.
	if err := os.Remove(file); err != nil {
		t.Fatal(err)
	}
	_, openErr := os.Open(file)
	gone := "file " + file + ": " + openErr.Error()
	_, i = svc.wait(t, "the read error", i, soon(), runIs(gone))
	svc.wait(t, "the invalid-file alert", i, soon(), runIs(invalidOpen))
	time.Sleep(time.Second)
	lines := svc.stop(t)
	counts := map[string]int{}
	for _, l := range lines {
		counts[l.text]++
	}
	if counts[gone] != 1 || counts[changed] != 2 {
		t.Errorf("the read error printed %d times, the change %d times; want 1 and 2:\n%s", counts[gone], counts[changed], runDump(lines))
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// An invalid-file alert that a stopped service left open resolves at the
// next start, once the file is valid.
func TestRunStartResolvesAStaleInvalidFileAlert(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 300*time.Millisecond)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))
	first := runStart(t, args...)
	first.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	runReplace(t, file, "domain corp.test.\ncorp.test DS none\n")
	first.wait(t, "the invalid-file alert", 0, time.Now().Add(runPatience), runIs("alert open medium invalid-file corp.test."))
	first.stop(t)

	runReplace(t, file, runFile)
	second := runStart(t, args...)
	second.wait(t, "the resolve at the start", 0, time.Now().Add(runPatience), runIs("alert resolve medium invalid-file corp.test."))
	second.stop(t)
	runNoSecret(t, state, first.out.String(), second.out.String())
}

// A restart prints how long the service was down, from the beat of the
// clean stop, sends one down notice, and a difference that stands opens no
// second alert.
func TestRunRestartPrintsDownAndOpensNothingTwice(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))
	first := runStart(t, args...)
	first.wait(t, "the alert", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	cancelled := time.Now()
	lines := first.stop(t)
	returned := time.Now()
	if _, down := runHead(t, lines); down.text != "" || svcCount(lines, "notice down - to 1 channels") != 0 {
		t.Errorf("the first start of a folder printed a down line or a down notice:\n%s", runDump(lines))
	}

	time.Sleep(1500 * time.Millisecond)
	restarted := time.Now()
	second := runStart(t, args...)
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey} {
		second.wait(t, "the first run of "+k, 0, time.Now().Add(runPatience), runRunOf(k))
	}
	// An alert line follows the checked line of its run at once.
	time.Sleep(500 * time.Millisecond)
	lines = second.stop(t)
	_, down := runHead(t, lines)
	if down.text == "" {
		t.Fatalf("the restart printed no down line:\n%s", runDump(lines))
	}
	since, d := runDown(t, down.text)
	slkWithin(t, "the last beat", since, cancelled.Truncate(time.Second), returned)
	if low, high := restarted.Sub(returned)-500*time.Millisecond, down.at.Sub(cancelled)+500*time.Millisecond; d < low || d > high {
		t.Errorf("the down line gives %v, want %v to %v", d, low, high)
	}
	if n := svcCount(lines, "notice down - to 1 channels"); n != 1 {
		t.Errorf("the restart printed %d down notices, want 1:\n%s", n, runDump(lines))
	}
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") {
			t.Errorf("the restart printed %q for a difference that stands", l.text)
		}
	}
	runNoSecret(t, state, first.out.String(), second.out.String())
}

// Delivery runs on its own timer: a failed send is tried again when its
// next try comes, with no new check and no new run of the command.
func TestRunRetriesDeliveryOnItsOwnTimer(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	failed := runPrefix("delivery slack failed " + runNotCovered + ": ")
	first, i := svc.wait(t, "the first attempt", 0, time.Now().Add(runPatience), failed)
	next := runNextTry(t, first.text)
	second, _ := svc.wait(t, "the second attempt", i+1, next.Add(4*time.Second), failed)
	svc.stop(t)
	slkWithin(t, "the first next try", next, first.at.Add(8*time.Second), first.at.Add(10*time.Second))
	slkWithin(t, "the second attempt", second.at, next, next.Add(3*time.Second))
	slkWithin(t, "the second next try", runNextTry(t, second.text), second.at.Add(18*time.Second), second.at.Add(20*time.Second))
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcHang is a TCP server that takes connections and never answers, so a
// send to it hangs in its TLS handshake.
func svcHang(t *testing.T) (addr string, accepted <-chan net.Conn) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	conns := make(chan net.Conn, 64)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(conns)
				return
			}
			conns <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for c := range conns {
			_ = c.Close()
		}
	})
	return ln.Addr().String(), conns
}

// A send that hangs does not hold the stop. The stop cuts it, which is no
// attempt: the row stays as it was, so the next start sends it at once.
func TestRunStopCutsAHangingSendAndKeepsItsRow(t *testing.T) {
	s := transportStart(t, expWorld)
	addr, accepted := svcHang(t)
	t.Setenv("OSK_SLACK_URL", "https://"+addr+"/x/"+runMarker)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	first := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	first.wait(t, "the alert", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	select {
	case <-accepted:
	case <-time.After(runPatience):
		t.Fatal("no send began within the patience of the alert")
	}
	for _, l := range first.stop(t) {
		if strings.HasPrefix(l.text, "delivery ") {
			t.Errorf("the cut send printed %q", runShow(l.text))
		}
	}

	t.Setenv("OSK_SLACK_URL", runDeadURL)
	second := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	second.wait(t, "the attempt of the kept row", 0, time.Now().Add(runPatience),
		runPrefix("delivery slack failed "+runNotCovered+": no answer "))
	second.stop(t)
	runNoSecret(t, state, first.out.String(), second.out.String())
}

// A standard output that fails every write blinds nothing: the alert is
// stored, its notice is tried, and the stop still gives exit code 0.
func TestRunKeepsWatchingWhenOutputFails(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStartTo(t, &runOutput{strict: true, broken: true}, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	svc.wait(t, "the first attempt", 0, time.Now().Add(runPatience), runPrefix("delivery slack failed "+runNotCovered+": "))
	svc.stop(t)

	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	if alerts, err := st.OpenAlerts(obs.DelegationKey(cliName("corp.test."))); err != nil || len(alerts) != 1 {
		t.Errorf("open alerts %+v, error %v; want one", alerts, err)
	}
	rows, err := st.Due("slack", time.Now().Add(time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Label != runNotCovered || rows[0].Attempts != 1 {
		t.Errorf("rows %+v, error %v; want one row %q after one attempt", rows, err, runNotCovered)
	}
}

// stopWithin cancels a service in this process and fails unless it returns
// within limit; stop then makes its checks.
func (s *runService) stopWithin(t *testing.T, limit time.Duration) []runLine {
	t.Helper()
	s.cancel()
	select {
	case <-s.done:
	case <-time.After(limit):
		t.Errorf("the service did not return within %v of the cancel", limit)
	}
	return s.stop(t)
}

// runStartedAfter accepts a checked line of the check k that started after
// at.
func runStartedAfter(k string, at time.Time) func(string) bool {
	return func(s string) bool {
		c, ok, _ := runParse(s)
		return ok && c.key == k && c.start.After(at)
	}
}

// svcOtherFile is the file of the second domain of the tests, which the
// fake world serves without a finding.
const svcOtherFile = "domain other.test.\nother.test. NS ns1.other.test. | ns2.other.test.\nother.test. DS none\n"

const svcOtherDelegationKey = "delegation other.test. other.test. NS"

// svcTwo gives the arguments of a service of corp.test. with fileA and
// other.test. with fileB.
func svcTwo(t *testing.T, s *transportServer, fileA, fileB, state string, iv map[string]string) []string {
	t.Helper()
	return runConfig(t, runLocalCfg(s, state, iv, runCfgDomain{Name: "corp.test.", Expect: fileA},
		runCfgDomain{Name: "other.test.", Expect: fileB}))
}

// An output that nobody reads holds no check of any domain: while the pipe
// is full the checks go on at their rate, and the stop does not wait for
// the lines.
func TestRunOutputThatNobodyReadsHoldsNoCheck(t *testing.T) {
	var corp, other atomic.Int64
	world := svcWorld(nil, nil)
	s := transportStart(t, func(q []byte, tcp bool) []byte {
		if name := svcQuestion(q); strings.HasSuffix(name, "other.test.") {
			other.Add(1)
		} else {
			corp.Add(1)
		}
		return world(q, tcp)
	})
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	// The write that finds the pipe full ends at the deadline.
	if err := w.SetWriteDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Write(make([]byte, 1<<22)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("filling the pipe: %v", err)
	}
	if err := w.SetWriteDeadline(time.Time{}); err != nil {
		t.Fatal(err)
	}
	// The interval is long, so that a run ends well before the next starts,
	// also on a slow machine.
	args := svcTwo(t, s, file, expFile(t, svcOtherFile), state, runIntervals("10s", "10s", "10s", "10s"))
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	errOut := &runBuffer{}
	var code int
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		code = serve(ctx, args, w, errOut)
	}()
	// Closing the reader ends every write that waits, so a service held in
	// one can still return.
	t.Cleanup(func() {
		cancel()
		_ = r.Close()
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
			t.Error("the service did not return within 10 s of the cancel")
		}
		_ = w.Close()
	})

	// The checks are waited for, not timed: a loaded machine delays the
	// first queries by seconds. The first run of both domains must come;
	// once its queries stop, a later run must send more while the output
	// stays full. A service held in a write sends nothing after its first
	// run, and the second wait ends at its deadline.
	const patience = 60 * time.Second
	waitCounts := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(patience); !ok(); time.Sleep(20 * time.Millisecond) {
			if time.Now().After(end) {
				t.Fatalf("with a full output, %s within %v; corp.test. sent %d queries, other.test. %d", what, patience, corp.Load(), other.Load())
			}
		}
	}
	waitCounts("the checks of corp.test. and other.test. did not both send queries", func() bool { return corp.Load() > 0 && other.Load() > 0 })
	var firstCorp, firstOther int64
	var changed time.Time
	waitCounts("the first run did not end", func() bool {
		if c, o := corp.Load(), other.Load(); c != firstCorp || o != firstOther || changed.IsZero() {
			firstCorp, firstOther, changed = c, o, time.Now()
		}
		return time.Since(changed) >= time.Second
	})
	waitCounts("the checks of corp.test. and other.test. sent no query after the first run", func() bool { return corp.Load() > firstCorp && other.Load() > firstOther })
	cancel()
	select {
	case <-returned:
	case <-time.After(2 * time.Second):
		t.Fatal("the service did not return within 2 s of the cancel")
	}
	if code != 0 || errOut.String() != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, runShow(errOut.String()))
	}
	_ = r.Close()
	runNoLeak(t, before)
}

// A FIFO at the path of a file holds whoever opens it to read until a
// writer comes. It is a problem of that file only: the checks of both
// domains go on, the invalid-file alert of its domain opens, and the stop is
// not held.
func TestRunFIFOAtTheFilePathHoldsNoCheck(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 300*time.Millisecond)
	fileA, fileB := expFile(t, runFile), expFile(t, svcOtherFile)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, svcTwo(t, s, fileA, fileB, state, runIntervals("1h", "5s", "1h", "1h"))...)
	firstA, _ := svc.wait(t, "the first run of the delegation of corp.test.", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	firstB, _ := svc.wait(t, "the first run of the delegation of other.test.", 0, time.Now().Add(runPatience), runRunOf(svcOtherDelegationKey))
	fifo := fileB + ".fifo"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fifo, fileB); err != nil {
		t.Fatal(err)
	}
	// A writer lets a reader that waits in the FIFO go, so that a service
	// held there can still stop.
	t.Cleanup(func() {
		if f, err := os.OpenFile(fileB, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	problem, i := svc.wait(t, "the problem of the file", 0, time.Now().Add(runPatience), runIs("file "+fileB+": is not a regular file"))
	opened, _ := svc.wait(t, "the invalid-file alert", i, time.Now().Add(runPatience), runIs("alert open medium invalid-file other.test."))
	if problem.domain != "other.test." || opened.domain != "other.test." {
		t.Errorf("the lines of the FIFO name the domains %q and %q, want other.test.", problem.domain, opened.domain)
	}
	for _, f := range []struct{ key, first string }{{runDelegationKey, firstA.text}, {svcOtherDelegationKey, firstB.text}} {
		c, _, _ := runParse(f.first)
		svc.wait(t, "a run of "+f.key+" after the FIFO came", 0, time.Now().Add(runPatience), runStartedAfter(f.key, c.start))
	}
	lines := svc.stopWithin(t, 2*time.Second)
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") && strings.HasSuffix(l.text, " corp.test.") {
			t.Errorf("the FIFO of other.test. gave %q", l.text)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A FIFO as the file at the start is refused before it is opened, as osk-dns-watcher
// check refuses it: the open would wait for a writer.
func TestRunRefusesAFIFOAsTheFileAtTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFIFO(t)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(t, s, file, state, nil)
	code, out, errOut := expWithin(t, 2*time.Second, func() (int, string, string) {
		o, e := &runBuffer{}, &runBuffer{}
		code := serve(context.Background(), args, o, e)
		return code, o.String(), e.String()
	})
	if want := "osk-dns-watcher: " + file + ": is not a regular file\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, runShow(errOut), want)
	}
	slkNotThere(t, state)
}

// A FIFO as the config file, or as the file of a secret, is refused before
// it is opened, as an expectations file is.
func TestRunRefusesAFIFOAsTheConfigOrASecretFile(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, nil, runCfgDomain{Name: "corp.test.", Expect: expFile(t, svcNSFile)})
	c.Webhooks = []runCfgHook{{Name: "siem", URL: runSecret{File: expFIFO(t)}, Key: runSecret{File: svcSecretFile(t, strings.Repeat("k", 40))}}}
	for what, args := range map[string][]string{
		"the config": {"--config", expFIFO(t)},
		"a secret":   runConfig(t, c),
	} {
		code, out, errOut := expWithin(t, 2*time.Second, func() (int, string, string) {
			o, e := &runBuffer{}, &runBuffer{}
			code := serve(context.Background(), args, o, e)
			return code, o.String(), e.String()
		})
		if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk-dns-watcher: ") || !strings.HasSuffix(errOut, "is not a regular file\n") {
			t.Errorf("a FIFO as %s: exit code %d, output %q, errors %q; want 1, nothing and a line that ends \"is not a regular file\"",
				what, code, out, runShow(errOut))
		}
	}
	slkNotThere(t, state)
}

// A read that hangs, as on a mount that stopped answering, holds no check.
// It is reported once as a problem of the file, and what it gives at its
// end is taken as any read.
func TestRunReadThatHangsHoldsNoCheck(t *testing.T) {
	if readStuck != 30*time.Second {
		t.Errorf("a read that hangs is reported after %v, want 30s", readStuck)
	}
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 100*time.Millisecond)
	release := make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	var hang atomic.Bool
	file := expFile(t, runFile)
	runSet(t, &readStuck, 300*time.Millisecond)
	old := readFile
	runSet(t, &readFile, func(path string) ([]byte, error) {
		if path == file && hang.Load() {
			<-release
		}
		return old(path)
	})
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "5s", "1h", "1h"))...)
	t.Cleanup(free)
	first, _ := svc.wait(t, "the first run of the delegation", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	hang.Store(true)
	stuck := "file " + file + ": the read has not ended after 300ms"
	_, i := svc.wait(t, "the report of the read", 0, time.Now().Add(runPatience), runIs(stuck))
	_, i = svc.wait(t, "the invalid-file alert", i, time.Now().Add(runPatience), runIs("alert open medium invalid-file corp.test."))
	c, _, _ := runParse(first.text)
	svc.wait(t, "a run of the delegation while the read hangs", 0, time.Now().Add(runPatience), runStartedAfter(runDelegationKey, c.start))
	hang.Store(false)
	free()
	svc.wait(t, "the resolve once the read ended", i, time.Now().Add(runPatience), runIs("alert resolve medium invalid-file corp.test."))
	lines := svc.stopWithin(t, 2*time.Second)
	if n := svcCount(lines, stuck); n != 1 {
		t.Errorf("the read that hung was reported %d times, want once", n)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcScript makes the reads of the files give the texts of its script, one
// after the other, once the test starts it; the last text stays. Reads of
// other paths are left as they are.
type svcScript struct {
	mu      sync.Mutex
	started bool
	scripts map[string][]string
	reads   map[string]int
}

func svcScripted(t *testing.T, scripts map[string][]string) *svcScript {
	t.Helper()
	sc := &svcScript{scripts: scripts, reads: map[string]int{}}
	old := readFile
	runSet(t, &readFile, func(path string) ([]byte, error) {
		sc.mu.Lock()
		script, ok := sc.scripts[path]
		if !sc.started || !ok {
			sc.mu.Unlock()
			return old(path)
		}
		defer sc.mu.Unlock()
		text := script[min(sc.reads[path], len(script)-1)]
		sc.reads[path]++
		return []byte(text), nil
	})
	return sc
}

func (sc *svcScript) start() {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.started = true
}

func (sc *svcScript) count(path string) int {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	return sc.reads[path]
}

// A file is taken only when two reads in a row give the same octets, so a
// file read while it is written, in part or empty, changes nothing; a real
// change is taken one read later. Each domain's file is judged on its own.
func TestRunTakesAChangedFileOnlyWhenTwoReadsAgree(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 50*time.Millisecond)
	// A file that is not valid is taken soon after two reads agree, so the
	// single odd reads below meet only the rule of two reads.
	runSet(t, &readSettle, 10*time.Millisecond)
	v1 := runFile + "www.example. A 192.0.2.80\n"
	v2 := runFile + "www.example. A 192.0.2.99\n"
	fileA, fileB := expFile(t, v1), expFile(t, svcOtherFile)
	sc := svcScripted(t, map[string][]string{
		fileA: {
			v1[:len(v1)-2], // cut inside the address
			v1, v1,
			runFile, // cut at the end of a line: a check is gone
			v1, v1,
			"", // as a command that writes the file leaves it while it runs
			v1, v1,
			v2, v2,
		},
		fileB: {svcOtherFile, "", svcOtherFile, svcOtherFile[:40], svcOtherFile},
	})
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, svcTwo(t, s, fileA, fileB, state, runIntervals("1h", "1h", "1h", "1h"))...)
	keys := []string{runSerialKey, runDelegationKey, runDSKey, "records corp.test. www.example. A", svcOtherDelegationKey}
	for _, k := range keys {
		svc.wait(t, "the first run of "+k, 0, time.Now().Add(runPatience), runRunOf(k))
	}
	sc.start()
	changed := "file " + fileA + " changed: 4 checks"
	at, i := svc.wait(t, "the change to the second file", 0, time.Now().Add(runPatience), runIs(changed))
	svc.wait(t, "the record-set alert of the second file", i, time.Now().Add(runPatience),
		runIs("alert open high record-set records www.example. A"))
	lines := svc.stop(t)
	if n := sc.count(fileA); n < 11 {
		t.Errorf("the service read the file of corp.test. %d times, want at least 11", n)
	}
	var alerts, files []string
	before := map[string]int{}
	for _, l := range lines {
		switch l.event {
		case "alert":
			// The fake world shows the NS line of other.test. as answered from
			// another zone; that alert stands, whatever its file does.
			if l.domain == "corp.test." || strings.Contains(l.text, " invalid-file ") {
				alerts = append(alerts, l.text)
			}
		case "file":
			files = append(files, l.text)
		}
		if c, ok, _ := runParse(l.text); ok && c.start.Before(at.at) {
			before[c.key]++
		}
	}
	if want := []string{"alert " + runNotCovered, "alert open high record-set records www.example. A"}; !slices.Equal(alerts, want) {
		t.Errorf("the alerts were %q, want only %q:\n%s", alerts, want, runDump(lines))
	}
	if want := []string{changed}; !slices.Equal(files, want) {
		t.Errorf("the file lines were %q, want only %q", files, want)
	}
	for _, k := range keys {
		if before[k] != 1 {
			t.Errorf("%s ran %d times before the change, want once", k, before[k])
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// runGated is an output whose first write waits until release is closed;
// first is closed when that write begins.
type runGated struct {
	first, release chan struct{}
	once           sync.Once
	mu             sync.Mutex
	raw            []string
}

func (g *runGated) Write(p []byte) (int, error) {
	g.once.Do(func() {
		close(g.first)
		<-g.release
	})
	g.mu.Lock()
	defer g.mu.Unlock()
	g.raw = append(g.raw, strings.TrimSuffix(string(p), "\n"))
	return len(p), nil
}

func (g *runGated) all() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.raw)
}

var runDropped = regexp.MustCompile(`^dropped ([1-9][0-9]*) lines: the output was not read$`)

// The logger never waits for its output: while the output holds a write,
// the checks go on, a line that finds no room is dropped, and the next line
// that finds room is preceded by the count. Fifty files that each turn
// invalid with 100 problems print far more lines than any queue holds.
func TestRunLoggerDropsLinesWithoutWaitingAndCountsThem(t *testing.T) {
	var queries atomic.Int64
	world := svcWorld(nil, nil)
	s := transportStart(t, func(q []byte, tcp bool) []byte {
		queries.Add(1)
		return world(q, tcp)
	})
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 50*time.Millisecond)
	runSet(t, &readSettle, 100*time.Millisecond)
	state := filepath.Join(t.TempDir(), "state")
	var domains []runCfgDomain
	for i := range 50 {
		name := fmt.Sprintf("d%02d.dead.test.", i)
		domains = append(domains, runCfgDomain{Name: name, Expect: expFile(t, "domain "+name+"\n")})
	}
	args := runConfig(t, runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), domains...))
	out := &runGated{first: make(chan struct{}), release: make(chan struct{})}
	release := sync.OnceFunc(func() { close(out.release) })
	t.Cleanup(release)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errOut := &runBuffer{}
	var code int
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		code = serve(ctx, args, out, errOut)
	}()
	select {
	case <-out.first:
	case <-time.After(runPatience):
		t.Fatal("the service wrote nothing within the patience")
	}
	before := queries.Load()
	bad := "domain d.dead.test.\n" + strings.Repeat("bad\n", 120)
	for _, d := range domains {
		runReplace(t, d.Expect, strings.Replace(bad, "d.dead.test.", d.Name, 1))
	}
	time.Sleep(3 * time.Second)
	if n := queries.Load() - before; n == 0 {
		t.Errorf("while the output held its first write, the checks sent no query")
	}
	release()
	time.Sleep(500 * time.Millisecond)
	cancel()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("the service did not return within 5 s of the cancel")
	}
	var texts []string
	for _, r := range out.all() {
		l, err := runParseLine(r)
		if err != nil {
			t.Error(runShow(err.Error()))
		}
		texts = append(texts, l.text)
	}
	i := slices.IndexFunc(texts, runDropped.MatchString)
	if code != 0 || errOut.String() != "" || len(texts) == 0 || !strings.HasPrefix(texts[0], "config ") || i < 1 ||
		i == len(texts)-1 || texts[len(texts)-1] != "stop" || slices.ContainsFunc(texts[i+1:], runDropped.MatchString) {
		t.Errorf("exit code %d, errors %q, %d lines written, the count of the dropped lines at line %d; want 0, none, the config line first, then one count of the dropped lines before the next line, and the stop last",
			code, runShow(errOut.String()), len(texts), i+1)
	}
	if problems := 50 * 100; i >= 0 && len(texts) >= problems {
		t.Errorf("%d lines were written although the output held them back, want fewer than the %d problems of the files", len(texts), problems)
	}
}

// ---- Several domains, the cap, the notices, the heartbeat, the history ----

func svcCount(lines []runLine, text string) int {
	n := 0
	for _, l := range lines {
		if l.text == text {
			n++
		}
	}
	return n
}

// svcQuestion gives the name that a query asks, in lower case.
func svcQuestion(q []byte) string {
	m, err := dnswire.Parse(q)
	if err != nil || len(m.Question) != 1 {
		return ""
	}
	return strings.ToLower(m.Question[0].Name.String())
}

func svcSOA(zone string, serial uint32) dnswire.Record {
	return cliRR(zone, 900, dnswire.SOA{MName: cliName("ns1." + zone), RName: cliName("hostmaster." + zone),
		Serial: serial, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300})
}

var (
	svcOtherNS = []dnswire.Record{
		cliRR("other.test.", 3600, dnswire.NS{Host: cliName("ns1.other.test.")}),
		cliRR("other.test.", 3600, dnswire.NS{Host: cliName("ns2.other.test.")}),
	}
	svcOtherWWW = cliRR("www.other.test.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.90")})
)

// svcWorld is expWorld with two more zones that the fake root serves
// itself: other.test., with www.other.test. A 192.0.2.90 and a name
// blind.other.test. that is always refused, and dead.test., of which no name
// is ever answered. A serial given makes the SOA of corp.test. or other.test.
// give it, so that a test can move it.
func svcWorld(corpSerial, otherSerial *atomic.Uint32) func([]byte, bool) []byte {
	return func(q []byte, tcp bool) []byte {
		m, err := dnswire.Parse(q)
		if err != nil || len(m.Question) != 1 {
			return nil
		}
		name, qtype := strings.ToLower(m.Question[0].Name.String()), m.Question[0].Type
		aa := uint16(transportQR | transportAA)
		otherSOA := svcSOA("other.test.", 1)
		if otherSerial != nil {
			otherSOA = svcSOA("other.test.", otherSerial.Load())
		}
		switch {
		case name == "dead.test.", strings.HasSuffix(name, ".dead.test."):
			return nil
		case name == "corp.test." && qtype == dnswire.TypeSOA && corpSerial != nil:
			return cliAnswer(q, aa, []dnswire.Record{svcSOA("corp.test.", corpSerial.Load())}, nil, nil)
		case name == "other.test." && qtype == dnswire.TypeNS:
			return cliAnswer(q, aa, svcOtherNS, nil, nil)
		case name == "other.test." && qtype == dnswire.TypeSOA:
			return cliAnswer(q, aa, []dnswire.Record{otherSOA}, nil, nil)
		case name == "www.other.test." && qtype == dnswire.TypeA:
			return cliAnswer(q, aa, []dnswire.Record{svcOtherWWW}, nil, nil)
		case name == "blind.other.test.":
			return cliAnswer(q, transportQR|cliRefused, nil, nil, nil)
		case name == "other.test.", strings.HasSuffix(name, ".other.test."):
			return cliAnswer(q, aa, nil, []dnswire.Record{otherSOA}, nil)
		}
		return expWorld(q, tcp)
	}
}

// svcReader opens the state folder for reading. Call it only after every
// service on the folder returned, for the reason given at runNoSecret.
func svcReader(t *testing.T, state string) *store.Reader {
	t.Helper()
	r, err := store.OpenReader(state)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return r
}

func svcNotices(t *testing.T, state string, kind store.NoticeKind) []store.Notice {
	t.Helper()
	all, err := svcReader(t, state).Notices(0)
	if err != nil {
		t.Fatal(err)
	}
	var notices []store.Notice
	for _, n := range all {
		if n.Kind == kind {
			notices = append(notices, n)
		}
	}
	return notices
}

// svcRows gives the labels of the pending rows of each channel. The URLs
// of the tests never answer, so a row stays pending after its attempts.
func svcRows(t *testing.T, state string, channels ...string) map[string][]store.Row {
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
	rows := map[string][]store.Row{}
	for _, c := range channels {
		if rows[c], err = s.Due(c, time.Now().Add(2*time.Hour)); err != nil {
			t.Fatal(err)
		}
	}
	return rows
}

func svcLabels(rows []store.Row) []string {
	var labels []string
	for _, r := range rows {
		labels = append(labels, r.Label)
	}
	slices.Sort(labels)
	return labels
}

// svcSecretFile writes a secret in a folder of its own, away from the state
// folder whose files a test scans.
func svcSecretFile(t *testing.T, value string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte(value+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// svcDeadHook is a webhook whose URL never answers.
func svcDeadHook(t *testing.T, name, min string) runCfgHook {
	t.Helper()
	return runCfgHook{Name: name, MinSeverity: min, URL: runSecret{File: svcSecretFile(t, "https://127.0.0.1:1/"+name+"/"+runMarker)},
		Key: runSecret{File: svcSecretFile(t, strings.Repeat("k", 40))}}
}

// svcNSFile covers the delegation. The fake root answers every name itself,
// so the check of its NS line shows a zone finding that stands; a test that
// must send nothing at its start uses runFile and a minimum of critical.
const svcNSFile = "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\n"

// One service watches each domain of the config with its own file: its own
// plan, checks, alerts and reload, each line naming its domain.
func TestRunWatchesEachDomainWithItsOwnFile(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	fileA := expFile(t, runFile+"www.example. A 192.0.2.99\n")
	fileB := expFile(t, svcOtherFile+"www.other.test. A 192.0.2.90\n")
	state := filepath.Join(t.TempDir(), "state")
	args := svcTwo(t, s, fileA, fileB, state, runIntervals("1h", "1h", "1h", "1h"))
	svc := runStart(t, args...)
	keysA := []string{runSerialKey, runDelegationKey, runDSKey, "records corp.test. www.example. A"}
	keysB := []string{"serial other.test. other.test. SOA", svcOtherDelegationKey, "ds other.test. other.test. DS",
		"records other.test. other.test. NS", "records other.test. www.other.test. A"}
	for _, k := range slices.Concat(keysA, keysB) {
		svc.wait(t, "the first run of "+k, 0, time.Now().Add(runPatience), runRunOf(k))
	}
	svc.wait(t, "the alert of www.example.", 0, time.Now().Add(runPatience), runIs("alert open high record-set records www.example. A"))
	changedAt := time.Now()
	runReplace(t, fileB, svcOtherFile+"www.other.test. A 192.0.2.99\n")
	changed, i := svc.wait(t, "the change of the file of other.test.", 0, changedAt.Add(3*time.Second), runIs("file "+fileB+" changed: 5 checks"))
	svc.wait(t, "the alert of www.other.test.", i, changedAt.Add(3*time.Second), runIs("alert open high record-set records www.other.test. A"))
	svc.wait(t, "the notice of the change", i, changedAt.Add(3*time.Second), runIs("notice expectations other.test. to 1 channels"))
	for _, k := range keysB {
		svc.wait(t, "a run of "+k+" after the change", i, changedAt.Add(3*time.Second), runStartedAfter(k, changed.at.Add(-time.Millisecond)))
	}
	time.Sleep(500 * time.Millisecond)
	lines := svc.stop(t)

	text := runCfgText(t, runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: fileA},
		runCfgDomain{Name: "other.test.", Expect: fileB}))
	c, problems := config.Parse(args[1], []byte(text))
	if c == nil {
		t.Fatalf("the config: %v", problems)
	}
	var head []string
	for _, l := range lines {
		if l.event == "start" || l.event == "checked" {
			break
		}
		head = append(head, l.text)
	}
	want := []string{"config " + args[1] + ": 2 domains, channels slack"}
	for _, w := range c.Warnings() {
		want = append(want, "warning "+w)
	}
	if !slices.Equal(head, want) {
		t.Errorf("the start began with:\n%s\nwant:\n%s", strings.Join(head, "\n"), strings.Join(want, "\n"))
	}
	starts := map[string]string{}
	for _, l := range lines {
		domain := ""
		switch l.event {
		case "start":
			domain = strings.Fields(l.text)[1]
			starts[domain] = l.text
		case "plan":
			domain = "a domain"
		case "checked":
			domain = strings.Fields(l.text)[3]
		case "alert":
			domain = "corp.test."
			if strings.Contains(l.text, "other.test.") {
				domain = "other.test."
			}
		case "delivery":
			if l.domain != "" {
				t.Errorf("the line %q names the domain %q, want none", l.text, l.domain)
			}
		case "file", "notice":
			domain = "other.test."
		}
		if domain == "a domain" && l.domain == "" || domain != "" && domain != "a domain" && l.domain != domain {
			t.Errorf("the line %q names the domain %q, want %q", l.text, l.domain, domain)
		}
		if c, ok, _ := runParse(l.text); ok && slices.Contains(keysA, c.key) && c.start.After(changed.at) {
			t.Errorf("the change of the file of other.test. started %q again", l.text)
		}
	}
	if starts["corp.test."] != "start corp.test. 4 checks, state "+state || starts["other.test."] != "start other.test. 5 checks, state "+state {
		t.Errorf("the start lines were %q, want one for each domain with its checks", starts)
	}
	notices := svcNotices(t, state, store.NoticeExpectations)
	if len(notices) != 1 || notices[0].Domain != "other.test." ||
		!slices.Equal(notices[0].Lines, []string{"- www.other.test. A 192.0.2.90", "+ www.other.test. A 192.0.2.99"}) {
		t.Errorf("the expectations notices were %+v, want one of other.test. with the changed line", notices)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcDeadFile is a file of a domain under dead.test. with lines more than
// the checks that may run at once.
func svcDeadFile(t *testing.T, domain string, lines int) string {
	t.Helper()
	text := "domain " + domain + "\n"
	for i := range lines {
		text += fmt.Sprintf("h%02d.%s TXT none\n", i, domain)
	}
	path := filepath.Join(t.TempDir(), domain+"expect")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// svcMostAtOnce gives the most checks that ran at one time: a check runs
// from the start that its checked line names to the time of that line.
// The writer ends a run before it starts another, so a start after a line
// is never before its time.
func svcMostAtOnce(lines []runLine) int {
	type edge struct {
		at   time.Time
		step int
	}
	var edges []edge
	for _, l := range lines {
		if c, ok, _ := runParse(l.text); ok {
			edges = append(edges, edge{c.start, 1}, edge{l.at, -1})
		}
	}
	slices.SortFunc(edges, func(a, b edge) int {
		if c := a.at.Compare(b.at); c != 0 {
			return c
		}
		return a.step - b.step // an end before a start at the same time
	})
	most, now := 0, 0
	for _, e := range edges {
		now += e.step
		most = max(most, now)
	}
	return most
}

// The cap of checks in flight holds over all domains: two domains whose
// servers never answer have 40 checks due at once, and 16 run.
func TestRunCapsChecksInFlightOverAllDomains(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runConfig(t, runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"),
		runCfgDomain{Name: "a.dead.test.", Expect: svcDeadFile(t, "a.dead.test.", 17)},
		runCfgDomain{Name: "b.dead.test.", Expect: svcDeadFile(t, "b.dead.test.", 17)}))...)
	deadline := time.Now().Add(20 * time.Second)
	for {
		if len(runRuns(t, svc.out.all())) == 40 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("the 40 checks did not all end within 20 s:\n%s", runDump(svc.out.all()))
		}
		time.Sleep(50 * time.Millisecond)
	}
	lines := svc.stop(t)
	if most := svcMostAtOnce(lines); most != schedule.MaxRunning {
		t.Errorf("at most %d checks ran at one time over both domains, want %d:\n%s", most, schedule.MaxRunning, runDump(lines))
	}
}

// A domain whose servers never answer, listed first, has more checks than
// the cap can run within their interval. A check of the domain with the
// fewest checks in flight goes first, so the second domain starts at once
// and its checks are never late by a whole interval.
func TestRunDeadDomainDoesNotStarveAnother(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	begin := time.Now()
	svc := runStart(t, runConfig(t, runLocalCfg(s, state, runIntervals("5s", "5s", "5s", "5s"),
		runCfgDomain{Name: "dead.test.", Expect: svcDeadFile(t, "dead.test.", 42)},
		runCfgDomain{Name: "corp.test.", Expect: expFile(t, svcNSFile)}))...)
	time.Sleep(time.Until(begin.Add(17 * time.Second)))
	end := time.Now()
	lines := svc.stop(t)
	runs := runRuns(t, lines)
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey, "records corp.test. corp.test. NS"} {
		rs := runs[k]
		if len(rs) < 2 {
			t.Errorf("%s started %d times in 17 s, want a start about every 5 s", k, len(rs))
			continue
		}
		if rs[0].start.After(begin.Add(time.Second)) || rs[len(rs)-1].start.Before(end.Add(-10*time.Second)) {
			t.Errorf("%s started first at %s and last at %s; want a first start within 1 s of %s and a start in the last 10 s before %s",
				k, rs[0].start, rs[len(rs)-1].start, begin.UTC(), end.UTC())
		}
		for i := 1; i < len(rs); i++ {
			if gap := rs[i].start.Sub(rs[i-1].start); gap >= 10*time.Second {
				t.Errorf("%s: start %d came %v after start %d, want less than two intervals", k, i+1, gap, i)
			}
		}
	}
	if most := svcMostAtOnce(lines); most > schedule.MaxRunning {
		t.Errorf("%d checks ran at one time, want at most %d", most, schedule.MaxRunning)
	}
}

// Each channel gets a row of each alert whose peak reaches its minimum,
// and a row of each notice whatever its minimum.
func TestRunSendsEachAlertToEveryChannelAtOrAboveItsMinimum(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: file})
	c.Webhooks = []runCfgHook{svcDeadHook(t, "hi", "high"), svcDeadHook(t, "crit", "critical")}
	svc := runStart(t, runConfig(t, c)...)
	_, i := svc.wait(t, "the not-covered alert", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	// The delegation is now covered by a line that differs: the not-covered
	// alert ends, a critical alert opens at the parent and a high one at the
	// zone.
	runReplace(t, file, "domain corp.test.\ncorp.test. NS ns9.corp.test.\ncorp.test. DS none\nwww.example. A 192.0.2.99\n")
	soon := time.Now().Add(5 * time.Second)
	for _, want := range []string{"alert resolve medium not-covered delegation corp.test. NS",
		"alert open critical nameservers delegation corp.test. NS", "alert open high record-set records corp.test. NS",
		"alert open high record-set records www.example. A", "notice expectations corp.test. to 3 channels"} {
		svc.wait(t, want, i, soon, runIs(want))
	}
	// A pass starts 1 s after the last one ended, so the first attempts may
	// come after the alerts.
	for _, ch := range []string{"slack", "hi", "crit"} {
		svc.wait(t, "an attempt to "+ch, 0, time.Now().Add(runPatience), runPrefix("delivery "+ch+" failed "))
	}
	lines := svc.stop(t)
	rows := svcRows(t, state, "slack", "hi", "crit")
	notice := "notice expectations corp.test."
	slack := svcLabels(rows["slack"])
	for _, l := range []string{runNotCovered, "resolve medium not-covered delegation corp.test. NS", notice,
		"open critical nameservers delegation corp.test. NS", "open high record-set records www.example. A"} {
		if !slices.Contains(slack, l) {
			t.Errorf("Slack, whose minimum is low, has no row %q: %q", l, slack)
		}
	}
	// The label gives the severity of each alert; none of these escalates,
	// so it is its peak.
	want := map[string][]string{"slack": slack}
	for _, l := range slack {
		severity := strings.Fields(l)[1]
		if l == notice || severity == "high" || severity == "critical" {
			want["hi"] = append(want["hi"], l)
		}
		if l == notice || severity == "critical" {
			want["crit"] = append(want["crit"], l)
		}
	}
	for ch, labels := range want {
		if got := svcLabels(rows[ch]); !slices.Equal(got, labels) {
			t.Errorf("the rows of %s are\n%s\nwant\n%s", ch, strings.Join(got, "\n"), strings.Join(labels, "\n"))
		}
		for _, r := range rows[ch] {
			var body struct {
				Schema int    `json:"schema"`
				Type   string `json:"type"`
				Text   string `json:"text"`
			}
			err := json.Unmarshal(r.Body, &body)
			switch {
			case err != nil || body.Text == "":
				t.Errorf("the row %q of %s has the body %q, want JSON with a text", r.Label, ch, r.Body)
			case ch != "slack" && (body.Schema != 1 || body.Type != map[bool]string{true: "notice", false: "alert"}[r.Label == notice]):
				t.Errorf("the row %q of %s has the body %s, want schema 1 and its type", r.Label, ch, r.Body)
			}
		}
	}
	for _, ch := range []string{"slack", "hi", "crit"} {
		if !slices.ContainsFunc(lines, func(l runLine) bool { return strings.HasPrefix(l.text, "delivery "+ch+" failed ") }) {
			t.Errorf("no attempt to %s was logged", ch)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcDownLines reads the lines of a down notice and gives its two times.
func svcDownLines(t *testing.T, n store.Notice) (last, started time.Time) {
	t.Helper()
	if len(n.Lines) != 2 || n.Domain != "" {
		t.Fatalf("the down notice holds the domain %q and the lines %q, want none and two", n.Domain, n.Lines)
	}
	last, err1 := time.Parse("2006-01-02 15:04:05 UTC", strings.TrimPrefix(n.Lines[0], "last beat "))
	started, err2 := time.Parse("2006-01-02 15:04:05 UTC", strings.TrimPrefix(n.Lines[1], "started   "))
	if err1 != nil || err2 != nil || !strings.HasPrefix(n.Lines[0], "last beat ") || !strings.HasPrefix(n.Lines[1], "started   ") {
		t.Fatalf("the down notice holds %q, want \"last beat <time>\" and \"started   <time>\"", n.Lines)
	}
	return last, started
}

// Each restart sends exactly one down notice to every channel, with the
// last beat and the start; the first start of a folder sends none.
func TestRunRestartSendsOneDownNoticeWithTheTimeDown(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: expFile(t, svcNSFile)})
	c.Webhooks = []runCfgHook{svcDeadHook(t, "crit", "critical")}
	args := runConfig(t, c)
	var outputs []string
	var stops []time.Time
	for round := range 3 {
		if round > 0 {
			time.Sleep(2100 * time.Millisecond)
		}
		svc := runStart(t, args...)
		svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
		time.Sleep(300 * time.Millisecond)
		lines := svc.stop(t)
		stops = append(stops, time.Now())
		outputs = append(outputs, svc.out.String(), svc.errOut.String())
		if n, want := svcCount(lines, "notice down - to 2 channels"), min(round, 1); n != want {
			t.Errorf("start %d printed %d down notices, want %d:\n%s", round+1, n, want, runDump(lines))
		}
	}
	notices := svcNotices(t, state, store.NoticeDown)
	if len(notices) != 2 {
		t.Fatalf("the store holds %d down notices, want 2", len(notices))
	}
	r := svcReader(t, state)
	for i, n := range notices {
		last, started := svcDownLines(t, n)
		slkWithin(t, "the last beat", last, stops[i].Add(-2*time.Second), stops[i])
		if d := started.Sub(last); d < 2*time.Second || d > 4*time.Second {
			t.Errorf("down notice %d gives %v between the last beat and the start, want about 2s", i+1, d)
		}
		rows, err := r.NoticeRows(n.ID)
		if err != nil || len(rows) != 2 || rows[0].Channel != "slack" || rows[1].Channel != "crit" {
			t.Errorf("the rows of down notice %d are %+v, error %v; want one for slack and one for crit", i+1, rows, err)
		}
	}
	runNoSecret(t, state, outputs...)
}

var svcAhead = regexp.MustCompile(`^down: the stored time (.+) is ahead of the clock; the down time is not known$`)

// svcSameSecond reports whether s names the time at, to the second, in one
// of the forms in which osk-dns-watcher prints times.
func svcSameSecond(s string, at time.Time) bool {
	for _, layout := range []string{runSecondLayout, runLineLayout, "2006-01-02 15:04:05 UTC", time.RFC3339Nano} {
		if t, err := time.Parse(layout, s); err == nil && t.Truncate(time.Second).Equal(at.Truncate(time.Second)) {
			return true
		}
	}
	return false
}

// A stored beat ahead of the clock tells no down time at all: no negative
// time, no down notice.
func TestRunStoredBeatAheadOfTheClockGivesNoDownTime(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	ahead := time.Now().Add(time.Hour).UTC()
	if err := errors.Join(st.Beat(ahead, nil), st.Close()); err != nil {
		t.Fatal(err)
	}
	args := runLocal(t, s, expFile(t, svcNSFile), state, runIntervals("1h", "1h", "1h", "1h"))
	svc := runStart(t, args...)
	svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	time.Sleep(300 * time.Millisecond)
	lines := svc.stop(t)
	_, down := runHead(t, lines)
	m := svcAhead.FindStringSubmatch(down.text)
	if m == nil || !svcSameSecond(m[1], ahead) {
		t.Errorf("the down line is %q, want \"down: the stored time %s is ahead of the clock; the down time is not known\"",
			down.text, ahead.Format(runSecondLayout))
	}
	for _, l := range lines {
		if strings.HasPrefix(l.text, "notice down") || strings.HasPrefix(l.text, "down since") {
			t.Errorf("a beat ahead of the clock gave %q", l.text)
		}
	}
	if n := svcNotices(t, state, store.NoticeDown); len(n) != 0 {
		t.Errorf("the store holds the down notices %+v, want none", n)
	}

	// The start stored a beat of its own, so the next start knows its down
	// time again.
	again := runStart(t, args...)
	again.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	lines = again.stop(t)
	if _, down := runHead(t, lines); !strings.HasPrefix(down.text, "down since ") {
		t.Errorf("the start after it printed the down line %q, want \"down since ...\"", down.text)
	}
	runNoSecret(t, state, svc.out.String(), again.out.String())
}

// An open alert whose line left the file is closed with the notice of the
// change, which tells its end: one notice, no resolve message of its own.
func TestRunRemovedLineClosesItsAlertWithOneNotice(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	file := expFile(t, runFile+"www.example. A 192.0.2.99\n")
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	svc.wait(t, "the alert of www", 0, time.Now().Add(runPatience), runIs("alert open high record-set records www.example. A"))
	svc.wait(t, "the alert of the delegation", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	i := len(svc.out.all())
	runReplace(t, file, runFile)
	soon := time.Now().Add(3 * time.Second)
	notice, _ := svc.wait(t, "the notice of the change", i, soon, runIs("notice expectations corp.test. to 1 channels"))
	closed, _ := svc.wait(t, "the closed line", i, soon, runIs("closed resolve high record-set records www.example. A"))
	time.Sleep(500 * time.Millisecond)
	lines := svc.stop(t)
	if notice.domain != "corp.test." || closed.domain != "corp.test." {
		t.Errorf("the notice and closed lines name the domains %q and %q, want corp.test.", notice.domain, closed.domain)
	}
	for _, l := range lines[i:] {
		if l.event == "alert" {
			t.Errorf("the line that left the file gave %q", l.text)
		}
	}
	notices := svcNotices(t, state, store.NoticeExpectations)
	if want := []string{"- www.example. A 192.0.2.99", "closed high record-set records www.example. A"}; len(notices) != 1 ||
		!slices.Equal(notices[0].Lines, want) || notices[0].Domain != "corp.test." {
		t.Errorf("the expectations notices are %+v, want one of corp.test. with %q", notices, want)
	}
	open, err := svcReader(t, state).AllOpenAlerts()
	if err != nil || len(open) != 1 || open[0].Rule != decide.RuleNotCovered {
		t.Errorf("open alerts %+v, error %v; want only the not-covered alert of the delegation", open, err)
	}
	want := []string{"notice expectations corp.test.", "open high record-set records www.example. A", runNotCovered}
	if got := svcLabels(svcRows(t, state, "slack")["slack"]); !slices.Equal(got, want) {
		t.Errorf("the rows of Slack are %q, want %q, and no resolve", got, want)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A domain that left the config has its every open alert closed at the
// next start, the alerts of its whole domain too, with one notice that
// lists each line of its last file. Back in the config, it is a first load
// again, which tells nothing.
func TestRunDomainThatLeftTheConfigClosesItsAlerts(t *testing.T) {
	s := transportStart(t, svcWorld(nil, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 200*time.Millisecond)
	fileA, fileB := expFile(t, runFile+"www.example. A 192.0.2.99\n"), expFile(t, svcOtherFile)
	state := filepath.Join(t.TempDir(), "state")
	iv := runIntervals("1h", "1h", "1h", "1h")
	first := runStart(t, svcTwo(t, s, fileA, fileB, state, iv)...)
	first.wait(t, "the alert of www", 0, time.Now().Add(runPatience), runIs("alert open high record-set records www.example. A"))
	first.wait(t, "the alert of the delegation", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	runReplace(t, fileA, "domain corp.test.\ncorp.test DS none\n")
	first.wait(t, "the invalid-file alert", 0, time.Now().Add(runPatience), runIs("alert open medium invalid-file corp.test."))
	first.stop(t)

	only := runConfig(t, runLocalCfg(s, state, iv, runCfgDomain{Name: "other.test.", Expect: fileB}))
	second := runStart(t, only...)
	soon := time.Now().Add(5 * time.Second)
	second.wait(t, "the notice of corp.test.", 0, soon, runIs("notice expectations corp.test. to 1 channels"))
	closed := []string{"high record-set records www.example. A", "medium invalid-file corp.test.", "medium not-covered delegation corp.test. NS"}
	for _, c := range closed {
		second.wait(t, "the closed alert "+c, 0, soon, runIs("closed resolve "+c))
	}
	second.stop(t)
	var want []string
	for _, l := range svcSumLines(svcCanonical(t, "corp.test. DS none", "www.example. A 192.0.2.99")) {
		want = append(want, "- "+l)
	}
	notices := svcNotices(t, state, store.NoticeExpectations)
	if len(notices) != 1 || notices[0].Domain != "corp.test." || len(notices[0].Lines) != len(want)+len(closed) {
		t.Fatalf("the expectations notices are %+v, want one of corp.test. with %d lines", notices, len(want)+len(closed))
	}
	// The closed alerts come in the order of the store.
	got := notices[0].Lines
	tail := slices.Sorted(slices.Values(got[len(want):]))
	if !slices.Equal(got[:len(want)], want) || !slices.Equal(tail, []string{"closed " + closed[0], "closed " + closed[1], "closed " + closed[2]}) {
		t.Errorf("the notice of corp.test. holds:\n%s\nwant the lines of its last file:\n%s\nthen a closed line for each of %q",
			strings.Join(got, "\n"), strings.Join(want, "\n"), closed)
	}
	open, err := svcReader(t, state).AllOpenAlerts()
	if err != nil || slices.ContainsFunc(open, func(a alert.Alert) bool { return a.Check.Domain.Equal(cliName("corp.test.")) }) {
		t.Errorf("open alerts %+v, error %v; want none of corp.test.", open, err)
	}

	runReplace(t, fileA, runFile)
	third := runStart(t, svcTwo(t, s, fileA, fileB, state, iv)...)
	third.wait(t, "the first run of corp.test.", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	time.Sleep(300 * time.Millisecond)
	for _, l := range third.stop(t) {
		if l.event == "notice" && strings.HasPrefix(l.text, "notice expectations") {
			t.Errorf("a domain back in the config gave %q", l.text)
		}
	}
	runNoSecret(t, state, first.out.String(), second.out.String(), third.out.String())
}

// Each change of a file in force gives one notice with the changed lines,
// a change made while osk-dns-watcher was down too; the first load of a file gives
// none. At most 200 changed lines are kept, then a line that counts the
// rest.
func TestRunChangedFileSendsOneNoticeWithTheChangedLines(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	v1 := svcNSFile + "www.example. A 192.0.2.80\n"
	v2 := svcNSFile + "www.example. A 192.0.2.99\n"
	file := expFile(t, v1)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: file})
	c.Webhooks = []runCfgHook{svcDeadHook(t, "crit", "critical")}
	args := runConfig(t, c)
	first := runStart(t, args...)
	first.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	runReplace(t, file, v2)
	_, i := first.wait(t, "the notice of the change", 0, time.Now().Add(runPatience), runIs("notice expectations corp.test. to 2 channels"))
	time.Sleep(500 * time.Millisecond)
	lines := first.stop(t)
	if n := svcCount(lines, "notice expectations corp.test. to 2 channels"); n != 1 || i == 0 {
		t.Errorf("the first load and one change gave %d notices, want 1", n)
	}

	var many []string
	for n := range 250 {
		many = append(many, fmt.Sprintf("h%03d.corp.test. TXT none", n))
	}
	runReplace(t, file, v2+strings.Join(many, "\n")+"\n")
	second := runStart(t, args...)
	second.wait(t, "the notice of the change made while osk-dns-watcher was down", 0, time.Now().Add(runPatience),
		runIs("notice expectations corp.test. to 2 channels"))
	second.stop(t)

	notices := svcNotices(t, state, store.NoticeExpectations)
	if len(notices) != 2 {
		t.Fatalf("the store holds %d expectations notices, want 2", len(notices))
	}
	if want := []string{"- www.example. A 192.0.2.80", "+ www.example. A 192.0.2.99"}; !slices.Equal(notices[0].Lines, want) {
		t.Errorf("the first notice holds %q, want %q", notices[0].Lines, want)
	}
	var added []string
	for _, l := range svcSumLines(svcCanonical(t, many...)) {
		if strings.HasPrefix(l, "h") {
			added = append(added, "+ "+l)
		}
	}
	got := notices[1].Lines
	kept := len(got) - 1
	// At most 200 lines are kept, the count of the rest among them or after them.
	if kept < 199 || kept > 200 || !slices.Equal(got[:kept], added[:kept]) || got[kept] != fmt.Sprintf("and %d more lines", 250-kept) {
		t.Errorf("the notice of 250 added lines holds %d lines, from %q to %q; want the first 199 or 200 and \"and <the rest> more lines\"",
			len(got), got[:min(1, len(got))], got[max(0, len(got)-1):])
	}
	runNoSecret(t, state, first.out.String(), second.out.String())
}

// svcRequest writes the request file of osk-dns-watcher test-alert, as it makes it.
func svcRequest(t *testing.T, state, text string) string {
	t.Helper()
	path := filepath.Join(state, "test-alert")
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(f, text); err != nil {
		t.Fatal(err)
	}
	if err := f.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func svcGone(t *testing.T, what, path string, deadline time.Time) {
	t.Helper()
	for {
		if _, err := os.Lstat(path); errors.Is(err, fs.ErrNotExist) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s was not removed by %s", what, deadline.UTC().Format(runLineLayout))
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// The request file of osk-dns-watcher test-alert is taken, answered with a test notice
// to every channel and removed; a file that holds no request is removed and
// sends nothing.
func TestRunTakesTheTestRequestFile(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: expFile(t, svcNSFile)})
	c.Webhooks = []runCfgHook{svcDeadHook(t, "siem", "critical")}
	svc := runStart(t, runConfig(t, c)...)
	svc.wait(t, "the start line", 0, time.Now().Add(runPatience), runPrefix("start "))
	const nonce = "0123456789abcdef0123456789abcdef"
	path := svcRequest(t, state, nonce+"\n")
	_, i := svc.wait(t, "the test request", 0, time.Now().Add(runPatience), runIs("test-alert "+nonce))
	svc.wait(t, "the test notice", i, time.Now().Add(runPatience), runIs("notice test - to 2 channels"))
	svcGone(t, "the request file", path, time.Now().Add(runPatience))
	for _, bad := range []string{"hello\n", strings.ToUpper(nonce) + "\n", nonce[:31] + "\n", nonce + "0\n", strings.Repeat(nonce, 3) + "\n"} {
		path := svcRequest(t, state, bad)
		_, i = svc.wait(t, "the refusal of "+strconv.Quote(bad), i+1, time.Now().Add(runPatience), runIs("test-alert ignored: not a request"))
		svcGone(t, "the file that holds no request", path, time.Now().Add(runPatience))
	}
	time.Sleep(300 * time.Millisecond)
	lines := svc.stop(t)
	if n := svcCount(lines, "notice test - to 2 channels"); n != 1 {
		t.Errorf("%d test notices were made, want 1", n)
	}
	notices := svcNotices(t, state, store.NoticeTest)
	if len(notices) != 1 || notices[0].Domain != "" || !slices.Equal(notices[0].Lines, []string{"request   " + nonce}) {
		t.Fatalf("the test notices are %+v, want one with the line \"request   %s\"", notices, nonce)
	}
	rows, err := svcReader(t, state).NoticeRows(notices[0].ID)
	if err != nil || len(rows) != 2 || rows[0].Channel != "slack" || rows[1].Channel != "siem" {
		t.Errorf("the rows of the test notice are %+v, error %v; want one for slack and one for siem", rows, err)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcCalmCfg is a config whose start sends nothing: the fake world shows
// every line of a name in corp.test. as answered from another zone, and only
// a not-covered delegation here, which a Slack channel with the minimum
// critical does not hear of.
func svcCalmCfg(t *testing.T, s *transportServer, file, state string, iv map[string]string) runCfg {
	t.Helper()
	c := runLocalCfg(s, state, iv, runCfgDomain{Name: "corp.test.", Expect: file})
	c.Slack.MinSeverity = "critical"
	c.Heartbeat = &runCfgBeat{URL: runSecret{Env: "OSK_HEARTBEAT_URL"}, Interval: "5s"}
	return c
}

// The outside heartbeat is posted while the service is healthy, and skipped
// while a channel fails.
func TestRunHeartbeatOnlyWhileHealthy(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	t.Setenv("OSK_HEARTBEAT_URL", "https://127.0.0.1:1/beat/"+runMarker)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &beatEvery, 300*time.Millisecond)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	begin := time.Now()
	svc := runStart(t, runConfig(t, svcCalmCfg(t, s, file, state, runIntervals("1h", "1h", "1h", "1h")))...)
	posted := runPrefix("heartbeat failed: ")
	_, i := svc.wait(t, "a heartbeat", 0, begin.Add(runPatience), posted)
	svc.wait(t, "a second heartbeat", i+1, begin.Add(runPatience), posted)

	// A delegation that differs is critical, and Slack, which cannot be
	// reached, fails.
	runReplace(t, file, "domain corp.test.\ncorp.test. NS ns9.corp.test.\ncorp.test. DS none\n")
	failed, j := svc.wait(t, "a failed delivery", i, time.Now().Add(runPatience), runPrefix("delivery slack failed "))
	skipped, k := svc.wait(t, "the skipped heartbeat", j, failed.at.Add(6500*time.Millisecond), runIs("heartbeat skipped: channel slack fails"))
	svc.wait(t, "the next skipped heartbeat", k+1, skipped.at.Add(6*time.Second), runIs("heartbeat skipped: channel slack fails"))
	lines := svc.stop(t)
	for _, l := range lines[:k] {
		if strings.HasPrefix(l.text, "heartbeat skipped") {
			t.Errorf("the healthy service printed %q", l.text)
		}
	}
	for _, l := range lines[k:] {
		if strings.HasPrefix(l.text, "heartbeat failed") || strings.HasPrefix(l.text, "heartbeat sent") {
			t.Errorf("the service with a failing channel printed %q after %q", runShow(l.text), skipped.text)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A heartbeat URL that never answers holds no check, and no stop.
func TestRunDeadHeartbeatHoldsNoCheck(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	addr, accepted := svcHang(t)
	t.Setenv("OSK_HEARTBEAT_URL", "https://"+addr+"/beat/"+runMarker)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runConfig(t, svcCalmCfg(t, s, expFile(t, runFile), state, runIntervals("1h", "5s", "1h", "1h")))...)
	select {
	case <-accepted:
	case <-time.After(runPatience):
		t.Fatal("no heartbeat began within the patience of the start")
	}
	// Each heartbeat hangs until the client gives it up; meanwhile the
	// delegation runs every 5 s.
	time.Sleep(12 * time.Second)
	lines := svc.stopWithin(t, 5*time.Second)
	if !slices.ContainsFunc(lines, func(l runLine) bool { return strings.HasPrefix(l.text, "heartbeat failed: ") }) {
		t.Errorf("no heartbeat that hung was given up:\n%s", runDump(lines))
	}
	runs := runRuns(t, lines)[runDelegationKey]
	if len(runs) < 3 {
		t.Errorf("the delegation ran %d times while the heartbeat hung, want at least 3", len(runs))
	}
	runGaps(t, runDelegationKey, runs, 5*time.Second)
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// svcPlant writes an alert of the check of name into the store: opened at
// opened, resolved at resolved unless that is zero, with a pending row on a
// channel that is not in the config when pending.
func svcPlant(t *testing.T, s *store.Store, name string, opened, resolved time.Time, pending bool) int64 {
	t.Helper()
	k := obs.RecordsKey(cliName("corp.test."), cliName(name), dnswire.TypeA)
	a := alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh, Check: k,
		Expected: "192.0.2.80", Value: "x", Opened: opened, Noticed: opened}
	e := alert.Event{Kind: alert.EventOpen, Alert: a, Was: a.Severity, At: opened}
	var rows []store.Delivery
	if pending {
		rows = []store.Delivery{{Channel: "gone", Label: e.Label(), Body: []byte("{}")}}
	}
	if err := s.Apply(k, false, opened, []store.Write{{Event: e, Deliveries: rows}}); err != nil {
		t.Fatal(err)
	}
	open, err := s.OpenAlerts(k)
	if err != nil || len(open) != 1 {
		t.Fatalf("open alerts of %s: %+v, %v", k, open, err)
	}
	if !resolved.IsZero() {
		a = open[0]
		a.Open, a.Resolved = false, resolved
		if err := s.Apply(k, false, resolved, []store.Write{{Event: alert.Event{Kind: alert.EventResolve, Alert: a, Was: a.Severity, At: resolved}}}); err != nil {
			t.Fatal(err)
		}
	}
	return open[0].ID
}

// History older than history_days is deleted at the start, 200 alerts at a
// time and again at the next beat while a batch was full. An open alert, an
// alert or a notice with a pending row, and newer history stay.
func TestRunDeletesHistoryByAge(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runSet(t, &beatEvery, 300*time.Millisecond)
	state := filepath.Join(t.TempDir(), "state")
	now := time.Now()
	days := func(n float64) time.Time { return now.Add(-time.Duration(n * float64(24*time.Hour))) }
	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	var old []int64
	for n := range 205 {
		old = append(old, svcPlant(t, st, fmt.Sprintf("h%03d.corp.test.", n), days(4), days(3), false))
	}
	kept := []int64{svcPlant(t, st, "pending.corp.test.", days(4), days(3), true)}
	sent := store.Notice{Kind: store.NoticeTest, Lines: []string{"request   " + strings.Repeat("a", 32)}, At: days(3)}
	if err := st.Notify(sent, []store.Delivery{{Channel: "slack", Label: "notice test -", Body: []byte("{}")}}); err != nil {
		t.Fatal(err)
	}
	rows, err := st.Due("slack", now)
	if err != nil || len(rows) != 1 {
		t.Fatalf("the row of the old notice: %+v, %v", rows, err)
	}
	if err := st.Record(rows[0].ID, store.Done{State: store.RowSent, Attempts: 1, At: days(3)}); err != nil {
		t.Fatal(err)
	}
	// The alert of a line of the file, open for days: the service sees the
	// same difference and keeps it open.
	k := obs.RecordsKey(cliName("corp.test."), cliName("www.example."), dnswire.TypeA)
	stand := alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh, Check: k,
		Expected: "192.0.2.99", Opened: days(4), Noticed: days(4)}
	if err := st.Apply(k, false, days(4), []store.Write{{Event: alert.Event{Kind: alert.EventOpen, Alert: stand, Was: stand.Severity, At: days(4)}}}); err != nil {
		t.Fatal(err)
	}
	kept = append(kept, svcPlant(t, st, "recent.corp.test.", days(0.1), now.Add(-time.Hour), false))
	waiting := store.Notice{Kind: store.NoticeTest, Lines: []string{"request   " + strings.Repeat("b", 32)}, At: days(3)}
	if err := errors.Join(st.Notify(waiting, []store.Delivery{{Channel: "gone", Label: "notice test -", Body: []byte("{}")}}), st.Close()); err != nil {
		t.Fatal(err)
	}

	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: expFile(t, svcNSFile+"www.example. A 192.0.2.99\n")})
	c.HistoryDays = 1
	svc := runStart(t, runConfig(t, c)...)
	history := regexp.MustCompile(`^history deleted (\d+) alerts and (\d+) notices from before (\S+)$`)
	first, i := svc.wait(t, "the first deletion", 0, time.Now().Add(runPatience), history.MatchString)
	second, _ := svc.wait(t, "the deletion at the next beat", i+1, first.at.Add(3*time.Second), history.MatchString)
	time.Sleep(time.Second)
	lines := svc.stop(t)
	for _, c := range []struct {
		l      runLine
		counts string
	}{{first, "200 1"}, {second, "5 0"}} {
		m := history.FindStringSubmatch(c.l.text)
		cutoff, err := time.Parse(runSecondLayout, m[3])
		if m[1]+" "+m[2] != c.counts || err != nil {
			t.Errorf("%q: want %s alerts and notices and a cutoff like %s", c.l.text, c.counts, runSecondLayout)
		} else {
			slkWithin(t, "the cutoff", cutoff, c.l.at.Add(-24*time.Hour-2*time.Second), c.l.at.Add(-24*time.Hour+time.Second))
		}
	}
	if n := slices.IndexFunc(lines, func(l runLine) bool {
		return history.MatchString(l.text) && l.text != first.text && l.text != second.text
	}); n >= 0 {
		t.Errorf("a third deletion was logged: %q", lines[n].text)
	}
	r := svcReader(t, state)
	for _, id := range old {
		if _, err := r.Alert(id); err == nil || err.Error() != fmt.Sprintf("store: no alert %d", id) {
			t.Errorf("the alert %d, resolved three days ago, is still there: %v", id, err)
			break
		}
	}
	for _, id := range kept {
		if _, err := r.Alert(id); err != nil {
			t.Errorf("the alert %d is gone: %v", id, err)
		}
	}
	if open, err := r.AllOpenAlerts(); err != nil || !slices.ContainsFunc(open, func(a alert.Alert) bool { return a.Check.String() == k.String() }) {
		t.Errorf("open alerts %+v, error %v; want the alert open for four days", open, err)
	}
	events, err := r.Events(0)
	if err != nil || slices.ContainsFunc(events, func(e store.EventRow) bool { return slices.Contains(old, e.Alert.ID) }) {
		t.Errorf("an event of a deleted alert is left, error %v", err)
	}
	notices := svcNotices(t, state, store.NoticeTest)
	if len(notices) != 1 || !slices.Equal(notices[0].Lines, waiting.Lines) {
		t.Errorf("the test notices left are %+v, want only the one with a pending row", notices)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// No secret of the config shows up in any output or any file of the state
// folder: the Slack URL and the heartbeat URL from the environment, the
// webhook URL and its key from files.
func TestRunKeepsSecretsOutOfOutputAndState(t *testing.T) {
	s := transportStart(t, expWorld)
	runReadEvery(t, 100*time.Millisecond)
	marks := []string{"slkmarkqzx", "hookmarkqzx", "keymarkqzx", "beatmarkqzx"}
	t.Setenv("OSK_SLACK_URL", "https://127.0.0.1:1/slack/"+marks[0])
	t.Setenv("OSK_HEARTBEAT_URL", "https://127.0.0.1:1/beat/"+marks[3])
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	c := runLocalCfg(s, state, runIntervals("1h", "1h", "1h", "1h"), runCfgDomain{Name: "corp.test.", Expect: file})
	c.Webhooks = []runCfgHook{{Name: "siem", URL: runSecret{File: svcSecretFile(t, "https://127.0.0.1:1/hook/"+marks[1])},
		Key: runSecret{File: svcSecretFile(t, marks[2]+strings.Repeat("k", 40))}}}
	c.Heartbeat = &runCfgBeat{URL: runSecret{Env: "OSK_HEARTBEAT_URL"}, Interval: "5s"}
	args := runConfig(t, c)
	svc := runStart(t, args...)
	svc.wait(t, "the alert", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	svcRequest(t, state, "0123456789abcdef0123456789abcdef\n")
	runReplace(t, file, svcNSFile)
	soon := time.Now().Add(8 * time.Second)
	for _, want := range []string{"notice test - to 2 channels", "notice expectations corp.test. to 2 channels",
		"alert resolve medium not-covered delegation corp.test. NS"} {
		svc.wait(t, want, 0, soon, runIs(want))
	}
	svc.wait(t, "a heartbeat", 0, soon, runPrefix("heartbeat "))
	svc.wait(t, "a failed delivery to siem", 0, soon, runPrefix("delivery siem failed "))
	lines := svc.stop(t)
	data, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatal(err)
	}
	svcNoMarker(t, state, marks, svc.out.String(), svc.errOut.String(), string(data), runDump(lines))
}

// A changed file that is valid is taken once two reads agree. A file that
// is not valid is taken only once it has stayed the same for readSettle:
// a file emptied for a moment, as an editor or a copy leaves it, opens no
// alert.
func TestRunTakesAnInvalidFileOnlyAfterItStaysInvalid(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	runSet(t, &readSettle, 1500*time.Millisecond)
	v1 := runFile + "www.example. A 192.0.2.80\n"
	file := expFile(t, v1)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, file, state, runIntervals("1h", "1h", "1h", "1h"))...)
	svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	svc.wait(t, "the alert of the delegation", 0, time.Now().Add(runPatience), runIs("alert "+runNotCovered))
	skip := len(svc.out.all())

	runReplace(t, file, "")
	time.Sleep(700 * time.Millisecond)
	runReplace(t, file, v1)
	time.Sleep(2 * time.Second)
	for _, l := range svc.out.all()[skip:] {
		if l.event == "file" || l.event == "alert" {
			t.Errorf("a file emptied for 700 ms gave %q", l.text)
		}
	}

	emptied := time.Now()
	runReplace(t, file, "")
	problem, i := svc.wait(t, "the problem of the empty file", 0, emptied.Add(4*time.Second), runIs("file "+file+": no domain line"))
	opened, _ := svc.wait(t, "the invalid-file alert", i, emptied.Add(4*time.Second), runIs("alert open medium invalid-file corp.test."))
	if problem.at.Before(emptied.Add(1400*time.Millisecond)) || opened.at.Before(emptied.Add(1400*time.Millisecond)) {
		t.Errorf("the empty file was taken at %s, less than 1.5 s after it was emptied at %s", problem.at, emptied.UTC())
	}
	runReplace(t, file, v1)
	_, i = svc.wait(t, "the resolve", i, time.Now().Add(runPatience), runIs("alert resolve medium invalid-file corp.test."))

	changed := time.Now()
	runReplace(t, file, runFile+"www.example. A 192.0.2.99\n")
	taken, _ := svc.wait(t, "the valid change", i, changed.Add(3*time.Second), runIs("file "+file+" changed: 4 checks"))
	if taken.at.After(changed.Add(time.Second)) {
		t.Errorf("a valid change was taken %v after it was written, want two reads, not the wait of a file that is not valid", taken.at.Sub(changed))
	}
	lines := svc.stop(t)
	if n := svcCount(lines, "alert open medium invalid-file corp.test."); n != 1 {
		t.Errorf("the invalid-file alert opened %d times, want once", n)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A move of the serial that the stop finds held, because the last notice
// of moves came less than one other-interval before, is told at the stop
// and not lost. After a restart, a quiet serial ends the notice only one
// other-interval after the start. runFile has no zone check: in the fake
// world a zone check shows a zone finding that stands, and its open alert
// would explain every move.
func TestRunHeldZoneMovesAreToldAtACleanStop(t *testing.T) {
	var serial atomic.Uint32
	serial.Store(1)
	s := transportStart(t, svcWorld(&serial, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(t, s, file, state, runIntervals("5s", "1h", "1h", "15s"))
	svc := runStart(t, args...)
	_, i := svc.wait(t, "the first serial run", 0, time.Now().Add(runPatience), runRunOf(runSerialKey))
	const label = "low zone-changed corp.test."
	moved := func(from, to int) func(string) bool {
		return func(text string) bool {
			return strings.HasPrefix(text, "moved corp.test. "+s.addr+" ") && strings.HasSuffix(text, fmt.Sprintf(" serial %d to %d", from, to))
		}
	}
	serial.Store(2)
	_, i = svc.wait(t, "the move from 1 to 2", i, time.Now().Add(runPatience), moved(1, 2))
	_, i = svc.wait(t, "the zone-changed alert", i, time.Now().Add(runPatience), runIs("alert open "+label))
	serial.Store(3)
	_, i = svc.wait(t, "the move from 2 to 3", i, time.Now().Add(runPatience), moved(2, 3))
	time.Sleep(500 * time.Millisecond)
	for _, l := range svc.out.all()[i:] {
		if l.event == "alert" {
			t.Errorf("a move within one other-interval of the last notice gave %q before the stop", l.text)
		}
	}
	lines := svc.stop(t)
	if u := slices.IndexFunc(lines, func(l runLine) bool { return l.text == "alert update "+label }); u < i {
		t.Errorf("the stop did not tell the held move with \"alert update %s\":\n%s", label, runDump(lines))
	}
	open, err := svcReader(t, state).AllOpenAlerts()
	z := slices.IndexFunc(open, func(a alert.Alert) bool { return a.Rule == decide.RuleZoneChanged })
	if err != nil || z < 0 || !strings.Contains(open[z].Value, " serial 2 until ") || !strings.Contains(open[z].Value, ", 3 since ") {
		t.Errorf("open alerts %+v, error %v; want the zone-changed alert with the move from 2 to 3", open, err)
	}

	restarted := time.Now()
	again := runStart(t, args...)
	resolved, _ := again.wait(t, "the resolve after the restart", 0, restarted.Add(30*time.Second), runIs("alert resolve "+label))
	again.stop(t)
	if resolved.at.Before(restarted.Add(15 * time.Second)) {
		t.Errorf("the quiet serial ended the notice %v after the restart, before one other-interval of 15s", resolved.at.Sub(restarted))
	}
	runNoSecret(t, state, svc.out.String(), again.out.String())
}

// Each domain has its own serial and rounds: a move of each opens the
// zone-changed alert of that domain, and a zone check of other.test. that
// never gets an answer holds its round only until the limit of its
// failures. Neither file has a zone check that gives an answer: in the fake
// world such a check shows a zone finding that stands, and its open alert
// would explain every move.
func TestRunZoneChangedOfEachDomainAndABlindZoneCheck(t *testing.T) {
	var corp, other atomic.Uint32
	corp.Store(1)
	other.Store(1)
	s := transportStart(t, svcWorld(&corp, &other))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	fileA, fileB := expFile(t, runFile), expFile(t, "domain other.test.\nother.test. DS none\nblind.other.test. A 192.0.2.5\n")
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, svcTwo(t, s, fileA, fileB, state, runIntervals("5s", "1h", "1h", "5s"))...)
	blind := "records other.test. blind.other.test. A"
	firstBlind, _ := svc.wait(t, "the first run of the blind check", 0, time.Now().Add(runPatience), runRunOf(blind))
	svc.wait(t, "the first serial run of other.test.", 0, time.Now().Add(runPatience), runRunOf("serial other.test. other.test. SOA"))
	svc.wait(t, "the first serial run of corp.test.", 0, time.Now().Add(runPatience), runRunOf(runSerialKey))
	fb, _, _ := runParse(firstBlind.text)
	corp.Store(2)
	other.Store(2)
	moved := time.Now()
	a, _ := svc.wait(t, "the zone-changed alert of corp.test.", 0, moved.Add(5*time.Second+3750*time.Millisecond+2*time.Second),
		runIs("alert open low zone-changed corp.test."))
	b, _ := svc.wait(t, "the zone-changed alert of other.test.", 0, fb.start.Add(15*time.Second+5*time.Second+3750*time.Millisecond+3*time.Second),
		runIs("alert open low zone-changed other.test."))
	lines := svc.stop(t)
	if a.domain != "corp.test." || b.domain != "other.test." {
		t.Errorf("the zone-changed alerts name the domains %q and %q", a.domain, b.domain)
	}
	if b.at.Before(fb.start.Add(15 * time.Second)) {
		t.Errorf("the round of other.test. ended at %s, before the blind check had failed for its limit of 15s from %s", b.at, fb.start)
	}
	for _, l := range lines {
		if c, ok, _ := runParse(l.text); ok && c.key == blind && c.result == "ok" {
			t.Errorf("the blind check gave %q", l.text)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A move of the serial while a zone check shows a difference that stands
// opens no zone-changed alert: the run of that check in the round gives no
// change, but its open alert already says that a watched record differs. In
// the fake world the NS line of svcNSFile shows a zone finding that stands.
func TestRunOpenDifferenceExplainsTheMove(t *testing.T) {
	var serial atomic.Uint32
	serial.Store(1)
	s := transportStart(t, svcWorld(&serial, nil))
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(t, s, expFile(t, svcNSFile), state, runIntervals("5s", "1h", "1h", "1h"))...)
	const ns = "records corp.test. corp.test. NS"
	_, i := svc.wait(t, "the zone alert", 0, time.Now().Add(runPatience), runIs("alert open high zone records corp.test. NS"))
	_, i = svc.wait(t, "a serial run", i, time.Now().Add(runPatience), runRunOf(runSerialKey))
	serial.Store(2)
	_, i = svc.wait(t, "the move", i, time.Now().Add(runPatience), runIs("moved corp.test. "+s.addr+" - serial 1 to 2"))
	_, i = svc.wait(t, "the run of the NS set in the round", i, time.Now().Add(runPatience), runRunOf(ns))
	svc.wait(t, "the next serial run", i, time.Now().Add(runPatience), runRunOf(runSerialKey))
	for _, l := range svc.stop(t) {
		if l.event == "alert" && strings.Contains(l.text, " zone-changed ") {
			t.Errorf("a move while a difference stands gave %q", l.text)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A state folder that other users may enter is refused, not changed, before
// anything is opened in it. One that only its owner may enter is used, and
// every file that the service makes in it is its owner's alone.
func TestRunRefusesAStateFolderOpenToOthers(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(state, 0o700); err != nil {
		t.Fatal(err)
	}
	args := runLocal(t, s, expFile(t, svcNSFile), state, runIntervals("1h", "1h", "1h", "1h"))
	for _, mode := range []os.FileMode{0o755, 0o750, 0o701, 0o710} {
		if err := os.Chmod(state, mode); err != nil {
			t.Fatal(err)
		}
		code, out, errOut := runRefused(t, args...)
		want := fmt.Sprintf("osk-dns-watcher: store: %s is open to other users (mode %04o); run chmod 700 %s\n", state, uint32(mode), state)
		if code != 1 || out != "" || errOut != want {
			t.Errorf("mode %04o: exit code %d, output %q, errors %q; want 1, nothing and %q", uint32(mode), code, out, errOut, want)
		}
		info, err := os.Stat(state)
		if err != nil || info.Mode().Perm() != mode {
			t.Errorf("the refused folder has the mode %v, %v; want %v as it was", info.Mode().Perm(), err, mode)
		}
		if entries, err := os.ReadDir(state); err != nil || len(entries) != 0 {
			t.Errorf("the refused folder holds %v, %v; want nothing", entries, err)
		}
	}
	if err := os.Chmod(state, 0o700); err != nil {
		t.Fatal(err)
	}
	svc := runStart(t, args...)
	svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
	svc.stop(t)
	err := filepath.WalkDir(state, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err == nil && info.Mode().Perm()&0o077 != 0 {
			t.Errorf("%s has the mode %v, open to other users", path, info.Mode().Perm())
		}
		return err
	})
	if err != nil {
		t.Error(err)
	}
}

// downNoticeDefault is the limit that osk-dns-watcher itself uses. TestMain sets the
// limit to 0, so that each test of a restart, which stops for seconds,
// still sees its one down notice.
var downNoticeDefault = downNotice

func TestMain(m *testing.M) {
	downNotice = 0
	dir, err := os.MkdirTemp("", "osk-dns-watcher-roots")
	if err != nil {
		crtTLS.err = err
	} else {
		crtTLS.srv, crtTLS.err = crtListen(dir)
	}
	code := m.Run()
	if crtTLS.srv != nil {
		crtTLS.srv.Close()
	}
	if dir != "" {
		_ = os.RemoveAll(dir)
	}
	os.Exit(code)
}

// A stop shorter than a minute, as for a change of the config, is told by
// the down line alone; from a minute on, the down notice goes to every
// channel.
func TestRunDownNoticeOnlyAfterAMinuteDown(t *testing.T) {
	if downNoticeDefault != time.Minute {
		t.Errorf("the down notice is sent from %v down, want 1m0s", downNoticeDefault)
	}
	runSet(t, &downNotice, downNoticeDefault)
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(t, s, expFile(t, svcNSFile), state, runIntervals("1h", "1h", "1h", "1h"))
	for _, c := range []struct {
		down    time.Duration
		notices int
	}{{50 * time.Second, 0}, {70 * time.Second, 1}} {
		st, err := store.Open(state)
		if err != nil {
			t.Fatal(err)
		}
		if err := errors.Join(st.Beat(time.Now().Add(-c.down), nil), st.Close()); err != nil {
			t.Fatal(err)
		}
		svc := runStart(t, args...)
		svc.wait(t, "the first run", 0, time.Now().Add(runPatience), runRunOf(runDelegationKey))
		lines := svc.stop(t)
		if _, down := runHead(t, lines); !strings.HasPrefix(down.text, "down since ") {
			t.Errorf("after %v down the down line is %q, want \"down since ...\"", c.down, down.text)
		}
		if n := svcCount(lines, "notice down - to 1 channels"); n != c.notices {
			t.Errorf("after %v down %d down notices were sent, want %d:\n%s", c.down, n, c.notices, runDump(lines))
		}
	}
	if n := svcNotices(t, state, store.NoticeDown); len(n) != 1 {
		t.Errorf("the store holds %d down notices, want 1", len(n))
	}
}
