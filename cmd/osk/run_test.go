package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// runMarker ends the Slack URL of these tests. The URL is a secret, so the
// marker may show up in no output, in no file of the state folder and in no
// test log line.
const runMarker = "runsecret"

// Nothing listens on port 1, so every send fails at once.
const runDeadURL = "https://127.0.0.1:1/x/" + runMarker

const runLineLayout = "2006-01-02T15:04:05.000Z"

// runSecondLayout is the layout of the times that a line gives to the second.
const runSecondLayout = "2006-01-02T15:04:05Z"

const runSynopsis = "osk run [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>]" +
	" [--serial-interval <duration>] [--parent-interval <duration>] [--fast-interval <duration>]" +
	" [--other-interval <duration>] [--fast <name>]... [--slack-min-severity <severity>] --expect <file> --state <folder>"

var runTiers = []string{"serial", "parent", "fast", "other"}

func runShow(s string) string {
	return strings.ReplaceAll(s, runMarker, "[marker]")
}

// runLine is one line of standard output: the time at its head and the rest.
type runLine struct {
	at   time.Time
	text string
	raw  string
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
	stamp, text, ok := strings.Cut(raw, " ")
	at, err := time.Parse(runLineLayout, stamp)
	switch {
	case !ok || err != nil || at.Format(runLineLayout) != stamp:
		o.faults = append(o.faults, fmt.Sprintf("the line %q does not start with the time in UTC and a space", runShow(raw)))
	case o.strict && (at.After(now) || now.Sub(at) > time.Second):
		o.faults = append(o.faults, fmt.Sprintf("the line %q was written at %s, not at the time it names",
			runShow(raw), now.UTC().Format(runLineLayout)))
	}
	o.lines = append(o.lines, runLine{at: at, text: text, raw: raw})
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
		t.Errorf("osk run %s ran until it was stopped instead of ending at once", runShow(strings.Join(args, " ")))
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

// runHead gives the lines that a service printed before its loops started,
// and its down line apart (zero when there is none).
func runHead(t *testing.T, lines []runLine) (head []string, down runLine) {
	t.Helper()
	for _, l := range lines {
		word, _, _ := strings.Cut(l.text, " ")
		switch word {
		case "checked", "moved", "alert", "delivery", "file", "stop":
			return head, down
		case "down":
			if down.text != "" {
				t.Errorf("two down lines: %q and %q", down.text, l.text)
			}
			down = l
		default:
			head = append(head, l.text)
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
	for _, o := range outputs {
		if strings.Contains(o, runMarker) {
			t.Errorf("an output holds the marker of the Slack URL:\n%s", runShow(o))
		}
	}
	size := 0
	err := filepath.WalkDir(state, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(runMarker)) {
			t.Errorf("%s holds the marker of the Slack URL", path)
		}
		size += len(data)
		return err
	})
	if _, serr := os.Stat(filepath.Join(state, "osk.db")); err != nil || serr != nil || size == 0 {
		t.Errorf("the state folder holds no store: %v, %v, %d octets read", err, serr, size)
	}
}

// runIntervals gives the interval flags; an empty value leaves the default.
func runIntervals(serial, parent, fast, other string) []string {
	var args []string
	for i, v := range []string{serial, parent, fast, other} {
		if v != "" {
			args = append(args, "--"+runTiers[i]+"-interval", v)
		}
	}
	return args
}

// runLocal gives the arguments of a service that starts from the fake root
// server s.
func runLocal(s *transportServer, file, state string, args ...string) []string {
	return slices.Concat([]string{"--root-server", s.addr, "--extra-range", "127.0.0.0/8"}, args,
		[]string{"--expect", file, "--state", state})
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

// runReadEvery makes the service read the file more often, so that a test
// of several changes takes seconds. A cleanup runs after those registered
// later, so calling it before runStart puts the period back only once the
// service returned.
func runReadEvery(t *testing.T, d time.Duration) {
	t.Helper()
	old := readEvery
	readEvery = d
	t.Cleanup(func() { readEvery = old })
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

// The loops of the service read the file every 5 s, store a beat every 10 s
// and start a delivery pass 1 s after the last one ended.
func TestRunPeriodsAreFiveTenAndOneSeconds(t *testing.T) {
	if readEvery != 5*time.Second || beatEvery != 10*time.Second || passPause != time.Second {
		t.Errorf("file read every %v, beat every %v, pause between passes %v; want 5s, 10s and 1s", readEvery, beatEvery, passPause)
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

// runGated is an output whose writes wait until release is closed; started
// tells when a write begins.
type runGated struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	lines   []string
}

func (g *runGated) Write(p []byte) (int, error) {
	g.started <- struct{}{}
	<-g.release
	g.mu.Lock()
	defer g.mu.Unlock()
	_, text, _ := strings.Cut(strings.TrimSuffix(string(p), "\n"), " ")
	g.lines = append(g.lines, text)
	return len(p), nil
}

func (g *runGated) all() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return slices.Clone(g.lines)
}

