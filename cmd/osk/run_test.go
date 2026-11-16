package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
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

func TestRunUsageLine(t *testing.T) {
	found := slices.ContainsFunc(strings.Split(usage, "\n"), func(l string) bool {
		return strings.HasPrefix(l, " ") && strings.TrimLeft(l, " ") == runSynopsis
	})
	if !found {
		t.Errorf("the usage lacks the line\n       %s\nusage:\n%s", runSynopsis, usage)
	}
}

// The loops of the service read the file every 5 s, store a beat every 10 s
// and start a delivery pass 1 s after the last one ended.
func TestRunPeriodsAreFiveTenAndOneSeconds(t *testing.T) {
	if readEvery != 5*time.Second || beatEvery != 10*time.Second || passPause != time.Second {
		t.Errorf("file read every %v, beat every %v, pause between passes %v; want 5s, 10s and 1s", readEvery, beatEvery, passPause)
	}
}

// Wrong use is found before the file is read, before the store is opened and
// before anything is sent. The file does not exist, so reading it would give
// exit code 1; the server, which answers, must get no query.
func TestRunWrongUseReadsOpensAndSendsNothing(t *testing.T) {
	s := transportStart(t, expWorld)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.expect")
	state := filepath.Join(dir, "state")
	root := []string{"--root-server", s.addr, "--extra-range", "127.0.0.0/8"}
	files := []string{"--expect", missing, "--state", state}
	const noURL = "--state needs the Slack webhook URL in the environment variable OSK_SLACK_URL"
	const badURL = "the environment variable OSK_SLACK_URL does not hold an https URL with a host and no user name"
	invalid := func(flag, value, why string) string {
		return fmt.Sprintf("invalid value %q for flag -%s: %s", value, flag, why)
	}
	_, prefixErr := netip.ParsePrefix("10.0.0.1")
	_, nameErr := dnswire.ParseName("a..b.")
	if prefixErr == nil || nameErr == nil {
		t.Fatal("10.0.0.1 reads as a prefix, or a..b. as a name")
	}
	unspecified := slices.Concat([]string{"--root-server", "0.0.0.0", "--extra-range", "127.0.0.0/8"}, files)
	type wrong struct {
		name, url string // url "unset": the variable is not set
		args      []string
		msgs      []string // the message is one of these
	}
	cases := []wrong{
		{"root server not an address", runDeadURL, slices.Concat([]string{"--root-server", "ns1.corp.test"}, files),
			[]string{invalid("root-server", "ns1.corp.test", "not an IP address with an optional port")}},
		{"root server bad port", runDeadURL, slices.Concat([]string{"--root-server", "127.0.0.1:99999"}, files),
			[]string{invalid("root-server", "127.0.0.1:99999", "not an IP address with an optional port")}},
		{"extra range not a prefix", runDeadURL, slices.Concat(root, []string{"--extra-range", "10.0.0.1"}, files),
			[]string{invalid("extra-range", "10.0.0.1", prefixErr.Error())}},
		{"timeout zero", runDeadURL, slices.Concat(root, []string{"--timeout", "0s"}, files), []string{"the timeout must be positive"}},
		{"timeout negative", runDeadURL, slices.Concat(root, []string{"--timeout", "-1s"}, files), []string{"the timeout must be positive"}},
		{"timeout not a duration", runDeadURL, slices.Concat(root, []string{"--timeout", "soon"}, files),
			[]string{invalid("timeout", "soon", "parse error")}},
		{"severity unknown", runDeadURL, slices.Concat(root, []string{"--slack-min-severity", "urgent"}, files),
			[]string{invalid("slack-min-severity", "urgent", "want low, medium, high or critical")}},
		{"severity empty", runDeadURL, slices.Concat(root, []string{"--slack-min-severity", ""}, files),
			[]string{invalid("slack-min-severity", "", "want low, medium, high or critical")}},
		{"no expect", runDeadURL, slices.Concat(root, []string{"--state", state}), []string{"--expect is required"}},
		{"no state", runDeadURL, slices.Concat(root, []string{"--expect", missing}), []string{"--state is required"}},
		{"an argument", runDeadURL, slices.Concat(root, files, []string{"corp.test."}),
			[]string{"takes no arguments: the file gives the domain and the sets"}},
		{"expect twice", runDeadURL, slices.Concat(root, files, []string{"--expect", missing}),
			[]string{invalid("expect", missing, "given more than once")}},
		{"state twice", runDeadURL, slices.Concat(root, files, []string{"--state", state}),
			[]string{invalid("state", state, "given more than once")}},
		{"fast without trailing dot", runDeadURL, slices.Concat(root, []string{"--fast", "mail.corp.test"}, files),
			[]string{invalid("fast", "mail.corp.test", "the name has no trailing dot")}},
		{"fast not a name", runDeadURL, slices.Concat(root, []string{"--fast", "a..b."}, files),
			[]string{invalid("fast", "a..b.", nameErr.Error())}},
		{"unknown flag", runDeadURL, slices.Concat(root, []string{"--other"}, files), []string{"flag provided but not defined: -other"}},
		{"no URL", "unset", slices.Concat(root, files), []string{noURL}},
		// An empty variable holds no URL, and it is no https URL either.
		{"empty URL", "", slices.Concat(root, files), []string{noURL, badURL}},
		{"root server unspecified", runDeadURL, unspecified, []string{"observe: invalid root server 0.0.0.0:53"}},
		// The flags come first, then the variable, then the settings of the
		// queries.
		{"interval before URL", "unset", slices.Concat(root, []string{"--fast-interval", "4s"}, files),
			[]string{"--fast-interval 4s is below the floor of 5s"}},
		{"state before URL", "unset", slices.Concat(root, []string{"--expect", missing}), []string{"--state is required"}},
		{"URL before root server", "unset", unspecified, []string{noURL}},
	}
	for _, tier := range runTiers {
		flag := tier + "-interval"
		cases = append(cases, wrong{flag + " not a duration", runDeadURL, slices.Concat(root, []string{"--" + flag, "soon"}, files),
			[]string{invalid(flag, "soon", "parse error")}})
		for _, v := range []string{"4s", "4.999s", "0s", "-5s", "25h", "24h0m1s"} {
			d, err := time.ParseDuration(v)
			if err != nil {
				t.Fatal(err)
			}
			msg := fmt.Sprintf("--%s %v is below the floor of 5s", flag, d)
			if d > 5*time.Second {
				msg = fmt.Sprintf("--%s %v is above 24h0m0s", flag, d)
			}
			cases = append(cases, wrong{flag + " " + v, runDeadURL, slices.Concat(root, []string{"--" + flag, v}, files), []string{msg}})
		}
	}
	for _, url := range []string{
		"http://hooks.example/" + runMarker,
		"hooks.example/" + runMarker,
		"https:///" + runMarker,
		"https://u@hooks.example/" + runMarker,
		"https://u:" + runMarker + "@hooks.example/x",
	} {
		cases = append(cases, wrong{"URL " + runShow(url), url, slices.Concat(root, files), []string{badURL}})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("OSK_SLACK_URL", c.url)
			if c.url == "unset" {
				if err := os.Unsetenv("OSK_SLACK_URL"); err != nil {
					t.Fatal(err)
				}
			}
			code, out, errOut := runRefused(t, c.args...)
			first, rest, _ := strings.Cut(errOut, "\n")
			msg, ok := strings.CutPrefix(first, "osk run: ")
			if code != 2 || out != "" || !ok || !slices.Contains(c.msgs, msg) || rest != usage {
				t.Errorf("osk run %s: exit code %d, output %q, errors:\n%s\nwant 2, nothing, \"osk run: \" and one of %q, then the usage",
					runShow(strings.Join(c.args, " ")), code, runShow(out), runShow(errOut), c.msgs)
			}
			if strings.Contains(errOut, runMarker) {
				t.Errorf("the errors echo the value of OSK_SLACK_URL")
			}
			slkNotThere(t, state)
		})
	}

	// The command word reaches the service through run.
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	code, out, errOut := transportRun("run", "--expect", missing)
	if want := "osk run: --state is required\n" + usage; code != 2 || out != "" || errOut != want {
		t.Errorf("osk run --expect: exit code %d, output %q, errors:\n%s\nwant 2, nothing and:\n%s", code, out, errOut, want)
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// A file with problems stops the start: its lines go to standard error as
// osk check prints them, and the store is never opened.
func TestRunFileProblemsStopTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	bad := expFile(t, "domain corp.test.\nmail.corp.test A 10.53.0.82\n")
	empty := expFile(t, "# only a comment\n")
	for _, c := range []struct{ file, want string }{
		{bad, "osk: " + bad + `:2: "mail.corp.test" has no trailing dot` + "\n"},
		{empty, "osk: " + empty + ": no domain line\n"},
	} {
		code, out, errOut := runRefused(t, runLocal(s, c.file, state)...)
		if code != 1 || out != "" || errOut != c.want {
			t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, runShow(out), runShow(errOut), c.want)
		}
		slkNotThere(t, state)
	}
	code, out, errOut := runRefused(t, runLocal(s, filepath.Join(dir, "missing"), state)...)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: ") || strings.Count(errOut, "\n") != 1 || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("a missing file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk: ...\"",
			code, runShow(out), runShow(errOut))
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// A store that cannot be opened stops the start before any check runs.
func TestRunStoreErrorsStopTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)

	busy := t.TempDir()
	held, err := store.Open(busy)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := runRefused(t, runLocal(s, file, busy)...)
	if err := held.Close(); err != nil {
		t.Error(err)
	}
	if want := "osk: store: " + busy + " is in use by another osk process\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("a store in use: exit code %d, output %q, errors %q; want 1, nothing and %q", code, runShow(out), runShow(errOut), want)
	}

	// A folder cannot be made under a regular file.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = runRefused(t, runLocal(s, file, filepath.Join(plain, "state"))...)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: ") || strings.Count(errOut, "\n") != 1 || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("a folder under a file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk: ...\"",
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
	svc := runStart(t, runLocal(s, file, state, slices.Concat(runIntervals("", "24h", "5s", ""),
		[]string{"--fast", "nothere.example.", "--fast", "www.example.", "--fast", "gone.corp.test."})...)...)

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
	svc := runStart(t, slices.Concat([]string{"--root-server", s.addr, "--root-server", silent.addr, "--extra-range", "127.0.0.0/8",
		"--timeout", "300ms"}, runIntervals("1h", "1h", "1h", "1h"), []string{"--expect", file, "--state", state})...)
	deadline := time.Now().Add(5 * time.Second)
	delegation, _ := svc.wait(t, "the delegation check", 0, deadline, runRunOf(runDelegationKey))
	shop, _ := svc.wait(t, "the check of www.shop.example.", 0, deadline, runRunOf("records corp.test. www.shop.example. A"))
	svc.stop(t)
	if c, _, _ := runParse(delegation.text); c.result != "ok" || c.tier != "parent" {
		t.Errorf("the delegation, answered by one root server of two: %q, want tier parent and ok", delegation.text)
	}
	c, _, _ := runParse(shop.text)
	reasons, ok := strings.CutPrefix(c.result, "failed ")
	words := strings.Split(reasons, ",")
	if !ok || c.tier != "other" || !slices.Contains(words, obs.ReasonNotPermitted.String()) ||
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
	v1 := runFile + "www.example. A 192.0.2.80\n"
	v2 := runFile + "www.example. A 192.0.2.99\n"
	file := expFile(t, v1)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)...)
	www := "records corp.test. www.example. A"
	keys := []string{runSerialKey, runDelegationKey, runDSKey, www}
	for _, k := range keys {
		svc.wait(t, "the first run of "+k, 0, time.Now().Add(5*time.Second), runRunOf(k))
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
	_, i = svc.wait(t, "the refusal of another domain", i, soon(),
		runIs("file "+file+": the domain changed from corp.test. to other.test.; start osk run again to watch another domain"))
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
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)
	first := runStart(t, args...)
	first.wait(t, "the first run", 0, time.Now().Add(5*time.Second), runRunOf(runDelegationKey))
	runReplace(t, file, "domain corp.test.\ncorp.test DS none\n")
	first.wait(t, "the invalid-file alert", 0, time.Now().Add(3*time.Second), runIs("alert open medium invalid-file corp.test."))
	first.stop(t)

	runReplace(t, file, runFile)
	second := runStart(t, args...)
	second.wait(t, "the resolve at the start", 0, time.Now().Add(3*time.Second), runIs("alert resolve medium invalid-file corp.test."))
	second.stop(t)
	runNoSecret(t, state, first.out.String(), second.out.String())
}

// A restart prints how long the service was down, from the beat of the
// clean stop, and a difference that stands opens no second alert.
func TestRunRestartPrintsDownAndOpensNothingTwice(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)
	first := runStart(t, args...)
	first.wait(t, "the alert", 0, time.Now().Add(5*time.Second), runIs("alert "+runNotCovered))
	cancelled := time.Now()
	lines := first.stop(t)
	returned := time.Now()
	if _, down := runHead(t, lines); down.text != "" {
		t.Errorf("the first start of a folder printed %q", down.text)
	}

	time.Sleep(1500 * time.Millisecond)
	restarted := time.Now()
	second := runStart(t, args...)
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey} {
		second.wait(t, "the first run of "+k, 0, restarted.Add(5*time.Second), runRunOf(k))
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
	svc := runStart(t, runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)...)
	failed := runPrefix("delivery slack failed " + runNotCovered + ": ")
	first, i := svc.wait(t, "the first attempt", 0, time.Now().Add(5*time.Second), failed)
	next := runNextTry(t, first.text)
	second, _ := svc.wait(t, "the second attempt", i+1, next.Add(4*time.Second), failed)
	svc.stop(t)
	slkWithin(t, "the first next try", next, first.at.Add(8*time.Second), first.at.Add(10*time.Second))
	slkWithin(t, "the second attempt", second.at, next, next.Add(3*time.Second))
	slkWithin(t, "the second next try", runNextTry(t, second.text), second.at.Add(18*time.Second), second.at.Add(20*time.Second))
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A send that hangs does not hold the stop. The stop cuts it, which is no
// attempt: the row stays as it was, so the next start sends it at once.
func TestRunStopCutsAHangingSendAndKeepsItsRow(t *testing.T) {
	s := transportStart(t, expWorld)
	// It takes connections and never answers, so a send hangs in its TLS
	// handshake.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	accepted := make(chan net.Conn, 8)
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				close(accepted)
				return
			}
			accepted <- c
		}
	}()
	t.Cleanup(func() {
		_ = ln.Close()
		for c := range accepted {
			_ = c.Close()
		}
	})
	t.Setenv("OSK_SLACK_URL", "https://"+ln.Addr().String()+"/x/"+runMarker)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	args := runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)
	first := runStart(t, args...)
	first.wait(t, "the alert", 0, time.Now().Add(5*time.Second), runIs("alert "+runNotCovered))
	select {
	case c := <-accepted:
		defer func() { _ = c.Close() }()
	case <-time.After(5 * time.Second):
		t.Fatal("no send began within 5 s of the alert")
	}
	for _, l := range first.stop(t) {
		if strings.HasPrefix(l.text, "delivery ") {
			t.Errorf("the cut send printed %q", runShow(l.text))
		}
	}

	t.Setenv("OSK_SLACK_URL", runDeadURL)
	second := runStart(t, args...)
	second.wait(t, "the attempt of the kept row", 0, time.Now().Add(3*time.Second),
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
	svc := runStartTo(t, &runOutput{strict: true, broken: true}, runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)...)
	svc.wait(t, "the first attempt", 0, time.Now().Add(5*time.Second), runPrefix("delivery slack failed "+runNotCovered+": "))
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

// An output that nobody reads holds no check: while the pipe is full the
// checks go on at their rate, and the stop does not wait for the lines.
func TestRunOutputThatNobodyReadsHoldsNoCheck(t *testing.T) {
	var queries atomic.Int64
	s := transportStart(t, func(q []byte, tcp bool) []byte {
		queries.Add(1)
		return expWorld(q, tcp)
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
	before := runtime.NumGoroutine()
	ctx, cancel := context.WithCancel(context.Background())
	errOut := &runBuffer{}
	var code int
	returned := make(chan struct{})
	go func() {
		defer close(returned)
		code = serve(ctx, runLocal(s, file, state, runIntervals("5s", "5s", "5s", "5s")...), w, errOut)
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

	time.Sleep(time.Second)
	first := queries.Load()
	time.Sleep(5500 * time.Millisecond)
	if later := queries.Load() - first; first == 0 || later == 0 {
		t.Errorf("with a full output the checks sent %d queries in the first second and %d in the 5.5 s after; want some in each", first, later)
	}
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

// A FIFO at the path of the file holds whoever opens it to read until a
// writer comes. It is a problem of the file: the checks go on, the
// invalid-file alert opens, and the stop is not held.
func TestRunFIFOAtTheFilePathHoldsNoCheck(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 100*time.Millisecond)
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(s, file, state, runIntervals("1h", "5s", "1h", "1h")...)...)
	first, _ := svc.wait(t, "the first run of the delegation", 0, time.Now().Add(5*time.Second), runRunOf(runDelegationKey))
	fifo := file + ".fifo"
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(fifo, file); err != nil {
		t.Fatal(err)
	}
	// A writer lets a reader that waits in the FIFO go, so that a service
	// held there can still stop.
	t.Cleanup(func() {
		if f, err := os.OpenFile(file, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	_, i := svc.wait(t, "the problem of the file", 0, time.Now().Add(3*time.Second), runIs("file "+file+": is not a regular file"))
	svc.wait(t, "the invalid-file alert", i, time.Now().Add(3*time.Second), runIs("alert open medium invalid-file corp.test."))
	c, _, _ := runParse(first.text)
	svc.wait(t, "a run of the delegation after the FIFO came", 0, c.start.Add(7*time.Second), runStartedAfter(runDelegationKey, c.start))
	svc.stopWithin(t, 2*time.Second)
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A FIFO as the file at the start is refused before it is opened, as osk
// check refuses it: the open would wait for a writer.
func TestRunRefusesAFIFOAsTheFileAtTheStart(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	file := expFIFO(t)
	state := filepath.Join(t.TempDir(), "state")
	code, out, errOut := expWithin(t, 2*time.Second, func() (int, string, string) {
		o, e := &runBuffer{}, &runBuffer{}
		code := serve(context.Background(), runLocal(s, file, state), o, e)
		return code, o.String(), e.String()
	})
	if want := "osk: " + file + ": is not a regular file\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, runShow(errOut), want)
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
	release := make(chan struct{})
	free := sync.OnceFunc(func() { close(release) })
	oldRead, oldStuck := readFile, readStuck
	readFile = func(path string) ([]byte, error) {
		<-release
		return readExpect(path)
	}
	readStuck = 300 * time.Millisecond
	t.Cleanup(func() { readFile, readStuck = oldRead, oldStuck })
	file := expFile(t, runFile)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(s, file, state, runIntervals("1h", "5s", "1h", "1h")...)...)
	t.Cleanup(free)
	first, _ := svc.wait(t, "the first run of the delegation", 0, time.Now().Add(5*time.Second), runRunOf(runDelegationKey))
	stuck := "file " + file + ": the read has not ended after 300ms"
	_, i := svc.wait(t, "the report of the read", 0, time.Now().Add(3*time.Second), runIs(stuck))
	_, i = svc.wait(t, "the invalid-file alert", i, time.Now().Add(3*time.Second), runIs("alert open medium invalid-file corp.test."))
	c, _, _ := runParse(first.text)
	svc.wait(t, "a run of the delegation while the read hangs", 0, c.start.Add(7*time.Second), runStartedAfter(runDelegationKey, c.start))
	free()
	svc.wait(t, "the resolve once the read ended", i, time.Now().Add(3*time.Second), runIs("alert resolve medium invalid-file corp.test."))
	lines := svc.stopWithin(t, 2*time.Second)
	reports := 0
	for _, l := range lines {
		if l.text == stuck {
			reports++
		}
	}
	if reports != 1 {
		t.Errorf("the read that hung was reported %d times, want once", reports)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A file is taken only when two reads in a row give the same octets, so a
// file read while it is written, in part or empty, changes nothing; a real
// change is taken one read later.
func TestRunTakesAChangedFileOnlyWhenTwoReadsAgree(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", runDeadURL)
	runReadEvery(t, 50*time.Millisecond)
	v1 := runFile + "www.example. A 192.0.2.80\n"
	v2 := runFile + "www.example. A 192.0.2.99\n"
	script := []string{
		v1[:len(v1)-2], // cut inside the address
		v1, v1,
		runFile, // cut at the end of a line: a check is gone
		v1, v1,
		"", // as a command that writes the file leaves it while it runs
		v1, v1,
		v2, v2,
	}
	var mu sync.Mutex
	reads := 0
	old := readFile
	readFile = func(string) ([]byte, error) {
		mu.Lock()
		defer mu.Unlock()
		text := script[min(reads, len(script)-1)]
		reads++
		return []byte(text), nil
	}
	t.Cleanup(func() { readFile = old })
	file := expFile(t, v1)
	state := filepath.Join(t.TempDir(), "state")
	svc := runStart(t, runLocal(s, file, state, runIntervals("1h", "1h", "1h", "1h")...)...)
	keys := []string{runSerialKey, runDelegationKey, runDSKey, "records corp.test. www.example. A"}
	for _, k := range keys {
		svc.wait(t, "the first run of "+k, 0, time.Now().Add(5*time.Second), runRunOf(k))
	}
	changed := "file " + file + " changed: 4 checks"
	at, i := svc.wait(t, "the change to the second file", 0, time.Now().Add(5*time.Second), runIs(changed))
	svc.wait(t, "the record-set alert of the second file", i, time.Now().Add(3*time.Second),
		runIs("alert open high record-set records www.example. A"))
	lines := svc.stop(t)
	mu.Lock()
	n := reads
	mu.Unlock()
	if n < len(script) {
		t.Errorf("the service read the file %d times, want at least %d", n, len(script))
	}
	var alerts, files []string
	before := map[string]int{}
	for _, l := range lines {
		switch {
		case strings.HasPrefix(l.text, "alert "):
			alerts = append(alerts, l.text)
		case strings.HasPrefix(l.text, "file "):
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

// The logger never waits for its output: a line that finds no room is
// dropped, and the next line that finds room is preceded by the count.
func TestRunLoggerDropsLinesWithoutWaitingAndCountsThem(t *testing.T) {
	out := &runGated{started: make(chan struct{}, 100), release: make(chan struct{})}
	l := newLogger(out, 4)
	l.print("line 1")
	<-out.started
	// Lines 2 to 5 fill the queue; 6 to 8 find no room.
	for i := 2; i <= 8; i++ {
		l.print("line " + strconv.Itoa(i))
	}
	close(out.release)
	for deadline := time.Now().Add(2 * time.Second); len(out.all()) < 5; time.Sleep(10 * time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatalf("the output got %q, want 5 lines", out.all())
		}
	}
	l.print("line 9")
	l.close(time.Second)
	want := []string{"line 1", "line 2", "line 3", "line 4", "line 5", "dropped 3 lines: the output was not read", "line 9"}
	if got := out.all(); !slices.Equal(got, want) {
		t.Errorf("the output got\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}
