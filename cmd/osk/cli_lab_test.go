//go:build lab

package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/cli"
)

// cliLabWorld is the config of a test of the reading commands, written in
// a folder of the test: one domain, corp.test., Slack and, unless left out,
// the webhook siem. Each secret ends in a marker of its own.
type cliLabWorld struct {
	n                            string // "10.53.<LAB_ID>."
	dir, config, state, expect   string
	slackPath, hookPath          string // the paths of the receiver, with the markers
	slackMark, hookMark, keyMark string
}

// cliLabFile is the expectations file of corp.test. as the lab serves it;
// the lines given come before the line of www.
func cliLabFile(n string, before ...string) string {
	lines := slices.Concat([]string{"domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none"},
		before, []string{"www.corp.test. A " + n + "81"})
	return strings.Join(lines, "\n") + "\n"
}

func cliLabMarker(t *testing.T) string {
	t.Helper()
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "m" + hex.EncodeToString(b)
}

// cliLabSetup starts a test with an empty receiver, the lab reset at its
// end, and the config in a new folder. intervals overrides the 1h of the
// tiers it names.
func cliLabSetup(t *testing.T, siem bool, file func(n string) string, intervals map[string]string) *cliLabWorld {
	t.Helper()
	n := expLab(t)
	expCtl(t, "hooks", "clear")
	dir := t.TempDir()
	w := &cliLabWorld{n: n, dir: dir, config: filepath.Join(dir, "osk.json"), state: filepath.Join(dir, "state"),
		expect:    filepath.Join(dir, "corp.test.expect"),
		slackMark: cliLabMarker(t), hookMark: cliLabMarker(t), keyMark: cliLabMarker(t)}
	w.slackPath = "/slack/T0/B0/" + w.slackMark
	w.hookPath = "/hook/" + w.hookMark
	t.Setenv("OSK_SLACK_URL", "https://hooks.lab.test"+w.slackPath)
	expWrite(t, dir, "siem-url", "https://hooks.lab.test"+w.hookPath+"\n")
	expWrite(t, dir, "siem-key", w.keyMark+strings.Repeat("k", 40-len(w.keyMark)))
	if file == nil {
		file = func(n string) string { return cliLabFile(n) }
	}
	expWrite(t, dir, "corp.test.expect", file(n))
	iv := map[string]string{"serial": "1h", "parent": "1h", "fast": "1h", "other": "1h"}
	for k, v := range intervals {
		iv[k] = v
	}
	webhooks := ""
	if siem {
		webhooks = `,
  "webhooks": [{"name": "siem", "url": {"file": "` + dir + `/siem-url"}, "key": {"file": "` + dir + `/siem-key"}}]`
	}
	expWrite(t, dir, "osk.json", `{
  "state": "`+w.state+`",
  "domains": [{"name": "corp.test.", "expect": "`+w.expect+`", "fast": ["www.corp.test."]}],
  "intervals": {"serial": "`+iv["serial"]+`", "parent": "`+iv["parent"]+`", "fast": "`+iv["fast"]+`", "other": "`+iv["other"]+`"},
  "network": {"root_servers": ["`+n+`2"], "extra_ranges": ["`+n+`0/24"]},
  "slack": {"url": {"env": "OSK_SLACK_URL"}}`+webhooks+`
}
`)
	return w
}

// cliLabWarnings are the two lines that every command that prints the
// warnings prints for the network of the config.
func cliLabWarnings(n string) []string {
	return []string{
		"warning network.root_servers is set: osk starts its walk at " + n + "2:53 instead of the root servers of the internet," +
			" so these servers decide every answer. Use it only in a lab or a private network.",
		"warning network.extra_ranges is set: data from DNS can now make osk send queries and HTTPS requests for MTA-STS policy files to " +
			n + "0/24. Use it only in a lab or a private network.",
	}
}

// cliLabNoMarker fails when an output holds a secret of the config.
func cliLabNoMarker(t *testing.T, w *cliLabWorld, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, m := range []string{w.slackMark, w.hookMark, w.keyMark} {
			if strings.Contains(o, m) {
				t.Errorf("an output holds a secret marker:\n%s", strings.ReplaceAll(o, m, "[marker]"))
			}
		}
	}
}

// cliLabCode is the value of accept --write for the change of alert id in
// file from the line old to line: the first 32 hex digits of the SHA-256 of
// the four, with "--" before line, each followed by LF.
func cliLabCode(id, file, old, line string) string {
	sum := sha256.Sum256([]byte(id + "\n" + file + "\n" + old + "\n--\n" + line + "\n"))
	return hex.EncodeToString(sum[:])[:32]
}

// cliLabOsk runs an osk command in this process. The service, when one
// runs, is a child process: a store and a reader of one folder must never
// be open in one process.
func cliLabOsk(args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	code = run(args, &out, &errOut)
	return code, out.String(), errOut.String()
}

// cliLabLog is one line that osk run logs.
type cliLabLog struct {
	Time   string `json:"time"`
	Level  string `json:"level"`
	Event  string `json:"event"`
	Domain string `json:"domain"`
	Text   string `json:"text"`
	at     time.Time
}

// cliLabService is osk run in a child process: the test binary again,
// through TestRunChild, which runs the arguments of OSK_RUN_CHILD.
type cliLabService struct {
	cmd    *exec.Cmd
	mu     sync.Mutex
	logs   []cliLabLog
	raw    []string
	errOut bytes.Buffer
	done   chan struct{}
}

func cliLabStart(t *testing.T, w *cliLabWorld) *cliLabService {
	t.Helper()
	s := &cliLabService{done: make(chan struct{})}
	s.cmd = exec.Command(os.Args[0], "-test.run=^TestRunChild$")
	s.cmd.Env = append(os.Environ(), "OSK_RUN_CHILD="+strings.Join([]string{"run", "--config", w.config}, "\n"))
	out, err := s.cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	s.cmd.Stderr = &s.errOut
	if err := s.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			var l cliLabLog
			err := json.Unmarshal(sc.Bytes(), &l)
			if err == nil {
				l.at, err = time.Parse("2006-01-02T15:04:05.000Z", l.Time)
			}
			s.mu.Lock()
			s.raw = append(s.raw, sc.Text())
			if err == nil {
				s.logs = append(s.logs, l)
			}
			s.mu.Unlock()
		}
		_ = s.cmd.Wait() // the exit code is read from ProcessState
		close(s.done)
	}()
	t.Cleanup(func() {
		select {
		case <-s.done:
		default:
			_ = s.cmd.Process.Signal(os.Interrupt) // a test that failed early left it running
			select {
			case <-s.done:
			case <-time.After(15 * time.Second):
				_ = s.cmd.Process.Kill() // it did not stop; the test fails below
				t.Error("osk run did not stop on SIGINT")
			}
		}
		if t.Failed() {
			t.Logf("log of osk run:\n%s\nerrors:\n%s", strings.Join(s.lines(), "\n"), s.errOut.String())
		}
	})
	s.wait(t, "the start line of osk run", time.Now().Add(20*time.Second), func(l cliLabLog) bool { return l.Event == "start" })
	return s
}

func (s *cliLabService) lines() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.raw)
}

func (s *cliLabService) all() []cliLabLog {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.logs)
}

// wait gives the first log line that match accepts, waiting for it until
// deadline.
func (s *cliLabService) wait(t *testing.T, what string, deadline time.Time, match func(cliLabLog) bool) cliLabLog {
	t.Helper()
	for {
		for _, l := range s.all() {
			if match(l) {
				return l
			}
		}
		select {
		case <-s.done:
			t.Fatalf("osk run ended before %s:\n%s\nerrors:\n%s", what, strings.Join(s.lines(), "\n"), s.errOut.String())
		default:
		}
		if time.Now().After(deadline) {
			t.Fatalf("no %s by %s", what, deadline.UTC().Format(time.TimeOnly))
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// stop sends SIGINT and waits for the clean stop.
func (s *cliLabService) stop(t *testing.T) {
	t.Helper()
	if err := s.cmd.Process.Signal(os.Interrupt); err != nil {
		t.Fatal(err)
	}
	select {
	case <-s.done:
	case <-time.After(15 * time.Second):
		t.Fatal("osk run did not stop within 15s of SIGINT")
	}
	if code := s.cmd.ProcessState.ExitCode(); code != 0 || s.errOut.Len() != 0 {
		t.Errorf("osk run stopped with exit code %d, errors %q; want 0 and none", code, s.errOut.String())
	}
}

// cliLabUntil runs try until it gives true, at most until deadline.
func cliLabUntil(t *testing.T, what string, deadline time.Time, every time.Duration, try func() bool) {
	t.Helper()
	for !try() {
		if time.Now().After(deadline) {
			t.Fatalf("no %s by %s", what, deadline.UTC().Format(time.TimeOnly))
		}
		time.Sleep(every)
	}
}

func cliLabSplit(out string) []string {
	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// cliLabStatus runs status as text and as JSON, and checks that the JSON
// says healthy exactly when its exit code is 0.
func cliLabStatus(t *testing.T, w *cliLabWorld) (code int, lines []string) {
	t.Helper()
	code, out, errOut := cliLabOsk("status", "--config", w.config)
	if errOut != "" {
		t.Errorf("osk status: errors %q, want none", errOut)
	}
	jsCode, js, errOut := cliLabOsk("status", "--config", w.config, "--json")
	var st struct {
		Healthy *bool `json:"healthy"`
	}
	if err := json.Unmarshal([]byte(js), &st); err != nil || st.Healthy == nil || *st.Healthy != (jsCode == 0) || errOut != "" {
		t.Errorf("osk status --json: exit code %d, errors %q, output %s; want healthy exactly when the exit code is 0", jsCode, errOut, js)
	}
	return code, cliLabSplit(out)
}

var cliLabBeat = regexp.MustCompile(`^beat (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC)$`)

// cliLabTime reads a time that the commands print to the second, and checks
// that it lies from the second of from to to.
func cliLabTime(t *testing.T, what, layout, s string, from, to time.Time) time.Time {
	t.Helper()
	at, err := time.Parse(layout, s)
	if err != nil {
		t.Errorf("%s: %v", what, err)
		return at
	}
	if at.Before(from.Truncate(time.Second)) || at.After(to) {
		t.Errorf("%s is %s, want a time from %s to %s", what, at.UTC(), from.UTC(), to.UTC())
	}
	return at
}

// status gives exit 0 while the service runs and delivers; 1 while a
// channel fails, and 0 again once the retry is sent; 1 once the beat of a
// stopped service is older than 30 s.
func TestStatusExitCodes(t *testing.T) {
	w := cliLabSetup(t, false, nil, map[string]string{"fast": "5s"})
	started := time.Now()
	svc := cliLabStart(t, w)

	var code int
	var lines []string
	cliLabUntil(t, "healthy status", time.Now().Add(12*time.Second), 200*time.Millisecond, func() bool {
		code, lines = cliLabStatus(t, w)
		return code == 0
	})
	if len(lines) != 5 || lines[0] != "healthy" || !cliLabBeat.MatchString(lines[1]) || lines[2] != "channel slack ok, 0 pending" ||
		!slices.Equal(lines[3:], cliLabWarnings(w.n)) {
		t.Errorf("osk status of a healthy service:\n%s\nwant healthy, the beat, channel slack ok, 0 pending and the warnings", strings.Join(lines, "\n"))
	} else {
		cliLabTime(t, "the beat", "2006-01-02 15:04:05 UTC", cliLabBeat.FindStringSubmatch(lines[1])[1], started, time.Now())
	}

	expCtl(t, "hooks", "reply", "503", "1")
	set := time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", w.n+"99")
	cliLabUntil(t, "status with a failing channel", set.Add(12*time.Second), 200*time.Millisecond, func() bool {
		code, lines = cliLabStatus(t, w)
		return code == 1
	})
	failed := time.Now()
	open := regexp.MustCompile(`^open \d+ high record-set records www\.corp\.test\. A since (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC)$`)
	if len(lines) != 6 || lines[0] != "unhealthy: channel slack fails" || !cliLabBeat.MatchString(lines[1]) ||
		!strings.HasPrefix(lines[2], "channel slack fails, 1 pending, last reason status 503") || !open.MatchString(lines[3]) ||
		!slices.Equal(lines[4:], cliLabWarnings(w.n)) {
		t.Errorf("osk status with a failing channel:\n%s\nwant unhealthy: channel slack fails, the beat, the channel with status 503, the open alert and the warnings",
			strings.Join(lines, "\n"))
	} else {
		cliLabTime(t, "the open time", "2006-01-02 15:04:05 UTC", open.FindStringSubmatch(lines[3])[1], set, failed)
	}

	// The retry comes 10 s after the failed attempt.
	cliLabUntil(t, "healthy status after the retry", failed.Add(15*time.Second), 200*time.Millisecond, func() bool {
		code, lines = cliLabStatus(t, w)
		return code == 0
	})
	if len(lines) != 6 || lines[0] != "healthy" || lines[2] != "channel slack ok, 0 pending" || !open.MatchString(lines[3]) {
		t.Errorf("osk status after the retry:\n%s\nwant healthy, channel slack ok, 0 pending and the open alert", strings.Join(lines, "\n"))
	}

	signal := time.Now()
	svc.stop(t)
	stopped := time.Now()
	problem := regexp.MustCompile(`^unhealthy: no beat from osk run since (\d{4}-\d\d-\d\d \d\d:\d\d:\d\d UTC)$`)
	cliLabUntil(t, "status without a beat", stopped.Add(31*time.Second), 500*time.Millisecond, func() bool {
		code, lines = cliLabStatus(t, w)
		return code == 1
	})
	seen := time.Now()
	if !problem.MatchString(lines[0]) {
		t.Fatalf("osk status after the stop:\n%s\nwant unhealthy: no beat from osk run since <the stop>", strings.Join(lines, "\n"))
	}
	beat := cliLabTime(t, "the last beat", "2006-01-02 15:04:05 UTC", problem.FindStringSubmatch(lines[0])[1], signal, stopped)
	// The beat is cut to the second, so it may lie up to 1 s before the
	// true one; status may not give up on it before 30 s.
	if seen.Before(beat.Add(30 * time.Second)) {
		t.Errorf("status gave up the beat of %s at %s, before 30s", beat.UTC(), seen.UTC())
	}
}

// cliLabBuffer is an output that a command writes while the test reads it.
type cliLabBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *cliLabBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *cliLabBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// cliLabWatch runs watch in this process until cancel; code and err may be
// read once done is closed.
type cliLabWatch struct {
	out    cliLabBuffer
	err    bytes.Buffer
	code   int
	done   chan struct{}
	cancel context.CancelFunc
}

func cliLabStartWatch(t *testing.T, ctx context.Context, w *cliLabWorld, args ...string) *cliLabWatch {
	ctx, cancel := context.WithCancel(ctx)
	r := &cliLabWatch{done: make(chan struct{}), cancel: cancel}
	go func() {
		r.code = cli.Watch(ctx, append([]string{"--config", w.config}, args...), &r.out, &r.err)
		close(r.done)
	}()
	t.Cleanup(func() {
		cancel()
		<-r.done
	})
	return r
}

// end cancels watch and checks that it ends with exit 0 within 2 s.
func (r *cliLabWatch) end(t *testing.T) {
	t.Helper()
	r.cancel()
	select {
	case <-r.done:
		if r.code != 0 || r.err.Len() != 0 {
			t.Errorf("watch: exit code %d, errors %q; want 0 and none", r.code, r.err.String())
		}
	case <-time.After(2 * time.Second):
		t.Fatal("watch did not end within 2s of the end of its context")
	}
}

// cliLabHook is one request that the receiver stored.
type cliLabHook struct {
	Time    string              `json:"time"`
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Status  int                 `json:"status"`
}

func cliLabHooks(t *testing.T) []cliLabHook {
	t.Helper()
	var hooks []cliLabHook
	for _, line := range slkHooks(t) {
		var h cliLabHook
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			t.Fatalf("hooks list: %v", err)
		}
		hooks = append(hooks, h)
	}
	return hooks
}

// cliLabSlackTexts gives the text of each Slack message the receiver holds.
func cliLabSlackTexts(t *testing.T, w *cliLabWorld) []string {
	t.Helper()
	var texts []string
	for _, h := range cliLabHooks(t) {
		var body struct {
			Text string `json:"text"`
		}
		if h.Path == w.slackPath && json.Unmarshal([]byte(h.Body), &body) == nil {
			texts = append(texts, body.Text)
		}
	}
	return texts
}

var cliLabRequest = regexp.MustCompile(`^  request   ([0-9a-f]{32})$`)

// watch prints the alert of a change within the time of one parent run,
// and the notice of a test, and nothing of what came before it started.
func TestWatchShowsEventsAsTheyHappen(t *testing.T) {
	w := cliLabSetup(t, true, nil, map[string]string{"parent": "5s"})
	cliLabStart(t, w)
	if code, out, errOut := cliLabOsk("test-alert", "--config", w.config); code != 0 || out != "test slack sent\ntest siem sent\n" {
		t.Fatalf("test-alert before watch: exit code %d, output %q, errors %q; want 0 and both channels sent", code, out, errOut)
	}

	watch := cliLabStartWatch(t, context.Background(), w)
	set := time.Now()
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	opened := regexp.MustCompile(`^(\S+) alert \d+ open critical nameservers delegation corp\.test\. NS$`)
	var lines []string
	cliLabUntil(t, "the alert in watch", set.Add(5*time.Second+3750*time.Millisecond+2*time.Second), 20*time.Millisecond, func() bool {
		lines = cliLabSplit(watch.out.String())
		return slices.ContainsFunc(lines, opened.MatchString)
	})
	if len(lines) != 1 {
		t.Fatalf("watch printed:\n%s\nwant only the line of the alert", strings.Join(lines, "\n"))
	}
	cliLabTime(t, "the time of the alert", "2006-01-02T15:04:05Z", opened.FindStringSubmatch(lines[0])[1], set, time.Now())

	asked := time.Now()
	if code, out, errOut := cliLabOsk("test-alert", "--config", w.config); code != 0 || out != "test slack sent\ntest siem sent\n" {
		t.Fatalf("test-alert: exit code %d, output %q, errors %q; want 0 and both channels sent", code, out, errOut)
	}
	cliLabUntil(t, "the test notice in watch", time.Now().Add(2*time.Second), 20*time.Millisecond, func() bool {
		lines = cliLabSplit(watch.out.String())
		return len(lines) >= 3
	})
	watch.end(t)
	lines = cliLabSplit(watch.out.String())
	head := regexp.MustCompile(`^(\S+) notice test -$`)
	if len(lines) != 3 || !head.MatchString(lines[1]) || !cliLabRequest.MatchString(lines[2]) {
		t.Fatalf("watch printed:\n%s\nwant the alert, <time> notice test - and its request line", strings.Join(lines, "\n"))
	}
	cliLabTime(t, "the time of the notice", "2006-01-02T15:04:05Z", head.FindStringSubmatch(lines[1])[1], asked, time.Now())
	nonce := cliLabRequest.FindStringSubmatch(lines[2])[1]
	if !slices.ContainsFunc(cliLabSlackTexts(t, w), func(s string) bool { return strings.Contains(s, "request    "+nonce) }) {
		t.Errorf("no Slack message holds the request %s that watch printed", nonce)
	}
}

// For 20 s the reading commands run as often as a person could start them,
// while the service checks every 5 s: its checks keep their pace, it
// alerts and delivers, every status returns within 1 s, and nothing waits
// for a lock or for standard input.
func TestReadersNeverBlockService(t *testing.T) {
	w := cliLabSetup(t, true, nil, map[string]string{"parent": "5s", "fast": "5s"})
	svc := cliLabStart(t, w)
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin := os.Stdin
	os.Stdin = read
	t.Cleanup(func() {
		os.Stdin = stdin
		_ = write.Close() // only a reader of standard input could notice
		_ = read.Close()
	})

	expCtl(t, "set", "both", "www.corp.test.", "300", "A", w.n+"99")
	start := time.Now()
	end := start.Add(20 * time.Second)
	ctx, cancel := context.WithDeadline(context.Background(), end)
	defer cancel()
	watch := cliLabStartWatch(t, ctx, w)

	type call struct {
		args        []string
		code        int
		out, errOut string
		took        time.Duration
	}
	var mu sync.Mutex
	var calls []call
	var id string
	openID := regexp.MustCompile(`(?m)^open (\d+) high record-set records www\.corp\.test\. A since `)
	loop := func(every time.Duration, args func() []string, done chan<- struct{}) {
		defer close(done)
		for time.Now().Before(end) {
			if a := args(); a != nil {
				began := time.Now()
				code, out, errOut := cliLabOsk(a...)
				c := call{a, code, out, errOut, time.Since(began)}
				mu.Lock()
				calls = append(calls, c)
				if m := openID.FindStringSubmatch(out); m != nil && a[0] == "status" {
					id = m[1]
				}
				mu.Unlock()
			}
			time.Sleep(every)
		}
	}
	statusDone, acceptDone := make(chan struct{}), make(chan struct{})
	go loop(200*time.Millisecond, func() []string { return []string{"status", "--config", w.config} }, statusDone)
	go loop(500*time.Millisecond, func() []string {
		mu.Lock()
		defer mu.Unlock()
		if id == "" {
			return nil
		}
		return []string{"accept", "--config", w.config, id}
	}, acceptDone)
	for _, done := range []chan struct{}{statusDone, acceptDone} {
		select {
		case <-done:
		case <-time.After(time.Until(end) + 10*time.Second):
			t.Fatal("a reading command did not return")
		}
	}
	select {
	case <-watch.done:
	case <-time.After(time.Until(end) + 2*time.Second):
		t.Fatal("watch did not end within 2s of the end of its context")
	}
	if watch.code != 0 || watch.err.Len() != 0 {
		t.Errorf("watch: exit code %d, errors %q; want 0 and none", watch.code, watch.err.String())
	}

	accepted := []string{w.expect + ":4", "- www.corp.test. A " + w.n + "81", "+ www.corp.test. A " + w.n + "99",
		"To write this change: osk accept --config " + w.config + " --write " +
			cliLabCode(id, w.expect, "www.corp.test. A "+w.n+"81", "www.corp.test. A "+w.n+"99") + " " + id}
	statuses, accepts := 0, 0
	for _, c := range calls {
		switch c.args[0] {
		case "status":
			statuses++
			if c.took > time.Second || c.errOut != "" {
				t.Errorf("osk status took %v, errors %q; want at most 1s and none", c.took, c.errOut)
			}
		case "accept":
			accepts++
			if c.code != 0 || c.errOut != "" || c.out != strings.Join(accepted, "\n")+"\n" {
				t.Errorf("osk accept %s: exit code %d, errors %q, output:\n%s\nwant 0, none and:\n%s", c.args[3], c.code, c.errOut, c.out, strings.Join(accepted, "\n"))
			}
		}
		for _, o := range []string{c.out, c.errOut} {
			if l := strings.ToLower(o); strings.Contains(l, "locked") || strings.Contains(l, "busy") {
				t.Errorf("osk %s printed:\n%s", c.args[0], o)
			}
		}
	}
	if statuses < 40 || accepts < 10 {
		t.Errorf("%d status and %d accept commands ran in 20s; want status every 200 ms and accept every 500 ms once the alert is open",
			statuses, accepts)
	}
	if !strings.Contains(watch.out.String(), " open high record-set records www.corp.test. A\n") {
		t.Errorf("watch printed:\n%s\nwant the alert of www", watch.out.String())
	}

	// From the start of the 20 s to their end, no 6 s pass without a judged
	// run of the delegation check.
	var checked []time.Time
	for _, l := range svc.all() {
		if l.Event == "checked" && strings.HasPrefix(l.Text, "checked parent delegation corp.test. corp.test. NS ") &&
			l.at.After(start) && l.at.Before(end) {
			checked = append(checked, l.at)
		}
	}
	last := start
	for _, at := range append(checked, end) {
		if at.Sub(last) >= 6*time.Second {
			t.Errorf("osk run judged no parent delegation check from %s to %s", last.UTC(), at.UTC())
		}
		last = at
	}
	for _, want := range []string{"alert open high record-set records www.corp.test. A", "delivery slack sent open high record-set records www.corp.test. A"} {
		if !slices.ContainsFunc(svc.all(), func(l cliLabLog) bool { return l.Text == want && !l.at.After(end) }) {
			t.Errorf("osk run did not log %q within the 20s", want)
		}
	}
	for _, l := range svc.lines() {
		if s := strings.ToLower(l); strings.Contains(s, "locked") || strings.Contains(s, "busy") {
			t.Errorf("osk run logged %s", l)
		}
	}
}

// cliLabKinds are the keys of each type of JSON line, in order: "" is the
// line itself, "seen[]" each item of the list seen, "open[].check" the
// object check of each item of the list open. The values are the structs
// that a line of the type decodes into with no key left over.
var cliLabKinds = map[string]struct {
	keys map[string][]string
	into func() any
}{
	"version": {map[string][]string{"": {"type", "osk", "go", "sqlite"}}, func() any {
		return &struct {
			Type, Osk, Go, Sqlite string
		}{}
	}},
	"header": {map[string][]string{"": {"type", "opcode", "status", "id", "flags"}}, func() any {
		return &struct {
			Type, Opcode, Status string
			ID                   int
			Flags                []string
		}{}
	}},
	"counts": {map[string][]string{"": {"type", "query", "answer", "authority", "additional"}}, func() any {
		return &struct {
			Type                                 string
			Query, Answer, Authority, Additional int
		}{}
	}},
	"edns": {map[string][]string{"": {"type", "version", "flags", "udp", "cookie"}}, func() any {
		return &struct {
			Type    string
			Version int
			Flags   []string
			UDP     int
			Cookie  string
		}{}
	}},
	"ede": {map[string][]string{"": {"type", "code", "text"}}, func() any {
		return &struct {
			Type string
			Code int
			Text string
		}{}
	}},
	"record": {map[string][]string{"": {"type", "section", "text"}}, func() any {
		return &struct{ Type, Section, Text string }{}
	}},
	"walk":    {map[string][]string{"": cliLabAnswerKeys}, cliLabAnswer},
	"answer":  {map[string][]string{"": cliLabAnswerKeys}, cliLabAnswer},
	"unknown": {map[string][]string{"": cliLabAnswerKeys}, cliLabAnswer},
	"finding": {map[string][]string{"": {"type", "severity", "rule", "kind", "name", "rtype", "expected", "seen"},
		"seen[]": {"address", "host", "text"}}, func() any {
		return &struct {
			Type, Severity, Rule, Kind, Name, RType, Expected string
			Seen                                              []struct{ Address, Host, Text string }
		}{}
	}},
	"checked": {map[string][]string{"": {"type", "domain", "sets", "findings", "unknown"}}, func() any {
		return &struct {
			Type                    string
			Domain                  string
			Sets, Findings, Unknown int
		}{}
	}},
	"line": {map[string][]string{"": {"type", "text"}}, func() any { return &struct{ Type, Text string }{} }},
	"skip": {map[string][]string{"": {"type", "name", "rtype", "why"}}, func() any {
		return &struct{ Type, Name, RType, Why string }{}
	}},
	"nsnoanswer": {map[string][]string{"": {"type", "servers"}}, func() any {
		return &struct {
			Type    string
			Servers []string
		}{}
	}},
	"nsset": {map[string][]string{"": {"type", "text", "parent", "zone"}}, func() any {
		return &struct {
			Type, Text   string
			Parent, Zone []string
		}{}
	}},
	"problem": {map[string][]string{"": {"type", "file", "line", "path", "text"}}, func() any {
		return &struct {
			Type, File string
			Line       int
			Path, Text string
		}{}
	}},
	"warning": {map[string][]string{"": {"type", "text"}}, func() any { return &struct{ Type, Text string }{} }},
	"result": {map[string][]string{"": {"type", "valid", "problems", "domains", "channels"}}, func() any {
		return &struct {
			Type              string
			Valid             bool
			Problems, Domains int
			Channels          []string
		}{}
	}},
	"status": {map[string][]string{
		"":             {"type", "healthy", "problems", "beat", "late", "channels", "open", "warnings"},
		"channels[]":   {"name", "pending", "failing", "reason"},
		"open[]":       {"id", "severity", "rule", "check", "opened"},
		"open[].check": {"kind", "domain", "name", "rtype"},
	}, func() any {
		return &struct {
			Type     string
			Healthy  bool
			Problems []string
			Beat     string
			Late     []string
			Channels []struct {
				Name    string
				Pending int
				Failing bool
				Reason  string
			}
			Open []struct {
				ID             int64
				Severity, Rule string
				Check          struct{ Kind, Domain, Name, RType string }
				Opened         string
			}
			Warnings []string
		}{}
	}},
	"event": {map[string][]string{
		"":      {"type", "id", "alert", "kind", "severity", "was", "rule", "check", "value", "at"},
		"check": {"kind", "domain", "name", "rtype"},
	}, func() any {
		return &struct {
			Type                      string
			ID, Alert                 int64
			Kind, Severity, Was, Rule string
			Check                     struct{ Kind, Domain, Name, RType string }
			Value, At                 string
		}{}
	}},
	"notice": {map[string][]string{"": {"type", "id", "kind", "domain", "lines", "at"}}, func() any {
		return &struct {
			Type         string
			ID           int64
			Kind, Domain string
			Lines        []string
			At           string
		}{}
	}},
	"change": {map[string][]string{"": {"type", "file", "line", "old", "new", "written", "code"}}, func() any {
		return &struct {
			Type, File string
			Line       int
			Old, New   string
			Written    bool
			Code       string
		}{}
	}},
	"attempt": {map[string][]string{"": {"type", "channel", "state", "reason", "next"}}, func() any {
		return &struct{ Type, Channel, State, Reason, Next string }{}
	}},
}

var cliLabAnswerKeys = []string{"type", "kind", "qname", "qtype", "address", "host", "received", "transport", "case", "data"}

func cliLabAnswer() any {
	return &struct{ Type, Kind, QName, QType, Address, Host, Received, Transport, Case, Data string }{}
}

// cliLabKeys walks the tokens of one JSON value and checks the keys of each
// object against want, by the path of the object.
func cliLabKeys(dec *json.Decoder, path string, want map[string][]string) error {
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	switch tok {
	case json.Delim('{'):
		var keys []string
		for dec.More() {
			k, err := dec.Token()
			if err != nil {
				return err
			}
			key, _ := k.(string)
			keys = append(keys, key)
			sub := key
			if path != "" {
				sub = path + "." + key
			}
			if err := cliLabKeys(dec, sub, want); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
		if wk, ok := want[path]; !ok || !slices.Equal(keys, wk) {
			return fmt.Errorf("the object %q has the keys %q, want %q", path, keys, wk)
		}
	case json.Delim('['):
		for dec.More() {
			if err := cliLabKeys(dec, path+"[]", want); err != nil {
				return err
			}
		}
		if _, err := dec.Token(); err != nil {
			return err
		}
	}
	return nil
}

// cliLabJSON checks every line of out: one object of a type that the
// command may print, with exactly the keys of that type in their order, of
// the types of its struct. It gives the lines by type.
func cliLabJSON(t *testing.T, what, out string, types ...string) map[string][]string {
	t.Helper()
	byType := map[string][]string{}
	if out == "" {
		t.Errorf("%s printed nothing", what)
		return byType
	}
	for _, line := range cliLabSplit(out) {
		var head struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal([]byte(line), &head); err != nil || !slices.Contains(types, head.Type) {
			t.Errorf("%s printed %s; want an object whose type is one of %q", what, line, types)
			continue
		}
		kind := cliLabKinds[head.Type]
		dec := json.NewDecoder(strings.NewReader(line))
		if err := cliLabKeys(dec, "", kind.keys); err != nil {
			t.Errorf("%s: %s: %v", what, line, err)
		} else if _, err := dec.Token(); err != io.EOF {
			t.Errorf("%s: %s: more than one value in the line", what, line)
		}
		dec = json.NewDecoder(strings.NewReader(line))
		dec.DisallowUnknownFields()
		if err := dec.Decode(kind.into()); err != nil {
			t.Errorf("%s: %s: %v", what, line, err)
		}
		byType[head.Type] = append(byType[head.Type], line)
	}
	return byType
}

// cliLabNeed fails when a type that the command must print is missing.
func cliLabNeed(t *testing.T, what string, byType map[string][]string, types ...string) {
	t.Helper()
	for _, k := range types {
		if len(byType[k]) == 0 {
			t.Errorf("%s printed no line of type %s", what, k)
		}
	}
}

// Every command that prints data prints JSON Lines with --json: each line
// an object whose type comes first, with the keys of that type in order.
func TestEveryCommandPrintsJSON(t *testing.T) {
	w := cliLabSetup(t, true, nil, map[string]string{"fast": "5s"})
	n := w.n
	net := []string{"--root-server", n + "2", "--extra-range", n + "0/24"}
	osk := func(code int, args ...string) string {
		t.Helper()
		got, out, errOut := cliLabOsk(args...)
		if got != code || errOut != "" {
			t.Errorf("osk %s: exit code %d, errors %q; want %d and none", strings.Join(args, " "), got, errOut, code)
		}
		cliLabNoMarker(t, w, out, errOut)
		return out
	}

	cliLabNeed(t, "version", cliLabJSON(t, "version", osk(0, "version", "--json"), "version"), "version")
	cliLabNeed(t, "query", cliLabJSON(t, "query", osk(0, "query", "--json", "@"+n+"11", "corp.test.", "SOA"),
		"header", "counts", "edns", "ede", "record"), "header", "counts", "record")
	cliLabNeed(t, "check", cliLabJSON(t, "check", osk(0, slices.Concat([]string{"check", "--json"}, net, []string{"corp.test."})...),
		"walk", "answer"), "walk", "answer")
	cliLabNeed(t, "snapshot", cliLabJSON(t, "snapshot", osk(0, slices.Concat([]string{"snapshot", "--json"}, net,
		[]string{"corp.test.", "www.corp.test.", "A"})...), "line", "skip", "nsnoanswer", "nsset"), "line")
	result := cliLabJSON(t, "validate", osk(0, "validate", "--config", w.config, "--json"), "problem", "warning", "result")
	cliLabNeed(t, "validate", result, "warning", "result")

	svc := cliLabStart(t, w)
	set := time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	svc.wait(t, "the alert of www", set.Add(12*time.Second), func(l cliLabLog) bool {
		return l.Text == "alert open high record-set records www.corp.test. A"
	})
	found := cliLabJSON(t, "check --expect", osk(1, slices.Concat([]string{"check", "--json"}, net, []string{"--expect", w.expect})...),
		"finding", "unknown", "checked")
	cliLabNeed(t, "check --expect", found, "finding", "checked")

	status := cliLabJSON(t, "status", osk(0, "status", "--config", w.config, "--json"), "status")
	cliLabNeed(t, "status", status, "status")
	var st struct {
		Open []struct {
			ID int64 `json:"id"`
		} `json:"open"`
	}
	if len(status["status"]) != 1 || json.Unmarshal([]byte(status["status"][0]), &st) != nil || len(st.Open) != 1 {
		t.Fatalf("status --json gave %q; want one line with one open alert", status["status"])
	}
	id := strconv.FormatInt(st.Open[0].ID, 10)
	cliLabNeed(t, "accept", cliLabJSON(t, "accept", osk(0, "accept", "--config", w.config, "--json", id), "change"), "change")

	watch := cliLabStartWatch(t, context.Background(), w, "--json")
	cliLabNeed(t, "test-alert", cliLabJSON(t, "test-alert", osk(0, "test-alert", "--config", w.config, "--json"), "attempt"), "attempt")
	set = time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"98")
	cliLabUntil(t, "an event in watch", set.Add(5*time.Second+3750*time.Millisecond+2*time.Second), 20*time.Millisecond, func() bool {
		return strings.Contains(watch.out.String(), `"type":"event"`)
	})
	watch.end(t)
	cliLabNoMarker(t, w, watch.out.String())
	cliLabNeed(t, "watch", cliLabJSON(t, "watch", watch.out.String(), "event", "notice"), "event", "notice")
}

// accept prints the change of the one line of www; with --write it changes
// only that line, the service loads the file, sends the change to the
// channels and resolves the alert; the alert is then no longer open.
func TestAcceptPrintsThenWrites(t *testing.T) {
	w := cliLabSetup(t, true, func(n string) string { return cliLabFile(n, "# web") }, map[string]string{"fast": "5s"})
	svc := cliLabStart(t, w)
	n := w.n
	set := time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	open := regexp.MustCompile(`(?m)^open (\d+) high record-set records www\.corp\.test\. A since `)
	var id string
	cliLabUntil(t, "the open alert in status", set.Add(12*time.Second), 200*time.Millisecond, func() bool {
		_, out, _ := cliLabOsk("status", "--config", w.config)
		if m := open.FindStringSubmatch(out); m != nil {
			id = m[1]
		}
		return id != ""
	})
	before, err := os.ReadFile(w.expect)
	if err != nil {
		t.Fatal(err)
	}
	change := []string{w.expect + ":5", "- www.corp.test. A " + n + "81", "+ www.corp.test. A " + n + "99"}

	writeCode := cliLabCode(id, w.expect, "www.corp.test. A "+n+"81", "www.corp.test. A "+n+"99")
	toWrite := "To write this change: osk accept --config " + w.config + " --write " + writeCode + " " + id
	code, out, errOut := cliLabOsk("accept", "--config", w.config, id)
	if want := strings.Join(append(change, toWrite), "\n") + "\n"; code != 0 || errOut != "" || out != want {
		t.Errorf("accept %s: exit code %d, errors %q, output:\n%s\nwant 0, none and:\n%s", id, code, errOut, out, want)
	}
	if after, err := os.ReadFile(w.expect); err != nil || !bytes.Equal(after, before) {
		t.Errorf("accept without --write changed the file:\n%s", after)
	}

	written := time.Now()
	code, out, errOut = cliLabOsk("accept", "--config", w.config, "--write", writeCode, id)
	if want := strings.Join(append(change, "written"), "\n") + "\n"; code != 0 || errOut != "" || out != want {
		t.Errorf("accept --write %s: exit code %d, errors %q, output:\n%s\nwant 0, none and:\n%s", id, code, errOut, out, want)
	}
	if after, err := os.ReadFile(w.expect); err != nil || string(after) != strings.Replace(string(before), n+"81", n+"99", 1) {
		t.Errorf("the file after accept --write:\n%s\nwant only line 5 changed", after)
	}

	deadline := written.Add(5*time.Second + 5*time.Second + 3750*time.Millisecond + time.Second)
	svc.wait(t, "the resolve of www", deadline, func(l cliLabLog) bool {
		return l.Text == "alert resolve high record-set records www.corp.test. A"
	})
	view := []string{"- www.corp.test. A " + n + "81", "+ www.corp.test. A " + n + "99"}
	cliLabUntil(t, "the Slack message of the change", deadline, 200*time.Millisecond, func() bool {
		return slices.ContainsFunc(cliLabSlackTexts(t, w), func(s string) bool {
			lines := strings.Split(s, "\n")
			i := slices.Index(lines, "```")
			return len(lines) > 0 && lines[0] == ":memo: *CHANGED* · the expectations of `corp.test.` changed" && i >= 0 &&
				len(lines) > i+len(view)+1 && slices.Equal(lines[i+1:i+1+len(view)], view) && lines[i+1+len(view)] == "```"
		})
	})

	// The resolve shows the line that the servers match now: the accepted value.
	cliLabUntil(t, "the Slack message of the resolve", deadline, 200*time.Millisecond, func() bool {
		return slices.ContainsFunc(cliLabSlackTexts(t, w), func(s string) bool {
			return strings.HasPrefix(s, ":white_check_mark: *RESOLVED*") && strings.Contains(s, "www.corp.test.") &&
				slices.Contains(strings.Split(s, "\n"), "now        "+n+"99") && !strings.Contains(s, n+"81")
		})
	})

	code, out, errOut = cliLabOsk("accept", "--config", w.config, id)
	if want := "osk: alert " + id + " is not open\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("accept of the resolved alert: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	code, out, errOut = cliLabOsk("accept", "--config", w.config, "99999")
	if want := "osk: store: no alert 99999\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("accept of an unknown id: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
}
