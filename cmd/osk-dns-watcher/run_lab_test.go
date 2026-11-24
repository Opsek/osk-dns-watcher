//go:build lab

package main

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// The receiver of the lab stores every request, so a test sees each Slack
// message as it was sent.
const (
	runLabURL  = "https://hooks.lab.test" + runLabPath
	runLabPath = "/slack/T0/B0/" + runMarker
)

// runChildEnv makes the test binary act as osk-dns-watcher, with the arguments in it,
// one on each line; runStartEnv set to 1 makes it go through the check for
// root, as main does.
const (
	runChildEnv = "OSK_RUN_CHILD"
	runStartEnv = "OSK_RUN_START"
)

// The deadline of a check is three quarters of its interval.
const runSerialDeadline = 11250 * time.Millisecond

// TestRunChild is osk-dns-watcher in a child process. A folder lock and a signal belong
// to a process, so a second service and a stop by signal need one.
func TestRunChild(t *testing.T) {
	args := os.Getenv(runChildEnv)
	if args == "" {
		return
	}
	if os.Getenv(runStartEnv) == "1" {
		os.Exit(start(strings.Split(args, "\n"), os.Stdout, os.Stderr))
	}
	os.Exit(run(strings.Split(args, "\n"), os.Stdout, os.Stderr))
}

// runChild starts osk-dns-watcher run with args in another process: the test binary
// again, which TestRunChild turns into osk-dns-watcher. Only -test.run is given: other
// test flags would write to its output or turn its exit into a panic.
func runChild(t *testing.T, args ...string) (*runService, *os.Process) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunChild$")
	cmd.Env = append(os.Environ(), runChildEnv+"="+strings.Join(append([]string{"run"}, args...), "\n"))
	s := &runService{out: &runOutput{}, errOut: &runBuffer{}, done: make(chan struct{})}
	cmd.Stdout, cmd.Stderr = s.out, s.errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		defer close(s.done)
		// The error only repeats the exit status, which ExitCode gives.
		_ = cmd.Wait()
		s.code = cmd.ProcessState.ExitCode()
	}()
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		<-s.done
	})
	return s, cmd.Process
}

func (s *runService) end(t *testing.T, limit time.Duration) {
	t.Helper()
	select {
	case <-s.done:
	case <-time.After(limit):
		t.Fatalf("the child did not end within %v; output:\n%s", limit, runDump(s.out.all()))
	}
}

// runSignalStop sends sig to a child. It must end within 5 s with exit code
// 0, the line stop last and nothing on standard error.
func runSignalStop(t *testing.T, s *runService, p *os.Process, sig os.Signal) {
	t.Helper()
	if err := p.Signal(sig); err != nil {
		t.Fatal(err)
	}
	s.end(t, 5*time.Second)
	lines := s.out.all()
	if s.code != 0 || len(lines) == 0 || lines[len(lines)-1].text != "stop" || s.errOut.String() != "" {
		t.Errorf("after %v: exit code %d, errors %q; output:\n%s\nwant 0, none and the line stop last",
			sig, s.code, runShow(s.errOut.String()), runDump(lines))
	}
	s.out.check(t)
}

// runLab starts a lab test: an empty receiver, the Slack URL of the lab and
// a state folder that does not exist yet.
func runLab(t *testing.T) (n, state string) {
	t.Helper()
	n = expLab(t)
	t.Setenv("OSK_SLACK_URL", runLabURL)
	expCtl(t, "hooks", "clear")
	return n, filepath.Join(t.TempDir(), "state")
}

// runLabCfg is the config of a service of corp.test. with file that starts
// from the lab root, may ask every lab address and sends to Slack only.
func runLabCfg(n, file, state string, iv map[string]string, fast ...string) runCfg {
	return runCfg{State: state, Domains: []runCfgDomain{{Name: "corp.test.", Expect: file, Fast: fast}}, Intervals: iv,
		Slack:   &runCfgSlack{URL: runSecret{Env: "OSK_SLACK_URL"}},
		Network: &runCfgNet{RootServers: []string{n + "2"}, ExtraRanges: []string{n + "0/24"}}}
}

func runLabArgs(t *testing.T, n, file, state string, iv map[string]string, fast ...string) []string {
	t.Helper()
	return runConfig(t, runLabCfg(n, file, state, iv, fast...))
}

func runRecords(name, typ string) string {
	return "records corp.test. " + name + " " + typ
}

// runFor lets a service run until window after the first start of the check
// k, stops it and gives its runs and lines.
func runFor(t *testing.T, svc *runService, k string, window time.Duration) (map[string][]runChecked, []runLine) {
	t.Helper()
	first, _ := svc.wait(t, "the first run of "+k, 0, time.Now().Add(10*time.Second), runRunOf(k))
	c, _, _ := runParse(first.text)
	time.Sleep(time.Until(c.start.Add(window)))
	lines := svc.stop(t)
	return runRuns(t, lines), lines
}

// runAfter accepts a checked line of the check k that started after at.
func runAfter(k string, at time.Time) func(string) bool {
	return func(s string) bool {
		c, ok, _ := runParse(s)
		return ok && c.key == k && c.start.After(at)
	}
}

// runHook is a request that the receiver stored.
type runHook struct {
	status int
	text   string
}

// runHooks gives the Slack messages that the receiver stored, in order;
// each must be a POST of JSON to the path of the URL of the tests.
func runHooks(t *testing.T) []runHook {
	t.Helper()
	var hooks []runHook
	for _, line := range slkHooks(t) {
		var r struct {
			Method  string              `json:"method"`
			Path    string              `json:"path"`
			Headers map[string][]string `json:"headers"`
			Body    string              `json:"body"`
			Status  int                 `json:"status"`
		}
		if err := json.Unmarshal([]byte(line), &r); err != nil {
			t.Fatalf("hooks list line %s: %v", runShow(line), err)
		}
		if r.Method != "POST" || r.Path != runLabPath || !slices.Equal(r.Headers["Content-Type"], []string{"application/json"}) {
			t.Errorf("request %s; want POST to the path of the Slack URL with Content-Type application/json", runShow(line))
		}
		var body map[string]json.RawMessage
		var text string
		if err := json.Unmarshal([]byte(r.Body), &body); err != nil || len(body) != 1 || json.Unmarshal(body["text"], &text) != nil {
			t.Fatalf("body %q; want a JSON object with the one key text, a string", runShow(r.Body))
		}
		hooks = append(hooks, runHook{r.Status, text})
	}
	return hooks
}

// runNotice reports a message that belongs to no alert: a test, a down
// time or a change of the expectations.
func runNotice(text string) bool {
	return strings.HasPrefix(text, ":test_tube: ") || strings.HasPrefix(text, ":warning: *DOWN* · ") ||
		strings.HasPrefix(text, ":memo: *CHANGED* · ")
}

// runHookCount checks the number of Slack messages of alerts.
func runHookCount(t *testing.T, what string, want int) []runHook {
	t.Helper()
	var alerts []runHook
	for _, h := range runHooks(t) {
		if !runNotice(h.text) {
			alerts = append(alerts, h)
		}
	}
	if len(alerts) != want {
		t.Fatalf("%s: the receiver holds %d messages of alerts, want %d", what, len(alerts), want)
	}
	return alerts
}

var runDownHeadline = regexp.MustCompile(`^:warning: \*DOWN\* · osk-dns-watcher did not run for (\d+ (?:d|h|min|s)(?: \d+ (?:h|min|s))?)$`)

// runParseDown reads a time down as the message writes it: one or two
// numbers, each followed by its unit.
func runParseDown(s string) (time.Duration, bool) {
	words := strings.Fields(s)
	var d time.Duration
	for i := 0; i+1 < len(words); i += 2 {
		n, err := strconv.Atoi(words[i])
		unit, ok := map[string]time.Duration{"d": 24 * time.Hour, "h": time.Hour, "min": time.Minute, "s": time.Second}[words[i+1]]
		if err != nil || !ok {
			return 0, false
		}
		d += time.Duration(n) * unit
	}
	return d, len(words) > 0 && len(words)%2 == 0
}

// runDownHooks checks that the receiver holds want down messages, and gives
// the time down that each tells.
func runDownHooks(t *testing.T, what string, want int) []time.Duration {
	t.Helper()
	var downs []time.Duration
	for _, h := range runHooks(t) {
		if !strings.HasPrefix(h.text, ":warning: *DOWN* · ") {
			continue
		}
		m := runDownHeadline.FindStringSubmatch(strings.Split(h.text, "\n")[0])
		if m == nil {
			t.Errorf("%s: the down message %q does not start with the time down", what, h.text)
			continue
		}
		d, ok := runParseDown(m[1])
		if !ok {
			t.Errorf("%s: the down message %q does not start with the time down", what, h.text)
		}
		downs = append(downs, d)
	}
	if len(downs) != want {
		t.Errorf("%s: the receiver holds %d down messages, want %d", what, len(downs), want)
	}
	return downs
}

func runNoAlert(t *testing.T, lines []runLine) {
	t.Helper()
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") {
			t.Errorf("the base lab gave %q", l.text)
		}
	}
}

func runSameHead(t *testing.T, lines []runLine, want []string) {
	t.Helper()
	if head, _ := runHead(t, lines); !slices.Equal(head, want) {
		t.Errorf("the start printed:\n%s\nwant:\n%s", strings.Join(head, "\n"), strings.Join(want, "\n"))
	}
}

func TestParentCheckedEveryInterval(t *testing.T) {
	n, state := runLab(t)
	svc := runStart(t, runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "5s", "1h", "1h"))...)
	runs, _ := runFor(t, svc, runDelegationKey, 12*time.Second)
	runCount(t, runs, "parent", 3, runDelegationKey, runDSKey)
	runCount(t, runs, "serial", 1, runSerialKey)
	runCount(t, runs, "other", 1, runRecords("corp.test.", "NS"))
	for _, k := range []string{runDelegationKey, runDSKey} {
		runGaps(t, k, runs[k], 5*time.Second)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// The fixed fast set at the domain, the ACME challenge name and the fast
// names of the config run every fast interval; a fast name that owns no
// line is reported at the start. Each name below the CAA line that has no CAA
// line of its own gets a CAA check, in the tier of the name.
func TestFastNamesEveryInterval(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "corp.test. A "+n+"80", "corp.test. AAAA fd53:0:0:"+os.Getenv("LAB_ID")+"::80",
		"corp.test. MX 10 mail.corp.test.", `corp.test. CAA 0 issue "ca.test"`, `corp.test. TXT "v=spf1 mx -all"`,
		"_acme-challenge.corp.test. TXT none", "www.corp.test. A "+n+"81", "mail.corp.test. A "+n+"82")
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("1h", "1h", "5s", "1h"), "mail.corp.test.", "nothere.corp.test.")...)
	fast := []string{runRecords("corp.test.", "A"), runRecords("corp.test.", "AAAA"), runRecords("corp.test.", "MX"),
		runRecords("corp.test.", "CAA"), runRecords("_acme-challenge.corp.test.", "TXT"), runRecords("mail.corp.test.", "A"),
		runRecords("mail.corp.test.", "CAA")}
	runs, lines := runFor(t, svc, fast[0], 12*time.Second)
	runSameHead(t, lines, runPlan("corp.test.", state, 14, [4]string{"1h0m0s 1", "1h0m0s 2", "5s 7", "1h0m0s 4"}, "nothere.corp.test."))
	runCount(t, runs, "fast", 3, fast...)
	runCount(t, runs, "other", 1, runRecords("corp.test.", "NS"), runRecords("corp.test.", "TXT"), runRecords("www.corp.test.", "A"),
		runRecords("www.corp.test.", "CAA"))
	for _, k := range fast {
		runGaps(t, k, runs[k], 5*time.Second)
	}
	runNoAlert(t, lines)
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

func TestOtherNamesEveryInterval(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "www.corp.test. A "+n+"81", "mail.corp.test. A "+n+"82", "cdn.corp.test. CNAME edge.dnshost.test.",
		`_dmarc.corp.test. TXT "v=DMARC1; p=reject"`)
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("1h", "1h", "1h", "8s"))...)
	other := []string{runRecords("corp.test.", "NS"), runRecords("_dmarc.corp.test.", "TXT"), runRecords("cdn.corp.test.", "CNAME"),
		runRecords("mail.corp.test.", "A"), runRecords("www.corp.test.", "A")}
	runs, _ := runFor(t, svc, other[0], 18*time.Second)
	runCount(t, runs, "other", 3, other...)
	runCount(t, runs, "parent", 1, runDelegationKey, runDSKey)
	for _, k := range other {
		runGaps(t, k, runs[k], 8*time.Second)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// Each interval is refused below 5 s and above 24 h, as a problem of the
// config, before anything is opened or sent; at the floor itself, every
// tier runs every 5 s.
func TestIntervalsSetWithFloor(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "corp.test. A "+n+"80", "www.corp.test. A "+n+"81")
	for _, tier := range runTiers {
		for _, c := range []struct{ value, msg string }{{"4s", "4s is below the floor of 5s"}, {"25h", "25h0m0s is above 24h0m0s"}} {
			text := runCfgText(t, runLabCfg(n, file, state, map[string]string{tier: c.value}))
			path := runConfigText(t, text)
			code, out, errOut := runRefused(t, "--config", path)
			want := runProblemLines(t, path, text, runCfgProblem{`"` + tier + `": "` + c.value + `"`, "intervals." + tier, c.msg})
			if code != 1 || out != "" || errOut != want {
				t.Errorf("intervals.%s %s: exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s",
					tier, c.value, code, runShow(out), runShow(errOut), want)
			}
		}
	}
	slkNotThere(t, state)
	runHookCount(t, "after the refusals", 0)
	runDownHooks(t, "after the refusals", 0)

	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("5s", "5s", "5s", "5s"))...)
	runs, _ := runFor(t, svc, runSerialKey, 11*time.Second)
	runCount(t, runs, "serial", 3, runSerialKey)
	runCount(t, runs, "parent", 3, runDelegationKey, runDSKey)
	runCount(t, runs, "fast", 3, runRecords("corp.test.", "A"))
	runCount(t, runs, "other", 3, runRecords("corp.test.", "NS"), runRecords("www.corp.test.", "A"))
	for k, rs := range runs {
		runGaps(t, k, rs, 5*time.Second)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A changed record is seen within one serial interval and its deadline: the
// serial run sees the move at each server, every check of the domain's own
// zone runs at once, and one Slack message tells the change. Three changes
// between two serial runs make each zone check run once.
func TestSerialMoveStartsZoneChecks(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "www.corp.test. A "+n+"81", "mail.corp.test. A "+n+"82", "edge.dnshost.test. A "+n+"83")
	begin := time.Now()
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("", "1h", "1h", "1h"))...)
	ns, www, mail, edge := runRecords("corp.test.", "NS"), runRecords("www.corp.test.", "A"), runRecords("mail.corp.test.", "A"),
		runRecords("edge.dnshost.test.", "A")
	zone := []string{ns, www, mail}
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey, ns, www, mail, edge} {
		l, _ := svc.wait(t, "the first run of "+k, 0, begin.Add(10*time.Second), runRunOf(k))
		if c, _, _ := runParse(l.text); c.result != "ok" {
			t.Errorf("the first round gave %q, want ok", l.text)
		}
	}
	runSameHead(t, svc.out.all(), runPlan("corp.test.", state, 7, [4]string{"15s 1", "1h0m0s 2", "1h0m0s 0", "1h0m0s 4"}))

	set := time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	seen := set.Add(15*time.Second + runSerialDeadline)
	serial, i := svc.wait(t, "the serial run after the change", 0, seen, runAfter(runSerialKey, set))
	for _, server := range []string{"11:53 ns1", "12:53 ns2"} {
		svc.wait(t, "the move at "+server, i, seen, runIs("moved corp.test. "+n+server+".corp.test. serial 1 to 2"))
	}
	moved, _, _ := runParse(serial.text)
	for _, k := range zone {
		svc.wait(t, "the run of "+k+" after the move", i, seen, runAfter(k, moved.start))
	}
	alert, _ := svc.wait(t, "the record-set alert", i, seen, runIs("alert open high record-set records www.corp.test. A"))
	svc.wait(t, "the Slack message", i, seen.Add(2*time.Second), runIs("delivery slack sent open high record-set records www.corp.test. A"))
	hooks := runHookCount(t, "after the change", 1)
	if hooks[0].status != 200 {
		t.Errorf("the receiver answered %d", hooks[0].status)
	}
	slkSameText(t, hooks[0].text, []string{
		":red_circle: *HIGH* · `www.corp.test. A` changed",
		"",
		"```",
		"expected   " + n + "81",
		"",
		"now        " + n + "99",
		"seen at    ns1.corp.test. (" + n + "11)   TTL 300",
		"           ns2.corp.test. (" + n + "12)   TTL 300",
		"```",
		"",
		slkClockOpen,
		"",
		":point_right: If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept.",
	}, slkRun{start: set, end: alert.at}, slkRun{start: begin, end: set})

	next, j := svc.wait(t, "the next serial run", i+1, moved.start.Add(15*time.Second+runSerialDeadline), runRunOf(runSerialKey))
	dataTool(t, "sh", "-c", strings.Repeat("labctl set both mail.corp.test. 300 A "+n+"82 && ", 2)+"labctl set both mail.corp.test. 300 A "+n+"82")
	nc, _, _ := runParse(next.text)
	r1, k := svc.wait(t, "the serial run after three changes", j+1, nc.start.Add(15*time.Second+runSerialDeadline), runRunOf(runSerialKey))
	for _, server := range []string{"11:53 ns1", "12:53 ns2"} {
		svc.wait(t, "the moves at "+server, k, nc.start.Add(15*time.Second+runSerialDeadline),
			runIs("moved corp.test. "+n+server+".corp.test. serial 2 to 5"))
	}
	c1, _, _ := runParse(r1.text)
	r2, _ := svc.wait(t, "the serial run after it", k+1, c1.start.Add(15*time.Second+runSerialDeadline), runRunOf(runSerialKey))
	c2, _, _ := runParse(r2.text)
	lines := svc.stop(t)

	runs := runRuns(t, lines)
	for _, k := range zone {
		between := 0
		for _, c := range runs[k] {
			if c.start.After(c1.start) && c.start.Before(c2.start) {
				between++
			}
		}
		if between != 1 {
			t.Errorf("%s started %d times between the serial runs at %s and %s, want once", k, between, c1.start, c2.start)
		}
	}
	runCount(t, runs, "parent", 1, runDelegationKey, runDSKey)
	runCount(t, runs, "other", 1, edge)
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

var runMoveLine = regexp.MustCompile(`^(\S+) (\S+) serial (\d+) until (\S+), (\d+) since (\S+)$`)

// runZoneText checks a notice of moved serials: its headline, one line for
// each server of the zone with its serial before and after, the action, and
// times that frame the change made from changed to changedEnd. It gives the
// line of the times.
func runZoneText(t *testing.T, text, n, headline, from, to string, changed, changedEnd time.Time) string {
	t.Helper()
	lines := strings.Split(text, "\n")
	action := ":point_right: If you did not change the zone, find out who did; only a zone transfer shows which record changed."
	if len(lines) != 10 || lines[0] != headline || lines[1] != "" || lines[2] != "```" || lines[5] != "```" || lines[6] != "" ||
		lines[8] != "" || lines[9] != action {
		t.Errorf("message:\n%s\nwant the headline %q, a code block of two lines, the times and the action", runShow(text), headline)
		return ""
	}
	var servers []string
	for _, l := range lines[3:5] {
		m := runMoveLine.FindStringSubmatch(l)
		if m == nil || m[3] != from || m[5] != to {
			t.Errorf("the line %q is not \"<addr> <host> serial %s until <time>, %s since <time>\"", l, from, to)
			continue
		}
		servers = append(servers, m[1]+" "+m[2])
		until, err1 := time.Parse(runSecondLayout, m[4])
		since, err2 := time.Parse(runSecondLayout, m[6])
		if err1 != nil || err2 != nil || until.After(changed) || since.Before(changedEnd.Truncate(time.Second)) {
			t.Errorf("the line %q: want the old serial last seen by %s and the new one first seen from %s",
				l, changed.UTC().Format(runSecondLayout), changedEnd.UTC().Format(runSecondLayout))
		}
	}
	slices.Sort(servers)
	if want := []string{n + "11:53 ns1.corp.test.", n + "12:53 ns2.corp.test."}; !slices.Equal(servers, want) {
		t.Errorf("the servers of the message are %q, want %q", servers, want)
	}
	return lines[7]
}

// A move that no change of a watched record explains opens a low notice
// that names each server's serials; a change put back between two serial
// runs updates it; one other-interval with no move resolves it.
func TestZoneChangedNotice(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "www.corp.test. A "+n+"81")
	begin := time.Now()
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("5s", "1h", "1h", "10s"))...)
	www := runRecords("www.corp.test.", "A")
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey, runRecords("corp.test.", "NS"), www} {
		svc.wait(t, "the first run of "+k, 0, begin.Add(10*time.Second), runRunOf(k))
	}
	_, i := svc.wait(t, "a serial run", 0, time.Now().Add(10*time.Second), runAfter(runSerialKey, begin.Add(time.Second)))
	const label = "low zone-changed corp.test."
	within := 5*time.Second + 3750*time.Millisecond + time.Second

	set := time.Now()
	expCtl(t, "set", "both", "extra.corp.test.", "300", "A", n+"77")
	setEnd := time.Now()
	for _, server := range []string{"11:53 ns1", "12:53 ns2"} {
		svc.wait(t, "the move at "+server, i, setEnd.Add(within), runIs("moved corp.test. "+n+server+".corp.test. serial 1 to 2"))
	}
	svc.wait(t, "the run of www after the move", i, setEnd.Add(within+time.Second), runAfter(www, set))
	opened, j := svc.wait(t, "the zone-changed alert", i, setEnd.Add(within+2*time.Second), runIs("alert open "+label))
	svc.wait(t, "its Slack message", j, opened.at.Add(3*time.Second), runIs("delivery slack sent open "+label))
	hooks := runHookCount(t, "after the change of an unwatched record", 1)
	times := runZoneText(t, hooks[0].text, n, ":large_yellow_circle: *LOW* · the zone `corp.test.` changed, and no watched record changed",
		"1", "2", set, setEnd)
	if clock, _ := slkClock(t, times); len(clock) != 2 || !strings.HasPrefix(times, ":clock3: First seen ") || !strings.Contains(times, " · last OK ") {
		t.Errorf("the times %q do not start with the first seen time and then the last OK time", times)
	} else {
		slkWithin(t, "the first seen time", clock[0], set.Truncate(time.Second), opened.at)
	}

	// The record goes and comes back between two serial runs: only the
	// serial shows it.
	_, k := svc.wait(t, "the next serial run", j+1, opened.at.Add(within), runRunOf(runSerialKey))
	put := time.Now()
	dataTool(t, "sh", "-c", "labctl set both www.corp.test. 300 A "+n+"99 && labctl set both www.corp.test. 300 A "+n+"81")
	putEnd := time.Now()
	for _, server := range []string{"11:53 ns1", "12:53 ns2"} {
		svc.wait(t, "the moves at "+server, k, putEnd.Add(within), runIs("moved corp.test. "+n+server+".corp.test. serial 2 to 4"))
	}
	updated, u := svc.wait(t, "the update of the notice", k, putEnd.Add(within+2*time.Second), runIs("alert update "+label))
	svc.wait(t, "its Slack message", u, updated.at.Add(3*time.Second), runIs("delivery slack sent update "+label))
	hooks = runHookCount(t, "after the change put back", 2)
	runZoneText(t, hooks[1].text, n, ":large_yellow_circle: *LOW*, changed again · the zone `corp.test.` changed, and no watched record changed",
		"2", "4", put, putEnd)

	resolved, r := svc.wait(t, "the resolve of the notice", u, updated.at.Add(20*time.Second), runIs("alert resolve "+label))
	if resolved.at.Before(updated.at.Add(10*time.Second - 200*time.Millisecond)) {
		t.Errorf("the notice resolved at %s, less than one other-interval after the last move was judged at %s", resolved.at, updated.at)
	}
	svc.wait(t, "its Slack message", r, resolved.at.Add(3*time.Second), runIs("delivery slack sent resolve "+label))
	lines := svc.stop(t)
	hooks = runHookCount(t, "after the quiet time", 3)
	slkSameText(t, hooks[2].text, []string{
		":white_check_mark: *RESOLVED* · the zone `corp.test.` has not changed again for a while",
		"",
		"```",
		"now        no new change of the serial",
		"```",
		"",
		slkClockClosed,
		"",
		":point_right: If you did not make or undo this change yourself, find out who did.",
	}, slkRun{start: set, end: opened.at}, slkRun{start: updated.at, end: resolved.at})
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") && strings.Contains(l.text, " record-set ") {
			t.Errorf("a change put back between two serial runs gave %q", l.text)
		}
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A check whose servers give no usable answer for five fast intervals is
// reported, and a usable answer resolves the report; a run with no usable
// answer is never taken as a changed record.
func TestFailingCheckReported(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "corp.test. A "+n+"80", "www.corp.test. A "+n+"81")
	begin := time.Now()
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("5s", "1h", "5s", "1h"))...)
	apex := runRecords("corp.test.", "A")
	for _, k := range []string{runSerialKey, runDelegationKey, runDSKey, runRecords("corp.test.", "NS"), apex, runRecords("www.corp.test.", "A")} {
		l, _ := svc.wait(t, "the first run of "+k, 0, begin.Add(10*time.Second), runRunOf(k))
		if c, _, _ := runParse(l.text); c.result != "ok" {
			t.Errorf("the first round gave %q, want ok", l.text)
		}
	}

	dropped := time.Now()
	expCtl(t, "drop-zone", "ns1", "corp.test.")
	expCtl(t, "drop-zone", "ns2", "corp.test.")
	failed, _ := svc.wait(t, "a failed run of "+apex, 0, dropped.Add(5*time.Second+3750*time.Millisecond+time.Second), func(s string) bool {
		c, ok, _ := runParse(s)
		return ok && c.key == apex && c.result != "ok"
	})
	fc, _, _ := runParse(failed.text)
	if fc.tier != "fast" || fc.result != "failed refused" {
		t.Errorf("the first run after the zone was dropped: %q, want tier fast and failed refused", failed.text)
	}
	const label = "medium check-failing records corp.test. A"
	opened, i := svc.wait(t, "the check-failing alert", 0, dropped.Add(25*time.Second+5*time.Second+3750*time.Millisecond+time.Second),
		runIs("alert open "+label))
	if opened.at.Before(fc.start.Add(25 * time.Second)) {
		t.Errorf("the alert opened at %s, before the runs had failed for 25 s from %s", opened.at, fc.start)
	}
	svc.wait(t, "its Slack message", i, opened.at.Add(3*time.Second), runIs("delivery slack sent open "+label))
	// The reset below also clears the receiver.
	hooks := runHookCount(t, "after the failures", 1)
	slkSameText(t, hooks[0].text, []string{
		":large_orange_circle: *MEDIUM* · the records check of `corp.test. A` has had no usable answer for too long",
		"",
		"```",
		"problem    no usable answer for 25 s",
		"```",
		"",
		slkClockOpen,
		"",
		":point_right: Find out why no server of `corp.test.` answers this machine; until one does, a change there is not seen.",
	}, slkRun{start: fc.start.Add(25 * time.Second), end: opened.at}, slkRun{start: begin, end: dropped})

	reset := time.Now()
	expCtl(t, "reset")
	resolved, j := svc.wait(t, "the resolve", i, time.Now().Add(5*time.Second+3750*time.Millisecond+time.Second), runIs("alert resolve "+label))
	svc.wait(t, "its Slack message", j, resolved.at.Add(3*time.Second), runIs("delivery slack sent resolve "+label))
	lines := svc.stop(t)
	hooks = runHookCount(t, "after the zone came back", 1)
	slkSameText(t, hooks[0].text, []string{
		":white_check_mark: *RESOLVED* · the records check of `corp.test. A` has usable answers again",
		"",
		"```",
		"now        a server answers",
		"```",
		"",
		slkClockClosed,
		"",
		":point_right: If you did not make or undo this change yourself, find out who did.",
	}, slkRun{start: fc.start.Add(25 * time.Second), end: opened.at}, slkRun{start: reset, end: resolved.at})
	var alerts []string
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") {
			alerts = append(alerts, l.text)
		}
	}
	if want := []string{"alert open " + label, "alert resolve " + label}; !slices.Equal(alerts, want) {
		t.Errorf("the alerts were %q, want only %q", alerts, want)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}

// A second service on a folder in use is refused; once the first stopped,
// another starts there, sends one down message, and stops cleanly on SIGINT.
func TestOneServicePerStateFolder(t *testing.T) {
	n, state := runLab(t)
	args := runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "1h", "1h", "1h"))
	first := runStart(t, args...)
	first.wait(t, "the start line", 0, time.Now().Add(5*time.Second), runPrefix("start "))
	second, _ := runChild(t, args...)
	second.end(t, 10*time.Second)
	if want := "osk-dns-watcher: store: " + state + " is in use by another osk-dns-watcher process\n"; second.code != 1 || second.out.String() != "" ||
		second.errOut.String() != want {
		t.Errorf("a second service: exit code %d, output %q, errors %q; want 1, nothing and %q",
			second.code, runShow(second.out.String()), runShow(second.errOut.String()), want)
	}
	first.stop(t)

	third, p := runChild(t, args...)
	third.wait(t, "the start line", 0, time.Now().Add(10*time.Second), runPrefix("start corp.test. "))
	third.wait(t, "the down message", 0, time.Now().Add(5*time.Second), runIs("delivery slack sent notice down -"))
	runSignalStop(t, third, p, os.Interrupt)
	runDownHooks(t, "after the restart", 1)
	runNoSecret(t, state, first.out.String(), second.out.String(), second.errOut.String(), third.out.String(), third.errOut.String())
}

// SIGTERM, which a container manager sends first, stops the service as
// SIGINT does.
func TestSIGTERMStopsTheServiceCleanly(t *testing.T) {
	n, state := runLab(t)
	child, p := runChild(t, runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "1h", "1h", "1h"))...)
	child.wait(t, "the first run", 0, time.Now().Add(10*time.Second), runRunOf(runDelegationKey))
	runSignalStop(t, child, p, syscall.SIGTERM)
	runNoSecret(t, state, child.out.String(), child.errOut.String())
}

// A message whose first send failed when the service was killed is sent
// once after the restart, beside one down message, and the difference that
// stands opens nothing new.
func TestRestartSendsNothingTwice(t *testing.T) {
	n, state := runLab(t)
	args := runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "5s", "1h", "1h"))
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCtl(t, "hooks", "reply", "503", "1")
	const label = "open critical nameservers delegation corp.test. NS"
	childStart := time.Now()
	child, p := runChild(t, args...)
	opened, _ := child.wait(t, "the alert", 0, childStart.Add(10*time.Second), runIs("alert "+label))
	child.wait(t, "the failed send", 0, childStart.Add(10*time.Second), runPrefix("delivery slack failed "+label+": status 503; next try "))
	killed := time.Now()
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	child.end(t, 5*time.Second)
	time.Sleep(2 * time.Second)

	begin := time.Now()
	svc := runStart(t, args...)
	svc.wait(t, "the send of the kept row", 0, begin.Add(15*time.Second), runIs("delivery slack sent "+label))
	svc.wait(t, "the down message", 0, begin.Add(15*time.Second), runIs("delivery slack sent notice down -"))
	time.Sleep(time.Until(begin.Add(10 * time.Second)))
	lines := svc.out.all()
	_, down := runHead(t, lines)
	if down.text == "" {
		t.Fatalf("the restart printed no down line:\n%s", runDump(lines))
	}
	if since, d := runDown(t, down.text); since.After(killed) || since.Before(childStart.Truncate(time.Second)) || d < 2*time.Second {
		t.Errorf("%q: want a beat of the killed service and at least 2s", down.text)
	}
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") {
			t.Errorf("the restart gave %q for a difference that stands", l.text)
		}
	}
	hooks := runHookCount(t, "after the restart", 2)
	if hooks[0].status != 503 || hooks[1].status != 200 || hooks[0].text != hooks[1].text {
		t.Errorf("the requests were answered %d and %d, with the texts:\n%s\n%s\nwant 503 then 200 and one text",
			hooks[0].status, hooks[1].status, hooks[0].text, hooks[1].text)
	}
	open := slkNameServersOpen(n)
	open[slices.Index(open, slkClockOpen)] = slkClockNoClean
	slkSameText(t, hooks[1].text, open, slkRun{start: childStart, end: opened.at})
	if downs := runDownHooks(t, "after the restart", 1); len(downs) == 1 && downs[0] < 2*time.Second {
		t.Errorf("the down message tells %v, want at least the 2s that the service was down", downs[0])
	}

	back := time.Now()
	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	resolved, i := svc.wait(t, "the resolve", 0, back.Add(5*time.Second+3750*time.Millisecond+time.Second),
		runIs("alert resolve critical nameservers delegation corp.test. NS"))
	svc.wait(t, "its Slack message", i, resolved.at.Add(3*time.Second), runIs("delivery slack sent resolve critical nameservers delegation corp.test. NS"))
	lines = svc.stop(t)
	hooks = runHookCount(t, "after the resolve", 3)
	slkSameText(t, hooks[2].text, slkNameServersResolved, slkRun{start: childStart, end: opened.at}, slkRun{start: back, end: resolved.at})
	runDownHooks(t, "after the resolve", 1)
	sent := 0
	for _, l := range lines {
		if l.text == "delivery slack sent "+label {
			sent++
		}
	}
	if sent != 1 {
		t.Errorf("the restarted service sent the open notice %d times, want once", sent)
	}
	runNoSecret(t, state, child.out.String(), child.errOut.String(), svc.out.String(), svc.errOut.String())
}

// The service stores a beat every 10 s, so after a crash the down line and
// the down message start at most 10 s before the crash.
func TestDownTimeAfterCrashIsAtMostTenSecondsEarly(t *testing.T) {
	n, state := runLab(t)
	args := runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "1h", "1h", "1h"))
	child, p := runChild(t, args...)
	start, _ := child.wait(t, "the start line", 0, time.Now().Add(10*time.Second), runPrefix("start "))
	time.Sleep(time.Until(start.at.Add(12 * time.Second)))
	killed := time.Now()
	if err := p.Kill(); err != nil {
		t.Fatal(err)
	}
	child.end(t, 5*time.Second)

	restarted := time.Now()
	svc := runStart(t, args...)
	svc.wait(t, "the first run", 0, time.Now().Add(10*time.Second), runRunOf(runDelegationKey))
	svc.wait(t, "the down message", 0, time.Now().Add(5*time.Second), runIs("delivery slack sent notice down -"))
	lines := svc.stop(t)
	_, down := runHead(t, lines)
	if down.text == "" {
		t.Fatalf("the restart printed no down line:\n%s", runDump(lines))
	}
	since, _ := runDown(t, down.text)
	slkWithin(t, "the last beat before the kill", since, killed.Add(-11*time.Second), killed)
	if downs := runDownHooks(t, "after the restart", 1); len(downs) == 1 {
		if gap := restarted.Sub(killed); downs[0] < gap.Truncate(time.Second) || downs[0] > gap+11*time.Second {
			t.Errorf("the down message tells %v, want %v to %v", downs[0], gap.Truncate(time.Second), gap+11*time.Second)
		}
	}
	runNoSecret(t, state, child.out.String(), child.errOut.String(), svc.out.String(), svc.errOut.String())
}

// A Slack send that the receiver holds for 8 s holds no check: the
// delegation still runs every 5 s.
func TestChecksKeepRunningWhileASlackSendHangs(t *testing.T) {
	n, state := runLab(t)
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCtl(t, "hooks", "reply", "200", "1", "--delay", "8")
	svc := runStart(t, runLabArgs(t, n, slkLabFile(t), state, runIntervals("1h", "5s", "1h", "1h"))...)
	const label = "open critical nameservers delegation corp.test. NS"
	opened, _ := svc.wait(t, "the alert", 0, time.Now().Add(10*time.Second), runIs("alert "+label))
	sent, _ := svc.wait(t, "the slow send", 0, opened.at.Add(12*time.Second), runIs("delivery slack sent "+label))
	lines := svc.stop(t)
	if sent.at.Sub(opened.at) < 8*time.Second {
		t.Errorf("the send ended %v after the alert, want at least the 8 s that the receiver held it", sent.at.Sub(opened.at))
	}
	runs := runRuns(t, lines)[runDelegationKey]
	runGaps(t, runDelegationKey, runs, 5*time.Second)
	during := 0
	for _, c := range runs {
		if c.start.After(opened.at) && c.start.Before(sent.at) {
			during++
		}
	}
	if during == 0 {
		t.Errorf("no run of the delegation started while the send hung:\n%s", runDump(lines))
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}
