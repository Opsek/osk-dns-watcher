//go:build lab

package main

import (
	"encoding/json"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"
)

// The receiver of the lab stores every request, so a test sees each Slack
// message as it was sent.
const (
	slkLabURL  = "https://hooks.lab.test" + slkLabPath
	slkLabPath = "/slack/T0/B0/" + slkMarker
)

const slkTimeLayout = "2006-01-02 15:04:05 UTC"

var slkTimes = regexp.MustCompile(`\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC`)

// slkRun is one run of osk check and the times just before and after it.
type slkRun struct {
	code       int
	out        string
	start, end time.Time
}

// slkLabCheck runs osk check with the state folder. It first waits for the
// next whole second: the messages give times to the second, so the times of
// two runs could not be told apart within one second.
func slkLabCheck(t *testing.T, n, file, state string, args ...string) slkRun {
	t.Helper()
	time.Sleep(time.Until(time.Now().Truncate(time.Second).Add(time.Second)))
	r := slkRun{start: time.Now()}
	var errOut string
	r.code, r.out, errOut = expOsk(n, "check", slices.Concat([]string{"--expect", file, "--state", state}, args)...)
	r.end = time.Now()
	if errOut != "" {
		t.Errorf("osk check: errors %q, want none", slkShow(errOut))
	}
	slkNoMarker(t, state, r.out, errOut)
	return r
}

func slkExpect(t *testing.T, what string, r slkRun, code int, want ...string) {
	t.Helper()
	if r.code != code {
		t.Errorf("%s: exit code %d, want %d", what, r.code, code)
	}
	slkSame(t, what, r.out, want)
}

// slkHooks gives the requests that the receiver stored, one JSON line each.
func slkHooks(t *testing.T) []string {
	t.Helper()
	out := dataTool(t, "labctl", "hooks", "list")
	if out == "" {
		return nil
	}
	return strings.Split(out, "\n")
}

func slkHookCount(t *testing.T, what string, want int) []string {
	t.Helper()
	hooks := slkHooks(t)
	if len(hooks) != want {
		t.Fatalf("%s: the receiver holds %d requests, want %d:\n%s", what, len(hooks), want, slkShow(strings.Join(hooks, "\n")))
	}
	return hooks
}

// slkSlackText checks that a stored request is a Slack message to the URL of
// the tests and gives its text.
func slkSlackText(t *testing.T, hook string) string {
	t.Helper()
	var r struct {
		Method  string              `json:"method"`
		Path    string              `json:"path"`
		Headers map[string][]string `json:"headers"`
		Body    string              `json:"body"`
		Status  int                 `json:"status"`
	}
	if err := json.Unmarshal([]byte(hook), &r); err != nil {
		t.Fatalf("hooks list line %s: %v", slkShow(hook), err)
	}
	if r.Method != "POST" || r.Path != slkLabPath || !slices.Equal(r.Headers["Content-Type"], []string{"application/json"}) || r.Status != 200 {
		t.Errorf("request %s; want POST to the path of the Slack URL with Content-Type application/json, answered 200", slkShow(hook))
	}
	var body map[string]json.RawMessage
	var text string
	if err := json.Unmarshal([]byte(r.Body), &body); err != nil || len(body) != 1 || json.Unmarshal(body["text"], &text) != nil {
		t.Fatalf("body %q; want a JSON object with the one key text, a string", slkShow(r.Body))
	}
	return text
}

// slkSameText compares a message with want, in which each time is written
// "<time>". The times of the message must lie, in order, in the runs given,
// and are returned.
func slkSameText(t *testing.T, got string, want []string, in ...slkRun) []string {
	t.Helper()
	times := slkTimes.FindAllString(got, -1)
	if len(times) != len(in) {
		t.Errorf("the message holds %d times, want %d:\n%s", len(times), len(in), slkShow(got))
		return times
	}
	for i, s := range times {
		at, err := time.Parse(slkTimeLayout, s)
		if err != nil {
			t.Errorf("time %q: %v", s, err)
			continue
		}
		slkWithin(t, "time "+s, at, in[i].start.Truncate(time.Second), in[i].end)
	}
	if norm := slkTimes.ReplaceAllString(got, "<time>"); norm != strings.Join(want, "\n") {
		t.Errorf("message:\n%s\nwant:\n%s", slkShow(got), strings.Join(want, "\n"))
	}
	return times
}

// slkNameServersOpen is the Slack message of the delegation of corp.test. to
// the name servers of dnshost.test.
func slkNameServersOpen(n string) []string {
	return []string{
		":rotating_light: CRITICAL: nameservers of `corp.test.` changed at the parent zone",
		"",
		"```",
		"expected  ns1.corp.test. | ns2.corp.test.",
		"now       ns1.dnshost.test. | ns2.dnshost.test.   at ns.test. (" + n + "3:53), TTL 300",
		"```",
		"",
		":clock3: First seen <time> / Last OK <time>",
		"",
		":point_right: If you did not change the nameservers, contact your registrar now.",
	}
}

var slkNameServersResolved = []string{
	":white_check_mark: RESOLVED: nameservers of `corp.test.` are as expected again",
	"",
	"```",
	"expected  ns1.corp.test. | ns2.corp.test.",
	"now       as expected again",
	"```",
	"",
	":clock3: First seen <time> / Resolved <time>",
	"",
	":point_right: If you did not make or undo this change yourself, find out who did.",
}

func slkNameServersFinding(n string) []string {
	return []string{
		"finding critical nameservers delegation corp.test. NS",
		"  expected ns1.corp.test. | ns2.corp.test.",
		"  seen " + n + "3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test.",
	}
}

// slkLabFile is the file of the delegation of corp.test., with the lines
// given after it.
func slkLabFile(t *testing.T, lines ...string) string {
	t.Helper()
	text := strings.Join(append([]string{"domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none"}, lines...), "\n")
	return expWrite(t, t.TempDir(), "corp.test.expect", text+"\n")
}

// slkLab starts a test with an empty receiver and the Slack URL of the lab.
func slkLab(t *testing.T) (n, state string) {
	t.Helper()
	n = expLab(t)
	t.Setenv("OSK_SLACK_URL", slkLabURL)
	expCtl(t, "hooks", "clear")
	// The store makes the folder for its owner alone; it refuses one that
	// other users may enter, as a folder of the tests may be.
	return n, filepath.Join(t.TempDir(), "state")
}

// A changed delegation gives one Slack message with its proof; a run that
// sees the same again sends nothing; the delegation put back gives one
// resolved message.
func TestSlackAlertThenResolved(t *testing.T) {
	n, state := slkLab(t)
	file := slkLabFile(t)

	r1 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the first run", r1, 0, "checked corp.test. 3 sets: 0 findings, 0 unknown answers")
	slkHookCount(t, "after the first run", 0)

	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	r2 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the run after the change", r2, 1, slices.Concat(slkNameServersFinding(n), []string{
		"checked corp.test. 3 sets: 1 findings, 0 unknown answers",
		"alert open critical nameservers delegation corp.test. NS",
		"delivery slack sent open critical nameservers delegation corp.test. NS",
	})...)
	sent := slkHookCount(t, "after the change", 1)
	opened := slkSameText(t, slkSlackText(t, sent[0]), slkNameServersOpen(n), r2, r1)

	r3 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the run with no change", r3, 1, append(slkNameServersFinding(n),
		"checked corp.test. 3 sets: 1 findings, 0 unknown answers")...)
	if hooks := slkHookCount(t, "after the run with no change", 1); hooks[0] != sent[0] {
		t.Errorf("the stored request changed:\n%s\nwant:\n%s", slkShow(hooks[0]), slkShow(sent[0]))
	}

	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	r4 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the run after the change back", r4, 0,
		"checked corp.test. 3 sets: 0 findings, 0 unknown answers",
		"alert resolve critical nameservers delegation corp.test. NS",
		"delivery slack sent resolve critical nameservers delegation corp.test. NS")
	hooks := slkHookCount(t, "after the change back", 2)
	if hooks[0] != sent[0] {
		t.Errorf("the first stored request changed:\n%s\nwant:\n%s", slkShow(hooks[0]), slkShow(sent[0]))
	}
	resolved := slkSameText(t, slkSlackText(t, hooks[1]), slkNameServersResolved, r2, r4)
	if len(opened) > 0 && len(resolved) > 0 && resolved[0] != opened[0] {
		t.Errorf("the resolved message gives first seen %s, the open one %s", resolved[0], opened[0])
	}
}

// The message shows the one server that differs, with the TTL of its answer,
// and the times of the run that saw it and of the last clean run.
func TestAlertCarriesProof(t *testing.T) {
	n, state := slkLab(t)
	file := slkLabFile(t, "www.corp.test. A "+n+"81")

	r1 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the first run", r1, 0, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")

	expCtl(t, "set", "ns2", "www.corp.test.", "120", "A", n+"99")
	r2 := slkLabCheck(t, n, file, state)
	slkExpect(t, "the run after the change", r2, 1,
		"finding high record-set records www.corp.test. A",
		"  expected "+n+"81",
		"  seen "+n+"12:53 ns2.corp.test. "+n+"99",
		"checked corp.test. 4 sets: 1 findings, 0 unknown answers",
		"alert open high record-set records www.corp.test. A",
		"delivery slack sent open high record-set records www.corp.test. A")
	sent := slkHookCount(t, "after the change", 1)
	slkSameText(t, slkSlackText(t, sent[0]), []string{
		":red_circle: HIGH: `www.corp.test. A` changed",
		"",
		"```",
		"expected  " + n + "81",
		"now       " + n + "99   at ns2.corp.test. (" + n + "12:53), TTL 120",
		"```",
		"",
		":clock3: First seen <time> / Last OK <time>",
		"",
		":point_right: If you did not make this change, check your DNS provider account now.",
	}, r2, r1)
}

// With a minimum of critical, the high alert of www is stored but never sent,
// also when it changes; the critical alert of the delegation is sent.
func TestMinimumSeverityPerChannel(t *testing.T) {
	n, state := slkLab(t)
	file := slkLabFile(t, "www.corp.test. A "+n+"81")

	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	r1 := slkLabCheck(t, n, file, state, "--slack-min-severity", "critical")
	slkExpect(t, "the run after the change of www", r1, 1,
		"finding high record-set records www.corp.test. A",
		"  expected "+n+"81",
		"  seen "+n+"11:53 ns1.corp.test. "+n+"99",
		"  seen "+n+"12:53 ns2.corp.test. "+n+"99",
		"checked corp.test. 4 sets: 1 findings, 0 unknown answers",
		"alert open high record-set records www.corp.test. A")
	slkHookCount(t, "after the change of www", 0)

	// The servers of www now answer under the names that the parent gives,
	// so the proof of www holds new lines.
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	r2 := slkLabCheck(t, n, file, state, "--slack-min-severity", "critical")
	slkExpect(t, "the run after the change of the delegation", r2, 1, slices.Concat(slkNameServersFinding(n), []string{
		"finding high record-set records www.corp.test. A",
		"  expected " + n + "81",
		"  seen " + n + "11:53 ns1.dnshost.test. " + n + "99",
		"  seen " + n + "12:53 ns2.dnshost.test. " + n + "99",
		"checked corp.test. 4 sets: 2 findings, 0 unknown answers",
		"alert open critical nameservers delegation corp.test. NS",
		"alert update high record-set records www.corp.test. A",
		"delivery slack sent open critical nameservers delegation corp.test. NS",
	})...)
	sent := slkHookCount(t, "after the change of the delegation", 1)
	// The delegation was clean in the first run, which found only www.
	slkSameText(t, slkSlackText(t, sent[0]), slkNameServersOpen(n), r2, r1)
}
