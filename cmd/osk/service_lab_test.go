//go:build lab

package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/cli"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// svcLab is the config of a lab test of the service: one domain,
// corp.test., Slack, and the webhook siem, each secret with a marker of its
// own, and the heartbeat when a test adds it.
type svcLab struct {
	n, dir, state, expect        string
	cfg                          runCfg
	slackPath, hookPath, keyPath string
	beatPath, urlPath            string
	key                          []byte
	marks                        []string // of the Slack URL, the webhook URL, the key and the heartbeat URL
}

// svcLabFile is the expectations file B: the delegation, no DS and www.
func svcLabFile(n string, more ...string) string {
	return strings.Join(slices.Concat([]string{"domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. DS none", "www.corp.test. A " + n + "81"}, more), "\n") + "\n"
}

// svcLabSetup writes the secrets and file B of a test and gives its config,
// every interval 1h but those of iv. The lab is put back at the end.
func svcLabSetup(t *testing.T, iv map[string]string) *svcLab {
	t.Helper()
	n := expLab(t)
	expCtl(t, "hooks", "clear")
	dir := t.TempDir()
	w := &svcLab{n: n, dir: dir, state: filepath.Join(dir, "state")}
	for range 4 {
		w.marks = append(w.marks, cliLabMarker(t))
	}
	w.slackPath, w.hookPath, w.beatPath = "/slack/T0/B0/"+w.marks[0], "/hook/"+w.marks[1], "/beat/"+w.marks[3]
	t.Setenv("OSK_SLACK_URL", "https://hooks.lab.test"+w.slackPath)
	t.Setenv("OSK_HEARTBEAT_URL", "https://hooks.lab.test"+w.beatPath)
	w.urlPath = expWrite(t, dir, "siem-url", "https://hooks.lab.test"+w.hookPath+"\n")
	w.key = []byte(w.marks[2] + strings.Repeat("k", 40-len(w.marks[2])))
	w.keyPath = expWrite(t, dir, "siem-key", string(w.key))
	w.expect = expWrite(t, dir, "corp.test.expect", svcLabFile(n))
	all := map[string]string{"serial": "1h", "parent": "1h", "fast": "1h", "other": "1h"}
	for k, v := range iv {
		all[k] = v
	}
	w.cfg = runCfg{State: w.state, Domains: []runCfgDomain{{Name: "corp.test.", Expect: w.expect, Fast: []string{"www.corp.test."}}},
		Intervals: all, Slack: &runCfgSlack{URL: runSecret{Env: "OSK_SLACK_URL"}},
		Webhooks: []runCfgHook{{Name: "siem", URL: runSecret{File: w.urlPath}, Key: runSecret{File: w.keyPath}}},
		Network:  &runCfgNet{RootServers: []string{n + "2"}, ExtraRanges: []string{n + "0/24"}}}
	return w
}

func (w *svcLab) withBeat() {
	w.cfg.Heartbeat = &runCfgBeat{URL: runSecret{Env: "OSK_HEARTBEAT_URL"}, Interval: "5s"}
}

// verify is the check of a receiver of the webhook, as its documentation
// gives it.
func svcVerify(key, body []byte, h map[string][]string, now time.Time) bool {
	get := func(name string) string {
		if v := h[name]; len(v) > 0 {
			return v[0]
		}
		return ""
	}
	ts := get("Osk-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec < now.Unix()-300 || sec > now.Unix()+300 {
		return false
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(get("Osk-Signature")))
}

func svcHookTime(t *testing.T, h cliLabHook) time.Time {
	t.Helper()
	at, err := time.Parse(time.RFC3339Nano, h.Time)
	if err != nil {
		t.Fatalf("the receiver time %q: %v", h.Time, err)
	}
	return at
}

// svcOn gives the requests that the receiver holds for path.
func svcOn(t *testing.T, path string) []cliLabHook {
	t.Helper()
	var on []cliLabHook
	for _, h := range cliLabHooks(t) {
		if h.Path == path {
			on = append(on, h)
		}
	}
	return on
}

// svcTexts gives the Slack texts that the receiver holds for path.
func svcTexts(t *testing.T, path string) []string {
	t.Helper()
	var texts []string
	for _, h := range svcOn(t, path) {
		var body struct {
			Text string `json:"text"`
		}
		if err := json.Unmarshal([]byte(h.Body), &body); err != nil {
			t.Fatalf("the Slack body %q: %v", h.Body, err)
		}
		texts = append(texts, body.Text)
	}
	return texts
}

// svcBody gives the values of a webhook body, which must be one JSON object.
func svcBody(t *testing.T, h cliLabHook) ([]string, map[string]json.RawMessage) {
	t.Helper()
	keys, values, err := svcObject([]byte(h.Body))
	if err != nil {
		t.Fatalf("the webhook body %q: %v", h.Body, err)
	}
	return keys, values
}

// svcView gives the lines of the code block of a Slack text.
func svcView(text string) []string {
	lines := strings.Split(text, "\n")
	i := slices.Index(lines, "```")
	if i < 0 {
		return nil
	}
	j := slices.Index(lines[i+1:], "```")
	if j < 0 {
		return nil
	}
	return lines[i+1 : i+1+j]
}

func svcChildRun(t *testing.T, startCheck bool, args ...string) (code int, stdout, stderr string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestRunChild$")
	cmd.Env = append(os.Environ(), runChildEnv+"="+strings.Join(args, "\n"))
	if startCheck {
		cmd.Env = append(cmd.Env, runStartEnv+"=1")
	}
	var out, errOut bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errOut
	err := cmd.Run()
	var exit *exec.ExitError
	if err != nil && !errors.As(err, &exit) {
		t.Fatal(err)
	}
	return cmd.ProcessState.ExitCode(), out.String(), errOut.String()
}

// A request of osk test-alert reaches the running service, which sends a
// test notice to each channel: the Slack message and the signed webhook
// body hold its nonce, and the command prints each channel's outcome. The
// heartbeat is posted meanwhile. With no service, the command gives up
// after 30 s and leaves no request.
func TestTestAlertFullPath(t *testing.T) {
	w := svcLabSetup(t, nil)
	w.withBeat()
	args := runConfig(t, w.cfg)
	started := time.Now()
	child, p := runChild(t, args...)
	child.wait(t, "the start line", 0, started.Add(20*time.Second), runPrefix("start "))
	asked := time.Now()
	code, out, errOut := transportRun("test-alert", "--config", args[1])
	answered := time.Now()
	if code != 0 || out != "test slack sent\ntest siem sent\n" || errOut != "" {
		t.Fatalf("test-alert: exit code %d, output %q, errors %q; want 0, both channels sent and none", code, out, errOut)
	}
	hooks := svcOn(t, w.hookPath)
	if len(hooks) != 1 {
		t.Fatalf("the receiver holds %d requests of the webhook, want 1", len(hooks))
	}
	keys, values := svcBody(t, hooks[0])
	var lines []string
	_ = json.Unmarshal(values["lines"], &lines)
	if len(lines) != 1 {
		t.Fatalf("the webhook body is %s, want a test notice with one line", hooks[0].Body)
	}
	nonce, ok := strings.CutPrefix(lines[0], "request   ")
	if !slices.Equal(keys, []string{"schema", "type", "id", "at", "notice", "domain", "lines", "text"}) || svcString(values["type"]) != "notice" ||
		svcString(values["notice"]) != "test" || len(lines) != 1 || !ok || !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(nonce) {
		t.Fatalf("the webhook body is %s, want a test notice with the one line \"request   <nonce>\"", hooks[0].Body)
	}
	if !svcVerify(w.key, []byte(hooks[0].Body), hooks[0].Headers, svcHookTime(t, hooks[0])) {
		t.Errorf("the webhook request does not pass the check of the receiver: headers %q", hooks[0].Headers)
	}
	texts := svcTexts(t, w.slackPath)
	if len(texts) != 1 {
		t.Fatalf("the receiver holds %d Slack messages, want 1", len(texts))
	}
	slkSameText(t, texts[0], []string{
		":test_tube: *TEST* · osk can send to this channel",
		"",
		"```",
		"request    " + nonce,
		"```",
		"",
		":clock3: <time> · <date> UTC",
		"",
		":point_right: Nothing to do: this message only tests the path from osk to this channel.",
	}, slkRun{start: asked, end: answered})
	if _, err := os.Lstat(filepath.Join(w.state, "test-alert")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the request file is still there: %v", err)
	}
	var beats []cliLabHook
	cliLabUntil(t, "two heartbeats", started.Add(12*time.Second), 200*time.Millisecond, func() bool {
		beats = svcOn(t, w.beatPath)
		return len(beats) >= 2
	})
	for _, b := range beats {
		keys, values := svcBody(t, b)
		at, err := time.Parse(runSecondLayout, svcString(values["at"]))
		if !slices.Equal(keys, []string{"schema", "type", "at"}) || string(values["schema"]) != "1" || svcString(values["type"]) != "heartbeat" ||
			err != nil || b.Method != "POST" {
			t.Errorf("a heartbeat is %s %s, want a POST of {\"schema\":1,\"type\":\"heartbeat\",\"at\":\"<time>\"}", b.Method, b.Body)
		} else {
			slkWithin(t, "the time of a heartbeat", at, started.Truncate(time.Second), svcHookTime(t, b))
		}
	}
	runSignalStop(t, child, p, os.Interrupt)

	code, out, errOut = expWithin(t, 33*time.Second, func() (int, string, string) { return transportRun("test-alert", "--config", args[1]) })
	if want := "osk: osk run did not take the test within 30s; is it running on " + w.state + "?\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("test-alert with no service: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	if _, err := os.Lstat(filepath.Join(w.state, "test-alert")); !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("the request file was left: %v", err)
	}
}

// svcSameAlertBody compares a webhook body with the example of its
// documentation: the keys in order and every value, the times and the id
// apart, which are checked against the run. It gives the id.
func svcSameAlertBody(t *testing.T, h cliLabHook, want map[string]string, wantText []string, times ...slkRun) string {
	t.Helper()
	keys, values := svcBody(t, h)
	order := []string{"schema", "type", "id", "at", "event", "severity", "was", "rule", "check", "expected", "seen", "more", "value",
		"first_seen", "last_clean", "resolved", "text"}
	if !slices.Equal(keys, order) {
		t.Errorf("the webhook body has the keys %q, want %q", keys, order)
	}
	for k, v := range want {
		if string(values[k]) != v {
			t.Errorf("the webhook body holds %s %s, want %s", k, values[k], v)
		}
	}
	id := svcString(values["id"])
	if !regexp.MustCompile(`^[0-9a-f]{32}$`).MatchString(id) {
		t.Errorf("the webhook body holds the id %q, want 32 lowercase hex", id)
	}
	for _, k := range []string{"at", "first_seen", "last_clean", "resolved"} {
		if s := svcString(values[k]); s != "" {
			if at, err := time.Parse(runSecondLayout, s); err != nil || at.Format(runSecondLayout) != s {
				t.Errorf("the webhook body holds %s %q, want the form %s", k, s, runSecondLayout)
			}
		}
	}
	slkSameText(t, svcString(values["text"]), wantText, times...)
	return id
}

// The webhook body of an alert is the documented one, and its signature
// passes the check of the receiver; a changed octet, another key or a time
// more than 300 s off fails it.
func TestWebhookSigned(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"parent": "5s"})
	n := w.n
	begin := time.Now()
	svc := runStart(t, runConfig(t, w.cfg)...)
	svc.wait(t, "the first run of the delegation", 0, begin.Add(10*time.Second), runRunOf(runDelegationKey))
	set := time.Now()
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	const label = "critical nameservers delegation corp.test. NS"
	opened, _ := svc.wait(t, "the alert", 0, set.Add(5*time.Second+3750*time.Millisecond+time.Second), runIs("alert open "+label))
	svc.wait(t, "its webhook request", 0, opened.at.Add(3*time.Second), runIs("delivery siem sent open "+label))
	hooks := svcOn(t, w.hookPath)
	if len(hooks) != 1 {
		t.Fatalf("the receiver holds %d requests of the webhook, want 1", len(hooks))
	}
	common := map[string]string{
		"schema": "1", "type": `"alert"`, "severity": `"critical"`, "was": `"critical"`, "rule": `"nameservers"`,
		"check":    `{"kind":"delegation","domain":"corp.test.","name":"corp.test.","rtype":"NS"}`,
		"expected": `"ns1.corp.test. | ns2.corp.test."`, "more": "0",
		"value": `["` + n + `3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test."]`,
	}
	open := map[string]string{"event": `"open"`, "resolved": `""`,
		"seen": `[{"server":"ns.test.","address":"` + n + `3:53","text":"ns1.dnshost.test. | ns2.dnshost.test.","ttl":300}]`}
	for k, v := range common {
		open[k] = v
	}
	openID := svcSameAlertBody(t, hooks[0], open, slkNameServersOpen(n), slkRun{start: set, end: opened.at}, slkRun{start: begin, end: set})
	body, at := []byte(hooks[0].Body), svcHookTime(t, hooks[0])
	if !svcVerify(w.key, body, hooks[0].Headers, at) {
		t.Errorf("the request does not pass the check of the receiver: headers %q", hooks[0].Headers)
	}
	changed := bytes.Clone(body)
	changed[len(changed)/2] ^= 1
	other := bytes.Clone(w.key)
	other[0] ^= 1
	if svcVerify(w.key, changed, hooks[0].Headers, at) || svcVerify(other, body, hooks[0].Headers, at) ||
		svcVerify(w.key, body, hooks[0].Headers, at.Add(301*time.Second)) || svcVerify(w.key, body, hooks[0].Headers, at.Add(-301*time.Second)) {
		t.Errorf("a changed octet, another key or a time 301 s off passes the check")
	}

	back := time.Now()
	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	resolved, _ := svc.wait(t, "the resolve", 0, back.Add(5*time.Second+3750*time.Millisecond+time.Second), runIs("alert resolve "+label))
	svc.wait(t, "its webhook request", 0, resolved.at.Add(3*time.Second), runIs("delivery siem sent resolve "+label))
	svc.stop(t)
	hooks = svcOn(t, w.hookPath)
	if len(hooks) != 2 {
		t.Fatalf("the receiver holds %d requests of the webhook, want 2", len(hooks))
	}
	end := map[string]string{"event": `"resolve"`, "seen": "[]"}
	for k, v := range common {
		end[k] = v
	}
	resolveID := svcSameAlertBody(t, hooks[1], end, slkNameServersResolved, slkRun{start: set, end: opened.at}, slkRun{start: back, end: resolved.at})
	if resolveID == openID || !svcVerify(w.key, []byte(hooks[1].Body), hooks[1].Headers, svcHookTime(t, hooks[1])) {
		t.Errorf("the resolve has the id %s of the open, or does not pass the check of the receiver", resolveID)
	}
}

// The heartbeat is posted while the service is healthy and stops while a
// channel fails.
func TestHeartbeatWhileHealthy(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"fast": "5s"})
	w.withBeat()
	w.cfg.Slack = nil
	w.cfg.Webhooks = []runCfgHook{{Name: "dead", URL: runSecret{File: expWrite(t, w.dir, "dead-url", "https://hooks.lab.test:444/dead\n")},
		Key: runSecret{File: w.keyPath}}}
	begin := time.Now()
	svc := runStart(t, runConfig(t, w.cfg)...)
	_, i := svc.wait(t, "a heartbeat", 0, begin.Add(12*time.Second), runIs("heartbeat sent"))
	svc.wait(t, "a second heartbeat", i+1, begin.Add(12*time.Second), runIs("heartbeat sent"))
	if beats := svcOn(t, w.beatPath); len(beats) < 2 {
		t.Errorf("the receiver holds %d heartbeats, want at least 2", len(beats))
	}
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", w.n+"99")
	failed, j := svc.wait(t, "the failed delivery", i, time.Now().Add(12*time.Second), runPrefix("delivery dead failed "))
	skipped, _ := svc.wait(t, "the skipped heartbeat", j, failed.at.Add(15*time.Second), runIs("heartbeat skipped: channel dead fails"))
	time.Sleep(time.Until(skipped.at.Add(15 * time.Second)))
	svc.stop(t)
	for _, b := range svcOn(t, w.beatPath) {
		if at := svcHookTime(t, b); at.After(skipped.at.Add(500*time.Millisecond)) && at.Before(skipped.at.Add(15*time.Second)) {
			t.Errorf("a heartbeat arrived at %s, after the service skipped one at %s", at, skipped.at)
		}
	}
}

// Each change of the expectations, one made while osk was down and the
// domain that left the config, reaches every channel with its lines; an
// alert whose line was removed ends with that notice and no message of its
// own.
func TestExpectationsChangeNotice(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"fast": "5s"})
	n := w.n
	args := runConfig(t, w.cfg)
	svc := runStart(t, args...)
	svc.wait(t, "the first run of www", 0, time.Now().Add(10*time.Second), runRunOf(runRecords("www.corp.test.", "A")))
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	_, i := svc.wait(t, "the alert of www", 0, time.Now().Add(12*time.Second), runIs("alert open high record-set records www.corp.test. A"))
	svc.wait(t, "its Slack message", i, time.Now().Add(3*time.Second), runIs("delivery slack sent open high record-set records www.corp.test. A"))
	changed := time.Now()
	runReplace(t, w.expect, strings.Replace(svcLabFile(n), "www.corp.test. A "+n+"81", "mail.corp.test. A "+n+"82", 1))
	// Two reads that agree, each 5 s apart, then the send.
	svc.wait(t, "the notice to Slack", i, changed.Add(5*time.Second+5*time.Second+2*time.Second),
		runIs("delivery slack sent notice expectations corp.test."))
	svc.wait(t, "the notice to siem", i, time.Now().Add(3*time.Second), runIs("delivery siem sent notice expectations corp.test."))
	svc.stop(t)
	view := []string{"- www.corp.test. A " + n + "81", "+ mail.corp.test. A " + n + "82", "closed high record-set records www.corp.test. A"}
	svcNoticeReached(t, w, view)
	for _, text := range svcTexts(t, w.slackPath) {
		if strings.HasPrefix(text, ":white_check_mark:") {
			t.Errorf("the alert whose line left the file sent a resolve:\n%s", text)
		}
	}

	runReplace(t, w.expect, strings.Replace(svcLabFile(n), "www.corp.test. A "+n+"81", "mail.corp.test. A "+n+"82\ncdn.corp.test. CNAME edge.dnshost.test.", 1))
	expCtl(t, "hooks", "clear")
	time.Sleep(2 * time.Second)
	again := runStart(t, args...)
	again.wait(t, "the notice of the change made while osk was down", 0, time.Now().Add(10*time.Second),
		runIs("delivery slack sent notice expectations corp.test."))
	again.wait(t, "the down message", 0, time.Now().Add(5*time.Second), runIs("delivery slack sent notice down -"))
	again.stop(t)
	svcNoticeReached(t, w, []string{"+ cdn.corp.test. CNAME edge.dnshost.test."})
	if downs := runDownHooksOn(t, w.slackPath); len(downs) != 1 || downs[0] < 2*time.Second {
		t.Errorf("the down messages tell %v, want one of at least 2s", downs)
	}

	// The reader is closed before the next service opens the store.
	r, err := store.OpenReader(w.state)
	if err != nil {
		t.Fatal(err)
	}
	open, err := r.AllOpenAlerts()
	if err := errors.Join(err, r.Close()); err != nil {
		t.Fatal(err)
	}
	expCtl(t, "hooks", "clear")
	shop := w.cfg
	shop.Domains = []runCfgDomain{{Name: "shop.test.", Expect: expWrite(t, w.dir, "shop.test.expect",
		"domain shop.test.\nshop.test. NS ns1.dnshost.test. | ns2.dnshost.test.\nshop.test. DS none\n")}}
	third := runStart(t, runConfig(t, shop)...)
	third.wait(t, "the notice of the domain that left", 0, time.Now().Add(10*time.Second), runIs("delivery slack sent notice expectations corp.test."))
	third.stop(t)
	var gone []string
	for _, l := range svcSumLines(svcCanonical(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none",
		"mail.corp.test. A "+n+"82", "cdn.corp.test. CNAME edge.dnshost.test.")) {
		gone = append(gone, "- "+l)
	}
	// The domain left with every alert it had open: a zone-changed alert
	// opens when the serial moved, as the change of www made it.
	for _, a := range open {
		gone = append(gone, closedLine(a))
	}
	svcNoticeReached(t, w, gone)
}

// runDownHooksOn gives the time down of each down message on path.
func runDownHooksOn(t *testing.T, path string) []time.Duration {
	t.Helper()
	var downs []time.Duration
	for _, text := range svcTexts(t, path) {
		if m := runDownHeadline.FindStringSubmatch(strings.Split(text, "\n")[0]); m != nil {
			d, ok := runParseDown(m[1])
			if !ok {
				t.Errorf("the down message %q", text)
			}
			downs = append(downs, d)
		}
	}
	return downs
}

// svcNoticeReached checks that Slack got exactly one message of a change of
// the expectations of corp.test. with these lines, and siem one notice with
// the same lines.
func svcNoticeReached(t *testing.T, w *svcLab, lines []string) {
	t.Helper()
	var texts []string
	for _, text := range svcTexts(t, w.slackPath) {
		if strings.HasPrefix(text, ":memo: *CHANGED* · ") {
			texts = append(texts, text)
		}
	}
	if len(texts) != 1 {
		t.Fatalf("the receiver holds %d Slack messages of a change of the expectations, want 1", len(texts))
	}
	head := strings.Split(texts[0], "\n")[0]
	if want := ":memo: *CHANGED* · the expectations of `corp.test.` changed"; head != want || !slices.Equal(svcView(texts[0]), lines) {
		t.Errorf("the message is:\n%s\nwant the headline %q and the lines:\n%s", texts[0], want, strings.Join(lines, "\n"))
	}
	var notices int
	for _, h := range svcOn(t, w.hookPath) {
		_, values := svcBody(t, h)
		var got []string
		_ = json.Unmarshal(values["lines"], &got)
		if svcString(values["notice"]) == "expectations" {
			notices++
			if svcString(values["domain"]) != "corp.test." || !slices.Equal(got, lines) {
				t.Errorf("the webhook notice is %s, want the domain corp.test. and the lines %q", h.Body, lines)
			}
		}
	}
	if notices != 1 {
		t.Errorf("siem got %d notices of a change of the expectations, want 1", notices)
	}
}

// A config with problems is refused with every problem named by its line
// and key path, by validate and by run, and run then opens and sends
// nothing. A missing secret and an expectations file of another domain are
// both named by validate.
func TestConfigProblemsNamed(t *testing.T) {
	w := svcLabSetup(t, nil)
	text := `{
  "slak": {},
  "State": "/var/lib/osk",
  "state": "` + w.state + `",
  "state": "` + w.state + `",
  "domains": [{"name": "corp.test.", "expect": "` + w.expect + `"}],
  "intervals": {"fast": "4s"},
  "slack": {"url": {"env": "OSK_SLACK_URL"}},
  "webhooks": [{"name": "slack", "url": {"file": "` + w.urlPath + `"}, "key": {"file": "` + w.keyPath + `"}}]
}
`
	path := runConfigText(t, text)
	problems := []string{
		path + `:2: unknown key "slak"`,
		path + `:3: unknown key "State"`,
		path + `:5: key "state" is given twice`,
		path + ":7: intervals.fast: 4s is below the floor of 5s",
		path + ":9: webhooks[0].name: the name slack belongs to the Slack channel",
	}
	code, out, errOut := transportRun("validate", "--config", path)
	if want := strings.Join(append(slices.Clone(problems), "5 problems"), "\n") + "\n"; code != 1 || out != want || errOut != "" {
		t.Errorf("validate: exit code %d, output:\n%s\nerrors %q; want 1, none and:\n%s", code, out, errOut, want)
	}
	code, out, errOut = runRefused(t, "--config", path)
	if want := "osk: " + strings.Join(problems, "\nosk: ") + "\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("run: exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s", code, out, errOut, want)
	}
	slkNotThere(t, w.state)
	if hooks := cliLabHooks(t); len(hooks) != 0 {
		t.Errorf("the refused config sent %d requests", len(hooks))
	}

	args := runConfig(t, w.cfg)
	shop := expWrite(t, w.dir, "shop.expect", "domain shop.test.\n")
	broken := w.cfg
	broken.Domains = []runCfgDomain{{Name: "corp.test.", Expect: shop, Fast: []string{"www.corp.test."}}}
	brokenArgs := runConfig(t, broken)
	t.Setenv("OSK_SLACK_URL", "")
	code, out, errOut = transportRun("validate", "--config", brokenArgs[1])
	secret := brokenArgs[1] + ":" + strconv.Itoa(runLineOf(t, runCfgText(t, broken), `"url"`)) +
		": slack.url: the environment variable is not set"
	want := slices.Concat([]string{secret, shop + ":1: the file is for shop.test., not corp.test."}, cliLabWarnings(w.n), []string{"2 problems"})
	if code != 1 || out != strings.Join(want, "\n")+"\n" || errOut != "" {
		t.Errorf("validate of a config without its Slack URL and with a file of another domain: exit code %d, output:\n%s\nerrors %q; want 1, none and:\n%s",
			code, out, errOut, strings.Join(want, "\n"))
	}
	code, out, errOut = runRefused(t, brokenArgs...)
	if want := "osk: " + secret + "\nosk: " + shop + ":1: the file is for shop.test., not corp.test.\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("run of the same config: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	t.Setenv("OSK_SLACK_URL", "https://hooks.lab.test"+w.slackPath)
	code, out, errOut = transportRun("validate", "--config", args[1])
	if want := strings.Join(append(cliLabWarnings(w.n), "valid: 1 domains, channels slack,siem"), "\n") + "\n"; code != 0 || out != want || errOut != "" {
		t.Errorf("validate of C: exit code %d, output:\n%s\nerrors %q; want 0, none and:\n%s", code, out, errOut, want)
	}
}

// Every command but version refuses root, before it opens or creates the
// state folder. A state folder that other users may enter is refused by the
// service and by the reading commands; one that only its owner may enter is
// used, and every file in it stays its owner's.
func TestRefusesRootAndOpenState(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Fatal("this test needs the runner of the lab, which runs as root")
	}
	w := svcLabSetup(t, nil)
	args := runConfig(t, w.cfg)
	const refused = "osk: osk does not run as root; start it as an ordinary user\n"
	for _, a := range [][]string{
		{"run", "--config", args[1]},
		{"status", "--config", args[1]},
		{"validate", "--config", args[1]},
		{"check", "--root-server", w.n + "2", "--extra-range", w.n + "0/24", "corp.test."},
	} {
		if code, out, errOut := svcChildRun(t, true, a...); code != 1 || out != "" || errOut != refused {
			t.Errorf("osk %s as root: exit code %d, output %q, errors %q; want 1, nothing and %q", a[0], code, out, errOut, refused)
		}
	}
	if code, out, errOut := svcChildRun(t, true, "version"); code != 0 || !strings.HasPrefix(out, "osk ") || errOut != "" {
		t.Errorf("osk version as root: exit code %d, output %q, errors %q; want 0, the version and none", code, out, errOut)
	}
	slkNotThere(t, w.state)

	if err := os.Mkdir(w.state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(w.state, 0o755); err != nil {
		t.Fatal(err)
	}
	open := "osk: store: " + w.state + " is open to other users (mode 0755); run chmod 700 " + w.state + "\n"
	if code, out, errOut := runRefused(t, args...); code != 1 || out != "" || errOut != open {
		t.Errorf("run on a folder of mode 0755: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, open)
	}
	if code, out, errOut := transportRun("status", "--config", args[1]); code != 1 || out != "" || errOut != open {
		t.Errorf("status on a folder of mode 0755: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, open)
	}
	if err := os.Chmod(w.state, 0o700); err != nil {
		t.Fatal(err)
	}
	svc := runStart(t, args...)
	svc.wait(t, "the first run", 0, time.Now().Add(10*time.Second), runRunOf(runDelegationKey))
	svc.stop(t)
	err := filepath.WalkDir(w.state, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err == nil && (info.Mode().Perm()&0o077 != 0 || path == w.state && info.Mode().Perm() != 0o700) {
			t.Errorf("%s has the mode %v", path, info.Mode().Perm())
		}
		return err
	})
	if err != nil {
		t.Error(err)
	}
}

// Every line of the service is one JSON object with its fields in order, at
// the time of writing, its level and its domain; the texts are those of the
// checks, alerts and deliveries.
func TestLogLinesAreJSON(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"parent": "5s"})
	args := runConfig(t, w.cfg)
	begin := time.Now()
	svc := runStart(t, args...)
	svc.wait(t, "the first run of the delegation", 0, begin.Add(10*time.Second), runRunOf(runDelegationKey))
	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	const label = "critical nameservers delegation corp.test. NS"
	soon := time.Now().Add(5*time.Second + 3750*time.Millisecond + 3*time.Second)
	for _, text := range []string{"alert open " + label, "delivery slack sent open " + label, "delivery siem sent open " + label} {
		svc.wait(t, text, 0, soon, runIs(text))
	}
	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	svc.wait(t, "the resolve", 0, time.Now().Add(5*time.Second+3750*time.Millisecond+3*time.Second), runIs("delivery siem sent resolve "+label))
	lines := svc.stop(t)
	end := time.Now()
	want := map[string]string{ // text or prefix, and the domain it names
		"config " + args[1] + ": 1 domains, channels slack,siem": "",
		"start corp.test. 5 checks, state " + w.state:            "corp.test.",
		"checked parent " + runDelegationKey + " ":               "corp.test.",
		"alert open " + label:                                    "corp.test.",
		"alert resolve " + label:                                 "corp.test.",
		"delivery slack sent open " + label:                      "",
		"delivery siem sent resolve " + label:                    "",
		"stop":                                                   "",
	}
	for _, warn := range cliLabWarnings(w.n) {
		want[warn] = ""
	}
	for prefix, domain := range want {
		i := slices.IndexFunc(lines, func(l runLine) bool { return strings.HasPrefix(l.text, prefix) })
		switch {
		case i < 0:
			t.Errorf("no line %q:\n%s", prefix, runDump(lines))
		case !strings.HasPrefix(lines[i].text, "delivery ") && lines[i].domain != domain:
			t.Errorf("the line %q names the domain %q, want %q", lines[i].text, lines[i].domain, domain)
		case lines[i].event == "warning" && lines[i].level != "warning":
			t.Errorf("the line %q has the level %q", lines[i].text, lines[i].level)
		}
	}
	for _, l := range lines {
		if l.at.Before(begin.Truncate(time.Millisecond)) || l.at.After(end) {
			t.Errorf("the line %q names the time %s, outside the run from %s to %s", l.raw, l.at, begin.UTC(), end.UTC())
		}
	}
}

// No secret of the config, from the environment or from a file, is in any
// output of any command, in the state folder or in the config; a key or a
// URL that is wrong is named without its value.
func TestSecretsFromEnvAndFile(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"fast": "5s"})
	w.withBeat()
	args := runConfig(t, w.cfg)
	child, p := runChild(t, args...)
	child.wait(t, "the start line", 0, time.Now().Add(20*time.Second), runPrefix("start "))
	var outputs []string
	osk := func(a ...string) {
		code, out, errOut := transportRun(a...)
		outputs = append(outputs, out, errOut)
		if code > 1 {
			t.Errorf("osk %s: exit code %d, errors %q", a[0], code, errOut)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	var watchOut, watchErr bytes.Buffer
	watched := make(chan struct{})
	go func() {
		defer close(watched)
		cli.Watch(ctx, []string{"--config", args[1]}, &watchOut, &watchErr)
	}()
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", w.n+"99")
	child.wait(t, "the alert", 0, time.Now().Add(12*time.Second), runIs("alert open high record-set records www.corp.test. A"))
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", w.n+"81")
	child.wait(t, "the resolve", 0, time.Now().Add(12*time.Second), runIs("delivery siem sent resolve high record-set records www.corp.test. A"))
	osk("test-alert", "--config", args[1])
	osk("status", "--config", args[1])
	osk("validate", "--config", args[1])
	child.wait(t, "a heartbeat", 0, time.Now().Add(6*time.Second), runPrefix("heartbeat "))
	cancel()
	<-watched
	runSignalStop(t, child, p, os.Interrupt)
	config, err := os.ReadFile(args[1])
	if err != nil {
		t.Fatal(err)
	}
	svcNoMarker(t, w.state, w.marks, slices.Concat(outputs, []string{child.out.String(), child.errOut.String(), watchOut.String(),
		watchErr.String(), string(config)})...)

	text := runCfgText(t, w.cfg)
	hooks := strings.Index(text, `"webhooks"`)
	line := func(at string) string {
		return strconv.Itoa(1 + strings.Count(text[:hooks+strings.Index(text[hooks:], at)], "\n"))
	}
	if err := os.WriteFile(w.keyPath, w.key[:31], 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut := transportRun("validate", "--config", args[1])
	want := args[1] + ":" + line(`"key"`) + ": webhooks[0].key: the key is shorter than 32 octets"
	if code != 1 || !slices.Contains(strings.Split(out, "\n"), want) || errOut != "" {
		t.Errorf("validate with a key of 31 octets: exit code %d, output:\n%s\nerrors %q; want 1 and the line %q", code, out, errOut, want)
	}
	if err := os.WriteFile(w.keyPath, w.key, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(w.urlPath, []byte("http://hooks.lab.test/x"+w.marks[1]+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	code, out2, errOut2 := transportRun("validate", "--config", args[1])
	want = args[1] + ":" + line(`"url"`) + ": webhooks[0].url: the value is not an https URL with a host and no user name"
	if code != 1 || !slices.Contains(strings.Split(out2, "\n"), want) || errOut2 != "" {
		t.Errorf("validate with an http URL: exit code %d, output:\n%s\nerrors %q; want 1 and the line %q", code, out2, errOut2, want)
	}
	for _, o := range []string{out, errOut, out2, errOut2} {
		for _, m := range w.marks {
			if strings.Contains(o, m) {
				t.Errorf("validate printed a secret marker:\n%s", strings.ReplaceAll(o, m, "[marker]"))
			}
		}
	}
}

// The two settings that weaken a default protection are reported by run,
// before the first start line, by status and by validate.
func TestWeakSettingsReported(t *testing.T) {
	w := svcLabSetup(t, nil)
	args := runConfig(t, w.cfg)
	svc := runStart(t, args...)
	svc.wait(t, "the first run", 0, time.Now().Add(10*time.Second), runRunOf(runDelegationKey))
	lines := svc.stop(t)
	var warnings []string
	for _, l := range lines {
		if l.event == "start" {
			break
		}
		if l.event == "warning" {
			warnings = append(warnings, l.text)
		}
	}
	all := 0
	for _, l := range lines {
		if l.event == "warning" {
			all++
		}
	}
	if !slices.Equal(warnings, cliLabWarnings(w.n)) || all != 2 {
		t.Errorf("run warned before its first start line:\n%s\nand %d times in all; want only:\n%s", strings.Join(warnings, "\n"), all,
			strings.Join(cliLabWarnings(w.n), "\n"))
	}
	child, p := runChild(t, args...)
	child.wait(t, "the start line", 0, time.Now().Add(20*time.Second), runPrefix("start "))
	_, out, _ := transportRun("status", "--config", args[1])
	runSignalStop(t, child, p, os.Interrupt)
	_, valid, _ := transportRun("validate", "--config", args[1])
	for what, o := range map[string]string{"status": out, "validate": valid} {
		var got []string
		for _, l := range strings.Split(o, "\n") {
			if strings.HasPrefix(l, "warning ") {
				got = append(got, l)
			}
		}
		if !slices.Equal(got, cliLabWarnings(w.n)) {
			t.Errorf("%s printed:\n%s\nwant the two warnings", what, o)
		}
	}
}

// The first request of an alert starts within 5 s of the run that saw it,
// on Slack and on the webhook, for the open and for the resolve.
func TestPostWithinFiveSeconds(t *testing.T) {
	w := svcLabSetup(t, map[string]string{"parent": "5s"})
	svc := runStart(t, runConfig(t, w.cfg)...)
	svc.wait(t, "the first run of the delegation", 0, time.Now().Add(10*time.Second), runRunOf(runDelegationKey))
	const label = "critical nameservers delegation corp.test. NS"
	for _, c := range []struct {
		servers      []string
		event, slack string
	}{
		{[]string{"ns1.dnshost.test.", "ns2.dnshost.test."}, "open", ":rotating_light: *CRITICAL* · "},
		{[]string{"ns1.corp.test.", "ns2.corp.test."}, "resolve", ":white_check_mark: *RESOLVED* · "},
	} {
		expCtl(t, append([]string{"delegate", "corp.test."}, c.servers...)...)
		_, i := svc.wait(t, "the "+c.event, 0, time.Now().Add(5*time.Second+3750*time.Millisecond+2*time.Second), runIs("alert "+c.event+" "+label))
		svc.wait(t, "the webhook request", i, time.Now().Add(6*time.Second), runIs("delivery siem sent "+c.event+" "+label))
		svc.wait(t, "the Slack message", i, time.Now().Add(6*time.Second), runIs("delivery slack sent "+c.event+" "+label))
		lines := svc.out.all()
		var judged runLine
		for _, l := range lines[:i] {
			if strings.HasPrefix(l.text, "checked parent "+runDelegationKey+" ") {
				judged = l
			}
		}
		if judged.text == "" {
			t.Fatalf("no checked line of the delegation before the %s", c.event)
		}
		for _, path := range []string{w.slackPath, w.hookPath} {
			var at time.Time
			for _, h := range svcOn(t, path) {
				if strings.Contains(h.Body, `"event":"`+c.event+`"`) || strings.Contains(h.Body, c.slack) {
					at = svcHookTime(t, h)
				}
			}
			if at.IsZero() || at.After(judged.at.Add(5*time.Second)) {
				t.Errorf("the %s request on %s came at %s, want within 5 s of the run judged at %s", c.event, path, at, judged.at)
			}
		}
	}
	svc.stop(t)
}
