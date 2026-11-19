//go:build lab

package deliver_test

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// dlvLab is the start of every lab address, "10.53.<LAB_ID>.".
func dlvLab(t *testing.T) string {
	t.Helper()
	prefix := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(prefix + "1"); err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	return prefix
}

func dlvLabctl(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command("labctl", args...).Output()
	if err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// dlvReset puts the lab back into its base state at the end of the test, and
// empties the receiver now.
func dlvReset(t *testing.T) {
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	dlvLabctl(t, "hooks", "clear")
}

// dlvRequest is a request that the receiver of the lab stored.
type dlvRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Status  int                 `json:"status"`
}

func dlvHooks(t *testing.T) []dlvRequest {
	t.Helper()
	var list []dlvRequest
	lines := bufio.NewScanner(bytes.NewReader(dlvLabctl(t, "hooks", "list")))
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var r dlvRequest
		if err := json.Unmarshal(lines.Bytes(), &r); err != nil {
			t.Fatalf("hooks list: %v: %s", err, lines.Bytes())
		}
		list = append(list, r)
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	return list
}

// dlvText is the text of a stored Slack request.
func dlvText(t *testing.T, r dlvRequest) string {
	t.Helper()
	var m struct {
		Text string `json:"text"`
	}
	if err := json.Unmarshal([]byte(r.Body), &m); err != nil {
		t.Fatalf("body %q: %v", r.Body, err)
	}
	return m.Text
}

// dlvClient may post to the receiver on its port 443 and on port 444, where
// nothing listens. It trusts the system's store, as the tool does.
func dlvClient() *httpclient.Client {
	return httpclient.New([]string{"hooks.lab.test:443", "hooks.lab.test:444"}, nil)
}

// dlvDead is a channel whose receiver never answers.
type dlvDead struct{ c *httpclient.Client }

func (dlvDead) Name() string                 { return "dead" }
func (dlvDead) MinSeverity() decide.Severity { return decide.SeverityLow }
func (dlvDead) Message(e alert.Event) []byte { return deliver.SlackMessage(e) }
func (dlvDead) Notice(n store.Notice) []byte { return []byte(deliver.NoticeText(n)) }
func (d dlvDead) Send(ctx context.Context, body []byte) deliver.Outcome {
	r, err := d.c.Post(ctx, "https://hooks.lab.test:444/dead", "application/json", body)
	if err != nil {
		return deliver.Outcome{Err: err.Error()}
	}
	return deliver.Outcome{Status: r.Status, RetryAfter: r.RetryAfter, Body: r.Body}
}

// dlvFinding is what decide reports for a record set of corp.test. or for
// its delegation, as ns2 or the parent shows it.
func dlvFinding(t *testing.T, rule decide.Rule, sev decide.Severity, at time.Time) decide.Finding {
	lab := dlvLab(t)
	corp := dlvName(t, "corp.test.")
	f := decide.Finding{Rule: rule, Severity: sev}
	server, text := obs.Server{Name: dlvName(t, "ns2.corp.test."), Addr: netip.MustParseAddrPort(lab + "12:53")}, lab+"99"
	switch rule {
	case decide.RuleNameServers:
		f.Check, f.Expected = obs.DelegationKey(corp), "ns1.corp.test. | ns2.corp.test."
		server, text = obs.Server{Name: dlvName(t, "ns.test."), Addr: netip.MustParseAddrPort(lab + "3:53")}, "ns1.dnshost.test. | ns2.dnshost.test."
	case decide.RuleRecordSet:
		f.Check, f.Expected = obs.RecordsKey(corp, dlvName(t, "www.corp.test."), dnswire.TypeA), lab+"81"
	case decide.RuleInvalidFile, decide.RuleNotCovered, decide.RuleZone, decide.RuleCheckFailing, decide.RuleZoneChanged,
		decide.RuleGlue, decide.RuleDS, decide.RuleGone, decide.RuleDisagree, decide.RuleAliasTarget, decide.RuleNameServerHost,
		decide.RuleMailTarget, decide.RuleChallenge, decide.RuleWildcard, decide.RuleCAA,
		decide.RuleIssuer, decide.RuleCertName, decide.RuleHostnames,
		decide.RuleSPF, decide.RuleDMARC, decide.RuleDKIM, decide.RuleMTASTS:
		t.Fatalf("no finding of rule %v here", rule)
	}
	f.Seen = []decide.Seen{{Answer: obs.Answer{Proof: obs.Proof{Server: server, Received: at}}, Text: text}}
	f.Value = server.Addr.String() + " " + server.Name.String() + " " + text
	return f
}

// dlvEvents applies the changes of one check at time at and returns the
// events.
func dlvEvents(t *testing.T, open []alert.Alert, at time.Time, changes ...decide.Change) []alert.Event {
	t.Helper()
	out := alert.Transition(alert.Input{Open: open, Changes: changes, Now: at})
	if len(out.Events) != len(changes) {
		t.Fatalf("Transition gave %d events for %d changes", len(out.Events), len(changes))
	}
	return out.Events
}

// dlvShow gives the line of each attempt.
func dlvShow(attempts []deliver.Attempt) []string {
	var lines []string
	for _, a := range attempts {
		lines = append(lines, a.Line())
	}
	return lines
}

// dlvNextTry is the end of a Line of a failed attempt.
func dlvNextTry(at time.Time) string {
	return "; next try " + at.UTC().Format("2006-01-02T15:04:05Z")
}

// A refused row of one channel and a dead second channel hold up no other
// row: each row gets its own attempt in the same pass.
func TestFailingRowBlocksNothing(t *testing.T) {
	dlvReset(t)
	s, _ := dlvStore(t)
	c := dlvClient()
	channels := []deliver.Channel{dlvDead{c}, deliver.NewSlack(c, "https://hooks.lab.test/slack", decide.SeverityLow)}
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	var events []alert.Event
	for _, f := range []decide.Finding{
		dlvFinding(t, decide.RuleRecordSet, decide.SeverityHigh, at),
		dlvFinding(t, decide.RuleNameServers, decide.SeverityCritical, at),
	} {
		e := dlvEvents(t, nil, at, decide.Change{Op: decide.OpOpen, Finding: f, At: at})
		if err := s.Apply(f.Check, false, at, deliver.Writes(e, channels)); err != nil {
			t.Fatal(err)
		}
		events = append(events, e...)
	}
	dlvLabctl(t, "hooks", "reply", "400", "1", "--body", "invalid_payload")

	attempts, err := deliver.Pass(context.Background(), s, channels, at)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 4 {
		t.Fatalf("%d attempts, want 4", len(attempts))
	}
	for i, a := range attempts[:2] {
		prefix := "delivery dead failed " + events[i].Label() + `: no answer "network: `
		if line := a.Line(); a.Channel != "dead" || !strings.HasPrefix(line, prefix) || !strings.HasSuffix(line, dlvNextTry(at.Add(10*time.Second))) {
			t.Errorf("attempt %d: %q, want %q…%q", i, line, prefix, dlvNextTry(at.Add(10*time.Second)))
		}
	}
	for i, want := range []string{
		"delivery slack given up " + events[0].Label() + `: status 400 "invalid_payload"`,
		"delivery slack sent " + events[1].Label(),
	} {
		if got := attempts[2+i].Line(); got != want {
			t.Errorf("attempt %d: %q, want %q", 2+i, got, want)
		}
	}
	hooks := dlvHooks(t)
	if len(hooks) != 2 || hooks[0].Status != 400 || hooks[1].Status != 200 {
		t.Fatalf("the receiver got %+v, want two requests, answered 400 then 200", hooks)
	}
	for i, r := range hooks {
		if r.Method != "POST" || r.Path != "/slack" || strings.Join(r.Headers["Content-Type"], ",") != "application/json" ||
			r.Body != string(deliver.SlackMessage(events[i])) {
			t.Errorf("request %d: %+v, want the message of event %d", i, r, i)
		}
	}

	later := at.Add(10 * time.Second)
	attempts, err = deliver.Pass(context.Background(), s, channels, later)
	if err != nil {
		t.Fatal(err)
	}
	if len(attempts) != 2 {
		t.Fatalf("%d attempts 10 s later, want the 2 rows of dead", len(attempts))
	}
	for i, a := range attempts {
		if a.Channel != "dead" || a.Row.Label != events[i].Label() || a.Done.Attempts != 2 || !strings.HasSuffix(a.Line(), dlvNextTry(later.Add(20*time.Second))) {
			t.Errorf("attempt %d 10 s later: %q after %d attempts, want dead's row of event %d after 2", i, a.Line(), a.Done.Attempts, i)
		}
	}
	if n := len(dlvHooks(t)); n != 2 {
		t.Errorf("the receiver has %d requests after the second pass, want still 2", n)
	}
}

// An alert raised to a higher severity sends its own notice.
func TestEscalationReachesSlack(t *testing.T) {
	dlvReset(t)
	s, _ := dlvStore(t)
	slack := deliver.NewSlack(dlvClient(), "https://hooks.lab.test/slack/T0/B0/dlvsecret", decide.SeverityLow)
	channels := []deliver.Channel{slack}
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	f := dlvFinding(t, decide.RuleRecordSet, decide.SeverityHigh, at)
	e := dlvEvents(t, nil, at, decide.Change{Op: decide.OpOpen, Finding: f, At: at})
	if err := s.Apply(f.Check, false, at, deliver.Writes(e, channels)); err != nil {
		t.Fatal(err)
	}
	if attempts, err := deliver.Pass(context.Background(), s, channels, at); err != nil || len(attempts) != 1 || attempts[0].Done.Reason != "" {
		t.Fatalf("first pass: %q, %v; want one sent row", dlvShow(attempts), err)
	}

	// No rule raises a severity yet, so the update is made by hand.
	open, err := s.OpenAlerts(f.Check)
	if err != nil || len(open) != 1 {
		t.Fatalf("OpenAlerts: %+v, %v; want one alert", open, err)
	}
	raised := f
	raised.Severity = decide.SeverityCritical
	later := at.Add(time.Minute)
	e = dlvEvents(t, open, later, decide.Change{Op: decide.OpUpdate, Finding: raised, At: later})
	if e[0].Kind != alert.EventEscalate || e[0].Was != decide.SeverityHigh {
		t.Fatalf("Transition gave %v from %v, want an escalation from high", e[0].Kind, e[0].Was)
	}
	if err := s.Apply(f.Check, false, later, deliver.Writes(e, channels)); err != nil {
		t.Fatal(err)
	}
	if attempts, err := deliver.Pass(context.Background(), s, channels, later); err != nil || len(attempts) != 1 || attempts[0].Done.Reason != "" {
		t.Fatalf("second pass: %q, %v; want one sent row", dlvShow(attempts), err)
	}
	hooks := dlvHooks(t)
	if len(hooks) != 2 {
		t.Fatalf("the receiver has %d requests, want 2", len(hooks))
	}
	if text, want := dlvText(t, hooks[0]), ":red_circle: *HIGH* · `www.corp.test. A` changed"; !strings.HasPrefix(text, want+"\n") {
		t.Errorf("first text:\n%s\nwant it to start with %q", text, want)
	}
	if text, want := dlvText(t, hooks[1]), ":rotating_light: *CRITICAL*, raised from high · `www.corp.test. A` changed"; !strings.HasPrefix(text, want+"\n") {
		t.Errorf("second text:\n%s\nwant it to start with %q", text, want)
	}
}

// A 429 waits as long as its Retry-After asks, not only the first delay.
func TestRetryAfterRespected(t *testing.T) {
	dlvReset(t)
	s, _ := dlvStore(t)
	channels := []deliver.Channel{deliver.NewSlack(dlvClient(), "https://hooks.lab.test/slack", decide.SeverityLow)}
	at := time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)
	f := dlvFinding(t, decide.RuleRecordSet, decide.SeverityHigh, at)
	e := dlvEvents(t, nil, at, decide.Change{Op: decide.OpOpen, Finding: f, At: at})
	if err := s.Apply(f.Check, false, at, deliver.Writes(e, channels)); err != nil {
		t.Fatal(err)
	}
	dlvLabctl(t, "hooks", "reply", "429", "1", "--header", "Retry-After: 120")

	attempts, err := deliver.Pass(context.Background(), s, channels, at)
	if want := "delivery slack failed " + e[0].Label() + ": status 429" + dlvNextTry(at.Add(120*time.Second)); err != nil ||
		len(attempts) != 1 || attempts[0].Line() != want {
		t.Fatalf("first pass: %q, %v; want one attempt %q", dlvShow(attempts), err, want)
	}
	if attempts, err := deliver.Pass(context.Background(), s, channels, at.Add(60*time.Second)); err != nil || len(attempts) != 0 {
		t.Fatalf("pass after 60 s: %q, %v; want no attempt", dlvShow(attempts), err)
	}
	attempts, err = deliver.Pass(context.Background(), s, channels, at.Add(120*time.Second))
	if want := "delivery slack sent " + e[0].Label(); err != nil || len(attempts) != 1 || attempts[0].Line() != want {
		t.Fatalf("pass after 120 s: %q, %v; want one attempt %q", dlvShow(attempts), err, want)
	}
	hooks := dlvHooks(t)
	if len(hooks) != 2 || hooks[0].Status != 429 || hooks[1].Status != 200 {
		t.Errorf("the receiver got %+v, want two requests, answered 429 then 200", hooks)
	}
}
