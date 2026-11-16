package deliver

import (
	"context"
	"encoding/json"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Slack posts notices to a Slack incoming webhook.
type Slack struct {
	client *httpclient.Client
	url    string // the webhook's secret is in its path: it goes only into the request
	min    decide.Severity
}

func NewSlack(c *httpclient.Client, url string, min decide.Severity) *Slack {
	return &Slack{client: c, url: url, min: min}
}

func (s *Slack) Name() string { return "slack" }

// String and GoString keep the URL out of anything that prints a channel.
func (Slack) String() string { return "slack" }

func (Slack) GoString() string { return "slack" }

func (s *Slack) MinSeverity() decide.Severity { return s.min }

func (s *Slack) Message(e alert.Event) []byte { return SlackMessage(e) }

func (s *Slack) Send(ctx context.Context, body []byte) Outcome {
	r, err := s.client.Post(ctx, s.url, "application/json", body)
	if err != nil {
		return Outcome{Err: err.Error()}
	}
	// An error word that the URL holds may be a part of its secret path.
	var word []byte
	if w := errorWord(r.Body); w != "" && !strings.Contains(strings.ToLower(s.url), w) {
		word = []byte(w)
	}
	return Outcome{Status: r.Status, RetryAfter: r.RetryAfter, Body: word}
}

func SlackMessage(e alert.Event) []byte {
	// Marshal cannot fail on a struct of one string.
	body, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{SlackText(e)})
	return body
}

// wording is the text of one rule. {D}, {N} and {NT} stand for the domain,
// the name, and the name with its type, each as inline code. now is the
// view line of a resolve.
type wording struct {
	phrase, resolved, action, now string
}

var wordings = map[decide.Rule]wording{
	decide.RuleNameServers: {
		phrase:   "nameservers of {D} changed at the parent zone",
		resolved: "nameservers of {D} are as expected again",
		action:   "If you did not change the nameservers, contact your registrar now.",
		now:      "as expected again",
	},
	decide.RuleRecordSet: {
		phrase:   "{NT} changed",
		resolved: "{NT} is as expected again",
		action:   "If you did not make this change, check your DNS provider account now.",
		now:      "as expected again",
	},
	decide.RuleZone: {
		phrase:   "{N} is answered from an unexpected zone",
		resolved: "{N} is answered from the expected zone again",
		action:   "If you did not create this zone, check the delegations under {D} at your DNS provider.",
		now:      "as expected again",
	},
	decide.RuleNotCovered: {
		phrase:   "{NT} has no expectation and is not checked",
		resolved: "{NT} has an expectation now",
		action:   "Add a line for {NT} to the expectations file of {D}.",
		now:      "covered by the expectations",
	},
	decide.RuleInvalidFile: {
		phrase:   "the expectations file of {D} is not valid",
		resolved: "the expectations file of {D} is valid again",
		action:   "Fix the file. Until then the last valid file is used.",
		now:      "the file is valid",
	},
}

const resolvedAction = "If you did not make or undo this change yourself, find out who did."

// emoji are Slack emoji codes, which keep the text printable ASCII.
var emoji = map[decide.Severity]string{
	decide.SeverityCritical: ":rotating_light:",
	decide.SeverityHigh:     ":red_circle:",
	decide.SeverityMedium:   ":large_orange_circle:",
	decide.SeverityLow:      ":large_yellow_circle:",
}

// maxServers caps the server lines, which keeps the text within 3000 octets.
const maxServers = 6

const timeLayout = "2006-01-02 15:04:05 UTC"

// SlackText is the notice of e. Every string that comes from DNS or from the
// expectations file passes through Clean and stands inside code. A rule
// without wording gives empty phrases, never DNS text outside code.
func SlackText(e alert.Event) string {
	w := wordings[e.Alert.Rule]
	phrase, action := w.phrase, w.action
	if e.Kind == alert.EventResolve {
		phrase, action = w.resolved, resolvedAction
	}
	fill := fields(e.Alert.Check)
	lines := []string{headline(e) + ": " + fill.Replace(phrase), "", "```"}
	lines = append(lines, view(e, w.now)...)
	lines = append(lines, "```", "", times(e), "", ":point_right: "+fill.Replace(action))
	return strings.Join(lines, "\n")
}

// fields fills the placeholders of a wording. A Replacer scans only the
// wording, never what it puts in, so DNS text cannot pose as a placeholder.
func fields(k obs.Key) *strings.Replacer {
	name := Clean(k.Name.Lower().String(), 100)
	return strings.NewReplacer(
		"{D}", "`"+Clean(k.Domain.Lower().String(), 100)+"`",
		"{N}", "`"+name+"`",
		"{NT}", "`"+name+" "+Clean(k.Type.String(), 20)+"`")
}

func headline(e alert.Event) string {
	sev := e.Alert.Severity
	head := emoji[sev] + " " + strings.ToUpper(sev.String())
	switch e.Kind {
	case alert.EventOpen:
		return head
	case alert.EventUpdate:
		return head + ", changed again"
	case alert.EventEscalate:
		return head + ", raised from " + e.Was.String()
	case alert.EventReminder:
		return head + ", still open"
	case alert.EventResolve:
		return ":white_check_mark: RESOLVED"
	}
	return head
}

// view gives the lines of the code block. Each label takes 10 columns, so the
// values stand under each other. resolvedNow is the now line of a resolve.
func view(e alert.Event, resolvedNow string) []string {
	a := e.Alert
	resolve := e.Kind == alert.EventResolve
	if a.Rule == decide.RuleInvalidFile && !resolve {
		return []string{"problem   " + Clean(a.Value, 160)}
	}
	expected := Clean(a.Expected, 160)
	if expected == "" {
		expected = "-"
	}
	lines := []string{"expected  " + expected}
	if resolve {
		return append(lines, "now       "+resolvedNow)
	}
	for _, l := range a.Lines[:min(len(a.Lines), maxServers)] {
		lines = append(lines, nowLine(l))
	}
	if more := len(a.Lines) - maxServers; more > 0 {
		lines = append(lines, "and "+strconv.Itoa(more)+" more servers")
	}
	return lines
}

func nowLine(l alert.Line) string {
	host, addr := "-", "-"
	if l.Server.Name.LabelCount() > 0 {
		host = Clean(l.Server.Name.Lower().String(), 64)
	}
	if l.Server.Addr.IsValid() {
		addr = Clean(l.Server.Addr.String(), 64)
	}
	return "now       " + Clean(l.Text, 160) + "   at " + host + " (" + addr + "), TTL " + strconv.FormatUint(uint64(l.TTL), 10)
}

func times(e alert.Event) string {
	first := ":clock3: First seen " + e.Alert.Opened.UTC().Format(timeLayout) + " / "
	switch {
	case e.Kind == alert.EventResolve:
		return first + "Resolved " + e.At.UTC().Format(timeLayout)
	case e.Alert.LastClean.IsZero():
		return first + "Last OK: no clean check recorded"
	}
	return first + "Last OK " + e.Alert.LastClean.UTC().Format(timeLayout)
}
