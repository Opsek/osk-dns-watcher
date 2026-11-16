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
	min decide.Severity
	// post alone holds the URL, whose path is the webhook's secret. fmt
	// prints a func as an address, so no verb, and no print of a value that
	// holds a Slack, can show it.
	post func(ctx context.Context, body []byte) Outcome
}

// slackWords are the error words of Slack's incoming webhooks. An answer
// reaches a reason only when it is one of them, so that no receiver can put
// a secret into a log line, the state or the output of status and watch.
var slackWords = []string{"invalid_payload", "user_not_found", "channel_not_found", "channel_is_archived",
	"action_prohibited", "posting_to_general_channel_denied", "too_many_attachments", "no_service",
	"no_service_id", "no_team", "team_disabled", "invalid_token", "no_text", "no_active_hooks"}

func NewSlack(c *httpclient.Client, url string, min decide.Severity) *Slack {
	post := func(ctx context.Context, body []byte) Outcome {
		r, err := c.Post(ctx, url, "application/json", body)
		return outcome(r, err, slackWords)
	}
	return &Slack{min: min, post: post}
}

func (s *Slack) Name() string { return "slack" }

// A printed Slack channel reads as its name.
func (Slack) String() string { return "slack" }

func (Slack) GoString() string { return "slack" }

func (s *Slack) MinSeverity() decide.Severity { return s.min }

func (s *Slack) Message(e alert.Event) []byte { return SlackMessage(e) }

func (s *Slack) Send(ctx context.Context, body []byte) Outcome { return s.post(ctx, body) }

func SlackMessage(e alert.Event) []byte {
	// Marshal cannot fail on a struct of one string.
	body, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{SlackText(e)})
	return body
}

// wording is the text of one rule. {D}, {N} and {NT} stand for the domain,
// the name, and the name with its type, each as inline code; {K} for the
// kind of the check, a fixed word of the tool. now is the view line of a
// resolve.
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
	decide.RuleCheckFailing: {
		phrase:   "the {K} check of {NT} has had no usable answer for too long",
		resolved: "the {K} check of {NT} has usable answers again",
		action:   "Find out why no server of {D} answers this machine; until one does, a change there is not seen.",
		now:      "a server answers now",
	},
	decide.RuleZoneChanged: {
		phrase:   "the zone {D} changed, and no watched record differs",
		resolved: "the zone {D} has not changed again for a while",
		action:   "If you did not change the zone, find out who did; only a zone transfer shows which record changed.",
		now:      "no new change of the serial",
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
		"{K}", k.Kind.String(),
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
	if !resolve && (a.Rule == decide.RuleInvalidFile || a.Rule == decide.RuleCheckFailing) {
		return []string{"problem   " + Clean(a.Value, 160)}
	}
	if !resolve && a.Rule == decide.RuleZoneChanged {
		// This alert has no server lines: each line of Value is one move.
		var moves []string
		for _, m := range strings.Split(a.Value, "\n") {
			moves = append(moves, Clean(m, 160))
		}
		return capped(moves)
	}
	expected := Clean(a.Expected, 160)
	if expected == "" {
		expected = "-"
	}
	lines := []string{"expected  " + expected}
	if resolve {
		return append(lines, "now       "+resolvedNow)
	}
	var servers []string
	for _, l := range a.Lines {
		servers = append(servers, nowLine(l))
	}
	return append(lines, capped(servers)...)
}

// capped keeps the first maxServers lines and counts the others.
func capped(lines []string) []string {
	if more := len(lines) - maxServers; more > 0 {
		return append(lines[:maxServers], "and "+strconv.Itoa(more)+" more servers")
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
