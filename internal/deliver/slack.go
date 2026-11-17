package deliver

import (
	"context"
	"encoding/json"
	"slices"
	"strconv"
	"strings"
	"time"

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
// resolve; it is empty for the rules that compare a set, whose resolve view
// lists the expected records.
type wording struct {
	phrase, resolved, action, now string
}

var wordings = map[decide.Rule]wording{
	decide.RuleNameServers: {
		phrase:   "nameservers of {D} changed at the parent zone",
		resolved: "nameservers of {D} are as expected again",
		action:   "If you did not change the nameservers, contact your registrar now.",
	},
	decide.RuleGlue: {
		phrase:   "nameserver addresses of {D} changed at the parent zone",
		resolved: "nameserver addresses of {D} are as expected again",
		action:   "If you did not change the addresses of your nameservers, contact your registrar now.",
		now:      "as expected again",
	},
	decide.RuleDS: {
		phrase:   "DS of {D} changed at the parent zone",
		resolved: "DS of {D} is as expected again",
		action:   "If you did not change your DNSSEC keys, contact your registrar now.",
	},
	decide.RuleGone: {
		phrase:   "{D} does not exist at the parent zone",
		resolved: "{D} exists at the parent zone again",
		action:   "Contact your registrar now: the registration may have expired, been deleted or been transferred.",
		now:      "the domain exists again",
	},
	decide.RuleDisagree: {
		phrase:   "the nameservers of {D} give different answers for {NT}",
		resolved: "the nameservers of {D} agree on {NT} again",
		action:   "Find out why one nameserver of {D} answers otherwise: it may be out of date, or not yours.",
		now:      "the servers agree",
	},
	decide.RuleAliasTarget: {
		phrase:   "{N} does not exist, and an alias in {D} points at it",
		resolved: "{N}, which an alias in {D} points at, exists again",
		action:   "Change or remove the alias now: whoever creates {N} receives its traffic.",
		now:      "the name exists again: check that it is yours",
	},
	decide.RuleNameServerHost: {
		phrase:   "nameserver {N} of {D} does not exist",
		resolved: "nameserver {N} of {D} exists again",
		action:   "Replace {N} at your registrar now, or restore it: whoever creates it can answer for {D}.",
		now:      "the name exists again: check that it is yours",
	},
	decide.RuleMailTarget: {
		phrase:   "{N} does not exist, and the mail records of {D} point at it",
		resolved: "{N}, which the mail records of {D} point at, exists again",
		action:   "Change the MX or SPF record that names {N} now: whoever creates it can receive or send mail as {D}.",
		now:      "the name exists again: check that it is yours",
	},
	decide.RuleChallenge: {
		phrase:   "a certificate-challenge record appeared at {NT}",
		resolved: "the certificate-challenge record at {NT} is gone",
		action:   "If you did not ask for a certificate for this name, find out who changed your DNS, and look for the certificate in the certificate logs.",
	},
	decide.RuleWildcard: {
		phrase:   "a wildcard answers for names under {N} that do not exist",
		resolved: "no wildcard answers under {N} again",
		action:   "If you did not add a wildcard under {N}, remove it at your DNS provider and find out who added it.",
		now:      "no wildcard",
	},
	decide.RuleRecordSet: {
		phrase:   "{NT} changed",
		resolved: "{NT} is as expected again",
		action:   "If you did not make this change, check your DNS provider account now.",
	},
	decide.RuleZone: {
		phrase:   "{N} is answered from an unexpected zone",
		resolved: "{N} is answered from the expected zone again",
		action:   "If you did not create this zone, check the delegations under {D} at your DNS provider.",
		now:      "the expected zone",
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
		now:      "a server answers",
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

// The fixed words of the view and the times line.
const (
	labelExpected = "expected"
	labelOr       = "or"
	labelNow      = "now"
	labelSeenAt   = "seen at"
	labelProblem  = "problem"

	// labelWidth makes the values of the code block stand under each other.
	labelWidth = 11

	dot = " · " // U+00B7, the only octet outside ASCII in a text

	timeOfDay  = "15:04:05"
	dateLayout = "2 Jan 2006"
)

// The caps keep the text near 3000 octets: the width of a record, records of
// one list, texts that servers gave, and server lines in the whole view.
// maxText is the last guard.
const (
	recordWidth = 120
	maxRecords  = 6
	maxAnswers  = 3
	maxServers  = 6
	maxText     = 3000
	cutLine     = "[cut]"
)

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
	return compose(headline(e)+dot+fill.Replace(phrase), view(e, w.now), times(e), fill.Replace(action))
}

// compose joins the four parts, each set apart by one empty line. When the
// text is over maxText, lines go from the end of the view, which then ends
// with a cut line; the other parts are never cut.
func compose(headline string, view []string, times, action string) string {
	text := assemble(headline, view, times, action)
	for len(text) > maxText && len(view) > 0 {
		view = view[:len(view)-1]
		text = assemble(headline, append(slices.Clone(view), cutLine), times, action)
	}
	return text
}

func assemble(headline string, view []string, times, action string) string {
	block := strings.Join(slices.Concat([]string{"```"}, view, []string{"```"}), "\n")
	return strings.Join([]string{headline, block, times, ":point_right: " + action}, "\n\n")
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

// title is the start of a headline; the two asterisks make the word bold.
func title(emoji, word, suffix string) string {
	return emoji + " *" + word + "*" + suffix
}

func headline(e alert.Event) string {
	sev := e.Alert.Severity
	word := strings.ToUpper(sev.String())
	switch e.Kind {
	case alert.EventUpdate:
		return title(emoji[sev], word, ", changed again")
	case alert.EventEscalate:
		return title(emoji[sev], word, ", raised from "+e.Was.String())
	case alert.EventReminder:
		return title(emoji[sev], word, ", still open")
	case alert.EventResolve:
		return title(":white_check_mark:", "RESOLVED", "")
	case alert.EventOpen:
		return title(emoji[sev], word, "")
	}
	return title(emoji[sev], word, "")
}

// pad writes a label in the width that all labels share.
func pad(label string) string {
	return label + strings.Repeat(" ", labelWidth-len(label))
}

// row is one line of a record list; label is empty on a line that continues
// the list.
type row struct{ label, text string }

// rowsOf gives one row for each record of text, the first under label.
func rowsOf(label, text string) []row {
	var rows []row
	for i, record := range splitOutsideQuotes(text, " | ") {
		if i > 0 {
			label = ""
		}
		rows = append(rows, row{label, record})
	}
	return rows
}

// splitOutsideQuotes cuts s at each sep that stands outside double quotes. A
// backslash keeps the next octet, as in record data, so a quote or a bar
// inside a TXT string never cuts the record.
func splitOutsideQuotes(s, sep string) []string {
	var parts []string
	start, quoted := 0, false
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && strings.HasPrefix(s[i:], sep):
			parts = append(parts, s[start:i])
			i += len(sep) - 1
			start = i + 1
		}
	}
	return append(parts, s[start:])
}

// recordLines writes at most maxRecords rows, then the count of the others.
// An empty record shows as "-".
func recordLines(rows []row) []string {
	var lines []string
	for _, r := range rows[:min(len(rows), maxRecords)] {
		text := Clean(r.text, recordWidth)
		if text == "" {
			text = "-"
		}
		lines = append(lines, pad(r.label)+text)
	}
	if more := len(rows) - maxRecords; more > 0 {
		lines = append(lines, pad("")+"and "+strconv.Itoa(more)+" more records")
	}
	return lines
}

// expectedRows lists the expected records under first; each later
// alternative starts on a line with the label "or".
func expectedRows(first, text string) []row {
	var rows []row
	for i, alt := range splitOutsideQuotes(text, " || ") {
		label := labelOr
		if i == 0 {
			label = first
		}
		rows = append(rows, rowsOf(label, alt)...)
	}
	return rows
}

// view gives the lines of the code block. resolvedNow is the now line of a
// resolve.
func view(e alert.Event, resolvedNow string) []string {
	a := e.Alert
	if e.Kind == alert.EventResolve {
		return resolveView(a, resolvedNow)
	}
	switch a.Rule {
	case decide.RuleInvalidFile, decide.RuleCheckFailing:
		return []string{pad(labelProblem) + Clean(a.Value, 160)}
	case decide.RuleZoneChanged:
		// Each line of Value is one move; the alert has no server lines.
		return moveLines(strings.Split(a.Value, "\n"))
	case decide.RuleGlue, decide.RuleAliasTarget, decide.RuleNameServerHost, decide.RuleMailTarget:
		// Expected holds one part for each host and type that differs, or for each
		// line that points at the name, joined by "; ". A part may hold " | ", so
		// it is not split as a record list.
		var rows []row
		for i, part := range strings.Split(a.Expected, "; ") {
			label := ""
			if i == 0 {
				label = labelExpected
			}
			rows = append(rows, row{label, part})
		}
		return append(recordLines(rows), seenLines(a.Lines)...)
	case decide.RuleNameServers, decide.RuleRecordSet, decide.RuleZone, decide.RuleNotCovered,
		decide.RuleDS, decide.RuleGone, decide.RuleDisagree, decide.RuleChallenge, decide.RuleWildcard:
	}
	return append(recordLines(expectedRows(labelExpected, a.Expected)), seenLines(a.Lines)...)
}

// resolveView shows the state now. The rules that compare a set have no
// words of their own: the state now is the expected one.
func resolveView(a alert.Alert, now string) []string {
	if now != "" {
		return []string{pad(labelNow) + now}
	}
	return recordLines(expectedRows(labelNow, a.Expected))
}

// answer is a text that servers gave, with the lines that carry it.
type answer struct {
	text    string
	servers []alert.Line
}

// answers groups lines by their text, in order of first appearance.
func answers(lines []alert.Line) []answer {
	var out []answer
	for _, l := range lines {
		i := slices.IndexFunc(out, func(a answer) bool { return a.text == l.Text })
		if i < 0 {
			out = append(out, answer{text: l.Text})
			i = len(out) - 1
		}
		out[i].servers = append(out[i].servers, l)
	}
	return out
}

// seenLines gives a block for each of the first maxAnswers distinct texts,
// with its servers. At most maxServers server lines stand in the whole view;
// a text that no server line is left for counts as an answer not shown.
func seenLines(lines []alert.Line) []string {
	all := answers(lines)
	var out []string
	left, more, blocks := maxServers, 0, 0
	for _, a := range all {
		if blocks == maxAnswers || left == 0 {
			break
		}
		blocks++
		shown := a.servers[:min(left, len(a.servers))]
		left -= len(shown)
		more += len(a.servers) - len(shown)
		out = append(out, "")
		out = append(out, recordLines(rowsOf(labelNow, a.text))...)
		out = append(out, serverLines(shown)...)
	}
	if more > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(more)+" more servers")
	}
	if hidden := len(all) - blocks; hidden > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(hidden)+" more answers")
	}
	return out
}

// moveLines keeps the first maxServers moves and counts the others.
func moveLines(moves []string) []string {
	var out []string
	for _, m := range moves[:min(len(moves), maxServers)] {
		out = append(out, Clean(m, 160))
	}
	if more := len(moves) - maxServers; more > 0 {
		out = append(out, "and "+strconv.Itoa(more)+" more servers")
	}
	return out
}

func serverLines(lines []alert.Line) []string {
	var out []string
	for i, l := range lines {
		label := ""
		if i == 0 {
			label = labelSeenAt
		}
		out = append(out, pad(label)+serverText(l))
	}
	return out
}

func serverText(l alert.Line) string {
	host, addr := "-", "-"
	if l.Server.Name.LabelCount() > 0 {
		host = Clean(l.Server.Name.Lower().String(), 64)
	}
	if a := l.Server.Addr; a.IsValid() {
		// The port is shown only when it is not the DNS port.
		shown := a.String()
		if a.Port() == 53 {
			shown = a.Addr().String()
		}
		addr = Clean(shown, 64)
	}
	return host + " (" + addr + ")   TTL " + strconv.FormatUint(uint64(l.TTL), 10)
}

func times(e alert.Event) string {
	a := e.Alert
	first := a.Opened.UTC()
	switch {
	case e.Kind == alert.EventResolve:
		end := e.At.UTC()
		return ":clock3: Open for " + openFor(end.Sub(first)) + dot + span("first seen", "resolved", first, end)
	case a.LastClean.IsZero():
		return ":clock3: First seen " + first.Format(timeOfDay) + dot + "no clean check before" + dot + first.Format(dateLayout) + " UTC"
	}
	return ":clock3: " + span("First seen", "last OK", first, a.LastClean.UTC())
}

// span names two moments; the date stands once when both fall on one day.
func span(firstWord, secondWord string, first, second time.Time) string {
	if first.Format(dateLayout) == second.Format(dateLayout) {
		return firstWord + " " + first.Format(timeOfDay) + dot + secondWord + " " + second.Format(timeOfDay) + dot + first.Format(dateLayout) + " UTC"
	}
	return firstWord + " " + first.Format(dateLayout+" "+timeOfDay) + dot + secondWord + " " + second.Format(dateLayout+" "+timeOfDay) + dot + "UTC"
}

// openFor writes d, cut to whole seconds: its largest unit that is not zero,
// and the next smaller unit when that one is not zero either.
func openFor(d time.Duration) string {
	left := max(int64(d/time.Second), 0)
	var amounts []int64
	names := []string{"d", "h", "min", "s"}
	for _, secs := range []int64{86400, 3600, 60, 1} {
		amounts = append(amounts, left/secs)
		left %= secs
	}
	i := slices.IndexFunc(amounts, func(n int64) bool { return n > 0 })
	if i < 0 {
		return "0 s"
	}
	out := strconv.FormatInt(amounts[i], 10) + " " + names[i]
	if i+1 < len(amounts) && amounts[i+1] > 0 {
		out += " " + strconv.FormatInt(amounts[i+1], 10) + " " + names[i+1]
	}
	return out
}
