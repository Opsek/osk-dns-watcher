package deliver

import (
	"context"
	"encoding/json"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
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
// lists the expected records. more is the phrase of an alert that lists
// weaker words; it is empty for a rule that has none.
type wording struct {
	phrase, more, resolved, action, now string
}

var wordings = map[decide.Rule]wording{
	decide.RuleNameServers: {
		phrase:   "nameservers of {D} changed at the parent zone",
		resolved: "nameservers of {D} are as expected again",
		action:   "If you did not change the nameservers, contact your registrar now. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleGlue: {
		phrase:   "nameserver addresses of {D} changed at the parent zone",
		resolved: "nameserver addresses of {D} are as expected again",
		action:   "If you did not change the addresses of your nameservers, contact your registrar now. If you did, edit the address line.",
		now:      "as expected again",
	},
	decide.RuleDS: {
		phrase:   "DS of {D} changed at the parent zone",
		resolved: "DS of {D} is as expected again",
		action:   "If you did not change your DNSSEC keys, contact your registrar now. If you did, run osk-dns-watcher accept.",
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
		action:   "If you did not add a wildcard under {N}, remove it at your DNS provider and find out who added it. If you did, write its lines by hand.",
		now:      "no wildcard",
	},
	decide.RuleCAA: {
		phrase:   "the CAA policy for {N} is weaker than expected",
		resolved: "the CAA policy for {N} is as strict as expected again",
		action:   "If you did not change the CAA records, restore them at your DNS provider now, then look for certificates for {N} that you did not ask for. If you did, run osk-dns-watcher accept.",
		now:      "as strict as expected",
	},
	decide.RuleIssuer: {
		phrase:   "a certificate for a name of {D} comes from an authority that the expectations do not permit",
		resolved: "no valid certificate for a name of {D} comes from an authority that the expectations do not permit",
		action:   "If you did not ask for this certificate, ask its authority to revoke it, and check your CAA records and your DNS provider account. If you did, allow the authority where the file restricts it: in your CAA records and their lines, and in the issuer lines.",
		now:      "no valid certificate from an authority that is not permitted",
	},
	decide.RuleCertName: {
		phrase:   "a wildcard certificate for {D} holds a name that the expectations do not list",
		resolved: "no valid certificate for {D} holds an unlisted wildcard",
		action:   "If you did not ask for it, ask its authority to revoke it: it is valid for every name at its level. If it is yours, run osk-dns-watcher accept to list it.",
		now:      "no unlisted wildcard on a valid certificate",
	},
	decide.RuleHostnames: {
		phrase:   "certificates name hosts under {D} that the expectations do not list",
		resolved: "every host under {D} on a valid certificate is in the expectations",
		action:   "Check that each host is yours. Run osk-dns-watcher accept to list them, or add a line for each host that osk-dns-watcher should watch.",
		now:      "no unlisted host on a valid certificate",
	},
	decide.RuleRecordSet: {
		phrase:   "{NT} changed",
		resolved: "{NT} is as expected again",
		action:   "If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleSPF: {
		phrase:   "the SPF record at {N} changed",
		more:     "the SPF record at {N} lets more senders pass than the file",
		resolved: "the SPF record at {N} is as expected again",
		action:   "If you did not make this change, restore the record at your DNS provider: every sender that it lets pass can send mail as {N}. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleDMARC: {
		phrase:   "the DMARC record {N} changed",
		more:     "the DMARC record {N} asks receivers to do less than the file",
		resolved: "the DMARC record {N} is as expected again",
		action:   "If you did not make this change, restore the record at your DNS provider: receivers follow it for mail that claims to come from your domain. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleDKIM: {
		phrase:   "the DKIM key {N} changed",
		more:     "the DKIM key {N} lets another key sign mail",
		resolved: "the DKIM key {N} is as expected again",
		action:   "If you did not change this key, remove the key that is not yours at your DNS provider: whoever holds its private key can sign mail that receivers trust. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleMTASTS: {
		phrase:   "MTA-STS at {N} changed",
		more:     "MTA-STS at {N} protects less than the file",
		resolved: "MTA-STS at {N} is as expected again",
		action:   "If you did not make this change, restore it: senders use MTA-STS to refuse mail servers that are not yours. If you did, run osk-dns-watcher accept.",
	},
	decide.RuleZone: {
		phrase:   "{N} is answered from an unexpected zone",
		resolved: "{N} is answered from the expected zone again",
		action:   "If you did not create this zone, check the delegations under {D} at your DNS provider. If you did, add its NS line by hand.",
		now:      "the expected zone",
	},
	decide.RuleNotCovered: {
		phrase:   "{NT} has no expectation and is not checked",
		resolved: "{NT} has an expectation now",
		action:   "Run osk-dns-watcher accept to add the line for {NT}. If it refuses, add the line to the expectations file of {D} by hand.",
		now:      "covered by the expectations",
	},
	decide.RuleInvalidFile: {
		phrase:   "the expectations file of {D} is not valid",
		resolved: "the expectations file of {D} is valid again",
		action:   "Fix the file. osk-dns-watcher validate names each fault. Until then the last valid file is used.",
		now:      "the file is valid",
	},
	decide.RuleCheckFailing: {
		phrase:   "the {K} check of {NT} has had no usable answer for too long",
		resolved: "the {K} check of {NT} has usable answers again",
		// The name may lie in the zone, in a subzone or outside the domain; the
		// servers that fail are those of its own zone, so the text names it.
		action: "Find out why no server answers this machine for {NT}; until one does, a change there is not seen.",
		now:    "a server answers",
	},
	decide.RuleZoneChanged: {
		phrase:   "the zone {D} changed, and no check saw a watched record change",
		resolved: "the zone {D} has not changed again for a while",
		action:   "If you did not change the zone, find out who did; only a zone transfer shows which record changed.",
		now:      "no new change of the serial",
	},
}

const resolvedAction = "If you did not make or undo this change yourself, find out who did."

// subzoneHost is the wording of nameserver-host when only NS lines of a
// subzone point at the host: the host answers only for that subzone, and its
// NS records are at the DNS provider of the zone above it, not at the
// registrar. {D} stands for the subzone.
var subzoneHost = wording{
	phrase:   "nameserver {N} of the subzone {D} does not exist",
	resolved: "nameserver {N} of the subzone {D} exists again",
	action:   "Replace the nameserver in the NS records of {D} at your DNS provider now, or restore it: whoever creates it can answer for {D}.",
	now:      "the name exists again: check that it is yours",
}

// hostSubzone gives the subzone of a nameserver-host alert whose pointing
// lines, which Expected holds as "<owner> NS <host>", are all lines of names
// below the domain: the owner of the first. A line of the domain itself, or
// one that does not read so, keeps the words of the domain.
func hostSubzone(a alert.Alert) (dnswire.Name, bool) {
	if a.Rule != decide.RuleNameServerHost {
		return dnswire.Name{}, false
	}
	var zone dnswire.Name
	for i, line := range strings.Split(a.Expected, "; ") {
		owner, rest, _ := strings.Cut(line, " ")
		n, err := dnswire.ParseName(owner)
		if err != nil || !strings.HasPrefix(rest, "NS ") || n.Equal(a.Check.Domain) || !n.IsSubdomainOf(a.Check.Domain) {
			return dnswire.Name{}, false
		}
		if i == 0 {
			zone = n
		}
	}
	return zone, true
}

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
	labelWeaker   = "weaker"

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
	maxWords    = 6
	maxText     = 3000
	cutLine     = "[cut]"
)

// SlackText is the notice of e. Every string that comes from DNS or from the
// expectations file passes through Clean and stands inside code. A rule
// without wording gives empty phrases, never DNS text outside code.
func SlackText(e alert.Event) string {
	w := wordings[e.Alert.Rule]
	k := e.Alert.Check
	if zone, ok := hostSubzone(e.Alert); ok {
		w, k.Domain = subzoneHost, zone
	}
	if e.Alert.Rule == decide.RuleCheckFailing && e.Alert.Check.Kind == obs.KindCertificates {
		// The words of a DNS check do not fit a certificate source.
		w.action = "Find out why osk-dns-watcher gets no usable answer from the certificate source; the log of osk-dns-watcher names the reason. Until it does, a new certificate is not seen."
		w.now = "the source answers"
	}
	if e.Alert.Rule == decide.RuleCheckFailing && e.Alert.Check.Kind == obs.KindPolicy {
		// The policy file comes from an HTTPS host, not from the DNS servers.
		w.action = "Find out why osk-dns-watcher cannot fetch the policy file from {N}; the log of osk-dns-watcher names the reason. Until it can, a change of the policy is not seen. A sender that cannot fetch the file uses the policy it has cached, or acts as if there were no policy."
	}
	if e.Alert.Rule == decide.RuleCheckFailing && (e.Alert.Check.Kind == obs.KindDelegation || e.Alert.Check.Kind == obs.KindDS) {
		// These checks ask the servers of the parent zone, not those of {D}.
		w.action = "Find out why no server of the parent zone of {D} answers this machine; until one does, a change there is not seen."
	}
	phrase, action, pointing := w.phrase, w.action, ""
	if e.Kind == alert.EventResolve {
		phrase, action = w.resolved, resolvedAction
		if dangling(e.Alert.Rule) {
			action = "Find out who holds {N} now. If it is not yours, remove or change the record that points at it."
			// The lines come from the file, so they join after the fill.
			if refs := Clean(e.Alert.Expected, recordWidth); refs != "" {
				pointing = " The record: `" + refs + "`"
			}
		}
	} else if w.more != "" && len(weakerWords(e.Alert.Value)) > 0 {
		phrase = w.more
	}
	fill := fields(k)
	return compose(headline(e)+dot+fill.Replace(phrase), view(e, w.now), times(e), fill.Replace(action)+pointing)
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
	nameType := name + " " + Clean(k.Type.String(), 20)
	if k.Kind == obs.KindCertificates {
		nameType = name // the check has no type of its own
	}
	return strings.NewReplacer(
		"{K}", k.Kind.String(),
		"{D}", "`"+Clean(k.Domain.Lower().String(), 100)+"`",
		"{N}", "`"+name+"`",
		"{NT}", "`"+nameType+"`")
}

// title is the start of a headline; the two asterisks make the word bold.
func title(emoji, word, suffix string) string {
	return emoji + " *" + word + "*" + suffix
}

// dangling tells the rules whose alert ends when the name exists again. The
// owner may have fixed the record, or someone else may have registered the
// name, so the end of such an alert is not good news and needs a check.
func dangling(r decide.Rule) bool {
	return r == decide.RuleAliasTarget || r == decide.RuleNameServerHost || r == decide.RuleMailTarget
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
		if dangling(e.Alert.Rule) {
			return title(":warning:", "CHECK", "")
		}
		return title(":white_check_mark:", "RESOLVED", "")
	case alert.EventOpen, alert.EventRefresh: // Writes never sends a refresh
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

// partLines lists the parts of an Expected text, the first under "expected".
func partLines(parts []string) []string {
	var rows []row
	for i, part := range parts {
		label := ""
		if i == 0 {
			label = labelExpected
		}
		rows = append(rows, row{label, part})
	}
	return recordLines(rows)
}

// nameLines lists the distinct texts of lines, which are names of
// certificates, the first under "now".
func nameLines(lines []alert.Line) []string {
	var texts []string
	seen := map[string]bool{}
	for _, l := range lines {
		if !seen[l.Text] {
			seen[l.Text] = true
			texts = append(texts, l.Text)
		}
	}
	var out []string
	for i, t := range texts[:min(len(texts), maxRecords)] {
		label := ""
		if i == 0 {
			label = labelNow
		}
		out = append(out, pad(label)+Clean(t, recordWidth))
	}
	if more := len(texts) - maxRecords; more > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(more)+" more names")
	}
	return out
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
		return moveLines(strings.Split(a.Value, "\n"), a.Opened.UTC())
	case decide.RuleGlue, decide.RuleAliasTarget, decide.RuleNameServerHost, decide.RuleMailTarget:
		// Expected holds one part for each host and type that differs, or for each
		// line that points at the name, joined by "; ". A part may hold " | ", so
		// it is not split as a record list.
		return append(partLines(strings.Split(a.Expected, "; ")), seenLines(a)...)
	case decide.RuleIssuer:
		// A part is a CAA line, which may hold "; " inside a quoted value.
		parts := partLines(splitOutsideQuotes(a.Expected, "; "))
		return append(append(parts, ""), nameLines(a.Lines)...)
	case decide.RuleCertName, decide.RuleHostnames:
		return nameLines(a.Lines)
	case decide.RuleSPF, decide.RuleDMARC, decide.RuleDKIM, decide.RuleMTASTS:
		// The words come first: compose cuts from the end of the view.
		return append(weakerLines(a.Value), setView(a)...)
	case decide.RuleNameServers, decide.RuleRecordSet, decide.RuleZone, decide.RuleNotCovered,
		decide.RuleDS, decide.RuleGone, decide.RuleDisagree, decide.RuleChallenge, decide.RuleWildcard,
		decide.RuleCAA:
	}
	return setView(a)
}

// setView lists the expected records, then each set that servers gave.
func setView(a alert.Alert) []string {
	return append(recordLines(expectedRows(labelExpected, a.Expected)), seenLines(a)...)
}

// weakerLines gives the words of a mail policy that Value holds, the first
// six under "weaker", then the count of the others, then one empty line. It
// gives no line when there is no word. A last word "and <k> more" is the
// cap of the rule, not a word: its k joins the count of the words left out.
func weakerLines(value string) []string {
	words := weakerWords(value)
	skipped := 0
	if n := len(words); n > 0 {
		if k, ok := capCount(words[n-1]); ok {
			words, skipped = words[:n-1], k
		}
	}
	var out []string
	for i, w := range words[:min(len(words), maxWords)] {
		label := ""
		if i == 0 {
			label = labelWeaker
		}
		out = append(out, pad(label)+Clean(w, recordWidth))
	}
	if more := max(len(words)-maxWords, 0) + skipped; more > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(more)+" more")
	}
	if len(out) > 0 {
		out = append(out, "")
	}
	return out
}

// capCount reads the word "and <k> more" that the rule puts after its
// twelfth word.
func capCount(word string) (int, bool) {
	num, ok := strings.CutPrefix(word, "and ")
	if !ok {
		return 0, false
	}
	num, ok = strings.CutSuffix(num, " more")
	if !ok {
		return 0, false
	}
	k, err := strconv.Atoi(num)
	return k, err == nil && k > 0
}

// weakerWords gives the words of the lines of value that start with "weaker ".
func weakerWords(value string) []string {
	var words []string
	for _, line := range strings.Split(value, "\n") {
		if w, ok := strings.CutPrefix(line, "weaker "); ok {
			words = append(words, w)
		}
	}
	return words
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
// a text that no server line is left for counts as an answer not shown. A
// server line ends with its TTL, except for a policy file, which has none.
func seenLines(a alert.Alert) []string {
	ttl := a.Check.Kind != obs.KindPolicy
	all := answers(a.Lines)
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
		out = append(out, serverLines(shown, ttl)...)
	}
	if more > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(more)+" more servers")
	}
	if hidden := len(all) - blocks; hidden > 0 {
		out = append(out, pad("")+"and "+strconv.Itoa(hidden)+" more answers")
	}
	return out
}

// moveLines keeps the first maxServers moves and counts the others. The times
// of a move are stored as RFC 3339 for the webhook; the view writes them as
// the clock line does, and leaves the date out on the day that the clock line
// shows, which is the day of first.
func moveLines(moves []string, first time.Time) []string {
	var out []string
	for _, m := range moves[:min(len(moves), maxServers)] {
		out = append(out, Clean(moveTimes.ReplaceAllStringFunc(m, func(s string) string {
			t, err := time.Parse("2006-01-02T15:04:05Z", s)
			switch {
			case err != nil:
				return s
			case t.Format(dateLayout) == first.Format(dateLayout):
				return t.Format(timeOfDay)
			}
			return t.Format(dateLayout+" "+timeOfDay) + " UTC"
		}), 160))
	}
	if more := len(moves) - maxServers; more > 0 {
		out = append(out, "and "+strconv.Itoa(more)+" more servers")
	}
	return out
}

// moveTimes finds the times in a line of a zone-changed Value.
var moveTimes = regexp.MustCompile(`\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ`)

func serverLines(lines []alert.Line, ttl bool) []string {
	var out []string
	for i, l := range lines {
		label := ""
		if i == 0 {
			label = labelSeenAt
		}
		out = append(out, pad(label)+serverText(l, ttl))
	}
	return out
}

func serverText(l alert.Line, ttl bool) string {
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
	text := host + " (" + addr + ")"
	if ttl {
		text += "   TTL " + strconv.FormatUint(uint64(l.TTL), 10)
	}
	return text
}

func times(e alert.Event) string {
	a := e.Alert
	first := a.Opened.UTC()
	switch {
	case e.Kind == alert.EventResolve:
		end := e.At.UTC()
		return ":clock3: Open for " + decide.ShortDuration(end.Sub(first)) + dot + span("first seen", "resolved", first, end)
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
