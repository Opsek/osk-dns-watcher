package deliver_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
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

// The Slack text as the message rules describe it, written apart from the
// code under test.

var (
	dlvEmoji = map[decide.Severity]string{
		decide.SeverityLow: ":large_yellow_circle:", decide.SeverityMedium: ":large_orange_circle:",
		decide.SeverityHigh: ":red_circle:", decide.SeverityCritical: ":rotating_light:",
	}
	dlvWord = map[decide.Severity]string{
		decide.SeverityLow: "LOW", decide.SeverityMedium: "MEDIUM", decide.SeverityHigh: "HIGH", decide.SeverityCritical: "CRITICAL",
	}
	// dlvSpans is the number of code spans of a text that is not a resolve.
	dlvSpans = map[decide.Rule]int{
		decide.RuleNameServers: 1, decide.RuleRecordSet: 1, decide.RuleZone: 2, decide.RuleNotCovered: 3, decide.RuleInvalidFile: 1,
	}
)

const (
	dlvResolveAction = "If you did not make or undo this change yourself, find out who did."
	dlvDot           = " · "
	// dlvIndent continues a list under its label.
	dlvIndent = "           "
	dlvClock  = "15:04:05"
	dlvDate   = "2 Jan 2006"
)

// dlvLabel pads a label to the 11 columns of the view.
func dlvLabel(s string) string {
	return s + strings.Repeat(" ", len(dlvIndent)-len(s))
}

// dlvSplit cuts s at sep outside double quotes. A backslash keeps the octet
// after it from closing or opening a quote.
func dlvSplit(s, sep string) []string {
	var parts []string
	quoted, from := false, 0
	for i := 0; i < len(s); i++ {
		switch {
		case s[i] == '\\':
			i++
		case s[i] == '"':
			quoted = !quoted
		case !quoted && strings.HasPrefix(s[i:], sep):
			parts = append(parts, s[from:i])
			i += len(sep) - 1
			from = i + 1
		}
	}
	return append(parts, s[from:])
}

// dlvList writes records under a label, one on each line, at most six.
func dlvList(label string, records []string) []string {
	var out []string
	for i, r := range records {
		if i == 6 {
			return append(out, dlvIndent+fmt.Sprintf("and %d more records", len(records)-6))
		}
		prefix := dlvIndent
		if i == 0 {
			prefix = dlvLabel(label)
		}
		out = append(out, prefix+dlvClean(r, 120))
	}
	return out
}

// dlvExpected writes an Expected text: the records of an exact form with the
// alternatives after each other, any other form on one line.
func dlvExpected(label, expected string) []string {
	if expected == "" {
		return []string{dlvLabel(label) + "-"}
	}
	if expected == "none" || strings.HasPrefix(expected, "in ") || strings.HasPrefix(expected, "like ") {
		return []string{dlvLabel(label) + dlvClean(expected, 120)}
	}
	var out []string
	for i, alt := range dlvSplit(expected, " || ") {
		l := "or"
		if i == 0 {
			l = label
		}
		out = append(out, dlvList(l, dlvSplit(alt, " | "))...)
	}
	return out
}

func dlvServerText(l alert.Line) string {
	addr, host := "-", "-"
	if a := l.Server.Addr; a.IsValid() {
		s := a.String()
		if a.Port() == 53 {
			s = a.Addr().String()
		}
		addr = dlvClean(s, 64)
	}
	if l.Server.Name.LabelCount() > 0 {
		host = dlvClean(l.Server.Name.Lower().String(), 64)
	}
	return host + " (" + addr + ")   TTL " + strconv.FormatUint(uint64(l.TTL), 10)
}

// dlvAnswers writes the lines of an alert grouped by their text: at most
// three answers and six servers.
func dlvAnswers(lines []alert.Line) []string {
	var texts []string
	groups := map[string][]alert.Line{}
	for _, l := range lines {
		if _, ok := groups[l.Text]; !ok {
			texts = append(texts, l.Text)
		}
		groups[l.Text] = append(groups[l.Text], l)
	}
	var out []string
	blocks, shown, inBlocks := 0, 0, 0
	for _, text := range texts {
		if blocks == 3 || shown == 6 {
			break
		}
		blocks++
		records := []string{"-"}
		if text != "" {
			records = dlvSplit(text, " | ")
		}
		out = append(out, "")
		out = append(out, dlvList("now", records)...)
		for i, l := range groups[text] {
			inBlocks++
			if shown == 6 {
				continue
			}
			prefix := dlvIndent
			if i == 0 {
				prefix = dlvLabel("seen at")
			}
			out = append(out, prefix+dlvServerText(l))
			shown++
		}
	}
	if inBlocks > shown {
		out = append(out, dlvIndent+fmt.Sprintf("and %d more servers", inBlocks-shown))
	}
	if len(texts) > blocks {
		out = append(out, dlvIndent+fmt.Sprintf("and %d more answers", len(texts)-blocks))
	}
	return out
}

// dlvDuration writes a time with its largest unit that is not zero and the
// next smaller unit when that is not zero.
func dlvDuration(d time.Duration) string {
	d = d.Truncate(time.Second)
	if d < time.Second {
		return "0 s"
	}
	secs := int64(d / time.Second)
	units := []struct {
		n    int64
		name string
	}{{secs / 86400, "d"}, {secs % 86400 / 3600, "h"}, {secs % 3600 / 60, "min"}, {secs % 60, "s"}}
	for i, u := range units {
		if u.n == 0 {
			continue
		}
		out := fmt.Sprintf("%d %s", u.n, u.name)
		if i+1 < len(units) && units[i+1].n > 0 {
			out += fmt.Sprintf(" %d %s", units[i+1].n, units[i+1].name)
		}
		return out
	}
	return "0 s"
}

// dlvClockLine writes two times with their date once when they share a day,
// and before each time when they do not.
func dlvClockLine(head string, first time.Time, mid string, second time.Time) string {
	first, second = first.UTC(), second.UTC()
	if first.Format(dlvDate) == second.Format(dlvDate) {
		return ":clock3: " + head + first.Format(dlvClock) + mid + second.Format(dlvClock) + dlvDot + first.Format(dlvDate) + " UTC"
	}
	return ":clock3: " + head + first.Format(dlvDate+" "+dlvClock) + mid + second.Format(dlvDate+" "+dlvClock) + dlvDot + "UTC"
}

func dlvFull(headline string, view []string, clock, action string) string {
	lines := append([]string{headline, "", "```"}, view...)
	return strings.Join(append(lines, "```", "", clock, "", action), "\n")
}

// dlvAssemble joins the four parts and, when the text is over 3000 octets,
// drops view lines from the end and ends the view with [cut].
func dlvAssemble(headline string, view []string, clock, action string) string {
	text := dlvFull(headline, view, clock, action)
	for n := len(view) - 1; len(text) > 3000 && n >= 0; n-- {
		text = dlvFull(headline, append(append([]string{}, view[:n]...), "[cut]"), clock, action)
	}
	return text
}

func dlvSlackText(e alert.Event) string {
	a, k := e.Alert, e.Alert.Check
	d := "`" + dlvClean(k.Domain.Lower().String(), 100) + "`"
	n := "`" + dlvClean(k.Name.Lower().String(), 100) + "`"
	nt := "`" + dlvClean(k.Name.Lower().String(), 100) + " " + dlvClean(k.Type.String(), 20) + "`"
	head := dlvEmoji[a.Severity] + " *" + dlvWord[a.Severity] + "*" + map[alert.EventKind]string{
		alert.EventOpen:     "",
		alert.EventUpdate:   ", changed again",
		alert.EventEscalate: ", raised from " + e.Was.String(),
		alert.EventReminder: ", still open",
		alert.EventResolve:  "",
	}[e.Kind]
	type words struct{ phrase, resolved, action, now string }
	w := map[decide.Rule]words{
		decide.RuleNameServers: {"nameservers of " + d + " changed at the parent zone", "nameservers of " + d + " are as expected again",
			"If you did not change the nameservers, contact your registrar now. If you did, run osk-dns-watcher accept.", ""},
		decide.RuleRecordSet: {nt + " changed", nt + " is as expected again",
			"If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept.", ""},
		decide.RuleZone: {n + " is answered from an unexpected zone", n + " is answered from the expected zone again",
			"If you did not create this zone, check the delegations under " + d + " at your DNS provider. If you did, add its NS line by hand.", "the expected zone"},
		decide.RuleNotCovered: {nt + " has no expectation and is not checked", nt + " has an expectation now",
			"Run osk-dns-watcher accept to add the line for " + nt + ". If it refuses, add the line to the expectations file of " + d + " by hand.", "covered by the expectations"},
		decide.RuleInvalidFile: {"the expectations file of " + d + " is not valid", "the expectations file of " + d + " is valid again",
			"Fix the file. osk-dns-watcher validate names each fault. Until then the last valid file is used.", "the file is valid"},
	}[a.Rule]
	resolve := e.Kind == alert.EventResolve
	phrase, action := w.phrase, w.action
	if resolve {
		head, phrase, action = ":white_check_mark: *RESOLVED*", w.resolved, dlvResolveAction
	}
	var view []string
	switch {
	case a.Rule == decide.RuleInvalidFile && !resolve:
		view = []string{dlvLabel("problem") + dlvClean(a.Value, 160)}
	case resolve && w.now != "":
		view = []string{dlvLabel("now") + w.now}
	case resolve:
		view = dlvExpected("now", a.Expected)
	default:
		view = append(dlvExpected("expected", a.Expected), dlvAnswers(a.Lines)...)
	}
	var clock string
	if resolve {
		clock = dlvClockLine("Open for "+dlvDuration(e.At.Sub(a.Opened))+dlvDot+"first seen ", a.Opened, dlvDot+"resolved ", e.At)
	} else if a.LastClean.IsZero() {
		clock = ":clock3: First seen " + a.Opened.UTC().Format(dlvClock) + dlvDot + "no clean check before" + dlvDot + a.Opened.UTC().Format(dlvDate) + " UTC"
	} else {
		clock = dlvClockLine("First seen ", a.Opened, dlvDot+"last OK ", a.LastClean)
	}
	return dlvAssemble(head+dlvDot+phrase, view, clock, ":point_right: "+action)
}

var dlvServerTTL = regexp.MustCompile(`   TTL \d+$`)

// dlvOctetFault describes the first octet of a text that no Slack text may
// hold, or returns "". The middle dot is allowed only as two octets with a
// space on each side.
func dlvOctetFault(text string) string {
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case c == 0xC2 && i > 0 && i+2 < len(text) && text[i+1] == 0xB7 && text[i-1] == ' ' && text[i+2] == ' ':
			i++
		case (c < 0x20 || c > 0x7E) && c != '\n', c == '<', c == '>':
			return fmt.Sprintf("octet %#02x at %d", c, i)
		case c == '&' && !strings.HasPrefix(text[i:], "&amp;") && !strings.HasPrefix(text[i:], "&lt;") &&
			!strings.HasPrefix(text[i:], "&gt;"):
			return fmt.Sprintf("an & at %d that starts no escape", i)
		}
	}
	return ""
}

// dlvMessageFault checks the message of e against the safety rules of a
// Slack text and against the text the rules give, and describes the first
// fault, or returns "".
func dlvMessageFault(e alert.Event) string {
	text := deliver.SlackText(e)
	body := deliver.SlackMessage(e)
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Sprintf("the body is not a JSON object: %v", err)
	}
	if got, ok := fields["text"].(string); len(fields) != 1 || !ok || got != text {
		return fmt.Sprintf("the body %q is not one key text with SlackText", body)
	}
	if want, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text}); err != nil || !bytes.Equal(body, want) {
		return fmt.Sprintf("the body %q is not the JSON encoding of the text", body)
	}
	if len(text) > 3000 {
		return fmt.Sprintf("%d octets, more than 3000", len(text))
	}
	if fault := dlvOctetFault(text); fault != "" {
		return fault
	}
	spans := 1
	if e.Kind != alert.EventResolve {
		spans = dlvSpans[e.Alert.Rule]
	}
	if got := strings.Count(text, "`"); got != 6+2*spans {
		return fmt.Sprintf("%d backticks, want %d", got, 6+2*spans)
	}
	// By position: headline, empty line, fence, view, fence, empty line,
	// times, empty line, action. Data from DNS cannot hold LF after Clean, so
	// each view line is one line.
	lines := strings.Split(text, "\n")
	n := len(lines)
	fence := -1
	for i := 3; i < n && fence < 0; i++ {
		if lines[i] == "```" {
			fence = i
		}
	}
	if n < 9 || lines[1] != "" || lines[2] != "```" || fence != n-5 || lines[n-4] != "" || lines[n-2] != "" {
		return fmt.Sprintf("not four parts with a code block in the second:\n%s", text)
	}
	// Outside code only the two stars of the severity word are allowed.
	stars := 0
	for i, l := range lines {
		if i >= 2 && i <= fence {
			continue
		}
		inSpan := false
		for _, c := range l {
			switch {
			case c == '`':
				inSpan = !inSpan
			case c == '*' && !inSpan:
				stars++
			}
		}
	}
	if stars != 2 {
		return fmt.Sprintf("%d stars outside code, want 2", stars)
	}
	servers, answers := 0, 0
	for _, l := range lines[3:fence] {
		switch {
		case strings.Contains(l, "·"):
			return fmt.Sprintf("a middle dot inside the code block: %q", l)
		case dlvServerTTL.MatchString(l):
			servers++
		case strings.HasPrefix(l, "now        "):
			answers++
		}
	}
	if servers > 6 {
		return fmt.Sprintf("%d server lines", servers)
	}
	if answers > 3 {
		return fmt.Sprintf("%d now blocks", answers)
	}
	if ref := dlvSlackText(e); text != ref {
		return fmt.Sprintf("text:\n%s\nwant:\n%s", text, ref)
	}
	return ""
}

func TestSlackMessageProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 7))
	for range 2000 {
		e := dlvHostileEvent(rng)
		if fault := dlvMessageFault(e); fault != "" {
			t.Fatalf("seed %d: event %+v: %s", seed, e, fault)
		}
	}
}

func dlvName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The times of the fixtures are in a zone east of UTC and carry fractions of
// a second, so a text must convert them and must not round.
var (
	dlvEast      = time.FixedZone("east", 5*3600)
	dlvOpened    = time.Date(2026, 11, 11, 19, 2, 7, 999e6, dlvEast)  // 14:02:07 UTC
	dlvLastClean = time.Date(2026, 11, 11, 19, 1, 7, 0, dlvEast)      // 14:01:07 UTC
	dlvResolved  = time.Date(2026, 11, 12, 13, 30, 0, 500e6, dlvEast) // 08:30:00 UTC
	dlvNoticed   = time.Date(2026, 11, 11, 20, 0, 0, 0, dlvEast)      // in no text
	dlvReceived  = time.Date(2026, 11, 11, 19, 2, 6, 0, dlvEast)      // in no text
	dlvLater     = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)      // the time of a pass
	dlvGateTime  = time.Date(2026, 11, 11, 14, 2, 7, 0, time.UTC)     // the gate example
	dlvGateClean = time.Date(2026, 11, 11, 14, 1, 7, 0, time.UTC)     // the gate example
)

// dlvLines are two servers: one with a name and an address, and one with
// neither, as the walk may give a root server.
func dlvLines(t testing.TB) []alert.Line {
	return []alert.Line{
		{Server: obs.Server{Name: dlvName(t, "NS1.Corp.Test."), Addr: netip.MustParseAddrPort("10.53.0.11:53")},
			Text: "10.53.0.99", TTL: 120, Received: dlvReceived},
		{Server: obs.Server{}, Text: "none", TTL: 300, Received: dlvReceived},
	}
}

// Each kind of event of each rule gives the text of the message rules, word
// for word.
func TestSlackTextForEachKindAndRule(t *testing.T) {
	servers := []string{
		"",
		"now        10.53.0.99",
		"seen at    ns1.corp.test. (10.53.0.11)   TTL 120",
		"",
		"now        none",
		"seen at    - (-)   TTL 300",
	}
	rules := []struct {
		rule                     decide.Rule
		check                    obs.Key
		expected                 string
		phrase, resolved, action string
		view, resolvedView       []string
	}{
		{decide.RuleNameServers, obs.DelegationKey(dlvName(t, "Corp.TEST.")), "ns1.corp.test. | ns2.corp.test.",
			"nameservers of `corp.test.` changed at the parent zone",
			"nameservers of `corp.test.` are as expected again",
			"If you did not change the nameservers, contact your registrar now. If you did, run osk-dns-watcher accept.",
			append([]string{"expected   ns1.corp.test.", "           ns2.corp.test."}, servers...),
			[]string{"now        ns1.corp.test.", "           ns2.corp.test."}},
		{decide.RuleRecordSet, obs.RecordsKey(dlvName(t, "Corp.TEST."), dlvName(t, "WWW.corp.test."), dnswire.TypeA), "10.53.0.81",
			"`www.corp.test. A` changed",
			"`www.corp.test. A` is as expected again",
			"If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept.",
			append([]string{"expected   10.53.0.81"}, servers...),
			[]string{"now        10.53.0.81"}},
		{decide.RuleZone, obs.RecordsKey(dlvName(t, "Corp.Test."), dlvName(t, "Shop.Corp.Test."), dnswire.TypeA), "corp.test.",
			"`shop.corp.test.` is answered from an unexpected zone",
			"`shop.corp.test.` is answered from the expected zone again",
			"If you did not create this zone, check the delegations under `corp.test.` at your DNS provider. If you did, add its NS line by hand.",
			append([]string{"expected   corp.test."}, servers...),
			[]string{"now        the expected zone"}},
		{decide.RuleNotCovered, obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "MAIL.corp.test."), dnswire.TypeTXT), "",
			"`mail.corp.test. TXT` has no expectation and is not checked",
			"`mail.corp.test. TXT` has an expectation now",
			"Run osk-dns-watcher accept to add the line for `mail.corp.test. TXT`. If it refuses, add the line to the expectations file of `corp.test.` by hand.",
			append([]string{"expected   -"}, servers...),
			[]string{"now        covered by the expectations"}},
		{decide.RuleInvalidFile, obs.Key{Domain: dlvName(t, "Corp.Test."), Name: dlvName(t, "Corp.Test.")}, "",
			"the expectations file of `corp.test.` is not valid",
			"the expectations file of `corp.test.` is valid again",
			"Fix the file. osk-dns-watcher validate names each fault. Until then the last valid file is used.",
			[]string{"problem    line 3: want a type after the name"},
			[]string{"now        the file is valid"}},
	}
	kinds := []struct {
		kind alert.EventKind
		head string
	}{
		{alert.EventOpen, ":red_circle: *HIGH*"},
		{alert.EventUpdate, ":red_circle: *HIGH*, changed again"},
		{alert.EventEscalate, ":red_circle: *HIGH*, raised from medium"},
		{alert.EventReminder, ":red_circle: *HIGH*, still open"},
		{alert.EventResolve, ":white_check_mark: *RESOLVED*"},
	}
	for _, r := range rules {
		for _, k := range kinds {
			e := alert.Event{
				Kind: k.kind,
				Alert: alert.Alert{ID: 7, Open: k.kind != alert.EventResolve, Rule: r.rule,
					Severity: decide.SeverityHigh, Peak: decide.SeverityCritical, Check: r.check,
					Expected: r.expected, Value: "line 3: want a type after the name", Lines: dlvLines(t),
					Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed},
				Was: decide.SeverityMedium,
				At:  dlvResolved,
			}
			want := dlvFull(k.head+dlvDot+r.phrase, r.view, ":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC",
				":point_right: "+r.action)
			if k.kind == alert.EventResolve {
				e.Alert.Resolved = dlvResolved
				want = dlvFull(k.head+dlvDot+r.resolved, r.resolvedView,
					":clock3: Open for 18 h 27 min · first seen 11 Nov 2026 14:02:07 · resolved 12 Nov 2026 08:30:00 · UTC",
					":point_right: "+dlvResolveAction)
			}
			if got := deliver.SlackText(e); got != want {
				t.Errorf("%v %v:\n%s\nwant:\n%s", k.kind, r.rule, got, want)
			}
			if got := dlvSlackText(e); got != want {
				t.Errorf("the reference text of this test is wrong for %v %v:\n%s", k.kind, r.rule, got)
			}
		}
	}
}

func dlvRecordSetEvent(t testing.TB, kind alert.EventKind, sev decide.Severity, lines []alert.Line) alert.Event {
	return alert.Event{
		Kind: kind,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: sev, Peak: sev,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "www.corp.test."), dnswire.TypeA),
			Expected: "10.53.0.81", Lines: lines, Opened: dlvOpened, LastClean: dlvLastClean},
		Was: decide.SeverityLow,
		At:  dlvOpened,
	}
}

// The emoji and the word follow the severity after the event; the severity
// before it is named in lower case.
func TestSlackTextSeverityWords(t *testing.T) {
	for sev, head := range map[decide.Severity]string{
		decide.SeverityLow:      ":large_yellow_circle: *LOW*",
		decide.SeverityMedium:   ":large_orange_circle: *MEDIUM*",
		decide.SeverityHigh:     ":red_circle: *HIGH*",
		decide.SeverityCritical: ":rotating_light: *CRITICAL*",
	} {
		e := dlvRecordSetEvent(t, alert.EventOpen, sev, nil)
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], head+" · `www.corp.test. A` changed"; got != want {
			t.Errorf("open %v: headline %q, want %q", sev, got, want)
		}
		e = dlvRecordSetEvent(t, alert.EventEscalate, decide.SeverityCritical, nil)
		e.Was = sev
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], ":rotating_light: *CRITICAL*, raised from "+sev.String()+" · `www.corp.test. A` changed"; got != want {
			t.Errorf("escalate from %v: headline %q, want %q", sev, got, want)
		}
		e = dlvRecordSetEvent(t, alert.EventResolve, sev, nil)
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], ":white_check_mark: *RESOLVED* · `www.corp.test. A` is as expected again"; got != want {
			t.Errorf("resolve at %v: headline %q, want %q", sev, got, want)
		}
	}
}

const (
	dlvRSHead   = ":red_circle: *HIGH* · `www.corp.test. A` changed"
	dlvRSClock  = ":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC"
	dlvRSAction = ":point_right: If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept."
)

// dlvRS is the text of the open event of the record-set alert of the tests
// with this view.
func dlvRS(view ...string) string {
	return dlvFull(dlvRSHead, view, dlvRSClock, dlvRSAction)
}

// dlvSame checks the text of e against want and against the reference text
// of these tests.
func dlvSame(t *testing.T, e alert.Event, want string) {
	t.Helper()
	if got := deliver.SlackText(e); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if got := dlvSlackText(e); got != want {
		t.Errorf("the reference text of this test is wrong:\n%s", got)
	}
}

func dlvAt(t testing.TB, name, addr, text string, ttl uint32) alert.Line {
	l := alert.Line{Server: obs.Server{Name: dlvName(t, name)}, Text: text, TTL: ttl}
	if addr != "" {
		l.Server.Addr = netip.MustParseAddrPort(addr)
	}
	return l
}

// At most six servers are shown; the rest are counted.
func TestSlackTextShowsSixServers(t *testing.T) {
	for _, n := range []int{0, 1, 6, 7, 40} {
		var lines []alert.Line
		view := []string{"expected   10.53.0.81"}
		if n > 0 {
			view = append(view, "", "now        10.53.0.99")
		}
		for i := 1; i <= n; i++ {
			lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), "10.53.0.99", 60))
			if i <= 6 {
				prefix := dlvIndent
				if i == 1 {
					prefix = "seen at    "
				}
				view = append(view, fmt.Sprintf("%sns%d.corp.test. (10.53.0.%d)   TTL 60", prefix, i, i))
			}
		}
		if n > 6 {
			view = append(view, fmt.Sprintf("           and %d more servers", n-6))
		}
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			dlvSame(t, dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines), dlvRS(view...))
		})
	}
}

func TestSlackTextWithoutCleanCheck(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventReminder, decide.SeverityHigh, nil)
	e.Alert.LastClean = time.Time{}
	want := dlvFull(":red_circle: *HIGH*, still open · `www.corp.test. A` changed", []string{"expected   10.53.0.81"},
		":clock3: First seen 14:02:07 · no clean check before · 11 Nov 2026 UTC", dlvRSAction)
	dlvSame(t, e, want)
}

// The date stands once at the end when the two times share a day, and before
// each time when they do not.
func TestSlackTextTimesOnOneDayAndOnTwo(t *testing.T) {
	view := []string{"expected   10.53.0.81"}
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, nil)
	e.Alert.Opened = time.Date(2026, 11, 11, 0, 0, 10, 0, time.UTC)
	e.Alert.LastClean = time.Date(2026, 11, 10, 23, 59, 0, 0, time.UTC)
	dlvSame(t, e, dlvFull(dlvRSHead, view, ":clock3: First seen 11 Nov 2026 00:00:10 · last OK 10 Nov 2026 23:59:00 · UTC", dlvRSAction))

	e.Alert.LastClean = time.Date(2026, 11, 11, 0, 0, 5, 0, time.UTC)
	dlvSame(t, e, dlvFull(dlvRSHead, view, ":clock3: First seen 00:00:10 · last OK 00:00:05 · 11 Nov 2026 UTC", dlvRSAction))

	r := dlvRecordSetEvent(t, alert.EventResolve, decide.SeverityHigh, nil)
	r.Alert.Opened = time.Date(2026, 11, 3, 23, 59, 50, 0, time.UTC)
	r.At = time.Date(2026, 11, 4, 0, 0, 20, 0, time.UTC)
	dlvSame(t, r, dlvFull(":white_check_mark: *RESOLVED* · `www.corp.test. A` is as expected again", []string{"now        10.53.0.81"},
		":clock3: Open for 30 s · first seen 3 Nov 2026 23:59:50 · resolved 4 Nov 2026 00:00:20 · UTC", ":point_right: "+dlvResolveAction))
	r.At = time.Date(2026, 11, 3, 23, 59, 55, 0, time.UTC)
	dlvSame(t, r, dlvFull(":white_check_mark: *RESOLVED* · `www.corp.test. A` is as expected again", []string{"now        10.53.0.81"},
		":clock3: Open for 5 s · first seen 23:59:50 · resolved 23:59:55 · 3 Nov 2026 UTC", ":point_right: "+dlvResolveAction))
}

// The time open has its largest unit that is not zero and the next smaller
// unit when that is not zero.
func TestSlackTextDurationForms(t *testing.T) {
	opened := time.Date(2026, 11, 11, 14, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		open time.Duration
		want string
	}{
		{0, "0 s"},
		{900 * time.Millisecond, "0 s"},
		{3 * time.Second, "3 s"},
		{time.Minute, "1 min"},
		{4*time.Minute + 10*time.Second, "4 min 10 s"},
		{time.Hour + 5*time.Second, "1 h"},
		{2*time.Hour + 5*time.Minute, "2 h 5 min"},
		{time.Hour + 2*time.Minute + 3*time.Second, "1 h 2 min"},
		{3*24*time.Hour + 4*time.Hour, "3 d 4 h"},
		{3*24*time.Hour + 5*time.Minute, "3 d"},
	} {
		t.Run(c.want, func(t *testing.T) {
			e := dlvRecordSetEvent(t, alert.EventResolve, decide.SeverityHigh, nil)
			e.Alert.Opened, e.At = opened, opened.Add(c.open)
			head := ":clock3: Open for " + c.want + " · first seen "
			lines := strings.Split(deliver.SlackText(e), "\n")
			if len(lines) < 3 || !strings.HasPrefix(lines[len(lines)-3], head) {
				t.Errorf("text:\n%s\nwant the times line to start with %q", strings.Join(lines, "\n"), head)
			}
			if got := dlvSlackText(e); !strings.Contains(got, "\n"+head) {
				t.Errorf("the reference text of this test is wrong:\n%s", got)
			}
		})
	}
}

// Each rule shows what holds again in its resolve text, and no expected line.
func TestSlackTextResolveViewOfEachRule(t *testing.T) {
	for _, c := range []struct {
		rule     decide.Rule
		check    obs.Key
		expected string
		phrase   string
		view     []string
	}{
		{decide.RuleNameServers, obs.DelegationKey(dlvName(t, "corp.test.")), "ns1.corp.test. | ns2.corp.test.",
			"nameservers of `corp.test.` are as expected again", []string{"now        ns1.corp.test.", "           ns2.corp.test."}},
		{decide.RuleNameServers, obs.DelegationKey(dlvName(t, "corp.test.")), "ns1.corp.test. | ns2.corp.test. || ns3.corp.test.",
			"nameservers of `corp.test.` are as expected again",
			[]string{"now        ns1.corp.test.", "           ns2.corp.test.", "or         ns3.corp.test."}},
		{decide.RuleRecordSet, obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "www.corp.test."), dnswire.TypeA), "10.53.0.81",
			"`www.corp.test. A` is as expected again", []string{"now        10.53.0.81"}},
		{decide.RuleZone, obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "shop.corp.test."), dnswire.TypeA), "corp.test.",
			"`shop.corp.test.` is answered from the expected zone again", []string{"now        the expected zone"}},
		{decide.RuleNotCovered, obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "mail.corp.test."), dnswire.TypeTXT), "",
			"`mail.corp.test. TXT` has an expectation now", []string{"now        covered by the expectations"}},
		{decide.RuleInvalidFile, obs.Key{Domain: dlvName(t, "corp.test."), Name: dlvName(t, "corp.test.")}, "",
			"the expectations file of `corp.test.` is valid again", []string{"now        the file is valid"}},
	} {
		e := alert.Event{Kind: alert.EventResolve, Alert: alert.Alert{Rule: c.rule, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh,
			Check: c.check, Expected: c.expected, Lines: dlvLines(t), Opened: dlvOpened, LastClean: dlvLastClean},
			Was: decide.SeverityHigh, At: dlvOpened.Add(10 * time.Second)}
		dlvSame(t, e, dlvFull(":white_check_mark: *RESOLVED* · "+c.phrase, c.view,
			":clock3: Open for 10 s · first seen 14:02:07 · resolved 14:02:17 · 11 Nov 2026 UTC", ":point_right: "+dlvResolveAction))
	}
}

// A list of records is cut only at a separator outside double quotes.
func TestSlackTextSplitsRecordsOutsideQuotes(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh,
		[]alert.Line{dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", `"v=spf1 | y"`, 60)})
	e.Alert.Expected = `"v=spf1 | x" | "other"`
	dlvSame(t, e, dlvRS(`expected   "v=spf1 | x"`, `           "other"`, "", `now        "v=spf1 | y"`,
		"seen at    ns1.corp.test. (10.53.0.11)   TTL 60"))
}

func TestSlackTextOneAnswerOfTwoServersIsOneBlock(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, []alert.Line{
		dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", "10.53.0.99", 120),
		dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", "10.53.0.99", 120),
	})
	dlvSame(t, e, dlvRS("expected   10.53.0.81", "", "now        10.53.0.99",
		"seen at    ns1.corp.test. (10.53.0.11)   TTL 120", "           ns2.corp.test. (10.53.0.12)   TTL 120"))
}

func TestSlackTextBlocksStandInOrderOfFirstAppearance(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, []alert.Line{
		dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", "10.53.0.99", 120),
		dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", "10.53.0.98", 60),
		dlvAt(t, "ns3.corp.test.", "10.53.0.13:53", "10.53.0.99", 30),
	})
	dlvSame(t, e, dlvRS("expected   10.53.0.81",
		"", "now        10.53.0.99", "seen at    ns1.corp.test. (10.53.0.11)   TTL 120", "           ns3.corp.test. (10.53.0.13)   TTL 30",
		"", "now        10.53.0.98", "seen at    ns2.corp.test. (10.53.0.12)   TTL 60"))
}

func TestSlackTextShowsOrForAlternatives(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, nil)
	e.Alert.Expected = "10.0.0.1 | 10.0.0.2 || 10.0.0.3"
	dlvSame(t, e, dlvRS("expected   10.0.0.1", "           10.0.0.2", "or         10.0.0.3"))
}

// The port is shown only when it is not 53.
func TestSlackTextShowsPortOtherThan53(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, []alert.Line{
		dlvAt(t, "ns1.corp.test.", "10.53.0.11:5353", "10.53.0.99", 60),
		dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", "10.53.0.99", 60),
		dlvAt(t, "ns3.corp.test.", "[2001:db8::1]:53", "10.53.0.99", 60),
		dlvAt(t, "ns4.corp.test.", "[2001:db8::2]:853", "10.53.0.99", 60),
	})
	dlvSame(t, e, dlvRS("expected   10.53.0.81", "", "now        10.53.0.99",
		"seen at    ns1.corp.test. (10.53.0.11:5353)   TTL 60",
		"           ns2.corp.test. (10.53.0.12)   TTL 60",
		"           ns3.corp.test. (2001:db8::1)   TTL 60",
		"           ns4.corp.test. ([2001:db8::2]:853)   TTL 60"))
}

// A list shows six records, then counts the rest.
func TestSlackTextShowsSixRecords(t *testing.T) {
	var seven []string
	for i := 1; i <= 7; i++ {
		seven = append(seven, fmt.Sprintf("10.0.0.%d", i))
	}
	list := strings.Join(seven, " | ")
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, []alert.Line{dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", list, 60)})
	e.Alert.Expected = list
	dlvSame(t, e, dlvRS("expected   10.0.0.1", "           10.0.0.2", "           10.0.0.3", "           10.0.0.4",
		"           10.0.0.5", "           10.0.0.6", "           and 1 more records",
		"", "now        10.0.0.1", "           10.0.0.2", "           10.0.0.3", "           10.0.0.4",
		"           10.0.0.5", "           10.0.0.6", "           and 1 more records",
		"seen at    ns1.corp.test. (10.53.0.11)   TTL 60"))
}

// A record is cut at 120 octets.
func TestSlackTextCutsARecordAt120(t *testing.T) {
	long := strings.Repeat("x", 130)
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, nil)
	e.Alert.Expected = long
	dlvSame(t, e, dlvRS("expected   "+strings.Repeat("x", 114)+" [cut]"))
}

// The view shows three answers, then counts the others.
func TestSlackTextShowsThreeAnswers(t *testing.T) {
	var lines []alert.Line
	for i := 1; i <= 4; i++ {
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), fmt.Sprintf("10.53.0.9%d", i), 60))
	}
	dlvSame(t, dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines), dlvRS("expected   10.53.0.81",
		"", "now        10.53.0.91", "seen at    ns1.corp.test. (10.53.0.1)   TTL 60",
		"", "now        10.53.0.92", "seen at    ns2.corp.test. (10.53.0.2)   TTL 60",
		"", "now        10.53.0.93", "seen at    ns3.corp.test. (10.53.0.3)   TTL 60",
		"           and 1 more answers"))
}

// Six servers are shown over all the answers.
func TestSlackTextShowsSixServersOverTwoAnswers(t *testing.T) {
	var lines []alert.Line
	for i := 1; i <= 7; i++ {
		text := "10.53.0.91"
		if i > 4 {
			text = "10.53.0.92"
		}
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), text, 60))
	}
	dlvSame(t, dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines), dlvRS("expected   10.53.0.81",
		"", "now        10.53.0.91", "seen at    ns1.corp.test. (10.53.0.1)   TTL 60", "           ns2.corp.test. (10.53.0.2)   TTL 60",
		"           ns3.corp.test. (10.53.0.3)   TTL 60", "           ns4.corp.test. (10.53.0.4)   TTL 60",
		"", "now        10.53.0.92", "seen at    ns5.corp.test. (10.53.0.5)   TTL 60", "           ns6.corp.test. (10.53.0.6)   TTL 60",
		"           and 1 more servers"))
}

// A text that the caps leave over 3000 octets loses lines from the end of its
// view, which ends with [cut]; its headline, times and action stay whole.
func TestSlackTextOver3000OctetsIsCut(t *testing.T) {
	record := func(prefix string, i int) string { return prefix + strings.Repeat("x", 100) + strconv.Itoa(i) }
	var expected []string
	for i := 1; i <= 6; i++ {
		expected = append(expected, record("e", i))
	}
	var lines []alert.Line
	for i := 1; i <= 3; i++ {
		var answer []string
		for j := 1; j <= 6; j++ {
			answer = append(answer, record("a"+strconv.Itoa(i), j))
		}
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), strings.Join(answer, " | "), 60))
	}
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines)
	e.Alert.Expected = strings.Join(expected, " | ")
	got := deliver.SlackText(e)
	all := strings.Split(got, "\n")
	n := len(all)
	if len(got) > 3000 || n < 9 || all[n-6] != "[cut]" || all[n-5] != "```" {
		t.Fatalf("%d octets, text:\n%s\nwant at most 3000 and the view ended by [cut]", len(got), got)
	}
	if all[0] != dlvRSHead || all[n-3] != dlvRSClock || all[n-1] != dlvRSAction {
		t.Errorf("text:\n%s\nwant the headline, the times and the action whole", got)
	}
	if len(got) < 2700 {
		t.Errorf("%d octets: more lines were cut than the limit needs", len(got))
	}
	if ref := dlvSlackText(e); got != ref {
		t.Errorf("text:\n%s\nwant:\n%s", got, ref)
	}
}

// Data from DNS that tries to leave its code span, to mention or to link is
// shown as text.
func TestSlackTextCleansHostileData(t *testing.T) {
	name, err := dnswire.NameFromLabels([]string{"<!channel>", "`x`", "corp", "test"})
	if err != nil {
		t.Fatal(err)
	}
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), name, dnswire.TypeTXT),
			Expected: "<https://x|y> & *_~",
			Lines: []alert.Line{{Server: obs.Server{Name: name, Addr: netip.MustParseAddrPort("10.53.0.11:53")},
				Text: "\"a\"\n```\n<@U123>\r\x00é", TTL: 1}},
			Opened: dlvOpened, LastClean: dlvLastClean},
		Was: decide.SeverityHigh,
		At:  dlvOpened,
	}
	want := ":red_circle: *HIGH* · `&lt;!channel&gt;.\\096x\\096.corp.test. TXT` changed\n\n" +
		"```\n" +
		"expected   &lt;https://x|y&gt; &amp; *_~\n" +
		"\n" +
		"now        \"a\"\\010\\096\\096\\096\\010&lt;@U123&gt;\\013\\000\\195\\169\n" +
		"seen at    &lt;!channel&gt;.\\096x\\096.corp.test. (10.53.0.11)   TTL 1\n" +
		"```\n\n" +
		":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC\n\n" +
		":point_right: If you did not make this change, check your DNS provider account now. If you did, run osk-dns-watcher accept."
	dlvSame(t, e, want)
}

// The two texts of the gate run of lab 0, as the webhook of Slack carries them.
func TestSlackMessageOfTheGateExample(t *testing.T) {
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleNameServers, Severity: decide.SeverityCritical, Peak: decide.SeverityCritical,
			Check:    obs.DelegationKey(dlvName(t, "corp.test.")),
			Expected: "ns1.corp.test. | ns2.corp.test.",
			Value:    "10.53.0.3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test.",
			Lines: []alert.Line{{Server: obs.Server{Name: dlvName(t, "ns.test."), Addr: netip.MustParseAddrPort("10.53.0.3:53")},
				Text: "ns1.dnshost.test. | ns2.dnshost.test.", TTL: 300, Received: dlvGateTime}},
			Opened: dlvGateTime, LastClean: dlvGateClean, Noticed: dlvGateTime},
		Was: decide.SeverityCritical,
		At:  dlvGateTime,
	}
	want := "{\"text\":\":rotating_light: *CRITICAL* · nameservers of `corp.test.` changed at the parent zone\\n\\n```\\n" +
		"expected   ns1.corp.test.\\n           ns2.corp.test.\\n\\n" +
		"now        ns1.dnshost.test.\\n           ns2.dnshost.test.\\n" +
		"seen at    ns.test. (10.53.0.3)   TTL 300\\n```\\n\\n" +
		":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC\\n\\n" +
		":point_right: If you did not change the nameservers, contact your registrar now. If you did, run osk-dns-watcher accept.\"}"
	if got := deliver.SlackMessage(e); string(got) != want {
		t.Errorf("message:\n%s\nwant:\n%s", got, want)
	}

	resolved := time.Date(2026, 11, 11, 14, 9, 41, 0, time.UTC)
	e.Kind, e.Alert.Open, e.Alert.Resolved, e.At = alert.EventResolve, false, resolved, resolved
	want = "{\"text\":\":white_check_mark: *RESOLVED* · nameservers of `corp.test.` are as expected again\\n\\n```\\n" +
		"now        ns1.corp.test.\\n           ns2.corp.test.\\n```\\n\\n" +
		":clock3: Open for 7 min 34 s · first seen 14:02:07 · resolved 14:09:41 · 11 Nov 2026 UTC\\n\\n" +
		":point_right: If you did not make or undo this change yourself, find out who did.\"}"
	if got := deliver.SlackMessage(e); string(got) != want {
		t.Errorf("resolved message:\n%s\nwant:\n%s", got, want)
	}
}

// The two examples of the message rules, byte for byte.
func TestSlackTextOfTheRuleExamples(t *testing.T) {
	opened := time.Date(2026, 11, 16, 15, 17, 12, 0, time.UTC)
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleNameServers, Severity: decide.SeverityCritical, Peak: decide.SeverityCritical,
			Check:    obs.DelegationKey(dlvName(t, "corp.test.")),
			Expected: "ns1.corp.test. | ns2.corp.test.",
			Lines:    []alert.Line{dlvAt(t, "ns.test.", "10.53.0.3:53", "ns1.dnshost.test. | ns2.dnshost.test.", 300)},
			Opened:   opened, LastClean: time.Date(2026, 11, 16, 15, 17, 10, 0, time.UTC)},
		Was: decide.SeverityCritical,
		At:  opened,
	}
	want := strings.Join([]string{
		":rotating_light: *CRITICAL* · nameservers of `corp.test.` changed at the parent zone",
		"",
		"```",
		"expected   ns1.corp.test.",
		"           ns2.corp.test.",
		"",
		"now        ns1.dnshost.test.",
		"           ns2.dnshost.test.",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
		"```",
		"",
		":clock3: First seen 15:17:12 · last OK 15:17:10 · 16 Nov 2026 UTC",
		"",
		":point_right: If you did not change the nameservers, contact your registrar now. If you did, run osk-dns-watcher accept.",
	}, "\n")
	dlvSame(t, e, want)

	e.Kind, e.Alert.Open, e.At = alert.EventResolve, false, opened.Add(3*time.Second)
	e.Alert.Resolved = e.At
	want = strings.Join([]string{
		":white_check_mark: *RESOLVED* · nameservers of `corp.test.` are as expected again",
		"",
		"```",
		"now        ns1.corp.test.",
		"           ns2.corp.test.",
		"```",
		"",
		":clock3: Open for 3 s · first seen 15:17:12 · resolved 15:17:15 · 16 Nov 2026 UTC",
		"",
		":point_right: If you did not make or undo this change yourself, find out who did.",
	}, "\n")
	dlvSame(t, e, want)
}

// dlvServer is a TLS test server and a client that trusts it and may post to
// it.
func dlvServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *httpclient.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	host, err := httpclient.HostOf(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return srv, httpclient.New([]string{host}, pool)
}

func TestSlackSendPostsTheMessage(t *testing.T) {
	type request struct {
		method, path, contentType string
		body                      []byte
	}
	got := make(chan request, 1)
	srv, c := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- request{r.Method, r.URL.Path, r.Header.Get("Content-Type"), body}
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := io.WriteString(w, "slow down"); err != nil {
			t.Error(err)
		}
	})
	slack := deliver.NewSlack(c, srv.URL+"/services/T0/B0/dlvsecret", decide.SeverityHigh)
	if slack.Name() != "slack" || slack.MinSeverity() != decide.SeverityHigh {
		t.Errorf("Name %q, MinSeverity %v; want slack, high", slack.Name(), slack.MinSeverity())
	}
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
	if !bytes.Equal(slack.Message(e), deliver.SlackMessage(e)) {
		t.Errorf("Message %q, want SlackMessage %q", slack.Message(e), deliver.SlackMessage(e))
	}
	o := slack.Send(context.Background(), deliver.SlackMessage(e))
	// The Date of the answer has a test of its own.
	o.Date = time.Time{}
	// "slow down" is no error word, so Send passes on no body.
	want := deliver.Outcome{Status: 429, RetryAfter: 30 * time.Second}
	if !reflect.DeepEqual(o, want) {
		t.Errorf("Send gave %+v, want %+v", o, want)
	}
	select {
	case r := <-got:
		if r.method != http.MethodPost || r.path != "/services/T0/B0/dlvsecret" || r.contentType != "application/json" ||
			!bytes.Equal(r.body, deliver.SlackMessage(e)) {
			t.Errorf("the server got %s %s, Content-Type %q, body %q", r.method, r.path, r.contentType, r.body)
		}
	default:
		t.Error("the server got no request")
	}
}

// The URL of a Slack channel is its secret, so a printed channel shows only
// its name.
func TestSlackPrintsNoURL(t *testing.T) {
	slack := deliver.NewSlack(httpclient.New(nil, nil), "https://hooks.slack.test/services/T0/B0/dlvprinted", decide.SeverityLow)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{slack, *slack} {
			if got := fmt.Sprintf(format, v); got != "slack" {
				t.Errorf("Sprintf(%q, %T) = %q, want slack", format, v, strings.ReplaceAll(got, "dlvprinted", "[marker]"))
			}
		}
	}
}

// dlvPrivateDir is a new folder that only its owner may enter: the store
// refuses a folder that other users can read, and t.TempDir makes one with
// the mode the umask leaves.
func dlvPrivateDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

// dlvStore opens a store in a new folder and closes it at the end of the
// test.
func dlvStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := dlvPrivateDir(t)
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, dir
}

// dlvFolderHolds reports whether a file in the folder holds the text.
func dlvFolderHolds(t *testing.T, dir, text string) bool {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(text)) {
			return true
		}
	}
	return false
}

// The path of a Slack webhook URL is its secret. Whatever goes wrong, it
// never reaches an error, a reason, a line of output or the store.
func TestWebhookSecretNeverLeaves(t *testing.T) {
	const secret = "dlvT0B0secret"
	// The server does not see a client leave while it reads nothing, so the
	// silent handler waits for the end of the test too.
	release := make(chan struct{})
	srv, trusting := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/redirect/"):
			w.Header().Set("Location", "https://"+r.Host+"/elsewhere")
			w.WriteHeader(http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/payload/"):
			w.WriteHeader(http.StatusBadRequest)
			if _, err := io.WriteString(w, "invalid_payload"); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/echo/"):
			w.WriteHeader(http.StatusBadRequest)
			if _, err := io.WriteString(w, "no_team: "+r.URL.Path); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/busy/"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasPrefix(r.URL.Path, "/silent/"):
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}
	})
	t.Cleanup(func() { close(release) })
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, _ := httpclient.HostOf(srv.URL)
	untrusting := httpclient.New([]string{host}, nil)
	closed := dlvClosedPort(t)
	refusing := httpclient.New([]string{"127.0.0.1:" + closed}, nil)
	const badURL = `no answer "not an https URL with a host and no user name"`
	cases := []struct {
		name   string
		c      *httpclient.Client
		url    string
		reason string // exact, or a prefix when it ends in a space
		state  store.RowState
	}{
		{"not https", trusting, "http://" + addr + "/services/" + secret, badURL, store.RowPending},
		{"user info", trusting, "https://u:" + secret + "@" + addr + "/services/" + secret, badURL, store.RowPending},
		{"bad escape", trusting, "https://" + addr + "/services/" + secret + "%zz", badURL, store.RowPending},
		{"bad port", trusting, "https://127.0.0.1:8x/services/" + secret, badURL, store.RowPending},
		{"control octet", trusting, "https://" + addr + "/services/" + secret + "\n", badURL, store.RowPending},
		{"host not listed", trusting, "https://127.0.0.9:" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + "/services/" + secret,
			`no answer "host not allowed"`, store.RowPending},
		{"refused connection", refusing, "https://127.0.0.1:" + closed + "/services/" + secret, `no answer "network: `, store.RowPending},
		{"timeout", trusting, "https://" + addr + "/silent/" + secret, `no answer "timeout"`, store.RowPending},
		{"untrusted certificate", untrusting, "https://" + addr + "/services/" + secret, `no answer "network: `, store.RowPending},
		{"redirect", trusting, "https://" + addr + "/redirect/" + secret, "status 302", store.RowGivenUp},
		{"4xx with a body", trusting, "https://" + addr + "/payload/" + secret, `status 400 "invalid_payload"`, store.RowGivenUp},
		{"4xx that repeats the path", trusting, "https://" + addr + "/echo/" + secret, "status 400", store.RowGivenUp},
		{"5xx", trusting, "https://" + addr + "/busy/" + secret, "status 503", store.RowPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The store is closed once, before its files are read; the
			// cleanup closes it only when the test stops before that.
			dir := dlvPrivateDir(t)
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = s.Close()
				}
			})
			slack := deliver.NewSlack(c.c, c.url, decide.SeverityLow)
			e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
			if err := s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{slack})); err != nil {
				t.Fatal(err)
			}
			// The silent server is left by the client's own timeout: a
			// send that the context of the pass cut would be no attempt.
			ctx, cancel := context.WithTimeout(context.Background(), httpclient.Timeout+5*time.Second)
			defer cancel()
			attempts, err := deliver.Pass(ctx, s, []deliver.Channel{slack}, dlvLater)
			if err != nil {
				t.Fatal(err)
			}
			if len(attempts) != 1 {
				t.Fatalf("%d attempts, want 1", len(attempts))
			}
			a := attempts[0]
			reason := a.Done.Reason
			if prefix := strings.HasSuffix(c.reason, " "); !prefix && reason != c.reason || prefix && !strings.HasPrefix(reason, c.reason) {
				t.Errorf("reason %q, want %q", reason, c.reason)
			}
			if a.Done.State != c.state {
				t.Errorf("state %v, want %v", a.Done.State, c.state)
			}
			for what, text := range map[string]string{"error": a.Outcome.Err, "body": string(a.Outcome.Body), "reason": reason, "line": a.Line()} {
				if strings.Contains(text, secret) {
					t.Errorf("the %s holds the secret: %q", what, text)
				}
			}
			closed = true
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if !dlvFolderHolds(t, dir, e.Label()) {
				t.Errorf("no file of the store holds the label %q, so the search for the secret saw no row", e.Label())
			}
			if dlvFolderHolds(t, dir, secret) {
				t.Error("a file of the store holds the secret")
			}
		})
	}
}

// dlvAnswer is a raw HTTP answer with this status and body.
func dlvAnswer(status, body string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

// A server may repeat the secret path of the webhook URL in any form: cut,
// escaped, in lower case, inside a longer text, or in a header that the client
// cannot read. None of its text reaches a result, a reason, a line or the
// store, except one of Slack's own error words.
func TestServerTextReachesNoReason(t *testing.T) {
	const m = "dlvEchoMarker7"
	const short = "dlvMk7z" // shorter than 8 octets
	const word = "dlvwordsecret"
	const p = "/services/T0/B0/" + m
	const noAnswer = `no answer "network: no usable answer"`
	cases := []struct {
		name, path, marker, answer, reason string
	}{
		{"path without its slash", p, m, dlvAnswer("400 Bad Request", p[1:]), "status 400"},
		{"last segment", p, m, dlvAnswer("400 Bad Request", m), "status 400"},
		{"JSON-escaped path", p, m, dlvAnswer("400 Bad Request", `{"error":"`+strings.ReplaceAll(p, "/", `\/`)+`"}`), "status 400"},
		{"URL-encoded path", p, m, dlvAnswer("400 Bad Request", url.QueryEscape(p)), "status 400"},
		{"path in lower case", p, m, dlvAnswer("400 Bad Request", strings.ToLower(p)), "status 400"},
		{"path in a bad Location", p, m, "HTTP/1.1 302 Found\r\nLocation: %zz" + p[1:] + "\r\nContent-Length: 0\r\n\r\n", noAnswer},
		{"path in a bad header line", p, m, "HTTP/1.1 200 OK\r\nX" + p[1:] + "\r\n\r\n", noAnswer},
		{"part of a longer segment", "/hooks/id-" + m + ".json", m, dlvAnswer("400 Bad Request", "unknown token "+m), "status 400"},
		{"query key", "/services/T0?v=1&" + m, m, dlvAnswer("400 Bad Request", "unknown parameter "+m), "status 400"},
		{"short segment", "/services/T0/B0/" + short, short, dlvAnswer("400 Bad Request", "token "+short+" revoked"), "status 400"},
		{"word of the URL", "/services/T0/B0/" + word, word, dlvAnswer("400 Bad Request", word), "status 400"},
		{"Slack error word", p, m, dlvAnswer("400 Bad Request", "invalid_payload\n"), `status 400 "invalid_payload"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_, err = io.WriteString(conn, c.answer)
				if err := errors.Join(err, conn.Close()); err != nil {
					t.Error(err)
				}
			})
			show := func(text string) string { return strings.ReplaceAll(text, c.marker, "[marker]") }
			holds := func(text string) bool { return strings.Contains(strings.ToLower(text), strings.ToLower(c.marker)) }
			// The store is closed before its files are read.
			dir := dlvPrivateDir(t)
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			slack := deliver.NewSlack(client, srv.URL+c.path, decide.SeverityLow)
			e := dlvOpen(t, "www.corp.test.", decide.SeverityHigh, decide.SeverityHigh)
			var attempts []deliver.Attempt
			err = s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{slack}))
			if err == nil {
				attempts, err = deliver.Pass(context.Background(), s, []deliver.Channel{slack}, dlvLater)
			}
			if err := errors.Join(err, s.Close()); err != nil || len(attempts) != 1 {
				t.Fatalf("Apply, Pass and Close: %d attempts, %v; want 1 and no error", len(attempts), err)
			}
			a := attempts[0]
			if a.Done.Reason != c.reason {
				t.Errorf("reason %q, want %q", show(a.Done.Reason), c.reason)
			}
			for what, text := range map[string]string{"error": a.Outcome.Err, "body": string(a.Outcome.Body), "reason": a.Done.Reason, "line": a.Line()} {
				if holds(text) {
					t.Errorf("the %s holds the secret: %q", what, show(text))
				}
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				data, err := os.ReadFile(filepath.Join(dir, f.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if holds(string(data)) {
					t.Errorf("%s holds the secret", f.Name())
				}
			}
			if !dlvFolderHolds(t, dir, e.Label()) {
				t.Error("no file of the store holds the label of the row, so the search saw no row")
			}
		})
	}
}

// dlvClosedPort returns a port of 127.0.0.1 where nothing listens.
func dlvClosedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
