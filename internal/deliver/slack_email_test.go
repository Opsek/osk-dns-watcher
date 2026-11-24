package deliver_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// emlwCase is one of the four mail rules: the line it watches, what the
// servers gave, the words of the alert, and the texts that the rule says.
type emlwCase struct {
	name     string
	rule     decide.Rule
	owner    string
	expected string // the line in force
	seen     string // the text that both servers of corp.test. give
	words    []string
	neutral  string // headline phrase without words
	more     string // headline phrase with words
	resolved string
	action   string
	spans    int // code spans of an open event
}

func emlwCases() []emlwCase {
	return []emlwCase{
		{
			name: "spf", rule: decide.RuleSPF, owner: "corp.test.",
			expected: `"v=spf1 mx -all"`, seen: `"v=spf1 mx include:evil.test ~all"`,
			words:    []string{"all gives softfail in place of fail", "include:evil.test gives pass in place of fail"},
			neutral:  "the SPF record at `corp.test.` changed",
			more:     "the SPF record at `corp.test.` lets more senders pass than the file",
			resolved: "the SPF record at `corp.test.` is as expected again",
			action:   "If you did not make this change, restore the record at your DNS provider: every sender that it lets pass can send mail as `corp.test.`. If you did, run osk-dns-watcher accept.",
			spans:    2,
		},
		{
			name: "dmarc", rule: decide.RuleDMARC, owner: "_dmarc.corp.test.",
			expected: `"v=DMARC1; p=reject"`, seen: `"v=DMARC1; p=none; rua=mailto:x@evil.test"`,
			words:    []string{"p=none in place of p=reject", "rua also sends reports to mailto:x@evil.test"},
			neutral:  "the DMARC record `_dmarc.corp.test.` changed",
			more:     "the DMARC record `_dmarc.corp.test.` asks receivers to do less than the file",
			resolved: "the DMARC record `_dmarc.corp.test.` is as expected again",
			action:   "If you did not make this change, restore the record at your DNS provider: receivers follow it for mail that claims to come from your domain. If you did, run osk-dns-watcher accept.",
			spans:    1,
		},
		{
			name: "dkim", rule: decide.RuleDKIM, owner: "s1._domainkey.corp.test.",
			expected: `"v=DKIM1; k=rsa; p=QUJDRA=="`, seen: `"v=DKIM1; k=rsa; p=RUZHSA=="`,
			words:    []string{`a key that the file does not list: k=rsa, 8 characters, ending "RUZHSA=="`},
			neutral:  "the DKIM key `s1._domainkey.corp.test.` changed",
			more:     "the DKIM key `s1._domainkey.corp.test.` lets another key sign mail",
			resolved: "the DKIM key `s1._domainkey.corp.test.` is as expected again",
			action:   "If you did not change this key, remove the key that is not yours at your DNS provider: whoever holds its private key can sign mail that receivers trust. If you did, run osk-dns-watcher accept.",
			spans:    1,
		},
		{
			name: "mta-sts", rule: decide.RuleMTASTS, owner: "_mta-sts.corp.test.",
			expected: `"v=STSv1; id=20261117"`, seen: "none",
			words:    []string{"no MTA-STS record: senders that have not cached the policy send mail without it"},
			neutral:  "MTA-STS at `_mta-sts.corp.test.` changed",
			more:     "MTA-STS at `_mta-sts.corp.test.` protects less than the file",
			resolved: "MTA-STS at `_mta-sts.corp.test.` is as expected again",
			action:   "If you did not make this change, restore it: senders use MTA-STS to refuse mail servers that are not yours. If you did, run osk-dns-watcher accept.",
			spans:    1,
		},
	}
}

const emlwMedium = ":large_orange_circle: *MEDIUM*"

// emlwServers gives n servers ns1.corp.test. to nsN.corp.test. that all give text.
func emlwServers(t testing.TB, n int, text string) []alert.Line {
	var lines []alert.Line
	for i := 1; i <= n; i++ {
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", 10+i), text, 300))
	}
	return lines
}

// emlwValue is the Value of an alert: one line for each server, as the
// rules write it ("<address> <host> <text>"), then "weaker <word>" for each word.
func emlwValue(lines []alert.Line, words []string) string {
	var out []string
	for _, l := range lines {
		out = append(out, l.Server.Addr.String()+" "+l.Server.Name.Lower().String()+" "+l.Text)
	}
	for _, w := range words {
		out = append(out, "weaker "+w)
	}
	return strings.Join(out, "\n")
}

func emlwEvent(t testing.TB, kind alert.EventKind, c emlwCase, lines []alert.Line, words []string) alert.Event {
	a := alert.Alert{
		ID: 4, Open: kind != alert.EventResolve, Rule: c.rule, Severity: decide.SeverityMedium, Peak: decide.SeverityMedium,
		Check:    obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, c.owner), dnswire.TypeTXT),
		Expected: c.expected, Lines: lines, Value: emlwValue(lines, words),
		Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed,
	}
	if kind == alert.EventResolve {
		a.Resolved = dlvResolved
	}
	return alert.Event{Kind: kind, Alert: a, Was: decide.SeverityLow, At: dlvResolved}
}

// emlwSetView is the generic part of the view of two servers that give seen.
func emlwSetView(c emlwCase) []string {
	return []string{
		"expected   " + c.expected,
		"",
		"now        " + c.seen,
		"seen at    ns1.corp.test. (10.53.0.11)   TTL 300",
		"           ns2.corp.test. (10.53.0.12)   TTL 300",
	}
}

// emlwWeakerView is the block of words: the first under "weaker", the others
// under 11 spaces, then one empty line.
func emlwWeakerView(words []string) []string {
	var view []string
	for i, w := range words {
		label := "           "
		if i == 0 {
			label = "weaker     "
		}
		view = append(view, label+w)
	}
	return append(view, "")
}

func emlwText(headline string, view []string, c emlwCase) string {
	return dlvFull(headline, view, dngOpenClock, ":point_right: "+c.action)
}

// An alert with words says that the record permits more and lists the words
// first; without a word it only says that the record changed; a resolve is
// the generic resolve with the line in force.
func TestSlackTextOfTheMailRules(t *testing.T) {
	for _, c := range emlwCases() {
		t.Run(c.name, func(t *testing.T) {
			lines := emlwServers(t, 2, c.seen)

			open := emlwEvent(t, alert.EventOpen, c, lines, c.words)
			dngCheck(t, open, emlwText(emlwMedium+dlvDot+c.more, slices.Concat(emlwWeakerView(c.words), emlwSetView(c)), c), c.spans)

			neutral := emlwEvent(t, alert.EventOpen, c, lines, nil)
			dngCheck(t, neutral, emlwText(emlwMedium+dlvDot+c.neutral, emlwSetView(c), c), c.spans)

			update := emlwEvent(t, alert.EventUpdate, c, lines, c.words)
			dngCheck(t, update, emlwText(emlwMedium+", changed again"+dlvDot+c.more, slices.Concat(emlwWeakerView(c.words), emlwSetView(c)), c), c.spans)
			updateNeutral := emlwEvent(t, alert.EventUpdate, c, lines, nil)
			dngCheck(t, updateNeutral, emlwText(emlwMedium+", changed again"+dlvDot+c.neutral, emlwSetView(c), c), c.spans)

			// The resolve names the line in force; the words of the open event,
			// which its alert may still hold, are not shown.
			resolveView := []string{"now        " + c.expected}
			for _, words := range [][]string{nil, c.words} {
				resolve := emlwEvent(t, alert.EventResolve, c, lines, words)
				dngCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+c.resolved, resolveView, dngResolveClock, dngResolved), 1)
			}
		})
	}
}

// The phrase with words is for every event that is not a resolve.
func TestSlackTextOfTheMailRulesUsesTheWordsPhraseForEachEventThatIsNotAResolve(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 2, c.seen)
	for kind, suffix := range map[alert.EventKind]string{
		alert.EventOpen: "", alert.EventUpdate: ", changed again", alert.EventEscalate: ", raised from low", alert.EventReminder: ", still open",
	} {
		e := emlwEvent(t, kind, c, lines, c.words)
		want := emlwMedium + suffix + dlvDot + c.more
		if got := strings.Split(deliver.SlackText(e), "\n")[0]; got != want {
			t.Errorf("%v with words: headline %q, want %q", kind, got, want)
		}
		e = emlwEvent(t, kind, c, lines, nil)
		want = emlwMedium + suffix + dlvDot + c.neutral
		if got := strings.Split(deliver.SlackText(e), "\n")[0]; got != want {
			t.Errorf("%v without words: headline %q, want %q", kind, got, want)
		}
	}
}

// Only a Value line that starts with "weaker " is a word.
func TestSlackTextOfTheMailRulesReadsOnlyLinesThatStartWithWeakerAndASpace(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 2, `"weaker all"`)
	for _, extra := range []string{"", "weaker", "weakerall", " weaker all", "Weaker all", "not weaker all"} {
		e := emlwEvent(t, alert.EventOpen, c, lines, nil)
		if extra != "" {
			e.Alert.Value += "\n" + extra
		}
		want := emlwText(emlwMedium+dlvDot+c.neutral, []string{
			"expected   " + c.expected, "", `now        "weaker all"`,
			"seen at    ns1.corp.test. (10.53.0.11)   TTL 300",
			"           ns2.corp.test. (10.53.0.12)   TTL 300",
		}, c)
		if got := deliver.SlackText(e); got != want {
			t.Errorf("a Value that adds %q gave:\n%s\nwant:\n%s", extra, got, want)
		}
	}
}

// The other rules have no words, whatever their Value holds.
func TestSlackTextOfOtherRulesShowsNoWeakerBlock(t *testing.T) {
	lines := []alert.Line{dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", "10.53.0.99", 300)}
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines)
	e.Alert.Value = emlwValue(lines, []string{"all gives softfail in place of fail"})
	want := dlvRS("expected   10.53.0.81", "", "now        10.53.0.99", "seen at    ns1.corp.test. (10.53.0.11)   TTL 300")
	if got := deliver.SlackText(e); got != want {
		t.Errorf("record-set text with a weaker line:\n%s\nwant:\n%s", got, want)
	}
}

// At most six words are shown, then the count of the others.
func TestSlackTextOfTheMailRulesShowsSixWords(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 2, c.seen)
	for _, n := range []int{1, 5, 6, 7, 8, 12, 40} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			var words []string
			for i := 1; i <= n; i++ {
				words = append(words, fmt.Sprintf("word %d", i))
			}
			shown := words[:min(n, 6)]
			view := emlwWeakerView(shown)
			if n > 6 {
				view = slices.Insert(view, 6, fmt.Sprintf("           and %d more", n-6))
			}
			view = slices.Concat(view, emlwSetView(c))
			dngCheck(t, emlwEvent(t, alert.EventOpen, c, lines, words), emlwText(emlwMedium+dlvDot+c.more, view, c), c.spans)
		})
	}
}

// The words come first and the generic view follows with its own limit of
// six servers.
func TestSlackTextOfTheMailRulesShowsWordsAndSevenServers(t *testing.T) {
	c := emlwCases()[1]
	lines := emlwServers(t, 7, c.seen)
	view := slices.Concat(emlwWeakerView(c.words), []string{"expected   " + c.expected, "", "now        " + c.seen})
	for i := 1; i <= 6; i++ {
		label := "           "
		if i == 1 {
			label = "seen at    "
		}
		view = append(view, fmt.Sprintf("%sns%d.corp.test. (10.53.0.%d)   TTL 300", label, i, 10+i))
	}
	view = append(view, "           and 1 more servers")
	dngCheck(t, emlwEvent(t, alert.EventOpen, c, lines, c.words), emlwText(emlwMedium+dlvDot+c.more, view, c), c.spans)
}

// A word is data from DNS: it passes through Clean at 120 octets.
func TestSlackTextOfTheMailRulesCleansEachWord(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 2, c.seen)
	long := strings.Repeat("x", 200)
	for _, w := range []struct{ name, word, shown string }{
		{"a backtick", "include:a`b.test gives pass in place of fail", `include:a\096b.test gives pass in place of fail`},
		{"markup", "a&b<c>d", "a&amp;b&lt;c&gt;d"},
		{"an octet outside ASCII", "a\xffb\x01", `a\255b\001`},
		{"a long word", long, strings.Repeat("x", 114) + " [cut]"},
		{"a word of 120 octets", strings.Repeat("y", 120), strings.Repeat("y", 120)},
		{"a word of 121 octets", strings.Repeat("y", 121), strings.Repeat("y", 114) + " [cut]"},
		{"a long word of escapes", strings.Repeat("`", 100), strings.Repeat(`\096`, 28) + " [cut]"},
	} {
		t.Run(w.name, func(t *testing.T) {
			words := []string{"first word", w.word, "last word"}
			view := slices.Concat(emlwWeakerView([]string{"first word", w.shown, "last word"}), emlwSetView(c))
			dngCheck(t, emlwEvent(t, alert.EventOpen, c, lines, words), emlwText(emlwMedium+dlvDot+c.more, view, c), c.spans)
		})
	}
}

// A text over 3000 octets loses lines from the end of the view, which then
// ends with [cut]; the words stand at its start, so all six stay.
func TestSlackTextOfTheMailRulesKeepsTheWordsWhenTheTextIsCut(t *testing.T) {
	c := emlwCases()[0]
	record := func(c byte) string { return `"` + strings.Repeat(string(c), 110) + `"` }
	records := func(c byte) string { return strings.Join(slices.Repeat([]string{record(c)}, 6), " | ") }
	c.expected = records('e')
	var lines []alert.Line
	for i, b := range []byte("abc") {
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i+1), fmt.Sprintf("10.53.0.%d:53", 11+i), records(b), 300))
	}
	var words []string
	for i := 1; i <= 7; i++ {
		words = append(words, strings.Repeat(strconv.Itoa(i), 150))
	}
	e := emlwEvent(t, alert.EventOpen, c, lines, words)
	got := deliver.SlackText(e)
	if len(got) > 3000 {
		t.Errorf("%d octets, more than 3000", len(got))
	}
	var shown []string
	for _, w := range words[:6] {
		shown = append(shown, dlvClean(w, 120))
	}
	block := slices.Insert(emlwWeakerView(shown), 6, "           and 1 more")
	view := slices.Concat(block, dlvExpected("expected", c.expected), dlvAnswers(lines))
	want := dlvAssemble(emlwMedium+dlvDot+c.more, view, dngOpenClock, ":point_right: "+c.action)
	if got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	for _, l := range block[:len(block)-1] {
		if !strings.Contains(got, "\n"+l+"\n") {
			t.Errorf("the cut text lacks the line %q", l)
		}
	}
	if !strings.Contains(got, "\n[cut]\n```\n") {
		t.Errorf("the view does not end with [cut]:\n%s", got)
	}
}

type emlwWebhook struct {
	Rule     string   `json:"rule"`
	Severity string   `json:"severity"`
	Expected string   `json:"expected"`
	Value    []string `json:"value"`
	More     int      `json:"more"`
	Text     string   `json:"text"`
	Seen     []struct {
		Text string `json:"text"`
	} `json:"seen"`
	Check struct {
		Kind, Domain, Name, RType string
	} `json:"check"`
}

// The webhook carries the rule word, and Value cut to six server lines and
// then every "weaker" line.
func TestWebhookMessageCarriesTheMailRules(t *testing.T) {
	for _, c := range emlwCases() {
		for _, servers := range []int{2, 6, 7, 40} {
			for _, nwords := range []int{0, 2, 11, 12} {
				t.Run(fmt.Sprintf("%s with %d servers and %d words", c.name, servers, nwords), func(t *testing.T) {
					var words []string
					for i := 1; i <= nwords; i++ {
						words = append(words, fmt.Sprintf("word %d of %s", i, c.name))
					}
					if nwords == 12 {
						// The line that stands for the words that osk-dns-watcher left out.
						words[11] = "and 3 more"
					}
					lines := emlwServers(t, servers, c.seen)
					e := emlwEvent(t, alert.EventOpen, c, lines, words)
					var got emlwWebhook
					if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
						t.Fatal(err)
					}
					if got.Rule != c.name || got.Severity != "medium" || got.Expected != c.expected {
						t.Errorf("rule %q, severity %q, expected %q; want %q, medium, %q", got.Rule, got.Severity, got.Expected, c.name, c.expected)
					}
					if got.Check.Kind != "records" || got.Check.Domain != "corp.test." || got.Check.Name != c.owner || got.Check.RType != "TXT" {
						t.Errorf("check %+v, want a records check of %s TXT in corp.test.", got.Check, c.owner)
					}
					var want []string
					for i := 1; i <= min(servers, 6); i++ {
						want = append(want, fmt.Sprintf("10.53.0.%d:53 ns%d.corp.test. %s", 10+i, i, c.seen))
					}
					for _, w := range words {
						want = append(want, "weaker "+w)
					}
					if !slices.Equal(got.Value, want) {
						t.Errorf("value:\n%q\nwant:\n%q", got.Value, want)
					}
					if got.More != max(servers-6, 0) || len(got.Seen) != min(servers, 6) {
						t.Errorf("%d seen and more %d; want %d and %d", len(got.Seen), got.More, min(servers, 6), max(servers-6, 0))
					}
					if got.Text != deliver.SlackText(e) {
						t.Errorf("text %q is not the Slack text", got.Text)
					}
				})
			}
		}
	}
}

// A word in the body is cleaned as in Slack, and a resolve carries the rule too.
func TestWebhookMessageCleansTheWordsOfTheMailRules(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 1, c.seen)
	e := emlwEvent(t, alert.EventOpen, c, lines, []string{"a`b\n<c>", strings.Repeat("z", 400)})
	// The line feed in a word starts a line that is no word line; Value holds
	// it as a line of its own, and the body cleans each line.
	var got emlwWebhook
	if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
		t.Fatal(err)
	}
	for _, l := range got.Value {
		if strings.ContainsAny(l, "`<>\n") || len(l) > 160 {
			t.Errorf("the body holds the line %q: it is not clean or longer than 160 octets", l)
		}
	}
	if strings.Contains(strings.Join(got.Value, "\n"), strings.Repeat("z", 400)) {
		t.Error("the body holds a word of 400 octets whole")
	}
	e = emlwEvent(t, alert.EventResolve, c, lines, nil)
	got = emlwWebhook{}
	if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil || got.Rule != "spf" {
		t.Errorf("resolve: rule %q (%v), want spf", got.Rule, err)
	}
}

// emlwFault checks the message of a mail alert against the rules of a Slack
// text and against the place and the number of the lines of words.
func emlwFault(e alert.Event, c emlwCase, words int) string {
	spans := c.spans
	if e.Kind == alert.EventResolve {
		spans = 1
	}
	if fault := dngFault(e, spans); fault != "" {
		return fault
	}
	text := deliver.SlackText(e)
	lines := strings.Split(text, "\n")
	headline, view := lines[0], lines[3:len(lines)-5]
	// What follows the name in the phrase: " changed", or the words' phrase.
	after := func(phrase string) string { return phrase[strings.LastIndex(phrase, "`")+1:] }
	switch {
	case e.Kind == alert.EventResolve:
		if !strings.HasPrefix(view[0], "now        ") || !strings.HasSuffix(headline, after(c.resolved)) {
			return fmt.Sprintf("a resolve: the headline is %q and the view starts with %q", headline, view[0])
		}
		return ""
	case words == 0:
		if !strings.HasPrefix(view[0], "expected   ") || !strings.HasSuffix(headline, after(c.neutral)) {
			return fmt.Sprintf("no words, but the headline is %q and the view starts with %q", headline, view[0])
		}
		return ""
	}
	if !strings.HasSuffix(headline, after(c.more)) {
		return fmt.Sprintf("words, but the headline is %q", headline)
	}
	if !strings.HasPrefix(view[0], "weaker     ") {
		return fmt.Sprintf("the view starts with %q, want the words", view[0])
	}
	end := slices.Index(view, "")
	if end < 1 || end > 7 {
		return fmt.Sprintf("the block of words has %d lines (end %d)", end, end)
	}
	for _, l := range view[1:end] {
		if !strings.HasPrefix(l, "           ") {
			return fmt.Sprintf("a line of the block of words starts with %q", l)
		}
	}
	if end+1 >= len(view) || !strings.HasPrefix(view[end+1], "expected   ") {
		return fmt.Sprintf("the generic view does not follow the words: %q", view[end+1:])
	}
	return ""
}

// Hostile words and servers: the message keeps every rule of a Slack text,
// shows at most six words and a count, and puts the words first.
func TestSlackMessagePropertyOfTheMailRules(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 29))
	cases := emlwCases()
	for range 3000 {
		e := dlvHostileEvent(rng)
		c := cases[rng.IntN(len(cases))]
		e.Alert.Rule = c.rule
		e.Alert.Check.Kind = obs.KindRecords
		words := rng.IntN(15)
		if rng.IntN(3) == 0 {
			words = 0
		}
		oneLine := func() string { return strings.ReplaceAll(dlvHostileText(rng, dlvSize(rng)), "\n", " ") }
		var out []string
		for range rng.IntN(8) {
			out = append(out, "10.53.0.1:53 ns1.corp.test. "+oneLine())
		}
		for range words {
			out = append(out, "weaker "+oneLine())
		}
		e.Alert.Value = strings.Join(out, "\n")
		if fault := emlwFault(e, c, words); fault != "" {
			t.Fatalf("seed %d: rule %s, event %+v: %s", seed, c.name, e, fault)
		}
	}
}

// A last word "and <k> more" is the cap of the rule, not a word: the line
// that ends the block counts the words it leaves out, and adds that k. A last
// word that only looks like it (no number, a blank after it, zero) is a word.
func TestSlackTextOfTheMailRulesCountsTheCapLine(t *testing.T) {
	c := emlwCases()[0]
	lines := emlwServers(t, 2, c.seen)
	plain := func(n int) []string {
		var words []string
		for i := 1; i <= n; i++ {
			words = append(words, fmt.Sprintf("word %d", i))
		}
		return words
	}
	for _, tc := range []struct {
		name  string
		words []string
		shown int
		more  string // the last line of the block, or "" for none
	}{
		{"6 words and 1 more", append(plain(6), "and 1 more"), 6, "and 1 more"},
		{"11 words and 3 more", append(plain(11), "and 3 more"), 6, "and 8 more"},
		{"5 words and 2 more", append(plain(5), "and 2 more"), 5, "and 2 more"},
		{"6 words and x more", append(plain(6), "and x more"), 6, "and 1 more"},
		{"6 words and 3 more with a blank", append(plain(6), "and 3 more "), 6, "and 1 more"},
		{"6 words and 0 more", append(plain(6), "and 0 more"), 6, "and 1 more"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			view := emlwWeakerView(plain(tc.shown))
			if tc.more != "" {
				view = slices.Insert(view, tc.shown, "           "+tc.more)
			}
			view = slices.Concat(view, emlwSetView(c))
			dngCheck(t, emlwEvent(t, alert.EventOpen, c, lines, tc.words), emlwText(emlwMedium+dlvDot+c.more, view, c), c.spans)
		})
	}
}
