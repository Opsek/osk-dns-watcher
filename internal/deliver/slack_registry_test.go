package deliver_test

import (
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	regDS1 = "11111 13 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"
	regDS2 = "22222 13 2 CDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCDCD"

	regOpenClock    = ":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC"
	regResolveClock = ":clock3: Open for 18 h 27 min · first seen 11 Nov 2026 14:02:07 · resolved 12 Nov 2026 08:30:00 · UTC"

	regGlueHead = "nameserver addresses of `corp.test.` changed at the parent zone"
	regDSHead   = "DS of `corp.test.` changed at the parent zone"
	regGoneHead = "`corp.test.` does not exist at the parent zone"

	regGlueAction = ":point_right: If you did not change the addresses of your nameservers, contact your registrar now."
	regDSAction   = ":point_right: If you did not change your DNSSEC keys, contact your registrar now."
	regGoneAction = ":point_right: Contact your registrar now: the registration may have expired, been deleted or been transferred."
	regResolved   = ":point_right: " + dlvResolveAction
)

// regEvent is an event of rule for corp.test. whose alert was opened at the
// time of the other tests of this package.
func regEvent(t testing.TB, kind alert.EventKind, rule decide.Rule, sev decide.Severity, key obs.Key, expected string, lines ...alert.Line) alert.Event {
	e := alert.Event{
		Kind: kind,
		Alert: alert.Alert{ID: 3, Open: kind != alert.EventResolve, Rule: rule, Severity: sev, Peak: sev, Check: key,
			Expected: expected, Lines: lines, Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed},
		Was: decide.SeverityHigh,
		At:  dlvResolved,
	}
	if kind == alert.EventResolve {
		e.Alert.Resolved = dlvResolved
	}
	return e
}

func regCorp(t testing.TB) obs.Key { return obs.DelegationKey(dlvName(t, "corp.test.")) }

func regDSKey(t testing.TB) obs.Key { return obs.DSKey(dlvName(t, "corp.test.")) }

func regCheck(t *testing.T, e alert.Event, want string) {
	t.Helper()
	if got := deliver.SlackText(e); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if fault := regFault(e); fault != "" {
		t.Errorf("the message of this event is faulty: %s", fault)
	}
}

func TestSlackTextOfTheGlueAlert(t *testing.T) {
	line := dlvAt(t, "NS.test.", "10.53.0.3:53", "ns2.corp.test. A 10.53.0.11", 300)
	open := regEvent(t, alert.EventOpen, decide.RuleGlue, decide.SeverityCritical, regCorp(t), "ns2.corp.test. A 10.53.0.12", line)
	regCheck(t, open, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGlueHead, []string{
		"expected   ns2.corp.test. A 10.53.0.12",
		"",
		"now        ns2.corp.test. A 10.53.0.11",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
	}, regOpenClock, regGlueAction))

	update := regEvent(t, alert.EventUpdate, decide.RuleGlue, decide.SeverityCritical, regCorp(t), "ns2.corp.test. A 10.53.0.12", line)
	if got, want := strings.Split(deliver.SlackText(update), "\n")[0], ":rotating_light: *CRITICAL*, changed again"+dlvDot+regGlueHead; got != want {
		t.Errorf("update headline %q, want %q", got, want)
	}

	resolve := regEvent(t, alert.EventResolve, decide.RuleGlue, decide.SeverityCritical, regCorp(t), "ns2.corp.test. A 10.53.0.12", line)
	regCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+"nameserver addresses of `corp.test.` are as expected again", []string{
		"now        as expected again",
	}, regResolveClock, regResolved))
}

// The parts of Expected are split at "; " and no further: a part with a bar
// stays one line. Each distinct text is a block of its own.
func TestSlackTextOfTheGlueAlertWithTwoParts(t *testing.T) {
	lines := []alert.Line{
		dlvAt(t, "ns.test.", "10.53.0.3:53", "ns1.corp.test. A 10.53.0.99", 300),
		dlvAt(t, "ns.test.", "10.53.0.3:53", "ns2.corp.test. AAAA 2001:db8::1", 300),
	}
	expected := "ns1.corp.test. A 10.53.0.11 | 10.53.0.21; ns2.corp.test. AAAA (no line)"
	e := regEvent(t, alert.EventOpen, decide.RuleGlue, decide.SeverityCritical, regCorp(t), expected, lines...)
	regCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGlueHead, []string{
		"expected   ns1.corp.test. A 10.53.0.11 | 10.53.0.21",
		"           ns2.corp.test. AAAA (no line)",
		"",
		"now        ns1.corp.test. A 10.53.0.99",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
		"",
		"now        ns2.corp.test. AAAA 2001:db8::1",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
	}, regOpenClock, regGlueAction))
}

// A part holds " || " too and is not split there: no line with the label or.
func TestSlackTextOfTheGlueAlertDoesNotSplitAPartAtAlternatives(t *testing.T) {
	line := dlvAt(t, "ns.test.", "10.53.0.3:53", "ns1.corp.test. A 10.53.0.99", 300)
	e := regEvent(t, alert.EventOpen, decide.RuleGlue, decide.SeverityCritical, regCorp(t), "ns1.corp.test. A 10.53.0.11 || 10.53.0.12", line)
	regCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGlueHead, []string{
		"expected   ns1.corp.test. A 10.53.0.11 || 10.53.0.12",
		"",
		"now        ns1.corp.test. A 10.53.0.99",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
	}, regOpenClock, regGlueAction))
}

// At most six parts are listed, then the count of the others; a part is cut
// at 120 octets.
func TestSlackTextOfTheGlueAlertShowsSixParts(t *testing.T) {
	line := dlvAt(t, "ns.test.", "10.53.0.3:53", "h1.corp.test. A 10.53.0.99", 300)
	long := "h7.corp.test. A " + strings.Repeat("9", 150)
	for _, n := range []int{1, 6, 7, 9} {
		var parts, view []string
		for i := 1; i <= n; i++ {
			part := fmt.Sprintf("h%d.corp.test. A 10.53.0.%d", i, i)
			if i == 7 {
				part = long
			}
			parts = append(parts, part)
			if i <= 6 {
				prefix := "           "
				if i == 1 {
					prefix = "expected   "
				}
				view = append(view, prefix+part)
			}
		}
		if n > 6 {
			view = append(view, fmt.Sprintf("           and %d more records", n-6))
		}
		view = append(view, "", "now        h1.corp.test. A 10.53.0.99", "seen at    ns.test. (10.53.0.3)   TTL 300")
		t.Run(fmt.Sprint(n), func(t *testing.T) {
			e := regEvent(t, alert.EventOpen, decide.RuleGlue, decide.SeverityCritical, regCorp(t), strings.Join(parts, "; "), line)
			regCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGlueHead, view, regOpenClock, regGlueAction))
		})
	}
	e := regEvent(t, alert.EventOpen, decide.RuleGlue, decide.SeverityCritical, regCorp(t), long, line)
	regCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGlueHead, []string{
		"expected   " + deliver.Clean(long, 120),
		"",
		"now        h1.corp.test. A 10.53.0.99",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
	}, regOpenClock, regGlueAction))
}

func TestSlackTextOfTheDSAlert(t *testing.T) {
	none := dlvAt(t, "ns.test.", "10.53.0.3:53", "none", 900)
	open := regEvent(t, alert.EventOpen, decide.RuleDS, decide.SeverityHigh, regDSKey(t), regDS1, none)
	regCheck(t, open, dlvFull(":red_circle: *HIGH*"+dlvDot+regDSHead, []string{
		"expected   " + regDS1,
		"",
		"now        none",
		"seen at    ns.test. (10.53.0.3)   TTL 900",
	}, regOpenClock, regDSAction))

	escalate := regEvent(t, alert.EventEscalate, decide.RuleDS, decide.SeverityCritical, regDSKey(t), regDS1, none)
	regCheck(t, escalate, dlvFull(":rotating_light: *CRITICAL*, raised from high"+dlvDot+regDSHead, []string{
		"expected   " + regDS1,
		"",
		"now        none",
		"seen at    ns.test. (10.53.0.3)   TTL 900",
	}, regOpenClock, regDSAction))

	resolve := regEvent(t, alert.EventResolve, decide.RuleDS, decide.SeverityHigh, regDSKey(t), regDS1, none)
	regCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+"DS of `corp.test.` is as expected again", []string{
		"now        " + regDS1,
	}, regResolveClock, regResolved))
}

// Expected none is one line; two records of Expected and of a seen text are
// one on each line; a resolve lists what Expected holds.
func TestSlackTextOfTheDSAlertWithNoneAndWithTwoRecords(t *testing.T) {
	two := dlvAt(t, "ns.test.", "10.53.0.3:53", regDS1+" | "+regDS2, 900)
	open := regEvent(t, alert.EventOpen, decide.RuleDS, decide.SeverityHigh, regDSKey(t), "none", two)
	regCheck(t, open, dlvFull(":red_circle: *HIGH*"+dlvDot+regDSHead, []string{
		"expected   none",
		"",
		"now        " + regDS1,
		"           " + regDS2,
		"seen at    ns.test. (10.53.0.3)   TTL 900",
	}, regOpenClock, regDSAction))

	one := dlvAt(t, "ns.test.", "10.53.0.3:53", "none", 900)
	open = regEvent(t, alert.EventOpen, decide.RuleDS, decide.SeverityHigh, regDSKey(t), regDS1+" | "+regDS2, one)
	regCheck(t, open, dlvFull(":red_circle: *HIGH*"+dlvDot+regDSHead, []string{
		"expected   " + regDS1,
		"           " + regDS2,
		"",
		"now        none",
		"seen at    ns.test. (10.53.0.3)   TTL 900",
	}, regOpenClock, regDSAction))

	for expected, view := range map[string][]string{
		"none":                  {"now        none"},
		regDS1 + " | " + regDS2: {"now        " + regDS1, "           " + regDS2},
	} {
		resolve := regEvent(t, alert.EventResolve, decide.RuleDS, decide.SeverityHigh, regDSKey(t), expected, one)
		regCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+"DS of `corp.test.` is as expected again", view, regResolveClock, regResolved))
	}
}

func TestSlackTextOfTheGoneAlert(t *testing.T) {
	line := dlvAt(t, "ns.test.", "10.53.0.3:53", "no such name", 900)
	open := regEvent(t, alert.EventOpen, decide.RuleGone, decide.SeverityCritical, regCorp(t), "", line)
	regCheck(t, open, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGoneHead, []string{
		"expected   -",
		"",
		"now        no such name",
		"seen at    ns.test. (10.53.0.3)   TTL 900",
	}, regOpenClock, regGoneAction))

	resolve := regEvent(t, alert.EventResolve, decide.RuleGone, decide.SeverityCritical, regCorp(t), "", line)
	regCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+"`corp.test.` exists at the parent zone again", []string{
		"now        the domain exists again",
	}, regResolveClock, regResolved))
}

// Eight servers that gave one answer are one block with six server
// lines at most.
func TestSlackTextOfTheGoneAlertShowsSixServers(t *testing.T) {
	var lines []alert.Line
	view := []string{"expected   -", "", "now        no such name"}
	for i := 1; i <= 8; i++ {
		lines = append(lines, dlvAt(t, fmt.Sprintf("ns%d.test.", i), fmt.Sprintf("10.53.0.%d:53", i), "no such name", 900))
		if i <= 6 {
			prefix := "           "
			if i == 1 {
				prefix = "seen at    "
			}
			view = append(view, fmt.Sprintf("%sns%d.test. (10.53.0.%d)   TTL 900", prefix, i, i))
		}
	}
	view = append(view, "           and 2 more servers")
	e := regEvent(t, alert.EventOpen, decide.RuleGone, decide.SeverityCritical, regCorp(t), "", lines...)
	regCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+regGoneHead, view, regOpenClock, regGoneAction))
}

// The webhook carries the words of the three rules and the kind and type of
// their checks.
func TestWebhookMessageCarriesTheRegistryRules(t *testing.T) {
	line := dlvAt(t, "ns.test.", "10.53.0.3:53", "no such name", 900)
	for _, c := range []struct {
		rule        decide.Rule
		key         obs.Key
		word, kind  string
		rtype       string
		sev         decide.Severity
		sevWord     string
		expected    string
		textContain string
	}{
		{decide.RuleGlue, regCorp(t), "glue", "delegation", "NS", decide.SeverityCritical, "critical", "ns2.corp.test. A 10.53.0.12", regGlueHead},
		{decide.RuleDS, regDSKey(t), "ds", "ds", "DS", decide.SeverityHigh, "high", "none", regDSHead},
		{decide.RuleGone, regCorp(t), "gone", "delegation", "NS", decide.SeverityCritical, "critical", "", regGoneHead},
	} {
		e := regEvent(t, alert.EventOpen, c.rule, c.sev, c.key, c.expected, line)
		var got struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
			Expected string `json:"expected"`
			Text     string `json:"text"`
			Check    struct {
				Kind, Domain, RType string
			} `json:"check"`
		}
		if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
			t.Fatal(err)
		}
		if got.Rule != c.word || got.Severity != c.sevWord || got.Expected != c.expected {
			t.Errorf("%s: rule %q, severity %q, expected %q; want %q, %q, %q", c.word, got.Rule, got.Severity, got.Expected, c.word, c.sevWord, c.expected)
		}
		if got.Check.Kind != c.kind || got.Check.Domain != "corp.test." || got.Check.RType != c.rtype {
			t.Errorf("%s: check %+v, want kind %q, domain corp.test. and type %q", c.word, got.Check, c.kind, c.rtype)
		}
		if got.Text != deliver.SlackText(e) || !strings.Contains(got.Text, c.textContain) {
			t.Errorf("%s: text %q is not the Slack text with %q", c.word, got.Text, c.textContain)
		}
	}
}

// Hostile data in the three new rules: only printable octets, two stars
// outside code, 6 + 2 backticks (one code span), at most 6 server lines and
// at most 3000 octets.
func TestSlackMessagePropertyOfTheRegistryRules(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 13))
	rules := []decide.Rule{decide.RuleGlue, decide.RuleDS, decide.RuleGone}
	for range 2000 {
		e := dlvHostileEvent(rng)
		e.Alert.Rule = rules[rng.IntN(len(rules))]
		if fault := regFault(e); fault != "" {
			t.Fatalf("seed %d: event %+v: %s", seed, e, fault)
		}
	}
}

func regFault(e alert.Event) string {
	text := deliver.SlackText(e)
	if len(text) > 3000 {
		return fmt.Sprintf("%d octets", len(text))
	}
	if fault := dlvOctetFault(text); fault != "" {
		return fault
	}
	if got := strings.Count(text, "`"); got != 8 {
		return fmt.Sprintf("%d backticks, want 8", got)
	}
	lines := strings.Split(text, "\n")
	n := len(lines)
	if n < 9 || lines[1] != "" || lines[2] != "```" || lines[n-5] != "```" || lines[n-4] != "" || lines[n-2] != "" {
		return "not four parts with a code block in the second:\n" + text
	}
	stars, inSpan := 0, false
	for _, l := range append([]string{lines[0]}, lines[n-4:]...) {
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
	servers := 0
	for _, l := range lines[3 : n-5] {
		if dlvServerTTL.MatchString(l) {
			servers++
		}
	}
	if servers > 6 {
		return fmt.Sprintf("%d server lines", servers)
	}
	return ""
}
