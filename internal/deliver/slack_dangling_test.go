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
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	dngOpenClock    = ":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC"
	dngResolveClock = ":clock3: Open for 18 h 27 min · first seen 11 Nov 2026 14:02:07 · resolved 12 Nov 2026 08:30:00 · UTC"
	dngResolved     = ":point_right: " + dlvResolveAction
)

// dngRule is what one rule says: the check of its alert, Expected, the
// servers' lines, the texts of an open and of a resolve event, and the
// number of code spans in each.
type dngRule struct {
	name         string
	rule         decide.Rule
	sev          decide.Severity
	key          func(testing.TB) obs.Key
	expected     string
	lines        func(testing.TB) []alert.Line
	headline     string // after the severity word
	view         []string
	action       string
	resolveHead  string // after RESOLVED
	resolveView  []string
	openSpans    int
	resolveSpans int
}

func dngKey(domain, name string, typ dnswire.Type) func(testing.TB) obs.Key {
	return func(t testing.TB) obs.Key {
		return obs.RecordsKey(dlvName(t, domain), dlvName(t, name), typ)
	}
}

// dngGone is the answer of two servers of dnshost.test. for a name that does
// not exist.
func dngGone(t testing.TB) []alert.Line {
	return []alert.Line{
		dlvAt(t, "ns1.dnshost.test.", "10.53.0.11:53", "no such name", 300),
		dlvAt(t, "ns2.dnshost.test.", "10.53.0.12:53", "no such name", 300),
	}
}

func dngGoneView(expected ...string) []string {
	var view []string
	for i, e := range expected {
		prefix := dlvIndent
		if i == 0 {
			prefix = "expected   "
		}
		view = append(view, prefix+e)
	}
	return append(view, "", "now        no such name",
		"seen at    ns1.dnshost.test. (10.53.0.11)   TTL 300",
		"           ns2.dnshost.test. (10.53.0.12)   TTL 300")
}

func dngRules() []dngRule {
	corpServers := func(t testing.TB, text string) []alert.Line {
		return []alert.Line{
			dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", text, 300),
			dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", text, 300),
		}
	}
	return []dngRule{
		{
			name: "disagree", rule: decide.RuleDisagree, sev: decide.SeverityMedium,
			key:      dngKey("corp.test.", "www.corp.test.", dnswire.TypeA),
			expected: "in 10.53.0.0/24",
			lines: func(t testing.TB) []alert.Line {
				return []alert.Line{
					dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", "10.53.0.81", 300),
					dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", "10.53.0.88", 300),
				}
			},
			headline: "the nameservers of `corp.test.` give different answers for `www.corp.test. A`",
			view: []string{
				"expected   in 10.53.0.0/24",
				"",
				"now        10.53.0.81",
				"seen at    ns1.corp.test. (10.53.0.11)   TTL 300",
				"",
				"now        10.53.0.88",
				"seen at    ns2.corp.test. (10.53.0.12)   TTL 300",
			},
			action:       "Find out why one nameserver of `corp.test.` answers otherwise: it may be out of date, or not yours.",
			resolveHead:  "the nameservers of `corp.test.` agree on `www.corp.test. A` again",
			resolveView:  []string{"now        the servers agree"},
			openSpans:    3,
			resolveSpans: 2,
		},
		{
			name: "alias-target", rule: decide.RuleAliasTarget, sev: decide.SeverityHigh,
			key:          dngKey("corp.test.", "edge.dnshost.test.", dnswire.TypeA),
			expected:     "cdn.corp.test. CNAME edge.dnshost.test.",
			lines:        dngGone,
			headline:     "`edge.dnshost.test.` does not exist, and an alias in `corp.test.` points at it",
			view:         dngGoneView("cdn.corp.test. CNAME edge.dnshost.test."),
			action:       "Change or remove the alias now: whoever creates `edge.dnshost.test.` receives its traffic.",
			resolveHead:  "`edge.dnshost.test.`, which an alias in `corp.test.` points at, exists again",
			resolveView:  []string{"now        the name exists again: check that it is yours"},
			openSpans:    3,
			resolveSpans: 2,
		},
		{
			name: "nameserver-host", rule: decide.RuleNameServerHost, sev: decide.SeverityCritical,
			key:          dngKey("corp.test.", "ns3.dnshost.test.", dnswire.TypeA),
			expected:     "corp.test. NS ns3.dnshost.test.",
			lines:        dngGone,
			headline:     "nameserver `ns3.dnshost.test.` of `corp.test.` does not exist",
			view:         dngGoneView("corp.test. NS ns3.dnshost.test."),
			action:       "Replace `ns3.dnshost.test.` at your registrar now, or restore it: whoever creates it can answer for `corp.test.`.",
			resolveHead:  "nameserver `ns3.dnshost.test.` of `corp.test.` exists again",
			resolveView:  []string{"now        the name exists again: check that it is yours"},
			openSpans:    4,
			resolveSpans: 2,
		},
		{
			name: "mail-target", rule: decide.RuleMailTarget, sev: decide.SeverityHigh,
			key:          dngKey("corp.test.", "mx.dnshost.test.", dnswire.TypeA),
			expected:     "corp.test. MX mx.dnshost.test.",
			lines:        dngGone,
			headline:     "`mx.dnshost.test.` does not exist, and the mail records of `corp.test.` point at it",
			view:         dngGoneView("corp.test. MX mx.dnshost.test."),
			action:       "Change the MX or SPF record that names `mx.dnshost.test.` now: whoever creates it can receive or send mail as `corp.test.`.",
			resolveHead:  "`mx.dnshost.test.`, which the mail records of `corp.test.` point at, exists again",
			resolveView:  []string{"now        the name exists again: check that it is yours"},
			openSpans:    4,
			resolveSpans: 2,
		},
		{
			name: "challenge", rule: decide.RuleChallenge, sev: decide.SeverityHigh,
			key:      dngKey("corp.test.", "_acme-challenge.corp.test.", dnswire.TypeTXT),
			expected: "none",
			lines:    func(t testing.TB) []alert.Line { return corpServers(t, `"t0ken1"`) },
			headline: "a certificate-challenge record appeared at `_acme-challenge.corp.test. TXT`",
			view: []string{
				"expected   none",
				"",
				`now        "t0ken1"`,
				"seen at    ns1.corp.test. (10.53.0.11)   TTL 300",
				"           ns2.corp.test. (10.53.0.12)   TTL 300",
			},
			action:       "If you did not ask for a certificate for this name, find out who changed your DNS, and look for the certificate in the certificate logs.",
			resolveHead:  "the certificate-challenge record at `_acme-challenge.corp.test. TXT` is gone",
			resolveView:  []string{"now        none"},
			openSpans:    1,
			resolveSpans: 1,
		},
		{
			// The check of a wildcard alert asks for a name of the zone Z; its
			// Name is Z.
			name: "wildcard", rule: decide.RuleWildcard, sev: decide.SeverityMedium,
			key:      dngKey("corp.test.", "corp.test.", dnswire.TypeA),
			expected: "none",
			lines:    func(t testing.TB) []alert.Line { return corpServers(t, "10.53.0.66") },
			headline: "a wildcard answers for names under `corp.test.` that do not exist",
			view: []string{
				"expected   none",
				"",
				"now        10.53.0.66",
				"seen at    ns1.corp.test. (10.53.0.11)   TTL 300",
				"           ns2.corp.test. (10.53.0.12)   TTL 300",
			},
			action:       "If you did not add a wildcard under `corp.test.`, remove it at your DNS provider and find out who added it.",
			resolveHead:  "no wildcard answers under `corp.test.` again",
			resolveView:  []string{"now        no wildcard"},
			openSpans:    2,
			resolveSpans: 1,
		},
	}
}

func dngEvent(t testing.TB, kind alert.EventKind, r dngRule) alert.Event {
	e := alert.Event{
		Kind: kind,
		Alert: alert.Alert{ID: 4, Open: kind != alert.EventResolve, Rule: r.rule, Severity: r.sev, Peak: r.sev, Check: r.key(t),
			Expected: r.expected, Lines: r.lines(t), Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed},
		Was: decide.SeverityMedium,
		At:  dlvResolved,
	}
	if kind == alert.EventResolve {
		e.Alert.Resolved = dlvResolved
	}
	return e
}

func dngCheck(t *testing.T, e alert.Event, want string, spans int) {
	t.Helper()
	got := deliver.SlackText(e)
	if got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
	if n := strings.Count(got, "`"); n != 6+2*spans {
		t.Errorf("%d backticks, want %d (%d code spans)", n, 6+2*spans, spans)
	}
	if fault := dngFault(e, spans); fault != "" {
		t.Errorf("the message of this event is faulty: %s", fault)
	}
}

func TestSlackTextOfTheDanglingRules(t *testing.T) {
	for _, r := range dngRules() {
		t.Run(r.name, func(t *testing.T) {
			head := dlvEmoji[r.sev] + " *" + dlvWord[r.sev] + "*"
			dngCheck(t, dngEvent(t, alert.EventOpen, r),
				dlvFull(head+dlvDot+r.headline, r.view, dngOpenClock, ":point_right: "+r.action), r.openSpans)

			update := dngEvent(t, alert.EventUpdate, r)
			if got, want := strings.Split(deliver.SlackText(update), "\n")[0], head+", changed again"+dlvDot+r.headline; got != want {
				t.Errorf("update headline %q, want %q", got, want)
			}

			dngCheck(t, dngEvent(t, alert.EventResolve, r),
				dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+r.resolveHead, r.resolveView, dngResolveClock, dngResolved), r.resolveSpans)
		})
	}
}

// A nameserver whose domain is gone: the answer names the zone that no
// longer delegates it, and one server gave it.
func TestSlackTextOfTheNameServerHostAlertWhoseDomainIsGone(t *testing.T) {
	r := dngRules()[2]
	r.lines = func(t testing.TB) []alert.Line {
		return []alert.Line{dlvAt(t, "ns.test.", "10.53.0.3:53", "no such name: test. does not delegate dnshost.test.", 300)}
	}
	e := dngEvent(t, alert.EventOpen, r)
	dngCheck(t, e, dlvFull(":rotating_light: *CRITICAL*"+dlvDot+r.headline, []string{
		"expected   corp.test. NS ns3.dnshost.test.",
		"",
		"now        no such name: test. does not delegate dnshost.test.",
		"seen at    ns.test. (10.53.0.3)   TTL 300",
	}, dngOpenClock, ":point_right: "+r.action), r.openSpans)
}

// The three rules that point at a name take Expected as the glue rule does:
// parts split at "; " and no further, one line each, each cut at 120 octets.
func TestSlackTextOfTheTargetRulesWithThreeParts(t *testing.T) {
	long := "cdn.corp.test. CNAME " + strings.Repeat("a", 150)
	first := "mail.corp.test. MX 10 | 20 mx.dnshost.test."
	rules := dngRules()
	for _, r := range rules[1:4] {
		t.Run(r.name, func(t *testing.T) {
			own := r.expected
			r.expected = first + "; " + own + "; " + long
			head := dlvEmoji[r.sev] + " *" + dlvWord[r.sev] + "*"
			want := dlvFull(head+dlvDot+r.headline, dngGoneView(first, own, deliver.Clean(long, 120)), dngOpenClock, ":point_right: "+r.action)
			dngCheck(t, dngEvent(t, alert.EventOpen, r), want, r.openSpans)
		})
	}
}

// The exchange of an MX record and an SPF include are both targets of the
// mail rule.
func TestSlackTextOfTheMailTargetAlertForAnInclude(t *testing.T) {
	r := dngRules()[3]
	r.expected = "corp.test. TXT include:spf.dnshost.test."
	dngCheck(t, dngEvent(t, alert.EventOpen, r),
		dlvFull(":red_circle: *HIGH*"+dlvDot+r.headline, dngGoneView(r.expected), dngOpenClock, ":point_right: "+r.action), r.openSpans)
}

// A disagree alert keeps the limits of the generic view: three answers, and
// six server lines in all.
func TestSlackTextOfTheDisagreeAlertKeepsTheLimits(t *testing.T) {
	r := dngRules()[0]
	head := ":large_orange_circle: *MEDIUM*" + dlvDot + r.headline

	var answers []alert.Line
	for i := 1; i <= 8; i++ {
		answers = append(answers, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), fmt.Sprintf("10.53.0.%d", 80+i), 300))
	}
	view := []string{"expected   in 10.53.0.0/24"}
	for i := 1; i <= 3; i++ {
		view = append(view, "", fmt.Sprintf("now        10.53.0.%d", 80+i), fmt.Sprintf("seen at    ns%d.corp.test. (10.53.0.%d)   TTL 300", i, i))
	}
	view = append(view, "           and 5 more answers")
	r.lines = func(testing.TB) []alert.Line { return answers }
	dngCheck(t, dngEvent(t, alert.EventOpen, r), dlvFull(head, view, dngOpenClock, ":point_right: "+r.action), r.openSpans)

	var servers []alert.Line
	view = []string{"expected   in 10.53.0.0/24", "", "now        10.53.0.81"}
	for i := 1; i <= 8; i++ {
		servers = append(servers, dlvAt(t, fmt.Sprintf("ns%d.corp.test.", i), fmt.Sprintf("10.53.0.%d:53", i), "10.53.0.81", 300))
		if i <= 6 {
			prefix := dlvIndent
			if i == 1 {
				prefix = "seen at    "
			}
			view = append(view, fmt.Sprintf("%sns%d.corp.test. (10.53.0.%d)   TTL 300", prefix, i, i))
		}
	}
	view = append(view, "           and 2 more servers")
	r.lines = func(testing.TB) []alert.Line { return servers }
	dngCheck(t, dngEvent(t, alert.EventOpen, r), dlvFull(head, view, dngOpenClock, ":point_right: "+r.action), r.openSpans)
}

// The webhook carries the word of each rule and the kind and type of its
// check.
func TestWebhookMessageCarriesTheDanglingRules(t *testing.T) {
	for _, r := range dngRules() {
		e := dngEvent(t, alert.EventOpen, r)
		var got struct {
			Rule     string `json:"rule"`
			Severity string `json:"severity"`
			Expected string `json:"expected"`
			Text     string `json:"text"`
			Check    struct {
				Kind, Domain, Name, RType string
			} `json:"check"`
		}
		if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
			t.Fatal(err)
		}
		if got.Rule != r.name || got.Severity != r.sev.String() || got.Expected != r.expected {
			t.Errorf("%s: rule %q, severity %q, expected %q; want %q, %q, %q", r.name, got.Rule, got.Severity, got.Expected, r.name, r.sev, r.expected)
		}
		k := r.key(t)
		if got.Check.Kind != "records" || got.Check.Domain != "corp.test." || got.Check.Name != k.Name.String() || got.Check.RType != k.Type.String() {
			t.Errorf("%s: check %+v, want a records check of %s %s in corp.test.", r.name, got.Check, k.Name, k.Type)
		}
		if got.Text != deliver.SlackText(e) || !strings.Contains(got.Text, r.headline) {
			t.Errorf("%s: text %q is not the Slack text with %q", r.name, got.Text, r.headline)
		}
	}
}

// Hostile data in the six rules: only printable octets, two stars outside
// code, 6 backticks plus 2 for each code span (the data can add none), at
// most 6 server lines and at most 3000 octets.
func TestSlackMessagePropertyOfTheDanglingRules(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 17))
	rules := dngRules()
	for range 3000 {
		e := dlvHostileEvent(rng)
		r := rules[rng.IntN(len(rules))]
		e.Alert.Rule = r.rule
		spans := r.openSpans
		if e.Kind == alert.EventResolve {
			spans = r.resolveSpans
		}
		if fault := dngFault(e, spans); fault != "" {
			t.Fatalf("seed %d: rule %s, event %+v: %s", seed, r.name, e, fault)
		}
	}
}

func dngFault(e alert.Event, spans int) string {
	text := deliver.SlackText(e)
	if len(text) > 3000 {
		return fmt.Sprintf("%d octets", len(text))
	}
	if fault := dlvOctetFault(text); fault != "" {
		return fault
	}
	if got, want := strings.Count(text, "`"), 6+2*spans; got != want {
		return fmt.Sprintf("%d backticks, want %d", got, want)
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
