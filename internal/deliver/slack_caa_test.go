package deliver_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// caaCase is one caa alert: the check name, the line that governs (Expected),
// the text that both servers of corp.test. give, and the view lines that the
// alert shows between the code fences.
type caaCase struct {
	name, check, expected, seen string
	ttl                         uint32
	view                        []string
}

func caaCases() []caaCase {
	servers := func(ttl string) []string {
		return []string{
			"seen at    ns1.corp.test. (10.53.0.11)   TTL " + ttl,
			"           ns2.corp.test. (10.53.0.12)   TTL " + ttl,
		}
	}
	return []caaCase{
		{
			name: "weakened apex", check: "corp.test.", expected: `0 issue "ca.test"`,
			seen: `0 issue "ca.test" | 0 issue "evil.test"`, ttl: 300,
			view: append([]string{
				`expected   0 issue "ca.test"`,
				"",
				`now        0 issue "ca.test"`,
				`           0 issue "evil.test"`,
			}, servers("300")...),
		},
		{
			name: "removed set", check: "corp.test.", expected: `0 issue "ca.test"`,
			seen: "none", ttl: 60,
			view: append([]string{
				`expected   0 issue "ca.test"`,
				"",
				"now        none",
			}, servers("60")...),
		},
		{
			name: "probe", check: "www.corp.test.", expected: `0 issue "ca.test"`,
			seen: `0 issue "evil.test"`, ttl: 300,
			view: append([]string{
				`expected   0 issue "ca.test"`,
				"",
				`now        0 issue "evil.test"`,
			}, servers("300")...),
		},
		{
			name: "two records and an alternative", check: "corp.test.",
			expected: `0 issue "ca.test" | 0 issuewild ";" || 0 issue "other.test"`,
			seen:     `0 issue "evil.test"`, ttl: 300,
			view: append([]string{
				`expected   0 issue "ca.test"`,
				`           0 issuewild ";"`,
				`or         0 issue "other.test"`,
				"",
				`now        0 issue "evil.test"`,
			}, servers("300")...),
		},
	}
}

func (c caaCase) rule() dngRule {
	return dngRule{
		name: "caa", rule: decide.RuleCAA, sev: decide.SeverityHigh,
		key:      dngKey("corp.test.", c.check, dnswire.TypeCAA),
		expected: c.expected,
		lines: func(t testing.TB) []alert.Line {
			return []alert.Line{
				dlvAt(t, "ns1.corp.test.", "10.53.0.11:53", c.seen, c.ttl),
				dlvAt(t, "ns2.corp.test.", "10.53.0.12:53", c.seen, c.ttl),
			}
		},
	}
}

func TestSlackTextOfTheCAAAlert(t *testing.T) {
	for _, c := range caaCases() {
		t.Run(c.name, func(t *testing.T) {
			r := c.rule()
			head := ":red_circle: *HIGH*" + dlvDot + "the CAA policy for `" + c.check + "` is weaker than expected"
			action := ":point_right: If you did not change the CAA records, restore them at your DNS provider now, then look for certificates for `" + c.check + "` that you did not ask for. If you did, run osk-dns-watcher accept."
			dngCheck(t, dngEvent(t, alert.EventOpen, r), dlvFull(head, c.view, dngOpenClock, action), 2)

			update := dngEvent(t, alert.EventUpdate, r)
			if got, want := strings.Split(deliver.SlackText(update), "\n")[0], ":red_circle: *HIGH*, changed again"+dlvDot+"the CAA policy for `"+c.check+"` is weaker than expected"; got != want {
				t.Errorf("update headline %q, want %q", got, want)
			}

			resolved := ":white_check_mark: *RESOLVED*" + dlvDot + "the CAA policy for `" + c.check + "` is as strict as expected again"
			dngCheck(t, dngEvent(t, alert.EventResolve, r),
				dlvFull(resolved, []string{"now        as strict as expected"}, dngResolveClock, dngResolved), 1)
		})
	}
}

// The words state the name of the check, not the domain.
func TestSlackTextOfTheCAAAlertNamesTheCheckedName(t *testing.T) {
	r := caaCases()[2].rule()
	got := deliver.SlackText(dngEvent(t, alert.EventOpen, r))
	if first := strings.Split(got, "\n")[0]; first != ":red_circle: *HIGH* · the CAA policy for `www.corp.test.` is weaker than expected" {
		t.Errorf("headline %q names another name than www.corp.test.", first)
	}
}

func TestWebhookMessageCarriesTheCAAAlert(t *testing.T) {
	for _, c := range caaCases() {
		t.Run(c.name, func(t *testing.T) {
			r := c.rule()
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
			if got.Rule != "caa" || got.Severity != "high" || got.Expected != c.expected {
				t.Errorf("rule %q, severity %q, expected %q; want caa, high, %q", got.Rule, got.Severity, got.Expected, c.expected)
			}
			if got.Check.Kind != "records" || got.Check.Domain != "corp.test." || got.Check.Name != c.check || got.Check.RType != "CAA" {
				t.Errorf("check %+v, want a records check of %s CAA in corp.test.", got.Check, c.check)
			}
			if got.Text != deliver.SlackText(e) {
				t.Errorf("text %q is not the Slack text", got.Text)
			}
		})
	}
}
