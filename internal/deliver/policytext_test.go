package deliver_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	pctWas  = "mta-sts enforce 604800 mail.corp.test."
	pctSeen = "mta-sts testing 86400 mail.corp.test. *.evil.test."

	pctMore    = "MTA-STS at `mta-sts.corp.test.` protects less than the file"
	pctNeutral = "MTA-STS at `mta-sts.corp.test.` changed"
	pctAction  = "If you did not make this change, restore it: senders use MTA-STS to refuse mail servers that are not yours."
)

var pctWords = []string{
	"mode testing in place of enforce: senders deliver mail even when the TLS check fails",
	"max_age 86400 in place of 604800: senders keep the policy for less time",
	"mx *.evil.test. is not allowed by the file",
}

// pctKey is the key of the policy check of corp.test.
func pctKey(t testing.TB) obs.Key {
	k, ok := obs.PolicyKey(dlvName(t, "corp.test."))
	if !ok {
		t.Fatal("no policy key for corp.test.")
	}
	return k
}

// pctServers gives n answers of the policy host, one for each address, all
// with text. A policy file has no TTL.
func pctServers(t testing.TB, n int, text string) []alert.Line {
	var lines []alert.Line
	for i := 1; i <= n; i++ {
		lines = append(lines, dlvAt(t, "mta-sts.corp.test.", fmt.Sprintf("10.53.0.%d:443", 29+i), text, 0))
	}
	return lines
}

func pctEvent(t testing.TB, kind alert.EventKind, lines []alert.Line, words []string) alert.Event {
	a := alert.Alert{
		ID: 4, Open: kind != alert.EventResolve, Rule: decide.RuleMTASTS, Severity: decide.SeverityMedium, Peak: decide.SeverityMedium,
		Check: pctKey(t), Expected: pctWas, Lines: lines, Value: emlwValue(lines, words),
		Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed,
	}
	if kind == alert.EventResolve {
		a.Resolved = dlvResolved
	}
	return alert.Event{Kind: kind, Alert: a, Was: decide.SeverityLow, At: dlvResolved}
}

// pctSetView is the generic part of the view for answers of one text: the
// server lines end after the address, with no TTL.
func pctSetView(text string, servers int) []string {
	view := []string{"expected   " + pctWas, "", "now        " + text}
	for i := 1; i <= servers; i++ {
		label := "           "
		if i == 1 {
			label = "seen at    "
		}
		view = append(view, fmt.Sprintf("%smta-sts.corp.test. (10.53.0.%d:443)", label, 29+i))
	}
	return view
}

func pctText(headline string, view []string) string {
	return dlvFull(headline, view, dngOpenClock, ":point_right: "+pctAction)
}

func TestPctSlackTextOfAPolicyAlert(t *testing.T) {
	for _, servers := range []int{1, 2} {
		t.Run(strconv.Itoa(servers)+" servers", func(t *testing.T) {
			lines := pctServers(t, servers, pctSeen)

			open := pctEvent(t, alert.EventOpen, lines, pctWords)
			view := slices.Concat(emlwWeakerView(pctWords), pctSetView(pctSeen, servers))
			dngCheck(t, open, pctText(emlwMedium+dlvDot+pctMore, view), 1)

			neutral := pctEvent(t, alert.EventOpen, lines, nil)
			dngCheck(t, neutral, pctText(emlwMedium+dlvDot+pctNeutral, pctSetView(pctSeen, servers)), 1)

			update := pctEvent(t, alert.EventUpdate, lines, pctWords)
			dngCheck(t, update, pctText(emlwMedium+", changed again"+dlvDot+pctMore, view), 1)

			resolve := pctEvent(t, alert.EventResolve, lines, pctWords)
			dngCheck(t, resolve, dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+"MTA-STS at `mta-sts.corp.test.` is as expected again",
				[]string{"now        " + pctWas}, dngResolveClock, dngResolved), 1)
		})
	}
}

// The policy has no TTL: no server line of a policy alert holds one, however
// many lines there are and whatever number the line carries.
func TestPctSlackTextOfAPolicyAlertShowsNoTTL(t *testing.T) {
	lines := pctServers(t, 7, pctSeen)
	for i := range lines {
		lines[i].TTL = 300
	}
	got := deliver.SlackText(pctEvent(t, alert.EventOpen, lines, pctWords))
	if strings.Contains(got, "TTL") {
		t.Errorf("a policy alert shows a TTL:\n%s", got)
	}
	if !strings.Contains(got, "           mta-sts.corp.test. (10.53.0.35:443)\n           and 1 more servers\n") {
		t.Errorf("the sixth server line, or the count of the seventh, is missing:\n%s", got)
	}
}

// The words come first, then the generic view; a record-set alert of the
// same domain keeps its TTL.
func TestPctSlackTextOfAPolicyAlertPutsTheWeakerBlockFirst(t *testing.T) {
	got := strings.Split(deliver.SlackText(pctEvent(t, alert.EventOpen, pctServers(t, 1, pctSeen), pctWords)), "\n")
	if len(got) < 8 || got[2] != "```" || !strings.HasPrefix(got[3], "weaker     ") {
		t.Errorf("the view does not start with the weaker block:\n%s", strings.Join(got, "\n"))
	}
}

// A word is data from the policy file: it passes through Clean at 120 octets,
// at most six words show, and the cap line of the rule adds its count.
func TestPctSlackTextOfAPolicyAlertCleansAndCutsTheWords(t *testing.T) {
	lines := pctServers(t, 1, pctSeen)
	long := strings.Repeat("x", 200)
	for _, c := range []struct {
		name  string
		words []string
		shown []string
		more  int
	}{
		{"a backtick", []string{"mx a`b.test is not allowed by the file"}, []string{"mx a`b.test is not allowed by the file"}, 0},
		{"markup", []string{"a&b<c>d"}, []string{"a&b<c>d"}, 0},
		{"an octet outside ASCII", []string{"a\xffb\x01"}, []string{"a\xffb\x01"}, 0},
		{"a long word", []string{long}, []string{long}, 0},
		{"eight words", pctNumbered(8), pctNumbered(8)[:6], 2},
		{"eleven words and the cap line of the rule", append(pctNumbered(11), "and 3 more"), pctNumbered(11)[:6], 8},
		{"six words and the cap line of the rule", append(pctNumbered(6), "and 2 more"), pctNumbered(6), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cleaned []string
			for _, w := range c.shown {
				cleaned = append(cleaned, dlvClean(w, 120))
			}
			block := emlwWeakerView(cleaned)
			if c.more > 0 {
				block = slices.Insert(block, len(cleaned), fmt.Sprintf("           and %d more", c.more))
			}
			view := slices.Concat(block, pctSetView(pctSeen, 1))
			dngCheck(t, pctEvent(t, alert.EventOpen, lines, c.words), pctText(emlwMedium+dlvDot+pctMore, view), 1)
		})
	}
}

func pctNumbered(n int) []string {
	var words []string
	for i := 1; i <= n; i++ {
		words = append(words, fmt.Sprintf("word %d", i))
	}
	return words
}

// The webhook value holds at most six server lines, then every weaker line.
func TestPctWebhookMessageOfAPolicyAlert(t *testing.T) {
	for _, servers := range []int{1, 6, 7, 40} {
		for _, nwords := range []int{0, 3, 11, 12} {
			t.Run(fmt.Sprintf("%d servers and %d words", servers, nwords), func(t *testing.T) {
				words := pctNumbered(nwords)
				if nwords == 12 {
					words[11] = "and 3 more"
				}
				lines := pctServers(t, servers, pctSeen)
				e := pctEvent(t, alert.EventOpen, lines, words)
				var got emlwWebhook
				if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
					t.Fatal(err)
				}
				if got.Rule != "mta-sts" || got.Severity != "medium" || got.Expected != pctWas {
					t.Errorf("rule %q, severity %q, expected %q; want mta-sts, medium, %q", got.Rule, got.Severity, got.Expected, pctWas)
				}
				if got.Check.Kind != "policy" || got.Check.Domain != "corp.test." || got.Check.Name != "mta-sts.corp.test." || got.Check.RType != "TXT" {
					t.Errorf("check %+v, want a policy check of mta-sts.corp.test. TXT in corp.test.", got.Check)
				}
				var want []string
				for i := 1; i <= min(servers, 6); i++ {
					want = append(want, fmt.Sprintf("10.53.0.%d:443 mta-sts.corp.test. %s", 29+i, pctSeen))
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

// pctFailing is an event of a failing check of key, with Value as the
// service writes it.
func pctFailing(t testing.TB, kind alert.EventKind, key obs.Key) alert.Event {
	r := dngRule{
		name: "check-failing", rule: decide.RuleCheckFailing, sev: decide.SeverityMedium,
		key:   func(testing.TB) obs.Key { return key },
		lines: func(testing.TB) []alert.Line { return nil },
	}
	e := dngEvent(t, kind, r)
	e.Alert.Value = "no usable answer for 30m0s"
	return e
}

// A failing policy check speaks of the policy host and of the log, not of
// DNS servers.
func TestPctSlackTextOfAFailingPolicyCheck(t *testing.T) {
	const head = ":large_orange_circle: *MEDIUM* · the policy check of `mta-sts.corp.test. TXT` has had no usable answer for too long"
	const action = ":point_right: Find out why osk cannot fetch the policy file from `mta-sts.corp.test.`; the log of osk names the reason. " +
		"Until it can, a change of the policy is not seen. A sender that cannot fetch the file uses the policy it has cached, or acts as if there were no policy."
	view := []string{"problem    no usable answer for 30m0s"}

	open := pctFailing(t, alert.EventOpen, pctKey(t))
	dngCheck(t, open, dlvFull(head, view, dngOpenClock, action), 2)
	if got := deliver.SlackText(open); strings.Contains(got, "no server of") {
		t.Errorf("the text holds the words of a DNS check:\n%s", got)
	}

	update := pctFailing(t, alert.EventUpdate, pctKey(t))
	dngCheck(t, update, dlvFull(strings.Replace(head, "*MEDIUM*", "*MEDIUM*, changed again", 1), view, dngOpenClock, action), 2)

	resolved := ":white_check_mark: *RESOLVED* · the policy check of `mta-sts.corp.test. TXT` has usable answers again"
	dngCheck(t, pctFailing(t, alert.EventResolve, pctKey(t)),
		dlvFull(resolved, []string{"now        a server answers"}, dngResolveClock, dngResolved), 1)
}

// The new words belong to the policy check alone: a DNS check and a
// certificate check keep their own.
func TestPctSlackTextOfOtherFailingChecksKeepsTheirWords(t *testing.T) {
	for _, c := range []struct {
		name, head, action string
		key                obs.Key
		spans              int
	}{
		{"records", ":large_orange_circle: *MEDIUM* · the records check of `_mta-sts.corp.test. TXT` has had no usable answer for too long",
			"Find out why no server of `corp.test.` answers this machine; until one does, a change there is not seen.",
			obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "_mta-sts.corp.test."), dnswire.TypeTXT), 2},
		{"certificates", ":large_orange_circle: *MEDIUM* · the certificates check of `corp.test.` has had no usable answer for too long",
			"Find out why osk gets no usable answer from the certificate source; the log of osk names the reason. Until it does, a new certificate is not seen.",
			obs.CertificatesKey(dlvName(t, "corp.test.")), 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			e := pctFailing(t, alert.EventOpen, c.key)
			dngCheck(t, e, dlvFull(c.head, []string{"problem    no usable answer for 30m0s"}, dngOpenClock, ":point_right: "+c.action), c.spans)
		})
	}
}
