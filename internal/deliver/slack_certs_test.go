package deliver_test

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/certlog"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// crtCase is one alert of a certificate rule: the check is the certificates
// check of corp.test., whose lines name no server and no TTL.
type crtCase struct {
	name        string
	rule        decide.Rule
	sev         decide.Severity
	expected    string
	texts       []string // the lines of the alert, in order
	headline    string   // after the severity word
	view        []string
	action      string
	resolveHead string
	resolveNow  string
}

const (
	crtIssuerHead      = "a certificate for a name of `corp.test.` comes from an authority that the expectations do not permit"
	crtIssuerAction    = "If you did not ask for this certificate, ask its authority to revoke it, and check your CAA records and your DNS provider account. If you did, allow the authority where the file restricts it: in your CAA records and their lines, and in the issuer lines."
	crtIssuerResolved  = "no valid certificate for a name of `corp.test.` comes from an authority that the expectations do not permit"
	crtCertNameHead    = "a wildcard certificate for `corp.test.` holds a name that the expectations do not list"
	crtCertNameAction  = "If you did not ask for it, ask its authority to revoke it: it is valid for every name at its level. If it is yours, run osk-dns-watcher accept to list it."
	crtCertNameResolve = "no valid certificate for `corp.test.` holds an unlisted wildcard"
	crtHostsHead       = "certificates name hosts under `corp.test.` that the expectations do not list"
	crtHostsAction     = "Check that each host is yours. Run osk-dns-watcher accept to list them, or add a line for each host that osk-dns-watcher should watch."
	crtHostsResolved   = "every host under `corp.test.` on a valid certificate is in the expectations"

	crtApexCAA = `corp.test. CAA 0 issue "ca.test"`
)

// crtNames are n names h01.corp.test. to hNN.corp.test.
func crtNames(n int) []string {
	var names []string
	for i := 1; i <= n; i++ {
		names = append(names, fmt.Sprintf("h%02d.corp.test.", i))
	}
	return names
}

// crtRows is the list of names of the view for names: the first under now,
// the others under it, at most six, then the count of the others.
func crtRows(names ...string) []string {
	var rows []string
	for i, n := range names {
		if i == 6 {
			return append(rows, dlvIndent+"and "+strconv.Itoa(len(names)-6)+" more names")
		}
		label := dlvIndent
		if i == 0 {
			label = "now        "
		}
		rows = append(rows, label+n)
	}
	return rows
}

func crtCases() []crtCase {
	issuerView := func(expected []string, names ...string) []string {
		return append(append(expected, ""), crtRows(names...)...)
	}
	seven := []string{
		`a.corp.test. CAA 0 issue "ca.test"`, `b.corp.test. CAA 0 issue "ca.test"`, `c.corp.test. CAA 0 issue "ca.test"`,
		`d.corp.test. CAA 0 issue "ca.test"`, `e.corp.test. CAA 0 issue "ca.test"`, `f.corp.test. CAA 0 issue "ca.test"`,
		`issuer ca.test`,
	}
	return []crtCase{
		{
			name: "issuer, one name", rule: decide.RuleIssuer, sev: decide.SeverityHigh, expected: crtApexCAA,
			texts:    []string{"www.corp.test. from evil.test"},
			headline: crtIssuerHead,
			view:     []string{`expected   corp.test. CAA 0 issue "ca.test"`, "", "now        www.corp.test. from evil.test"},
			action:   crtIssuerAction, resolveHead: crtIssuerResolved, resolveNow: "no such certificate is valid now",
		},
		{
			name: "issuer, two names and an issuer line", rule: decide.RuleIssuer, sev: decide.SeverityHigh,
			expected: `corp.test. CAA 0 issue "ca.test"; issuer ca.test`,
			texts:    []string{"api.corp.test. from evil.test,other.test", "www.corp.test. from an authority with no CAA name (Evil CA)"},
			headline: crtIssuerHead,
			view: []string{
				`expected   corp.test. CAA 0 issue "ca.test"`,
				`           issuer ca.test`,
				"",
				"now        api.corp.test. from evil.test,other.test",
				"           www.corp.test. from an authority with no CAA name (Evil CA)",
			},
			action: crtIssuerAction, resolveHead: crtIssuerResolved, resolveNow: "no such certificate is valid now",
		},
		{
			// The part of a CAA line holds "; " inside its quoted value, and a
			// record list holds " | ": neither cuts the part.
			name: "issuer, a part with a semicolon inside quotes", rule: decide.RuleIssuer, sev: decide.SeverityHigh,
			expected: `corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/acct/1" | 0 issuewild ";"; issuer ca.test`,
			texts:    []string{"www.corp.test. from evil.test"},
			headline: crtIssuerHead,
			view: []string{
				`expected   corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/acct/1" | 0 issuewild ";"`,
				`           issuer ca.test`,
				"",
				"now        www.corp.test. from evil.test",
			},
			action: crtIssuerAction, resolveHead: crtIssuerResolved, resolveNow: "no such certificate is valid now",
		},
		{
			name: "issuer, seven parts and seven names", rule: decide.RuleIssuer, sev: decide.SeverityHigh,
			expected: strings.Join(seven, "; "),
			texts:    crtNames(7),
			headline: crtIssuerHead,
			view: issuerView([]string{
				`expected   a.corp.test. CAA 0 issue "ca.test"`,
				`           b.corp.test. CAA 0 issue "ca.test"`,
				`           c.corp.test. CAA 0 issue "ca.test"`,
				`           d.corp.test. CAA 0 issue "ca.test"`,
				`           e.corp.test. CAA 0 issue "ca.test"`,
				`           f.corp.test. CAA 0 issue "ca.test"`,
				`           and 1 more records`,
			}, crtNames(7)...),
			action: crtIssuerAction, resolveHead: crtIssuerResolved, resolveNow: "no such certificate is valid now",
		},
		{
			name: "issuer, a name twice shows once", rule: decide.RuleIssuer, sev: decide.SeverityHigh, expected: crtApexCAA,
			texts:    []string{"www.corp.test. from evil.test", "www.corp.test. from evil.test"},
			headline: crtIssuerHead,
			view:     []string{`expected   corp.test. CAA 0 issue "ca.test"`, "", "now        www.corp.test. from evil.test"},
			action:   crtIssuerAction, resolveHead: crtIssuerResolved, resolveNow: "no such certificate is valid now",
		},
		{
			name: "certname, one name", rule: decide.RuleCertName, sev: decide.SeverityHigh,
			texts:    []string{"*.corp.test."},
			headline: crtCertNameHead,
			view:     []string{"now        *.corp.test."},
			action:   crtCertNameAction, resolveHead: crtCertNameResolve, resolveNow: "no such certificate is valid now",
		},
		{
			name: "certname, three names", rule: decide.RuleCertName, sev: decide.SeverityHigh,
			texts:    []string{"*.corp.test.", "*.eu.corp.test.", "*.us.corp.test."},
			headline: crtCertNameHead,
			view:     []string{"now        *.corp.test.", "           *.eu.corp.test.", "           *.us.corp.test."},
			action:   crtCertNameAction, resolveHead: crtCertNameResolve, resolveNow: "no such certificate is valid now",
		},
		{
			name: "certname, seven names", rule: decide.RuleCertName, sev: decide.SeverityHigh,
			texts:    crtNames(7),
			headline: crtCertNameHead,
			view:     crtRows(crtNames(7)...),
			action:   crtCertNameAction, resolveHead: crtCertNameResolve, resolveNow: "no such certificate is valid now",
		},
		{
			name: "hostnames, one name", rule: decide.RuleHostnames, sev: decide.SeverityLow,
			texts:    []string{"api.corp.test."},
			headline: crtHostsHead,
			view:     []string{"now        api.corp.test."},
			action:   crtHostsAction, resolveHead: crtHostsResolved, resolveNow: "no unlisted host on a valid certificate",
		},
		{
			name: "hostnames, six names", rule: decide.RuleHostnames, sev: decide.SeverityLow,
			texts:    crtNames(6),
			headline: crtHostsHead,
			view: []string{
				"now        h01.corp.test.", "           h02.corp.test.", "           h03.corp.test.",
				"           h04.corp.test.", "           h05.corp.test.", "           h06.corp.test.",
			},
			action: crtHostsAction, resolveHead: crtHostsResolved, resolveNow: "no unlisted host on a valid certificate",
		},
		{
			name: "hostnames, seven names", rule: decide.RuleHostnames, sev: decide.SeverityLow,
			texts:    crtNames(7),
			headline: crtHostsHead,
			view: []string{
				"now        h01.corp.test.", "           h02.corp.test.", "           h03.corp.test.",
				"           h04.corp.test.", "           h05.corp.test.", "           h06.corp.test.",
				"           and 1 more names",
			},
			action: crtHostsAction, resolveHead: crtHostsResolved, resolveNow: "no unlisted host on a valid certificate",
		},
		{
			name: "hostnames, forty names", rule: decide.RuleHostnames, sev: decide.SeverityLow,
			texts:    crtNames(40),
			headline: crtHostsHead,
			view:     crtRows(crtNames(40)...),
			action:   crtHostsAction, resolveHead: crtHostsResolved, resolveNow: "no unlisted host on a valid certificate",
		},
	}
}

func (c crtCase) dng() dngRule {
	return dngRule{
		name: c.rule.String(), rule: c.rule, sev: c.sev,
		key: func(t testing.TB) obs.Key {
			return obs.CertificatesKey(dlvName(t, "corp.test."))
		},
		expected: c.expected,
		lines: func(testing.TB) []alert.Line {
			var lines []alert.Line
			for _, text := range c.texts {
				lines = append(lines, alert.Line{Text: text, Received: dlvReceived})
			}
			return lines
		},
	}
}

// crtEvent is the event of kind for c: the value of its alert is the texts of
// its lines joined by LF.
func crtEvent(t testing.TB, kind alert.EventKind, c crtCase) alert.Event {
	e := dngEvent(t, kind, c.dng())
	e.Alert.Value = strings.Join(c.texts, "\n")
	return e
}

func TestSlackTextOfTheCertificateAlerts(t *testing.T) {
	for _, c := range crtCases() {
		t.Run(c.name, func(t *testing.T) {
			head := dlvEmoji[c.sev] + " *" + dlvWord[c.sev] + "*"
			dngCheck(t, crtEvent(t, alert.EventOpen, c),
				dlvFull(head+dlvDot+c.headline, c.view, dngOpenClock, ":point_right: "+c.action), 1)

			update := crtEvent(t, alert.EventUpdate, c)
			dngCheck(t, update, dlvFull(head+", changed again"+dlvDot+c.headline, c.view, dngOpenClock, ":point_right: "+c.action), 1)

			dngCheck(t, crtEvent(t, alert.EventResolve, c),
				dlvFull(":white_check_mark: *RESOLVED*"+dlvDot+c.resolveHead, []string{"now        " + c.resolveNow}, dngResolveClock, dngResolved), 1)
		})
	}
}

// The whole text of an open issuer alert, written out octet for octet.
func TestSlackTextOfAnOpenIssuerAlertWhole(t *testing.T) {
	c := crtCases()[0]
	want := ":red_circle: *HIGH* · a certificate for a name of `corp.test.` comes from an authority that the expectations do not permit\n" +
		"\n" +
		"```\n" +
		"expected   corp.test. CAA 0 issue \"ca.test\"\n" +
		"\n" +
		"now        www.corp.test. from evil.test\n" +
		"```\n" +
		"\n" +
		":clock3: First seen 14:02:07 · last OK 14:01:07 · 11 Nov 2026 UTC\n" +
		"\n" +
		":point_right: If you did not ask for this certificate, ask its authority to revoke it, and check your CAA records and your DNS provider account. If you did, allow the authority where the file restricts it: in your CAA records and their lines, and in the issuer lines."
	if got := deliver.SlackText(crtEvent(t, alert.EventOpen, c)); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
}

// The view of these alerts has no seen at line, a certificate has no server.
func TestSlackTextOfTheCertificateAlertsHasNoServerLine(t *testing.T) {
	for _, c := range crtCases() {
		for _, kind := range []alert.EventKind{alert.EventOpen, alert.EventUpdate, alert.EventReminder} {
			text := deliver.SlackText(crtEvent(t, kind, c))
			if strings.Contains(text, "seen at") || strings.Contains(text, "TTL") {
				t.Errorf("%s, %s: the text has a server line:\n%s", c.name, kind, text)
			}
		}
	}
}

// The check of the certificates names the domain alone: the words of
// check-failing say the kind and the domain, no name and no type.
func TestSlackTextOfTheCertificatesCheckFailing(t *testing.T) {
	r := dngRule{
		name: "check-failing", rule: decide.RuleCheckFailing, sev: decide.SeverityMedium,
		key:   func(t testing.TB) obs.Key { return obs.CertificatesKey(dlvName(t, "corp.test.")) },
		lines: func(testing.TB) []alert.Line { return nil },
	}
	open := dngEvent(t, alert.EventOpen, r)
	open.Alert.Value = "no usable answer for 30 min"
	head := ":large_orange_circle: *MEDIUM* · the certificates check of `corp.test.` has had no usable answer for too long"
	action := ":point_right: Find out why osk-dns-watcher gets no usable answer from the certificate source; the log of osk-dns-watcher names the reason. Until it does, a new certificate is not seen."
	view := []string{"problem    no usable answer for 30 min"}
	dngCheck(t, open, dlvFull(head, view, dngOpenClock, action), 1)

	update := dngEvent(t, alert.EventUpdate, r)
	update.Alert.Value = open.Alert.Value
	dngCheck(t, update, dlvFull(strings.Replace(head, "*MEDIUM*", "*MEDIUM*, changed again", 1), view, dngOpenClock, action), 1)

	resolved := ":white_check_mark: *RESOLVED* · the certificates check of `corp.test.` has usable answers again"
	dngCheck(t, dngEvent(t, alert.EventResolve, r),
		dlvFull(resolved, []string{"now        the source answers"}, dngResolveClock, dngResolved), 1)
}

// A DNS check keeps the old sentences of check-failing.
func TestSlackTextOfADNSCheckFailingKeepsItsWords(t *testing.T) {
	r := dngRule{
		name: "check-failing", rule: decide.RuleCheckFailing, sev: decide.SeverityMedium,
		key:   dngKey("corp.test.", "www.corp.test.", 1),
		lines: func(testing.TB) []alert.Line { return nil },
	}
	open := dngEvent(t, alert.EventOpen, r)
	open.Alert.Value = "no usable answer for 30 min"
	head := ":large_orange_circle: *MEDIUM* · the records check of `www.corp.test. A` has had no usable answer for too long"
	action := ":point_right: Find out why no server of `corp.test.` answers this machine; until one does, a change there is not seen."
	dngCheck(t, open, dlvFull(head, []string{"problem    no usable answer for 30 min"}, dngOpenClock, action), 2)

	resolved := ":white_check_mark: *RESOLVED* · the records check of `www.corp.test. A` has usable answers again"
	dngCheck(t, dngEvent(t, alert.EventResolve, r),
		dlvFull(resolved, []string{"now        a server answers"}, dngResolveClock, dngResolved), 1)
}

// crtWant is the body of e as the format describes it for an alert of the
// certificates check of corp.test.: no type, no server, the names as lines
// that have no server and no TTL.
func crtWant(e alert.Event, names []string) wbhAlert {
	a := e.Alert
	w := wbhAlert{
		Schema: 1, Type: "alert", ID: wbhID(a.Rule.String()+" certificates corp.test.", e.Kind.String(), wbhNanos(e.At)),
		At: wbhTime(e.At), Event: e.Kind.String(), Severity: a.Severity.String(), Was: e.Was.String(), Rule: a.Rule.String(),
		Check:    wbhCheck{Kind: "certificates", Domain: "corp.test.", Name: "corp.test.", Rtype: ""},
		Expected: dlvClean(a.Expected, 160), Seen: []wbhSeen{}, Value: names,
		FirstSeen: wbhTime(a.Opened), LastClean: wbhTime(a.LastClean), Resolved: wbhTime(a.Resolved), Text: deliver.SlackText(e),
	}
	if e.Kind != alert.EventResolve {
		for i, n := range names {
			if i == 6 {
				w.More = len(names) - 6
				break
			}
			w.Seen = append(w.Seen, wbhSeen{Server: "", Address: "", Text: n, TTL: 0})
		}
	}
	return w
}

func TestWebhookMessageOfTheCertificateAlerts(t *testing.T) {
	for _, c := range crtCases() {
		t.Run(c.name, func(t *testing.T) {
			for _, kind := range []alert.EventKind{alert.EventOpen, alert.EventResolve} {
				e := crtEvent(t, kind, c)
				if fault := wbhBodyFault(deliver.WebhookMessage(e), crtWant(e, c.texts)); fault != "" {
					t.Errorf("%s: %s", kind, fault)
				}
			}
		})
	}
}

// The value of the body holds every name, up to the 200 lines of a body, each
// as it is; the servers of seen stay at six.
func TestWebhookMessageValueHoldsEveryNameUpTo200Lines(t *testing.T) {
	for _, n := range []int{7, 8, 200, 201, 250} {
		c := crtCase{rule: decide.RuleHostnames, sev: decide.SeverityLow, texts: crtNames(n)}
		e := crtEvent(t, alert.EventOpen, c)
		var got wbhAlert
		if err := json.Unmarshal(deliver.WebhookMessage(e), &got); err != nil {
			t.Fatal(err)
		}
		if want := c.texts[:min(n, 200)]; len(got.Value) != len(want) || strings.Join(got.Value, "\n") != strings.Join(want, "\n") {
			t.Errorf("%d names: the value holds %d lines, want the first %d names", n, len(got.Value), len(want))
		}
		if len(got.Seen) != 6 || got.More != n-6 {
			t.Errorf("%d names: %d seen and more %d, want 6 and %d", n, len(got.Seen), got.More, n-6)
		}
	}
}

// crtBody is a page of the source with one certificate for each of names.
func crtBody(id int, caa string, names ...string) string {
	quoted, _ := json.Marshal(names)
	return fmt.Sprintf(`{"id":"%d","tbs_sha256":"%064x","not_before":"2026-11-01T00:00:00Z","not_after":"2027-02-01T00:00:00Z",`+
		`"dns_names":%s,"issuer":{"friendly_name":"Evil CA","caa_domains":%s}}`, id, id, quoted, caa)
}

// crtFiles are two files of corp.test.: one with no line of policy, and one
// with a CAA line and an issuer line, so that all three rules can speak.
var crtFiles = []string{
	"domain corp.test.\ncorp.test. NS ns1.corp.test.\nwww.corp.test. A 10.53.0.81\n",
	"domain corp.test.\nissuer ca.test\ncertname *.eu.corp.test.\ncorp.test. CAA 0 issue \"ca.test\"\nwww.corp.test. A 10.53.0.81\n",
}

// Any bytes that the source parser reads, judged by the three rules and shown
// as an open event, a changed alert and a resolve: the Slack text keeps the
// layout and its octets, with two stars and 6 + 2F backticks (F is 1), and the
// webhook body is valid JSON that carries the same text, with no server and
// no type.
func FuzzCertificateText(f *testing.F) {
	var many []string
	for i := range 40 {
		many = append(many, fmt.Sprintf("h%02d.corp.test", i))
	}
	f.Add([]byte("[" + crtBody(1, `["evil.test"]`, "corp.test", "*.corp.test", "www.corp.test", "api.corp.test") + "]"))
	f.Add([]byte("[" + crtBody(1, `[]`, "api.corp.test", "*.corp.test") + "," + crtBody(2, `["ca.test","evil.test"]`, many...) + "]"))
	f.Add([]byte("[" + crtBody(7, `["ca.test"]`, "*.eu.corp.test", "*.us.corp.test", "x.y.z.corp.test") + "]"))
	f.Add([]byte(`[{"id":"1","tbs_sha256":"` + strings.Repeat("0", 64) + `","not_before":"2026-11-01T00:00:00Z","not_after":"2027-02-01T00:00:00Z",` +
		`"dns_names":["a.corp.test"],"issuer":{"friendly_name":"E` + "`" + `vil <@U123> &*_~","caa_domains":[]}}]`))
	f.Add([]byte("[]"))
	f.Add([]byte("\x00\xff["))
	f.Fuzz(func(t *testing.T, data []byte) {
		issuances, err := certlog.Parse(data)
		if err != nil {
			return
		}
		corp := dlvName(t, "corp.test.")
		start := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
		c := obs.Certificates{Key: obs.CertificatesKey(corp), Start: start, Usable: true, Asked: true, Complete: true, Issuances: issuances}
		for _, text := range crtFiles {
			file, err := expect.Parse([]byte(text))
			if err != nil {
				t.Fatal(err)
			}
			for _, finding := range decide.CertificateFindings(file, c) {
				crtCheckFinding(t, finding, start)
			}
		}
	})
}

// crtCheckFinding opens an alert from finding and checks what is sent for it.
func crtCheckFinding(t *testing.T, finding decide.Finding, now time.Time) {
	t.Helper()
	out := alert.Transition(alert.Input{Changes: []decide.Change{{Op: decide.OpOpen, Finding: finding, At: now}}, Now: now})
	if len(out.Events) != 1 {
		t.Fatalf("%d events for one open of %v", len(out.Events), finding.Rule)
	}
	open := out.Events[0]
	update := open
	update.Kind = alert.EventUpdate
	resolve := open
	resolve.Kind = alert.EventResolve
	resolve.Alert.Open = false
	resolve.Alert.Resolved = now.Add(time.Minute)
	resolve.At = now.Add(time.Minute)
	for _, e := range []alert.Event{open, update, resolve} {
		if fault := crtFault(e, finding); fault != "" {
			t.Fatalf("%v of %v: %s\nfinding %+v", e.Kind, finding.Rule, fault, finding)
		}
	}
}

// crtFault describes the first fault of the Slack text and of the webhook body
// of e, or returns "".
func crtFault(e alert.Event, finding decide.Finding) string {
	// Layout 2: four parts, one code block, octets, the two stars, 6 + 2F
	// backticks with F = 1, at most 3000 octets.
	if fault := dngFault(e, 1); fault != "" {
		return fault
	}
	text := deliver.SlackText(e)
	if !strings.HasPrefix(text, ":") || strings.Contains(text, "seen at") {
		return "the text starts with no emoji code, or has a server line:\n" + text
	}
	if fault := crtViewFault(text, e, finding); fault != "" {
		return fault
	}
	body := deliver.WebhookMessage(e)
	var got wbhAlert
	if err := json.Unmarshal(body, &got); err != nil {
		return fmt.Sprintf("body %s: %v", body, err)
	}
	if fault := wbhShapeFault(body, wbhAlertKeys(len(got.Seen)), &wbhAlert{}); fault != "" {
		return fault
	}
	if got.Text != text || got.Rule != finding.Rule.String() || got.Check != (wbhCheck{Kind: "certificates", Domain: "corp.test.", Name: "corp.test.", Rtype: ""}) {
		return fmt.Sprintf("body %s: text, rule or check differ from the event", body)
	}
	lines := strings.Split(finding.Value, "\n")
	// A resolve shows no line; the others show six, and count the rest.
	wantSeen, wantMore := min(len(finding.Seen), 6), max(len(finding.Seen)-6, 0)
	if e.Kind == alert.EventResolve {
		wantSeen, wantMore = 0, 0
	}
	if len(got.Value) != min(len(lines), 200) || len(got.Seen) != wantSeen || got.More != wantMore {
		return fmt.Sprintf("body %s: %d value lines, %d seen, more %d; finding has %d names", body, len(got.Value), len(got.Seen), got.More, len(finding.Seen))
	}
	for _, s := range append([]string{got.Expected}, got.Value...) {
		if !wbhPlain(s) {
			return fmt.Sprintf("body %s: %q holds an octet that is not plain", body, s)
		}
	}
	return ""
}

// crtViewFault checks the number of lines of the view of an open or changed
// alert: the expected rows of an issuer alert (cut at "; " outside quotes,
// at most six and a count), one empty line, then at most six names and a
// count. A resolve has the one line of now.
func crtViewFault(text string, e alert.Event, finding decide.Finding) string {
	lines := strings.Split(text, "\n")
	view := lines[3 : len(lines)-5]
	if slices.Contains(view, "[cut]") {
		return ""
	}
	rows := func(n int) int {
		if n > 6 {
			return 7
		}
		return n
	}
	want := 1
	if e.Kind != alert.EventResolve {
		want = rows(len(finding.Seen))
		if finding.Rule == decide.RuleIssuer {
			want += rows(len(dlvSplit(finding.Expected, "; "))) + 1
		}
	}
	if len(view) != want {
		return fmt.Sprintf("the view has %d lines, want %d:\n%s", len(view), want, text)
	}
	return ""
}
