//go:build lab

package main

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// regWindow is how long a change at the parent may take to show as an alert:
// the interval of the parent checks, a start spread of 75%, and a second.
const regWindow = 5*time.Second + 3750*time.Millisecond + time.Second

// regDS is one DS record, in the canonical form that the expectations
// print.
const regDS = "11111 13 2 ABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABABAB"

const regResolveAction = ":point_right: If you did not make or undo this change yourself, find out who did."

var (
	regOpenTimes    = regexp.MustCompile(`^:clock3: First seen \d\d:\d\d:\d\d · last OK \d\d:\d\d:\d\d · \d{1,2} [A-Z][a-z]{2} \d{4} UTC$`)
	regResolveTimes = regexp.MustCompile(`^:clock3: Open for \d+ (d|h|min|s)( \d+ (h|min|s))? · first seen \d\d:\d\d:\d\d · resolved \d\d:\d\d:\d\d · \d{1,2} [A-Z][a-z]{2} \d{4} UTC$`)
)

// regAlertLines are the alert lines that osk run logged.
func regAlertLines(svc *cliLabService) []string {
	var out []string
	for _, l := range svc.all() {
		if strings.HasPrefix(l.Text, "alert ") {
			out = append(out, l.Text)
		}
	}
	return out
}

func regIs(text string) func(cliLabLog) bool {
	return func(l cliLabLog) bool { return l.Text == text }
}

// regChecked waits for a line of a finished check of the parent.
func regChecked(t *testing.T, svc *cliLabService, kind string) cliLabLog {
	t.Helper()
	return svc.wait(t, "a checked parent "+kind+" line", time.Now().Add(20*time.Second), func(l cliLabLog) bool {
		return l.Event == "checked" && strings.HasPrefix(l.Text, "checked parent "+kind+" corp.test. ")
	})
}

// regTexts waits until the receiver holds at least n Slack messages and
// gives them.
func regTexts(t *testing.T, w *cliLabWorld, n int, deadline time.Time) []string {
	t.Helper()
	var texts []string
	cliLabUntil(t, strconv.Itoa(n)+" Slack requests", deadline, 50*time.Millisecond, func() bool {
		texts = cliLabSlackTexts(t, w)
		return len(texts) >= n
	})
	return texts
}

// regMessage is one Slack text cut into its four parts.
type regMessage struct {
	head, clock, action string
	view                []string
}

func regSplit(t *testing.T, text string) regMessage {
	t.Helper()
	lines := strings.Split(text, "\n")
	n := len(lines)
	if n < 9 || lines[1] != "" || lines[2] != "```" || lines[n-5] != "```" || lines[n-4] != "" || lines[n-2] != "" {
		t.Fatalf("not four parts with a code block in the second:\n%s", text)
	}
	return regMessage{head: lines[0], view: lines[3 : n-5], clock: lines[n-3], action: lines[n-1]}
}

// regExpect checks the Slack text that starts with head against the view
// and the action, and its times line against re.
func regExpect(t *testing.T, text, head string, view []string, re *regexp.Regexp, action string) {
	t.Helper()
	m := regSplit(t, text)
	if m.head != head {
		t.Errorf("headline %q, want %q", m.head, head)
	}
	if !slices.Equal(m.view, view) {
		t.Errorf("view:\n%s\nwant:\n%s", strings.Join(m.view, "\n"), strings.Join(view, "\n"))
	}
	if !re.MatchString(m.clock) {
		t.Errorf("times line %q does not match %s", m.clock, re)
	}
	if m.action != action {
		t.Errorf("action %q, want %q", m.action, action)
	}
}

// regTextWith gives the one text of texts whose first line is head.
func regTextWith(t *testing.T, texts []string, head string) string {
	t.Helper()
	var found []string
	for _, s := range texts {
		if strings.HasPrefix(s, head+"\n") {
			found = append(found, s)
		}
	}
	if len(found) != 1 {
		t.Fatalf("%d Slack texts start with %q, want 1; all texts:\n%s", len(found), head, strings.Join(texts, "\n---\n"))
	}
	return found[0]
}

// regNegativeTTL is the negative TTL of the answer that the parent gives to
// the question, as dig sees it: the smaller of the TTL of the SOA record and
// its minimum.
func regNegativeTTL(t *testing.T, w *cliLabWorld, qname, qtype string) string {
	t.Helper()
	soas := cliPick(cliAskDig(t, w.n+"3:53", qname, qtype).sections["AUTHORITY"], "", "SOA")
	if len(soas) != 1 {
		t.Fatalf("dig %s %s shows SOA lines %q, want one", qname, qtype, soas)
	}
	f := strings.SplitN(soas[0], "\t", 5)
	data := strings.Fields(f[4])
	ttl, err1 := strconv.Atoi(f[1])
	minimum, err2 := strconv.Atoi(data[len(data)-1])
	if err1 != nil || err2 != nil {
		t.Fatalf("the SOA line %q has no TTL and minimum", soas[0])
	}
	return strconv.Itoa(min(ttl, minimum))
}

// regReferralTTL is the TTL of the NS set that the parent gives in its
// referral for corp.test., as dig sees it.
func regReferralTTL(t *testing.T, w *cliLabWorld) string {
	t.Helper()
	ns := cliPick(cliAskDig(t, w.n+"3:53", "corp.test.", "NS").sections["AUTHORITY"], "", "NS")
	if len(ns) == 0 {
		t.Fatal("dig shows no NS record in the referral for corp.test.")
	}
	return strings.SplitN(ns[0], "\t", 5)[1]
}

// regHosts are the address lines of the two nameserver hosts.
func regHosts(n string) []string {
	return []string{"ns1.corp.test. A " + n + "11", "ns2.corp.test. A " + n + "12"}
}

func TestGlueChangedAlert(t *testing.T) {
	w := cliLabSetup(t, false, func(n string) string { return cliLabFile(n, regHosts(n)...) }, map[string]string{"parent": "5s"})
	svc := cliLabStart(t, w)

	regChecked(t, svc, "delegation")
	if lines := regAlertLines(svc); len(lines) != 0 {
		t.Fatalf("alert lines before any change: %q", lines)
	}

	set := time.Now()
	expCtl(t, "glue", "ns2.corp.test.", w.n+"11")
	svc.wait(t, "the glue alert", set.Add(regWindow), regIs("alert open critical glue delegation corp.test. NS"))
	texts := regTexts(t, w, 1, time.Now().Add(3*time.Second))
	if len(texts) != 1 {
		t.Fatalf("the receiver holds %d Slack requests, want exactly one:\n%s", len(texts), strings.Join(texts, "\n---\n"))
	}
	regExpect(t, texts[0], ":rotating_light: *CRITICAL* · nameserver addresses of `corp.test.` changed at the parent zone", []string{
		"expected   ns2.corp.test. A " + w.n + "12",
		"",
		"now        ns2.corp.test. A " + w.n + "11",
		"seen at    ns.test. (" + w.n + "3)   TTL " + regReferralTTL(t, w),
	}, regOpenTimes, ":point_right: If you did not change the addresses of your nameservers, contact your registrar now.")
	if ttl := regReferralTTL(t, w); ttl != "300" {
		t.Errorf("dig shows the TTL %s for the referral, the lab holds 300", ttl)
	}

	set = time.Now()
	expCtl(t, "glue", "ns2.corp.test.", w.n+"12")
	svc.wait(t, "the resolve of the glue alert", set.Add(regWindow), regIs("alert resolve critical glue delegation corp.test. NS"))
	texts = regTexts(t, w, 2, time.Now().Add(3*time.Second))
	regExpect(t, regTextWith(t, texts, ":white_check_mark: *RESOLVED* · nameserver addresses of `corp.test.` are as expected again"),
		":white_check_mark: *RESOLVED* · nameserver addresses of `corp.test.` are as expected again",
		[]string{"now        as expected again"}, regResolveTimes, regResolveAction)

	want := []string{"alert open critical glue delegation corp.test. NS", "alert resolve critical glue delegation corp.test. NS"}
	if got := regAlertLines(svc); !slices.Equal(got, want) {
		t.Errorf("alert lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestDSChangedAlert(t *testing.T) {
	expCtl(t, "ds", "corp.test.", regDS)
	w := cliLabSetup(t, false, func(n string) string {
		return strings.Replace(cliLabFile(n), "corp.test. DS none", "corp.test. DS "+regDS, 1)
	}, map[string]string{"parent": "5s"})
	svc := cliLabStart(t, w)

	regChecked(t, svc, "ds")
	if lines := regAlertLines(svc); len(lines) != 0 {
		t.Fatalf("alert lines before any change: %q", lines)
	}

	set := time.Now()
	expCtl(t, "ds", "corp.test.", "none")
	svc.wait(t, "the ds alert", set.Add(regWindow), regIs("alert open high ds ds corp.test. DS"))
	texts := regTexts(t, w, 1, time.Now().Add(3*time.Second))
	seenNone := []string{
		"expected   " + regDS,
		"",
		"now        none",
		"seen at    ns.test. (" + w.n + "3)   TTL " + regNegativeTTL(t, w, "corp.test.", "DS"),
	}
	const dsPhrase = " · DS of `corp.test.` changed at the parent zone"
	const dsAction = ":point_right: If you did not change your DNSSEC keys, contact your registrar now."
	regExpect(t, regTextWith(t, texts, ":red_circle: *HIGH*"+dsPhrase), ":red_circle: *HIGH*"+dsPhrase, seenNone, regOpenTimes, dsAction)

	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	opened := svc.wait(t, "the nameservers alert", time.Now().Add(regWindow), regIs("alert open critical nameservers delegation corp.test. NS"))
	svc.wait(t, "the escalation of the ds alert", opened.at.Add(regWindow), regIs("alert escalate critical ds ds corp.test. DS"))
	texts = regTexts(t, w, 3, time.Now().Add(3*time.Second))
	raised := ":rotating_light: *CRITICAL*, raised from high" + dsPhrase
	regExpect(t, regTextWith(t, texts, raised), raised, seenNone, regOpenTimes, dsAction)

	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	resolved := svc.wait(t, "the resolve of the nameservers alert", time.Now().Add(regWindow),
		regIs("alert resolve critical nameservers delegation corp.test. NS"))
	runs := func() int {
		n := 0
		for _, l := range svc.all() {
			if l.Event == "checked" && strings.HasPrefix(l.Text, "checked parent ds corp.test. ") && l.at.After(resolved.at) {
				n++
			}
		}
		return n
	}
	cliLabUntil(t, "two more runs of the ds check", time.Now().Add(2*regWindow), 100*time.Millisecond, func() bool { return runs() >= 2 })
	for _, l := range regAlertLines(svc) {
		if strings.Contains(l, " ds ds corp.test. DS") && !strings.HasPrefix(l, "alert open ") && !strings.HasPrefix(l, "alert escalate ") {
			t.Errorf("the ds alert changed after the nameservers alert resolved: %q", l)
		}
	}

	set = time.Now()
	expCtl(t, "ds", "corp.test.", regDS)
	svc.wait(t, "the resolve of the ds alert", set.Add(regWindow), regIs("alert resolve critical ds ds corp.test. DS"))
	texts = regTexts(t, w, 5, time.Now().Add(3*time.Second))
	back := ":white_check_mark: *RESOLVED* · DS of `corp.test.` is as expected again"
	regExpect(t, regTextWith(t, texts, back), back, []string{"now        " + regDS}, regResolveTimes, regResolveAction)

	for _, l := range regAlertLines(svc) {
		if strings.Contains(l, " glue ") {
			t.Errorf("a glue alert opened for hosts that no line watches: %q", l)
		}
	}
}

func TestDomainGoneAlert(t *testing.T) {
	w := cliLabSetup(t, false, nil, map[string]string{"parent": "5s"})
	svc := cliLabStart(t, w)

	regChecked(t, svc, "delegation")
	if lines := regAlertLines(svc); len(lines) != 0 {
		t.Fatalf("alert lines before any change: %q", lines)
	}

	set := time.Now()
	expCtl(t, "undelegate", "corp.test.")
	deadline := set.Add(regWindow)
	svc.wait(t, "the gone alert", deadline, regIs("alert open critical gone delegation corp.test. NS"))
	svc.wait(t, "the nameservers alert", deadline, regIs("alert open critical nameservers delegation corp.test. NS"))
	texts := regTexts(t, w, 2, time.Now().Add(3*time.Second))
	const gonePhrase = " · `corp.test.` does not exist at the parent zone"
	regExpect(t, regTextWith(t, texts, ":rotating_light: *CRITICAL*"+gonePhrase), ":rotating_light: *CRITICAL*"+gonePhrase, []string{
		"expected   -",
		"",
		"now        no such name",
		"seen at    ns.test. (" + w.n + "3)   TTL " + regNegativeTTL(t, w, "corp.test.", "NS"),
	}, regOpenTimes, ":point_right: Contact your registrar now: the registration may have expired, been deleted or been transferred.")

	// undelegate removed the glue too, so the restore has three steps.
	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	expCtl(t, "glue", "ns1.corp.test.", w.n+"11")
	set = time.Now()
	expCtl(t, "glue", "ns2.corp.test.", w.n+"12")
	deadline = set.Add(regWindow)
	svc.wait(t, "the resolve of the gone alert", deadline, regIs("alert resolve critical gone delegation corp.test. NS"))
	svc.wait(t, "the resolve of the nameservers alert", deadline, regIs("alert resolve critical nameservers delegation corp.test. NS"))
	texts = regTexts(t, w, 4, time.Now().Add(3*time.Second))
	back := ":white_check_mark: *RESOLVED* · `corp.test.` exists at the parent zone again"
	regExpect(t, regTextWith(t, texts, back), back, []string{"now        the domain exists again"}, regResolveTimes, regResolveAction)

	for _, l := range regAlertLines(svc) {
		if strings.Contains(l, " ds ds ") {
			t.Errorf("a ds alert for a DS that none matches: %q", l)
		}
	}
}
