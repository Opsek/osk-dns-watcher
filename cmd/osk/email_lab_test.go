//go:build lab

package main

import (
	"fmt"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// emlLabInterval is the interval of the checks of these tests: the record
// lines are in the tier "other", and every other tier keeps 1h.
const emlLabInterval = 5 * time.Second

// emlLabRule is what one of the mail alerts says about the TXT line at
// name of corp.test.
type emlLabRule struct {
	word     string // the rule word of the alert lines
	kind     string // the kind of the check: records, or policy for the policy file
	name     string // the owner of the line
	marker   string // in the headline of every message of the alert
	neutral  string // the phrase of an alert that names no word
	more     string // the phrase of an alert that names words
	resolved string
	action   string
}

var (
	emlLabSPF = emlLabRule{
		word: "spf", kind: "records", name: "corp.test.", marker: "the SPF record at `corp.test.`",
		neutral:  "the SPF record at `corp.test.` changed",
		more:     "the SPF record at `corp.test.` lets more senders pass than the file",
		resolved: "the SPF record at `corp.test.` is as expected again",
		action:   "If you did not make this change, restore the record at your DNS provider: every sender that it lets pass can send mail as `corp.test.`.",
	}
	emlLabDMARC = emlLabRule{
		word: "dmarc", kind: "records", name: "_dmarc.corp.test.", marker: "the DMARC record `_dmarc.corp.test.`",
		neutral:  "the DMARC record `_dmarc.corp.test.` changed",
		more:     "the DMARC record `_dmarc.corp.test.` asks receivers to do less than the file",
		resolved: "the DMARC record `_dmarc.corp.test.` is as expected again",
		action:   "If you did not make this change, restore the record at your DNS provider: receivers follow it for mail that claims to come from your domain.",
	}
	emlLabDKIM = emlLabRule{
		word: "dkim", kind: "records", name: "s1._domainkey.corp.test.", marker: "the DKIM key `s1._domainkey.corp.test.`",
		neutral:  "the DKIM key `s1._domainkey.corp.test.` changed",
		more:     "the DKIM key `s1._domainkey.corp.test.` lets another key sign mail",
		resolved: "the DKIM key `s1._domainkey.corp.test.` is as expected again",
		action:   "If you did not change this key, remove the key that is not yours at your DNS provider: whoever holds its private key can sign mail that receivers trust.",
	}
	emlLabMTASTS = emlLabRule{
		word: "mta-sts", kind: "records", name: "_mta-sts.corp.test.", marker: "MTA-STS at `_mta-sts.corp.test.`",
		neutral:  "MTA-STS at `_mta-sts.corp.test.` changed",
		more:     "MTA-STS at `_mta-sts.corp.test.` protects less than the file",
		resolved: "MTA-STS at `_mta-sts.corp.test.` is as expected again",
		action:   "If you did not make this change, restore it: senders use MTA-STS to refuse mail servers that are not yours.",
	}
	emlLabPolicy = emlLabRule{
		word: "mta-sts", kind: "policy", name: "mta-sts.corp.test.", marker: "MTA-STS at `mta-sts.corp.test.`",
		more:     "MTA-STS at `mta-sts.corp.test.` protects less than the file",
		resolved: "MTA-STS at `mta-sts.corp.test.` is as expected again",
		action:   "If you did not make this change, restore it: senders use MTA-STS to refuse mail servers that are not yours.",
	}
)

// label is the end of every alert line of the alert.
func (r emlLabRule) label() string { return "medium " + r.word + " " + r.kind + " " + r.name + " TXT" }

func (r emlLabRule) runPrefix() string {
	return "checked other " + r.kind + " corp.test. " + r.name + " TXT "
}

// emlLabFirstRun waits for the first finished run of the check of the line.
// A started service has up to 60 s before its first line on a busy machine.
func emlLabFirstRun(t *testing.T, svc *cliLabService, r emlLabRule) {
	t.Helper()
	svc.wait(t, "a finished run of the check of "+r.name+" TXT", time.Now().Add(60*time.Second), func(l cliLabLog) bool {
		return l.Event == "checked" && strings.HasPrefix(l.Text, r.runPrefix()) && strings.HasSuffix(l.Text, " ok")
	})
}

// emlLabEvents gives the kinds of the alert lines of the alert, in order:
// open, update or resolve.
func emlLabEvents(svc *cliLabService, r emlLabRule) []string {
	var events []string
	for _, l := range regAlertLines(svc) {
		if event, rest, ok := strings.Cut(strings.TrimPrefix(l, "alert "), " "); ok && rest == r.label() {
			events = append(events, event)
		}
	}
	return events
}

// emlLabTexts waits until the receiver holds n Slack messages of the alert
// and gives them in order, and requires that no more came. The messages of
// other alerts and notices are left out.
func emlLabTexts(t *testing.T, w *cliLabWorld, r emlLabRule, n int) []string {
	t.Helper()
	var texts []string
	cliLabUntil(t, strconv.Itoa(n)+" Slack messages of the "+r.word+" alert", time.Now().Add(3*time.Second), 50*time.Millisecond, func() bool {
		texts = nil
		for _, s := range cliLabSlackTexts(t, w) {
			if head, _, _ := strings.Cut(s, "\n"); strings.Contains(head, r.marker) {
				texts = append(texts, s)
			}
		}
		return len(texts) >= n
	})
	if len(texts) != n {
		t.Fatalf("the receiver holds %d Slack messages of the %s alert, want exactly %d:\n%s", len(texts), r.word, n, strings.Join(texts, "\n---\n"))
	}
	return texts
}

// emlLabLatest gives the Slack text of the last open or update line of the
// alert, and whether it is an update.
func emlLabLatest(t *testing.T, svc *cliLabService, w *cliLabWorld, r emlLabRule) (text string, changed bool) {
	t.Helper()
	events := emlLabEvents(svc, r)
	texts := emlLabTexts(t, w, r, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		switch events[i] {
		case "open":
			return texts[i], false
		case "update":
			return texts[i], true
		}
	}
	t.Fatalf("no open or update line of the %s alert in %q", r.word, events)
	return "", false
}

// emlLabResolveText gives the Slack text of the last resolve line.
func emlLabResolveText(t *testing.T, svc *cliLabService, w *cliLabWorld, r emlLabRule) string {
	t.Helper()
	events := emlLabEvents(svc, r)
	texts := emlLabTexts(t, w, r, len(events))
	for i := len(events) - 1; i >= 0; i-- {
		if events[i] == "resolve" {
			return texts[i]
		}
	}
	t.Fatalf("no resolve line of the %s alert in %q", r.word, events)
	return ""
}

// emlLabChange changes the zone with the labctl command args, waits for the
// alert line of event that is logged after the change, and, for an alert
// that stays open, for a run of the check that begins half an interval after
// that line, so that both servers are in view. labctl changes ns1 and then
// ns2, and a run between the two changes sees one server only: its line is
// followed by an update.
func emlLabChange(t *testing.T, svc *cliLabService, r emlLabRule, event string, args ...string) {
	t.Helper()
	set := time.Now()
	expCtl(t, args...)
	line := "alert " + event + " " + r.label()
	first := svc.wait(t, "the "+event+" line of the "+r.word+" alert", set.Add(dngWindow(emlLabInterval)), func(l cliLabLog) bool {
		return l.Text == line && l.at.After(set)
	})
	if event != "resolve" {
		dngNextRun(t, svc, r.runPrefix(), first.at.Add(emlLabInterval/2), emlLabInterval)
	}
}

// emlLabView is the view of an open alert: the words, the line in force,
// and what the two servers give. A set that is none has its negative TTL.
func emlLabView(t *testing.T, w *cliLabWorld, r emlLabRule, words []string, expected, now string) []string {
	t.Helper()
	var view []string
	for i, word := range words {
		label := "           "
		if i == 0 {
			label = "weaker     "
		}
		view = append(view, label+word)
	}
	if len(words) > 0 {
		view = append(view, "")
	}
	ttl := func(addr string) string {
		if now == "none" {
			return dngNegativeTTL(t, addr, r.name, "TXT")
		}
		return dngTTL(t, addr, r.name, "TXT")
	}
	return append(view, "expected   "+expected, "", "now        "+now,
		"seen at    ns1.corp.test. ("+w.n+"11)   TTL "+ttl(w.n+"11:53"),
		"           ns2.corp.test. ("+w.n+"12)   TTL "+ttl(w.n+"12:53"))
}

// emlLabExpectOpen checks the last message of the open alert: its phrase,
// and its view with the words, the line in force and the set that both
// servers give. update says that the message must be an update.
func emlLabExpectOpen(t *testing.T, svc *cliLabService, w *cliLabWorld, r emlLabRule, update bool, phrase string, words []string, expected, now string) {
	t.Helper()
	text, changed := emlLabLatest(t, svc, w, r)
	if update && !changed {
		t.Errorf("the last message of the %s alert is its first, want an update", r.word)
	}
	regExpect(t, text, dngHead(":large_orange_circle: *MEDIUM*", changed, " · "+phrase), emlLabView(t, w, r, words, expected, now),
		regOpenTimes, ":point_right: "+r.action)
}

// emlLabExpectResolve checks the last resolve message: the line in force is
// what the servers give again.
func emlLabExpectResolve(t *testing.T, svc *cliLabService, w *cliLabWorld, r emlLabRule, expected string) {
	t.Helper()
	regExpect(t, emlLabResolveText(t, svc, w, r), ":white_check_mark: *RESOLVED* · "+r.resolved,
		[]string{"now        " + expected}, regResolveTimes, regResolveAction)
}

// emlLabNone requires that no alert line of the rules that the alert
// replaces, or of the checks that a probe would add, is there.
func emlLabNone(t *testing.T, svc *cliLabService) {
	t.Helper()
	for _, rule := range []string{"record-set", "disagree", "mail-target", "zone-changed"} {
		dngNone(t, svc, rule)
	}
}

// emlLabAlerts requires that the alert lines are an open line, between
// minUpdates and maxUpdates update lines of the alert, and a resolve line,
// and no other line.
func emlLabAlerts(t *testing.T, svc *cliLabService, r emlLabRule, minUpdates, maxUpdates int) {
	t.Helper()
	lines := regAlertLines(svc)
	prefix := "alert %s " + r.label()
	updates := len(lines) - 2
	ok := len(lines) >= 2 && lines[0] == fmt.Sprintf(prefix, "open") && lines[len(lines)-1] == fmt.Sprintf(prefix, "resolve") &&
		updates >= minUpdates && updates <= maxUpdates
	for i := 1; ok && i < len(lines)-1; i++ {
		ok = lines[i] == fmt.Sprintf(prefix, "update")
	}
	if !ok {
		t.Errorf("alert lines:\n%s\nwant an open line, %d to %d update lines and a resolve line of %s", strings.Join(lines, "\n"), minUpdates, maxUpdates, r.label())
	}
}

// A weakened SPF record, a stricter one and the return to the file: each
// change is a change of one alert, which names the policy and, while the
// record lets more senders pass, says how. The include of the record is not
// in the file, so nothing probes it.
func TestSPFWeakenedAlert(t *testing.T) {
	const strict = `"v=spf1 mx -all"`
	const weak = `"v=spf1 mx include:evil.test ~all"`
	const stricter = `"v=spf1 -all"`
	r := emlLabSPF
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "corp.test. TXT "+strict)
	}, map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)

	emlLabFirstRun(t, svc, r)
	dngNoAlerts(t, svc)

	emlLabChange(t, svc, r, "open", "set", "both", "corp.test.", "300", "TXT", weak)
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, false, r.more, []string{
		"all gives softfail in place of fail",
		"include:evil.test gives pass in place of fail",
	}, strict, weak)

	// A stricter record permits nothing more: the alert is updated and its
	// words are gone.
	emlLabChange(t, svc, r, "update", "set", "both", "corp.test.", "300", "TXT", stricter)
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, true, r.neutral, nil, strict, stricter)

	emlLabChange(t, svc, r, "resolve", "set", "both", "corp.test.", "300", "TXT", strict)
	emlLabExpectResolve(t, svc, w, r, strict)
	emlLabNone(t, svc)
	emlLabAlerts(t, svc, r, 1, 3)
}

// A DMARC record that asks less of receivers, and one that is gone.
func TestDMARCWeakenedAlert(t *testing.T) {
	const strict = `"v=DMARC1; p=reject"`
	const weak = `"v=DMARC1; p=none; rua=mailto:x@evil.test"`
	r := emlLabDMARC
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "_dmarc.corp.test. TXT "+strict)
	}, map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)

	emlLabFirstRun(t, svc, r)
	dngNoAlerts(t, svc)

	emlLabChange(t, svc, r, "open", "set", "both", "_dmarc.corp.test.", "300", "TXT", weak)
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, false, r.more, []string{
		"p=none in place of p=reject",
		"rua also sends reports to mailto:x@evil.test",
	}, strict, weak)

	emlLabChange(t, svc, r, "update", "del", "both", "_dmarc.corp.test.", "TXT")
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, true, r.more, []string{"no DMARC record: receivers apply no DMARC policy"}, strict, "none")

	emlLabChange(t, svc, r, "resolve", "set", "both", "_dmarc.corp.test.", "300", "TXT", strict)
	emlLabExpectResolve(t, svc, w, r, strict)
	emlLabNone(t, svc)
	emlLabAlerts(t, svc, r, 1, 3)
}

// Another key at a selector that the file lists, then the key of the file
// written in two strings: the text differs, so the alert is updated, but the
// policy is the same, so it names no word.
func TestDKIMKeyChangedAlert(t *testing.T) {
	const key = `"v=DKIM1; k=rsa; p=QUJDRA=="`
	const other = `"v=DKIM1; k=rsa; p=RUZHSA=="`
	const split = `"v=DKIM1; k=rsa; " "p=QUJDRA=="`
	r := emlLabDKIM
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "s1._domainkey.corp.test. TXT "+key)
	}, map[string]string{"other": "5s"})
	expCtl(t, "set", "both", "s1._domainkey.corp.test.", "300", "TXT", key)
	svc := cliLabStart(t, w)

	emlLabFirstRun(t, svc, r)
	dngNoAlerts(t, svc)

	emlLabChange(t, svc, r, "open", "set", "both", "s1._domainkey.corp.test.", "300", "TXT", other)
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, false, r.more,
		[]string{`a key that the file does not list: k=rsa, 8 characters, ending "RUZHSA=="`}, key, other)

	emlLabChange(t, svc, r, "update", "set", "both", "s1._domainkey.corp.test.", "300", "TXT", split)
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, true, r.neutral, nil, key, split)

	emlLabChange(t, svc, r, "resolve", "set", "both", "s1._domainkey.corp.test.", "300", "TXT", key)
	emlLabExpectResolve(t, svc, w, r, key)
	emlLabNone(t, svc)
	emlLabAlerts(t, svc, r, 1, 3)
}

// An MTA-STS record that is gone says that senders get no policy; a record
// with another id permits nothing less, and its alert says only that the
// record changed.
func TestMTASTSRecordAlert(t *testing.T) {
	const record = `"v=STSv1; id=20261117"`
	const newer = `"v=STSv1; id=20261118"`
	r := emlLabMTASTS
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "_mta-sts.corp.test. TXT "+record)
	}, map[string]string{"other": "5s"})
	expCtl(t, "set", "both", "_mta-sts.corp.test.", "300", "TXT", record)
	svc := cliLabStart(t, w)

	emlLabFirstRun(t, svc, r)
	dngNoAlerts(t, svc)

	emlLabChange(t, svc, r, "open", "del", "both", "_mta-sts.corp.test.", "TXT")
	emlLabNone(t, svc)
	emlLabExpectOpen(t, svc, w, r, false, r.more,
		[]string{"no MTA-STS record: senders that have not cached the policy send mail without it"}, record, "none")

	set := time.Now()
	expCtl(t, "set", "both", "_mta-sts.corp.test.", "300", "TXT", record)
	svc.wait(t, "the resolve line of the mta-sts alert", set.Add(dngWindow(emlLabInterval)), func(l cliLabLog) bool {
		return l.Text == "alert resolve "+r.label() && l.at.After(set)
	})
	emlLabExpectResolve(t, svc, w, r, record)

	// Another id: the alert opens again, with no word. The file has no
	// mta-sts line, so the id is the only sign of a new policy and nothing
	// fetches the policy file; with the line, the id is not compared (see
	// TestMTASTSPolicyAlert).
	set = time.Now()
	expCtl(t, "set", "both", "_mta-sts.corp.test.", "300", "TXT", newer)
	opened := svc.wait(t, "the second open line of the mta-sts alert", set.Add(dngWindow(emlLabInterval)), func(l cliLabLog) bool {
		return l.Text == "alert open "+r.label() && l.at.After(set)
	})
	dngNextRun(t, svc, r.runPrefix(), opened.at.Add(emlLabInterval/2), emlLabInterval)
	emlLabExpectOpen(t, svc, w, r, false, r.neutral, nil, record, newer)

	set = time.Now()
	expCtl(t, "set", "both", "_mta-sts.corp.test.", "300", "TXT", record)
	svc.wait(t, "the second resolve line of the mta-sts alert", set.Add(dngWindow(emlLabInterval)), func(l cliLabLog) bool {
		return l.Text == "alert resolve "+r.label() && l.at.After(set)
	})
	emlLabExpectResolve(t, svc, w, r, record)
	emlLabNone(t, svc)

	// An open line may be followed by one update line: labctl changes ns1
	// and then ns2.
	dngExpectAlerts(t, svc, "alert open "+r.label(), "alert resolve "+r.label(), "alert open "+r.label(), "alert resolve "+r.label())
}

// emlLabPolicyBody is a policy file as the policy host serves it.
func emlLabPolicyBody(mode string, maxAge int, mx ...string) string {
	lines := []string{"version: STSv1", "mode: " + mode}
	for _, m := range mx {
		lines = append(lines, "mx: "+m)
	}
	return strings.Join(append(lines, "max_age: "+strconv.Itoa(maxAge)), "\n") + "\n"
}

// emlLabExpectPolicy checks the last message of the open alert of the policy
// file. The policy host has no TTL, and it is one server, so one server line.
func emlLabExpectPolicy(t *testing.T, svc *cliLabService, w *cliLabWorld, update bool, words []string, now string) {
	t.Helper()
	r := emlLabPolicy
	text, changed := emlLabLatest(t, svc, w, r)
	if update && !changed {
		t.Errorf("the last message of the policy alert is its first, want an update")
	}
	view := []string{"weaker     " + words[0]}
	for _, word := range words[1:] {
		view = append(view, "           "+word)
	}
	view = append(view, "", "expected   mta-sts enforce 604800 mail.corp.test.", "", "now        "+now,
		"seen at    mta-sts.corp.test. ("+w.n+"30:443)")
	regExpect(t, text, dngHead(":large_orange_circle: *MEDIUM*", changed, " · "+r.more), view, regOpenTimes, ":point_right: "+r.action)
}

// emlLabPolicyEvents requires the kinds of the alert lines of the policy
// alert, and that the TXT record of the policy has no alert.
func emlLabPolicyEvents(t *testing.T, svc *cliLabService, want ...string) {
	t.Helper()
	if got := emlLabEvents(svc, emlLabPolicy); !slices.Equal(got, want) {
		t.Errorf("alert lines of the policy alert: %q, want %q", got, want)
	}
	if got := emlLabEvents(svc, emlLabMTASTS); len(got) != 0 {
		t.Errorf("alert lines of the MTA-STS record: %q, want none", got)
	}
}

// A policy file that is weaker than the line of the file alerts while the
// record does not change. A failed fetch is not "no policy": it does not
// resolve the alert. The fetch gives one answer, so no change needs a wait
// for a second server.
func TestMTASTSPolicyAlert(t *testing.T) {
	const record = `"v=STSv1; id=1"`
	const line = "mta-sts enforce 604800 mail.corp.test."
	const weakerMode = "mode testing in place of enforce: senders deliver mail even when the TLS check fails"
	enforce := emlLabPolicyBody("enforce", 604800, "mail.corp.test")
	testing1 := emlLabPolicyBody("testing", 604800, "mail.corp.test")
	testing2 := emlLabPolicyBody("testing", 604800, "mail.corp.test", "*.evil.test")
	r := emlLabPolicy
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "_mta-sts.corp.test. TXT "+record, line)
	}, map[string]string{"other": "5s"})
	expCtl(t, "set", "both", "_mta-sts.corp.test.", "300", "TXT", record)
	expCtl(t, "policy", r.name, "200", enforce)
	svc := cliLabStart(t, w)

	emlLabFirstRun(t, svc, r)
	dngNoAlerts(t, svc)

	// The mode is lowered and the record stays as it is.
	emlLabChange(t, svc, r, "open", "policy", r.name, "200", testing1)
	emlLabNone(t, svc)
	emlLabPolicyEvents(t, svc, "open")
	emlLabExpectPolicy(t, svc, w, false, []string{weakerMode}, "mta-sts testing 604800 mail.corp.test.")

	emlLabChange(t, svc, r, "update", "policy", r.name, "200", testing2)
	emlLabNone(t, svc)
	emlLabPolicyEvents(t, svc, "open", "update")
	emlLabExpectPolicy(t, svc, w, true, []string{weakerMode, "mx *.evil.test. is not allowed by the file"},
		"mta-sts testing 604800 mail.corp.test. *.evil.test.")

	// A fetch that fails tells nothing about the policy: two failed runs
	// pass, and the alert stays as it is.
	set := time.Now()
	expCtl(t, "policy", r.name, "404")
	failed := func(l cliLabLog) bool {
		return l.Event == "checked" && strings.HasPrefix(l.Text, r.runPrefix()) && strings.Contains(l.Text, " failed ") && l.at.After(set)
	}
	first := svc.wait(t, "a failed run of the policy check", set.Add(dngWindow(emlLabInterval)), failed)
	svc.wait(t, "a second failed run of the policy check", first.at.Add(dngWindow(emlLabInterval)), func(l cliLabLog) bool {
		return failed(l) && l.at.After(first.at)
	})
	emlLabPolicyEvents(t, svc, "open", "update")
	emlLabNone(t, svc)

	emlLabChange(t, svc, r, "resolve", "policy", r.name, "200", enforce)
	emlLabExpectResolve(t, svc, w, r, line)
	emlLabPolicyEvents(t, svc, "open", "update", "resolve")
	emlLabNone(t, svc)
}
