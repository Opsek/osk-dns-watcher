//go:build lab

package main

import (
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/schedule"
)

// dngWindow is how long a change may take to show as an alert: the interval
// of its tier, a start spread of 75%, and a second.
func dngWindow(interval time.Duration) time.Duration {
	return interval + interval*3/4 + time.Second
}

// dngChecked waits for the first finished run of a check: its kind, name and
// type as the log of a run prints them after the tier.
func dngChecked(t *testing.T, svc *cliLabService, tier, key string) cliLabLog {
	t.Helper()
	prefix := "checked " + tier + " " + key + " "
	return svc.wait(t, "a checked "+tier+" "+key+" line", time.Now().Add(20*time.Second), func(l cliLabLog) bool {
		return l.Event == "checked" && strings.HasPrefix(l.Text, prefix) && strings.HasSuffix(l.Text, " ok")
	})
}

func dngNoAlerts(t *testing.T, svc *cliLabService) {
	t.Helper()
	if lines := regAlertLines(svc); len(lines) != 0 {
		t.Fatalf("alert lines before any change: %q", lines)
	}
}

// dngCount is the number of alert lines of a rule.
func dngCount(svc *cliLabService, rule string) int {
	n := 0
	for _, l := range regAlertLines(svc) {
		if strings.Contains(l, " "+rule+" ") {
			n++
		}
	}
	return n
}

// dngTTL is the TTL that the server at addr gives for the set, as dig sees
// it.
func dngTTL(t *testing.T, addr, name, qtype string) string {
	t.Helper()
	sets := cliPick(cliAskDig(t, addr, name, qtype).sections["ANSWER"], name, qtype)
	if len(sets) == 0 {
		t.Fatalf("dig @%s %s %s shows no record", addr, name, qtype)
	}
	return strings.SplitN(sets[0], "\t", 5)[1]
}

// dngRequests waits for n Slack requests and requires that no more came.
func dngRequests(t *testing.T, w *cliLabWorld, n int) []string {
	t.Helper()
	texts := regTexts(t, w, n, time.Now().Add(3*time.Second))
	if len(texts) != n {
		t.Fatalf("the receiver holds %d Slack requests, want exactly %d:\n%s", len(texts), n, strings.Join(texts, "\n---\n"))
	}
	return texts
}

func dngNone(t *testing.T, svc *cliLabService, rule string) {
	t.Helper()
	if n := dngCount(svc, rule); n != 0 {
		t.Errorf("%d %s alert lines, want none:\n%s", n, rule, strings.Join(regAlertLines(svc), "\n"))
	}
}

func TestServersDisagreeAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string {
		return strings.Replace(cliLabFile(n), "www.corp.test. A "+n+"81", "www.corp.test. A in "+n+"0/24", 1)
	}, map[string]string{"fast": "5s", "other": "5s"})
	svc := cliLabStart(t, w)
	const open = "alert open medium disagree records www.corp.test. A"
	const resolve = "alert resolve medium disagree records www.corp.test. A"

	dngChecked(t, svc, "fast", "records corp.test. www.corp.test. A")
	dngNoAlerts(t, svc)

	// The split must last 11 runs and twice the interval of the other tier;
	// with both tiers at one interval the runs are the later condition. A run
	// that started just before the change may already have asked ns2 after
	// it, so the time bound has a second of slack.
	t0 := time.Now()
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", w.n+"88")
	opened := svc.wait(t, "the disagree alert", t0.Add(schedule.DisagreeRuns*interval+dngWindow(interval)), regIs(open))
	if early := t0.Add(2*interval - time.Second); opened.at.Before(early) {
		t.Errorf("the disagree alert came at %s, not before %s", opened.at.Format(time.TimeOnly+".000"), early.Format(time.TimeOnly+".000"))
	}
	// The run that began the split may have started just before the change
	// and still have asked ns2 after it, so one run of the 11 may precede T0.
	if runs := dngRunsSince(svc, t0, opened.at); runs < schedule.DisagreeRuns-1 {
		t.Errorf("the disagree alert came after %d runs that started since the change, want at least %d", runs, schedule.DisagreeRuns-1)
	}
	dngNone(t, svc, "record-set")
	texts := dngRequests(t, w, 1)
	const phrase = " · the nameservers of `corp.test.` give different answers for `www.corp.test. A`"
	regExpect(t, texts[0], ":large_orange_circle: *MEDIUM*"+phrase, []string{
		"expected   in " + w.n + "0/24",
		"",
		"now        " + w.n + "81",
		"seen at    ns1.corp.test. (" + w.n + "11)   TTL " + dngTTL(t, w.n+"11:53", "www.corp.test.", "A"),
		"",
		"now        " + w.n + "88",
		"seen at    ns2.corp.test. (" + w.n + "12)   TTL " + dngTTL(t, w.n+"12:53", "www.corp.test.", "A"),
	}, regOpenTimes, ":point_right: Find out why one nameserver of `corp.test.` answers otherwise: it may be out of date, or not yours.")

	set := time.Now()
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", w.n+"81")
	// The alert ends only after 11 runs in which the servers agree; the run
	// that was already on its way at the change may be the first of them.
	ended := svc.wait(t, "the resolve of the disagree alert", set.Add(schedule.DisagreeRuns*interval+dngWindow(interval)), regIs(resolve))
	if runs := dngRunsSince(svc, set, ended.at); runs < schedule.DisagreeRuns-1 {
		t.Errorf("the disagree alert ended after %d runs that started since the servers agreed, want at least %d", runs, schedule.DisagreeRuns-1)
	}
	texts = regTexts(t, w, 2, time.Now().Add(3*time.Second))
	back := ":white_check_mark: *RESOLVED* · the nameservers of `corp.test.` agree on `www.corp.test. A` again"
	regExpect(t, regTextWith(t, texts, back), back, []string{"now        the servers agree"}, regResolveTimes, regResolveAction)

	// A server that gives a set the line does not allow is a record-set
	// alert, and it explains the difference: no disagree alert opens.
	set = time.Now()
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", "10.54.0.1")
	svc.wait(t, "the record-set alert", set.Add(dngWindow(interval)), regIs("alert open high record-set records www.corp.test. A"))
	before := dngCount(svc, "disagree")
	// Long enough for a disagree alert to open if the record-set alert did not hold it back.
	quiet := set.Add(schedule.DisagreeRuns*interval + dngWindow(interval))
	cliLabUntil(t, "the end of the quiet time", quiet.Add(interval), 100*time.Millisecond, func() bool { return !time.Now().Before(quiet) })
	if got := dngCount(svc, "disagree"); got != before {
		t.Errorf("%d disagree alert lines after the record-set alert, want the %d of before:\n%s", got, before, strings.Join(regAlertLines(svc), "\n"))
	}
	set = time.Now()
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", w.n+"81")
	svc.wait(t, "the resolve of the record-set alert", set.Add(dngWindow(interval)), regIs("alert resolve high record-set records www.corp.test. A"))
}

func TestChallengeRecordAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "_acme-challenge.corp.test. TXT none", "_acme-challenge.www.corp.test. TXT none")
	}, map[string]string{"fast": "5s"})
	svc := cliLabStart(t, w)

	for _, name := range []string{"_acme-challenge.corp.test.", "_acme-challenge.www.corp.test."} {
		dngChecked(t, svc, "fast", "records corp.test. "+name+" TXT")
	}
	dngNoAlerts(t, svc)

	requests := 0
	for _, c := range []struct{ name, token string }{
		{"_acme-challenge.corp.test.", `"t0ken1"`},
		{"_acme-challenge.www.corp.test.", `"t0ken2"`},
	} {
		phrase := " · a certificate-challenge record appeared at `" + c.name + " TXT`"
		gone := ":white_check_mark: *RESOLVED* · the certificate-challenge record at `" + c.name + " TXT` is gone"

		set := time.Now()
		expCtl(t, "set", "both", c.name, "300", "TXT", c.token)
		svc.wait(t, "the challenge alert of "+c.name, set.Add(dngWindow(interval)), regIs("alert open high challenge records "+c.name+" TXT"))
		dngNone(t, svc, "record-set")
		requests++
		texts := dngRequests(t, w, requests)
		regExpect(t, regTextWith(t, texts, ":red_circle: *HIGH*"+phrase), ":red_circle: *HIGH*"+phrase, []string{
			"expected   none",
			"",
			"now        " + c.token,
			"seen at    ns1.corp.test. (" + w.n + "11)   TTL " + dngTTL(t, w.n+"11:53", c.name, "TXT"),
			"           ns2.corp.test. (" + w.n + "12)   TTL " + dngTTL(t, w.n+"12:53", c.name, "TXT"),
		}, regOpenTimes, ":point_right: If you did not ask for a certificate for this name, find out who changed your DNS, and look for the certificate in the certificate logs.")

		set = time.Now()
		expCtl(t, "del", "both", c.name, "TXT")
		svc.wait(t, "the resolve of the challenge alert of "+c.name, set.Add(dngWindow(interval)), regIs("alert resolve high challenge records "+c.name+" TXT"))
		requests++
		texts = regTexts(t, w, requests, time.Now().Add(3*time.Second))
		regExpect(t, regTextWith(t, texts, gone), gone, []string{"now        none"}, regResolveTimes, regResolveAction)
	}
	dngNone(t, svc, "record-set")
	if got := dngCount(svc, "challenge"); got != 4 {
		t.Errorf("%d challenge alert lines, want 4:\n%s", got, strings.Join(regAlertLines(svc), "\n"))
	}
}

// dngRunsSince is the number of finished runs of the www check that started
// at or after from and were logged by upTo.
func dngRunsSince(svc *cliLabService, from, upTo time.Time) int {
	n := 0
	for _, l := range svc.all() {
		fields := strings.Fields(l.Text)
		if l.Event != "checked" || !strings.HasPrefix(l.Text, "checked fast records corp.test. www.corp.test. A ") || len(fields) < 2 || fields[len(fields)-1] != "ok" {
			continue
		}
		start, err := time.Parse(receivedLayout, fields[len(fields)-2])
		if err == nil && !start.Before(from) && !l.at.After(upTo) {
			n++
		}
	}
	return n
}

// dngNegativeTTL is the TTL of a no-such-name answer of the server at addr,
// as dig sees it: the smaller of the TTL of the SOA record and its minimum.
func dngNegativeTTL(t *testing.T, addr, qname, qtype string) string {
	t.Helper()
	soas := cliPick(cliAskDig(t, addr, qname, qtype).sections["AUTHORITY"], "", "SOA")
	if len(soas) != 1 {
		t.Fatalf("dig @%s %s %s shows SOA lines %q, want one", addr, qname, qtype, soas)
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

// dngGoneView is the view of an alert about a name that does not exist, as
// the two nameservers of dnshost.test. report it.
func dngGoneView(t *testing.T, w *cliLabWorld, expected, name string) []string {
	t.Helper()
	return []string{
		"expected   " + expected,
		"",
		"now        no such name",
		"seen at    ns1.dnshost.test. (" + w.n + "11)   TTL " + dngNegativeTTL(t, w.n+"11:53", name, "A"),
		"           ns2.dnshost.test. (" + w.n + "12)   TTL " + dngNegativeTTL(t, w.n+"12:53", name, "A"),
	}
}

// dngProbed waits for the first finished run of the probe of a name outside
// the domain.
func dngProbed(t *testing.T, svc *cliLabService, name string) cliLabLog {
	t.Helper()
	return dngChecked(t, svc, "other", "records corp.test. "+name+" A")
}

// labctl changes ns1 and then ns2, and a run of a check can fall between the
// two changes. An alert that lists the servers is then opened, or resolved,
// with one server in view, and the next run, which sees both, sends one
// update. So each event of an alert may be followed by one update of its own
// rule, and nothing more.

// dngExpectAlerts requires these alert lines in this order, and no others,
// except that an open line may be followed by one update line of the same
// alert.
func dngExpectAlerts(t *testing.T, svc *cliLabService, want ...string) {
	t.Helper()
	var got []string
	prev := ""
	for _, l := range regAlertLines(svc) {
		if label, ok := strings.CutPrefix(l, "alert update "); ok {
			if !strings.HasPrefix(prev, "alert open ") || !strings.HasSuffix(prev, " "+label) {
				t.Errorf("the update %q does not follow the open line of its alert (before it: %q)", l, prev)
			}
		} else {
			got = append(got, l)
		}
		prev = l
	}
	if !slices.Equal(got, want) {
		t.Errorf("alert lines:\n%s\nwant (an update after an open line is allowed):\n%s", strings.Join(regAlertLines(svc), "\n"), strings.Join(want, "\n"))
	}
}

// dngNextRun waits for a finished run of the check whose checked line
// starts with prefix, logged after the time given. The run that opened an
// alert logs its checked line within milliseconds of the alert, so the time
// is half an interval after the open line: the next run is a whole interval
// later.
func dngNextRun(t *testing.T, svc *cliLabService, prefix string, after time.Time, interval time.Duration) {
	t.Helper()
	cliLabUntil(t, "a run of the check after the alert", after.Add(dngWindow(interval)), 100*time.Millisecond, func() bool {
		for _, l := range svc.all() {
			if l.Event == "checked" && strings.HasPrefix(l.Text, prefix) && strings.HasSuffix(l.Text, " ok") && l.at.After(after) {
				return true
			}
		}
		return false
	})
}

// dngSettled waits until a run after the open line has seen both servers.
func dngSettled(t *testing.T, svc *cliLabService, opened cliLabLog, runPrefix string, interval time.Duration) {
	t.Helper()
	dngNextRun(t, svc, runPrefix, opened.at.Add(interval/2), interval)
}

// dngLatest gives the Slack text of the last open or update of the alert that
// the line open belongs to, and whether it is an update.
func dngLatest(t *testing.T, svc *cliLabService, w *cliLabWorld, open string) (text string, changed bool) {
	t.Helper()
	lines := regAlertLines(svc)
	texts := dngRequests(t, w, len(lines))
	label := strings.TrimPrefix(open, "alert open ")
	for i := len(lines) - 1; i >= 0; i-- {
		switch lines[i] {
		case "alert open " + label:
			return texts[i], false
		case "alert update " + label:
			return texts[i], true
		}
	}
	t.Fatalf("no open or update line of %q in:\n%s", label, strings.Join(lines, "\n"))
	return "", false
}

// dngHead is the headline of a text: the severity part, the suffix of an
// update, and the phrase that starts with the middle dot.
func dngHead(severity string, changed bool, phrase string) string {
	if changed {
		severity += ", changed again"
	}
	return severity + phrase
}

// dngSteady requires that two more runs of a settled check send nothing.
func dngSteady(t *testing.T, svc *cliLabService, runPrefix string, interval time.Duration) {
	t.Helper()
	before := regAlertLines(svc)
	dngMoreRuns(t, svc, runPrefix, 2, interval)
	if got := regAlertLines(svc); !slices.Equal(got, before) {
		t.Errorf("alert lines changed over two runs of a steady check:\n%s\nbefore:\n%s", strings.Join(got, "\n"), strings.Join(before, "\n"))
	}
}

// dngResolved waits for the resolve line and gives the Slack text that starts
// with head.
func dngResolved(t *testing.T, svc *cliLabService, w *cliLabWorld, set time.Time, interval time.Duration, resolve, head string) string {
	t.Helper()
	svc.wait(t, "the resolve line "+resolve, set.Add(dngWindow(interval)), regIs(resolve))
	texts := dngRequests(t, w, len(regAlertLines(svc)))
	return regTextWith(t, texts, head)
}

func TestAliasTargetGoneAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "cdn.corp.test. CNAME edge.dnshost.test.")
	}, map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)
	const open = "alert open high alias-target records edge.dnshost.test. A"
	const resolve = "alert resolve high alias-target records edge.dnshost.test. A"
	const probe = "checked other records corp.test. edge.dnshost.test. A "

	dngProbed(t, svc, "edge.dnshost.test.")
	dngNoAlerts(t, svc)

	set := time.Now()
	expCtl(t, "del", "both", "edge.dnshost.test.", "A")
	opened := svc.wait(t, "the alias-target alert", set.Add(dngWindow(interval)), regIs(open))
	dngSettled(t, svc, opened, probe, interval)
	text, changed := dngLatest(t, svc, w, open)
	const phrase = " · `edge.dnshost.test.` does not exist, and an alias in `corp.test.` points at it"
	regExpect(t, text, dngHead(":red_circle: *HIGH*", changed, phrase),
		dngGoneView(t, w, "cdn.corp.test. CNAME edge.dnshost.test.", "edge.dnshost.test."),
		regOpenTimes, ":point_right: Change or remove the alias now: whoever creates `edge.dnshost.test.` receives its traffic.")

	set = time.Now()
	expCtl(t, "set", "both", "edge.dnshost.test.", "300", "A", w.n+"83")
	back := ":white_check_mark: *RESOLVED* · `edge.dnshost.test.`, which an alias in `corp.test.` points at, exists again"
	text = dngResolved(t, svc, w, set, interval, resolve, back)
	regExpect(t, text, back, []string{"now        the name exists again: check that it is yours"}, regResolveTimes, regResolveAction)

	// The CNAME line matches the whole time: only the probe has anything to say.
	dngExpectAlerts(t, svc, open, resolve)
}

func TestNameServerHostGoneAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string {
		return strings.Replace(cliLabFile(n), "corp.test. NS ns1.corp.test. | ns2.corp.test.",
			"corp.test. NS ns1.corp.test. | ns2.corp.test. | ns3.dnshost.test.", 1)
	}, map[string]string{"other": "5s"})
	// ns3 is a nameserver of corp.test. at the parent and in the zone. The
	// parent has glue for ns1 and ns2 only.
	expCtl(t, "set", "both", "ns3.dnshost.test.", "300", "A", w.n+"12")
	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.", "ns3.dnshost.test.")
	expCtl(t, "set", "both", "corp.test.", "300", "NS", "ns1.corp.test.", "ns2.corp.test.", "ns3.dnshost.test.")
	svc := cliLabStart(t, w)
	const open = "alert open critical nameserver-host records ns3.dnshost.test. A"
	const resolve = "alert resolve critical nameserver-host records ns3.dnshost.test. A"
	const probe = "checked other records corp.test. ns3.dnshost.test. A "
	const phrase = " · nameserver `ns3.dnshost.test.` of `corp.test.` does not exist"
	const action = ":point_right: Replace `ns3.dnshost.test.` at your registrar now, or restore it: whoever creates it can answer for `corp.test.`."
	back := ":white_check_mark: *RESOLVED* · nameserver `ns3.dnshost.test.` of `corp.test.` exists again"
	backView := []string{"now        the name exists again: check that it is yours"}

	dngProbed(t, svc, "ns3.dnshost.test.")
	dngNoAlerts(t, svc)

	// The host is gone, and its domain is still delegated.
	set := time.Now()
	expCtl(t, "del", "both", "ns3.dnshost.test.", "A")
	opened := svc.wait(t, "the nameserver-host alert", set.Add(dngWindow(interval)), regIs(open))
	dngSettled(t, svc, opened, probe, interval)
	text, changed := dngLatest(t, svc, w, open)
	regExpect(t, text, dngHead(":rotating_light: *CRITICAL*", changed, phrase),
		dngGoneView(t, w, "corp.test. NS ns3.dnshost.test.", "ns3.dnshost.test."), regOpenTimes, action)

	set = time.Now()
	expCtl(t, "set", "both", "ns3.dnshost.test.", "300", "A", w.n+"12")
	text = dngResolved(t, svc, w, set, interval, resolve, back)
	regExpect(t, text, back, backView, regResolveTimes, regResolveAction)

	// The domain of the host is gone: its parent no longer delegates it.
	set = time.Now()
	expCtl(t, "undelegate", "dnshost.test.")
	opened = svc.wait(t, "the nameserver-host alert for the missing domain", set.Add(dngWindow(interval)+interval), func(l cliLabLog) bool {
		return l.Text == open && dngLines(svc, open) == 2
	})
	dngSettled(t, svc, opened, probe, interval)
	// The text names the zone of the SOA record of the answer, so that zone must be test.
	if soa := cliPick(cliAskDig(t, w.n+"3:53", "ns3.dnshost.test.", "A").sections["AUTHORITY"], "", "SOA"); len(soa) != 1 || !strings.HasPrefix(soa[0], "test.\t") {
		t.Errorf("the SOA of the answer of ns.test. is %q, want one owned by test.", soa)
	}
	text, changed = dngLatest(t, svc, w, open)
	regExpect(t, text, dngHead(":rotating_light: *CRITICAL*", changed, phrase), []string{
		"expected   corp.test. NS ns3.dnshost.test.",
		"",
		"now        no such name: test. does not delegate dnshost.test.",
		"seen at    ns.test. (" + w.n + "3)   TTL " + dngNegativeTTL(t, w.n+"3:53", "ns3.dnshost.test.", "A"),
	}, regOpenTimes, action)

	// undelegate removed the glue too, so the restore has three changes.
	expCtl(t, "delegate", "dnshost.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCtl(t, "glue", "ns1.dnshost.test.", w.n+"11")
	set = time.Now()
	expCtl(t, "glue", "ns2.dnshost.test.", w.n+"12")
	svc.wait(t, "the second resolve", set.Add(dngWindow(interval)), func(l cliLabLog) bool {
		return l.Text == resolve && dngLines(svc, resolve) == 2
	})
	texts := dngRequests(t, w, len(regAlertLines(svc)))
	regExpect(t, texts[len(texts)-1], back, backView, regResolveTimes, regResolveAction)
	// The corp.test. checks still get answers from ns1 and ns2: nothing else opens.
	dngExpectAlerts(t, svc, open, resolve, open, resolve)
}

func TestMailTargetGoneAlert(t *testing.T) {
	const interval = 5 * time.Second
	const spf = `"v=spf1 include:spf.dnshost.test -all"`
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, "corp.test. MX 10 mx.dnshost.test.", "corp.test. TXT "+spf)
	}, map[string]string{"fast": "5s", "other": "5s"})
	expCtl(t, "set", "both", "corp.test.", "300", "MX", "10 mx.dnshost.test.")
	expCtl(t, "set", "both", "mx.dnshost.test.", "300", "A", w.n+"85")
	expCtl(t, "set", "both", "corp.test.", "300", "TXT", spf)
	expCtl(t, "set", "both", "spf.dnshost.test.", "300", "TXT", `"v=spf1 ip4:`+w.n+`0/24 -all"`)
	svc := cliLabStart(t, w)

	dngProbed(t, svc, "mx.dnshost.test.")
	dngProbed(t, svc, "spf.dnshost.test.")
	dngNoAlerts(t, svc)

	var alerts []string
	for _, c := range []struct {
		name, expected, record string
		restore                []string
	}{
		{"mx.dnshost.test.", "corp.test. MX mx.dnshost.test.", "A", []string{"A", w.n + "85"}},
		{"spf.dnshost.test.", "corp.test. TXT include:spf.dnshost.test.", "TXT", []string{"TXT", `"v=spf1 ip4:` + w.n + `0/24 -all"`}},
	} {
		open := "alert open high mail-target records " + c.name + " A"
		resolve := "alert resolve high mail-target records " + c.name + " A"
		alerts = append(alerts, open, resolve)

		set := time.Now()
		expCtl(t, "del", "both", c.name, c.record)
		opened := svc.wait(t, "the mail-target alert of "+c.name, set.Add(dngWindow(interval)), regIs(open))
		dngSettled(t, svc, opened, "checked other records corp.test. "+c.name+" A ", interval)
		text, changed := dngLatest(t, svc, w, open)
		phrase := " · `" + c.name + "` does not exist, and the mail records of `corp.test.` point at it"
		regExpect(t, text, dngHead(":red_circle: *HIGH*", changed, phrase),
			dngGoneView(t, w, c.expected, c.name), regOpenTimes,
			":point_right: Change the MX or SPF record that names `"+c.name+"` now: whoever creates it can receive or send mail as `corp.test.`.")

		set = time.Now()
		expCtl(t, "set", "both", c.name, "300", c.restore[0], c.restore[1])
		back := ":white_check_mark: *RESOLVED* · `" + c.name + "`, which the mail records of `corp.test.` point at, exists again"
		text = dngResolved(t, svc, w, set, interval, resolve, back)
		regExpect(t, text, back, []string{"now        the name exists again: check that it is yours"}, regResolveTimes, regResolveAction)
	}
	dngExpectAlerts(t, svc, alerts...)
}

// dngWildcardHead is the first headline of a wildcard alert.
const dngWildcardHead = " · a wildcard answers for names under `corp.test.` that do not exist"

func TestWildcardAddedAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string { return cliLabFile(n, "*.corp.test. A none") },
		map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)
	const open = "alert open medium wildcard wildcard corp.test. A"
	const resolve = "alert resolve medium wildcard wildcard corp.test. A"
	const wildcardRuns = "checked other wildcard corp.test. corp.test. A "

	dngChecked(t, svc, "other", "wildcard corp.test. corp.test. A")
	dngNoAlerts(t, svc)

	set := time.Now()
	expCtl(t, "set", "both", "*.corp.test.", "300", "A", w.n+"66")
	opened := svc.wait(t, "the wildcard alert", set.Add(dngWindow(interval)), regIs(open))
	dngSettled(t, svc, opened, wildcardRuns, interval)
	text, changed := dngLatest(t, svc, w, open)
	ttl := dngTTL(t, w.n+"11:53", "no-such-name.corp.test.", "A")
	regExpect(t, text, dngHead(":large_orange_circle: *MEDIUM*", changed, dngWildcardHead), []string{
		"expected   none",
		"",
		"now        " + w.n + "66",
		"seen at    ns1.corp.test. (" + w.n + "11)   TTL " + ttl,
		"           ns2.corp.test. (" + w.n + "12)   TTL " + dngTTL(t, w.n+"12:53", "no-such-name.corp.test.", "A"),
	}, regOpenTimes, ":point_right: If you did not add a wildcard under `corp.test.`, remove it at your DNS provider and find out who added it.")

	// Each run asks another random name; the answer does not change, so
	// nothing is sent again.
	dngSteady(t, svc, wildcardRuns, interval)

	set = time.Now()
	expCtl(t, "del", "both", "*.corp.test.", "A")
	back := ":white_check_mark: *RESOLVED* · no wildcard answers under `corp.test.` again"
	text = dngResolved(t, svc, w, set, interval, resolve, back)
	regExpect(t, text, back, []string{"now        no wildcard"}, regResolveTimes, regResolveAction)

	// A wildcard with no A record gives no data for a random name: not seen.
	expCtl(t, "set", "both", "*.corp.test.", "300", "TXT", `"catch all"`)
	dngTTL(t, w.n+"11:53", "no-such-name.corp.test.", "TXT") // fails unless a random name now gets the TXT set
	dngMoreRuns(t, svc, wildcardRuns, 2, interval)
	dngExpectAlerts(t, svc, open, resolve)
	dngRequests(t, w, len(regAlertLines(svc)))

	// The wildcard check owns the line: the file's none line has no records check.
	for _, l := range svc.all() {
		if l.Event == "checked" && strings.Contains(l.Text, "records corp.test. *.corp.test. A") {
			t.Errorf("a records check of the wildcard line: %q", l.Text)
		}
	}
}

// dngMoreRuns waits for n more finished runs of the check whose checked line
// starts with prefix.
func dngMoreRuns(t *testing.T, svc *cliLabService, prefix string, n int, interval time.Duration) {
	t.Helper()
	count := func() int {
		c := 0
		for _, l := range svc.all() {
			if l.Event == "checked" && strings.HasPrefix(l.Text, prefix) && strings.HasSuffix(l.Text, " ok") {
				c++
			}
		}
		return c
	}
	want := count() + n
	cliLabUntil(t, "more runs of the check", time.Now().Add(time.Duration(n+1)*dngWindow(interval)), 100*time.Millisecond, func() bool { return count() >= want })
}

// dngLines is the number of alert lines with exactly this text.
func dngLines(svc *cliLabService, text string) int {
	n := 0
	for _, l := range regAlertLines(svc) {
		if l == text {
			n++
		}
	}
	return n
}

// A wildcard of another type than A is no wildcard alert: the line of its own
// is an ordinary record-set line.
func TestWildcardOfAnotherTypeIsARecordSetAlert(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string { return cliLabFile(n, "*.corp.test. MX none") },
		map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)
	const open = "alert open high record-set records *.corp.test. MX"
	const resolve = "alert resolve high record-set records *.corp.test. MX"

	dngChecked(t, svc, "other", "records corp.test. *.corp.test. MX")
	dngNoAlerts(t, svc)

	set := time.Now()
	expCtl(t, "set", "both", "*.corp.test.", "300", "MX", "10 mx.evil.test.")
	opened := svc.wait(t, "the record-set alert", set.Add(dngWindow(interval)), regIs(open))
	dngSettled(t, svc, opened, "checked other records corp.test. *.corp.test. MX ", interval)
	text, changed := dngLatest(t, svc, w, open)
	regExpect(t, text, dngHead(":red_circle: *HIGH*", changed, " · `*.corp.test. MX` changed"), []string{
		"expected   none",
		"",
		"now        10 mx.evil.test.",
		"seen at    ns1.corp.test. (" + w.n + "11)   TTL " + dngTTL(t, w.n+"11:53", "*.corp.test.", "MX"),
		"           ns2.corp.test. (" + w.n + "12)   TTL " + dngTTL(t, w.n+"12:53", "*.corp.test.", "MX"),
	}, regOpenTimes, ":point_right: If you did not make this change, check your DNS provider account now.")

	set = time.Now()
	expCtl(t, "del", "both", "*.corp.test.", "MX")
	back := ":white_check_mark: *RESOLVED* · `*.corp.test. MX` is as expected again"
	text = dngResolved(t, svc, w, set, interval, resolve, back)
	regExpect(t, text, back, []string{"now        none"}, regResolveTimes, regResolveAction)

	dngExpectAlerts(t, svc, open, resolve)
	for _, l := range svc.all() {
		if strings.Contains(l.Text, " wildcard ") {
			t.Errorf("a wildcard line for a file with no *.corp.test. A line: %q", l.Text)
		}
	}
}

// The wildcard check is a check of the zone: a moved serial starts it at
// once, and the change that it finds explains the move.
func TestWildcardFoundAtOnceAfterASerialMove(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string { return cliLabFile(n, "*.corp.test. A none") },
		map[string]string{"serial": "5s", "other": "1h"})
	svc := cliLabStart(t, w)
	const open = "alert open medium wildcard wildcard corp.test. A"

	dngChecked(t, svc, "other", "wildcard corp.test. corp.test. A")
	dngNoAlerts(t, svc)

	set := time.Now()
	expCtl(t, "set", "both", "*.corp.test.", "300", "A", w.n+"66")
	svc.wait(t, "the wildcard alert", set.Add(dngWindow(interval)+interval), regIs(open))
	// Two more serial rounds: the move is explained, so no zone-changed notice.
	dngMoreRuns(t, svc, "checked serial ", 2, interval)
	text, changed := dngLatest(t, svc, w, open)
	if head := strings.SplitN(text, "\n", 2)[0]; head != dngHead(":large_orange_circle: *MEDIUM*", changed, dngWildcardHead) {
		t.Errorf("the Slack text starts with %q", head)
	}
	dngExpectAlerts(t, svc, open)
	for _, l := range svc.all() {
		if strings.Contains(l.Text, "zone-changed") {
			t.Errorf("a zone-changed line after a wildcard alert: %q", l.Text)
		}
	}
}

// dngLabel finds a random label of a wildcard check in a text.
var dngLabel = regexp.MustCompile(`[a-z2-7]{26}`)

// A DNAME above the wildcard line builds each answer from the asked name. The
// label must not reach the alert: one open, no update after both servers
// were seen, and the label is written as *.
func TestWildcardThroughADNAMEOpensOnce(t *testing.T) {
	const interval = 5 * time.Second
	w := cliLabSetup(t, false, func(n string) string { return cliLabFile(n, "*.sub.corp.test. A none") },
		map[string]string{"other": "5s"})
	svc := cliLabStart(t, w)
	const open = "alert open medium wildcard wildcard sub.corp.test. A"
	const runs = "checked other wildcard corp.test. sub.corp.test. A "

	dngChecked(t, svc, "other", "wildcard corp.test. sub.corp.test. A")
	dngNoAlerts(t, svc)

	set := time.Now()
	expCtl(t, "set", "both", "sub.corp.test.", "300", "DNAME", "other.test.")
	asked := cliAskDig(t, w.n+"11:53", "probe-label.sub.corp.test.", "A").sections["ANSWER"]
	if len(cliPick(asked, "", "DNAME")) != 1 || len(cliPick(asked, "probe-label.sub.corp.test.", "CNAME")) != 1 {
		t.Fatalf("a name under sub.corp.test. gets %q, want a DNAME and a CNAME", asked)
	}
	cname := strings.SplitN(cliPick(asked, "probe-label.sub.corp.test.", "CNAME")[0], "\t", 5)
	opened := svc.wait(t, "the wildcard alert", set.Add(dngWindow(interval)), regIs(open))
	dngSettled(t, svc, opened, runs, interval)
	text, changed := dngLatest(t, svc, w, open)
	regExpect(t, text, dngHead(":large_orange_circle: *MEDIUM*", changed, " · a wildcard answers for names under `sub.corp.test.` that do not exist"), []string{
		"expected   none",
		"",
		"now        CNAME *.other.test.",
		"seen at    ns1.corp.test. (" + w.n + "11)   TTL " + cname[1],
		"           ns2.corp.test. (" + w.n + "12)   TTL " + cname[1],
	}, regOpenTimes, ":point_right: If you did not add a wildcard under `sub.corp.test.`, remove it at your DNS provider and find out who added it.")

	dngSteady(t, svc, runs, interval)
	dngExpectAlerts(t, svc, open)
	for _, s := range dngRequests(t, w, len(regAlertLines(svc))) {
		if m := dngLabel.FindString(s); m != "" {
			t.Errorf("a random label %q in the Slack text:\n%s", m, s)
		}
	}
}
