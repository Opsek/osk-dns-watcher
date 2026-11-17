//go:build lab

package main

import (
	"fmt"
	"regexp"
	"strings"
	"testing"
	"time"
)

// caaChecked waits for the first finished run of the CAA check of a name, in
// whatever tier the plan puts it.
func caaChecked(t *testing.T, svc *cliLabService, name string) {
	t.Helper()
	re := regexp.MustCompile(`^checked (fast|other) records corp\.test\. ` + regexp.QuoteMeta(name) + ` CAA .* ok$`)
	svc.wait(t, "a finished CAA check of "+name, time.Now().Add(60*time.Second), func(l cliLabLog) bool {
		return l.Event == "checked" && re.MatchString(l.Text)
	})
}

// caaRan reports whether l is a finished run of the CAA check of a name.
func caaRan(l cliLabLog, name string) bool {
	return l.Event == "checked" && strings.Contains(l.Text, " records corp.test. "+name+" CAA ") && strings.HasSuffix(l.Text, " ok")
}

// caaRuns counts the finished runs of the CAA check of a name that were
// logged after at.
func caaRuns(svc *cliLabService, name string, at time.Time) int {
	n := 0
	for _, l := range svc.all() {
		if caaRan(l, name) && l.at.After(at) {
			n++
		}
	}
	return n
}

// caaWait waits until the log holds the nth line with this text, and gives
// it. The alerts of one check repeat their lines, so the first line with the
// text is not always the one that is wanted.
func caaWait(t *testing.T, svc *cliLabService, what string, deadline time.Time, text string, n int) cliLabLog {
	t.Helper()
	var got cliLabLog
	cliLabUntil(t, what, deadline, 50*time.Millisecond, func() bool {
		count := 0
		for _, l := range svc.all() {
			if l.Text == text {
				if count++; count == n {
					got = l
					return true
				}
			}
		}
		return false
	})
	return got
}

// caaSettled waits for a run of the CAA check of name that began after half
// an interval past the alert line, so that both servers are in view.
func caaSettled(t *testing.T, svc *cliLabService, opened cliLabLog, name string, interval time.Duration) {
	t.Helper()
	after := opened.at.Add(interval / 2)
	cliLabUntil(t, "a run of the CAA check of "+name+" after the alert", after.Add(dngWindow(interval)), 100*time.Millisecond,
		func() bool { return caaRuns(svc, name, after) > 0 })
}

// caaResolveText gives the Slack text of the last resolve line of an alert.
func caaResolveText(t *testing.T, svc *cliLabService, w *cliLabWorld, resolve string) string {
	t.Helper()
	lines := regAlertLines(svc)
	texts := dngRequests(t, w, len(lines))
	for i := len(lines) - 1; i >= 0; i-- {
		if lines[i] == resolve {
			return texts[i]
		}
	}
	t.Fatalf("no line %q in:\n%s", resolve, strings.Join(lines, "\n"))
	return ""
}

// caaView is the view of an open alert: the expected lines, the lines of the
// set that the servers give, and the two servers with the TTL of each.
func caaView(w *cliLabWorld, expected, now []string, ttl func(addr string) string) []string {
	view := append(append(expected, ""), now...)
	return append(view,
		"seen at    ns1.corp.test. ("+w.n+"11)   TTL "+ttl(w.n+"11:53"),
		"           ns2.corp.test. ("+w.n+"12)   TTL "+ttl(w.n+"12:53"))
}

// A weakened CAA policy at the apex and at a name below it, a policy that is
// gone, and a stricter one: each is its own alert, and none moves the serial
// without an alert that explains it.
func TestCAAWeakenedAlert(t *testing.T) {
	const interval = 5 * time.Second
	const strict = `0 issue "ca.test"`
	w := cliLabSetup(t, false, func(n string) string {
		return cliLabFile(n, `corp.test. CAA `+strict)
	}, map[string]string{"serial": "5s", "fast": "5s", "other": "5s"})
	svc := cliLabStart(t, w)

	ttl := func(name string) func(addr string) string {
		return func(addr string) string { return dngTTL(t, addr, name, "CAA") }
	}
	negative := func(name string) func(addr string) string {
		return func(addr string) string { return dngNegativeTTL(t, addr, name, "CAA") }
	}
	// expectOpen checks the Slack text of the last open or update line of the
	// caa alert of name, once both servers are in view.
	expectOpen := func(opened cliLabLog, name string, view []string) {
		t.Helper()
		caaSettled(t, svc, opened, name, interval)
		text, changed := dngLatest(t, svc, w, "alert open high caa records "+name+" CAA")
		regExpect(t, text, dngHead(":red_circle: *HIGH*", changed, " · the CAA policy for `"+name+"` is weaker than expected"), view, regOpenTimes,
			fmt.Sprintf(":point_right: If you did not change the CAA records, restore them at your DNS provider now, then look for certificates for `%s` that you did not ask for.", name))
	}
	expectResolve := func(name string) {
		t.Helper()
		text := caaResolveText(t, svc, w, "alert resolve high caa records "+name+" CAA")
		regExpect(t, text, ":white_check_mark: *RESOLVED* · the CAA policy for `"+name+"` is as strict as expected again",
			[]string{"now        as strict as expected"}, regResolveTimes, regResolveAction)
	}
	const (
		openApex    = "alert open high caa records corp.test. CAA"
		resolveApex = "alert resolve high caa records corp.test. CAA"
		openWWW     = "alert open high caa records www.corp.test. CAA"
		resolveWWW  = "alert resolve high caa records www.corp.test. CAA"
		openRecord  = "alert open medium record-set records corp.test. CAA"
		resolveRec  = "alert resolve medium record-set records corp.test. CAA"
	)

	// The checks of the apex line and of the probe of www.corp.test. have run
	// on the unchanged zone: nothing is open.
	caaChecked(t, svc, "corp.test.")
	caaChecked(t, svc, "www.corp.test.")
	dngNoAlerts(t, svc)

	// Another authority is allowed at the apex.
	set := time.Now()
	expCtl(t, "set", "both", "corp.test.", "300", "CAA", strict, `0 issue "evil.test"`)
	opened := caaWait(t, svc, "the caa alert", set.Add(dngWindow(interval)), openApex, 1)
	dngNone(t, svc, "record-set")
	expectOpen(opened, "corp.test.", caaView(w, []string{"expected   " + strict},
		[]string{"now        " + strict, `           0 issue "evil.test"`}, ttl("corp.test.")))

	set = time.Now()
	expCtl(t, "set", "both", "corp.test.", "300", "CAA", strict)
	caaWait(t, svc, "the resolve of the caa alert", set.Add(dngWindow(interval)), resolveApex, 1)
	expectResolve("corp.test.")

	// The policy is gone.
	set = time.Now()
	expCtl(t, "del", "both", "corp.test.", "CAA")
	opened = caaWait(t, svc, "the caa alert of the removed policy", set.Add(dngWindow(interval)), openApex, 2)
	dngNone(t, svc, "record-set")
	expectOpen(opened, "corp.test.", caaView(w, []string{"expected   " + strict}, []string{"now        none"}, negative("corp.test.")))

	set = time.Now()
	expCtl(t, "set", "both", "corp.test.", "300", "CAA", strict)
	caaWait(t, svc, "the second resolve of the caa alert", set.Add(dngWindow(interval)), resolveApex, 2)
	expectResolve("corp.test.")

	// A name below the apex has a set of its own that allows another
	// authority; the apex line governs it.
	set = time.Now()
	expCtl(t, "set", "both", "www.corp.test.", "300", "CAA", `0 issue "evil.test"`)
	opened = caaWait(t, svc, "the caa alert of www.corp.test.", set.Add(dngWindow(interval)), openWWW, 1)
	dngNone(t, svc, "record-set")
	expectOpen(opened, "www.corp.test.", caaView(w, []string{"expected   " + strict},
		[]string{`now        0 issue "evil.test"`}, ttl("www.corp.test.")))

	set = time.Now()
	expCtl(t, "del", "both", "www.corp.test.", "CAA")
	caaWait(t, svc, "the resolve of the caa alert of www.corp.test.", set.Add(dngWindow(interval)), resolveWWW, 1)
	expectResolve("www.corp.test.")

	// A stricter policy is an ordinary change of the set: no caa alert follows.
	caaLines := dngCount(svc, "caa")
	set = time.Now()
	expCtl(t, "set", "both", "corp.test.", "300", "CAA", `0 issue ";"`)
	opened = caaWait(t, svc, "the record-set alert", set.Add(dngWindow(interval)), openRecord, 1)
	caaSettled(t, svc, opened, "corp.test.", interval)
	text, changed := dngLatest(t, svc, w, openRecord)
	regExpect(t, text, dngHead(":large_orange_circle: *MEDIUM*", changed, " · `corp.test. CAA` changed"), caaView(w,
		[]string{"expected   " + strict}, []string{`now        0 issue ";"`}, ttl("corp.test.")),
		regOpenTimes, ":point_right: If you did not make this change, check your DNS provider account now.")
	settled := caaRuns(svc, "corp.test.", opened.at.Add(interval/2))
	cliLabUntil(t, "two more runs of the CAA check", time.Now().Add(3*dngWindow(interval)), 100*time.Millisecond,
		func() bool { return caaRuns(svc, "corp.test.", opened.at.Add(interval/2)) >= settled+2 })
	if got := dngCount(svc, "caa"); got != caaLines {
		t.Errorf("%d caa alert lines after a stricter policy, want the %d of before:\n%s", got, caaLines, strings.Join(regAlertLines(svc), "\n"))
	}

	set = time.Now()
	expCtl(t, "set", "both", "corp.test.", "300", "CAA", strict)
	caaWait(t, svc, "the resolve of the record-set alert", set.Add(dngWindow(interval)), resolveRec, 1)
	regExpect(t, caaResolveText(t, svc, w, resolveRec), ":white_check_mark: *RESOLVED* · `corp.test. CAA` is as expected again",
		[]string{"now        " + strict}, regResolveTimes, regResolveAction)

	// Each change moved the serial, and its own alert explained the move.
	dngExpectAlerts(t, svc, openApex, resolveApex, openApex, resolveApex, openWWW, resolveWWW, openRecord, resolveRec)
	for _, l := range svc.all() {
		if strings.Contains(l.Text, "zone-changed") {
			t.Errorf("a zone-changed line: %q", l.Text)
		}
	}
}
