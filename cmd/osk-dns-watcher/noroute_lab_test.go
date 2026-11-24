//go:build lab

package main

import (
	"os"
	"slices"
	"strings"
	"testing"
	"time"
)

// rtlNoRoute gives ns2.corp.test. an IPv6 address, at the parent and in its
// zone, inside a prefix that the checks may ask. The runner of the lab has
// no IPv6, so it has no route to that address: the case of osk-dns-watcher
// on Docker's default network. It gives the address and the prefix.
func rtlNoRoute(t *testing.T, n string) (addr, prefix string) {
	t.Helper()
	lab := os.Getenv("LAB_ID")
	addr = "fd53:0:0:" + lab + "::12"
	expCtl(t, "glue", "ns2.corp.test.", n+"12", addr)
	expCtl(t, "set", "both", "ns2.corp.test.", "300", "AAAA", addr)
	return addr, "fd53:0:0:" + lab + "::/64"
}

// rtlChanged is the Slack message of www.corp.test. A after ns2 changed it.
func rtlChanged(n string) []string {
	return []string{
		":red_circle: *HIGH* · `www.corp.test. A` changed",
		"",
		"```",
		"expected   " + n + "81",
		"",
		"now        " + n + "99",
		"seen at    ns2.corp.test. (" + n + "12)   TTL 120",
		"```",
		"",
		slkClockOpen,
		"",
		":point_right: If you did not make this change, check your DNS provider account now.",
	}
}

const rtlNotAsked = "not asked: 1 IPv6 address of the servers, to which this machine has no route"

// This machine has no route to the IPv6 address of ns2. The snapshot leaves
// it out and says so. check --expect names it in one line and exits 0, and
// an alert shows the last clean run, because the other servers answered.
func TestNoRouteToAServerKeepsTheLastCleanCheck(t *testing.T) {
	n, state := slkLab(t)
	_, prefix := rtlNoRoute(t, n)

	code, out, errOut := expOsk(n, "snapshot", "--extra-range", prefix, "corp.test.", "www.corp.test.", "A")
	if code != 0 || errOut != "" || !slices.Contains(strings.Split(out, "\n"), "# "+rtlNotAsked) ||
		!strings.Contains(out, "\nwww.corp.test. A "+n+"81\n") {
		t.Errorf("osk-dns-watcher snapshot: exit code %d, errors %q, output:\n%s\nwant 0, none, the line of www and %q",
			code, errOut, out, "# "+rtlNotAsked)
	}

	file := slkLabFile(t, "www.corp.test. A "+n+"81")
	r1 := slkLabCheck(t, n, file, state, "--extra-range", prefix)
	slkExpect(t, "the first run", r1, 0, rtlNotAsked, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")

	expCtl(t, "set", "ns2", "www.corp.test.", "120", "A", n+"99")
	r2 := slkLabCheck(t, n, file, state, "--extra-range", prefix)
	slkExpect(t, "the run after the change", r2, 1,
		"finding high record-set records www.corp.test. A",
		"  expected "+n+"81",
		"  seen "+n+"12:53 ns2.corp.test. "+n+"99",
		rtlNotAsked,
		"checked corp.test. 4 sets: 1 findings, 0 unknown answers",
		"alert open high record-set records www.corp.test. A",
		"delivery slack sent open high record-set records www.corp.test. A")
	sent := slkHookCount(t, "after the change", 1)
	slkSameText(t, slkSlackText(t, sent[0]), rtlChanged(n), r2, r1)
}

// The service says once in its log that this machine has no route to the
// address, however many runs meet it, and its alert shows the last clean run.
func TestRunWithNoRouteToAServerKeepsTheLastCleanCheck(t *testing.T) {
	n, state := runLab(t)
	addr, prefix := rtlNoRoute(t, n)
	file := slkLabFile(t, "www.corp.test. A "+n+"81")
	c := runLabCfg(n, file, state, runIntervals("1h", "1h", "5s", "1h"), "www.corp.test.")
	c.Network.ExtraRanges = append(c.Network.ExtraRanges, prefix)
	begin := time.Now()
	svc := runStart(t, runConfig(t, c)...)
	www := runRecords("www.corp.test.", "A")
	first, i := svc.wait(t, "the first run of "+www, 0, begin.Add(10*time.Second), runRunOf(www))
	if ch, _, _ := runParse(first.text); ch.result != "ok" {
		t.Errorf("the first run gave %q, want ok", first.text)
	}
	svc.wait(t, "the second run of "+www, i+1, begin.Add(20*time.Second), runRunOf(www))

	set := time.Now()
	expCtl(t, "set", "ns2", "www.corp.test.", "120", "A", n+"99")
	alert, j := svc.wait(t, "the record-set alert", i, set.Add(15*time.Second), runIs("alert open high record-set records www.corp.test. A"))
	svc.wait(t, "the Slack message", j, set.Add(17*time.Second), runIs("delivery slack sent open high record-set records www.corp.test. A"))
	lines := svc.stop(t)

	hooks := runHookCount(t, "after the change", 1)
	slkSameText(t, hooks[0].text, rtlChanged(n), slkRun{start: set, end: alert.at}, slkRun{start: begin, end: set})
	want := "warning this machine has no route to some addresses of the nameservers, such as " + addr +
		". osk-dns-watcher cannot ask them. A check counts as OK when the other servers answer."
	var warnings []string
	for _, l := range lines {
		if strings.Contains(l.text, "no route") || strings.HasPrefix(l.text, "route back") {
			warnings = append(warnings, l.level+" "+l.text)
		}
	}
	if !slices.Equal(warnings, []string{"warning " + want}) {
		t.Errorf("the lines about routes:\n%s\nwant only:\nwarning %s", strings.Join(warnings, "\n"), want)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}
