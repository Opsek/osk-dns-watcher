//go:build lab

package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Every server of the lab refuses every query, from the root down, as when
// this machine has lost its DNS. A run with no usable answer did not see
// which zone answers, so it gives no zone alert, also once the walk no
// longer starts from a cut learned before and ends at the root. The check
// is reported as failing after five fast intervals, as any check with no
// usable answer is, and that report ends when the servers answer again.
func TestOutageGivesNoZoneAlert(t *testing.T) {
	n, state := runLab(t)
	file := slkLabFile(t, "corp.test. A "+n+"80", "www.corp.test. A "+n+"81")
	begin := time.Now()
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("5s", "1h", "5s", "1h"))...)
	apex := runRecords("corp.test.", "A")
	for _, k := range []string{runSerialKey, apex} {
		l, _ := svc.wait(t, "the first run of "+k, 0, begin.Add(10*time.Second), runRunOf(k))
		if c, _, _ := runParse(l.text); c.result != "ok" {
			t.Errorf("the first round gave %q, want ok", l.text)
		}
	}

	dropped := time.Now()
	expCtl(t, "drop-zone", "root", ".")
	expCtl(t, "drop-zone", "tld", "test.")
	expCtl(t, "drop-zone", "both", "corp.test.")
	const label = "medium check-failing records corp.test. A"
	opened, i := svc.wait(t, "the check-failing alert", 0, dropped.Add(25*time.Second+5*time.Second+3750*time.Millisecond+time.Second),
		runIs("alert open "+label))
	svc.wait(t, "its Slack message", i, opened.at.Add(3*time.Second), runIs("delivery slack sent open "+label))

	expCtl(t, "reset")
	svc.wait(t, "the resolve", i, time.Now().Add(5*time.Second+3750*time.Millisecond+time.Second), runIs("alert resolve "+label))
	lines := svc.stop(t)
	var alerts []string
	for _, l := range lines {
		if strings.HasPrefix(l.text, "alert ") {
			alerts = append(alerts, l.text)
		}
	}
	if want := []string{"alert open " + label, "alert resolve " + label}; !slices.Equal(alerts, want) {
		t.Errorf("the alerts were %q, want only %q", alerts, want)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}
