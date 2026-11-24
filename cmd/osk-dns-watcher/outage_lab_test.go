//go:build lab

package main

import (
	"slices"
	"strings"
	"testing"
	"time"
)

// Every server of the lab refuses every query, from the root down, as when
// this machine has lost its DNS. Such a run holds no referral into a zone
// below that of the domain, so it gives no zone alert, also once the walk no
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

// The servers of corp.test. delegate a subzone that the file does not
// declare to a nameserver that never answers. No run gets a usable answer,
// but the referral shows the new cut, so the first run opens the zone alert
// and names the server of corp.test. that gave the referral.
func TestSubzoneThatDoesNotAnswerGivesZoneAlert(t *testing.T) {
	n, state := runLab(t)
	expCtl(t, "set", "both", "dead.corp.test.", "300", "A", n+"99")
	expCtl(t, "set", "both", "sub.corp.test.", "300", "NS", "dead.corp.test.")
	file := slkLabFile(t, "www.sub.corp.test. A "+n+"81")
	begin := time.Now()
	svc := runStart(t, runLabArgs(t, n, file, state, runIntervals("1h", "1h", "1h", "5s"))...)
	www := runRecords("www.sub.corp.test.", "A")
	first, i := svc.wait(t, "the first run of "+www, 0, begin.Add(10*time.Second), runRunOf(www))
	if c, _, _ := runParse(first.text); c.result == "ok" {
		t.Errorf("the first run gave %q, want a failure", first.text)
	}
	const label = "high zone records www.sub.corp.test. A"
	opened, j := svc.wait(t, "the zone alert", i, first.at.Add(time.Second), runIs("alert open "+label))
	svc.wait(t, "its Slack message", j, opened.at.Add(3*time.Second), runIs("delivery slack sent open "+label))
	svc.stop(t)
	text := runHookCount(t, "after the first run", 1)[0].text
	referred := strings.Contains(text, "ns1.corp.test. ("+n+"11)") || strings.Contains(text, "ns2.corp.test. ("+n+"12)")
	if !strings.Contains(text, "is answered from an unexpected zone") || !referred {
		t.Errorf("the message:\n%s\nwant the zone headline and a server of corp.test. under seen at", text)
	}
	runNoSecret(t, state, svc.out.String(), svc.errOut.String())
}
