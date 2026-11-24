package main

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The invalid-file alert and the zone-changed alert share the key of the
// domain, but each shows a last OK time of its own: the file alert the last
// read that gave the file in force, the zone alert the last serial run that
// saw no move. A quiet serial run while the file alert is open still counts
// for the zone, and still brings the reminder of the file alert.
func TestRunGivesEachAlertOfTheDomainItsOwnLastOK(t *testing.T) {
	s := rteStore(t)
	var log bytes.Buffer
	m, d := rteMonitor(t, s, &log)
	m.policy = alert.Policy{Remind: time.Hour}
	at := func(after time.Duration) time.Time { return rteNow.Add(after) }
	must := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	valid := fileRead{done: true, data: []byte(rteFile(t).String())}
	bad := fileRead{done: true, data: []byte("domain corp.test.\ncorp.test NS ns1.corp.test.\n")}

	// Two reads that agree take the file; the third repeats it.
	for _, sec := range []time.Duration{5, 10, 15} {
		must(m.reread(d, valid, at(sec*time.Second)))
	}
	must(m.zoneChanges(d, nil, at(20*time.Second)))
	// A file that is not valid is taken once it stayed so for readSettle.
	written := at(25 * time.Second)
	for _, when := range []time.Time{written, written.Add(readSettle), written.Add(readSettle + 5*time.Second)} {
		must(m.reread(d, bad, when))
	}
	quiet := written.Add(readSettle + 10*time.Second)
	must(m.zoneChanges(d, nil, quiet))
	moved := quiet.Add(10 * time.Second)
	move := decide.Move{Server: obs.Server{Addr: netip.MustParseAddrPort("192.0.2.11:53")}, From: 1, To: 2, Until: quiet, Since: moved}
	must(m.zoneChanges(d, []decide.Move{move}, moved))

	open, err := s.OpenAlerts(d.scope())
	must(err)
	want := map[decide.Rule]time.Time{decide.RuleInvalidFile: at(15 * time.Second), decide.RuleZoneChanged: quiet}
	if len(open) != len(want) {
		t.Fatalf("%d open alerts of the domain, want %d: %+v", len(open), len(want), open)
	}
	for _, a := range open {
		if !a.LastClean.Equal(want[a.Rule]) {
			t.Errorf("the %s alert shows last OK %s, want %s", a.Rule, a.LastClean.UTC(), want[a.Rule].UTC())
		}
	}

	later := at(25*time.Second + readSettle + time.Hour)
	must(m.zoneChanges(d, nil, later))
	if got, err := s.LastClean(d.scope()); err != nil || !got.Equal(later) {
		t.Errorf("the last OK time of the zone is %s, %v; want %s", got.UTC(), err, later.UTC())
	}

	// The file is put right, then broken again: the new alert shows the last
	// read of the file put right.
	fixed := later.Add(5 * time.Second)
	for _, when := range []time.Time{fixed, fixed.Add(5 * time.Second), fixed.Add(10 * time.Second)} {
		must(m.reread(d, valid, when))
	}
	broken := fixed.Add(15 * time.Second)
	for _, when := range []time.Time{broken, broken.Add(readSettle)} {
		must(m.reread(d, bad, when))
	}
	open, err = s.OpenAlerts(d.scope())
	if err != nil || len(open) != 1 || open[0].Rule != decide.RuleInvalidFile || !open[0].LastClean.Equal(fixed.Add(10*time.Second)) {
		t.Errorf("open alerts %+v, %v; want the invalid-file alert with last OK %s", open, err, fixed.Add(10*time.Second).UTC())
	}

	m.out.close(time.Second)
	if text := log.String(); !strings.Contains(text, "alert reminder medium invalid-file corp.test.") {
		t.Errorf("a quiet serial run brought no reminder of the invalid-file alert:\n%s", text)
	}
}

// The service starts only with a valid file, so a file broken before any
// read shows the start as its last OK time.
func TestRunInvalidFileAtTheFirstReadShowsTheStart(t *testing.T) {
	s := rteStore(t)
	m, d := rteMonitor(t, s, &bytes.Buffer{})
	bad := fileRead{done: true, data: []byte("domain corp.test.\ncorp.test NS ns1.corp.test.\n")}
	for _, when := range []time.Time{rteNow.Add(5 * time.Second), rteNow.Add(5*time.Second + readSettle)} {
		if err := m.reread(d, bad, when); err != nil {
			t.Fatal(err)
		}
	}
	m.out.close(time.Second)
	open, err := s.OpenAlerts(d.scope())
	if err != nil || len(open) != 1 || !open[0].LastClean.Equal(rteNow) {
		t.Errorf("open alerts %+v, %v; want the invalid-file alert with last OK %s", open, err, rteNow.UTC())
	}
}
