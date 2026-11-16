//go:build lab

package store

import (
	"context"
	"maps"
	"net/netip"
	"os/exec"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// hisEpisode stores an alert of the finding f as the service makes it: an
// open at opened with a row to slack, and, unless resolved is zero, a
// resolve then with a row to slack. It gives the alert's id.
func hisEpisode(t *testing.T, s *Store, f decide.Finding, opened, resolved time.Time) int64 {
	t.Helper()
	write := func(in alert.Input, kind alert.EventKind) Write {
		t.Helper()
		out := alert.Transition(in)
		if len(out.Events) != 1 || out.Events[0].Kind != kind {
			t.Fatalf("Transition gives %d events, want one %v", len(out.Events), kind)
		}
		e := out.Events[0]
		return Write{Event: e, Deliveries: []Delivery{{Channel: "slack", Label: e.Label(), Body: []byte("{}")}}}
	}
	stoApply(t, s, f.Check, false, opened, write(alert.Input{
		Changes: []decide.Change{{Op: decide.OpOpen, Finding: f, At: opened}}, Now: opened}, alert.EventOpen))
	a := stoNth(t, s, f.Check, 1, 0)
	if !resolved.IsZero() {
		stoApply(t, s, f.Check, false, resolved, write(alert.Input{Open: []alert.Alert{a},
			Changes: []decide.Change{{Op: decide.OpResolve, Finding: a.Finding(), At: resolved}}, Now: resolved}, alert.EventResolve))
	}
	return a.ID
}

// History older than its limit goes with its events and rows; an open
// alert, history with a pending row, and recent history stay.
func TestHistoryDeletedByAge(t *testing.T) {
	stoLabctl(t, "hooks", "clear")
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	lab := stoLab(t)
	stoLabctl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")

	o, err := observe.New(observe.Config{
		RootServers: []netip.AddrPort{netip.MustParseAddrPort(lab + "2:53")},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix(lab + "0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := obs.DelegationKey(stoName(t, "corp.test."))
	ob, err := o.Run(context.Background(), observe.Check{Key: key, Interval: time.Minute})
	if err != nil {
		t.Fatalf("Run(%v): %v", key, err)
	}
	file, err := expect.Parse([]byte("domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\n"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	changes := decide.Decide(decide.Input{Expect: file, Observation: ob, Now: now})
	if len(changes) != 1 || changes[0].Op != decide.OpOpen {
		t.Fatalf("decide gives %d changes, want one open", len(changes))
	}
	f := changes[0].Finding

	s := stoOpen(t, stoDir(t))
	day := 24 * time.Hour
	a := hisEpisode(t, s, f, now.Add(-10*day), now.Add(-9*day))
	b := hisEpisode(t, s, f, now.Add(-10*day), now.Add(-9*day))
	d := hisEpisode(t, s, f, now.Add(-2*time.Hour), now.Add(-time.Hour))
	c := hisEpisode(t, s, f, now.Add(-10*day), time.Time{})
	// Every row is sent, but the resolve row of B.
	for _, id := range slices.Concat(ntcAlertRows(t, s, a), ntcAlertRows(t, s, b)[:1], ntcAlertRows(t, s, c), ntcAlertRows(t, s, d)) {
		ntcRecord(t, s, id, ntcSent(now.Add(-time.Hour)))
	}
	n1 := ntcNotice(t, s, now.Add(-9*day), "slack")
	ntcRecord(t, s, ntcNoticeRows(t, s, n1)[0], ntcSent(now.Add(-9*day)))
	n2 := ntcNotice(t, s, now.Add(-9*day), "slack")
	// Old rows of the tables that history never deletes from.
	stoApply(t, s, obs.DSKey(stoName(t, "corp.test.")), true, now.Add(-10*day))
	if err := s.Beat(now.Add(-8*day), nil); err != nil {
		t.Fatal(err)
	}
	ntcReload(t, s, "corp.test.", file.String(), nil, nil)

	before := ntcReadHistory(t, s.db)
	alerts, notices, err := s.Prune(now.Add(-7*day), 200)
	if err != nil || alerts != 1 || notices != 1 {
		t.Errorf("Prune(now - 7 days, 200) = %d, %d, %v; want 1 alert and 1 notice", alerts, notices, err)
	}
	after := ntcReadHistory(t, s.db)
	if got, want := slices.Sorted(maps.Keys(after.open)), []int64{b, d, c}; !slices.Equal(got, want) {
		t.Errorf("alerts %v stay, want B, D and C: %v", got, want)
	}
	if got := slices.Sorted(maps.Keys(after.at)); !slices.Equal(got, []int64{n2}) {
		t.Errorf("notices %v stay, want N2: %d", got, n2)
	}
	if got, want := ntcRender(after, nil), ntcWithout(before, []int64{a}, []int64{n1}); got != want {
		t.Errorf("after Prune:\n%s\nwant:\n%s", got, want)
	}
	if got, want := ntcCounts(t, s.db), "alert 3, event 5, delivery 6, check_state 1, notice 1, loaded 1, beat 1"; got != want {
		t.Errorf("after Prune: %s, want %s", got, want)
	}
}
