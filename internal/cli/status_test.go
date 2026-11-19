package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// cliNow is the time that status sees in these tests. It has a part below
// the second, which the printed times leave out.
var cliNow = time.Date(2026, 11, 15, 10, 0, 0, 500_000_000, time.UTC)

func cliSetClock(t *testing.T, now time.Time) {
	t.Helper()
	old := clock
	clock = func() time.Time { return now }
	t.Cleanup(func() { clock = old })
}

func cliText(at time.Time) string { return at.UTC().Format("2006-01-02 15:04:05 UTC") }

func cliJSONTime(at time.Time) string { return at.UTC().Format("2006-01-02T15:04:05Z") }

type cliChannelJSON struct {
	Name    string `json:"name"`
	Pending int    `json:"pending"`
	Failing bool   `json:"failing"`
	Reason  string `json:"reason"`
}

type cliOpenJSON struct {
	ID       int64    `json:"id"`
	Severity string   `json:"severity"`
	Rule     string   `json:"rule"`
	Check    cliCheck `json:"check"`
	Opened   string   `json:"opened"`
}

type cliStatusJSON struct {
	Type     string           `json:"type"`
	Healthy  bool             `json:"healthy"`
	Problems []string         `json:"problems"`
	Beat     string           `json:"beat"`
	Late     []string         `json:"late"`
	Channels []cliChannelJSON `json:"channels"`
	Open     []cliOpenJSON    `json:"open"`
	Warnings []string         `json:"warnings"`
}

// cliStatusIs runs status as text and as JSON. Both must give code, the
// JSON must say healthy exactly when the code is 0, and every list that is
// empty must print as [].
func cliStatusIs(t *testing.T, w *cliWorld, code int, text []string, js cliStatusJSON) {
	t.Helper()
	got, out, errOut := cliRun(5*time.Second, "status", "--config", w.config)
	if got != code || errOut != "" {
		t.Errorf("osk-dns-watcher status: exit code %d, errors %q; want %d and none", got, errOut, code)
	}
	cliSame(t, "osk-dns-watcher status", out, text...)

	js.Type = "status"
	for _, l := range []*[]string{&js.Problems, &js.Late, &js.Warnings} {
		if *l == nil {
			*l = []string{}
		}
	}
	if js.Open == nil {
		js.Open = []cliOpenJSON{}
	}
	if js.Healthy != (code == 0) {
		t.Fatalf("the test expects healthy %t with exit code %d", js.Healthy, code)
	}
	got, out, errOut = cliRun(5*time.Second, "status", "--config", w.config, "--json")
	if got != code || errOut != "" {
		t.Errorf("osk-dns-watcher status --json: exit code %d, errors %q; want %d and none", got, errOut, code)
	}
	cliSame(t, "osk-dns-watcher status --json", out, cliMarshal(t, js))
}

func cliRecordsCheck(name, rtype string) cliCheck {
	return cliCheck{Kind: "records", Domain: "corp.test.", Name: name, RType: rtype}
}

func cliHealthy() []cliChannelJSON {
	return []cliChannelJSON{{Name: "slack"}, {Name: "siem"}}
}

func TestStatusOfAHealthyServicePrintsBeatChannelsOpenAlertsAndWarnings(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, true)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-time.Hour), "10.53.0.99")
	file := cliAlert(decide.RuleInvalidFile, decide.SeverityMedium, cliScopeKey("corp.test."), "", cliNow.Add(-2*time.Hour))
	mail := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "mail.corp.test.", dnswire.TypeA),
		"10.53.0.82", cliNow.Add(-3*time.Hour), "10.53.0.98")
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-5*time.Second), nil); err != nil {
			t.Fatal(err)
		}
		// The row of siem waits 30 s, half the time after which a row
		// counts as stuck.
		cliApply(t, s, cliNow.Add(-30*time.Second), cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "slack", "siem"))
		cliRecord(t, s, cliRows(t, s, "slack", cliNow)[0], store.Done{State: store.RowSent, Attempts: 1, At: cliNow.Add(-29 * time.Second)})
		cliOpen(t, s, cliNow, file)
		m := cliOpen(t, s, cliNow, mail)[0]
		m.Open, m.Resolved = false, cliNow.Add(-2*time.Hour)
		cliApply(t, s, cliNow, cliEvent(alert.EventResolve, m, m.Severity, m.Resolved))
	})
	cliStatusIs(t, w, 0, append([]string{
		"healthy",
		"beat " + cliText(cliNow.Add(-5*time.Second)),
		"channel slack ok, 0 pending",
		"channel siem ok, 1 pending",
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
		"open 2 medium invalid-file corp.test. since " + cliText(file.Opened),
	}, cliPrefixed("warning ", cliWarnings)...), cliStatusJSON{
		Healthy:  true,
		Beat:     cliJSONTime(cliNow.Add(-5 * time.Second)),
		Channels: []cliChannelJSON{{Name: "slack"}, {Name: "siem", Pending: 1}},
		Open: []cliOpenJSON{
			{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
			{ID: 2, Severity: "medium", Rule: "invalid-file", Check: cliCheck{Domain: "corp.test.", Name: "corp.test."}, Opened: cliJSONTime(file.Opened)},
		},
		Warnings: cliWarnings,
	})
}

func TestStatusWithoutABeatIsUnhealthy(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	cliStatusIs(t, w, 1, []string{
		"unhealthy: no beat from osk-dns-watcher run yet",
		"beat none",
		"channel slack ok, 0 pending",
		"channel siem ok, 0 pending",
	}, cliStatusJSON{Problems: []string{"no beat from osk-dns-watcher run yet"}, Channels: cliHealthy()})
}

// A beat of exactly 30 s ago still counts; one nanosecond more does not.
func TestStatusTakesABeatOfAtMost30Seconds(t *testing.T) {
	cliSetClock(t, cliNow)
	for _, c := range []struct {
		age  time.Duration
		code int
	}{{30 * time.Second, 0}, {30*time.Second + time.Nanosecond, 1}} {
		w := cliNewWorld(t, false)
		beat := cliNow.Add(-c.age)
		cliStore(t, w.state, func(s *store.Store) {
			if err := s.Beat(beat, nil); err != nil {
				t.Fatal(err)
			}
		})
		text := []string{"healthy", "beat " + cliText(beat), "channel slack ok, 0 pending", "channel siem ok, 0 pending"}
		js := cliStatusJSON{Healthy: true, Beat: cliJSONTime(beat), Channels: cliHealthy()}
		if c.code == 1 {
			problem := "no beat from osk-dns-watcher run since " + cliText(beat)
			text[0] = "unhealthy: " + problem
			js.Healthy, js.Problems = false, []string{problem}
		}
		cliStatusIs(t, w, c.code, text, js)
	}
}

func TestStatusNamesEachLateCheck(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	late := []string{"records corp.test. mail.corp.test. A", "serial corp.test. corp.test. SOA"}
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-time.Second), late); err != nil {
			t.Fatal(err)
		}
	})
	cliStatusIs(t, w, 1, []string{
		"unhealthy: 2 checks late",
		"beat " + cliText(cliNow.Add(-time.Second)),
		"late " + late[0],
		"late " + late[1],
		"channel slack ok, 0 pending",
		"channel siem ok, 0 pending",
	}, cliStatusJSON{Problems: []string{"2 checks late"}, Beat: cliJSONTime(cliNow.Add(-time.Second)), Late: late, Channels: cliHealthy()})
}

// A channel fails with a pending row that was tried: the reason is that of
// the tried row with the greatest id. It also fails when its last finished
// row was given up.
func TestStatusNamesEachFailingChannelWithItsLastReason(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-10*time.Minute), "10.53.0.99")
	mail := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "mail.corp.test.", dnswire.TypeA),
		"10.53.0.82", cliNow.Add(-9*time.Minute), "10.53.0.98")
	const connect = `no answer "network: cannot connect"`
	const refused = `status 404 "no_service"`
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		cliApply(t, s, www.Opened, cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "slack", "siem"))
		cliApply(t, s, mail.Opened, cliEvent(alert.EventOpen, mail, mail.Severity, mail.Opened, "slack"))
		slack, siem := cliRows(t, s, "slack", cliNow), cliRows(t, s, "siem", cliNow)
		if len(slack) != 2 || len(siem) != 1 {
			t.Fatalf("rows: slack %v, siem %v; want 2 and 1", slack, siem)
		}
		cliRecord(t, s, slack[0], store.Done{State: store.RowPending, Attempts: 1, NextAt: cliNow.Add(10 * time.Second),
			Reason: "status 503", At: cliNow.Add(-5 * time.Minute)})
		cliRecord(t, s, slack[1], store.Done{State: store.RowPending, Attempts: 2, NextAt: cliNow.Add(20 * time.Second),
			Reason: connect, At: cliNow.Add(-6 * time.Minute)})
		cliRecord(t, s, siem[0], store.Done{State: store.RowGivenUp, Attempts: 1, Reason: refused, At: cliNow.Add(-3 * time.Minute)})
	})
	beat := cliNow.Add(-time.Second)
	cliStatusIs(t, w, 1, []string{
		"unhealthy: channel slack fails; channel siem fails",
		"beat " + cliText(beat),
		"channel slack fails, 2 pending, last reason " + connect,
		"channel siem fails, 0 pending, last reason " + refused,
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
		"open 2 high record-set records mail.corp.test. A since " + cliText(mail.Opened),
	}, cliStatusJSON{
		Problems: []string{"channel slack fails", "channel siem fails"},
		Beat:     cliJSONTime(beat),
		Channels: []cliChannelJSON{{"slack", 2, true, connect}, {"siem", 0, true, refused}},
		Open: []cliOpenJSON{
			{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
			{ID: 2, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("mail.corp.test.", "A"), Opened: cliJSONTime(mail.Opened)},
		},
	})
}

// The last finished row is the one finished last, not the one with the
// greatest id: a row sent after an older row was given up heals the channel.
func TestStatusJudgesAChannelByItsLastFinishedRow(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-10*time.Minute), "10.53.0.99")
	mail := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "mail.corp.test.", dnswire.TypeA),
		"10.53.0.82", cliNow.Add(-9*time.Minute), "10.53.0.98")
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		cliApply(t, s, www.Opened, cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "slack", "siem"))
		cliApply(t, s, mail.Opened, cliEvent(alert.EventOpen, mail, mail.Severity, mail.Opened, "slack", "siem"))
		slack, siem := cliRows(t, s, "slack", cliNow), cliRows(t, s, "siem", cliNow)
		if len(slack) != 2 || len(siem) != 2 {
			t.Fatalf("rows: slack %v, siem %v; want 2 each", slack, siem)
		}
		cliRecord(t, s, slack[0], store.Done{State: store.RowSent, Attempts: 1, At: cliNow.Add(-2 * time.Minute)})
		cliRecord(t, s, slack[1], store.Done{State: store.RowGivenUp, Attempts: 1, Reason: "status 410", At: cliNow.Add(-time.Minute)})
		cliRecord(t, s, siem[0], store.Done{State: store.RowSent, Attempts: 1, At: cliNow.Add(-time.Minute)})
		cliRecord(t, s, siem[1], store.Done{State: store.RowGivenUp, Attempts: 1, Reason: "status 410", At: cliNow.Add(-2 * time.Minute)})
	})
	beat := cliNow.Add(-time.Second)
	cliStatusIs(t, w, 1, []string{
		"unhealthy: channel slack fails",
		"beat " + cliText(beat),
		"channel slack fails, 0 pending, last reason status 410",
		"channel siem ok, 0 pending",
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
		"open 2 high record-set records mail.corp.test. A since " + cliText(mail.Opened),
	}, cliStatusJSON{
		Problems: []string{"channel slack fails"},
		Beat:     cliJSONTime(beat),
		Channels: []cliChannelJSON{{"slack", 0, true, "status 410"}, {Name: "siem"}},
		Open: []cliOpenJSON{
			{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
			{ID: 2, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("mail.corp.test.", "A"), Opened: cliJSONTime(mail.Opened)},
		},
	})
}

// A row that was never tried and is due for more than 60 s shows that the
// loop of its channel is stuck; at exactly 60 s it is not yet.
func TestStatusCountsARowDueForMoreThan60SecondsAsAFailure(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-10*time.Minute), "10.53.0.99")
	mail := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "mail.corp.test.", dnswire.TypeA),
		"10.53.0.82", cliNow.Add(-9*time.Minute), "10.53.0.98")
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		cliApply(t, s, cliNow.Add(-time.Minute-time.Nanosecond), cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "slack"))
		cliApply(t, s, cliNow.Add(-time.Minute), cliEvent(alert.EventOpen, mail, mail.Severity, mail.Opened, "siem"))
	})
	beat := cliNow.Add(-time.Second)
	cliStatusIs(t, w, 1, []string{
		"unhealthy: channel slack fails",
		"beat " + cliText(beat),
		"channel slack fails, 1 pending, last reason -",
		"channel siem ok, 1 pending",
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
		"open 2 high record-set records mail.corp.test. A since " + cliText(mail.Opened),
	}, cliStatusJSON{
		Problems: []string{"channel slack fails"},
		Beat:     cliJSONTime(beat),
		Channels: []cliChannelJSON{{"slack", 1, true, ""}, {"siem", 1, false, ""}},
		Open: []cliOpenJSON{
			{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
			{ID: 2, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("mail.corp.test.", "A"), Opened: cliJSONTime(mail.Opened)},
		},
	})
}

func TestStatusIgnoresTheRowsOfAChannelThatIsNotInTheConfig(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-10*time.Minute), "10.53.0.99")
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(cliNow.Add(-time.Second), nil); err != nil {
			t.Fatal(err)
		}
		cliApply(t, s, www.Opened, cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "pager"))
		cliRecord(t, s, cliRows(t, s, "pager", cliNow)[0], store.Done{State: store.RowPending, Attempts: 3,
			NextAt: cliNow.Add(time.Minute), Reason: "status 500", At: cliNow.Add(-time.Minute)})
	})
	beat := cliNow.Add(-time.Second)
	cliStatusIs(t, w, 0, []string{
		"healthy",
		"beat " + cliText(beat),
		"channel slack ok, 0 pending",
		"channel siem ok, 0 pending",
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
	}, cliStatusJSON{Healthy: true, Beat: cliJSONTime(beat), Channels: cliHealthy(), Open: []cliOpenJSON{
		{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
	}})
}

// The problems come in one line: the beat, the late checks, then each
// failing channel in the order of the config.
func TestStatusJoinsEveryProblemInOneLineInOrder(t *testing.T) {
	cliSetClock(t, cliNow)
	w := cliNewWorld(t, false)
	www := cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA),
		"10.53.0.81", cliNow.Add(-10*time.Minute), "10.53.0.99")
	late := "records corp.test. www.corp.test. A"
	beat := cliNow.Add(-31 * time.Second)
	cliStore(t, w.state, func(s *store.Store) {
		if err := s.Beat(beat, []string{late}); err != nil {
			t.Fatal(err)
		}
		// siem comes first in the store; the config puts slack first.
		cliApply(t, s, www.Opened, cliEvent(alert.EventOpen, www, www.Severity, www.Opened, "siem", "slack"))
		cliRecord(t, s, cliRows(t, s, "siem", cliNow)[0], store.Done{State: store.RowGivenUp, Attempts: 1, Reason: "status 400", At: cliNow.Add(-time.Minute)})
		cliRecord(t, s, cliRows(t, s, "slack", cliNow)[0], store.Done{State: store.RowPending, Attempts: 1,
			NextAt: cliNow.Add(time.Minute), Reason: "status 502", At: cliNow.Add(-time.Minute)})
	})
	problems := []string{"no beat from osk-dns-watcher run since " + cliText(beat), "1 checks late", "channel slack fails", "channel siem fails"}
	cliStatusIs(t, w, 1, []string{
		"unhealthy: " + strings.Join(problems, "; "),
		"beat " + cliText(beat),
		"late " + late,
		"channel slack fails, 1 pending, last reason status 502",
		"channel siem fails, 0 pending, last reason status 400",
		"open 1 high record-set records www.corp.test. A since " + cliText(www.Opened),
	}, cliStatusJSON{
		Problems: problems,
		Beat:     cliJSONTime(beat),
		Late:     []string{late},
		Channels: []cliChannelJSON{{"slack", 1, true, "status 502"}, {"siem", 0, true, "status 400"}},
		Open: []cliOpenJSON{
			{ID: 1, Severity: "high", Rule: "record-set", Check: cliRecordsCheck("www.corp.test.", "A"), Opened: cliJSONTime(www.Opened)},
		},
	})
}
