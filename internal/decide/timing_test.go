package decide

import (
	"errors"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// timLimit is the failure limit of a check every 5 s: five intervals.
const timLimit = 25 * time.Second

func timFile(t testing.TB) *expect.File {
	return decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none",
		"www.corp.test. A 10.53.0.81", "nx.corp.test. A none")
}

func timWWW(t testing.TB) obs.Key {
	return decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
}

// timFailedRun is a run of key in which both servers failed.
func timFailedRun(t testing.TB, key obs.Key, zone string) obs.Observation {
	return decObservation(key, decName(t, zone), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonRefused)),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonTimeout)))
}

func timFailing(key obs.Key, limit time.Duration) Finding {
	return Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: key, Value: "no usable answer for " + limit.String()}
}

func timInput(f *expect.File, open []Finding, o obs.Observation, now, since time.Time, limit time.Duration) Input {
	return Input{Expect: f, Open: open, Observation: o, Now: now, FailingSince: since, FailLimit: limit}
}

// timPlain gives a finding with an empty Seen the nil Seen, so that both
// forms of "nothing seen" compare equal.
func timPlain(cs []Change) []Change {
	out := slices.Clone(cs)
	for i := range out {
		if len(out[i].Finding.Seen) == 0 {
			out[i].Finding.Seen = nil
		}
	}
	return out
}

func timSame(t *testing.T, got, want []Change) {
	t.Helper()
	decSameChanges(t, timPlain(got), timPlain(want))
}

func TestCheckFailingAndZoneChangedAreRulesSixAndSeven(t *testing.T) {
	// The store keeps the number of a rule.
	if RuleCheckFailing != 6 || RuleZoneChanged != 7 {
		t.Errorf("check-failing is %d and zone-changed %d, want 6 and 7", RuleCheckFailing, RuleZoneChanged)
	}
	for _, c := range []struct{ got, want string }{
		{Rule(6).String(), "check-failing"},
		{Rule(7).String(), "zone-changed"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
}

func TestFailedOnlyWhenNoAnswerIsUsable(t *testing.T) {
	www, corp := timWWW(t), decName(t, "corp.test.")
	records := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))
	at := func(host, addr string, r obs.Result) obs.Answer { return decAnswer(t, host, addr, r) }
	type failedCase struct {
		name string
		o    obs.Observation
		want bool
	}
	var cases []failedCase
	for r := obs.ReasonNoResult; r <= obs.ReasonDeadline; r++ {
		o := decObservation(www, corp, nil, at("ns1.corp.test.", decNS1, decFailure(r)), at("ns2.corp.test.", decNS2, decFailure(r)))
		cases = append(cases, failedCase{"every server " + r.String(), o, true})
	}
	referral := at("ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test."))
	cases = append(cases,
		failedCase{"the zero result", decObservation(www, corp, nil, at("ns1.corp.test.", decNS1, obs.Result{})), true},
		failedCase{"no answer at all", decObservation(www, corp, nil), true},
		failedCase{"the walk from the root failed", decObservation(www, dnswire.Name{}, nil, decFailedWalk()), true},
		failedCase{"the limits of the tool itself", decObservation(www, corp, nil,
			at("ns1.corp.test.", decNS1, decFailure(obs.ReasonRateLimited)),
			at("ns2.corp.test.", decNS2, decFailure(obs.ReasonBudget)),
			at("ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonDeadline)),
			at("ns4.corp.test.", "", decFailure(obs.ReasonWalk))), true},
		failedCase{"usable answers in the walk only", decObservation(www, corp, []obs.Answer{referral},
			at("ns1.corp.test.", decNS1, decFailure(obs.ReasonTimeout))), true},
		failedCase{"one dead server of two", decObservation(www, corp, nil,
			records, at("ns2.corp.test.", decNS2, decFailure(obs.ReasonTimeout))), false},
		failedCase{"no data and a failure", decObservation(www, corp, nil,
			at("ns1.corp.test.", decNS1, decFailure(obs.ReasonNetwork)), at("ns2.corp.test.", decNS2, decNoData(t, "corp.test."))), false},
		failedCase{"no such name and a failure", decObservation(www, corp, nil,
			at("ns1.corp.test.", decNS1, decNoName(t, "corp.test.")), at("ns2.corp.test.", decNS2, decFailure(obs.ReasonServFail))), false},
		failedCase{"a host with no address beside an answer", decObservation(www, corp, nil,
			records, at("ns3.corp.test.", "", decFailure(obs.ReasonWalk))), false},
		failedCase{"failures in the walk only", decObservation(www, corp, []obs.Answer{decFailedWalk()}, records), false},
	)
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := Failed(c.o); got != c.want {
				t.Errorf("Failed is %v, want %v", got, c.want)
			}
		})
	}
}

func TestCheckFailingOpensOnceTheSeriesLastsTheLimit(t *testing.T) {
	f, key := timFile(t), timWWW(t)
	o := timFailedRun(t, key, "corp.test.")
	since := decT0
	long := since.Add(100 * time.Hour)
	for _, c := range []struct {
		name       string
		now, since time.Time
		limit      time.Duration
		opens      bool
	}{
		{"1ns before the limit", since.Add(timLimit - 1), since, timLimit, false},
		{"at the limit", since.Add(timLimit), since, timLimit, true},
		{"long after the limit", long, since, timLimit, true},
		{"limit 0", long, since, 0, false},
		{"a negative limit", long, since, -timLimit, false},
		{"no series", long, time.Time{}, timLimit, false},
		{"a series that starts after now", since.Add(-time.Second), since, timLimit, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			var want []Change
			if c.opens {
				// Medium, although a record-set finding of an A set is high.
				want = []Change{{Op: OpOpen, Finding: timFailing(key, c.limit), At: c.now}}
			}
			timSame(t, Decide(timInput(f, nil, o, c.now, c.since, c.limit)), want)
		})
	}
}

func TestCheckFailingValueNamesTheLimitAndNoTime(t *testing.T) {
	f, key := timFile(t), timWWW(t)
	o := timFailedRun(t, key, "corp.test.")
	for _, c := range []struct {
		limit time.Duration
		want  string
	}{
		{25 * time.Second, "no usable answer for 25s"},
		{3 * time.Minute, "no usable answer for 3m0s"},
		{15 * time.Minute, "no usable answer for 15m0s"},
		{time.Hour, "no usable answer for 1h0m0s"},
	} {
		got := Decide(timInput(f, nil, o, decT0.Add(c.limit), decT0, c.limit))
		if len(got) != 1 || got[0].Op != OpOpen || got[0].Finding.Value != c.want || got[0].Finding.Expected != "" || len(got[0].Finding.Seen) != 0 {
			t.Errorf("limit %v gave%s\nwant one open with value %q, no expected and nothing seen", c.limit, decShowChanges(got), c.want)
		}
	}

	open := Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: key, Value: "no usable answer for 25s"}
	otherReason := decObservation(key, decName(t, "corp.test."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonNetwork)),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonBudget)))
	otherReason.Start = decT0.Add(time.Hour)
	later := decT0.Add(2 * time.Hour)
	for _, c := range []struct {
		name  string
		o     obs.Observation
		since time.Time
		limit time.Duration
		want  []Change
	}{
		{"a later run", o, decT0, timLimit, nil},
		{"another reason of failure", otherReason, decT0, timLimit, nil},
		{"a series that started later", o, decT0.Add(time.Hour), timLimit, nil},
		{"another limit", o, decT0, 5 * time.Minute, []Change{{Op: OpUpdate, Finding: timFailing(key, 5*time.Minute), At: later}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSame(t, Decide(timInput(f, []Finding{open}, c.o, later, c.since, c.limit)), c.want)
		})
	}
}

func TestCheckFailingNeedsARunWithNoUsableAnswer(t *testing.T) {
	f, key := timFile(t), timWWW(t)
	now := decT0.Add(time.Hour)
	oneDead := decObservation(key, decName(t, "corp.test."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonNetwork)))
	// The series is past the limit, but one server still shows the set.
	timSame(t, Decide(timInput(f, nil, oneDead, now, decT0, timLimit)), nil)
	bothDead := timFailedRun(t, key, "corp.test.")
	timSame(t, Decide(timInput(f, nil, bothDead, now, decT0, timLimit)), []Change{{Op: OpOpen, Finding: timFailing(key, timLimit), At: now}})
}

func TestCheckFailingForEveryKindOfCheck(t *testing.T) {
	corp := decName(t, "corp.test.")
	now := decT0.Add(time.Hour)
	for _, file := range []struct {
		name string
		f    *expect.File
	}{{"with a line", timFile(t)}, {"no file", nil}} {
		for _, c := range []struct {
			key  obs.Key
			zone string
		}{
			{obs.DelegationKey(corp), "test."},
			{obs.DSKey(corp), "test."},
			{timWWW(t), "corp.test."},
			{obs.SerialKey(corp), "corp.test."},
		} {
			t.Run(file.name+"/"+c.key.Kind.String(), func(t *testing.T) {
				o := timFailedRun(t, c.key, c.zone)
				var want []Change
				for _, found := range Findings(file.f, o) {
					want = append(want, Change{Op: OpOpen, Finding: found, At: now})
				}
				want = append(want, Change{Op: OpOpen, Finding: timFailing(c.key, timLimit), At: now})
				timSame(t, Decide(timInput(file.f, nil, o, now, decT0, timLimit)), want)
			})
		}
	}
}

func TestCheckFailingComesAfterFindingsAndBeforeResolves(t *testing.T) {
	f, key := timFile(t), timWWW(t)
	now := decT0.Add(time.Hour)
	failing := Change{Op: OpOpen, Finding: timFailing(key, timLimit), At: now}

	t.Run("after a zone finding of the same run", func(t *testing.T) {
		walk, _ := decCut(t)
		o := decObservation(key, decName(t, "www.corp.test."), walk,
			decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decFailure(obs.ReasonTimeout)))
		found := Findings(f, o)
		if len(found) != 1 || found[0].Rule != RuleZone {
			t.Fatalf("want one zone finding:%s", decShow(found))
		}
		timSame(t, Decide(timInput(f, nil, o, now, decT0, timLimit)), []Change{{Op: OpOpen, Finding: found[0], At: now}, failing})
	})

	// A record-set alert that only ns2 showed.
	recordSet := Findings(f, decObservation(key, decName(t, "corp.test."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")),
		decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99"))))
	if len(recordSet) != 1 {
		t.Fatalf("want one record-set finding:%s", decShow(recordSet))
	}
	t.Run("the server that showed another alert fails", func(t *testing.T) {
		o := timFailedRun(t, key, "corp.test.")
		timSame(t, Decide(timInput(f, recordSet, o, now, decT0, timLimit)), []Change{failing})
	})
	t.Run("another alert whose server is no longer asked", func(t *testing.T) {
		o := decObservation(key, decName(t, "corp.test."), nil,
			decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonTimeout)),
			decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonTimeout)))
		timSame(t, Decide(timInput(f, recordSet, o, now, decT0, timLimit)), []Change{failing})
	})
}

// A run with no usable answer shows nothing, so it ends no alert, also one
// whose servers are no longer asked; one usable answer is enough to judge.
func TestFailedRunResolvesNoAlert(t *testing.T) {
	f := timFile(t)
	corp, test := decName(t, "corp.test."), decName(t, "test.")
	now := decT0.Add(time.Hour)
	www, delegation := timWWW(t), obs.DelegationKey(corp)
	recordSet := Findings(f, decObservation(www, corp, nil,
		decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99"))))
	nameServers := Findings(f, decObservation(delegation, test, nil,
		decAnswer(t, "a.ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.dnshost.test."))))
	if len(recordSet) != 1 || len(nameServers) != 1 {
		t.Fatalf("want one finding each:%s%s", decShow(recordSet), decShow(nameServers))
	}
	for _, c := range []struct {
		name   string
		key    obs.Key
		zone   string
		was    Finding
		answer obs.Result
	}{
		{"record-set", www, "corp.test.", recordSet[0], decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")},
		{"nameservers", delegation, "test.", nameServers[0], decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")},
	} {
		t.Run(c.name, func(t *testing.T) {
			// Neither server of the run showed the alert.
			failed := decObservation(c.key, decName(t, c.zone), nil,
				decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonTimeout)),
				decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonRefused)))
			timSame(t, Decide(timInput(f, []Finding{c.was}, failed, now, time.Time{}, 0)), nil)
			oneAnswer := decObservation(c.key, decName(t, c.zone), nil,
				decAnswer(t, "ns1.corp.test.", decNS1, c.answer),
				decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonRefused)))
			timSame(t, Decide(timInput(f, []Finding{c.was}, oneAnswer, now, time.Time{}, 0)),
				[]Change{{Op: OpResolve, Finding: c.was, At: now}})
		})
	}
}

func TestSeverityAloneUpdatesTheTimingRules(t *testing.T) {
	f, key := timFile(t), timWWW(t)
	corp := decName(t, "corp.test.")
	now := decT0.Add(time.Hour)
	failing := timFailing(key, timLimit)
	low := failing
	low.Severity = SeverityLow
	timSame(t, Decide(timInput(f, []Finding{low}, timFailedRun(t, key, "corp.test."), now, decT0, timLimit)),
		[]Change{{Op: OpUpdate, Finding: failing, At: now}})

	opened := ZoneChanges(corp, timMoves(t), nil, now)
	if len(opened) != 1 {
		t.Fatalf("want one open:%s", decShowChanges(opened))
	}
	medium := opened[0].Finding
	medium.Severity = SeverityMedium
	timSame(t, ZoneChanges(corp, timMoves(t), []Finding{medium}, now), []Change{{Op: OpUpdate, Finding: opened[0].Finding, At: now}})
}

func TestCheckFailingResolvesExactlyWhenARunHasAUsableAnswer(t *testing.T) {
	f, www := timFile(t), timWWW(t)
	corp := decName(t, "corp.test.")
	nx := decRecordsKey(t, "corp.test.", "nx.corp.test.", dnswire.TypeA)
	mail := decRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA)
	now := decT0.Add(time.Hour)
	open, openNX := timFailing(www, timLimit), timFailing(nx, timLimit)
	upper := timFailing(decRecordsKey(t, "CORP.TEST.", "WWW.Corp.Test.", dnswire.TypeA), timLimit)
	other := open
	other.Value = "no usable answer for 3m0s"

	ok := decObservation(www, corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")),
		// A failure with no address blocks the general rule.
		decAnswer(t, "ns3.corp.test.", "", decFailure(obs.ReasonWalk)))
	noData := decObservation(nx, corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decNoData(t, "corp.test.")),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonTimeout)))
	noName := decObservation(nx, corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonRefused)),
		decAnswer(t, "ns2.corp.test.", decNS2, decNoName(t, "corp.test.")))
	failed := timFailedRun(t, www, "corp.test.")
	failedWalk := decObservation(www, dnswire.Name{}, nil, decFailedWalk())
	resolve := func(f Finding) []Change { return []Change{{Op: OpResolve, Finding: f, At: now}} }

	for _, c := range []struct {
		name  string
		open  []Finding
		o     obs.Observation
		since time.Time
		limit time.Duration
		want  []Change
	}{
		{"an answer beside a host with no address", []Finding{open}, ok, time.Time{}, timLimit, resolve(open)},
		{"no data", []Finding{openNX}, noData, time.Time{}, timLimit, resolve(openNX)},
		{"no such name", []Finding{openNX}, noName, time.Time{}, timLimit, resolve(openNX)},
		{"the open alert names the check in capitals", []Finding{upper}, ok, time.Time{}, timLimit, resolve(upper)},
		{"a duplicate resolves once", []Finding{open, other}, ok, time.Time{}, 0, resolve(open)},
		// A restart forgot the series: the alert stays open, although no
		// server that it saw fails.
		{"a failed run after a restart", []Finding{open}, failed, time.Time{}, timLimit, nil},
		{"a failed run before the limit", []Finding{open}, failed, now.Add(-10 * time.Second), timLimit, nil},
		{"a failed run with no limit", []Finding{open}, failed, decT0, 0, nil},
		{"a failed walk", []Finding{open}, failedWalk, time.Time{}, timLimit, nil},
		{"the series still lasts", []Finding{open}, failed, decT0, timLimit, nil},
		{"an alert of another check", []Finding{timFailing(mail, timLimit)}, ok, time.Time{}, timLimit, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSame(t, Decide(timInput(f, c.open, c.o, now, c.since, c.limit)), c.want)
		})
	}
}

func TestDecideNeverTouchesZoneChanged(t *testing.T) {
	f := timFile(t)
	corp := decName(t, "corp.test.")
	now := decT0.Add(time.Hour)
	changed := Finding{Rule: RuleZoneChanged, Severity: SeverityLow, Check: obs.Key{Domain: corp, Name: corp},
		Value: "10.53.0.11:53 ns1.corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:15Z"}
	soa := "ns1.corp.test. hostmaster.corp.test. 2 3600 600 604800 300"
	serial := decObservation(obs.SerialKey(corp), corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "corp.test.", dnswire.TypeSOA, soa)),
		decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "corp.test.", dnswire.TypeSOA, soa)))
	apex := decRecordsKey(t, "corp.test.", "corp.test.", dnswire.TypeNS)
	for _, o := range []obs.Observation{
		serial,
		timFailedRun(t, obs.SerialKey(corp), "corp.test."),
		timFailedRun(t, obs.DelegationKey(corp), "test."),
		timFailedRun(t, apex, "corp.test."),
	} {
		t.Run(o.Key.String(), func(t *testing.T) {
			without := Decide(timInput(f, nil, o, now, decT0, timLimit))
			if failing := slices.ContainsFunc(without, func(c Change) bool { return c.Finding.Rule == RuleCheckFailing }); failing != timNoUsable(o) {
				t.Errorf("check-failing change %v for a run that failed %v:%s", failing, timNoUsable(o), decShowChanges(without))
			}
			timSame(t, Decide(timInput(f, []Finding{changed}, o, now, decT0, timLimit)), without)
		})
	}
}

// timMoves are two servers whose serial moved, in no sorted order, with
// times in another zone than UTC and with parts of a second.
func timMoves(t testing.TB) []Move {
	plus := time.FixedZone("UTC+1:30", 90*60)
	return []Move{
		{Server: obs.Server{Name: decName(t, "ns2.corp.test."), Addr: netip.MustParseAddrPort(decNS2)}, From: 1, To: 2,
			Until: time.Date(2026, 11, 13, 10, 0, 0, 750_000_000, time.UTC), Since: time.Date(2026, 11, 13, 10, 0, 15, 0, time.UTC)},
		{Server: obs.Server{Name: decName(t, "NS1.Corp.Test."), Addr: netip.MustParseAddrPort("[fd53::11]:53")}, From: 4294967295, To: 0,
			Until: time.Date(2026, 11, 13, 11, 29, 59, 999_999_999, plus), Since: time.Date(2026, 11, 13, 11, 30, 14, 0, plus)},
	}
}

const (
	timLineNS2 = "10.53.0.12:53 ns2.corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:15Z"
	timLineNS1 = "[fd53::11]:53 ns1.corp.test. serial 4294967295 until 2026-11-13T09:59:59Z, 0 since 2026-11-13T10:00:14Z"
)

func TestZoneChangesOpensALowAlertWithOneLinePerMoveInOrder(t *testing.T) {
	corp := decName(t, "corp.test.")
	now := decT0.Add(time.Hour)
	moves := append(timMoves(t),
		Move{Server: obs.Server{Name: dnswire.Name{}, Addr: netip.MustParseAddrPort("10.53.0.2:53")}, From: 2026111300, To: 2026111301,
			Until: time.Date(2026, 11, 13, 10, 1, 0, 0, time.UTC), Since: time.Date(2026, 11, 13, 10, 1, 30, 0, time.UTC)},
		Move{Server: obs.Server{Name: decName(t, "ns3.corp.test.")}, From: 7, To: 9,
			Until: time.Date(2026, 11, 13, 10, 2, 0, 0, time.UTC), Since: time.Date(2026, 11, 13, 10, 2, 15, 0, time.UTC)})
	kept := slices.Clone(moves)
	want := strings.Join([]string{
		timLineNS2,
		timLineNS1,
		"10.53.0.2:53 - serial 2026111300 until 2026-11-13T10:01:00Z, 2026111301 since 2026-11-13T10:01:30Z",
		"- ns3.corp.test. serial 7 until 2026-11-13T10:02:00Z, 9 since 2026-11-13T10:02:15Z",
	}, "\n")

	got := ZoneChanges(corp, moves, nil, now)
	if len(got) != 1 || got[0].Op != OpOpen || !got[0].At.Equal(now) {
		t.Fatalf("want one open at %v:%s", now, decShowChanges(got))
	}
	f := got[0].Finding
	if f.Rule != RuleZoneChanged || f.Severity != SeverityLow || f.Expected != "" || len(f.Seen) != 0 {
		t.Errorf("the finding is%s", decShow([]Finding{f}))
	}
	if c := f.Check; c.Kind != 0 || c.Type != 0 || !c.Domain.Equal(corp) || !c.Name.Equal(corp) {
		t.Errorf("the finding has check %+v, want the domain alone", f.Check)
	}
	if f.Value != want {
		t.Errorf("value\n%s\nwant\n%s", f.Value, want)
	}
	if !reflect.DeepEqual(moves, kept) {
		t.Error("ZoneChanges changed the moves")
	}
}

func TestZoneChangesUpdatesOnlyOnANewLine(t *testing.T) {
	corp, shop := decName(t, "corp.test."), decName(t, "shop.test.")
	now := decT0.Add(time.Hour)
	moves := timMoves(t)
	opened := ZoneChanges(corp, moves, nil, now)
	if len(opened) != 1 || opened[0].Op != OpOpen {
		t.Fatalf("want one open:%s", decShowChanges(opened))
	}
	f := opened[0].Finding
	with := func(check obs.Key, value string) Finding {
		g := f
		g.Check, g.Value = check, value
		return g
	}
	scope := obs.Key{Domain: corp, Name: corp}
	upper := obs.Key{Domain: decName(t, "CORP.TEST."), Name: decName(t, "Corp.Test.")}
	both := timLineNS2 + "\n" + timLineNS1
	again := Move{Server: moves[0].Server, From: 2, To: 3,
		Until: time.Date(2026, 11, 13, 10, 0, 15, 0, time.UTC), Since: time.Date(2026, 11, 13, 10, 5, 0, 0, time.UTC)}
	againFinding := with(scope, "10.53.0.12:53 ns2.corp.test. serial 2 until 2026-11-13T10:00:15Z, 3 since 2026-11-13T10:05:00Z")
	invalid := FileChanges(corp, errors.New("line 2: an empty record"), nil, now)[0].Finding

	for _, c := range []struct {
		name  string
		moves []Move
		open  []Finding
		want  []Change
	}{
		{"the same lines", moves, []Finding{with(scope, both)}, nil},
		{"the same lines in another order", moves, []Finding{with(scope, timLineNS1+"\n"+timLineNS2)}, nil},
		{"an older line besides", moves, []Finding{with(scope, both+"\n"+againFinding.Value)}, nil},
		{"a line is new", moves, []Finding{with(scope, timLineNS1)}, []Change{{Op: OpUpdate, Finding: f, At: now}}},
		{"the serial moved again", []Move{again}, []Finding{with(scope, both)}, []Change{{Op: OpUpdate, Finding: againFinding, At: now}}},
		{"the domain in capitals", moves, []Finding{with(upper, both)}, nil},
		{"another domain", moves, []Finding{with(obs.Key{Domain: shop, Name: shop}, both)}, []Change{{Op: OpOpen, Finding: f, At: now}}},
		{"only invalid-file is open", moves, []Finding{invalid}, []Change{{Op: OpOpen, Finding: f, At: now}}},
		{"the first of two counts", moves, []Finding{with(scope, timLineNS2), with(scope, both)}, []Change{{Op: OpUpdate, Finding: f, At: now}}},
		{"a later duplicate is ignored", moves, []Finding{with(scope, both), with(scope, timLineNS2)}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSame(t, ZoneChanges(corp, c.moves, c.open, now), c.want)
		})
	}
}

func TestZoneChangesResolvesWhenNoServerMoved(t *testing.T) {
	corp, shop := decName(t, "corp.test."), decName(t, "shop.test.")
	now := decT0.Add(time.Hour)
	opened := ZoneChanges(corp, timMoves(t), nil, now)
	if len(opened) != 1 {
		t.Fatalf("want one open:%s", decShowChanges(opened))
	}
	open := opened[0].Finding
	upper := open
	upper.Check = obs.Key{Domain: decName(t, "CORP.TEST."), Name: decName(t, "Corp.Test.")}
	other := open
	other.Check = obs.Key{Domain: shop, Name: shop}
	shorter := open
	shorter.Value = timLineNS2
	bad := errors.New("line 2: an empty record")
	invalid := FileChanges(corp, bad, nil, now)[0].Finding
	resolve := func(f Finding) []Change { return []Change{{Op: OpResolve, Finding: f, At: now}} }

	for _, c := range []struct {
		name  string
		moves []Move
		open  []Finding
		want  []Change
	}{
		{"no move", nil, []Finding{open}, resolve(open)},
		{"an empty list of moves", []Move{}, []Finding{open}, resolve(open)},
		{"nothing open", nil, nil, nil},
		{"only invalid-file is open", nil, []Finding{invalid}, nil},
		{"another domain", nil, []Finding{other}, nil},
		{"the domain in capitals", nil, []Finding{upper}, resolve(upper)},
		{"a duplicate resolves once", nil, []Finding{open, shorter}, resolve(open)},
		{"after invalid-file", nil, []Finding{invalid, open}, resolve(open)},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSame(t, ZoneChanges(corp, c.moves, c.open, now), c.want)
		})
	}

	t.Run("the file rule leaves it alone", func(t *testing.T) {
		timSame(t, FileChanges(corp, nil, []Finding{open}, now), nil)
		timSame(t, FileChanges(corp, bad, []Finding{open}, now), []Change{{Op: OpOpen, Finding: invalid, At: now}})
	})
}

// The property tests draw their inputs from a fixed seed, so a failure can
// be replayed; every message names the seed of its case.
const (
	timSeed  = 20261113
	timCases = 2000
)

// timNoUsable is the definition of a failed run: no answer is records, no
// data or no such name.
func timNoUsable(o obs.Observation) bool {
	return !slices.ContainsFunc(o.Answers, func(a obs.Answer) bool {
		return !strings.HasPrefix(decCase(a.Result), "failure")
	})
}

// timFirstOfEach gives the open findings of the check key, the first of
// each rule, in order.
func timFirstOfEach(open []Finding, key string) []Finding {
	var mine []Finding
	for _, f := range open {
		if f.Check.String() == key && !slices.ContainsFunc(mine, func(m Finding) bool { return m.Rule == f.Rule }) {
			mine = append(mine, f)
		}
	}
	return mine
}

// timNews reports whether f tells more than the open finding was: another
// Expected or Severity, or a line of Value that was not there.
func timNews(was, f Finding) bool {
	if was.Expected != f.Expected || was.Severity != f.Severity {
		return true
	}
	var old []string
	if was.Value != "" {
		old = strings.Split(was.Value, "\n")
	}
	return f.Value != "" && slices.ContainsFunc(strings.Split(f.Value, "\n"), func(l string) bool { return !slices.Contains(old, l) })
}

// timBlocks reports whether a failure now could hide what was shows: a
// failure with no address, or at an address that showed it.
func timBlocks(was Finding, answers []obs.Answer) bool {
	return slices.ContainsFunc(answers, func(a obs.Answer) bool {
		if !strings.HasPrefix(decCase(a.Result), "failure") {
			return false
		}
		return !a.Server.Addr.IsValid() || slices.ContainsFunc(was.Seen, func(s Seen) bool { return s.Answer.Server.Addr == a.Server.Addr })
	})
}

// timGeneral is the general judgement of Decide, with no check-failing
// alert: open or update for each finding of Findings, then a resolve of each
// open alert that no finding holds and no failure blocks. A run with no
// usable answer resolves nothing.
func timGeneral(in Input) []Change {
	found := Findings(in.Expect, in.Observation)
	open := timFirstOfEach(in.Open, in.Observation.Key.String())
	var changes []Change
	for _, f := range found {
		i := slices.IndexFunc(open, func(o Finding) bool { return o.Rule == f.Rule })
		if i < 0 {
			changes = append(changes, Change{Op: OpOpen, Finding: f, At: in.Now})
		} else if timNews(open[i], f) {
			changes = append(changes, Change{Op: OpUpdate, Finding: f, At: in.Now})
		}
	}
	if timNoUsable(in.Observation) {
		return changes
	}
	for _, was := range open {
		if !slices.ContainsFunc(found, func(f Finding) bool { return f.Rule == was.Rule }) && !timBlocks(was, in.Observation.Answers) {
			changes = append(changes, Change{Op: OpResolve, Finding: rsvLineInForce(in.Expect, in.Observation.Key, was), At: in.Now})
		}
	}
	return changes
}

func timIsFailing(key string) func(Finding) bool {
	return func(f Finding) bool { return f.Rule == RuleCheckFailing && f.Check.String() == key }
}

// timWant is what Decide must give: the changes of timGeneral without the
// check-failing alerts of the check, the check-failing open or update after
// the other opens and updates, and its resolve in the order of the open
// alerts.
func timWant(in Input) []Change {
	key := in.Observation.Key.String()
	base := in
	base.Open = slices.DeleteFunc(slices.Clone(in.Open), timIsFailing(key))
	general := timGeneral(base)
	n := slices.IndexFunc(general, func(c Change) bool { return c.Op == OpResolve })
	if n < 0 {
		n = len(general)
	}
	want := slices.Clone(general[:n])
	failed := timNoUsable(in.Observation)
	if failed && !in.FailingSince.IsZero() && in.FailLimit > 0 && in.Now.Sub(in.FailingSince) >= in.FailLimit {
		f := Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: in.Observation.Key,
			Value: "no usable answer for " + in.FailLimit.String()}
		i := slices.IndexFunc(in.Open, timIsFailing(key))
		if i < 0 {
			want = append(want, Change{Op: OpOpen, Finding: f, At: in.Now})
		} else if timNews(in.Open[i], f) {
			want = append(want, Change{Op: OpUpdate, Finding: f, At: in.Now})
		}
	}
	resolves := general[n:]
	for _, was := range timFirstOfEach(in.Open, key) {
		if was.Rule == RuleCheckFailing {
			if !failed {
				want = append(want, Change{Op: OpResolve, Finding: was, At: in.Now})
			}
			continue
		}
		if len(resolves) > 0 && resolves[0].Finding.Rule == was.Rule {
			want = append(want, resolves[0])
			resolves = resolves[1:]
		}
	}
	return want
}

// timFailingCase draws one input of Decide with the two timing fields from
// seed: equal seeds give equal inputs. The open alerts of the observed check
// have the five rules from invalid-file to record-set, and zero to two
// check-failing alerts as the store keeps them. FailingSince lies at, 1ns short of, before or after the
// limit, so that the bound is hit.
func timFailingCase(t testing.TB, seed uint64) Input {
	g := &decGen{t: t, rng: rand.New(rand.NewPCG(seed, 6))}
	key := g.key()
	for key.Kind == 0 || key.Kind > obs.KindSerial {
		key = g.key()
	}
	o := g.observation(key, true)
	if g.rng.IntN(4) == 0 {
		for i := range o.Answers {
			o.Answers[i].Result = decFailure(obs.Reason(g.rng.IntN(15)))
		}
	}
	var open []Finding
	for range g.rng.IntN(4) {
		check := key
		if n := g.rng.IntN(4); n == 0 {
			check = g.recased(key)
		} else if n == 1 {
			check = g.other(key)
		}
		f := g.finding(check, o.Start)
		if f.Check.String() == key.String() {
			f.Rule = Rule(1 + g.rng.IntN(5))
		}
		open = append(open, f)
	}
	limits := []time.Duration{0, -time.Minute, 25 * time.Second, 3 * time.Minute, 15 * time.Minute, time.Hour}
	for range g.rng.IntN(3) {
		check := key
		if g.rng.IntN(3) == 0 {
			check = g.recased(key)
		}
		was := Finding{Rule: RuleCheckFailing, Severity: decPick(g, SeverityMedium, SeverityMedium, SeverityMedium, SeverityLow), Check: check,
			Value: "no usable answer for " + decPick(g, limits[2:]...).String()}
		open = slices.Insert(open, g.rng.IntN(len(open)+1), was)
	}
	limit := decPick(g, limits...)
	now := o.Deadline.Add(time.Duration(g.rng.IntN(120)) * time.Second)
	var since time.Time
	switch g.rng.IntN(6) {
	case 0:
		// No series: the run had a usable answer, or a restart forgot it.
	case 1:
		since = now.Add(-limit)
	case 2:
		since = now.Add(-limit + time.Nanosecond)
	case 3:
		since = now.Add(-limit - time.Duration(g.rng.IntN(3600))*time.Second)
	case 4:
		since = now.Add(-time.Duration(g.rng.IntN(1800)) * time.Second)
	default:
		since = now.Add(time.Duration(1+g.rng.IntN(60)) * time.Second)
	}
	return Input{Expect: g.file(), Open: open, Observation: o, Now: now, FailingSince: since, FailLimit: limit}
}

// timTally counts what the cases showed, and fails at the end of the test
// when some outcome never came up: the inputs would not test it.
type timTally map[string]int

func (c timTally) check(t *testing.T, outcomes ...string) {
	t.Helper()
	for _, o := range outcomes {
		if c[o] == 0 {
			t.Errorf("no case gave %q", o)
		}
	}
}

func TestFailingRuleProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", timSeed, timCases)
	tally := timTally{}
	for i := range timCases {
		seed := uint64(timSeed + i)
		in, same := timFailingCase(t, seed), timFailingCase(t, seed)
		key := in.Observation.Key.String()
		got := Decide(in)
		if !reflect.DeepEqual(in, same) {
			t.Fatalf("seed %d: Decide changed its input", seed)
		}
		failed := Failed(in.Observation)
		if failed != timNoUsable(in.Observation) {
			t.Fatalf("seed %d: Failed is %v for answers %v", seed, failed, timResultCases(in.Observation))
		}
		if want := timWant(in); !reflect.DeepEqual(timPlain(got), timPlain(want)) {
			t.Fatalf("seed %d (failed %v, since %v, limit %v, now %v):\n got %s\n want %s", seed, failed,
				in.FailingSince, in.FailLimit, in.Now, decShowChanges(got), decShowChanges(want))
		}
		for _, c := range got {
			if failed && (c.Finding.Rule == RuleRecordSet || c.Finding.Rule == RuleNameServers) {
				t.Fatalf("seed %d: a run with no usable answer gave %v %v", seed, c.Op, c.Finding.Rule)
			}
		}
		// With both timing fields zero and no check-failing alert, only the
		// general judgement is left.
		zero := in
		zero.FailingSince, zero.FailLimit = time.Time{}, 0
		zero.Open = slices.DeleteFunc(slices.Clone(in.Open), timIsFailing(key))
		if a, b := Decide(zero), timGeneral(zero); !reflect.DeepEqual(timPlain(a), timPlain(b)) {
			t.Fatalf("seed %d: with no timing fields\n got %s\n want %s", seed, decShowChanges(a), decShowChanges(b))
		}
		if again := Decide(same); !reflect.DeepEqual(got, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, decShowChanges(got), decShowChanges(again))
		}
		outs := make([][]Change, 4)
		var wg sync.WaitGroup
		for j := range outs {
			wg.Go(func() { outs[j] = Decide(in) })
		}
		wg.Wait()
		for j, out := range outs {
			if !reflect.DeepEqual(out, got) {
				t.Fatalf("seed %d: goroutine %d gave%s\nwant%s", seed, j, decShowChanges(out), decShowChanges(got))
			}
		}
		timTallyFailing(tally, in, got, failed)
	}
	tally.check(t, "open", "update", "resolve", "kept open while failing", "no news", "past the limit with no series")
}

func timResultCases(o obs.Observation) []string {
	var cases []string
	for _, a := range o.Answers {
		cases = append(cases, decCase(a.Result))
	}
	return cases
}

func timTallyFailing(tally timTally, in Input, got []Change, failed bool) {
	key := in.Observation.Key.String()
	isOpen := slices.ContainsFunc(in.Open, timIsFailing(key))
	i := slices.IndexFunc(got, func(c Change) bool { return c.Finding.Rule == RuleCheckFailing })
	switch {
	case i >= 0:
		tally[got[i].Op.String()]++
	case isOpen && failed:
		tally["kept open while failing"]++
	}
	if isOpen && failed && in.FailLimit > 0 && !in.FailingSince.IsZero() && in.Now.Sub(in.FailingSince) >= in.FailLimit && i < 0 {
		tally["no news"]++
	}
	if failed && in.FailingSince.IsZero() && in.FailLimit > 0 {
		tally["past the limit with no series"]++
	}
}

// timMoveLine is one line of the Value of zone-changed.
func timMoveLine(m Move) string {
	addr, host := "-", "-"
	if m.Server.Addr.IsValid() {
		addr = m.Server.Addr.String()
	}
	if m.Server.Name.LabelCount() > 0 {
		host = m.Server.Name.Lower().String()
	}
	const layout = "2006-01-02T15:04:05Z"
	return addr + " " + host + " serial " + strconv.FormatUint(uint64(m.From), 10) + " until " + m.Until.UTC().Format(layout) +
		", " + strconv.FormatUint(uint64(m.To), 10) + " since " + m.Since.UTC().Format(layout)
}

func timMove(g *decGen, now time.Time) Move {
	var m Move
	m.Server.Name = g.name(decPick(g, decHosts...))
	if g.rng.IntN(6) > 0 {
		m.Server.Addr = netip.MustParseAddrPort(decPick(g, decAddrs...))
	}
	m.From = decPick(g, 0, 1, 2, 4294967295, g.rng.Uint32())
	m.To = decPick(g, 0, 2, 3, 4294967295, g.rng.Uint32())
	zone := decPick(g, time.UTC, time.FixedZone("east", 5*3600+1800), time.FixedZone("west", -8*3600))
	m.Until = now.Add(-time.Duration(g.rng.Int64N(int64(time.Hour)))).In(zone)
	m.Since = m.Until.Add(time.Duration(g.rng.Int64N(int64(time.Hour))))
	return m
}

// timZoneCase draws one input of ZoneChanges from seed: equal seeds give
// equal inputs. A stored zone-changed alert holds some lines of these moves
// and of others, in any order.
func timZoneCase(t testing.TB, seed uint64) (dnswire.Name, []Move, []Finding, time.Time) {
	g := &decGen{t: t, rng: rand.New(rand.NewPCG(seed, 7))}
	domain := g.name(decPick(g, "corp.test.", "example."))
	now := decT0.Add(time.Duration(g.rng.IntN(1000)) * time.Minute)
	var moves []Move
	if n := g.rng.IntN(4); n > 0 || g.rng.IntN(2) == 0 {
		moves = make([]Move, n)
	}
	var pool []string
	for i := range moves {
		moves[i] = timMove(g, now)
		pool = append(pool, timMoveLine(moves[i]))
	}
	for range 2 {
		pool = append(pool, timMoveLine(timMove(g, now)))
	}
	stored := func(check obs.Key) Finding {
		var lines []string
		for _, l := range pool {
			if g.rng.IntN(3) > 0 {
				lines = append(lines, l)
			}
		}
		g.rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
		severity := decPick(g, SeverityLow, SeverityLow, SeverityLow, SeverityMedium)
		return Finding{Rule: RuleZoneChanged, Severity: severity, Check: check, Value: strings.Join(lines, "\n")}
	}
	scope := obs.Key{Domain: domain, Name: domain}
	var open []Finding
	for range g.rng.IntN(4) {
		var f Finding
		switch n := g.rng.IntN(6); {
		case n < 2:
			f = stored(scope)
		case n == 2:
			f = stored(g.recased(scope))
		case n == 3:
			shop := g.name("shop.test.")
			f = stored(obs.Key{Domain: shop, Name: shop})
		case n == 4:
			f = Finding{Rule: RuleInvalidFile, Severity: SeverityMedium, Check: scope, Value: "line 2: an empty record"}
		default:
			f = g.finding(g.other(scope), now)
		}
		open = append(open, f)
	}
	return domain, moves, open, now
}

func timZoneWant(domain dnswire.Name, moves []Move, open []Finding, now time.Time) []Change {
	scope := obs.Key{Domain: domain, Name: domain}
	i := slices.IndexFunc(open, func(f Finding) bool { return f.Rule == RuleZoneChanged && f.Check.String() == scope.String() })
	if len(moves) == 0 {
		if i < 0 {
			return nil
		}
		return []Change{{Op: OpResolve, Finding: open[i], At: now}}
	}
	lines := make([]string, len(moves))
	for j, m := range moves {
		lines[j] = timMoveLine(m)
	}
	f := Finding{Rule: RuleZoneChanged, Severity: SeverityLow, Check: scope, Value: strings.Join(lines, "\n")}
	if i < 0 {
		return []Change{{Op: OpOpen, Finding: f, At: now}}
	}
	if timNews(open[i], f) {
		return []Change{{Op: OpUpdate, Finding: f, At: now}}
	}
	return nil
}

func TestZoneChangesProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", timSeed, timCases)
	tally := timTally{}
	for i := range timCases {
		seed := uint64(timSeed + i)
		domain, moves, open, now := timZoneCase(t, seed)
		_, sameMoves, sameOpen, _ := timZoneCase(t, seed)
		got := ZoneChanges(domain, moves, open, now)
		if !reflect.DeepEqual(moves, sameMoves) || !reflect.DeepEqual(open, sameOpen) {
			t.Fatalf("seed %d: ZoneChanges changed its input", seed)
		}
		if want := timZoneWant(domain, moves, open, now); !reflect.DeepEqual(timPlain(got), timPlain(want)) {
			t.Fatalf("seed %d (%d moves):\n got %s\n want %s", seed, len(moves), decShowChanges(got), decShowChanges(want))
		}
		if again := ZoneChanges(domain, sameMoves, sameOpen, now); !reflect.DeepEqual(got, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, decShowChanges(got), decShowChanges(again))
		}
		outs := make([][]Change, 4)
		var wg sync.WaitGroup
		for j := range outs {
			wg.Go(func() { outs[j] = ZoneChanges(domain, moves, open, now) })
		}
		wg.Wait()
		for j, out := range outs {
			if !reflect.DeepEqual(out, got) {
				t.Fatalf("seed %d: goroutine %d gave%s\nwant%s", seed, j, decShowChanges(out), decShowChanges(got))
			}
		}
		switch {
		case len(got) > 0:
			tally[got[0].Op.String()]++
		case len(moves) > 0:
			tally["moves and no news"]++
		default:
			tally["no move and nothing open"]++
		}
	}
	tally.check(t, "open", "update", "resolve", "moves and no news", "no move and nothing open")
}
