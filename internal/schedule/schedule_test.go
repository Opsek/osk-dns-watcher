package schedule

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Every time is built from schT0; no test reads the clock or sleeps.
var schT0 = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)

const (
	schNS1 = "10.53.0.11:53"
	schNS2 = "10.53.0.12:53"
)

func schAfter(d time.Duration) time.Time { return schT0.Add(d) }

func schSec(n int) time.Time { return schT0.Add(time.Duration(n) * time.Second) }

// schWhen prints a time as its distance from schT0.
func schWhen(at time.Time) string {
	if at.IsZero() {
		return "zero"
	}
	return "T0+" + at.Sub(schT0).String()
}

func schServer(t testing.TB, host, addr string) obs.Server {
	t.Helper()
	return obs.Server{Name: schName(t, host), Addr: netip.MustParseAddrPort(addr)}
}

func schSOARecord(t testing.TB, serial uint32) dnswire.Record {
	t.Helper()
	return dnswire.Record{Name: schName(t, "corp.test."), Class: dnswire.ClassINET, TTL: 300,
		Data: dnswire.SOA{MName: schName(t, "ns1.corp.test."), RName: schName(t, "hostmaster.corp.test."),
			Serial: serial, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300}}
}

func schSOA(t testing.TB, serial uint32) obs.Result {
	t.Helper()
	return obs.RecordsResult(obs.Records{Set: []dnswire.Record{schSOARecord(t, serial)}})
}

func schA(t testing.TB) obs.Result {
	t.Helper()
	return obs.RecordsResult(obs.Records{Set: []dnswire.Record{{Name: schName(t, "corp.test."),
		Class: dnswire.ClassINET, TTL: 300, Data: dnswire.A{Addr: netip.MustParseAddr("10.53.0.80")}}}})
}

func schNoData(t testing.TB, serial uint32) obs.Result {
	t.Helper()
	return obs.NoDataResult(obs.NoData{SOA: schSOARecord(t, serial)})
}

func schNoName(t testing.TB, serial uint32) obs.Result {
	t.Helper()
	return obs.NoNameResult(obs.NoName{SOA: schSOARecord(t, serial)})
}

var schTimeout = obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout})

// schAt is the answer of host at addr, received at the time given.
func schAt(t testing.TB, host, addr string, received time.Time, r obs.Result) obs.Answer {
	t.Helper()
	return obs.Answer{Proof: obs.Proof{Server: schServer(t, host, addr), Sent: received.Add(-time.Millisecond),
		Received: received}, Result: r}
}

func schObs(k obs.Key, start time.Time, answers ...obs.Answer) obs.Observation {
	return obs.Observation{Key: k, Start: start, Deadline: start.Add(time.Second), Zone: k.Domain, Answers: answers}
}

// schPair is a run of k that started at start, in which ns1 gave r1 after
// 100 ms and ns2 gave r2 after 200 ms.
func schPair(t testing.TB, k obs.Key, start time.Time, r1, r2 obs.Result) obs.Observation {
	t.Helper()
	return schObs(k, start, schAt(t, "ns1.corp.test.", schNS1, start.Add(100*time.Millisecond), r1),
		schAt(t, "ns2.corp.test.", schNS2, start.Add(200*time.Millisecond), r2))
}

func schUsable(t testing.TB, k obs.Key, start time.Time) obs.Observation {
	t.Helper()
	return schPair(t, k, start, schA(t), schA(t))
}

func schFailed(t testing.TB, k obs.Key, start time.Time) obs.Observation {
	t.Helper()
	return schPair(t, k, start, schTimeout, schTimeout)
}

// schSerialObs is a run of the serial check with the serials of ns1 and
// ns2; 0 stands for no answer.
func schSerialObs(t testing.TB, start time.Time, s1, s2 uint32) obs.Observation {
	t.Helper()
	result := func(serial uint32) obs.Result {
		if serial == 0 {
			return schTimeout
		}
		return schSOA(t, serial)
	}
	return schPair(t, schSerialKey(t), start, result(s1), result(s2))
}

func schSerialKey(t testing.TB) obs.Key {
	t.Helper()
	return obs.SerialKey(schName(t, "corp.test."))
}

func schKey(t testing.TB, name string, typ dnswire.Type) obs.Key {
	t.Helper()
	return obs.RecordsKey(schName(t, "corp.test."), schName(t, name), typ)
}

func schMoveText(m decide.Move) string {
	return fmt.Sprintf("%s %s serial %d until %s, %d since %s", m.Server.Addr, m.Server.Name.Lower(), m.From,
		schWhen(m.Until), m.To, schWhen(m.Since))
}

func schMoveTexts(moves []decide.Move) []string {
	texts := make([]string, len(moves))
	for i, m := range moves {
		texts[i] = schMoveText(m)
	}
	return texts
}

// schSameMoves compares moves by address; the order of the moves of a round
// is left open.
func schSameMoves(got, want []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(got)), slices.Sorted(slices.Values(want)))
}

// schStart calls Due(now) and fails unless it started every key given.
func schStart(t testing.TB, s *Schedule, now time.Time, keys ...obs.Key) []Check {
	t.Helper()
	got := s.Due(now)
	texts := schKeyTexts(got)
	for _, k := range keys {
		if !slices.Contains(texts, k.String()) {
			t.Fatalf("Due(%s) gave%s\nwithout %s", schWhen(now), schShow(texts), k)
		}
	}
	return got
}

// schEnd ends a run as the caller does: Done, then Judged with the changes,
// for a check with no open alert.
func schEnd(t testing.TB, s *Schedule, o obs.Observation, now time.Time, changes ...decide.Change) (Report, []decide.Move, bool) {
	t.Helper()
	return schEndOpen(t, s, o, nil, now, changes...)
}

// schEndOpen is schEnd for a check whose open alerts have the findings open.
func schEndOpen(t testing.TB, s *Schedule, o obs.Observation, open []decide.Finding, now time.Time, changes ...decide.Change) (Report, []decide.Move, bool) {
	t.Helper()
	r := s.Done(o, now)
	moves, ok := s.Judged(o, open, changes, now)
	return r, moves, ok
}

// schSettle starts every check at T0 and ends each but the keys given at
// T0+1s with a usable answer: serial 1 at ns1 and ns2.
func schSettle(t testing.TB, s *Schedule, keep ...obs.Key) {
	t.Helper()
	started := schStart(t, s, schT0, keep...)
	if len(started) < 4 {
		t.Fatalf("Due(T0) of a new schedule gave%s", schShow(schKeyTexts(started)))
	}
	for _, c := range started {
		if slices.ContainsFunc(keep, func(k obs.Key) bool { return k.String() == c.Key.String() }) {
			continue
		}
		o := schUsable(t, c.Key, schT0)
		if c.Key.Kind == obs.KindSerial {
			o = schSerialObs(t, schT0, 1, 1)
		}
		schEnd(t, s, o, schSec(1))
	}
}

// schBase holds three zone checks (the apex NS and A sets, www), a cut and a
// name outside the domain.
func schBase(t testing.TB) *expect.File {
	t.Helper()
	return schFile(t,
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"edge.dnshost.test. A 10.53.0.84",
	)
}

// schZoneKeys are the zone checks of schBase, in plan order.
func schZoneKeys(t testing.TB) []obs.Key {
	t.Helper()
	return []obs.Key{schKey(t, "corp.test.", dnswire.TypeA), schKey(t, "corp.test.", dnswire.TypeNS),
		schKey(t, "www.corp.test.", dnswire.TypeA)}
}

// schMoved gives a schedule of schBase whose serial moved from 1 to 2 at
// both servers in the run that started at T0+7s and ended at T0+8s, with
// every zone check started again at T0+8s.
func schMoved(t testing.TB) *Schedule {
	t.Helper()
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	r, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 2, 2), schSec(8))
	if len(r.Moves) != 2 {
		t.Fatalf("serial 1 to 2 at both servers gave the moves %q", schMoveTexts(r.Moves))
	}
	if ok || len(moves) != 0 {
		t.Fatalf("the serial run that moved ended its round at once: %v %q", ok, schMoveTexts(moves))
	}
	schStart(t, s, schSec(8), schZoneKeys(t)...)
	return s
}

// schBothMoved are the moves of schMoved.
var schBothMoved = []string{
	"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+7.1s",
	"10.53.0.12:53 ns2.corp.test. serial 1 until T0+200ms, 2 since T0+7.2s",
}

// schWantJudged fails the test unless Judged gave ok and the moves wanted.
func schWantJudged(t testing.TB, what string, moves []decide.Move, ok bool, wantOK bool, want []string) {
	t.Helper()
	if ok != wantOK || !schSameMoves(schMoveTexts(moves), want) {
		t.Fatalf("%s: Judged gave %v %q, want %v %q", what, ok, schMoveTexts(moves), wantOK, want)
	}
}

func TestNewChecksAreThePlan(t *testing.T) {
	f, fast := schBase(t), schNames(t, "www.corp.test.")
	schSameChecks(t, "Checks", New(f, fast, schIv).Checks(), schModelPlan(t, f, fast, schIv))
}

func TestFirstDueStartsEveryCheckInPlanOrderAndNoneWhileTheyRun(t *testing.T) {
	f := schBase(t)
	s := New(f, nil, schIv)
	schSameChecks(t, "the first Due", s.Due(schT0), schModelPlan(t, f, nil, schIv))
	if got := s.Due(schAfter(time.Hour)); len(got) != 0 {
		t.Fatalf("an hour later, with every check running, Due gave%s", schShow(schKeyTexts(got)))
	}
	if next, ok := s.Next(); ok {
		t.Fatalf("Next gave %s while every check runs", schWhen(next))
	}
}

func TestCheckIsDueOneIntervalAfterTheStartThatDueGave(t *testing.T) {
	s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
	if next, ok := s.Next(); !ok || !next.IsZero() {
		t.Fatalf("Next of a new schedule gave %s %v, want the zero time", schWhen(next), ok)
	}
	// The runs start late and end later; the start that Due gave counts.
	for _, c := range schStart(t, s, schT0) {
		o := schUsable(t, c.Key, schAfter(500*time.Millisecond))
		if c.Key.Kind == obs.KindSerial {
			o = schSerialObs(t, schAfter(500*time.Millisecond), 1, 1)
		}
		schEnd(t, s, o, schSec(2))
	}
	waits := []struct {
		at   time.Duration
		want []string
	}{
		{7 * time.Second, []string{"serial corp.test. corp.test. SOA"}},
		{61 * time.Second, []string{"delegation corp.test. corp.test. NS", "ds corp.test. corp.test. DS"}},
		{300 * time.Second, []string{"records corp.test. www.corp.test. A"}},
	}
	for _, w := range waits {
		if next, ok := s.Next(); !ok || !next.Equal(schAfter(w.at)) {
			t.Fatalf("Next gave %s %v, want T0+%v", schWhen(next), ok, w.at)
		}
		if got := s.Due(schAfter(w.at - time.Nanosecond)); len(got) != 0 {
			t.Fatalf("Due one nanosecond before T0+%v gave%s", w.at, schShow(schKeyTexts(got)))
		}
		// What starts here keeps running, so it is not due again below.
		if got := schKeyTexts(s.Due(schAfter(w.at))); !slices.Equal(got, w.want) {
			t.Fatalf("Due(T0+%v) gave%s\nwant%s", w.at, schShow(got), schShow(w.want))
		}
	}
	if next, ok := s.Next(); ok {
		t.Fatalf("Next gave %s while every check runs", schWhen(next))
	}
}

func TestDueOrdersByDueTimeThenPlanOrder(t *testing.T) {
	s := New(schFile(t, "corp.test. A 10.53.0.80", "corp.test. MX 10 mail.corp.test.",
		"www.corp.test. A 10.53.0.81"), nil, schIv)
	schSettle(t, s)
	want := []string{
		"serial corp.test. corp.test. SOA",    // due at T0+7s
		"records corp.test. corp.test. A",     // T0+43s
		"records corp.test. corp.test. MX",    // T0+43s
		"delegation corp.test. corp.test. NS", // T0+61s
		"ds corp.test. corp.test. DS",         // T0+61s
		"records corp.test. www.corp.test. A", // T0+300s
	}
	if got := schKeyTexts(s.Due(schSec(300))); !slices.Equal(got, want) {
		t.Fatalf("Due(T0+300s) gave%s\nwant%s", schShow(got), schShow(want))
	}
}

// schManyLines are 20 lines, so that the plan has 23 checks.
func schManyLines() []string {
	var lines []string
	for i := range 20 {
		lines = append(lines, fmt.Sprintf("h%02d.corp.test. A none", i))
	}
	return lines
}

func TestDueStartsNoMoreThanMaxRunningAtOnce(t *testing.T) {
	f := schFile(t, schManyLines()...)
	s := New(f, nil, schIv)
	plan := schModelPlan(t, f, nil, schIv)
	schSameChecks(t, "the first Due", s.Due(schT0), plan[:MaxRunning])
	if next, ok := s.Next(); ok {
		t.Fatalf("Next gave %s while %d checks run", schWhen(next), MaxRunning)
	}
	if got := s.Due(schAfter(time.Hour)); len(got) != 0 {
		t.Fatalf("Due started%s while %d checks run", schShow(schKeyTexts(got)), MaxRunning)
	}
	if r := s.Done(schUsable(t, plan[3].Key, schT0), schSec(1)); !r.Known {
		t.Fatalf("Done of %s: not known", plan[3].Key)
	}
	if next, ok := s.Next(); !ok || !next.IsZero() {
		t.Fatalf("Next gave %s %v with a free slot and checks never started, want the zero time", schWhen(next), ok)
	}
	schSameChecks(t, "Due with one free slot", s.Due(schSec(2)), plan[MaxRunning:MaxRunning+1])
}

func TestDoneOfKeyOutsideThePlanIsUnknownAndChangesNothing(t *testing.T) {
	s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
	if got := s.Due(schT0); len(got) != 4 {
		t.Fatalf("Due(T0) gave%s", schShow(schKeyTexts(got)))
	}
	for _, o := range []obs.Observation{
		schFailed(t, schKey(t, "nothere.corp.test.", dnswire.TypeA), schT0),
		schPair(t, obs.SerialKey(schName(t, "shop.test.")), schT0, schSOA(t, 7), schSOA(t, 7)),
	} {
		r, moves, ok := schEnd(t, s, o, schSec(1))
		if r.Known || !r.FailingSince.IsZero() || len(r.Moves) != 0 || ok || len(moves) != 0 {
			t.Fatalf("Done and Judged of %s gave %+v, %v %q", o.Key, r, ok, schMoveTexts(moves))
		}
	}
	if got := s.Due(schAfter(time.Hour)); len(got) != 0 {
		t.Fatalf("an unknown key ended a run: Due gave%s", schShow(schKeyTexts(got)))
	}
}

func TestDoneReportsTierAndFailLimitOfTheCheck(t *testing.T) {
	f := schFile(t, "corp.test. A 10.53.0.80", "www.corp.test. A 10.53.0.81")
	cases := []struct {
		key   obs.Key
		tier  Tier
		limit time.Duration
	}{
		{schSerialKey(t), TierSerial, 60 * schIv.Serial},
		{obs.DelegationKey(schName(t, "corp.test.")), TierParent, 5 * schIv.Parent},
		{obs.DSKey(schName(t, "corp.test.")), TierParent, 5 * schIv.Parent},
		{schKey(t, "corp.test.", dnswire.TypeA), TierFast, 5 * schIv.Fast},
		{schKey(t, "www.corp.test.", dnswire.TypeA), TierOther, 3 * schIv.Other},
	}
	for _, failed := range []bool{false, true} {
		s := New(f, nil, schIv)
		schStart(t, s, schT0)
		for _, c := range cases {
			o := schUsable(t, c.key, schT0)
			if failed {
				o = schFailed(t, c.key, schT0)
			}
			r := s.Done(o, schSec(1))
			if !r.Known || r.Tier != c.tier || r.FailLimit != c.limit {
				t.Errorf("Done of %s (failed %v) gave known %v, tier %d, limit %v; want tier %d, limit %v",
					c.key, failed, r.Known, uint8(r.Tier), r.FailLimit, uint8(c.tier), c.limit)
			}
		}
	}
}

func TestFailingSinceIsTheStartOfTheFirstFailedRunUntilAUsableAnswer(t *testing.T) {
	s := New(schFile(t, "corp.test. A 10.53.0.80"), nil, schIv)
	k := schKey(t, "corp.test.", dnswire.TypeA)
	runs := []struct {
		o    obs.Observation
		want time.Time
	}{
		{schFailed(t, k, schSec(0)), schSec(0)},
		{schFailed(t, k, schSec(43)), schSec(0)},
		// One server of two answered: the check still sees the set.
		{schPair(t, k, schSec(86), schTimeout, schA(t)), time.Time{}},
		{schFailed(t, k, schSec(129)), schSec(129)},
		{schFailed(t, k, schSec(172)), schSec(129)},
		{schPair(t, k, schSec(215), schNoName(t, 1), schTimeout), time.Time{}},
		{schFailed(t, k, schSec(258)), schSec(258)},
		{schPair(t, k, schSec(301), schTimeout, schNoData(t, 1)), time.Time{}},
	}
	for i, run := range runs {
		schStart(t, s, run.o.Start, k)
		// Done comes 2 s after the start: the series counts from the start.
		r := s.Done(run.o, run.o.Start.Add(2*time.Second))
		if !r.FailingSince.Equal(run.want) {
			t.Fatalf("run %d at %s: FailingSince %s, want %s", i, schWhen(run.o.Start), schWhen(r.FailingSince),
				schWhen(run.want))
		}
	}
}

// schSerialRuns runs the serial check of s once for each observation, each
// started when it says, and gives the moves of each run.
func schSerialRuns(t testing.TB, s *Schedule, runs ...obs.Observation) [][]string {
	t.Helper()
	var got [][]string
	for _, o := range runs {
		schStart(t, s, o.Start, o.Key)
		r, _, _ := schEnd(t, s, o, o.Start.Add(time.Second))
		got = append(got, schMoveTexts(r.Moves))
	}
	return got
}

func schWantMoves(t testing.TB, got, want [][]string) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("the moves of each run:\n got %q\nwant %q", got, want)
	}
}

func TestSerialMoveNamesTheServerOldAndNewSerialAndWhenEachWasSeen(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	got := schSerialRuns(t, s,
		schSerialObs(t, schSec(0), 1, 1), // the first sight moves nothing
		schSerialObs(t, schSec(10), 1, 1),
		schSerialObs(t, schSec(20), 2, 1),
		schSerialObs(t, schSec(30), 2, 2),
	)
	schWantMoves(t, got, [][]string{{}, {},
		{"10.53.0.11:53 ns1.corp.test. serial 1 until T0+10.1s, 2 since T0+20.1s"},
		{"10.53.0.12:53 ns2.corp.test. serial 1 until T0+20.2s, 2 since T0+30.2s"},
	})
}

func TestSerialWithoutUsableAnswerKeepsTheLastSeenSerial(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	got := schSerialRuns(t, s,
		schSerialObs(t, schSec(0), 1, 0),
		schSerialObs(t, schSec(10), 0, 0),
		schSerialObs(t, schSec(20), 2, 0),
		schSerialObs(t, schSec(30), 2, 5), // the first sight of ns2
	)
	schWantMoves(t, got, [][]string{{}, {}, {"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+20.1s"}, {}})
}

func TestOnlyAnswersOfRecordsGiveASerial(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	k := schSerialKey(t)
	got := schSerialRuns(t, s,
		schSerialObs(t, schSec(0), 1, 1),
		schPair(t, k, schSec(10), schNoData(t, 9), schNoName(t, 9)),
		schSerialObs(t, schSec(20), 1, 1),
		schSerialObs(t, schSec(30), 1, 2),
	)
	schWantMoves(t, got, [][]string{{}, {}, {}, {"10.53.0.12:53 ns2.corp.test. serial 1 until T0+20.2s, 2 since T0+30.2s"}})
}

func TestSerialIsKeptForEachAddressNotEachHost(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	k := schSerialKey(t)
	run := func(start time.Time, v4, v6 uint32) obs.Observation {
		return schObs(k, start, schAt(t, "ns1.corp.test.", schNS1, start.Add(100*time.Millisecond), schSOA(t, v4)),
			schAt(t, "ns1.corp.test.", "[fd53::11]:53", start.Add(200*time.Millisecond), schSOA(t, v6)))
	}
	got := schSerialRuns(t, s, run(schSec(0), 1, 2), run(schSec(10), 1, 2), run(schSec(20), 1, 3))
	schWantMoves(t, got, [][]string{{}, {}, {"[fd53::11]:53 ns1.corp.test. serial 2 until T0+10.2s, 3 since T0+20.2s"}})
}

func TestRecordsCheckOfTheApexSOAIsNoSerialRun(t *testing.T) {
	s := New(schFile(t, "corp.test. SOA none"), nil, schIv)
	soa := schKey(t, "corp.test.", dnswire.TypeSOA)
	schStart(t, s, schT0, soa, schSerialKey(t))
	if r, _, _ := schEnd(t, s, schPair(t, soa, schT0, schSOA(t, 5), schSOA(t, 5)), schSec(1)); len(r.Moves) != 0 {
		t.Fatalf("the records check of the SOA set gave the moves %q", schMoveTexts(r.Moves))
	}
	if r, _, _ := schEnd(t, s, schSerialObs(t, schT0, 6, 6), schSec(1)); len(r.Moves) != 0 {
		t.Fatalf("the first serial run gave the moves %q", schMoveTexts(r.Moves))
	}
	got := schSerialRuns(t, s, schSerialObs(t, schSec(10), 7, 6))
	schWantMoves(t, got, [][]string{{"10.53.0.11:53 ns1.corp.test. serial 6 until T0+100ms, 7 since T0+10.1s"}})
}

func TestMoveMakesEveryZoneCheckDueAtOnce(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	schEnd(t, s, schSerialObs(t, schSec(7), 2, 2), schSec(8))
	want := schKeyTexts([]Check{{Key: schZoneKeys(t)[0]}, {Key: schZoneKeys(t)[1]}, {Key: schZoneKeys(t)[2]}})
	if got := schKeyTexts(s.Due(schSec(8))); !slices.Equal(got, want) {
		t.Fatalf("Due right after the move gave%s\nwant the zone checks%s", schShow(got), schShow(want))
	}
}

func TestZoneCheckRunningAtTheMoveRunsAgainAfterItsDoneAndItsRunDoesNotCount(t *testing.T) {
	zone := schZoneKeys(t)
	apexA, apexNS, www := zone[0], zone[1], zone[2]
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, www)
	schStart(t, s, schSec(7), schSerialKey(t))
	schEnd(t, s, schSerialObs(t, schSec(7), 2, 2), schSec(8))
	if got, want := schKeyTexts(s.Due(schSec(8))), []string{apexA.String(), apexNS.String()}; !slices.Equal(got, want) {
		t.Fatalf("Due right after the move gave%s\nwant%s", schShow(got), schShow(want))
	}
	for _, k := range []obs.Key{apexA, apexNS} {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9))
		schWantJudged(t, k.String(), moves, ok, false, nil)
	}
	_, moves, ok := schEnd(t, s, schUsable(t, www, schT0), schSec(10))
	schWantJudged(t, "the run of www that started before the move", moves, ok, false, nil)
	if got := schKeyTexts(s.Due(schSec(10))); !slices.Equal(got, []string{www.String()}) {
		t.Fatalf("Due after the run in flight ended gave%s\nwant %s", schShow(got), www)
	}
	_, moves, ok = schEnd(t, s, schUsable(t, www, schSec(10)), schSec(11))
	schWantJudged(t, "the run of www that started after the move", moves, ok, true, schBothMoved)
}

func TestTwoMovesWhileZoneChecksRunGiveOneStart(t *testing.T) {
	zone := schZoneKeys(t)
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, zone...)
	schSerialRuns(t, s, schSerialObs(t, schSec(7), 2, 2), schSerialObs(t, schSec(15), 3, 3))
	if got := s.Due(schSec(16)); len(got) != 0 {
		t.Fatalf("Due while the zone checks run gave%s", schShow(schKeyTexts(got)))
	}
	for _, k := range zone {
		schEnd(t, s, schUsable(t, k, schT0), schSec(17))
	}
	schStart(t, s, schSec(17), zone...)
	for _, k := range zone {
		schEnd(t, s, schUsable(t, k, schSec(17)), schSec(18))
	}
	if got := s.Due(schSec(21)); len(got) != 0 {
		t.Fatalf("Due after the zone checks ran once gave%s", schShow(schKeyTexts(got)))
	}
	schSerialRuns(t, s, schSerialObs(t, schSec(22), 3, 3))
	if got := s.Due(schSec(23)); len(got) != 0 {
		t.Fatalf("Due after a serial run without a move gave%s", schShow(schKeyTexts(got)))
	}
}

func TestRoundWithoutChangeEndsUnexplainedWithItsMoves(t *testing.T) {
	s := schMoved(t)
	for i, k := range schZoneKeys(t) {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i))
		if i < 2 {
			schWantJudged(t, k.String(), moves, ok, false, nil)
		} else {
			schWantJudged(t, "the last zone check", moves, ok, true, schBothMoved)
		}
	}
}

func TestRecordSetOrZoneChangeExplainsTheRound(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleRecordSet, decide.RuleZone} {
		for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
			s := schMoved(t)
			for i, k := range schZoneKeys(t) {
				var changes []decide.Change
				if i == 0 {
					changes = []decide.Change{{Op: op, Finding: decide.Finding{Rule: rule, Check: k}, At: schSec(9)}}
				}
				_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
				schWantJudged(t, fmt.Sprintf("%s %s, then %s", op, rule, k), moves, ok, false, nil)
			}
		}
	}
}

func TestOtherRulesLeaveTheRoundUnexplained(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleInvalidFile, decide.RuleNotCovered, decide.RuleNameServers} {
		s := schMoved(t)
		for i, k := range schZoneKeys(t) {
			changes := []decide.Change{{Op: decide.OpOpen, Finding: decide.Finding{Rule: rule, Check: k}, At: schSec(9)}}
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
			if i == 2 {
				schWantJudged(t, fmt.Sprintf("open %s, then %s", rule, k), moves, ok, true, schBothMoved)
			}
		}
	}
}

// A refresh only keeps the servers of an alert current and sends nothing,
// so it does not explain a round, also for a rule whose message would.
func TestRefreshLeavesTheRoundUnexplained(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleRecordSet, decide.RuleZone, decide.RuleSPF} {
		s := schMoved(t)
		for i, k := range schZoneKeys(t) {
			changes := []decide.Change{{Op: decide.OpRefresh, Finding: decide.Finding{Rule: rule, Check: k}, At: schSec(9)}}
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
			if i == 2 {
				schWantJudged(t, fmt.Sprintf("refresh %s, then %s", rule, k), moves, ok, true, schBothMoved)
			}
		}
	}
}

func TestChangeOfARunThatStartedAtTheLastQuietSerialVerdictExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	// The quiet serial run of the settling was judged at T0+1s; this is the
	// second run of its check, and it started then.
	change := decide.Change{Op: decide.OpOpen, Finding: decide.Finding{Rule: decide.RuleRecordSet, Check: zone[0]}, At: schSec(9)}
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(1)), schSec(9), change)
	schWantJudged(t, "the run with an old notice", moves, ok, false, nil)
	for i, k := range zone {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(9)), schSec(10+i))
		schWantJudged(t, k.String(), moves, ok, i == 2, map[bool][]string{true: schBothMoved}[i == 2])
	}
}

func TestFailedZoneRunStaysPendingUntilAUsableRun(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEnd(t, s, schFailed(t, zone[0], schSec(8)), schSec(9))
	schWantJudged(t, "a failed run", moves, ok, false, nil)
	for _, k := range zone[1:] {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(10))
		schWantJudged(t, k.String()+" while the apex A set failed", moves, ok, false, nil)
	}
	schStart(t, s, schSec(51), zone[0]) // its interval after its start at T0+8s
	_, moves, ok = schEnd(t, s, schUsable(t, zone[0], schSec(51)), schSec(52))
	schWantJudged(t, "the next usable run", moves, ok, true, schBothMoved)
}

func TestExplainedRoundStaysExplainedAfterAnotherMove(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	change := decide.Change{Op: decide.OpOpen, Finding: decide.Finding{Rule: decide.RuleRecordSet, Check: zone[0]}, At: schSec(9)}
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9), change)
	schSerialRuns(t, s, schSerialObs(t, schSec(14), 3, 3))
	schStart(t, s, schSec(15), zone[0])
	for _, k := range zone[1:] {
		schEnd(t, s, schUsable(t, k, schSec(8)), schSec(16))
	}
	schStart(t, s, schSec(16), zone[1:]...)
	for i, k := range zone {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(16)), schSec(17+i))
		schWantJudged(t, k.String()+" after the second move", moves, ok, false, nil)
	}
}

func TestNewMoveMakesEveryZoneCheckPendingAgainAndMergesTheMoves(t *testing.T) {
	zone := schZoneKeys(t)
	apexA, apexNS, www := zone[0], zone[1], zone[2]
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	schSerialRuns(t, s, schSerialObs(t, schSec(7), 2, 1))
	schStart(t, s, schSec(8), zone...)
	for _, k := range []obs.Key{apexA, apexNS} {
		schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9))
	}
	got := schSerialRuns(t, s, schSerialObs(t, schSec(14), 3, 3))
	schWantMoves(t, got, [][]string{{
		"10.53.0.11:53 ns1.corp.test. serial 2 until T0+7.1s, 3 since T0+14.1s",
		"10.53.0.12:53 ns2.corp.test. serial 1 until T0+7.2s, 3 since T0+14.2s",
	}})
	schStart(t, s, schSec(15), apexA, apexNS)
	schEnd(t, s, schUsable(t, www, schSec(8)), schSec(16))
	schStart(t, s, schSec(16), www)
	_, moves, ok := schEnd(t, s, schUsable(t, www, schSec(16)), schSec(17))
	schWantJudged(t, "www, with the apex sets pending again", moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, apexA, schSec(15)), schSec(18))
	schWantJudged(t, "the apex A set", moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, apexNS, schSec(15)), schSec(19))
	schWantJudged(t, "the last zone check", moves, ok, true, []string{
		"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 3 since T0+14.1s",
		"10.53.0.12:53 ns2.corp.test. serial 1 until T0+7.2s, 3 since T0+14.2s",
	})
}

func TestZoneWithoutZoneChecksEndsTheRoundAtOnce(t *testing.T) {
	s := New(schFile(t, "sub.corp.test. NS ns1.sub.corp.test.", "www.sub.corp.test. A 10.53.0.85",
		"edge.dnshost.test. A 10.53.0.84"), nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 2, 1), schSec(8))
	schWantJudged(t, "the serial run that moved", moves, ok, true,
		[]string{"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+7.1s"})
}

func TestFirstSerialRunWithoutMoveIsQuiet(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schStart(t, s, schT0, schSerialKey(t))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schT0, 1, 1), schSec(1))
	schWantJudged(t, "the first serial run", moves, ok, true, nil)
}

func TestQuietComesOneOtherIntervalAfterTheLastUnexplainedRound(t *testing.T) {
	s := schMoved(t)
	zone := schZoneKeys(t)
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9))
	schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(9))
	_, moves, ok := schEnd(t, s, schUsable(t, zone[2], schSec(8)), schSec(10))
	schWantJudged(t, "the end of the round", moves, ok, true, schBothMoved)
	end := schSec(10)
	early := end.Add(schIv.Other - 8*time.Second)
	schStart(t, s, early, schSerialKey(t))
	_, moves, ok = schEnd(t, s, schSerialObs(t, early, 2, 2), end.Add(schIv.Other-time.Nanosecond))
	schWantJudged(t, "a serial run without move 1 ns before the other interval", moves, ok, false, nil)
	late := end.Add(schIv.Other - time.Second)
	schStart(t, s, late, schSerialKey(t))
	_, moves, ok = schEnd(t, s, schSerialObs(t, late, 2, 2), end.Add(schIv.Other))
	schWantJudged(t, "a serial run without move one other interval after", moves, ok, true, nil)
}

func TestNoQuietWhileARoundIsPending(t *testing.T) {
	s := schMoved(t)
	schStart(t, s, schSec(14), schSerialKey(t))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(14), 2, 2), schSec(15))
	schWantJudged(t, "a serial run without move while the zone checks run", moves, ok, false, nil)
}

func TestQuietOnlyForTheSerialCheck(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	k := schZoneKeys(t)[0]
	schStart(t, s, schSec(43), k)
	_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(43)), schSec(44))
	schWantJudged(t, "a records check with no round", moves, ok, false, nil)
}

// A serial run without a usable answer sees no serial, so it cannot say that
// the serial stayed: the notice stays open while the tool is blind.
func TestNoQuietOnASerialRunWithoutUsableAnswer(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 0, 0), schSec(8))
	schWantJudged(t, "a failed serial run", moves, ok, false, nil)
	schStart(t, s, schSec(14), schSerialKey(t))
	_, moves, ok = schEnd(t, s, schSerialObs(t, schSec(14), 0, 1), schSec(15))
	schWantJudged(t, "a serial run with one usable answer", moves, ok, true, nil)
}

func TestJudgedOfKeyOutsideThePlanIsFalse(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	o := schSerialObs(t, schSec(7), 1, 1)
	o.Key = obs.SerialKey(schName(t, "shop.test."))
	if moves, ok := s.Judged(o, nil, nil, schSec(8)); ok || len(moves) != 0 {
		t.Fatalf("Judged of %s gave %v %q", o.Key, ok, schMoveTexts(moves))
	}
}

// schBaseAndMail is schBase with mail.corp.test. A added.
func schBaseAndMail(t testing.TB) *expect.File {
	t.Helper()
	return schFile(t,
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81",
		"mail.corp.test. A 10.53.0.82",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"edge.dnshost.test. A 10.53.0.84",
	)
}

func TestReplaceGivesTheNewPlanWithEveryCheckDueAtOnce(t *testing.T) {
	fast := schNames(t, "mail.corp.test.")
	s := New(schBase(t), fast, schIv)
	schSettle(t, s)
	f2 := schFile(t, "corp.test. A 10.53.0.80", "mail.corp.test. A 10.53.0.82", "edge.dnshost.test. A 10.53.0.84")
	s.Replace(f2)
	want := schModelPlan(t, f2, fast, schIv)
	schSameChecks(t, "Checks after Replace", s.Checks(), want)
	schSameChecks(t, "Due right after Replace", s.Due(schSec(2)), want)
}

func TestReplaceKeepsRunningChecksRunning(t *testing.T) {
	www := schZoneKeys(t)[2]
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, www)
	s.Replace(schBaseAndMail(t))
	var want []Check
	for _, c := range schModelPlan(t, schBaseAndMail(t), nil, schIv) {
		if c.Key.String() != www.String() {
			want = append(want, c)
		}
	}
	schSameChecks(t, "Due right after Replace", s.Due(schSec(2)), want)
}

// A check that left the plan still has its queries in flight, so it holds
// its place among the checks that run until its Done.
func TestKeyThatLeftThePlanHoldsItsSlotUntilItsDone(t *testing.T) {
	lines := schManyLines()
	s := New(schFile(t, lines...), nil, schIv)
	if got := s.Due(schT0); len(got) != MaxRunning {
		t.Fatalf("Due(T0) started %d checks, want %d", len(got), MaxRunning)
	}
	s.Replace(schFile(t, lines[1:]...))
	if got := s.Due(schSec(1)); len(got) != 0 {
		t.Fatalf("Due started%s while %d checks ran", schShow(schKeyTexts(got)), MaxRunning)
	}
	if next, ok := s.Next(); ok {
		t.Fatalf("Next gave %s while %d checks ran", schWhen(next), MaxRunning)
	}
	left := schKey(t, "h00.corp.test.", dnswire.TypeA)
	r, moves, ok := schEnd(t, s, schUsable(t, left, schT0), schSec(2))
	if r.Known || ok || len(moves) != 0 {
		t.Fatalf("Done and Judged of the key that left gave %+v, %v %q", r, ok, schMoveTexts(moves))
	}
	if got, want := schKeyTexts(s.Due(schSec(2))), []string{"records corp.test. h13.corp.test. A"}; !slices.Equal(got, want) {
		t.Fatalf("Due after the key that left ended gave%s\nwant%s", schShow(got), schShow(want))
	}
}

func TestReplaceKeepsTheFailureSeries(t *testing.T) {
	k := schZoneKeys(t)[0]
	s := New(schBase(t), nil, schIv)
	schStart(t, s, schT0, k)
	if r := s.Done(schFailed(t, k, schT0), schSec(1)); !r.FailingSince.Equal(schT0) {
		t.Fatalf("the first failed run gave FailingSince %s", schWhen(r.FailingSince))
	}
	s.Replace(schBaseAndMail(t))
	schStart(t, s, schSec(2), k)
	if r := s.Done(schFailed(t, k, schSec(2)), schSec(3)); !r.FailingSince.Equal(schT0) {
		t.Fatalf("the failed run after Replace gave FailingSince %s, want T0", schWhen(r.FailingSince))
	}
}

func TestReplaceKeepsTheSerialMemory(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	s.Replace(schBaseAndMail(t))
	got := schSerialRuns(t, s, schSerialObs(t, schSec(2), 2, 1))
	schWantMoves(t, got, [][]string{{"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+2.1s"}})
}

func TestReplaceKeepsInTheRoundOnlyKeysThatAreStillZoneChecks(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9))
	// www becomes a cut, and mail is a new zone check: neither is pending.
	s.Replace(schFile(t,
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81",
		"www.corp.test. NS ns1.www.corp.test.",
		"mail.corp.test. A 10.53.0.82",
	))
	_, moves, ok := schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(10))
	schWantJudged(t, "the last zone check still pending", moves, ok, true, schBothMoved)
}

// Replace returns nothing, so a round that it leaves without a pending check
// ends at the next Judged, as a round of a zone without zone checks does.
func TestRoundEmptiedByReplaceEndsAtTheNextJudged(t *testing.T) {
	s := schMoved(t)
	s.Replace(schFile(t, "sub.corp.test. NS ns1.sub.corp.test.", "edge.dnshost.test. A 10.53.0.84"))
	schStart(t, s, schSec(14), schSerialKey(t))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(14), 2, 2), schSec(15))
	schWantJudged(t, "the serial run after Replace", moves, ok, true, schBothMoved)
}

// A failed run gives no notice, so its change explains nothing.
func TestFailedZoneRunGivesNoNotice(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9))
	schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(9))
	change := decide.Change{Op: decide.OpOpen, Finding: decide.Finding{Rule: decide.RuleRecordSet, Check: zone[2]}, At: schSec(53)}
	_, moves, ok := schEnd(t, s, schFailed(t, zone[2], schSec(8)), schSec(53), change)
	schWantJudged(t, "a failed run with a change", moves, ok, false, nil)
	schStart(t, s, schSec(308), zone[2]) // its interval after its start at T0+8s
	_, moves, ok = schEnd(t, s, schUsable(t, zone[2], schSec(308)), schSec(309))
	schWantJudged(t, "the last pending check", moves, ok, true, schBothMoved)
}

// A second run of a check that already left the round gives a notice that
// started after the move, so it explains the round, which then waits for the
// checks that are still pending.
func TestSecondRunOfAZoneCheckWithANoticeExplainsTheRound(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9))
	schStart(t, s, schSec(51), zone[0])
	change := decide.Change{Op: decide.OpOpen, Finding: decide.Finding{Rule: decide.RuleRecordSet, Check: zone[0]}, At: schSec(52)}
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(51)), schSec(52), change)
	schWantJudged(t, "a second run with a change", moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(53))
	schWantJudged(t, zone[1].String(), moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, zone[2], schSec(8)), schSec(53))
	schWantJudged(t, "the last pending check", moves, ok, false, nil)
}

// At the instant of a move, a run that starts then is part of the round: it
// counts, and the move does not start it again.
func TestRunStartedAtTheInstantOfTheMoveCountsAndIsNotStartedAgain(t *testing.T) {
	zone := schZoneKeys(t)
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	if got := schKeyTexts(schStart(t, s, schSec(42), schSerialKey(t))); len(got) != 1 {
		t.Fatalf("Due(T0+42s) gave%s", schShow(got))
	}
	if got := schKeyTexts(schStart(t, s, schSec(43), zone[0])); len(got) != 1 {
		t.Fatalf("Due(T0+43s) gave%s", schShow(got))
	}
	schEnd(t, s, schSerialObs(t, schSec(42), 2, 2), schSec(43))
	if got, want := schKeyTexts(s.Due(schSec(43))), []string{zone[1].String(), zone[2].String()}; !slices.Equal(got, want) {
		t.Fatalf("Due at the instant of the move gave%s\nwant%s", schShow(got), schShow(want))
	}
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(43)), schSec(44))
	schWantJudged(t, zone[0].String(), moves, ok, false, nil)
	if got := s.Due(schSec(44)); len(got) != 0 {
		t.Fatalf("Due after the run that started at the move gave%s", schShow(schKeyTexts(got)))
	}
	schEnd(t, s, schUsable(t, zone[1], schSec(43)), schSec(45))
	_, moves, ok = schEnd(t, s, schUsable(t, zone[2], schSec(43)), schSec(45))
	schWantJudged(t, "the last zone check", moves, ok, true, []string{
		"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+42.1s",
		"10.53.0.12:53 ns2.corp.test. serial 1 until T0+200ms, 2 since T0+42.2s",
	})
}

// schDrive starts every check due at at and ends each one second later: the
// serial check with serial at both servers, a check that blind names with a
// failed run, every other check with a usable one. It fails unless every key
// of want started. It gives the moves of each report, and how many serial
// runs were quiet.
func schDrive(t testing.TB, s *Schedule, at time.Time, serial uint32, blind func(obs.Key) bool, want ...obs.Key) (reports [][]decide.Move, quiet int) {
	t.Helper()
	for _, c := range schStart(t, s, at, want...) {
		o := schUsable(t, c.Key, at)
		switch {
		case c.Key.Kind == obs.KindSerial:
			o = schSerialObs(t, at, serial, serial)
		case blind != nil && blind(c.Key):
			o = schFailed(t, c.Key, at)
		}
		_, moves, ok := schEnd(t, s, o, at.Add(time.Second))
		switch {
		case ok && len(moves) > 0:
			reports = append(reports, moves)
		case ok:
			quiet++
		}
	}
	return reports, quiet
}

// A serial that moves to a new value at every serial run, as a serial taken
// from the clock gives, is reported at most once for each other-interval. The zone checks still run at once after each move, and the
// last report names the newest serial of each server.
func TestMovingSerialIsReportedAtMostOncePerOtherInterval(t *testing.T) {
	iv := Defaults()
	s := New(schBase(t), nil, iv)
	schSettle(t, s)
	var at []time.Time
	var last []decide.Move
	note := func(when time.Time, reports [][]decide.Move) {
		for _, r := range reports {
			at, last = append(at, when), r
		}
	}
	serial := uint32(1)
	run := schT0
	for range 40 {
		serial++
		run = run.Add(iv.Serial)
		r, _ := schDrive(t, s, run, serial, nil, schSerialKey(t))
		note(run.Add(time.Second), r)
		r, _ = schDrive(t, s, run.Add(time.Second), serial, nil, schZoneKeys(t)...)
		note(run.Add(2*time.Second), r)
	}
	// The serial stays; the moves held back are told once the interval has
	// passed.
	for range 25 {
		run = run.Add(iv.Serial)
		r, _ := schDrive(t, s, run, serial, nil, schSerialKey(t))
		note(run.Add(time.Second), r)
		if len(at) > 0 && !at[len(at)-1].Before(run) {
			break
		}
	}
	if len(at) < 2 {
		t.Fatalf("40 moves gave %d reports, want one at the first move and later ones", len(at))
	}
	for i := 1; i < len(at); i++ {
		if at[i].Sub(at[i-1]) < iv.Other {
			t.Errorf("reports at %s and %s, less than one other-interval apart", schWhen(at[i-1]), schWhen(at[i]))
		}
	}
	if len(last) != 2 || last[0].To != serial || last[1].To != serial {
		t.Errorf("the last report, at %s, gave %q; want serial %d at both servers", schWhen(at[len(at)-1]), schMoveTexts(last), serial)
	}
}

// Moves held back by the bound are told at the first serial run without a
// move one other-interval after the last report; the notice cannot end
// before they are told, and ends one other-interval after that.
func TestHeldMovesAreToldBeforeTheNoticeEnds(t *testing.T) {
	iv := Defaults()
	s := New(schBase(t), nil, iv)
	schSettle(t, s)
	schDrive(t, s, schSec(15), 2, nil, schSerialKey(t))
	if r, _ := schDrive(t, s, schSec(16), 2, nil, schZoneKeys(t)...); len(r) != 1 {
		t.Fatalf("the first move gave %d reports, want 1", len(r))
	}
	first := schSec(17)
	schDrive(t, s, schSec(30), 3, nil, schSerialKey(t))
	if r, _ := schDrive(t, s, schSec(31), 3, nil, schZoneKeys(t)...); len(r) != 0 {
		t.Fatalf("a move 15 s after the last report was told at once: %q", schMoveTexts(r[0]))
	}
	var told, quiet time.Time
	for run := schSec(45); run.Before(schSec(1000)) && quiet.IsZero(); run = run.Add(iv.Serial) {
		r, q := schDrive(t, s, run, 3, nil, schSerialKey(t))
		switch {
		case len(r) == 1 && told.IsZero():
			told = run.Add(time.Second)
			if want := []string{
				"10.53.0.11:53 ns1.corp.test. serial 2 until T0+15.1s, 3 since T0+30.1s",
				"10.53.0.12:53 ns2.corp.test. serial 2 until T0+15.2s, 3 since T0+30.2s",
			}; !schSameMoves(schMoveTexts(r[0]), want) {
				t.Errorf("the held moves were told as %q, want %q", schMoveTexts(r[0]), want)
			}
		case len(r) > 0:
			t.Fatalf("a second report at %s: %q", schWhen(run.Add(time.Second)), schMoveTexts(r[0]))
		case q > 0:
			quiet = run.Add(time.Second)
		}
	}
	if told.IsZero() || told.Sub(first) < iv.Other || told.Sub(first) >= iv.Other+iv.Serial {
		t.Errorf("the held moves were told at %s, want within one serial interval after %s", schWhen(told), schWhen(first.Add(iv.Other)))
	}
	if quiet.IsZero() || quiet.Sub(told) < iv.Other || quiet.Sub(told) >= iv.Other+iv.Serial {
		t.Errorf("the notice may end at %s, want within one serial interval after %s", schWhen(quiet), schWhen(told.Add(iv.Other)))
	}
}

// A zone check that has failed past its limit cannot see the zone. Its
// check-failing alert tells of it, so the round stops waiting for it at the
// run that passes the limit, and the move is reported.
func TestZoneCheckBlindPastItsLimitNoLongerHoldsTheRound(t *testing.T) {
	iv := Defaults()
	s := New(schBase(t), nil, iv)
	schSettle(t, s)
	www := schKey(t, "www.corp.test.", dnswire.TypeA)
	blind := func(k obs.Key) bool { return k.String() == www.String() }
	schDrive(t, s, schSec(15), 2, blind, schSerialKey(t))
	// www fails from its run at T0+16s on; it runs every other-interval.
	pastLimit := schSec(16).Add(iv.FailLimit(TierOther))
	var reported time.Time
	var moves []decide.Move
	for at := schSec(16); at.Before(pastLimit.Add(iv.Other)) && reported.IsZero(); at = at.Add(time.Second) {
		if r, _ := schDrive(t, s, at, 2, blind); len(r) > 0 {
			reported, moves = at.Add(time.Second), r[0]
		}
	}
	if want := pastLimit.Add(time.Second); !reported.Equal(want) {
		t.Fatalf("the move was reported at %s, want at %s, when the run of www that passes its limit ends", schWhen(reported), schWhen(want))
	}
	if want := []string{
		"10.53.0.11:53 ns1.corp.test. serial 1 until T0+100ms, 2 since T0+15.1s",
		"10.53.0.12:53 ns2.corp.test. serial 1 until T0+200ms, 2 since T0+15.2s",
	}; !schSameMoves(schMoveTexts(moves), want) {
		t.Errorf("the report gave %q, want %q", schMoveTexts(moves), want)
	}
}

// ---- The property: a model of the rules, run against the code ----

type schSeen struct {
	serial uint32
	at     time.Time
}

type schRound struct {
	pending  map[string]bool
	moves    []schEntry
	since    time.Time       // the quiet instant when the round was created
	standing map[string]bool // zone checks whose run since the last move had an open record-set or zone alert
	ended    time.Time       // zero while the zone checks run; else the end of the checks, and the round waits
}

// schEntry is the moves of one address merged, as a round or the report
// keeps them.
type schEntry struct {
	move decide.Move
	news bool // one of the moves went to a serial that was not known
}

// schMergeEntry keeps the first From and Until and the last To and Since of
// each address; news when one of its moves was.
func schMergeEntry(entries []schEntry, e schEntry) []schEntry {
	for i := range entries {
		if entries[i].move.Server.Addr == e.move.Server.Addr {
			entries[i].move.To, entries[i].move.Since = e.move.To, e.move.Since
			entries[i].news = entries[i].news || e.news
			return entries
		}
	}
	return append(entries, e)
}

// schModel is the schedule as the rules state it, kept by key text and by
// address.
type schModel struct {
	iv         Intervals
	plan       []Check
	keys       []string             // the key text of each check of plan
	index      map[string]int       // the place of each key text in plan
	start      map[string]time.Time // the last start; Replace forgets it
	running    map[string]time.Time // the start of each run in flight
	series     map[string]time.Time
	unsure     map[string]bool // left the plan with a series: kept or dropped
	serials    map[string]schSeen
	known      map[uint32]bool // first seen at an address, or told; a set, as the cases give serials 1 to 4 only, far below the bound
	moved      time.Time
	quiet      time.Time       // when the last serial run with an answer and no move was judged
	noticed    time.Time       // the latest start of a run of a zone check with a notice of its own
	judgedOnce map[string]bool // the keys judged since the plan was made or replaced
	early      int             // rounds that a notice started before their move explained
	waits      int             // rounds that waited for the next run of a check whose difference stood
	folds      int             // moves that joined a round that waited
	waitEnds   int             // waits that a notice ended
	round      *schRound
	held       []schEntry // the moves of unexplained rounds not told yet
	lastReport time.Time  // when moves were last told
}

func schNewModel(plan []Check, iv Intervals) *schModel {
	m := &schModel{iv: iv, start: map[string]time.Time{}, running: map[string]time.Time{},
		series: map[string]time.Time{}, unsure: map[string]bool{}, serials: map[string]schSeen{},
		known: map[uint32]bool{}, judgedOnce: map[string]bool{}}
	m.setPlan(plan)
	return m
}

func (m *schModel) setPlan(plan []Check) {
	m.plan, m.keys, m.index = plan, schKeyTexts(plan), map[string]int{}
	for i, k := range m.keys {
		m.index[k] = i
	}
}

func (m *schModel) find(k string) (Check, bool) {
	i, ok := m.index[k]
	if !ok {
		return Check{}, false
	}
	return m.plan[i], true
}

func (m *schModel) dueAt(i int) time.Time {
	c := m.plan[i]
	st, ok := m.start[m.keys[i]]
	switch {
	case !ok:
		return time.Time{}
	// A zone check that was already due before the move keeps the earlier
	// time.
	case c.Zone && m.moved.After(st) && m.moved.Before(st.Add(c.Interval)):
		return m.moved
	}
	return st.Add(c.Interval)
}

// due gives what Due(now) must give, and whether the cap held some back.
func (m *schModel) due(now time.Time) ([]Check, bool) {
	var due []int
	for i, k := range m.keys {
		if _, run := m.running[k]; !run && !m.dueAt(i).After(now) {
			due = append(due, i)
		}
	}
	slices.SortStableFunc(due, func(a, b int) int { return m.dueAt(a).Compare(m.dueAt(b)) })
	free := max(0, MaxRunning-len(m.running))
	capped := len(due) > free
	var checks []Check
	for _, i := range due[:min(len(due), free)] {
		checks = append(checks, m.plan[i])
		m.start[m.keys[i]], m.running[m.keys[i]] = now, now
	}
	return checks, capped
}

func (m *schModel) next() (time.Time, bool) {
	if len(m.running) >= MaxRunning {
		return time.Time{}, false
	}
	var at time.Time
	found := false
	for i, k := range m.keys {
		if _, run := m.running[k]; !run && (!found || m.dueAt(i).Before(at)) {
			at, found = m.dueAt(i), true
		}
	}
	return at, found
}

func (m *schModel) limit(tier Tier) time.Duration {
	return map[Tier]time.Duration{TierSerial: 60 * m.iv.Serial, TierParent: 5 * m.iv.Parent,
		TierFast: 5 * m.iv.Fast, TierOther: 3 * m.iv.Other}[tier]
}

// done gives the Report that Done must give. When the key came back to the
// plan with a series, alt is the other FailingSince that is allowed.
func (m *schModel) done(o obs.Observation, failed bool, now time.Time) (want Report, alt time.Time) {
	k := o.Key.String()
	delete(m.running, k)
	c, known := m.find(k)
	if !known {
		return Report{}, time.Time{}
	}
	want = Report{Known: true, Tier: c.Tier, FailLimit: m.limit(c.Tier)}
	if failed {
		if _, ok := m.series[k]; !ok {
			m.series[k] = o.Start
		} else if m.unsure[k] {
			alt = o.Start
		}
		want.FailingSince = m.series[k]
	} else {
		delete(m.series, k)
	}
	delete(m.unsure, k)
	if o.Key.Kind == obs.KindSerial {
		want.Moves = m.serialRun(o, now)
		// The serial is seen unchanged only when no earlier move waits.
		want.Quiet = !failed && len(want.Moves) == 0 && m.round == nil && len(m.held) == 0
	}
	return want, alt
}

// schSerialOf gives the serial of an answer of records that holds a SOA
// record; other answers give none.
func schSerialOf(r obs.Result) (uint32, bool) {
	type found struct {
		serial uint32
		ok     bool
	}
	nothing := func() found { return found{} }
	f := obs.Match(r, func(rs obs.Records) found {
		for _, rr := range rs.Set {
			if soa, ok := rr.Data.(dnswire.SOA); ok {
				return found{soa.Serial, true}
			}
		}
		return nothing()
	}, func(obs.NoData) found { return nothing() }, func(obs.NoName) found { return nothing() },
		func(obs.Failure) found { return nothing() })
	return f.serial, f.ok
}

func (m *schModel) serialRun(o obs.Observation, now time.Time) []decide.Move {
	var moves []decide.Move
	var entries []schEntry
	var first []uint32
	for _, a := range o.Answers {
		serial, ok := schSerialOf(a.Result)
		if !ok {
			continue
		}
		addr := a.Server.Addr.String()
		old, seen := m.serials[addr]
		switch {
		case !seen:
			first = append(first, serial)
		case old.serial != serial:
			mv := decide.Move{Server: a.Server, From: old.serial, To: serial, Until: old.at, Since: a.Received}
			moves = append(moves, mv)
			entries = append(entries, schEntry{mv, !m.known[serial]})
		}
		m.serials[addr] = schSeen{serial, a.Received}
	}
	// A first sight in the run makes no move of the same run old.
	for _, serial := range first {
		m.known[serial] = true
	}
	if len(moves) == 0 {
		return nil
	}
	m.moved = now
	switch {
	case m.round == nil:
		m.round = &schRound{since: m.quiet}
	case !m.round.ended.IsZero():
		// The waiting moves join the round of this move, with their window.
		m.folds++
	}
	for _, e := range entries {
		m.round.moves = schMergeEntry(m.round.moves, e)
	}
	m.round.pending, m.round.standing, m.round.ended = map[string]bool{}, map[string]bool{}, time.Time{}
	for i, c := range m.plan {
		if c.Zone {
			m.round.pending[m.keys[i]] = true
		}
	}
	return moves
}

func schExplains(changes []decide.Change) bool {
	return slices.ContainsFunc(changes, func(c decide.Change) bool {
		return c.Finding.Rule == decide.RuleRecordSet || c.Finding.Rule == decide.RuleZone
	})
}

// schStands reports an open record-set or zone alert of the check k: its
// difference stands, or the run ended it with a notice.
func schStands(k string, open []decide.Finding) bool {
	return slices.ContainsFunc(open, func(f decide.Finding) bool {
		return f.Check.String() == k && (f.Rule == decide.RuleRecordSet || f.Rule == decide.RuleZone)
	})
}

type schVerdict struct {
	moves          []decide.Move
	ok             bool
	explainedEnded bool
	held           bool // unexplained moves wait: the last report is less than an other-interval ago
	flushed        bool // a quiet serial run told the moves that waited
	excused        bool // a zone check past its failure limit left the round
	nothingNew     bool // an unexplained round ended, and no address has news to tell
}

// told is the rule of the reports: the moves that wait are told at once when
// none was told yet or the last report is one other-interval old, else they
// keep waiting. The serials told are known from then on.
func (m *schModel) told(now time.Time) schVerdict {
	if !m.lastReport.IsZero() && now.Sub(m.lastReport) < m.iv.Other {
		return schVerdict{held: true}
	}
	v := schVerdict{ok: true}
	for _, e := range m.held {
		v.moves = append(v.moves, e.move)
		m.known[e.move.To] = true
	}
	m.held, m.lastReport = nil, now
	return v
}

func (m *schModel) judged(o obs.Observation, failed, moved bool, open []decide.Finding, changes []decide.Change, now time.Time) schVerdict {
	k := o.Key.String()
	c, known := m.find(k)
	if !known {
		return schVerdict{}
	}
	// The first usable run of a check after the plan was made gives no
	// notice: it may have seen a change that came before the service.
	first := !m.judgedOnce[k]
	m.judgedOnce[k] = m.judgedOnce[k] || !failed
	if c.Zone && !first && !failed && schExplains(changes) && o.Start.After(m.noticed) {
		m.noticed = o.Start
	}
	if o.Key.Kind == obs.KindSerial && !moved && !failed {
		m.quiet = now
	}
	if r := m.round; r != nil {
		// While the round waits, only a run that started at or after the end
		// of its zone checks counts.
		waiting := !r.ended.IsZero()
		if c.Zone && !o.Start.Before(m.moved) && !o.Start.Before(r.ended) && !failed && r.pending[k] {
			delete(r.pending, k)
			if !waiting && schStands(k, open) {
				r.standing[k] = true
			}
		}
		excused := false
		if since, ok := m.series[k]; r.pending[k] && failed && ok && now.Sub(since) >= m.limit(c.Tier) {
			delete(r.pending, k)
			excused = true
		}
		// A notice that started after the serial was last quiet, before the
		// round was created, belongs to the change of the round, whether it
		// came before or after the move. It ends a wait at once.
		explained := m.noticed.After(r.since)
		if len(r.pending) > 0 && !(waiting && explained) {
			return schVerdict{excused: excused}
		}
		if explained {
			m.round = nil
			if m.noticed.Before(m.moved) {
				m.early++
			}
			if waiting {
				m.waitEnds++
			}
			for _, e := range r.moves {
				m.known[e.move.To] = true
			}
			return schVerdict{explainedEnded: true, excused: excused}
		}
		// A difference that stood may end at the next run of its check.
		if !waiting && len(r.standing) > 0 {
			r.pending, r.standing, r.ended = r.standing, map[string]bool{}, now
			m.waits++
			return schVerdict{excused: excused}
		}
		m.round = nil
		m.hold(r.moves)
		if len(m.held) == 0 {
			return schVerdict{excused: excused, nothingNew: true}
		}
		v := m.told(now)
		v.excused = excused
		return v
	}
	if o.Key.Kind != obs.KindSerial || moved || failed {
		return schVerdict{}
	}
	if len(m.held) > 0 {
		v := m.told(now)
		v.flushed = v.ok
		return v
	}
	return schVerdict{ok: m.lastReport.IsZero() || now.Sub(m.lastReport) >= m.iv.Other}
}

// hold merges moves into the held ones. Only an address with news that is
// not back at its first serial is held.
func (m *schModel) hold(moves []schEntry) {
	for _, e := range moves {
		m.held = schMergeEntry(m.held, e)
	}
	var tell []schEntry
	for _, e := range m.held {
		if e.news && e.move.From != e.move.To {
			tell = append(tell, e)
		}
	}
	m.held = tell
}

// flush is Flush: the held moves and those of a round that waits are told,
// with no bound.
func (m *schModel) flush(now time.Time) []decide.Move {
	if r := m.round; r != nil && !r.ended.IsZero() {
		m.round = nil
		m.hold(r.moves)
	}
	var moves []decide.Move
	for _, e := range m.held {
		moves = append(moves, e.move)
		m.known[e.move.To] = true
	}
	if len(moves) > 0 {
		m.lastReport = now
	}
	m.held = nil
	return moves
}

func (m *schModel) replace(plan []Check) {
	m.setPlan(plan)
	for k := range m.series {
		if _, in := m.find(k); !in {
			m.unsure[k] = true
		}
	}
	clear(m.start)
	clear(m.judgedOnce)
	if m.round != nil {
		for _, set := range []map[string]bool{m.round.pending, m.round.standing} {
			for k := range set {
				if c, in := m.find(k); !in || !c.Zone {
					delete(set, k)
				}
			}
		}
	}
}

type schCounts struct {
	capped, moves, unexplained, explained, replaced, quiet, series, held, flushed, excused, early, nothingNew int
	waits, folds, waitEnds, stops                                                                             int
}

type schInFlight struct {
	key   obs.Key
	start time.Time
}

// schSim drives the code and a twin with the same calls, and the model.
type schSim struct {
	t       *testing.T
	rng     *rand.Rand
	c, act  int
	file    *expect.File
	fast    []dnswire.Name
	s, twin *Schedule
	m       *schModel
	now     time.Time
	run     map[string]schInFlight // the trace: what Due gave and Done did not end
	last    map[string]time.Time   // the trace: the last start since the last Replace
	moves   []time.Time            // the trace: the time of each Done that gave moves
	alerts  map[string]decide.Rule // the open alert of each check, as decide is given it
	n       *schCounts
	kit     *schKit
}

func (sim *schSim) fail(format string, args ...any) {
	sim.t.Helper()
	sim.t.Fatalf("%s: %s", sim.where(), fmt.Sprintf(format, args...))
}

func (sim *schSim) where() string {
	return fmt.Sprintf("seed %d case %d action %d", schSeed, sim.c, sim.act)
}

func (sim *schSim) advance(least time.Duration) {
	gaps := []time.Duration{0, time.Nanosecond, time.Millisecond, time.Second, 5 * time.Second, 30 * time.Second}
	sim.now = sim.now.Add(least + schPick(sim.rng, gaps...)*time.Duration(1+sim.rng.IntN(4)))
}

func (sim *schSim) movedIn(after, upTo time.Time) bool {
	return slices.ContainsFunc(sim.moves, func(m time.Time) bool { return m.After(after) && !m.After(upTo) })
}

func (sim *schSim) due() []Check {
	sim.t.Helper()
	got, twin := sim.s.Due(sim.now), sim.twin.Due(sim.now)
	if !reflect.DeepEqual(got, twin) {
		sim.fail("an equal schedule gave Due%s\nthe first%s", schShow(schTexts(twin)), schShow(schTexts(got)))
	}
	want, capped := sim.m.due(sim.now)
	if !slices.EqualFunc(got, want, func(a, b Check) bool {
		return a.Tier == b.Tier && a.Interval == b.Interval && a.Zone == b.Zone && a.Key.String() == b.Key.String()
	}) {
		sim.fail("Due(%s) gave%s\nwant%s", schWhen(sim.now), schShow(schTexts(got)), schShow(schTexts(want)))
	}
	if capped {
		sim.n.capped++
	}
	for _, c := range got {
		k := c.Key.String()
		if _, run := sim.run[k]; run {
			sim.fail("Due(%s) gave %s, which runs", schWhen(sim.now), k)
		}
		if p, ok := sim.last[k]; ok && sim.now.Sub(p) < c.Interval && !(c.Zone && sim.movedIn(p, sim.now)) {
			sim.fail("%s started at %s and again at %s, with no move between", k, schWhen(p), schWhen(sim.now))
		}
		sim.run[k], sim.last[k] = schInFlight{c.Key, sim.now}, sim.now
	}
	if len(sim.run) > MaxRunning {
		sim.fail("%d checks run", len(sim.run))
	}
	return got
}

func (sim *schSim) jump() {
	sim.t.Helper()
	next, ok := sim.s.Next()
	if !ok {
		sim.advance(0)
		sim.due()
		return
	}
	if next.After(sim.now) {
		sim.now = next
	}
	if got := sim.due(); len(got) == 0 {
		sim.fail("Next gave %s, and Due(%s) started nothing", schWhen(next), schWhen(sim.now))
	}
}

func (sim *schSim) checkNext() {
	sim.t.Helper()
	got, ok := sim.s.Next()
	if twin, twinOK := sim.twin.Next(); twinOK != ok || !twin.Equal(got) {
		sim.fail("an equal schedule gave Next %s %v, the first %s %v", schWhen(twin), twinOK, schWhen(got), ok)
	}
	if want, wantOK := sim.m.next(); ok != wantOK || ok && !got.Equal(want) {
		sim.fail("Next gave %s %v, want %s %v", schWhen(got), ok, schWhen(want), wantOK)
	}
}

// schKit holds the servers and answers that the property uses again and
// again, built once: readers of a result never change it.
type schKit struct {
	ns1, ns2           obs.Server
	a, noName, refused obs.Result
	noData, soa        []obs.Result // by serial, 0 to 9
	elsewhere          obs.Key      // a check that no file of the cases has
}

func schNewKit(t testing.TB) *schKit {
	t.Helper()
	k := &schKit{ns1: schServer(t, "ns1.corp.test.", schNS1), ns2: schServer(t, "ns2.corp.test.", schNS2),
		a: schA(t), noName: schNoName(t, 1), refused: obs.FailureResult(obs.Failure{Reason: obs.ReasonRefused}),
		elsewhere: obs.RecordsKey(schName(t, "corp.test."), schName(t, "elsewhere.example."), dnswire.TypeA)}
	for serial := range uint32(10) {
		k.noData = append(k.noData, schNoData(t, serial))
		k.soa = append(k.soa, schSOA(t, serial))
	}
	return k
}

func (sim *schSim) serialAnswer(addr string) (obs.Result, bool) {
	rng := sim.rng
	switch x := rng.IntN(20); {
	case x < 3:
		return schTimeout, false
	case x == 3:
		return sim.kit.noData[1+rng.IntN(9)], true
	}
	serial := uint32(1)
	if seen, ok := sim.m.serials[addr]; ok {
		serial = seen.serial
	}
	if rng.IntN(10) == 0 {
		serial = uint32(1 + rng.IntN(4))
	}
	return sim.kit.soa[serial], true
}

// observation gives a run of k that started at start and ends now, and
// whether no answer of it is usable.
func (sim *schSim) observation(k obs.Key, start time.Time) (obs.Observation, bool) {
	kit := sim.kit
	span := sim.now.Sub(start)
	answer := func(r1, r2 obs.Result) obs.Observation {
		return schObs(k, start, obs.Answer{Proof: obs.Proof{Server: kit.ns1, Received: start.Add(span / 3)}, Result: r1},
			obs.Answer{Proof: obs.Proof{Server: kit.ns2, Received: start.Add(span * 2 / 3)}, Result: r2})
	}
	if k.Kind == obs.KindSerial {
		r1, ok1 := sim.serialAnswer(schNS1)
		r2, ok2 := sim.serialAnswer(schNS2)
		return answer(r1, r2), !ok1 && !ok2
	}
	switch sim.rng.IntN(10) {
	case 0, 1:
		return answer(schTimeout, kit.refused), true
	case 2:
		return answer(schTimeout, kit.a), false
	case 3:
		return answer(kit.noName, kit.noData[1]), false
	}
	return answer(kit.a, kit.a), false
}

func (sim *schSim) changes(k obs.Key) []decide.Change {
	rng := sim.rng
	if rng.IntN(10) < 7 {
		return nil
	}
	rules := []decide.Rule{decide.RuleNotCovered, decide.RuleNameServers, decide.RuleInvalidFile,
		decide.RuleRecordSet, decide.RuleZone}
	var changes []decide.Change
	for range 1 + rng.IntN(2) {
		changes = append(changes, decide.Change{Op: schPick(rng, decide.OpOpen, decide.OpUpdate, decide.OpResolve),
			Finding: decide.Finding{Rule: schPick(rng, rules...), Check: k}, At: sim.now})
	}
	return changes
}

// open gives the findings of the open alerts of k that decide is given. An
// alert stays open for many runs, as a difference that stands does; now and
// then one opens or ends. Now and then an alert of another check comes too,
// which must not count.
func (sim *schSim) open(k obs.Key) []decide.Finding {
	rng := sim.rng
	key := k.String()
	if rng.IntN(8) == 0 {
		if _, ok := sim.alerts[key]; ok {
			delete(sim.alerts, key)
		} else {
			sim.alerts[key] = schPick(rng, decide.RuleRecordSet, decide.RuleZone, decide.RuleNotCovered, decide.RuleCheckFailing)
		}
	}
	var open []decide.Finding
	if rule, ok := sim.alerts[key]; ok {
		open = append(open, decide.Finding{Rule: rule, Check: k})
	}
	if rng.IntN(10) == 0 {
		open = append(open, decide.Finding{Rule: decide.RuleRecordSet, Check: sim.kit.elsewhere})
	}
	return open
}

func schReportText(r Report) string {
	return fmt.Sprintf("known %v tier%d failing since %s limit %v moves %q quiet %v", r.Known, uint8(r.Tier),
		schWhen(r.FailingSince), r.FailLimit, schMoveTexts(r.Moves), r.Quiet)
}

func (sim *schSim) finish() {
	sim.t.Helper()
	if len(sim.run) == 0 {
		sim.advance(0)
		sim.due()
		return
	}
	k := schPick(sim.rng, slices.Sorted(maps.Keys(sim.run))...)
	run := sim.run[k]
	sim.advance(0)
	o, failed := sim.observation(run.key, run.start)
	got := sim.s.Done(o, sim.now)
	if twin := sim.twin.Done(o, sim.now); !reflect.DeepEqual(got, twin) {
		sim.fail("an equal schedule gave Done %s, the first %s", schReportText(twin), schReportText(got))
	}
	want, alt := sim.m.done(o, failed, sim.now)
	if schReportText(got) != schReportText(want) {
		other := want
		other.FailingSince = alt
		if alt.IsZero() || schReportText(got) != schReportText(other) {
			sim.fail("Done of %s (failed %v) gave\n\t%s\nwant\n\t%s", k, failed, schReportText(got), schReportText(want))
		}
		sim.m.series[k] = alt
	}
	delete(sim.run, k)
	sim.n.early += sim.m.early
	sim.m.early = 0
	if len(got.Moves) > 0 {
		sim.moves = append(sim.moves, sim.now)
		sim.n.moves++
	}
	if !got.FailingSince.IsZero() && got.FailingSince.Before(o.Start) {
		sim.n.series++
	}
	open, changes := sim.open(run.key), sim.changes(run.key)
	moves, ok := sim.s.Judged(o, open, changes, sim.now)
	if twinMoves, twinOK := sim.twin.Judged(o, open, changes, sim.now); twinOK != ok || !reflect.DeepEqual(twinMoves, moves) {
		sim.fail("an equal schedule gave Judged %v %q, the first %v %q", twinOK, schMoveTexts(twinMoves), ok,
			schMoveTexts(moves))
	}
	v := sim.m.judged(o, failed, len(want.Moves) > 0, open, changes, sim.now)
	if ok != v.ok || !schSameMoves(schMoveTexts(moves), schMoveTexts(v.moves)) {
		sim.fail("Judged of %s (failed %v, open %v, changes %v) gave %v %q, want %v %q", k, failed, open, changes, ok,
			schMoveTexts(moves), v.ok, schMoveTexts(v.moves))
	}
	switch {
	case ok && len(moves) > 0:
		sim.n.unexplained++
	case ok:
		sim.n.quiet++
	case v.explainedEnded:
		sim.n.explained++
	}
	for _, c := range []struct {
		hit bool
		n   *int
	}{{v.held, &sim.n.held}, {v.flushed, &sim.n.flushed}, {v.excused, &sim.n.excused}, {v.nothingNew, &sim.n.nothingNew}} {
		if c.hit {
			*c.n++
		}
	}
}

// replacement gives the lines of a file that keeps most lines, the lines of
// running checks more often, and adds a few.
func (sim *schSim) replacement() []string {
	seen := map[string]bool{}
	var lines []string
	for _, e := range sim.file.Expectations {
		keep := 7
		if _, running := sim.run[obs.RecordsKey(sim.file.Domain, e.Name, e.Type).String()]; running {
			keep = 9
		}
		if sim.rng.IntN(10) < keep {
			lines = append(lines, e.String())
			seen[e.Name.Lower().String()+e.Type.String()] = true
		}
	}
	return append(lines, schRandomLines(sim.rng, 4, seen)...)
}

func (sim *schSim) replace() {
	sim.t.Helper()
	lines := sim.replacement()
	f := schFile(sim.t, lines...)
	sim.file = f
	sim.s.Replace(f)
	sim.twin.Replace(schFile(sim.t, lines...))
	plan := schModelPlan(sim.t, f, sim.fast, sim.m.iv)
	sim.m.replace(plan)
	clear(sim.last)
	schSameChecks(sim.t, sim.where()+": Checks after Replace", sim.s.Checks(), plan)
	sim.n.replaced++
}

// stop calls Flush, as a stop does; the schedule goes on after it, which a
// service never does, but every rule still holds.
func (sim *schSim) stop() {
	sim.t.Helper()
	got := sim.s.Flush(sim.now)
	if twin := sim.twin.Flush(sim.now); !reflect.DeepEqual(got, twin) {
		sim.fail("an equal schedule gave Flush %q, the first %q", schMoveTexts(twin), schMoveTexts(got))
	}
	if want := sim.m.flush(sim.now); !schSameMoves(schMoveTexts(got), schMoveTexts(want)) {
		sim.fail("Flush gave %q, want %q", schMoveTexts(got), schMoveTexts(want))
	}
	if len(got) > 0 {
		sim.n.stops++
	}
}

func TestScheduleProperty(t *testing.T) {
	n, kit := &schCounts{}, schNewKit(t)
	for c := range schCases {
		rng := schRand(c)
		lines := schRandomLines(rng, 28, map[string]bool{})
		f := schFile(t, lines...)
		fast := schRandomFast(t, rng)
		iv := Intervals{Serial: schPick(rng, 5*time.Second, 7*time.Second, 15*time.Second),
			Parent: schPick(rng, 10*time.Second, 61*time.Second), Fast: schPick(rng, 6*time.Second, 43*time.Second),
			Other: schPick(rng, 20*time.Second, 300*time.Second)}
		plan := schModelPlan(t, f, fast, iv)
		sim := &schSim{t: t, rng: rng, c: c, file: f, fast: fast,
			s: New(f, fast, iv), twin: New(schFile(t, lines...), slices.Clone(fast), iv),
			m: schNewModel(plan, iv), now: schT0, run: map[string]schInFlight{}, last: map[string]time.Time{},
			alerts: map[string]decide.Rule{}, n: n, kit: kit}
		schSameChecks(t, sim.where()+": Checks", sim.s.Checks(), plan)
		for sim.act = range 100 {
			switch r := rng.IntN(20); {
			case r < 7:
				sim.advance(0)
				sim.due()
			case r < 9:
				sim.jump()
			case r < 19:
				sim.finish()
			case rng.IntN(4) == 0:
				sim.stop()
			default:
				sim.replace()
			}
			sim.checkNext()
		}
		n.waits, n.folds, n.waitEnds = n.waits+sim.m.waits, n.folds+sim.m.folds, n.waitEnds+sim.m.waitEnds
	}
	t.Logf("seed %d: %+v", schSeed, *n)
	if n.capped == 0 || n.moves == 0 || n.unexplained == 0 || n.explained == 0 || n.replaced == 0 || n.quiet == 0 || n.series == 0 ||
		n.held == 0 || n.flushed == 0 || n.excused == 0 || n.early == 0 || n.nothingNew == 0 ||
		n.waits == 0 || n.folds == 0 || n.waitEnds == 0 || n.stops == 0 {
		t.Fatalf("seed %d: the cases miss a kind of event: %+v", schSeed, *n)
	}
}
