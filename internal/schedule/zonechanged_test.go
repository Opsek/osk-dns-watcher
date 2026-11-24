package schedule

import (
	"slices"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The rows below state when a round reports its moves as a zone change that
// no watched record explains. Machines behind one address that lag a change
// serve the old records and the old serial for a while, and two rules keep
// the report true. When the run of a zone check in the round left an alert of
// its own standing, the moves wait for the next run of that check: the alert
// may end there, and that end is the notice of the move. And a move to a
// serial that is known, because it was there at the first sight or the
// operator was told of it, is no change to tell.

// zcRound ends the three zone checks with usable runs that started at start,
// the first with the open findings given. Only the last run ends the round;
// it gives want, or nothing when want is empty.
func zcRound(t testing.TB, s *Schedule, what string, start time.Time, open []decide.Finding, want []string) {
	t.Helper()
	for i, k := range schZoneKeys(t) {
		var mine []decide.Finding
		if i == 0 {
			mine = open
		}
		_, moves, ok := schEndOpen(t, s, schUsable(t, k, start), mine, start.Add(time.Second))
		if i < 2 {
			schWantJudged(t, what+", "+k.String(), moves, ok, false, nil)
			continue
		}
		schWantJudged(t, what+", the last zone check", moves, ok, len(want) > 0, want)
	}
}

// zcNoticeRound ends the round with a notice of its own in the run of the
// first zone check; the runs started at start.
func zcNoticeRound(t testing.TB, s *Schedule, start time.Time) {
	t.Helper()
	for i, k := range schZoneKeys(t) {
		var changes []decide.Change
		if i == 0 {
			changes = []decide.Change{rndOwn(k)}
		}
		_, moves, ok := schEnd(t, s, schUsable(t, k, start), start.Add(time.Second), changes...)
		schWantJudged(t, "the round with a notice, "+k.String(), moves, ok, false, nil)
	}
}

// zcSerialRun ends a serial run that started at start with the serials of
// ns1 and ns2 (0: no answer), and wants n moves and Judged as given.
func zcSerialRun(t testing.TB, s *Schedule, start time.Time, s1, s2 uint32, n int, wantOK bool, want []string) {
	t.Helper()
	r, moves, ok := schEnd(t, s, schSerialObs(t, start, s1, s2), start.Add(time.Second))
	if len(r.Moves) != n {
		t.Fatalf("the serial run at %s moved %q, want %d moves", schWhen(start), schMoveTexts(r.Moves), n)
	}
	schWantJudged(t, "the serial run at "+schWhen(start), moves, ok, wantOK, want)
}

func zcOpen(rule decide.Rule, k obs.Key) []decide.Finding {
	return []decide.Finding{{Rule: rule, Check: k}}
}

// ---- A difference that stands ----

// zcWaiting gives the schedule of schMoved whose round ended at T0+9 with no
// notice, while the run of the apex A set had an alert of rule open: the
// round waits for the next run of that check.
func zcWaiting(t testing.TB, rule decide.Rule) *Schedule {
	t.Helper()
	s := schMoved(t)
	zcRound(t, s, "the round with a difference that stands", schSec(8), zcOpen(rule, schZoneKeys(t)[0]), nil)
	return s
}

// The case of a change put back while a machine that lags still gives the
// changed record: the alert of the check stands in its run of the round, and
// its next run sees the record put back and ends the alert. That end is the
// notice of the move: nothing is reported, then or later.
func TestStandingDifferenceThatEndsAtTheNextRunExplainsTheMoves(t *testing.T) {
	apex := schZoneKeys(t)[0]
	for _, rule := range rndRules {
		t.Run(rule.String(), func(t *testing.T) {
			s := zcWaiting(t, rule)
			_, moves, ok := schEndOpen(t, s, schUsable(t, apex, schSec(51)), zcOpen(rule, apex), schSec(52),
				rndChange(rule, decide.OpResolve, apex))
			schWantJudged(t, "the next run, which ends the alert", moves, ok, false, nil)
			_, moves, ok = schEnd(t, s, schSerialObs(t, schSec(56), 2, 2), schSec(57))
			schWantJudged(t, "a quiet serial run after it", moves, ok, true, nil)
			if got := s.Flush(schSec(58)); len(got) != 0 {
				t.Errorf("Flush gave %q, want nothing", schMoveTexts(got))
			}
		})
	}
}

// When the next usable run of the check shows the difference again with no
// notice, the moves are told then. Until that run, nothing ends the wait: a
// run of another check, a run of the check that started before the round
// ended, a failed run, or a quiet serial run, which also ends no notice.
func TestStandingDifferenceThatStaysIsToldAfterTheNextRun(t *testing.T) {
	zone := schZoneKeys(t)
	apex, ns := zone[0], zone[1]
	open := zcOpen(decide.RuleRecordSet, apex)
	s := zcWaiting(t, decide.RuleRecordSet)
	_, moves, ok := schEnd(t, s, schUsable(t, ns, schSec(20)), schSec(21))
	schWantJudged(t, "a run of another check", moves, ok, false, nil)
	_, moves, ok = schEndOpen(t, s, schUsable(t, apex, schSec(8).Add(time.Second/2)), open, schSec(22))
	schWantJudged(t, "a run that started before the round ended", moves, ok, false, nil)
	_, moves, ok = schEndOpen(t, s, schFailed(t, apex, schSec(30)), open, schSec(31))
	schWantJudged(t, "a failed run", moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schSerialObs(t, schSec(35), 2, 2), schSec(36))
	schWantJudged(t, "a quiet serial run while the moves wait", moves, ok, false, nil)
	_, moves, ok = schEndOpen(t, s, schUsable(t, apex, schSec(51)), open, schSec(52))
	schWantJudged(t, "the next usable run, with the difference still there", moves, ok, true, schBothMoved)
}

// A check that fails past its limit has its own alert and may never answer
// again: the wait for it stops at the run that passes the limit.
func TestStandingDifferenceOfACheckThatFailsPastItsLimitIsTold(t *testing.T) {
	apex := schZoneKeys(t)[0]
	open := zcOpen(decide.RuleRecordSet, apex)
	s := zcWaiting(t, decide.RuleRecordSet)
	first := schSec(51)
	_, moves, ok := schEndOpen(t, s, schFailed(t, apex, first), open, first.Add(time.Second))
	schWantJudged(t, "the first failed run", moves, ok, false, nil)
	limit := first.Add(schIv.FailLimit(TierFast))
	_, moves, ok = schEndOpen(t, s, schFailed(t, apex, limit), open, limit)
	schWantJudged(t, "the failed run at the limit", moves, ok, true, schBothMoved)
}

// Moves that wait live only in memory: a stop tells them.
func TestWaitingMovesAreToldAtAStop(t *testing.T) {
	s := zcWaiting(t, decide.RuleRecordSet)
	if got := schMoveTexts(s.Flush(schSec(20))); !schSameMoves(got, schBothMoved) {
		t.Errorf("Flush gave %q, want %q", got, schBothMoved)
	}
	if again := s.Flush(schSec(21)); len(again) != 0 {
		t.Errorf("a second Flush gave %q, want nothing", schMoveTexts(again))
	}
}

// A move while moves wait joins them in one round, which keeps the window of
// the first move: a notice that started in that window, even before a later
// quiet serial run, explains them all.
func TestMoveWhileMovesWaitJoinsThemWithTheFirstWindow(t *testing.T) {
	zone := schZoneKeys(t)
	t.Run("told as one", func(t *testing.T) {
		s := zcWaiting(t, decide.RuleRecordSet)
		zcSerialRun(t, s, schSec(21), 3, 3, 2, false, nil)
		zcRound(t, s, "the round of both moves", schSec(22), nil, rndBoth(schT0, 1, schSec(21), 3))
	})
	t.Run("explained in the first window", func(t *testing.T) {
		s := zcWaiting(t, decide.RuleRecordSet)
		zcSerialRun(t, s, schSec(14), 2, 2, 0, false, nil)
		zcSerialRun(t, s, schSec(21), 3, 3, 2, false, nil)
		_, moves, ok := schEnd(t, s, schUsable(t, zone[2], schSec(12)), schSec(22), rndOwn(zone[2]))
		schWantJudged(t, "a notice that started before the quiet serial run", moves, ok, false, nil)
		zcRound(t, s, "the round of both moves", schSec(22), nil, nil)
	})
}

// A check that leaves the zone with Replace can hold no wait: the moves are
// told at the next judgement.
func TestReplaceEndsTheWaitForACheckThatLeftTheZone(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	for _, k := range zone[:2] {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9))
		schWantJudged(t, k.String(), moves, ok, false, nil)
	}
	_, moves, ok := schEndOpen(t, s, schUsable(t, zone[2], schSec(8)), zcOpen(decide.RuleRecordSet, zone[2]), schSec(9))
	schWantJudged(t, "www with a difference that stands", moves, ok, false, nil)
	s.Replace(schFile(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81", "www.corp.test. NS ns1.www.corp.test."))
	_, moves, ok = schEnd(t, s, schUsable(t, zone[0], schSec(20)), schSec(21))
	schWantJudged(t, "the next judgement", moves, ok, true, schBothMoved)
}

// The same Replace before the round ends: the check that stood and left the
// zone starts no wait, and the round reports at its last zone check.
func TestReplaceBeforeTheRoundEndsDropsACheckThatStood(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEndOpen(t, s, schUsable(t, zone[2], schSec(8)), zcOpen(decide.RuleRecordSet, zone[2]), schSec(9))
	schWantJudged(t, "www with a difference that stands", moves, ok, false, nil)
	s.Replace(schFile(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81", "www.corp.test. NS ns1.www.corp.test."))
	_, moves, ok = schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(10))
	schWantJudged(t, zone[0].String(), moves, ok, false, nil)
	_, moves, ok = schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(10))
	schWantJudged(t, "the last zone check", moves, ok, true, schBothMoved)
}

// An open alert alone explains nothing: a run outside the round with an
// alert that stands, and no notice, leaves the next move to be told.
func TestOpenAlertAloneExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	_, moves, ok := schEndOpen(t, s, schUsable(t, zone[0], schSec(5)), zcOpen(decide.RuleRecordSet, zone[0]), schSec(6))
	schWantJudged(t, "a run with an alert that stands", moves, ok, false, nil)
	rndMoveRun(t, s, schSec(14), 2, 2, 2)
	zcRound(t, s, "the round", schSec(15), nil, rndBoth(schT0, 1, schSec(14), 2))
}

// An open alert that says nothing of a record of the zone, such as one of a
// check that fails or is not covered, holds nothing back.
func TestOpenAlertOfAnotherRuleHoldsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	for _, rule := range rndOtherRules() {
		t.Run(rule.String(), func(t *testing.T) {
			s := schMoved(t)
			zcRound(t, s, "the round", schSec(8), zcOpen(rule, zone[0]), schBothMoved)
		})
	}
}

// Only the alerts of the check that ran count, as in decide.
func TestOpenDifferenceOfAnotherCheckHoldsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	zcRound(t, s, "the round", schSec(8), zcOpen(decide.RuleRecordSet, zone[1]), schBothMoved)
}

// A run with no usable answer saw nothing: it neither counts for the round
// nor shows that a difference stands.
func TestOpenDifferenceOfAFailedRunHoldsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEndOpen(t, s, schFailed(t, zone[0], schSec(8)), zcOpen(decide.RuleRecordSet, zone[0]), schSec(9))
	schWantJudged(t, "the failed run", moves, ok, false, nil)
	zcRound(t, s, "the round", schSec(9), nil, schBothMoved)
}

// ---- A serial that is known ----

// An address that lags gives, after a quiet serial run, the serial whose
// change a notice told: the move starts the zone checks again, and the round
// reports nothing. A move to a new serial after it is told at once.
func TestLateMoveToAToldSerialIsNoNews(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	zcSerialRun(t, s, schSec(7), 2, 1, 1, false, nil)
	zcNoticeRound(t, s, schSec(8))
	zcSerialRun(t, s, schSec(14), 2, 1, 0, true, nil)
	zcSerialRun(t, s, schSec(21), 2, 2, 1, false, nil)
	schStart(t, s, schSec(22), zone...)
	zcRound(t, s, "the round of the late address", schSec(22), nil, nil)
	zcSerialRun(t, s, schSec(28), 3, 3, 2, false, nil)
	zcRound(t, s, "the round of a new serial", schSec(29), nil, rndBoth(schSec(21), 2, schSec(28), 3))
}

// A move back to the serial from before a change that a notice told, as a
// machine that lags gives, is no news: also when the alerts of that change
// still stand, the round waits for the next run, and the difference stays.
func TestBackwardMoveToAToldSerialIsNoNews(t *testing.T) {
	apex := schZoneKeys(t)[0]
	for _, standing := range []bool{false, true} {
		t.Run(map[bool]string{false: "no alert open", true: "beside an alert that stands"}[standing], func(t *testing.T) {
			s := rndNew(t)
			zcSerialRun(t, s, schSec(7), 2, 2, 2, false, nil)
			zcNoticeRound(t, s, schSec(8))
			zcSerialRun(t, s, schSec(14), 2, 2, 0, true, nil)
			zcSerialRun(t, s, schSec(21), 2, 1, 1, false, nil)
			if !standing {
				zcRound(t, s, "the round of the move back", schSec(22), nil, nil)
				return
			}
			open := zcOpen(decide.RuleRecordSet, apex)
			zcRound(t, s, "the round of the move back", schSec(22), open, nil)
			_, moves, ok := schEndOpen(t, s, schUsable(t, apex, schSec(65)), open, schSec(66))
			schWantJudged(t, "the next run, with the difference still there", moves, ok, false, nil)
			if got := s.Flush(schSec(67)); len(got) != 0 {
				t.Errorf("Flush gave %q, want nothing", schMoveTexts(got))
			}
		})
	}
}

// An address that goes to a new serial and back shows no change once its
// moves are merged: within one round, and while its moves wait for the
// bound of the reports.
func TestAddressBackAtItsSerialShowsNoChange(t *testing.T) {
	t.Run("one round", func(t *testing.T) {
		s := rndNew(t)
		zcSerialRun(t, s, schSec(7), 2, 1, 1, false, nil)
		zcSerialRun(t, s, schSec(14), 1, 1, 1, false, nil)
		zcRound(t, s, "the round", schSec(15), nil, nil)
	})
	t.Run("held for the report", func(t *testing.T) {
		s := rndNew(t)
		zcSerialRun(t, s, schSec(7), 2, 2, 2, false, nil)
		zcRound(t, s, "the first round", schSec(8), nil, rndBoth(schT0, 1, schSec(7), 2))
		reported := schSec(9)
		zcSerialRun(t, s, schSec(21), 3, 2, 1, false, nil)
		zcRound(t, s, "the round of a new serial, held", schSec(22), nil, nil)
		zcSerialRun(t, s, schSec(35), 2, 2, 1, false, nil)
		zcRound(t, s, "the round of the move back", schSec(36), nil, nil)
		quiet := reported.Add(schIv.Other)
		_, moves, ok := schEnd(t, s, schSerialObs(t, quiet.Add(-time.Second), 2, 2), quiet)
		schWantJudged(t, "the quiet serial run one other-interval after the report", moves, ok, true, nil)
	})
}

// A serial that one address showed while its move waited for the report
// was never told: another address that moves to it has news, also when the
// first one went back.
func TestSerialShownWhileItsMoveWaitsIsStillNews(t *testing.T) {
	s := rndNew(t)
	zcSerialRun(t, s, schSec(7), 2, 2, 2, false, nil)
	zcRound(t, s, "the first round", schSec(8), nil, rndBoth(schT0, 1, schSec(7), 2))
	reported := schSec(9)
	zcSerialRun(t, s, schSec(21), 3, 2, 1, false, nil)
	zcRound(t, s, "the round of a new serial, held", schSec(22), nil, nil)
	zcSerialRun(t, s, schSec(35), 2, 3, 2, false, nil)
	zcRound(t, s, "the round in which the addresses swap", schSec(36), nil, nil)
	quiet := reported.Add(schIv.Other)
	_, moves, ok := schEnd(t, s, schSerialObs(t, quiet.Add(-time.Second), 2, 3), quiet)
	schWantJudged(t, "the quiet serial run one other-interval after the report", moves, ok, true,
		[]string{rndMove(2, schSec(21), 2, schSec(35), 3)})
}

// Two providers number the serials of one domain apart. A new serial at
// either one is news, above or below the serials of the other; a move back
// to a serial that was told is not.
func TestSerialsOfTwoProvidersAreNewsByValueNotByOrder(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, schSerialKey(t))
	zcSerialRun(t, s, schT0, 2026112401, 7, 0, true, nil)
	zcSerialRun(t, s, schSec(7), 2026112401, 8, 1, false, nil)
	zcRound(t, s, "the round of a new low serial", schSec(8), nil, []string{rndMove(2, schT0, 7, schSec(7), 8)})
	zcSerialRun(t, s, schSec(21), 2026112402, 7, 2, false, nil)
	zcRound(t, s, "the round of a new high serial and a move back, held", schSec(22), nil, nil)
	got, want := schMoveTexts(s.Flush(schSec(23))), []string{rndMove(1, schSec(7), 2026112401, schSec(21), 2026112402)}
	if !slices.Equal(got, want) {
		t.Errorf("Flush gave %q, want %q", got, want)
	}
}

// The serials known are bounded: one that no server gives any more is
// forgotten after knownSerials newer ones were told, and is news again. One
// that a server still gives is seen at every run and stays known.
func TestKnownSerialsAreBoundedAndTheServedOnesStay(t *testing.T) {
	s := rndNew(t)
	const first = 1000
	start := schSec(7)
	for i := range uint32(knownSerials) {
		zcSerialRun(t, s, start, first+i, 1, 1, false, nil) // ns2 keeps giving 1
		zcNoticeRound(t, s, start.Add(time.Second))
		start = start.Add(7 * time.Second)
	}
	last := uint32(first + knownSerials - 1)
	zcSerialRun(t, s, start, last, 1, 0, true, nil)
	zcSerialRun(t, s, start.Add(7*time.Second), 1, 1, 1, false, nil)
	zcRound(t, s, "the round of a move to the serial that ns2 gives", start.Add(8*time.Second), nil, nil)
	quiet := start.Add(14 * time.Second)
	zcSerialRun(t, s, quiet, 1, 1, 0, true, nil)
	zcSerialRun(t, s, start.Add(21*time.Second), first, 1, 1, false, nil)
	zcRound(t, s, "the round of a move to the oldest serial told", start.Add(22*time.Second), nil,
		[]string{rndMove(1, quiet, 1, start.Add(21*time.Second), first)})
}

// The bound is exact. Beside serial 1, which ns2 keeps giving, 63 serials
// told fill known to its 64 places and all stay; a 64th told pushes the
// oldest out and keeps the next one.
func TestKnownSerialsHoldExactlyTheBound(t *testing.T) {
	const first = 1000
	tell := func(t *testing.T, n uint32) (*Schedule, time.Time) {
		t.Helper()
		s := rndNew(t)
		start := schSec(7)
		for i := range n {
			zcSerialRun(t, s, start, first+i, 1, 1, false, nil)
			zcNoticeRound(t, s, start.Add(time.Second))
			start = start.Add(7 * time.Second)
		}
		zcSerialRun(t, s, start, first+n-1, 1, 0, true, nil)
		return s, start.Add(7 * time.Second)
	}
	t.Run("the 64th place", func(t *testing.T) {
		s, start := tell(t, knownSerials-1)
		zcSerialRun(t, s, start, first, 1, 1, false, nil)
		zcRound(t, s, "the round of a move to the oldest serial told", start.Add(time.Second), nil, nil)
	})
	t.Run("one past the bound", func(t *testing.T) {
		s, start := tell(t, knownSerials)
		zcSerialRun(t, s, start, first+1, 1, 1, false, nil)
		zcRound(t, s, "the round of a move to the second serial told", start.Add(time.Second), nil, nil)
		quiet := start.Add(7 * time.Second)
		zcSerialRun(t, s, quiet, first+1, 1, 0, true, nil)
		zcSerialRun(t, s, start.Add(14*time.Second), first, 1, 1, false, nil)
		zcRound(t, s, "the round of a move to the oldest serial told", start.Add(15*time.Second), nil,
			[]string{rndMove(1, quiet, first+1, start.Add(14*time.Second), first)})
	})
}

// An address whose merged moves hold one move to a new serial and one to a
// known serial has news, whichever came first.
func TestMergedMoveIsNewsWhenOneOfItsMovesIs(t *testing.T) {
	for _, newsFirst := range []bool{true, false} {
		t.Run(map[bool]string{true: "news first", false: "news last"}[newsFirst], func(t *testing.T) {
			s := New(schBase(t), nil, schIv)
			schSettle(t, s, schSerialKey(t))
			zcSerialRun(t, s, schT0, 1, 5, 0, true, nil) // known: 1 and 5
			mid, last := uint32(2), uint32(5)
			if !newsFirst {
				mid, last = 5, 2
			}
			zcSerialRun(t, s, schSec(7), mid, 5, 1, false, nil)
			zcSerialRun(t, s, schSec(14), last, 5, 1, false, nil)
			zcRound(t, s, "the round of both moves", schSec(15), nil, []string{rndMove(1, schT0, 1, schSec(14), last)})
		})
	}
}

// A serial that one address shows for the first time does not make the move
// of another address to it, in the same run, old.
func TestFirstSightInTheRunOfAMoveLeavesTheMoveNews(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, schSerialKey(t))
	zcSerialRun(t, s, schT0, 0, 1, 0, true, nil)
	zcSerialRun(t, s, schSec(7), 2, 2, 1, false, nil)
	zcRound(t, s, "the round", schSec(8), nil, []string{rndMove(2, schT0, 1, schSec(7), 2)})
}
