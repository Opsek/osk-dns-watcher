package schedule

import (
	"slices"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The rows below state when a round reports its moves as a zone change that
// no watched record explains. Two rules keep that report true: a run whose
// check still has an alert open that says a watched record differs counts
// like a run with a notice of its own; and a move to a serial that is known,
// because it was there at the first sight or the operator was told of it, is
// no change to tell. Machines behind one address that lag a change make both
// common: they serve the old records and the old serial for a while.

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

// A round's run of a zone check whose difference stands gives no change, but
// its open alert, of each rule that tells of the zone, explains the round.
func TestOpenDifferenceExplainsTheRound(t *testing.T) {
	zone := schZoneKeys(t)
	for _, rule := range rndRules {
		t.Run(rule.String(), func(t *testing.T) {
			s := schMoved(t)
			zcRound(t, s, "the round with a difference that stands", schSec(8), zcOpen(rule, zone[0]), nil)
		})
	}
}

// An open alert that says nothing of a record of the zone, such as one of a
// check that fails or is not covered, explains nothing.
func TestOpenAlertOfAnotherRuleExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	for _, rule := range rndOtherRules() {
		t.Run(rule.String(), func(t *testing.T) {
			s := schMoved(t)
			zcRound(t, s, "the round", schSec(8), zcOpen(rule, zone[0]), schBothMoved)
		})
	}
}

// Only the alerts of the check that ran count, as in decide.
func TestOpenDifferenceOfAnotherCheckExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	zcRound(t, s, "the round", schSec(8), zcOpen(decide.RuleRecordSet, zone[1]), schBothMoved)
}

// A run with no usable answer saw nothing: it neither counts for the round
// nor tells of the open difference.
func TestOpenDifferenceOfAFailedRunExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEndOpen(t, s, schFailed(t, zone[0], schSec(8)), zcOpen(decide.RuleRecordSet, zone[0]), schSec(9))
	schWantJudged(t, "the failed run", moves, ok, false, nil)
	zcRound(t, s, "the round", schSec(9), nil, schBothMoved)
}

// An open difference counts as a notice does: from before the last quiet
// serial run it explains nothing; after it, it explains the next move too.
func TestOpenDifferenceCountsAsANoticeOfItsWindow(t *testing.T) {
	zone := schZoneKeys(t)
	for _, quietBetween := range []bool{true, false} {
		name := map[bool]string{true: "a quiet serial run between", false: "no quiet serial run between"}[quietBetween]
		t.Run(name, func(t *testing.T) {
			s := rndNew(t)
			_, moves, ok := schEndOpen(t, s, schUsable(t, zone[0], schSec(5)), zcOpen(decide.RuleRecordSet, zone[0]), schSec(6))
			schWantJudged(t, "the run with an open difference", moves, ok, false, nil)
			var want []string
			if quietBetween {
				rndQuiet(t, s, schSec(7), 1)
				want = rndBoth(schSec(7), 1, schSec(14), 2)
			}
			rndMoveRun(t, s, schSec(14), 2, 2, 2)
			zcRound(t, s, "the round", schSec(15), nil, want)
		})
	}
}

// The first run of a check after New tells of the state, also by an open
// alert that an earlier run of the service left.
func TestOpenDifferenceOfTheFirstRunSinceNewExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := New(schBase(t), nil, schIv)
	rndQuiet(t, s, schT0, 1)
	_, moves, ok := schEndOpen(t, s, schUsable(t, zone[0], schSec(5)), zcOpen(decide.RuleRecordSet, zone[0]), schSec(6))
	schWantJudged(t, "the first run", moves, ok, false, nil)
	rndMoveRun(t, s, schSec(14), 2, 2, 2)
	zcRound(t, s, "the round", schSec(15), nil, rndBoth(schT0, 1, schSec(14), 2))
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
// machine that lags gives, is no news.
func TestBackwardMoveToAToldSerialIsNoNews(t *testing.T) {
	s := rndNew(t)
	zcSerialRun(t, s, schSec(7), 2, 2, 2, false, nil)
	zcNoticeRound(t, s, schSec(8))
	zcSerialRun(t, s, schSec(14), 2, 2, 0, true, nil)
	zcSerialRun(t, s, schSec(21), 2, 1, 1, false, nil)
	zcRound(t, s, "the round of the move back", schSec(22), nil, nil)
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

// A serial that one address shows for the first time does not make the move
// of another address to it, in the same run, old.
func TestFirstSightInTheRunOfAMoveLeavesTheMoveNews(t *testing.T) {
	s := New(schBase(t), nil, schIv)
	schSettle(t, s, schSerialKey(t))
	zcSerialRun(t, s, schT0, 0, 1, 0, true, nil)
	zcSerialRun(t, s, schSec(7), 2, 2, 1, false, nil)
	zcRound(t, s, "the round", schSec(8), nil, []string{rndMove(2, schT0, 1, schSec(7), 2)})
}
