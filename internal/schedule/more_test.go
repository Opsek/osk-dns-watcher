package schedule

import (
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// schEndDue starts every check that is due at now and ends each with a usable
// answer that has not moved the serial.
func schEndDue(t testing.TB, s *Schedule, now time.Time) {
	t.Helper()
	for _, c := range s.Due(now) {
		o := schUsable(t, c.Key, now)
		if c.Key.Kind == obs.KindSerial {
			o = schSerialObs(t, now, 2, 2)
		}
		schEnd(t, s, o, now)
	}
}

// The run that ends the round is the one that makes the failure last exactly
// as long as the limit.
func TestRoundStopsWaitingForAZoneCheckThatHasFailedForExactlyItsLimit(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	www := zone[2]
	schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9))
	schEnd(t, s, schUsable(t, zone[1], schSec(8)), schSec(9))
	_, moves, ok := schEnd(t, s, schFailed(t, www, schSec(8)), schSec(9))
	schWantJudged(t, "the first failed run", moves, ok, false, nil)

	end := schSec(8).Add(schIv.FailLimit(TierOther))
	schStart(t, s, end, www)
	_, moves, ok = schEnd(t, s, schFailed(t, www, end), end)
	schWantJudged(t, "a failed run at exactly the limit", moves, ok, true, schBothMoved)
}

// The held moves leave at the first judgement that is one other-interval
// after the last report, not one nanosecond later.
func TestMovesAreReportedExactlyOneOtherIntervalAfterTheLastReport(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	for _, k := range zone {
		schEnd(t, s, schUsable(t, k, schSec(8)), schSec(10))
	}
	reported := schSec(10)

	// Every check that is due on its own runs first, so that only the move
	// makes the zone checks due at the time of the serial run.
	schEndDue(t, s, reported.Add(schIv.Other-15*time.Second))
	moveAt := reported.Add(schIv.Other - 3*time.Second)
	schStart(t, s, moveAt, schSerialKey(t))
	schEnd(t, s, schSerialObs(t, moveAt, 3, 3), moveAt)
	schStart(t, s, moveAt, zone...)
	for _, k := range zone[:2] {
		schEnd(t, s, schUsable(t, k, moveAt), moveAt)
	}
	_, moves, ok := schEnd(t, s, schUsable(t, zone[2], moveAt), reported.Add(schIv.Other))
	if !ok || len(moves) != 2 || moves[0].To != 3 || moves[1].To != 3 {
		t.Errorf("the round that ended one other-interval after the last report gave %v %q; want both moves to serial 3",
			ok, schMoveTexts(moves))
	}
}

// Flush with nothing held is not a report: the first moves that follow are
// still given at once.
func TestFlushOfNothingKeepsTheNextReportDue(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	if moves := s.Flush(schSec(8)); len(moves) != 0 {
		t.Fatalf("Flush with nothing held gave %q", schMoveTexts(moves))
	}
	for i, k := range zone {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i))
		if i == len(zone)-1 {
			schWantJudged(t, "the last zone check after an empty Flush", moves, ok, true, schBothMoved)
		}
	}
}

// Flush gives the moves that are held back and forgets them.
func TestFlushGivesTheHeldMovesOnce(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	for _, k := range zone {
		schEnd(t, s, schUsable(t, k, schSec(8)), schSec(10))
	}
	reported := schSec(10)
	schEndDue(t, s, reported.Add(schIv.Other-15*time.Second))
	moveAt := reported.Add(schIv.Other - 3*time.Second)
	schStart(t, s, moveAt, schSerialKey(t))
	schEnd(t, s, schSerialObs(t, moveAt, 3, 3), moveAt)
	schStart(t, s, moveAt, zone...)
	for _, k := range zone {
		_, moves, ok := schEnd(t, s, schUsable(t, k, moveAt), moveAt)
		if ok || len(moves) != 0 {
			t.Fatalf("a round that ends within one other-interval of the last report gave %v %q; want it held", ok, schMoveTexts(moves))
		}
	}
	moves := s.Flush(moveAt)
	if len(moves) != 2 || moves[0].To != 3 || moves[1].To != 3 {
		t.Errorf("Flush gave %q; want both held moves to serial 3", schMoveTexts(moves))
	}
	if again := s.Flush(moveAt); len(again) != 0 {
		t.Errorf("a second Flush gave %q; want none", schMoveTexts(again))
	}
}
