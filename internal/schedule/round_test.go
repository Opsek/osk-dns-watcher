package schedule

import (
	"fmt"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// A round that ends is explained when a run of a zone check, judged inside or
// outside the round, started after the instant at which the serial was last
// judged quiet and gave a notice of its own. The rows below state each side of
// that rule: the start of the notice against that instant, the check that
// gave the notice, the rule of the change, the first run of a check, and what
// a failed run does. Judged is asserted at every step.

// rndRules are the rules whose change tells the operator about the zone.
var rndRules = []decide.Rule{decide.RuleRecordSet, decide.RuleChallenge, decide.RuleZone, decide.RuleWildcard, decide.RuleCAA,
	decide.RuleSPF, decide.RuleDMARC, decide.RuleDKIM, decide.RuleMTASTS}

var rndOps = []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve}

// rndOtherRules are all the rules whose change tells nothing of the zone.
func rndOtherRules() []decide.Rule {
	var others []decide.Rule
	for r := decide.RuleInvalidFile; r <= decide.RuleMTASTS; r++ {
		if !slices.Contains(rndRules, r) {
			others = append(others, r)
		}
	}
	return others
}

// rndNew is a schedule of schBase that has seen the serial quiet at T0.
func rndNew(t testing.TB) *Schedule {
	t.Helper()
	s := New(schBase(t), nil, schIv)
	schSettle(t, s)
	return s
}

func rndChange(rule decide.Rule, op decide.Op, k obs.Key) decide.Change {
	return decide.Change{Op: op, Finding: decide.Finding{Rule: rule, Check: k}, At: schT0}
}

func rndOwn(k obs.Key) decide.Change { return rndChange(decide.RuleRecordSet, decide.OpOpen, k) }

// rndMove is the text of the move that server ns (1 or 2) makes in a serial
// run that started at start, when its last serial was seen in the run that
// started at prev.
func rndMove(ns int, prev time.Time, from uint32, start time.Time, to uint32) string {
	addr, host := schNS1, "ns1.corp.test."
	if ns == 2 {
		addr, host = schNS2, "ns2.corp.test."
	}
	off := time.Duration(ns) * 100 * time.Millisecond
	return fmt.Sprintf("%s %s serial %d until %s, %d since %s", addr, host, from, schWhen(prev.Add(off)), to, schWhen(start.Add(off)))
}

// rndBoth are the moves of both servers from one serial to another.
func rndBoth(prev time.Time, from uint32, start time.Time, to uint32) []string {
	return []string{rndMove(1, prev, from, start, to), rndMove(2, prev, from, start, to)}
}

// rndNotice ends a run of a check that started at start, with a change, and
// expects that it ends no round.
func rndNotice(t testing.TB, s *Schedule, k obs.Key, start, now time.Time, change decide.Change) {
	t.Helper()
	_, moves, ok := schEnd(t, s, schUsable(t, k, start), now, change)
	schWantJudged(t, "a run with a notice, "+schWhen(start), moves, ok, false, nil)
}

// rndMoveRun ends a serial run that moved n servers while no round ends.
func rndMoveRun(t testing.TB, s *Schedule, start time.Time, s1, s2 uint32, n int) {
	t.Helper()
	r, moves, ok := schEnd(t, s, schSerialObs(t, start, s1, s2), start.Add(time.Second))
	if len(r.Moves) != n {
		t.Fatalf("the serial run at %s moved %q, want %d moves", schWhen(start), schMoveTexts(r.Moves), n)
	}
	schWantJudged(t, "the serial run that moved", moves, ok, false, nil)
}

// rndQuiet ends a serial run with no move; with no round and nothing held
// the notice of earlier moves ends.
func rndQuiet(t testing.TB, s *Schedule, start time.Time, serial uint32) {
	t.Helper()
	r, moves, ok := schEnd(t, s, schSerialObs(t, start, serial, serial), start.Add(time.Second))
	if len(r.Moves) != 0 {
		t.Fatalf("the serial run at %s moved %q", schWhen(start), schMoveTexts(r.Moves))
	}
	schWantJudged(t, "the quiet serial run at "+schWhen(start), moves, ok, true, nil)
}

// rndRound ends the three zone checks with usable runs that started at
// start, each with no change. Only the last one ends the round; it gives want
// as the moves to report, or none when want is empty.
func rndRound(t testing.TB, s *Schedule, what string, start time.Time, want []string) {
	t.Helper()
	for i, k := range schZoneKeys(t) {
		_, moves, ok := schEnd(t, s, schUsable(t, k, start), start.Add(time.Second))
		if i < 2 {
			schWantJudged(t, what+", "+k.String(), moves, ok, false, nil)
			continue
		}
		schWantJudged(t, what+", the last zone check", moves, ok, len(want) > 0, want)
	}
}

// A regular run of a zone check that starts in the tick of the serial run
// sees the change first; the round that follows finds nothing new and is
// still explained.
func TestNoticeJudgedBeforeTheMoveExplainsTheRound(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
	rndMoveRun(t, s, schSec(7), 2, 2, 2)
	rndRound(t, s, "the round after a notice before the move", schSec(8), nil)
	rndQuiet(t, s, schSec(22), 2)
}

// The same notice from before the last quiet serial run belongs to an older
// change, so the move is reported.
func TestNoticeBeforeTheLastQuietSerialRunExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
	rndQuiet(t, s, schSec(7), 1)
	rndMoveRun(t, s, schSec(14), 2, 2, 2)
	rndRound(t, s, "the round after an old notice", schSec(15), rndBoth(schSec(7), 1, schSec(14), 2))
}

// The start of the notice against the instant at which the quiet serial run
// was judged: one moment before and the same instant do not explain, one
// moment after does, and an unset start never does. The order in which the
// two runs are judged changes nothing.
func TestNoticeInstantAgainstTheQuietSerialRun(t *testing.T) {
	quietRun := schSec(7)
	quiet := quietRun.Add(time.Second) // rndQuiet judges the run one second after its start
	rows := []struct {
		name      string
		at        time.Time
		explained bool
	}{
		{"one nanosecond before", quiet.Add(-time.Nanosecond), false},
		{"the same instant", quiet, false},
		{"one nanosecond after", quiet.Add(time.Nanosecond), true},
		{"a second after", quiet.Add(time.Second), true},
		{"unset", time.Time{}, false},
	}
	for _, row := range rows {
		for _, noticeFirst := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s, notice first %v", row.name, noticeFirst), func(t *testing.T) {
				zone := schZoneKeys(t)
				s := rndNew(t)
				now := quiet.Add(2 * time.Second)
				if noticeFirst {
					rndNotice(t, s, zone[0], row.at, now, rndOwn(zone[0]))
				}
				rndQuiet(t, s, quietRun, 1)
				if !noticeFirst {
					rndNotice(t, s, zone[0], row.at, now, rndOwn(zone[0]))
				}
				rndMoveRun(t, s, schSec(14), 2, 2, 2)
				var want []string
				if !row.explained {
					want = rndBoth(quietRun, 1, schSec(14), 2)
				}
				rndRound(t, s, "the round", schSec(15), want)
			})
		}
	}
}

// The order seen in the lab: the serial run that moved is judged first, then
// a run of a zone check that started before the move and saw the change. It
// explains the round the move started, if it started after the serial was
// last quiet (judged at T0+1s).
func TestNoticeThatStartedBeforeTheMoveAndIsJudgedAfterItExplainsTheRound(t *testing.T) {
	quiet := schSec(1)
	rows := []struct {
		name      string
		at        time.Time
		explained bool
	}{
		{"the instant of the quiet run", quiet, false},
		{"one nanosecond after", quiet.Add(time.Nanosecond), true},
		{"before the serial run started", schSec(5), true},
		{"in the tick of the serial run", schSec(7), true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			zone := schZoneKeys(t)
			s := rndNew(t)
			rndMoveRun(t, s, schSec(7), 2, 2, 2)
			rndNotice(t, s, zone[0], row.at, schSec(9), rndOwn(zone[0]))
			var want []string
			if !row.explained {
				want = schBothMoved
			}
			rndRound(t, s, "the round", schSec(8), want)
		})
	}
}

// A failed run gives no notice, in either order.
func TestFailedRunWithAChangeGivesNoNotice(t *testing.T) {
	zone := schZoneKeys(t)
	fail := func(t *testing.T, s *Schedule) {
		_, moves, ok := schEnd(t, s, schFailed(t, zone[0], schSec(7)), schSec(9), rndOwn(zone[0]))
		schWantJudged(t, "a failed run with a change", moves, ok, false, nil)
	}
	t.Run("before the move", func(t *testing.T) {
		s := rndNew(t)
		fail(t, s)
		rndMoveRun(t, s, schSec(7), 2, 2, 2)
		rndRound(t, s, "the round", schSec(8), rndBoth(schT0, 1, schSec(7), 2))
	})
	t.Run("after the move", func(t *testing.T) {
		s := rndNew(t)
		rndMoveRun(t, s, schSec(7), 2, 2, 2)
		fail(t, s)
		rndRound(t, s, "the round", schSec(8), rndBoth(schT0, 1, schSec(7), 2))
	})
}

// The first run of a check that is judged after New may have seen a change
// that came before the service started; its notice explains nothing. The
// second run of the same check does.
func TestNoticeOfTheFirstJudgedRunSinceNewExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	t.Run("first run", func(t *testing.T) {
		s := New(schBase(t), nil, schIv)
		rndQuiet(t, s, schT0, 1)
		rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), rndBoth(schT0, 1, schSec(14), 2))
	})
	t.Run("in the tick of the start", func(t *testing.T) {
		s := New(schBase(t), nil, schIv)
		rndNotice(t, s, zone[0], schT0, schSec(1), rndOwn(zone[0]))
		rndQuiet(t, s, schT0, 1)
		rndMoveRun(t, s, schSec(7), 2, 2, 2)
		rndRound(t, s, "the round", schSec(8), rndBoth(schT0, 1, schSec(7), 2))
	})
	t.Run("second run", func(t *testing.T) {
		s := New(schBase(t), nil, schIv)
		rndQuiet(t, s, schT0, 1)
		_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(3)), schSec(4))
		schWantJudged(t, "the first run", moves, ok, false, nil)
		rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), nil)
	})
	t.Run("the first run of another check", func(t *testing.T) {
		s := New(schBase(t), nil, schIv)
		rndQuiet(t, s, schT0, 1)
		for i := range 2 {
			_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(3+i)), schSec(4+i))
			schWantJudged(t, "a run of the first check", moves, ok, false, nil)
		}
		rndNotice(t, s, zone[1], schSec(7), schSec(8), rndOwn(zone[1]))
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), rndBoth(schT0, 1, schSec(14), 2))
	})
}

// Replace makes the first run of each check count as a first run again, also
// for a check that stays in the plan.
func TestNoticeOfTheFirstJudgedRunSinceReplaceExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	t.Run("first run", func(t *testing.T) {
		s := rndNew(t)
		s.Replace(schBase(t))
		rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), rndBoth(schT0, 1, schSec(14), 2))
	})
	t.Run("second run", func(t *testing.T) {
		s := rndNew(t)
		s.Replace(schBase(t))
		_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(5)), schSec(6))
		schWantJudged(t, "the first run", moves, ok, false, nil)
		rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), nil)
	})
}

// Two servers take one change one after the other, in two serial runs: the
// second move starts again a round that finds nothing new, and one notice
// explains both.
func TestOneNoticeExplainsTwoMovesOfTwoServers(t *testing.T) {
	zone := schZoneKeys(t)
	for _, endFirst := range []bool{true, false} {
		t.Run(fmt.Sprintf("first round ended %v", endFirst), func(t *testing.T) {
			s := rndNew(t)
			rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
			rndMoveRun(t, s, schSec(7), 2, 1, 1)
			if endFirst {
				rndRound(t, s, "the round of the first server", schSec(8), nil)
				rndMoveRun(t, s, schSec(22), 2, 2, 1)
				rndRound(t, s, "the round of the second server", schSec(23), nil)
				return
			}
			rndMoveRun(t, s, schSec(14), 2, 2, 1)
			rndRound(t, s, "the round of both servers", schSec(15), nil)
		})
	}
}

// A notice explains the moves up to the next quiet serial run; a move after
// that run with no notice of its own is reported.
func TestMoveAfterAQuietSerialRunIsReportedAgain(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
	rndMoveRun(t, s, schSec(7), 2, 2, 2)
	rndRound(t, s, "the explained round", schSec(8), nil)
	rndMoveRun(t, s, schSec(22), 3, 3, 2)
	rndRound(t, s, "a second move with no quiet run between", schSec(23), nil)
	rndQuiet(t, s, schSec(37), 3)
	rndMoveRun(t, s, schSec(52), 4, 4, 2)
	rndRound(t, s, "a move after the quiet run", schSec(53), rndBoth(schSec(37), 3, schSec(52), 4))
}

// A serial run with no usable answer sees no serial, so it is not a quiet
// run, and the notice before it still counts. A run with one usable answer
// is quiet.
func TestFailedSerialRunDoesNotMoveTheQuietInstant(t *testing.T) {
	zone := schZoneKeys(t)
	t.Run("no answer", func(t *testing.T) {
		s := rndNew(t)
		rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
		_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 0, 0), schSec(8))
		schWantJudged(t, "the failed serial run", moves, ok, false, nil)
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), nil)
	})
	t.Run("one answer", func(t *testing.T) {
		s := rndNew(t)
		rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
		_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 0, 1), schSec(8))
		schWantJudged(t, "the serial run with one answer", moves, ok, true, nil)
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), []string{
			rndMove(1, schT0, 1, schSec(14), 2), rndMove(2, schSec(7), 1, schSec(14), 2)})
	})
}

// A notice of a check that is no zone check, or of the serial check, tells
// nothing of the zone.
func TestNoticeOfACheckThatIsNoZoneCheckExplainsNothing(t *testing.T) {
	var subjects []obs.Key
	for _, c := range rndNew(t).Checks() {
		if !c.Zone && c.Key.Kind != obs.KindSerial {
			subjects = append(subjects, c.Key)
		}
	}
	if len(subjects) == 0 {
		t.Fatal("the plan of schBase holds no check outside the zone")
	}
	for _, k := range subjects {
		t.Run(k.String(), func(t *testing.T) {
			s := rndNew(t)
			rndNotice(t, s, k, schSec(7), schSec(8), rndOwn(k))
			rndMoveRun(t, s, schSec(7), 2, 2, 2)
			rndRound(t, s, "the round", schSec(8), rndBoth(schT0, 1, schSec(7), 2))
		})
	}
	t.Run("the serial check", func(t *testing.T) {
		s := rndNew(t)
		_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(7), 1, 1), schSec(8), rndOwn(schSerialKey(t)))
		schWantJudged(t, "a quiet serial run with a change", moves, ok, true, nil)
		rndMoveRun(t, s, schSec(14), 2, 2, 2)
		rndRound(t, s, "the round", schSec(15), rndBoth(schSec(7), 1, schSec(14), 2))
	})
}

// A change with no notice of its own, such as a new name server, a check
// that no line covers, or a failing check, does not explain the move.
func TestChangeWithNoNoticeOfItsOwnExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	for _, rule := range rndOtherRules() {
		for _, op := range []decide.Op{decide.OpOpen, decide.OpResolve} {
			t.Run(fmt.Sprintf("%s %s", op, rule), func(t *testing.T) {
				s := rndNew(t)
				rndNotice(t, s, zone[0], schSec(7), schSec(8), rndChange(rule, op, zone[0]))
				rndMoveRun(t, s, schSec(7), 2, 2, 2)
				rndRound(t, s, "the round", schSec(8), rndBoth(schT0, 1, schSec(7), 2))
			})
		}
	}
}

// Each rule that tells of the zone explains, whether the change opens an
// alert, updates it or ends it.
func TestEveryNoticeRuleExplainsTheNextMove(t *testing.T) {
	zone := schZoneKeys(t)
	for _, rule := range rndRules {
		for _, op := range rndOps {
			t.Run(fmt.Sprintf("%s %s", op, rule), func(t *testing.T) {
				s := rndNew(t)
				rndNotice(t, s, zone[0], schSec(7), schSec(8), rndChange(rule, op, zone[0]))
				rndMoveRun(t, s, schSec(7), 2, 2, 2)
				rndRound(t, s, "the round", schSec(8), nil)
			})
		}
	}
}

// rndNoticeInRound ends the round of schMoved with a notice in the run of the
// first zone check, which counts for the round.
func rndNoticeInRound(t testing.TB, s *Schedule) {
	t.Helper()
	zone := schZoneKeys(t)
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9), rndOwn(zone[0]))
	schWantJudged(t, "the run with a notice", moves, ok, false, nil)
	for _, k := range zone[1:] {
		_, moves, ok = schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9))
		schWantJudged(t, k.String(), moves, ok, false, nil)
	}
}

// A notice in the round itself explains it, as before; a move after the
// next quiet serial run is reported.
func TestNoticeInsideTheRoundStillExplainsIt(t *testing.T) {
	s := schMoved(t)
	rndNoticeInRound(t, s)
	rndQuiet(t, s, schSec(22), 2)
	rndMoveRun(t, s, schSec(37), 3, 3, 2)
	rndRound(t, s, "a move after the quiet run", schSec(38), rndBoth(schSec(22), 2, schSec(37), 3))
}

// The notice of a counted run is a notice like any other: it explains the
// moves that follow until a quiet serial run.
func TestNoticeInsideTheRoundExplainsTheNextMoveToo(t *testing.T) {
	s := schMoved(t)
	rndNoticeInRound(t, s)
	rndMoveRun(t, s, schSec(22), 3, 3, 2)
	rndRound(t, s, "a second move with no quiet run between", schSec(23), nil)
	rndQuiet(t, s, schSec(37), 3)
	rndMoveRun(t, s, schSec(52), 4, 4, 2)
	rndRound(t, s, "a move after the quiet run", schSec(53), rndBoth(schSec(37), 3, schSec(52), 4))
}

// A notice that is judged while the round is pending, from a run that does
// not count for the round, stays a notice for the move that comes next: no
// quiet serial run came between them.
func TestNoticeOfARunInsideARoundThatDoesNotCountExplainsTheNextMove(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	rndMoveRun(t, s, schSec(7), 2, 2, 2)
	rndNotice(t, s, zone[0], schSec(5), schSec(9), rndOwn(zone[0]))
	rndMoveRun(t, s, schSec(21), 3, 3, 2)
	rndRound(t, s, "the round of both moves", schSec(22), nil)
}

// rndQuietInRound judges a quiet serial run while the round of schMoved waits
// for a slow zone check.
func rndQuietInRound(t testing.TB, s *Schedule, start time.Time) {
	t.Helper()
	_, moves, ok := schEnd(t, s, schSerialObs(t, start, 2, 2), start.Add(time.Second))
	schWantJudged(t, "a serial run with no move while the round is pending", moves, ok, false, nil)
}

// A round keeps the quiet instant from when it was created: a quiet serial
// run judged later, while a slow zone check holds the round, does not hide
// the notice of the move.
func TestQuietSerialRunInsideARoundDoesNotHideTheNoticeOfThatRound(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9), rndOwn(zone[0]))
	schWantJudged(t, "a counted run with a notice", moves, ok, false, nil)
	rndQuietInRound(t, s, schSec(14))
	for _, k := range zone[1:] {
		_, moves, ok = schEnd(t, s, schUsable(t, k, schSec(8)), schSec(16))
		schWantJudged(t, k.String(), moves, ok, false, nil)
	}
}

// The quiet serial run that was judged inside a round counts for the rounds
// that are created later.
func TestQuietSerialRunInsideARoundCountsForTheNextRound(t *testing.T) {
	zone := schZoneKeys(t)
	s := schMoved(t)
	_, moves, ok := schEnd(t, s, schUsable(t, zone[0], schSec(8)), schSec(9), rndOwn(zone[0]))
	schWantJudged(t, "a counted run with a notice", moves, ok, false, nil)
	rndQuietInRound(t, s, schSec(14))
	for _, k := range zone[1:] {
		schEnd(t, s, schUsable(t, k, schSec(8)), schSec(16))
	}
	rndMoveRun(t, s, schSec(21), 3, 3, 2)
	rndRound(t, s, "the round after the quiet run", schSec(22), rndBoth(schSec(14), 2, schSec(21), 3))
}

// A second move while the round runs does not renew the quiet instant of the
// round, so the notice that is judged inside it, from before the quiet serial
// run, still explains it.
func TestSecondMoveKeepsTheQuietInstantOfTheRound(t *testing.T) {
	zone := schZoneKeys(t)
	s := rndNew(t)
	rndMoveRun(t, s, schSec(7), 2, 2, 2)
	rndNotice(t, s, zone[0], schSec(5), schSec(9), rndOwn(zone[0]))
	_, moves, ok := schEnd(t, s, schSerialObs(t, schSec(14), 2, 2), schSec(15))
	schWantJudged(t, "a serial run with no move while the round is pending", moves, ok, false, nil)
	rndMoveRun(t, s, schSec(21), 3, 3, 2)
	rndRound(t, s, "the round of both moves", schSec(22), nil)
}

// Only a usable run counts as the first run of a check. The first run after
// New fails; the next one is usable, started after the serial was last
// quiet, and sees a difference that was there before the start: its notice
// explains nothing. The run after that one does.
func TestNoticeOfTheFirstUsableRunSinceNewExplainsNothing(t *testing.T) {
	zone := schZoneKeys(t)
	for _, third := range []bool{false, true} {
		t.Run(fmt.Sprintf("notice at the third run %v", third), func(t *testing.T) {
			s := New(schBase(t), nil, schIv)
			rndQuiet(t, s, schT0, 1)
			_, moves, ok := schEnd(t, s, schFailed(t, zone[0], schSec(3)), schSec(4))
			schWantJudged(t, "the failed first run", moves, ok, false, nil)
			if third {
				_, moves, ok = schEnd(t, s, schUsable(t, zone[0], schSec(5)), schSec(6))
				schWantJudged(t, "the first usable run", moves, ok, false, nil)
				rndNotice(t, s, zone[0], schSec(7), schSec(8), rndOwn(zone[0]))
			} else {
				rndNotice(t, s, zone[0], schSec(5), schSec(6), rndOwn(zone[0]))
			}
			rndMoveRun(t, s, schSec(14), 2, 2, 2)
			var want []string
			if !third {
				want = rndBoth(schT0, 1, schSec(14), 2)
			}
			rndRound(t, s, "the round", schSec(15), want)
		})
	}
}

// A change of a mail rule tells of the zone as a change of the line does, for
// each of the four and each op, and no other rule beside them does.
func TestOwnNoticeHoldsEveryMailRuleInEveryOp(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleSPF, decide.RuleDMARC, decide.RuleDKIM, decide.RuleMTASTS} {
		for _, op := range rndOps {
			if !ownNotice(rndChange(rule, op, obs.Key{})) {
				t.Errorf("ownNotice of %s %s is false", op, rule)
			}
		}
	}
	for _, rule := range []decide.Rule{decide.RuleDisagree, decide.RuleCheckFailing, decide.RuleZoneChanged} {
		if ownNotice(rndChange(rule, decide.OpOpen, obs.Key{})) {
			t.Errorf("ownNotice of open %s is true", rule)
		}
	}
}
