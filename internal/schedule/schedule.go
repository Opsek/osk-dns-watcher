package schedule

import (
	"maps"
	"net/netip"
	"slices"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Schedule keeps what decides when each check runs next. The maps are keyed
// by Key.String(), because an obs.Key cannot be a map key; no result is ever
// built by ranging over a map, so it never depends on map order.
type Schedule struct {
	iv   Intervals
	fast []dnswire.Name
	plan []Check
	keys []string // keys[i] is plan[i].Key.String(), kept because every call needs it

	starts      map[string]time.Time // no entry: not started since New or the last Replace
	judged      map[string]bool      // a usable run of the key was judged since New or the last Replace
	running     map[string]bool      // also a key that left the plan, until its Done
	failing     map[string]time.Time // start of the unbroken series of failed runs
	disagreeing map[string]*series   // the unbroken series of runs with two differing answers

	serials     []sighting // one per address of the domain's servers
	known       []uint32   // serials that tell nothing new, the one seen last at the end; see know
	serialMoved bool       // the last serial run saw a move
	quiet       time.Time  // when the last serial run with a usable answer and no move was judged
	noticed     time.Time  // latest start of a run of a zone check that gave a notice of its own
	moved       time.Time  // when the last move was seen
	round       *round     // nil when no round is pending

	held       []move    // moves of ended rounds that wait for their report
	lastReport time.Time // when moves were last reported
}

// series is what a records check has shown about its servers disagreeing.
// A split counts only while every server keeps giving the same answer,
// because servers whose answers rotate by design disagree at random and
// never steadily.
type series struct {
	since time.Time                 // o.Start of the first run of the split
	runs  int                       // runs of the split; 0: no split now
	quiet int                       // runs since the last run that went on with a split
	texts map[netip.AddrPort]string // the last set that each server address gave
}

// sighting is the serial that an address gave last, and when.
type sighting struct {
	server obs.Server
	serial uint32
	at     time.Time
}

// move is what a round and the report keep of the moves of one address:
// merged, from the first serial to the last.
type move struct {
	decide.Move
	news bool // one of the moves went to a serial that was not known
}

// round is the work that a move of the serial starts: each zone check must
// give a usable answer once after the move, before the move is judged.
type round struct {
	moves   []move          // one per address, in order of first sight
	pending map[string]bool // the zone checks still to run
	// since is quiet when the round was created: the serial was last seen
	// quiet before the first move of the round, and a quiet serial run while
	// a slow check holds the round must not hide a notice of that move.
	since time.Time
	// standing holds the zone checks whose run since the last move had an
	// alert of a notice rule open. A difference that stands gives no change,
	// and a machine that lags can still give the old record of a change that
	// was put back, so such a run cannot show that the alert is about to end.
	standing map[string]bool
	// ended is zero while the zone checks run. When they ended with no notice
	// and a check in standing, the round waits: ended is that instant, and
	// pending holds those checks until each has a usable run that started at
	// or after it.
	ended time.Time
}

// Report is what the schedule adds to an observation for decide.
type Report struct {
	Known        bool // o's key is in the plan; false: drop o
	Tier         Tier
	FailingSince time.Time     // for decide.Input
	FailLimit    time.Duration // for decide.Input
	DisagreeLong bool          // for decide.Input
	DisagreeOver bool          // for decide.Input
	Moves        []decide.Move // serial checks only: the servers whose serial moved in o
}

// DisagreeRuns is how many runs in a row a split must last before it is
// reported. With two servers and two equally likely answers, a steady split
// of N runs comes by chance once in 2*4^(N-1) runs; 11 runs make about one
// false alert in 4 years for a set checked every 60 seconds, and are 10
// minutes of the fast tier.
const DisagreeRuns = 11

func New(f *expect.File, fast []dnswire.Name, iv Intervals) *Schedule {
	s := &Schedule{
		iv:          iv,
		fast:        slices.Clone(fast),
		starts:      map[string]time.Time{},
		judged:      map[string]bool{},
		running:     map[string]bool{},
		failing:     map[string]time.Time{},
		disagreeing: map[string]*series{},
	}
	s.setPlan(f)
	return s
}

func (s *Schedule) setPlan(f *expect.File) {
	s.plan = Plan(f, s.fast, s.iv)
	s.keys = make([]string, len(s.plan))
	for i, c := range s.plan {
		s.keys[i] = c.Key.String()
	}
}

func (s *Schedule) Checks() []Check { return slices.Clone(s.plan) }

// Replace puts the checks of a changed file in force. Every check is due at
// once, because a line may now expect something else; what the runs in
// flight and the past runs showed is kept for the keys that stay.
func (s *Schedule) Replace(f *expect.File) {
	s.setPlan(f)
	clear(s.starts)
	// The next run of each check is judged against the new lines, so its
	// notices tell of the file, not of a change of the zone.
	clear(s.judged)
	// A line that comes back must start new series, not join old ones.
	for k := range s.failing {
		if !slices.Contains(s.keys, k) {
			delete(s.failing, k)
		}
	}
	for k := range s.disagreeing {
		if !slices.Contains(s.keys, k) {
			delete(s.disagreeing, k)
		}
	}
	if s.round == nil {
		return
	}
	zone := s.zoneChecks()
	notZone := func(k string, _ bool) bool { return !zone[k] }
	maps.DeleteFunc(s.round.pending, notZone)
	// A check that left would hold a wait for good.
	maps.DeleteFunc(s.round.standing, notZone)
	// A round left with no pending check ends at the next Judged.
}

// dueTime is the time from which plan[i] may start again. A zone check that
// started before the last move is due at the move, so that a changed record
// is seen at once; one that was already waiting for a free place keeps its
// earlier time, so a move never sends it back in the queue.
func (s *Schedule) dueTime(i int) time.Time {
	start, ok := s.starts[s.keys[i]]
	if !ok {
		return time.Time{}
	}
	due := start.Add(s.plan[i].Interval)
	if s.plan[i].Zone && s.moved.After(start) && s.moved.Before(due) {
		return s.moved
	}
	return due
}

// Due marks as running, with start now, and returns the checks due at now,
// the earliest due first. It never starts a running check again, and never
// lets more than MaxRunning run, so a start, a change of the file or a move
// of a large zone queues instead of bursting.
func (s *Schedule) Due(now time.Time) []Check {
	return s.Take(now, MaxRunning)
}

// Take is Due limited to at most n checks, so that one cap can bound the
// checks of several schedules.
func (s *Schedule) Take(now time.Time, n int) []Check {
	var due []int
	for i := range s.plan {
		if !s.running[s.keys[i]] && !s.dueTime(i).After(now) {
			due = append(due, i)
		}
	}
	slices.SortStableFunc(due, func(a, b int) int { return s.dueTime(a).Compare(s.dueTime(b)) })
	due = due[:max(0, min(len(due), n, MaxRunning-len(s.running)))]
	var checks []Check
	for _, i := range due {
		s.running[s.keys[i]] = true
		s.starts[s.keys[i]] = now
		checks = append(checks, s.plan[i])
	}
	return checks
}

// Next gives the earliest due time of a check that is not running. ok is
// false when no check can start before a running one is Done.
func (s *Schedule) Next() (next time.Time, ok bool) {
	if len(s.running) >= MaxRunning {
		return time.Time{}, false
	}
	for i := range s.plan {
		if s.running[s.keys[i]] {
			continue
		}
		if t := s.dueTime(i); !ok || t.Before(next) {
			next, ok = t, true
		}
	}
	return next, ok
}

// Done ends the run that gave o, seen at now.
func (s *Schedule) Done(o obs.Observation, now time.Time) Report {
	k := o.Key.String()
	usable := !decide.Failed(o)
	r := s.finish(k, o.Start, usable)
	if !r.Known {
		return r
	}
	if o.Key.Kind == obs.KindRecords {
		r.DisagreeLong, r.DisagreeOver = s.disagreeState(k, o, now)
	}
	if o.Key.Kind == obs.KindSerial {
		moves := s.serialMoves(o)
		for _, m := range moves {
			r.Moves = append(r.Moves, m.Move)
		}
		s.serialMoved = len(moves) > 0
		// Not o.Start: a zone check that started in the same tick saw the
		// zone at the same moment, so its notice shows no later change.
		if usable && !s.serialMoved {
			s.quiet = now
		}
		if s.serialMoved {
			s.startRound(moves, now)
		}
	}
	return r
}

// DoneCertificates ends the run that gave c. A certificate run is no DNS
// answer: it moves no serial and joins no round.
func (s *Schedule) DoneCertificates(c obs.Certificates, now time.Time) Report {
	return s.finish(c.Key.String(), c.Start, c.Usable)
}

// finish takes the run of key k out of the running set and reports what the
// schedule knows of its check.
func (s *Schedule) finish(k string, start time.Time, usable bool) Report {
	// A key that left the plan still held a place among the running checks.
	delete(s.running, k)
	i := slices.Index(s.keys, k)
	if i < 0 {
		return Report{}
	}
	tier := s.plan[i].Tier
	return Report{Known: true, Tier: tier, FailingSince: s.failingSince(k, start, usable), FailLimit: s.iv.FailLimit(tier)}
}

func (s *Schedule) failingSince(k string, start time.Time, usable bool) time.Time {
	if usable {
		delete(s.failing, k)
		return time.Time{}
	}
	since, ok := s.failing[k]
	if !ok {
		since = start
		s.failing[k] = since
	}
	return since
}

// disagreeState counts o in the entry of its key and reports whether the
// split is long enough to open an alert and whether it has been absent long
// enough to end one. A split goes on while every server that the entry knows
// gives the set it gave last; a new server joins. A run with no split in
// which a known server was asked and failed, and the others repeat, is
// unknown: a stale server that fails now and then must not end its own split.
func (s *Schedule) disagreeState(k string, o obs.Observation, now time.Time) (long, over bool) {
	d := s.disagreeing[k]
	if d == nil {
		d = &series{texts: map[netip.AddrPort]string{}}
		s.disagreeing[k] = d
	}
	sets := decide.Sets(o)
	repeats := d.runs > 0 && !slices.ContainsFunc(sets, func(x decide.Seen) bool {
		last, known := d.texts[x.Answer.Server.Addr]
		return known && last != x.Text
	})
	split := decide.Disagree(o)
	switch {
	case split && repeats:
		d.runs++
		d.quiet = 0
	case split:
		d.since, d.runs = o.Start, 1
		clear(d.texts)
		d.quiet++
	case repeats && d.failedAt(o, sets):
		return d.long(now, s.iv), d.quiet >= DisagreeRuns
	default:
		// The texts stay but are never read while runs is 0.
		d.runs = 0
		d.quiet++
	}
	if split {
		for _, x := range sets {
			d.texts[x.Answer.Server.Addr] = x.Text
		}
	}
	return d.long(now, s.iv), d.quiet >= DisagreeRuns
}

// failedAt reports whether o holds a failure at a server that d knows, or a
// failure with no address (the walk failed). A server that o did not ask,
// for instance one taken out of the NS set, is no failure.
func (d *series) failedAt(o obs.Observation, sets []decide.Seen) bool {
	return slices.ContainsFunc(o.Answers, func(a obs.Answer) bool {
		if slices.ContainsFunc(sets, func(x decide.Seen) bool { return x.Answer.Server.Addr == a.Server.Addr }) {
			return false
		}
		_, known := d.texts[a.Server.Addr]
		return known || !a.Server.Addr.IsValid()
	})
}

func (d *series) long(now time.Time, iv Intervals) bool {
	return d.runs >= DisagreeRuns && now.Sub(d.since) >= iv.DisagreeLimit()
}

// DisagreeLimit is how long the runs of a check may show two differing
// answers before it is reported: two intervals of the other tier, 10 minutes
// at the defaults. A server that is only slow to catch up must not alert.
func (iv Intervals) DisagreeLimit() time.Duration { return 2 * iv.Other }

// serialMoves compares the serial of each address in o with the one it gave
// before. An address that gave no serial keeps what it gave before, and the
// first serial of an address is only remembered: there is nothing to compare
// it with. A move is news when its serial is not known.
func (s *Schedule) serialMoves(o obs.Observation) []move {
	var moves []move
	var again []uint32 // serials to know once o is judged, in the order seen
	for _, a := range o.Answers {
		serial, ok := soaSerial(a.Result)
		if !ok {
			continue
		}
		news := !slices.Contains(s.known, serial)
		seen := sighting{a.Server, serial, a.Received}
		i := slices.IndexFunc(s.serials, func(x sighting) bool { return x.server.Addr == a.Server.Addr })
		if i < 0 {
			s.serials = append(s.serials, seen)
			again = append(again, serial)
			continue
		}
		if last := s.serials[i]; last.serial != serial {
			moves = append(moves, move{decide.Move{Server: a.Server, From: last.serial, To: serial, Until: last.at, Since: a.Received}, news})
		}
		if !news {
			again = append(again, serial)
		}
		s.serials[i] = seen
	}
	// Only after the loop: a serial that one address shows for the first
	// time does not make the move of another address to it in the same run
	// old.
	for _, serial := range again {
		s.know(serial)
	}
	return moves
}

// knownSerials bounds known. A machine behind an address that lags a change
// serves a serial from shortly before it, so the last serials are enough;
// the bound keeps a zone whose serial moves at every run from filling
// memory. A serial that a server still gives is seen at every run and stays.
const knownSerials = 64

// know puts serial at the end of known, the serials whose moves tell nothing
// new: each one is the first serial seen at an address, or the operator was
// told of a change to it. The membership of a value is all that counts, never
// an order of serials: two providers of one domain number their serials
// apart, and a new serial at either one is news.
func (s *Schedule) know(serial uint32) {
	s.known = slices.DeleteFunc(s.known, func(x uint32) bool { return x == serial })
	s.known = append(s.known, serial)
	if len(s.known) > knownSerials {
		s.known = slices.Delete(s.known, 0, 1)
	}
}

func soaSerial(r obs.Result) (uint32, bool) {
	set := obs.Match(r,
		func(rs obs.Records) []dnswire.Record { return rs.Set },
		func(obs.NoData) []dnswire.Record { return nil },
		func(obs.NoName) []dnswire.Record { return nil },
		func(obs.Failure) []dnswire.Record { return nil })
	for _, rr := range set {
		if soa, ok := rr.Data.(dnswire.SOA); ok {
			return soa.Serial, true
		}
	}
	return 0, false
}

// startRound makes every zone check pending again, also those that a running
// round had already seen, because each move may have changed any record. A
// move that is no news starts a round too: to run the checks again costs
// little, and a machine that lags can still show a record that differs. A
// move while a round waits joins that round, with its window, so that one
// verdict judges all its moves.
func (s *Schedule) startRound(moves []move, now time.Time) {
	s.moved = now
	if s.round == nil {
		s.round = &round{since: s.quiet}
	}
	for _, m := range moves {
		s.round.moves = merge(s.round.moves, m)
	}
	s.round.pending = s.zoneChecks()
	s.round.standing = map[string]bool{}
	s.round.ended = time.Time{}
}

// merge keeps one move per address, from the first serial to the last; it is
// news when one of its moves was.
func merge(moves []move, m move) []move {
	i := slices.IndexFunc(moves, func(x move) bool { return x.Server.Addr == m.Server.Addr })
	if i < 0 {
		return append(moves, m)
	}
	moves[i].To, moves[i].Since = m.To, m.Since
	moves[i].news = moves[i].news || m.news
	return moves
}

func (s *Schedule) zoneChecks() map[string]bool {
	zone := map[string]bool{}
	for i, c := range s.plan {
		if c.Zone {
			zone[s.keys[i]] = true
		}
	}
	return zone
}

// Judged takes what decide made of o: open is the Open that decide was given,
// changes what it gave. ok with moves: rounds ended, no run gave a notice of
// its own since the serial was last seen quiet, and no difference that stood
// in a round can end any more, so the caller reports the moves. ok without
// moves: the serial has been quiet for a while, so the caller ends the notice
// of earlier moves.
func (s *Schedule) Judged(o obs.Observation, open []decide.Finding, changes []decide.Change, now time.Time) (moves []decide.Move, ok bool) {
	k := o.Key.String()
	i := slices.Index(s.keys, k)
	if i < 0 {
		return nil, false
	}
	// The first usable run since the plan was made or replaced has no run
	// before it to differ from, so its notice tells of the state, not of a
	// change. Runs end out of the order of their starts; the latest start
	// counts.
	if s.judged[k] && s.plan[i].Zone && !decide.Failed(o) && o.Start.After(s.noticed) && slices.ContainsFunc(changes, ownNotice) {
		s.noticed = o.Start
	}
	s.judged[k] = s.judged[k] || !decide.Failed(o)
	if s.round != nil {
		return s.judgeRound(k, s.plan[i].Tier, o, stands(k, open), now)
	}
	// A run with no usable answer is no evidence that the serial stayed.
	if o.Key.Kind != obs.KindSerial || decide.Failed(o) || s.serialMoved {
		return nil, false
	}
	// Moves held back are told before the notice may end.
	if len(s.held) > 0 {
		return s.report(now)
	}
	return nil, s.lastReport.IsZero() || now.Sub(s.lastReport) >= s.iv.Other
}

// judgeRound counts o for the round when it gave a usable answer and started
// after the last move, or, while the round waits, at or after the end of its
// zone checks: a failed run is no evidence that nothing differs. stands tells
// that the check of o had an alert of a notice rule open.
func (s *Schedule) judgeRound(k string, tier Tier, o obs.Observation, stands bool, now time.Time) ([]decide.Move, bool) {
	r := s.round
	waiting := !r.ended.IsZero()
	if r.pending[k] && !o.Start.Before(s.moved) && !o.Start.Before(r.ended) && !decide.Failed(o) {
		delete(r.pending, k)
		if stands && !waiting {
			r.standing[k] = true
		}
	}
	// A zone check that has failed past its limit has its check-failing
	// alert; waiting for its usable answer would mute every later move.
	if since, failing := s.failing[k]; r.pending[k] && failing && now.Sub(since) >= s.iv.FailLimit(tier) {
		delete(r.pending, k)
	}
	// A notice from a run that started after the serial was last seen quiet
	// told the operator of a change in the window in which the serial moved:
	// the move is that change, or comes with it. Such a notice ends a wait at
	// once.
	explained := s.noticed.After(r.since)
	if len(r.pending) > 0 && !(waiting && explained) {
		return nil, false
	}
	if explained {
		s.round = nil
		for _, m := range r.moves {
			s.know(m.To)
		}
		return nil, false
	}
	// A difference that stood in the round can still end at the next run of
	// its check: a machine that lags gave the old record of a change that was
	// put back, and that end is the notice of the move. Reported now, the
	// moves would come beside an alert that is about to end; dropped, a
	// change that is put back between two runs would leave no trace at all.
	if !waiting && len(r.standing) > 0 {
		r.pending, r.standing, r.ended = r.standing, map[string]bool{}, now
		return nil, false
	}
	s.round = nil
	s.hold(r.moves)
	if len(s.held) == 0 {
		return nil, false
	}
	return s.report(now)
}

// hold adds moves to the held ones. A move to a known serial tells nothing
// new, and an address that is back at the serial it started from shows no
// change, so neither is held.
func (s *Schedule) hold(moves []move) {
	for _, m := range moves {
		s.held = merge(s.held, m)
	}
	s.held = slices.DeleteFunc(s.held, func(m move) bool { return !m.news || m.From == m.To })
}

// report gives the held moves at most once for each other-interval: a serial
// that moves at every run would otherwise send a notice at every run.
func (s *Schedule) report(now time.Time) ([]decide.Move, bool) {
	if !s.lastReport.IsZero() && now.Sub(s.lastReport) < s.iv.Other {
		return nil, false
	}
	s.lastReport = now
	return s.tell(), true
}

// Flush gives the moves that report holds back, and those of a round that
// waits, and forgets them, for a stop: they live only in memory, so a stop
// that kept them would never tell them.
func (s *Schedule) Flush(now time.Time) []decide.Move {
	if r := s.round; r != nil && !r.ended.IsZero() {
		s.round = nil
		s.hold(r.moves)
	}
	moves := s.tell()
	if len(moves) > 0 {
		s.lastReport = now
	}
	return moves
}

// tell gives the held moves and forgets them. Their serials are known from
// then on: the operator is told of them.
func (s *Schedule) tell() []decide.Move {
	var moves []decide.Move
	for _, m := range s.held {
		moves = append(moves, m.Move)
		s.know(m.To)
	}
	s.held = nil
	return moves
}

// noticeRule reports a rule whose alert tells the operator that a watched
// record of the zone differs from the file, or, when it ends, that it
// differed.
func noticeRule(r decide.Rule) bool {
	return decide.LineRule(r) || r == decide.RuleZone || r == decide.RuleWildcard || r == decide.RuleCAA
}

// ownNotice reports a change that tells the operator about the zone anyway,
// also when it ends an alert because a change was put back.
func ownNotice(c decide.Change) bool { return noticeRule(c.Finding.Rule) }

// stands reports whether an alert of a notice rule of check k was open
// before its run: the run left that difference standing, or ended it with a
// notice. Only the alerts of k count, as in decide.
func stands(k string, open []decide.Finding) bool {
	return slices.ContainsFunc(open, func(f decide.Finding) bool { return f.Check.String() == k && noticeRule(f.Rule) })
}
