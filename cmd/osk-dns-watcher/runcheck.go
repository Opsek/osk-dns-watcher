package main

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/certlog"
	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// monitor is the state of a running service. Only the goroutine of serve,
// the writer, uses it, and it alone writes alerts, notices, beats and check
// states, which makes it safe to read the open alerts of a check and then
// Apply. The delivery loops use only store (to send and record rows),
// channels and out; the heartbeat only beatTo, health and out.
type monitor struct {
	cfg      *config.Config
	domains  []*watched
	observer *observe.Observer
	store    *store.Store
	channels []deliver.Channel
	policy   alert.Policy
	beatTo   *beater // nil: no heartbeat
	health   healthState
	out      *logger
	running  int               // checks in flight over all domains
	loaded   map[string]string // the expectations last loaded, by domain
	started  time.Time
	pruneAt  time.Time // the next deletion of old history
	asking   bool      // a read of the test request is in flight
	// certRunning counts the certificate runs among running. certWaiting
	// holds the certificate checks that a schedule marked running while
	// maxCertRuns ran, the first taken first.
	certRunning int
	certWaiting []taken
}

// maxCertRuns bounds the certificate runs in flight over all domains. A run
// may wait on a slow source for three quarters of its interval, and the
// places of MaxRunning are there for the DNS checks.
const maxCertRuns = 2

// taken is a check that its schedule marked running and that has not
// started yet.
type taken struct {
	d *watched
	c schedule.Check
}

// watched is what the service keeps of one domain of the config.
type watched struct {
	name    dnswire.Name
	label   string // the name in lower case, as the lines and the store give it
	path    string
	fast    []dnswire.Name
	file    *expect.File // in force: the last valid file of the domain
	sched   *schedule.Schedule
	running int                  // checks of the domain in flight
	judged  map[string]time.Time // by check: its last judged run, or when it entered the plan
	last    fileRead             // the read that was taken last
	next    fileRead             // the read before, which the next one must repeat
	since   time.Time            // when next was read first
	reading time.Time            // when the read in flight started; zero when none
	stuck   bool                 // the read in flight was reported
	// certs is used only by the run of the certificates check, never by the
	// writer: the schedule starts no run of a check while another is in
	// flight. nil: the certificate logs are not read.
	certs *certlog.Source
}

func newWatched(d config.Domain, f *expect.File, iv schedule.Intervals, now time.Time) *watched {
	w := &watched{
		name:   d.Name,
		label:  d.Name.Lower().String(),
		path:   d.Expect,
		fast:   d.Fast,
		file:   f,
		sched:  schedule.New(f, d.Fast, iv),
		judged: map[string]time.Time{},
	}
	w.replan(now)
	return w
}

// replan starts the time of each check that entered the plan at now, and
// forgets the checks that left it.
func (w *watched) replan(now time.Time) {
	keep := map[string]bool{}
	for _, c := range w.sched.Checks() {
		k := c.Key.String()
		keep[k] = true
		if _, ok := w.judged[k]; !ok {
			w.judged[k] = now
		}
	}
	maps.DeleteFunc(w.judged, func(k string, _ time.Time) bool { return !keep[k] })
}

// scope is the key of the alerts about the whole domain, as decide gives
// them: no check has it, so only the service opens and ends them.
func (w *watched) scope() obs.Key {
	return obs.Key{Domain: w.name, Name: w.name}
}

// result is the end of one run of a check of d.
type result struct {
	d     *watched
	o     obs.Observation
	err   error
	certs *obs.Certificates // a run of the certificates check, which has no o or err
}

// watch runs the delivery loops, the heartbeat and the writer until ctx ends
// or the store fails. Every goroutine it starts has ended when it returns,
// except a read of a file that hangs.
func (m *monitor) watch(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	failed := make(chan error, len(m.channels))
	for _, c := range m.channels {
		wg.Go(func() {
			if err := m.send(ctx, c); err != nil {
				failed <- err
			}
		})
	}
	if m.beatTo != nil {
		wg.Go(func() { m.heartbeat(ctx) })
	}
	results := make(chan result)
	// One read in flight for each file and one for the test request, so no
	// read waits for a receiver.
	reads := make(chan domainRead, len(m.domains))
	requests := make(chan request, 1)
	timer := time.NewTimer(0)
	beat := time.NewTicker(beatEvery)
	read := time.NewTicker(readEvery)
	defer timer.Stop()
	defer beat.Stop()
	defer read.Stop()
	for ctx.Err() == nil {
		m.startChecks(ctx, &wg, results)
		var due <-chan time.Time
		if at, ok := m.next(); ok {
			// Since Go 1.23, Reset also drops a tick that was not received.
			timer.Reset(time.Until(at))
			due = timer.C
		}
		var err error
		select {
		case <-ctx.Done():
		case err = <-failed:
		case r := <-results:
			m.running--
			r.d.running--
			if r.certs != nil {
				m.certRunning--
			}
			// A run that the stop cut short shows nothing of the zone.
			if ctx.Err() == nil {
				err = m.judge(r)
			}
		case <-due:
		case <-beat.C:
			err = m.tick(time.Now())
		case <-read.C:
			err = m.startReads(reads, requests, time.Now())
		case r := <-reads:
			r.d.reading = time.Time{}
			err = m.reread(r.d, r.r, time.Now())
		case r := <-requests:
			m.asking = false
			err = m.takeRequest(r, time.Now())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// startChecks starts due checks while fewer than MaxRunning run over all
// domains, because the domains share observe's limit for each address of
// their parent and their DNS provider. A certificate check taken while
// maxCertRuns run waits for a free one, and the checks due behind it start.
func (m *monitor) startChecks(ctx context.Context, wg *sync.WaitGroup, results chan<- result) {
	now := time.Now()
	for m.running < schedule.MaxRunning {
		if len(m.certWaiting) > 0 && m.certRunning < maxCertRuns {
			t := m.certWaiting[0]
			m.certWaiting = m.certWaiting[1:]
			m.startCheck(ctx, wg, results, t.d, t.c)
			continue
		}
		d := m.pick(now)
		if d == nil {
			return
		}
		for _, c := range d.sched.Take(now, 1) {
			if c.Key.Kind == obs.KindCertificates && m.certRunning >= maxCertRuns {
				m.certWaiting = append(m.certWaiting, taken{d, c})
				continue
			}
			m.startCheck(ctx, wg, results, d, c)
		}
	}
}

func (m *monitor) startCheck(ctx context.Context, wg *sync.WaitGroup, results chan<- result, d *watched, c schedule.Check) {
	m.running++
	d.running++
	if c.Key.Kind == obs.KindCertificates {
		m.certRunning++
	}
	wg.Go(func() { m.check(ctx, d, c, results) })
}

// pick gives the domain to start a check of, among those with a check due
// at now: the one with the fewest checks in flight, then the one whose
// check is due first, then the one listed first; nil when none is due. A
// domain whose servers do not answer holds each place until its checks time
// out, and after its start or a change of its file every check of it is due
// at once; by earliest due time alone it would then take every place while
// the other domains wait.
func (m *monitor) pick(now time.Time) *watched {
	var best *watched
	var at time.Time
	for _, d := range m.domains {
		t, ok := d.sched.Next()
		if !ok || t.After(now) {
			continue
		}
		if best == nil || d.running < best.running || d.running == best.running && t.Before(at) {
			best, at = d, t
		}
	}
	return best
}

// next gives when the next check is due. ok is false while MaxRunning run:
// nothing can start before one ends, and a due time in the past would only
// wake the writer for nothing.
func (m *monitor) next() (next time.Time, ok bool) {
	if m.running >= schedule.MaxRunning {
		return time.Time{}, false
	}
	for _, d := range m.domains {
		if t, due := d.sched.Next(); due && (!ok || t.Before(next)) {
			next, ok = t, true
		}
	}
	return next, ok
}

// check runs one check and hands its result to the writer, unless the
// service stops first.
func (m *monitor) check(ctx context.Context, d *watched, c schedule.Check, results chan<- result) {
	r := result{d: d}
	if c.Key.Kind == obs.KindCertificates {
		r.certs = readCerts(ctx, d.certs, c.Interval)
	} else {
		r.o, r.err = m.observer.Run(ctx, observe.Check{Key: c.Key, Interval: c.Interval})
	}
	select {
	case results <- r:
	case <-ctx.Done():
	}
}

// readCerts runs the source within three quarters of the interval, as
// observe bounds a DNS check, so that the run ends before the next is due
// and the late checks keep their meaning. A request that the bound cuts is a
// timeout.
func readCerts(ctx context.Context, s *certlog.Source, interval time.Duration) *obs.Certificates {
	ctx, cancel := context.WithTimeout(ctx, interval-interval/4)
	defer cancel()
	c := s.Run(ctx, time.Now())
	return &c
}

// judge takes the result of one run. A result whose key left the file is
// dropped: no line of the file judges it any more.
func (m *monitor) judge(r result) error {
	if r.certs != nil {
		return m.judgeCerts(r.d, *r.certs)
	}
	if r.err != nil {
		return r.err
	}
	d, o, now := r.d, r.o, time.Now()
	rep := d.sched.Done(o, now)
	if !rep.Known {
		return nil
	}
	d.judged[o.Key.String()] = now
	m.out.log(levelInfo, d.label, checkedLine(rep.Tier, o))
	for _, mv := range rep.Moves {
		m.out.log(levelInfo, d.label, movedLine(d.name, mv))
	}
	failed := slices.ContainsFunc(o.Answers, func(a obs.Answer) bool { return isFailure(a.Result) })
	nsOpen, err := m.nameServersOpen(d, o.Key)
	if err != nil {
		return err
	}
	changes, err := m.apply(d, o.Key, failed, now, func(open []decide.Finding) []decide.Change {
		return decide.Decide(decide.Input{Expect: d.file, Open: open, Observation: o, Now: now,
			FailingSince: rep.FailingSince, FailLimit: rep.FailLimit, NameServersOpen: nsOpen,
			DisagreeLong: rep.DisagreeLong, DisagreeOver: rep.DisagreeOver})
	})
	if err != nil {
		return err
	}
	moves, ok := d.sched.Judged(o, changes, now)
	// After a start the schedule knows no move of before it, so a quiet
	// serial run could end a zone-changed alert whose last moves were never
	// told; one other-interval of quiet must pass first.
	if !ok || len(moves) == 0 && now.Sub(m.started) < m.cfg.Intervals.Other {
		return nil
	}
	return m.zoneChanges(d, moves, now)
}

// judgeCerts takes one run of the certificates check of d. A run records a
// clean time only when it asked the source and read the whole list: a run
// inside a wait or in the middle of a listing has not seen the check clean.
// The run is no DNS answer, so it plays no part in a zone round.
func (m *monitor) judgeCerts(d *watched, c obs.Certificates) error {
	now := time.Now()
	rep := d.sched.DoneCertificates(c, now)
	if !rep.Known {
		return nil
	}
	d.judged[c.Key.String()] = now
	m.out.log(levelInfo, d.label, certsLine(rep.Tier, c))
	_, err := m.apply(d, c.Key, !c.Usable || !c.Complete || !c.Asked, now, func(open []decide.Finding) []decide.Change {
		return decide.DecideCertificates(decide.CertInput{Expect: d.file, Open: open, Certificates: c, Now: now,
			FailingSince: rep.FailingSince, FailLimit: rep.FailLimit})
	})
	return err
}

func (m *monitor) zoneChanges(d *watched, moves []decide.Move, now time.Time) error {
	_, err := m.apply(d, d.scope(), false, now, func(open []decide.Finding) []decide.Change {
		return decide.ZoneChanges(d.name, moves, open, now)
	})
	return err
}

// flush tells, as an update of zone-changed, the moves that its rate bound
// still holds: they live only in memory, and a restart would lose them.
func (m *monitor) flush(now time.Time) error {
	for _, d := range m.domains {
		if moves := d.sched.Flush(now); len(moves) > 0 {
			if err := m.zoneChanges(d, moves, now); err != nil {
				return err
			}
		}
	}
	return nil
}

// fileChanges opens, updates or ends the invalid-file alert of d.
func (m *monitor) fileChanges(d *watched, problem error, now time.Time) error {
	_, err := m.apply(d, d.scope(), false, now, func(open []decide.Finding) []decide.Change {
		return decide.FileChanges(d.name, problem, open, now)
	})
	return err
}

// nameServersOpen tells whether an alert of rule nameservers is open for the
// domain of d. Only the ds check asks: a new DS next to new nameservers is a
// takeover, so decide raises the ds alert to critical then.
func (m *monitor) nameServersOpen(d *watched, k obs.Key) (bool, error) {
	if k.Kind != obs.KindDS {
		return false, nil
	}
	open, err := m.store.OpenAlerts(obs.DelegationKey(d.name))
	if err != nil {
		return false, err
	}
	return slices.ContainsFunc(open, func(a alert.Alert) bool { return a.Rule == decide.RuleNameServers }), nil
}

// apply is the alert path of check k of d. judge gets the findings of the
// open alerts of k, so a difference that stands gives no event. The events,
// their deliveries and the clean time of k are stored in one transaction.
// failed tells that the run cannot show k clean, so it records no clean time.
func (m *monitor) apply(d *watched, k obs.Key, failed bool, now time.Time, judge func(open []decide.Finding) []decide.Change) ([]decide.Change, error) {
	open, err := m.store.OpenAlerts(k)
	if err != nil {
		return nil, err
	}
	lastClean, err := m.store.LastClean(k)
	if err != nil {
		return nil, err
	}
	findings := make([]decide.Finding, len(open))
	for i, a := range open {
		findings[i] = a.Finding()
	}
	changes := judge(findings)
	out := alert.Transition(alert.Input{Open: open, Changes: changes, Failed: failed, LastClean: lastClean, Now: now, Policy: m.policy})
	if err := m.store.Apply(k, out.Clean, now, deliver.Writes(out.Events, m.channels)); err != nil {
		return nil, err
	}
	for _, e := range out.Events {
		m.out.log(levelInfo, d.label, "alert "+e.Label())
	}
	return changes, nil
}

// tick is the beat of the writer: the stored beat with the late checks, and
// the next batch of old history when one is due.
func (m *monitor) tick(now time.Time) error {
	if err := m.beat(now, m.late(now)); err != nil {
		return err
	}
	if now.Before(m.pruneAt) {
		return nil
	}
	return m.prune(now)
}

// beat stores the beat, then reads the health that the heartbeat reports
// on: only the writer knows which checks are late.
func (m *monitor) beat(now time.Time, late []string) error {
	if err := m.store.Beat(now, late); err != nil {
		return err
	}
	h, err := m.store.Health(now, m.cfg.Channels())
	if err != nil {
		return err
	}
	m.health.set(h)
	return nil
}

// late gives the keys of the checks not judged for more than two intervals
// and 10 s: a run starts at most one interval after the last start and ends
// within three quarters of one, and the 10 s cover the wait for a free place
// and for the beat.
func (m *monitor) late(now time.Time) []string {
	var late []string
	for _, d := range m.domains {
		for _, c := range d.sched.Checks() {
			k := c.Key.String()
			if now.Sub(d.judged[k]) > 2*c.Interval+10*time.Second {
				late = append(late, k)
			}
		}
	}
	slices.Sort(late)
	return late
}

// prune deletes one batch of history from before history_days. A full batch
// leaves more to delete at the next beat.
func (m *monitor) prune(now time.Time) error {
	cutoff := now.Add(-time.Duration(m.cfg.HistoryDays) * 24 * time.Hour)
	alerts, notices, err := m.store.Prune(cutoff, pruneBatch)
	if err != nil {
		return err
	}
	if alerts > 0 || notices > 0 {
		m.out.print(fmt.Sprintf("history deleted %d alerts and %d notices from before %s",
			alerts, notices, cutoff.UTC().Format(secondLayout)))
	}
	m.pruneAt = now.Add(pruneEvery)
	if alerts == pruneBatch || notices == pruneBatch {
		m.pruneAt = now
	}
	return nil
}

// healthState is the health that the writer read at its last beat. The
// heartbeat judges it at its own time, so a writer that stopped beating
// stops the heartbeat too.
type healthState struct {
	mu sync.Mutex
	h  store.Health
}

func (s *healthState) set(h store.Health) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.h = h
}

func (s *healthState) problems(now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.h.Problems(now)
}

// checkedLine tells how a run of a check went: ok when some server gave a
// usable answer, else the reasons of the failures. A failed policy check
// also gives the cause in parentheses: no alert names it.
func checkedLine(t schedule.Tier, o obs.Observation) string {
	head := "checked " + t.String() + " " + o.Key.String() + " " + o.Start.UTC().Format(receivedLayout)
	if !decide.Failed(o) {
		return head + " ok"
	}
	var reasons []string
	for _, a := range o.Answers {
		r := obs.Match(a.Result,
			func(obs.Records) string { return "" },
			func(obs.NoData) string { return "" },
			func(obs.NoName) string { return "" },
			func(f obs.Failure) string {
				// The fetch of a policy file gives only fixed texts, such as
				// "HTTP status 404", that hold no octet of the answer.
				if o.Key.Kind == obs.KindPolicy && f.Detail != "" {
					return f.Reason.String() + " (" + f.Detail + ")"
				}
				return f.Reason.String()
			})
		if r != "" && !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	return head + " failed " + strings.Join(reasons, ",")
}

// certsLine tells how a run of the certificates check went. A run inside a
// wait that the source asked for says so: it read nothing new.
func certsLine(t schedule.Tier, c obs.Certificates) string {
	head := "checked " + t.String() + " " + c.Key.String() + " " + c.Start.UTC().Format(receivedLayout)
	if !c.Usable {
		return head + " failed " + c.Failure
	}
	line := head + " ok " + strconv.Itoa(len(c.Issuances)) + " valid"
	if !c.Complete {
		line += " (listing)"
	}
	unread := 0
	for _, is := range c.Issuances {
		unread += is.Unread
	}
	if unread > 0 {
		line += ", " + strconv.Itoa(unread) + " names not read"
	}
	if !c.Asked {
		line += " (not asked: the source said to wait)"
	}
	return line
}

// movedLine names a server as the proof of an alert does: "-" for no
// address, and for a server whose name is not known.
func movedLine(domain dnswire.Name, mv decide.Move) string {
	addr, host := "-", "-"
	if mv.Server.Addr.IsValid() {
		addr = mv.Server.Addr.String()
	}
	if mv.Server.Name.LabelCount() > 0 {
		host = mv.Server.Name.Lower().String()
	}
	return fmt.Sprintf("moved %s %s %s serial %d to %d", domain.Lower().String(), addr, host, mv.From, mv.To)
}
