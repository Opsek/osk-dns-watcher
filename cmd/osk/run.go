package main

import (
	"bytes"
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/signal"
	"slices"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/schedule"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// The fixed periods of the service. They are variables only so that a test
// can shorten them.
var (
	beatEvery = 10 * time.Second // after a crash, the stored beat is at most this old
	readEvery = 5 * time.Second  // a change of the file is taken within two of these
	passPause = time.Second      // from the end of one delivery pass to the next
	readStuck = 30 * time.Second // a read that has not ended by then is a problem of the file
)

// readFile reads the file again; a variable only so that a test can play a
// read that hangs or gives the file in part.
var readFile = readRegular

// readRegular is readExpect for the file lines of the service, which name
// the path themselves.
func readRegular(path string) ([]byte, error) {
	data, err := readExpect(path)
	if errors.Is(err, errNotRegular) {
		return nil, errNotRegular
	}
	return data, err
}

const (
	// logLines is how many lines wait for an output that takes them slowly;
	// beyond, lines are dropped and counted.
	logLines = 1024
	// logDrain is how long the stop waits for the output to take them.
	logDrain = time.Second
)

const secondLayout = "2006-01-02T15:04:05Z"

var tiers = []schedule.Tier{schedule.TierSerial, schedule.TierParent, schedule.TierFast, schedule.TierOther}

// service runs "osk run" until SIGINT or SIGTERM, each a clean stop.
func service(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, args, stdout, stderr)
}

// serve runs "osk run" until ctx ends: it runs each check of the file at the
// interval of its tier, keeps the alerts in the state folder and sends their
// notices to Slack. args are those after the command word.
func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	ra, msg := parseRun(args)
	if msg != "" {
		return runWrongUse(stderr, msg)
	}
	slack, msg := slackChannel(ra.minimum)
	if msg != "" {
		return runWrongUse(stderr, msg)
	}
	o, err := observe.New(ra.cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return runWrongUse(stderr, err.Error())
	}
	data, err := readExpect(ra.file)
	if err != nil {
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	f, err := expect.Keep(nil, data)
	if err != nil {
		return fail(stderr, 1, problemLines(ra.file, err))
	}
	s, err := store.Open(ra.state)
	if err != nil {
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	m := &monitor{
		path:     ra.file,
		domain:   f.Domain,
		fast:     ra.fast,
		file:     f,
		last:     fileRead{data: data},
		next:     fileRead{data: data},
		sched:    schedule.New(f, ra.fast, ra.iv),
		observer: o,
		store:    s,
		channels: []deliver.Channel{slack},
		out:      newLogger(stdout, logLines),
	}
	err = m.start(ra)
	if err == nil {
		err = m.watch(ctx)
	}
	return m.stop(err, stderr)
}

func runWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk run: "+msg+"\n"+usage)
}

// runArgs are the flags of run.
type runArgs struct {
	cfg     observe.Config
	file    string
	state   string
	iv      schedule.Intervals
	fast    []dnswire.Name
	minimum decide.Severity
}

// parseRun reads the flags of run. It returns a message when they are wrong.
func parseRun(args []string) (runArgs, string) {
	ra := runArgs{iv: schedule.Defaults(), minimum: decide.SeverityLow}
	var file, state *string
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("root-server", "a root server to start from, in place of the built-in ones", func(s string) error {
		server, err := parseServer(s)
		ra.cfg.RootServers = append(ra.cfg.RootServers, server)
		return err
	})
	flags.Func("extra-range", "a prefix of non-public addresses that may be asked", func(s string) error {
		prefix, err := netip.ParsePrefix(s)
		ra.cfg.ExtraRanges = append(ra.cfg.ExtraRanges, prefix)
		return err
	})
	flags.DurationVar(&ra.cfg.QueryTimeout, "timeout", 2*time.Second, "time for one query")
	flags.DurationVar(&ra.iv.Serial, "serial-interval", ra.iv.Serial, "time between two checks of the serial")
	flags.DurationVar(&ra.iv.Parent, "parent-interval", ra.iv.Parent, "time between two checks at the parent zone")
	flags.DurationVar(&ra.iv.Fast, "fast-interval", ra.iv.Fast, "time between two checks of a fast set")
	flags.DurationVar(&ra.iv.Other, "other-interval", ra.iv.Other, "time between two checks of any other set")
	flags.Func("fast", "a name whose sets are checked at the fast interval", func(s string) error {
		n, err := parseFast(s)
		ra.fast = append(ra.fast, n)
		return err
	})
	flags.Func("slack-min-severity", "the lowest severity of an alert that Slack hears of", func(s string) (err error) {
		ra.minimum, err = parseSeverity(s)
		return err
	})
	flags.Func("expect", "a file of expectations to compare with", once(&file))
	flags.Func("state", "a folder that keeps the alerts from run to run", once(&state))
	if err := flags.Parse(args); err != nil {
		return ra, err.Error()
	}
	switch {
	case ra.cfg.QueryTimeout <= 0:
		return ra, "the timeout must be positive"
	case file == nil:
		return ra, "--expect is required"
	case state == nil:
		return ra, "--state is required"
	case flags.NArg() > 0:
		return ra, "takes no arguments: the file gives the domain and the sets"
	}
	for _, t := range tiers {
		switch d := ra.iv.Of(t); {
		case d < schedule.Floor:
			return ra, fmt.Sprintf("--%s-interval %v is below the floor of %v", t, d, schedule.Floor)
		case d > schedule.Ceiling:
			return ra, fmt.Sprintf("--%s-interval %v is above %v", t, d, schedule.Ceiling)
		}
	}
	ra.file, ra.state = *file, *state
	return ra, ""
}

// once gives a flag function that keeps the value in *p and refuses a
// second value.
func once(p **string) func(string) error {
	return func(s string) error {
		if *p != nil {
			return errors.New("given more than once")
		}
		*p = &s
		return nil
	}
}

// parseFast reads a name of --fast. As in the file, a name without its
// trailing dot is a mistake: "www" may not stand for "www.corp.test.".
func parseFast(s string) (dnswire.Name, error) {
	body, ok := strings.CutSuffix(s, ".")
	// A dot after an odd number of backslashes belongs to the last label.
	if !ok || (len(body)-len(strings.TrimRight(body, `\`)))%2 == 1 {
		return dnswire.Name{}, errors.New("the name has no trailing dot")
	}
	return dnswire.ParseName(s)
}

// monitor is the state of a running service. Only the goroutine of serve,
// the writer, uses it; the delivery loops use only store, channels and out.
// Being the one writer of alerts and check states makes it safe to read the
// open alerts of a check and then Apply.
type monitor struct {
	path     string
	domain   dnswire.Name
	fast     []dnswire.Name
	file     *expect.File // in force: the last valid file of the domain
	last     fileRead     // the read that was taken last
	next     fileRead     // the read before, which the next one must repeat
	reading  time.Time    // when the read in flight started; zero when none
	stuck    bool         // the read in flight was reported
	sched    *schedule.Schedule
	observer *observe.Observer
	store    *store.Store
	channels []deliver.Channel
	out      *logger
}

// fileRead is the outcome of one read of the file: its octets, or the text
// of the error.
type fileRead struct {
	data []byte
	err  string
}

// start stores the beat of this start and prints the start lines. The file
// is valid now, so an invalid-file alert left by the last run ends here.
func (m *monitor) start(ra runArgs) error {
	now := time.Now()
	last, err := m.store.LastBeat()
	if err == nil {
		err = m.store.Beat(now, nil)
	}
	if err != nil {
		return err
	}
	checks := m.sched.Checks()
	m.out.print(fmt.Sprintf("start %s %d checks, state %s", m.domain.Lower().String(), len(checks), ra.state))
	for _, t := range tiers {
		n := 0
		for _, c := range checks {
			if c.Tier == t {
				n++
			}
		}
		m.out.print(fmt.Sprintf("plan %s every %v %d checks", t, ra.iv.Of(t), n))
	}
	m.printUnused()
	if !last.IsZero() {
		m.out.print("down since " + last.UTC().Format(secondLayout) + " for " + now.Sub(last).Round(time.Second).String())
	}
	return m.fileChanges(nil, now)
}

func (m *monitor) printUnused() {
	for _, n := range schedule.Unused(m.file, m.fast) {
		m.out.print("fast " + n.Lower().String() + " has no line in the file")
	}
}

// result is the end of one run of a check.
type result struct {
	o   obs.Observation
	err error
}

// watch runs the delivery loops and the check loop until ctx ends or the
// store fails. Every goroutine it starts has ended when it returns, except a
// read of the file that hangs.
func (m *monitor) watch(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	var wg sync.WaitGroup
	defer wg.Wait()
	defer cancel()
	failed := make(chan error, len(m.channels))
	for _, c := range m.channels {
		wg.Go(func() {
			if err := m.notify(ctx, c); err != nil {
				failed <- err
			}
		})
	}
	results := make(chan result)
	// One read at a time, so its result never waits for a receiver.
	reads := make(chan fileRead, 1)
	timer := time.NewTimer(0)
	beat := time.NewTicker(beatEvery)
	read := time.NewTicker(readEvery)
	defer timer.Stop()
	defer beat.Stop()
	defer read.Stop()
	for ctx.Err() == nil {
		for _, c := range m.sched.Due(time.Now()) {
			wg.Go(func() { m.check(ctx, c, results) })
		}
		var due <-chan time.Time
		if at, ok := m.sched.Next(); ok {
			// Since Go 1.23, Reset also drops a tick that was not received.
			timer.Reset(time.Until(at))
			due = timer.C
		}
		var err error
		select {
		case <-ctx.Done():
		case err = <-failed:
		case r := <-results:
			// A run that the stop cut short shows nothing of the zone.
			if ctx.Err() == nil {
				err = m.judge(r)
			}
		case <-due:
		case <-beat.C:
			err = m.store.Beat(time.Now(), nil)
		case <-read.C:
			err = m.startRead(reads, time.Now())
		case r := <-reads:
			m.reading = time.Time{}
			err = m.reread(r, time.Now())
		}
		if err != nil {
			return err
		}
	}
	return nil
}

// check runs one check and hands its result to the writer, unless the
// service stops first.
func (m *monitor) check(ctx context.Context, c schedule.Check, results chan<- result) {
	o, err := m.observer.Run(ctx, observe.Check{Key: c.Key, Interval: c.Interval})
	select {
	case results <- result{o, err}:
	case <-ctx.Done():
	}
}

// notify is the delivery loop of one channel, so that a channel that does
// not answer holds up only its own rows, and no check waits for it. The end
// of ctx cuts a send in flight; that row stays pending for the next start.
func (m *monitor) notify(ctx context.Context, c deliver.Channel) error {
	for {
		attempts, err := deliver.Pass(ctx, m.store, []deliver.Channel{c}, time.Now())
		for _, a := range attempts {
			m.out.print(a.Line())
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(passPause):
		}
	}
}

// judge takes the result of one run. A result whose key left the file is
// dropped: no line of the file judges it any more.
func (m *monitor) judge(r result) error {
	if r.err != nil {
		return r.err
	}
	o, now := r.o, time.Now()
	rep := m.sched.Done(o, now)
	if !rep.Known {
		return nil
	}
	m.out.print(checkedLine(rep.Tier, o))
	for _, mv := range rep.Moves {
		m.out.print(movedLine(m.domain, mv))
	}
	failed := slices.ContainsFunc(o.Answers, func(a obs.Answer) bool { return isFailure(a.Result) })
	changes, err := m.apply(o.Key, failed, now, func(open []decide.Finding) []decide.Change {
		return decide.Decide(decide.Input{Expect: m.file, Open: open, Observation: o, Now: now,
			FailingSince: rep.FailingSince, FailLimit: rep.FailLimit})
	})
	if err != nil {
		return err
	}
	moves, ok := m.sched.Judged(o, changes, now)
	if !ok {
		return nil
	}
	_, err = m.apply(m.scope(), false, now, func(open []decide.Finding) []decide.Change {
		return decide.ZoneChanges(m.domain, moves, open, now)
	})
	return err
}

// startRead reads the file again off the writer, so that a path that holds
// its reader (a FIFO swapped in after the check, a mount that stopped
// answering) cannot stop the checks. No read starts while one is in flight;
// one that has not ended after readStuck is reported once.
func (m *monitor) startRead(reads chan<- fileRead, now time.Time) error {
	if m.reading.IsZero() {
		m.reading, m.stuck = now, false
		read, path := readFile, m.path
		go func() {
			data, err := read(path)
			r := fileRead{data: data}
			if err != nil {
				r = fileRead{err: err.Error()}
			}
			reads <- r
		}()
		return nil
	}
	if m.stuck || now.Sub(m.reading) < readStuck {
		return nil
	}
	m.stuck = true
	return m.take(fileRead{err: "the read has not ended after " + readStuck.String()}, now)
}

// reread takes a read of the file when the read before gave the same: a
// file read while it is written, in part or empty, gives one odd read, and
// must not replace the file in force. The same outcome as the one taken last
// changes nothing, so a lasting problem is printed once.
func (m *monitor) reread(r fileRead, now time.Time) error {
	if !r.same(m.next) {
		m.next = r
		return nil
	}
	if r.same(m.last) {
		return nil
	}
	return m.take(r, now)
}

func (r fileRead) same(o fileRead) bool {
	return bytes.Equal(r.data, o.data) && r.err == o.err
}

// take puts the outcome of a read in force. A valid file of the domain
// becomes the file in force when its content differs; a file that cannot be
// read or is not valid leaves the one in force and opens or updates the
// invalid-file alert.
func (m *monitor) take(r fileRead, now time.Time) error {
	m.last = r
	f := m.file
	var problem error
	if r.err != "" {
		problem = errors.New(r.err)
	} else {
		f, problem = expect.Keep(m.file, r.data)
	}
	if problem == nil && !f.Domain.Equal(m.domain) {
		problem = &expect.Error{Problems: []expect.Problem{{Text: "the domain changed from " + m.domain.Lower().String() +
			" to " + f.Domain.Lower().String() + "; start osk run again to watch another domain"}}}
	}
	if problem != nil {
		for _, line := range fileLines(m.path, problem) {
			m.out.print(line)
		}
	}
	if err := m.fileChanges(problem, now); err != nil {
		return err
	}
	if problem != nil || f.String() == m.file.String() {
		return nil
	}
	m.file = f
	m.sched.Replace(f)
	m.out.print(fmt.Sprintf("file %s changed: %d checks", m.path, len(m.sched.Checks())))
	m.printUnused()
	return nil
}

// fileLines gives a line for each problem of a read of the file.
func fileLines(path string, problem error) []string {
	var e *expect.Error
	if !errors.As(problem, &e) {
		return []string{"file " + path + ": " + problem.Error()}
	}
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = "file " + path + ": " + p.Text
		if p.Line > 0 {
			lines[i] = fmt.Sprintf("file %s:%d: %s", path, p.Line, p.Text)
		}
	}
	return lines
}

// fileChanges opens, updates or ends the invalid-file alert of the domain.
func (m *monitor) fileChanges(problem error, now time.Time) error {
	_, err := m.apply(m.scope(), false, now, func(open []decide.Finding) []decide.Change {
		return decide.FileChanges(m.domain, problem, open, now)
	})
	return err
}

// scope is the key of the alerts about the whole domain, as decide gives
// them: no check has it, so only the service opens and ends them.
func (m *monitor) scope() obs.Key {
	return obs.Key{Domain: m.domain, Name: m.domain}
}

// apply is the alert path of check k. judge gets the findings of the open
// alerts of k, so a difference that stands gives no event. The events, their
// deliveries and the clean time of k are stored in one transaction. failed
// tells that some answer of the run is a failure.
func (m *monitor) apply(k obs.Key, failed bool, now time.Time, judge func(open []decide.Finding) []decide.Change) ([]decide.Change, error) {
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
	out := alert.Transition(alert.Input{Open: open, Changes: changes, Failed: failed, LastClean: lastClean, Now: now})
	if err := m.store.Apply(k, out.Clean, now, deliver.Writes(out.Events, m.channels)); err != nil {
		return nil, err
	}
	for _, e := range out.Events {
		m.out.print("alert " + e.Label())
	}
	return changes, nil
}

// stop stores the beat of the stop and closes the store. err is what ended
// the service, nil for the end of its context. Only the first error is
// told: after a store error, the others are mostly its echo.
func (m *monitor) stop(err error, stderr io.Writer) int {
	beatErr := m.store.Beat(time.Now(), nil)
	closeErr := m.store.Close()
	if err := cmp.Or(err, beatErr, closeErr); err != nil {
		m.out.close(logDrain)
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	m.out.print("stop")
	m.out.close(logDrain)
	return 0
}

// checkedLine tells how a run of a check went: ok when some server gave a
// usable answer, else the reasons of the failures.
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
			func(f obs.Failure) string { return f.Reason.String() })
		if r != "" && !slices.Contains(reasons, r) {
			reasons = append(reasons, r)
		}
	}
	return head + " failed " + strings.Join(reasons, ",")
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

// logger writes the lines of standard output from a goroutine of its own, so
// that an output that nobody reads cannot stop the checks. Each line starts
// with the time it was printed and is one Write; the lines are queued under
// the mutex, so they never mix and stand in time order.
type logger struct {
	mu      sync.Mutex
	lines   chan string
	dropped int
	done    chan struct{} // closed when every queued line was written
}

func newLogger(w io.Writer, size int) *logger {
	l := &logger{lines: make(chan string, size), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for line := range l.lines {
			// A broken log must not blind the monitor.
			_, _ = io.WriteString(w, line)
		}
	}()
	return l
}

// print never waits: a line that finds the queue full is dropped, and the
// next line that finds room is preceded by the count.
func (l *logger) print(line string) {
	stamp := time.Now().UTC().Format(receivedLayout) + " "
	l.mu.Lock()
	defer l.mu.Unlock()
	// Only print adds to the queue, under the mutex, so the room seen here
	// stays until the sends below.
	if l.dropped > 0 && cap(l.lines)-len(l.lines) >= 2 {
		l.lines <- stamp + "dropped " + strconv.Itoa(l.dropped) + " lines: the output was not read\n"
		l.dropped = 0
	}
	if l.dropped > 0 || len(l.lines) == cap(l.lines) {
		l.dropped++
		return
	}
	l.lines <- stamp + line + "\n"
}

// close lets the output take the queued lines for at most wait: a write that
// never ends must not hold the stop. Nothing may print after it.
func (l *logger) close(wait time.Duration) {
	close(l.lines)
	select {
	case <-l.done:
	case <-time.After(wait):
	}
}
