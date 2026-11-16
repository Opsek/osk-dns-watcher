package schedule

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The service starts the checks of all its domains under one cap: each
// time, it takes one check from the domain with the fewest checks in flight,
// then the earliest due time. Take is what lets it take fewer checks than
// Due gives.

func TestTakeGivesTheFirstChecksOfDueAndMarksOnlyThose(t *testing.T) {
	f := schBase(t)
	s, twin := New(f, nil, schIv), New(f, nil, schIv)
	all := twin.Due(schT0)
	if len(all) != len(schModelPlan(t, f, nil, schIv)) {
		t.Fatalf("Due(T0) of a new schedule gave%s", schShow(schKeyTexts(all)))
	}
	if got := s.Take(schT0, 0); len(got) != 0 {
		t.Fatalf("Take(T0, 0) gave%s", schShow(schKeyTexts(got)))
	}
	schSameChecks(t, "Take(T0, 3)", s.Take(schT0, 3), all[:3])
	schSameChecks(t, "Take(T0, 1) after it", s.Take(schT0, 1), all[3:4])
	schSameChecks(t, "Take(T0, 100) after them", s.Take(schT0, 100), all[4:])
	if got := s.Take(schAfter(time.Hour), 1); len(got) != 0 {
		t.Fatalf("Take gave%s while every check runs", schShow(schKeyTexts(got)))
	}
	if next, ok := s.Next(); ok {
		t.Fatalf("Next gave %s while every check runs", schWhen(next))
	}
}

func TestTakeNeverLetsMoreThanMaxRunningRun(t *testing.T) {
	f := schFile(t, schManyLines()...)
	s := New(f, nil, schIv)
	plan := schModelPlan(t, f, nil, schIv)
	schSameChecks(t, "Take(T0, 100)", s.Take(schT0, 100), plan[:MaxRunning])
	if got := s.Take(schT0, 1); len(got) != 0 {
		t.Fatalf("Take gave%s while %d checks run", schShow(schKeyTexts(got)), MaxRunning)
	}
	s.Done(schUsable(t, plan[2].Key, schT0), schSec(1))
	schSameChecks(t, "Take(T0+1s, 5) with one free slot", s.Take(schSec(1), 5), plan[MaxRunning:MaxRunning+1])
}

// Due is Take with the cap of one schedule: equal schedules give equal
// checks.
func TestDueEqualsTakeOfMaxRunning(t *testing.T) {
	f := schFile(t, schManyLines()...)
	a, b := New(f, nil, schIv), New(f, nil, schIv)
	schSameChecks(t, "Take(T0, MaxRunning)", a.Take(schT0, MaxRunning), b.Due(schT0))
	for _, c := range a.Checks()[:5] {
		a.Done(schUsable(t, c.Key, schT0), schSec(1))
		b.Done(schUsable(t, c.Key, schT0), schSec(1))
	}
	schSameChecks(t, "Take(T0+2s, MaxRunning) after five ended", a.Take(schSec(2), MaxRunning), b.Due(schSec(2)))
}

// ---- The property: several schedules under one cap, as the service runs them ----

// schTakeDomains are the domains of the property, each with names of its
// own zone, of a cut and outside it.
var schTakeDomains = []string{"corp.test.", "shop.test.", "example.org.", "a.b.example."}

var schTakeLabels = []string{"", "www.", "mail.", "_dmarc.", "_acme-challenge.", "sub.", "x.sub.", "h1.", "h2.", "h3.",
	"h4.", "h5.", "h6.", "h7.", "h8."}

var schTakeTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCAA,
	dnswire.TypeNS, dnswire.TypeCNAME}

// schTakeFile is a random file of domain d: lines of the form none, and NS
// lines with data, which make cuts.
func schTakeFile(t testing.TB, rng *rand.Rand, d string) *expect.File {
	t.Helper()
	lines := []string{"domain " + d}
	seen := map[string]bool{}
	for range rng.IntN(16) {
		owner, typ := schPick(rng, schTakeLabels...)+d, schPick(rng, schTakeTypes...)
		if seen[owner+typ.String()] {
			continue
		}
		seen[owner+typ.String()] = true
		form := "none"
		if typ == dnswire.TypeNS && rng.IntN(2) == 0 {
			form = "ns1." + owner
		}
		lines = append(lines, owner+" "+typ.String()+" "+form)
	}
	text := strings.Join(lines, "\n") + "\n"
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return f
}

var schTakeIntervals = []Intervals{
	schIv,
	{Serial: 5 * time.Second, Parent: 5 * time.Second, Fast: 5 * time.Second, Other: 5 * time.Second},
	{Serial: 15 * time.Second, Parent: time.Minute, Fast: time.Minute, Other: 5 * time.Minute},
}

// schTakeDomain is one schedule of the property, with every call made on
// it, so that a fresh schedule can be brought to the same state.
type schTakeDomain struct {
	file *expect.File
	iv   Intervals
	s    *Schedule
	log  []func(*Schedule)
}

func (d *schTakeDomain) do(op func(*Schedule)) {
	op(d.s)
	d.log = append(d.log, op)
}

func (d *schTakeDomain) replay() *Schedule {
	s := New(d.file, nil, d.iv)
	for _, op := range d.log {
		op(s)
	}
	return s
}

type schTakeRun struct {
	domain int
	check  Check
	start  time.Time
}

// schTakeCase drives up to four schedules as the writer of the service
// does, and gives the trace of every Take and Next, so that a second drive
// with the same seed can be compared with it.
type schTakeCase struct {
	t       *testing.T
	rng     *rand.Rand
	c, act  int
	now     time.Time
	domains []*schTakeDomain
	running map[string]schTakeRun
	trace   []string
	kit     *schKit
	capped  bool // the cap held back a due check at least once
	probes  int
}

func (tc *schTakeCase) fail(format string, args ...any) {
	tc.t.Helper()
	tc.t.Fatalf("seed %d case %d action %d: %s", schSeed, tc.c, tc.act, fmt.Sprintf(format, args...))
}

func (tc *schTakeCase) record(format string, args ...any) {
	tc.trace = append(tc.trace, fmt.Sprintf(format, args...))
}

// pick gives the domain that the writer takes a check from: of the domains
// with a check due now, the one with the fewest checks in flight, then the
// earliest due time, then the first of the config, so that a domain whose
// servers never answer cannot hold back the others.
func (tc *schTakeCase) pick() (int, bool) {
	best, found := 0, false
	var at time.Time
	flying := map[int]int{}
	for _, r := range tc.running {
		flying[r.domain]++
	}
	for i, d := range tc.domains {
		next, ok := d.s.Next()
		tc.record("next %d %s %v", i, schWhen(next), ok)
		if !ok || next.After(tc.now) {
			continue
		}
		if !found || flying[i] < flying[best] || flying[i] == flying[best] && next.Before(at) {
			best, at, found = i, next, true
		}
	}
	return best, found
}

// fill starts checks while fewer than MaxRunning run over all domains.
func (tc *schTakeCase) fill() {
	tc.t.Helper()
	for {
		i, ok := tc.pick()
		if !ok {
			return
		}
		if len(tc.running) >= MaxRunning {
			tc.capped = true
			return
		}
		d := tc.domains[i]
		probe := tc.rng.IntN(8) == 0
		var want []Check
		if probe {
			want = d.replay().Due(tc.now)
		}
		now := tc.now
		got := d.s.Take(now, 1)
		d.log = append(d.log, func(s *Schedule) { s.Take(now, 1) })
		tc.record("take %d %s %q", i, schWhen(tc.now), schKeyTexts(got))
		if len(got) != 1 {
			tc.fail("Next of domain %d is due at %s, and Take(now, 1) gave%s", i, schWhen(tc.now), schShow(schKeyTexts(got)))
		}
		if probe {
			tc.probes++
			if len(want) == 0 || schText(got[0]) != schText(want[0]) {
				tc.fail("Take(%s, 1) gave %s; the first check of Due of an equal schedule is %s",
					schWhen(tc.now), schText(got[0]), schText(want[0]))
			}
			tc.probe(d)
		}
		k := got[0].Key.String()
		if _, run := tc.running[k]; run {
			tc.fail("Take gave %s, which runs", k)
		}
		tc.running[k] = schTakeRun{i, got[0], tc.now}
		if len(tc.running) > MaxRunning {
			tc.fail("%d checks run over all domains", len(tc.running))
		}
	}
}

// probe compares Take(now, n) of an equal schedule with the first n checks
// of Due of another.
func (tc *schTakeCase) probe(d *schTakeDomain) {
	tc.t.Helper()
	n := tc.rng.IntN(MaxRunning + 3)
	a, b := d.replay(), d.replay()
	got, due := a.Take(tc.now, n), b.Due(tc.now)
	want := due[:min(n, len(due))]
	if !slices.Equal(schTexts(got), schTexts(want)) {
		tc.fail("Take(%s, %d) gave%s\nwant the first %d of Due:%s", schWhen(tc.now), n, schShow(schTexts(got)), n,
			schShow(schTexts(due)))
	}
	keys := schKeyTexts(got)
	if len(slices.Compact(slices.Sorted(slices.Values(keys)))) != len(keys) {
		tc.fail("Take gave a key twice:%s", schShow(keys))
	}
	for _, k := range keys {
		if _, run := tc.running[k]; run {
			tc.fail("Take(%s, %d) gave %s, which runs", schWhen(tc.now), n, k)
		}
	}
}

// observation is the end of run r: usable, failed, or for a serial check a
// serial at each server, so that serials move now and then.
func (tc *schTakeCase) observation(r schTakeRun) obs.Observation {
	at := func(s obs.Server, res obs.Result) obs.Answer {
		return obs.Answer{Proof: obs.Proof{Server: s, Sent: tc.now, Received: tc.now}, Result: res}
	}
	k := r.check.Key
	if k.Kind == obs.KindSerial {
		return schObs(k, r.start, at(tc.kit.ns1, tc.kit.soa[1+tc.rng.IntN(3)]), at(tc.kit.ns2, tc.kit.soa[1+tc.rng.IntN(3)]))
	}
	if tc.rng.IntN(4) == 0 {
		return schObs(k, r.start, at(tc.kit.ns1, schTimeout), at(tc.kit.ns2, tc.kit.refused))
	}
	return schObs(k, r.start, at(tc.kit.ns1, tc.kit.a), at(tc.kit.ns2, tc.kit.noName))
}

// end ends one run, as the writer does: Done, then Judged.
func (tc *schTakeCase) end() {
	keys := slices.Sorted(maps.Keys(tc.running))
	if len(keys) == 0 {
		return
	}
	k := schPick(tc.rng, keys...)
	r := tc.running[k]
	delete(tc.running, k)
	o := tc.observation(r)
	var changes []decide.Change
	if tc.rng.IntN(5) == 0 {
		changes = []decide.Change{{Op: decide.OpOpen, Finding: decide.Finding{Rule: decide.RuleRecordSet, Check: r.check.Key}, At: tc.now}}
	}
	now := tc.now
	tc.domains[r.domain].do(func(s *Schedule) {
		s.Done(o, now)
		s.Judged(o, changes, now)
	})
	tc.record("end %s %s", k, schWhen(now))
}

func (tc *schTakeCase) step() {
	switch x := tc.rng.IntN(20); {
	case x < 6:
		tc.fill()
	case x < 14:
		for range 1 + tc.rng.IntN(3) {
			tc.end()
		}
	case x < 19:
		gaps := []time.Duration{0, time.Millisecond, time.Second, 5 * time.Second, 61 * time.Second, 5 * time.Minute}
		tc.now = tc.now.Add(schPick(tc.rng, gaps...))
	default:
		i := tc.rng.IntN(len(tc.domains))
		d := tc.domains[i]
		f := schTakeFile(tc.t, tc.rng, d.file.Domain.String())
		d.do(func(s *Schedule) { s.Replace(f) })
		tc.record("replace %d %s", i, f)
	}
}

func schTakeDrive(t *testing.T, c int, kit *schKit) *schTakeCase {
	t.Helper()
	tc := &schTakeCase{t: t, rng: schRand(c), c: c, now: schT0, running: map[string]schTakeRun{}, kit: kit}
	for _, d := range schTakeDomains[:1+tc.rng.IntN(len(schTakeDomains))] {
		f := schTakeFile(t, tc.rng, d)
		iv := schPick(tc.rng, schTakeIntervals...)
		tc.domains = append(tc.domains, &schTakeDomain{file: f, iv: iv, s: New(f, nil, iv)})
	}
	for tc.act = 0; tc.act < 40; tc.act++ {
		tc.step()
	}
	tc.fill()
	return tc
}

// Over random domains, files, runs and times, driven as the writer drives
// them: each Take(now, 1) gives exactly the earliest due check of its
// schedule, the first check of Due; Take(now, n) is the first n checks of
// Due; no check runs twice; at most MaxRunning run over all domains; and the
// same calls give the same results.
func TestTakeProperty(t *testing.T) {
	kit := schNewKit(t)
	capped, probes, several := 0, 0, 0
	for c := range schCases {
		first := schTakeDrive(t, c, kit)
		second := schTakeDrive(t, c, kit)
		if !slices.Equal(first.trace, second.trace) {
			i := 0
			for i < min(len(first.trace), len(second.trace)) && first.trace[i] == second.trace[i] {
				i++
			}
			t.Fatalf("seed %d case %d: the same calls gave other results at call %d: %q and %q", schSeed, c, i,
				first.trace[min(i, len(first.trace)-1)], second.trace[min(i, len(second.trace)-1)])
		}
		if first.capped {
			capped++
		}
		if len(first.domains) > 1 {
			several++
		}
		probes += first.probes
	}
	// The cases must reach the cap and compare with Due often, or the
	// property proves little.
	if capped < schCases/20 || probes < schCases || several < schCases/2 {
		t.Errorf("seed %d: %d cases reached the cap over all domains, %d had several domains, %d probes; want at least %d, %d and %d",
			schSeed, capped, several, probes, schCases/20, schCases/2, schCases)
	}
}
