package schedule

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// dngChallengeOwner says whether the lines of n are fast because of their
// name: the first label is _acme-challenge in any case, and n is at or under
// the domain d.
func dngChallengeOwner(n, d dnswire.Name) bool {
	labels := n.Labels()
	return len(labels) > 0 && strings.EqualFold(labels[0], "_acme-challenge") && n.IsSubdomainOf(d)
}

// dngLimit is the limit of schIv: twice its other interval.
const dngLimit = 10 * time.Minute

// dngResultOf is the answer of one server for owner, by word: "x" is a
// failure, "nodata" and "noname" are those answers, and anything else is a
// set of A records at 10.53.0.<n> for each number n of the comma list.
func dngResultOf(t testing.TB, owner, word string) obs.Result {
	t.Helper()
	switch word {
	case "x":
		return schTimeout
	case "nodata":
		return schNoData(t, 1)
	case "noname":
		return schNoName(t, 1)
	}
	var set []dnswire.Record
	for _, last := range strings.Split(word, ",") {
		set = append(set, dnswire.Record{Name: schName(t, owner), Class: dnswire.ClassINET, TTL: uint32(300 + len(set)),
			Data: dnswire.A{Addr: netip.MustParseAddr("10.53.0." + last)}})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

// dngServer is the address of the nth server, from 0; its name is the nth
// of ns1, ns2 and so on.
func dngServer(n int) (host, addr string) {
	return fmt.Sprintf("ns%d.corp.test.", n+1), fmt.Sprintf("10.53.0.%d:53", 11+n)
}

// dngRunOf is a run of k that started at start; the nth server gave the nth
// word of run, which dngResultOf reads. The word "-" is a server that the run
// did not ask, and "walk" is a failure that has no address.
func dngRunOf(t testing.TB, k obs.Key, start time.Time, run string) obs.Observation {
	t.Helper()
	var answers []obs.Answer
	for i, word := range strings.Fields(run) {
		switch word {
		case "-":
			continue
		case "walk":
			answers = append(answers, obs.Answer{Result: schTimeout})
			continue
		}
		host, addr := dngServer(i)
		answers = append(answers, schAt(t, host, addr, start.Add(time.Duration(i+1)*100*time.Millisecond), dngResultOf(t, k.Name.String(), word)))
	}
	return schObs(k, start, answers...)
}

// dngAlternate is n runs, which are a and b by turns.
func dngAlternate(n int, a, b string) []string {
	runs := make([]string, n)
	for i := range runs {
		runs[i] = []string{a, b}[i%2]
	}
	return runs
}

func dngTimes(n int, run string) []string {
	runs := make([]string, n)
	for i := range runs {
		runs[i] = run
	}
	return runs
}

// dngReports gives the Report of each run, when one run starts every step
// and Done comes 2 s after its start.
func dngReports(t testing.TB, s *Schedule, k obs.Key, step time.Duration, runs []string) []Report {
	t.Helper()
	var reports []Report
	for i, run := range runs {
		start := schT0.Add(time.Duration(i) * step)
		r := s.Done(dngRunOf(t, k, start, run), start.Add(2*time.Second))
		if !r.Known {
			t.Fatalf("run %d of %s is not known", i, k)
		}
		reports = append(reports, r)
	}
	return reports
}

// dngLongs gives DisagreeLong of each run.
func dngLongs(t testing.TB, s *Schedule, k obs.Key, step time.Duration, runs []string) []bool {
	t.Helper()
	var longs []bool
	for _, r := range dngReports(t, s, k, step, runs) {
		longs = append(longs, r.DisagreeLong)
	}
	return longs
}

// dngSpan is the numbers from a to b.
func dngSpan(a, b int) []int {
	var span []int
	for i := a; i <= b; i++ {
		span = append(span, i)
	}
	return span
}

// ---- the constants ----

func TestDisagreeLimitIsTwiceTheOtherInterval(t *testing.T) {
	for _, c := range []struct {
		iv   Intervals
		want time.Duration
	}{
		{Defaults(), 10 * time.Minute},
		{schIv, 600 * time.Second},
		{Intervals{Serial: time.Second, Parent: time.Hour, Fast: 3 * time.Hour, Other: 7 * time.Second}, 14 * time.Second},
		{Intervals{Serial: time.Hour, Parent: time.Hour, Fast: time.Hour, Other: 0}, 0},
		{Intervals{Other: Ceiling}, 2 * Ceiling},
	} {
		if got := c.iv.DisagreeLimit(); got != c.want {
			t.Errorf("%+v DisagreeLimit() = %v, want %v", c.iv, got, c.want)
		}
	}
	if got := schIv.DisagreeLimit(); got != dngLimit {
		t.Errorf("the limit of the test intervals is %v, want %v", got, dngLimit)
	}
}

func TestDisagreeRunsIsEleven(t *testing.T) {
	runs := DisagreeRuns
	if runs != 11 {
		t.Errorf("DisagreeRuns is %d, want 11", runs)
	}
}

// ---- DisagreeLong: the number of runs and the time ----

// With a run every limit, only the number of runs holds the alert back.
func TestDisagreeLongNeedsElevenRunsOfASteadySplit(t *testing.T) {
	for _, name := range []string{"corp.test.", "www.corp.test."} {
		k := schKey(t, name, dnswire.TypeA)
		s := New(schFile(t, "corp.test. A 10.53.0.80", "www.corp.test. A 10.53.0.81"), nil, schIv)
		longs := dngLongs(t, s, k, dngLimit, dngTimes(15, "81 88"))
		for i, long := range longs {
			if want := i >= 10; long != want {
				t.Errorf("%s: run %d of the split has DisagreeLong %v, want %v", name, i+1, long, want)
			}
		}
	}
}

// dngSeriesNow gives DisagreeLong of the last of runs, which Done judges at
// last; the earlier runs start a second apart from base and are judged two
// seconds after their start.
func dngSeriesNow(t testing.TB, k obs.Key, runs []string, last time.Time) bool {
	t.Helper()
	s := New(schFile(t, "corp.test. A 10.53.0.80", "www.corp.test. A 10.53.0.81"), nil, schIv)
	var r Report
	for i, run := range runs {
		start := schT0.Add(time.Duration(i) * time.Second)
		now := start.Add(2 * time.Second)
		if i == len(runs)-1 {
			now = last
		}
		r = s.Done(dngRunOf(t, k, start, run), now)
	}
	return r.DisagreeLong
}

func TestDisagreeLongNeedsTheLimitAndElevenRuns(t *testing.T) {
	const ns = time.Nanosecond
	for _, name := range []string{"corp.test.", "www.corp.test."} {
		k := schKey(t, name, dnswire.TypeA)
		for _, c := range []struct {
			what  string
			runs  []string
			since time.Duration // the start of the series, after T0
			at    time.Duration // the time of the last Done, after the start of the series
			want  bool
		}{
			{"10 runs, the limit long reached", dngTimes(10, "81 88"), 0, dngLimit, false},
			{"10 runs, far over the limit", dngTimes(10, "81 88"), 0, 24 * time.Hour, false},
			{"11 runs, a nanosecond short", dngTimes(11, "81 88"), 0, dngLimit - ns, false},
			{"11 runs, at the limit", dngTimes(11, "81 88"), 0, dngLimit, true},
			{"11 runs, a nanosecond over", dngTimes(11, "81 88"), 0, dngLimit + ns, true},
			{"11 runs, far over", dngTimes(11, "81 88"), 0, 24 * time.Hour, true},
			{"12 runs, a nanosecond short", dngTimes(12, "81 88"), 0, dngLimit - ns, false},
			{"12 runs, at the limit", dngTimes(12, "81 88"), 0, dngLimit, true},
			// A series that began again counts from the start of its first run.
			{"restarted, 11 runs, a nanosecond short", append(dngTimes(5, "81 88"), dngTimes(11, "81 89")...), 5 * time.Second, dngLimit - ns, false},
			{"restarted, 11 runs, at the limit", append(dngTimes(5, "81 88"), dngTimes(11, "81 89")...), 5 * time.Second, dngLimit, true},
			{"restarted, 10 runs, over the limit", append(dngTimes(5, "81 88"), dngTimes(10, "81 89")...), 5 * time.Second, 24 * time.Hour, false},
		} {
			last := schT0.Add(c.since + c.at)
			if got := dngSeriesNow(t, k, c.runs, last); got != c.want {
				t.Errorf("%s, %s: DisagreeLong is %v, want %v", name, c.what, got, c.want)
			}
		}
	}
}

// ---- DisagreeLong: when the series goes on and when it begins again ----

func TestDisagreeSeriesGoesOnOrBeginsAgain(t *testing.T) {
	base := "81 88 89 81"
	runs := func(parts ...[]string) []string { return slices.Concat(parts...) }
	rows := []struct {
		name  string
		runs  []string
		first int // the first run with DisagreeLong, from 0; -1: none
	}{
		{"a steady split", dngTimes(15, "81 88"), 10},
		{"a steady split of four", dngTimes(15, base), 10},
		{"one of two changes, the second", runs(dngTimes(8, "81 88"), dngTimes(12, "81 89")), 18},
		{"one of two changes, the first", runs(dngTimes(8, "81 88"), dngTimes(12, "89 88")), 18},
		{"both of two change", runs(dngTimes(8, "81 88"), dngTimes(12, "88 81")), 18},
		{"only the first of four changes", runs(dngTimes(8, base), dngTimes(12, "82 88 89 81")), 18},
		{"only the second of four changes", runs(dngTimes(8, base), dngTimes(12, "81 82 89 81")), 18},
		{"only the third of four changes", runs(dngTimes(8, base), dngTimes(12, "81 88 82 81")), 18},
		{"only the last of four changes", runs(dngTimes(8, base), dngTimes(12, "81 88 89 82")), 18},
		{"a change back to the first text", runs(dngTimes(8, "81 88"), dngTimes(1, "81 89"), dngTimes(12, "81 88")), 19},
		{"a change at the 10th run", runs(dngTimes(9, "81 88"), dngTimes(12, "81 89")), 19},
		{"a change at the 11th run", runs(dngTimes(10, "81 88"), dngTimes(12, "81 89")), 20},
		{"a change at every run", dngAlternate(30, "81 88", "88 81"), -1},

		{"the servers agree once", runs(dngTimes(8, "81 88"), dngTimes(1, "81 81"), dngTimes(12, "81 88")), 19},
		// A run in which no usable answer contradicts the series, but a known
		// server gave none, tells nothing: it neither counts nor ends the series.
		{"every answer fails once", runs(dngTimes(8, "81 88"), dngTimes(1, "x x"), dngTimes(12, "81 88")), 11},
		{"only one answer is usable, the first", runs(dngTimes(8, "81 88"), dngTimes(1, "81 x"), dngTimes(12, "81 88")), 11},
		{"only one answer is usable, the last", runs(dngTimes(8, "81 88"), dngTimes(1, "x 88"), dngTimes(12, "81 88")), 11},
		// A known server that was not asked at all does not make a run unknown;
		// one that was asked and failed does, and so does a failure with no address.
		{"only one answer is there, the others are not asked", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81"), dngTimes(12, "81 88 81")), 18},
		{"a known server is not asked, another is", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81 - 81"), dngTimes(12, "81 88 81")), 18},
		{"a failure with no address makes a run unknown", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81 walk"), dngTimes(12, "81 88 81")), 13},
		{"a failure with no address alone", runs(dngTimes(5, "81 88 81"), dngTimes(3, "walk"), dngTimes(12, "81 88 81")), 13},
		{"a failure with no address, but a known server changed", runs(dngTimes(5, "81 88 81"), dngTimes(3, "82 walk"), dngTimes(12, "81 88 81")), 18},
		{"a failure at an address the series does not know", runs(dngTimes(5, "81 88"), dngTimes(3, "81 - x"), dngTimes(12, "81 88")), 18},
		{"a known server failed and another is not asked", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81 x -"), dngTimes(12, "81 88 81")), 13},
		{"every known server answered with its text, no split: one text", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81 81 81"), dngTimes(12, "81 88 81")), 18},
		{"unknown runs change nothing", runs(dngTimes(5, "81 88 81"), dngTimes(3, "81 x 81"), dngTimes(12, "81 88 81")), 13},
		{"unknown runs with another server out", runs(dngTimes(5, "81 88 81"), dngTimes(3, "x 88 x"), dngTimes(12, "81 88 81")), 13},
		{"unknown runs and a returning server with another text", runs(dngTimes(5, "81 88 81"), dngTimes(2, "81 x 81"), dngTimes(12, "81 89 81")), 17},
		{"a known server changed, so the run is not unknown", runs(dngTimes(5, "81 88 81"), dngTimes(3, "82 x 82"), dngTimes(12, "81 88 81")), 18},
		{"no server is missing, so the run is not unknown", runs(dngTimes(5, "81 88 81"), dngTimes(1, "81 81 81"), dngTimes(12, "81 88 81")), 16},
		{"no series yet, so an unknown run is none", runs(dngTimes(3, "81 x"), dngTimes(15, "81 88")), 13},
		{"no data and no such name agree once", runs(dngTimes(8, "81 88"), dngTimes(1, "nodata noname"), dngTimes(12, "81 88")), 19},
		{"the servers agree at the 11th run", runs(dngTimes(10, "81 88"), dngTimes(1, "81 81"), dngTimes(12, "81 88")), 21},
		{"the servers always agree", dngTimes(20, "81 81"), -1},
		{"no server answers", dngTimes(20, "x x"), -1},

		{"a failed server keeps its text", runs(dngTimes(8, base), []string{"x 88 89 81"}, dngTimes(12, base)), 10},
		{"a failed second server keeps its text", runs(dngTimes(8, base), []string{"81 x 89 81"}, dngTimes(12, base)), 10},
		{"a failed third server keeps its text", runs(dngTimes(8, base), []string{"81 88 x 81"}, dngTimes(12, base)), 10},
		{"a failed last server keeps its text", runs(dngTimes(8, base), []string{"81 88 89 x"}, dngTimes(12, base)), 10},
		{"a failed server keeps its text for long", runs(dngTimes(2, base), dngTimes(20, "x 88 89 81"), dngTimes(3, base)), 10},
		{"a failed first server comes back with another text", runs(dngTimes(8, base), []string{"x 88 89 81"}, dngTimes(12, "82 88 89 81")), 19},
		{"a failed second server comes back with another text", runs(dngTimes(8, base), []string{"81 x 89 81"}, dngTimes(12, "81 82 89 81")), 19},
		{"a failed last server comes back with another text", runs(dngTimes(8, base), []string{"81 88 89 x"}, dngTimes(12, "81 88 89 82")), 19},
		{"a server that gave no data comes back with a set", runs(dngTimes(8, "81 nodata 82"), []string{"81 x 82"}, dngTimes(12, "81 88 82")), 19},
		{"a server that is not in the run keeps its text", runs(dngTimes(8, base), []string{"81 88 89"}, dngTimes(12, base)), 10},
		{"a server that is not in the run comes back with another text", runs(dngTimes(8, base), []string{"81 88 89"}, dngTimes(12, "81 88 89 82")), 19},
		{"a failure at a new server", runs(dngTimes(8, "81 88"), []string{"81 88 x"}, dngTimes(12, "81 88 89")), 10},

		{"a new server joins", runs(dngTimes(8, "81 88"), dngTimes(12, "81 88 89")), 10},
		{"a new server joins with the text of another", runs(dngTimes(8, "81 88"), dngTimes(12, "81 88 88")), 10},
		{"two new servers join", runs(dngTimes(8, "81 88"), dngTimes(12, "81 88 89 82")), 10},
		{"a new server joins and changes", runs(dngTimes(8, "81 88"), dngTimes(1, "81 88 89"), dngTimes(12, "81 88 82")), 19},
		{"a new server joins, and an old one changes", runs(dngTimes(8, "81 88"), dngTimes(12, "81 89 89")), 18},
		{"a joined server changes at the 11th run", runs(dngTimes(8, "81 88"), dngTimes(2, "81 88 89"), dngTimes(12, "81 88 82")), 20},

		{"no data and no such name are one text", runs(dngTimes(5, "81 nodata"), dngTimes(10, "81 noname")), 10},
		{"no data then a set", runs(dngTimes(8, "81 nodata"), dngTimes(12, "81 88")), 18},
		{"a set then no data", runs(dngTimes(8, "81 88"), dngTimes(12, "81 nodata")), 18},
		{"the order of a set is no change", runs(dngTimes(1, "81,82 88"), dngTimes(1, "82,81 88"), dngTimes(1, "81,82 88"), dngTimes(12, "82,81 88")), 10},
		{"a repeated record is no change", runs(dngTimes(1, "81,82 88"), dngTimes(1, "81,82,82 88"), dngTimes(12, "82,81,81 88")), 10},
		{"another record in a set is a change", runs(dngTimes(8, "81,82 88"), dngTimes(12, "81,83 88")), 18},
		{"one record less in a set is a change", runs(dngTimes(8, "81,82 88"), dngTimes(12, "81 88")), 18},
	}
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
			for i, long := range dngLongs(t, s, k, dngLimit, r.runs) {
				if want := r.first >= 0 && i >= r.first; long != want {
					t.Errorf("run %d has DisagreeLong %v, want %v (the first is run %d)", i, long, want, r.first)
				}
			}
		})
	}
}

// ---- DisagreeOver: the runs in which the split is absent ----

func TestDisagreeOverCountsQuietRuns(t *testing.T) {
	runs := func(parts ...[]string) []string { return slices.Concat(parts...) }
	rows := []struct {
		name string
		runs []string
		over []int // the runs with DisagreeOver, from 0
	}{
		{"agreeing from the start", dngTimes(20, "81 81"), dngSpan(10, 19)},
		{"ten agreeing runs are not enough", dngTimes(10, "81 81"), nil},
		{"no check ever splits", dngTimes(5, "81 88 89"), nil},
		{"agreeing after a split", runs(dngTimes(5, "81 88"), dngTimes(20, "81 81")), dngSpan(15, 24)},
		{"ten agreeing runs after a split", runs(dngTimes(5, "81 88"), dngTimes(10, "81 81")), nil},
		{"eleven agreeing runs after a split", runs(dngTimes(5, "81 88"), dngTimes(11, "81 81")), []int{15}},
		{"no data and no such name agree", runs(dngTimes(3, "81 88"), dngTimes(11, "nodata noname")), []int{13}},
		{"the count goes on beyond 11", runs(dngTimes(3, "81 88"), dngTimes(40, "81 81")), dngSpan(13, 42)},
		{"unknown runs raise nothing", runs(dngTimes(5, "81 88"), dngTimes(30, "81 x")), nil},
		{"servers that are not asked: each run is quiet", runs(dngTimes(5, "81 88 81"), dngTimes(11, "81")), []int{15}},
		{"a failure with no address raises nothing", runs(dngTimes(5, "81 88"), dngTimes(30, "81 walk")), nil},
		{"a failure at an address that is not known, the known one not asked", runs(dngTimes(5, "81 88"), dngTimes(11, "81 - x")), []int{15}},
		{"no series, no usable pair: each run is quiet", dngTimes(20, "81 x"), dngSpan(10, 19)},
		{"a split that restarts at every run", dngAlternate(20, "81 88", "81 89"), dngSpan(10, 19)},
		{"a continuing run sets it to 0", runs(dngTimes(3, "81 88"), dngTimes(10, "81 81"), dngTimes(3, "81 88")), []int{13}},
		{"a continuing run sets it to 0, so ten more are needed", runs(dngTimes(3, "81 88"), dngTimes(10, "81 81"), dngTimes(3, "81 88"), dngTimes(10, "81 81")), []int{13}},
		{"a split that comes and goes", dngAlternate(20, "81 81", "81 88"), dngSpan(10, 19)},
		{"a known server changed, so the run is quiet", runs(dngTimes(5, "81 88 81"), dngTimes(15, "82 x 82")), dngSpan(15, 19)},
		{"unknown runs then agreement", runs(dngTimes(3, "81 88"), dngTimes(10, "81 x"), dngTimes(12, "81 81")), []int{23, 24}},
	}
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
			var got []int
			for i, rep := range dngReports(t, s, k, dngLimit, r.runs) {
				if rep.DisagreeOver {
					got = append(got, i)
				}
			}
			if !slices.Equal(got, r.over) {
				t.Errorf("DisagreeOver in runs %v, want %v", got, r.over)
			}
		})
	}
}

// An address is the key of a server, not its name.
func TestDisagreeSeriesKnowsServersByAddress(t *testing.T) {
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
	for i := range 15 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		host := fmt.Sprintf("alias%d.corp.test.", i)
		o := schObs(k, start,
			schAt(t, host, schNS1, start.Add(100*time.Millisecond), dngResultOf(t, k.Name.String(), "81")),
			schAt(t, "ns2.corp.test.", schNS2, start.Add(200*time.Millisecond), dngResultOf(t, k.Name.String(), "88")))
		if r := s.Done(o, start.Add(2*time.Second)); r.DisagreeLong != (i >= 10) {
			t.Errorf("run %d has DisagreeLong %v with a server whose name changes", i, r.DisagreeLong)
		}
	}
}

// ---- DisagreeLong: other checks ----

// Only a check of records can disagree.
func TestDisagreeLongIsFalseForEveryKindButRecords(t *testing.T) {
	corp := schName(t, "corp.test.")
	s := New(schBase(t), nil, schIv)
	for _, k := range []obs.Key{schSerialKey(t), obs.DelegationKey(corp), obs.DSKey(corp)} {
		for i := range 30 {
			start := schT0.Add(time.Duration(i) * dngLimit)
			r := s.Done(dngRunOf(t, k, start, "81 88"), start.Add(2*time.Second))
			if !r.Known || r.DisagreeLong {
				t.Fatalf("run %d of %s with two different answers gave known %v, DisagreeLong %v", i, k, r.Known, r.DisagreeLong)
			}
		}
	}
}

func TestDisagreeSeriesOfEachCheckIsItsOwn(t *testing.T) {
	www, mail := schKey(t, "www.corp.test.", dnswire.TypeA), schKey(t, "mail.corp.test.", dnswire.TypeA)
	s := New(schFile(t, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"), nil, schIv)
	// www splits from the first run; mail agrees for five runs, then splits.
	for i := range 20 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		now := start.Add(2 * time.Second)
		mailRun := "81 81"
		if i >= 5 {
			mailRun = "81 88"
		}
		if r := s.Done(dngRunOf(t, www, start, "81 88"), now); r.DisagreeLong != (i >= 10) {
			t.Fatalf("run %d: www has DisagreeLong %v", i, r.DisagreeLong)
		}
		if r := s.Done(dngRunOf(t, mail, start, mailRun), now); r.DisagreeLong != (i >= 15) {
			t.Fatalf("run %d: mail has DisagreeLong %v", i, r.DisagreeLong)
		}
	}
}

func TestDoneOfAKeyOutsideThePlanHasNoDisagreeSeries(t *testing.T) {
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	other := schKey(t, "nothere.corp.test.", dnswire.TypeA)
	s := New(schFile(t, "www.corp.test. A 10.53.0.81"), nil, schIv)
	for i := range 40 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		if r := s.Done(dngRunOf(t, other, start, "81 88"), start.Add(2*time.Second)); r.Known || r.DisagreeLong {
			t.Fatalf("Done of a key outside the plan gave %+v", r)
		}
	}
	// It is no run of the check that is in the plan, either.
	for i := range 15 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		s.Done(dngRunOf(t, other, start, "81 88"), start.Add(time.Second))
		if r := s.Done(dngRunOf(t, k, start, "81 88"), start.Add(2*time.Second)); r.DisagreeLong != (i >= 10) {
			t.Fatalf("run %d has DisagreeLong %v beside runs of a key outside the plan", i, r.DisagreeLong)
		}
	}
}

// ---- Replace ----

func TestReplaceKeepsTheDisagreeSeriesOfAKeyThatStays(t *testing.T) {
	www, mail := schKey(t, "www.corp.test.", dnswire.TypeA), schKey(t, "mail.corp.test.", dnswire.TypeA)
	lines := []string{"www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"}
	s := New(schFile(t, lines...), nil, schIv)
	for i := range 10 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		s.Done(dngRunOf(t, www, start, "81 88"), start.Add(2*time.Second))
		s.Done(dngRunOf(t, mail, start, "81 88"), start.Add(2*time.Second))
	}
	// Another line comes and one stays; the series of both keys go on.
	s.Replace(schFile(t, append(slices.Clone(lines), "cdn.corp.test. A none")...))
	start := schT0.Add(10 * dngLimit)
	for _, k := range []obs.Key{www, mail} {
		if r := s.Done(dngRunOf(t, k, start, "81 88"), start.Add(2*time.Second)); !r.DisagreeLong {
			t.Errorf("the 11th run of %s after Replace has DisagreeLong false", k)
		}
	}
}

// A key that leaves the plan loses its series, so that a line that comes
// back does not alert on its first run, and the others keep theirs.
func TestReplaceDeletesTheDisagreeSeriesOfAKeyThatLeft(t *testing.T) {
	www, mail := schKey(t, "www.corp.test.", dnswire.TypeA), schKey(t, "mail.corp.test.", dnswire.TypeA)
	both := schFile(t, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82")
	s := New(both, nil, schIv)
	for i := range 10 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		s.Done(dngRunOf(t, www, start, "81 88"), start.Add(2*time.Second))
		s.Done(dngRunOf(t, mail, start, "81 88"), start.Add(2*time.Second))
	}
	s.Replace(schFile(t, "mail.corp.test. A 10.53.0.82"))
	s.Replace(both)
	for i := 10; i < 30; i++ {
		start := schT0.Add(time.Duration(i) * dngLimit)
		now := start.Add(2 * time.Second)
		if r := s.Done(dngRunOf(t, mail, start, "81 88"), now); !r.DisagreeLong {
			t.Fatalf("run %d: mail, which never left the plan, has DisagreeLong false", i)
		}
		// www counts again from the run after it came back: its 11th run is run 20.
		if r := s.Done(dngRunOf(t, www, start, "81 88"), now); r.DisagreeLong != (i >= 20) {
			t.Fatalf("run %d: www has DisagreeLong %v", i, r.DisagreeLong)
		}
	}
}

// The count of quiet runs is kept for a key that stays and lost for a key
// that leaves, and nothing but Replace deletes it.
func TestReplaceKeepsTheQuietCountOfAKeyThatStaysAndDeletesTheOtherOnes(t *testing.T) {
	www, mail := schKey(t, "www.corp.test.", dnswire.TypeA), schKey(t, "mail.corp.test.", dnswire.TypeA)
	both := schFile(t, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82")
	s := New(both, nil, schIv)
	for i := range 20 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		for _, k := range []obs.Key{www, mail} {
			if r := s.Done(dngRunOf(t, k, start, "81 81"), start.Add(2*time.Second)); r.DisagreeOver != (i >= 10) {
				t.Fatalf("run %d of %s has DisagreeOver %v", i, k, r.DisagreeOver)
			}
		}
	}
	s.Replace(schFile(t, "mail.corp.test. A 10.53.0.82"))
	s.Replace(both)
	start := schT0.Add(20 * dngLimit)
	if r := s.Done(dngRunOf(t, mail, start, "81 81"), start.Add(2*time.Second)); !r.DisagreeOver {
		t.Error("mail, which stayed, lost its quiet runs")
	}
	if r := s.Done(dngRunOf(t, www, start, "81 81"), start.Add(2*time.Second)); r.DisagreeOver {
		t.Error("www, which left and came back, kept its quiet runs")
	}
	for i := 21; i < 30; i++ {
		start := schT0.Add(time.Duration(i) * dngLimit)
		if r := s.Done(dngRunOf(t, www, start, "81 81"), start.Add(2*time.Second)); r.DisagreeOver != (i >= 30) {
			t.Fatalf("run %d of www after it came back has DisagreeOver %v", i, r.DisagreeOver)
		}
	}
	start = schT0.Add(30 * dngLimit)
	if r := s.Done(dngRunOf(t, www, start, "81 81"), start.Add(2*time.Second)); !r.DisagreeOver {
		t.Error("the 11th quiet run of www after it came back has DisagreeOver false")
	}
}

func TestReplaceDeletesTheFailureSeriesOfAKeyThatLeft(t *testing.T) {
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	mail := schKey(t, "mail.corp.test.", dnswire.TypeA)
	both := schFile(t, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82")
	s := New(both, nil, schIv)
	for i := range 3 {
		s.Done(schFailed(t, k, schSec(i)), schSec(i+1))
		s.Done(schFailed(t, mail, schSec(i)), schSec(i+1))
	}
	s.Replace(schFile(t, "mail.corp.test. A 10.53.0.82"))
	s.Replace(both)
	if r := s.Done(schFailed(t, k, schSec(10)), schSec(11)); !r.FailingSince.Equal(schSec(10)) {
		t.Errorf("the first failed run after the key came back has FailingSince %s, want T0+10s", schWhen(r.FailingSince))
	}
	if r := s.Done(schFailed(t, mail, schSec(10)), schSec(11)); !r.FailingSince.Equal(schT0) {
		t.Errorf("a key that stayed has FailingSince %s, want T0", schWhen(r.FailingSince))
	}
}

// A run that was in flight when its key left ends without a trace.
func TestDoneOfAKeyThatLeftDoesNotStartASeries(t *testing.T) {
	k := schKey(t, "www.corp.test.", dnswire.TypeA)
	with := schFile(t, "www.corp.test. A 10.53.0.81")
	s := New(with, nil, schIv)
	for i := range 10 {
		start := schT0.Add(time.Duration(i) * dngLimit)
		s.Done(dngRunOf(t, k, start, "81 88"), start.Add(2*time.Second))
	}
	s.Replace(schFile(t, "mail.corp.test. A 10.53.0.82"))
	late := schT0.Add(10 * dngLimit)
	if r := s.Done(dngRunOf(t, k, late, "81 88"), late.Add(2*time.Second)); r.Known || r.DisagreeLong {
		t.Fatalf("Done of a key that left gave %+v", r)
	}
	s.Replace(with)
	for i := 11; i < 25; i++ {
		start := schT0.Add(time.Duration(i) * dngLimit)
		if r := s.Done(dngRunOf(t, k, start, "81 88"), start.Add(2*time.Second)); r.DisagreeLong != (i >= 21) {
			t.Fatalf("run %d after the key came back has DisagreeLong %v", i, r.DisagreeLong)
		}
	}
}

// ---- the property ----

// dngModel keeps, for each check, what the rules of the series state: the
// start of the split, the number of its runs, the last text of each address
// and the number of runs since it last went on.
type dngModel struct {
	limit   time.Duration
	entries map[string]*dngEntry
}

type dngEntry struct {
	since time.Time
	runs  int
	quiet int
	texts map[string]string
}

// dngTextsOf gives the text of each answer of o that is not a failure, by
// address.
func dngTextsOf(o obs.Observation) map[string]string {
	texts := map[string]string{}
	for _, a := range o.Answers {
		set := obs.Match(a.Result,
			func(r obs.Records) *[]dnswire.Record { return &r.Set },
			func(obs.NoData) *[]dnswire.Record { return new([]dnswire.Record) },
			func(obs.NoName) *[]dnswire.Record { return new([]dnswire.Record) },
			func(obs.Failure) *[]dnswire.Record { return nil })
		if set != nil {
			texts[a.Server.Addr.String()] = expect.SetText(o.Key.Type, *set)
		}
	}
	return texts
}

// done gives DisagreeLong and DisagreeOver of o seen at now, and which of
// the six things the run did to the entry.
func (m *dngModel) done(o obs.Observation, now time.Time) (long, over bool, event string) {
	k := o.Key.String()
	e := m.entries[k]
	if e == nil {
		e = &dngEntry{texts: map[string]string{}}
		m.entries[k] = e
	}
	texts := dngTextsOf(o)
	distinct := map[string]bool{}
	for _, tx := range texts {
		distinct[tx] = true
	}
	disagree := o.Key.Kind == obs.KindRecords && len(distinct) > 1
	repeats := true
	for addr, old := range e.texts {
		tx, ok := texts[addr]
		repeats = repeats && (!ok || tx == old)
	}
	// A run is unknown only when a known server was asked and failed, or a
	// failure has no address; a known server that was not asked is no failure.
	failedKnown := false
	for _, a := range o.Answers {
		if _, usable := dngTextsOf(obs.Observation{Key: o.Key, Answers: []obs.Answer{a}})[a.Server.Addr.String()]; usable {
			continue
		}
		_, known := e.texts[a.Server.Addr.String()]
		failedKnown = failedKnown || !a.Server.Addr.IsValid() || known
	}
	switch {
	case disagree && e.runs > 0 && repeats:
		event = "continued"
		e.runs++
		e.quiet = 0
		for addr, tx := range texts {
			e.texts[addr] = tx
		}
	case disagree:
		event = "started"
		if e.runs > 0 {
			event = "restarted"
		}
		e.since, e.runs, e.texts = o.Start, 1, texts
		e.quiet++
	case e.runs > 0 && failedKnown && repeats:
		event = "unknown"
	default:
		event = "idle"
		if e.runs > 0 {
			event = "ended"
		}
		e.runs, e.texts = 0, map[string]string{}
		e.quiet++
	}
	return e.runs >= 11 && now.Sub(e.since) >= m.limit, e.quiet >= 11, event
}

func (m *dngModel) keep(present map[string]bool) {
	for k := range m.entries {
		if !present[k] {
			delete(m.entries, k)
		}
	}
}

func TestDisagreeSeriesProperty(t *testing.T) {
	const cases, turns = 600, 150
	lines := []string{"www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82", "corp.test. A 10.53.0.80"}
	keys := []obs.Key{schKey(t, "www.corp.test.", dnswire.TypeA), schKey(t, "mail.corp.test.", dnswire.TypeA), schKey(t, "corp.test.", dnswire.TypeA)}
	words := []string{"81", "88", "89", "81,82", "nodata"}
	tally := map[string]int{}
	for c := range cases {
		rng := schRand(c)
		iv := Intervals{Serial: 15 * time.Second, Parent: time.Minute, Fast: schPick(rng, 6*time.Second, 43*time.Second),
			Other: schPick(rng, 20*time.Second, 60*time.Second, 100*time.Second, 300*time.Second)}
		limit := 2 * iv.Other
		noise := schPick(rng, 0, 0.02, 0.08, 0.25)
		agree := schPick(rng, 0.01, 0.01, 0.1, 0.5)
		lone := schPick(rng, 0.0, 0.05, 0.3)
		used := keys[:schPick(rng, 1, 3)]
		step := schPick(rng, time.Second, limit/10, limit/10, limit/10-time.Nanosecond, limit/3)
		present := map[string]bool{}
		for _, k := range keys {
			present[k.String()] = true
		}
		planFile := func() *expect.File {
			var in []string
			for i, k := range keys {
				if present[k.String()] {
					in = append(in, lines[i])
				}
			}
			return schFile(t, in...)
		}
		s := New(planFile(), nil, iv)
		m := &dngModel{limit: limit, entries: map[string]*dngEntry{}}
		servers := map[string][]string{}
		for _, k := range keys {
			first := schPick(rng, words...)
			servers[k.String()] = []string{first, schPick(rng, "88", "89", first), first, schPick(rng, first, "88")}
		}
		at := schT0
		for turn := range turns {
			where := fmt.Sprintf("seed %d case %d turn %d", schSeed, c, turn)
			if rng.IntN(25) == 0 {
				for _, k := range keys {
					present[k.String()] = rng.IntN(5) != 0
				}
				s.Replace(planFile())
				m.keep(present)
			}
			at = at.Add(step)
			k := used[rng.IntN(len(used))]
			cur := servers[k.String()]
			if rng.Float64() < noise {
				cur[rng.IntN(len(cur))] = schPick(rng, words...)
			}
			run := slices.Clone(cur)
			switch x := rng.Float64(); {
			case x < noise/2:
				run[rng.IntN(len(run))] = schPick(rng, "x", "x", "walk")
			case x < noise:
				run = run[:2+rng.IntN(3)]
			case x < noise+agree:
				for i := range run {
					run[i] = run[0]
				}
			case x < noise+agree+lone:
				// Only one server is heard: the others fail or are not asked.
				keep := rng.IntN(len(run))
				for i := range run {
					if i != keep {
						run[i] = schPick(rng, "x", "-")
					}
				}
			}
			offset := schPick(rng, 0, 0, 0, time.Second, 2*time.Second)
			o := dngRunOf(t, k, at, strings.Join(run, " "))
			r := s.Done(o, at.Add(offset))
			if r.Known != present[k.String()] {
				t.Fatalf("%s: Done of %s gave known %v", where, k, r.Known)
			}
			if !r.Known {
				tally["left"]++
				continue
			}
			long, over, event := m.done(o, at.Add(offset))
			tally[event]++
			if r.DisagreeLong != long || r.DisagreeOver != over {
				t.Fatalf("%s: Done of %s gave long %v over %v, want long %v over %v (%s)", where, k, r.DisagreeLong, r.DisagreeOver, long, over, event)
			}
			e := m.entries[k.String()]
			age := at.Add(offset).Sub(e.since)
			switch {
			case long && age == limit:
				tally["long at the limit"]++
			case long:
				tally["long"]++
			case e.runs >= 11 && limit-age < time.Second:
				tally["short of the limit"]++
			case e.runs >= 11:
				tally["held by time"]++
			case age >= limit && e.runs > 0:
				tally["held by runs"]++
			}
			switch {
			case over && e.quiet == 11:
				tally["over at 11"]++
			case over:
				tally["over"]++
			case e.quiet == 10:
				tally["quiet 10"]++
			}
		}
	}
	for _, want := range []struct {
		what  string
		least int
	}{{"started", 500}, {"continued", 2000}, {"restarted", 300}, {"ended", 300}, {"idle", 300}, {"unknown", 300}, {"left", 100}, {"long", 500},
		{"long at the limit", 50}, {"short of the limit", 20}, {"held by time", 100}, {"held by runs", 100}, {"over", 300}, {"over at 11", 50}, {"quiet 10", 50}} {
		if tally[want.what] < want.least {
			t.Errorf("seed %d: %d cases of %q, want at least %d: the cases miss a kind", schSeed, tally[want.what], want.what, want.least)
		}
	}
}

// ---- fixed-seed simulations: the schedule and the rules as the service drives them ----

// dngRig drives one check as the service does: Done, then Decide with the
// alerts that are open, and counts what Decide says.
type dngRig struct {
	t       testing.TB
	s       *Schedule
	file    *expect.File
	key     obs.Key
	tier    Tier
	run     int
	open    []decide.Finding
	opens   []int // the run of each open
	updates []int
	resolve []int
	results map[string]obs.Result
	model   *dngModel // the rules of the series, to know which run went on with a split
	lastGo  int       // the last run that went on with a split
}

func newDngRig(t testing.TB, line string, tier Tier, iv Intervals) *dngRig {
	t.Helper()
	f := schFile(t, line)
	owner, _, _ := strings.Cut(line, " ")
	return &dngRig{t: t, s: New(f, nil, iv), file: f, key: schKey(t, owner, dnswire.TypeA), tier: tier, results: map[string]obs.Result{},
		model: &dngModel{limit: iv.DisagreeLimit(), entries: map[string]*dngEntry{}}, lastGo: -1}
}

// feed is the next run, which started at start; the nth server gave the nth
// word. Decide sees it a second later.
func (g *dngRig) feed(start time.Time, words ...string) {
	g.t.Helper()
	var answers []obs.Answer
	for i, w := range words {
		if w == "-" {
			continue
		}
		r, ok := g.results[w]
		if !ok {
			r = dngResultOf(g.t, g.key.Name.String(), w)
			g.results[w] = r
		}
		host, addr := dngServer(i)
		answers = append(answers, schAt(g.t, host, addr, start.Add(time.Duration(10*(i+1))*time.Millisecond), r))
	}
	o := schObs(g.key, start, answers...)
	now := start.Add(time.Second)
	rep := g.s.Done(o, now)
	if !rep.Known || rep.Tier != g.tier {
		g.t.Fatalf("run %d: Done gave known %v, tier %v, want tier %v", g.run, rep.Known, rep.Tier, g.tier)
	}
	changes := decide.Decide(decide.Input{Expect: g.file, Open: g.open, Observation: o, Now: now,
		FailingSince: rep.FailingSince, FailLimit: rep.FailLimit, DisagreeLong: rep.DisagreeLong, DisagreeOver: rep.DisagreeOver})
	if _, _, event := g.model.done(o, now); event == "continued" {
		g.lastGo = g.run
	}
	for _, c := range changes {
		if c.Finding.Rule != decide.RuleDisagree {
			g.t.Fatalf("run %d: an unexpected %v %v", g.run, c.Op, c.Finding.Rule)
		}
		switch c.Op {
		case decide.OpOpen:
			g.opens = append(g.opens, g.run)
			g.open = append(g.open, c.Finding)
		case decide.OpUpdate:
			g.updates = append(g.updates, g.run)
			g.open[0] = c.Finding
		case decide.OpResolve:
			g.resolve = append(g.resolve, g.run)
			if g.run-g.lastGo < DisagreeRuns {
				g.t.Fatalf("run %d: the alert ended %d runs after a run that went on with the split, want at least %d", g.run, g.run-g.lastGo, DisagreeRuns)
			}
			g.open = nil
		}
	}
	if n := len(g.open); n > 1 {
		g.t.Fatalf("run %d: %d alerts are open", g.run, n)
	}
	g.run++
}

// events is the number of opens, updates and resolves so far.
func (g *dngRig) events() int { return len(g.opens) + len(g.updates) + len(g.resolve) }

// dngDay is one tier of the simulations: its line, tier and the time
// between two runs of its checks.
type dngDay struct {
	name  string
	line  string
	tier  Tier
	every time.Duration
}

func dngTiers() (fast, other dngDay) {
	iv := Defaults()
	return dngDay{"fast tier", "corp.test. A in 10.53.0.0/24", TierFast, iv.Fast},
		dngDay{"other tier", "www.corp.test. A in 10.53.0.0/24", TierOther, iv.Other}
}

// A healthy zone whose servers each pick one of two weighted addresses per
// query, as weighted or random routing does. Every answer is allowed by the
// line, so nothing is stale and nothing is rogue.
func TestWeightedAnswersOpenNothing(t *testing.T) {
	fast, other := dngTiers()
	for _, c := range []struct {
		day     dngDay
		servers int
		span    time.Duration
		seed    uint64
	}{
		{other, 2, 365 * 24 * time.Hour, 1},
		{other, 4, 365 * 24 * time.Hour, 2},
		{fast, 2, 30 * 24 * time.Hour, 3},
		{fast, 4, 30 * 24 * time.Hour, 4},
	} {
		t.Run(fmt.Sprintf("%s, %d servers", c.day.name, c.servers), func(t *testing.T) {
			g := newDngRig(t, c.day.line, c.day.tier, Defaults())
			rng := rand.New(rand.NewPCG(c.seed, 7))
			words := make([]string, c.servers)
			runs := int(c.span / c.day.every)
			for i := range runs {
				for sv := range words {
					words[sv] = []string{"81", "82"}[rng.IntN(2)]
				}
				g.feed(schT0.Add(time.Duration(i)*c.day.every), words...)
			}
			if g.events() != 0 {
				t.Errorf("%d runs gave %d opens (at %v), %d updates, %d resolves", runs, len(g.opens), g.opens, len(g.updates), len(g.resolve))
			}
		})
	}
}

// Each of four servers gives two of four addresses per query, as a
// multivalue answer does.
func TestRotatingSubsetsOpenAndUpdateNothing(t *testing.T) {
	fast, other := dngTiers()
	pool := []string{"81", "82", "83", "84"}
	for _, c := range []struct {
		day  dngDay
		span time.Duration
	}{{fast, 30 * 24 * time.Hour}, {other, 365 * 24 * time.Hour}} {
		t.Run(c.day.name, func(t *testing.T) {
			g := newDngRig(t, c.day.line, c.day.tier, Defaults())
			rng := rand.New(rand.NewPCG(5, 6))
			words := make([]string, 4)
			runs := int(c.span / c.day.every)
			for i := range runs {
				for sv := range words {
					p := rng.Perm(len(pool))
					words[sv] = pool[p[0]] + "," + pool[p[1]]
				}
				g.feed(schT0.Add(time.Duration(i)*c.day.every), words...)
			}
			if g.events() != 0 {
				t.Errorf("%d runs gave %d opens (at %v), %d updates, %d resolves", runs, len(g.opens), g.opens, len(g.updates), len(g.resolve))
			}
		})
	}
}

// One server stays on an old answer while the others have the new one. The
// alert opens at the first run in which the split has lasted 11 runs and the
// limit, stays quiet while it goes on and ends after 11 runs in which the
// servers agree.
func TestSteadyStaleServerOpensOnceAndResolves(t *testing.T) {
	iv := Defaults()
	fastHalf := iv
	fastHalf.Fast = 30 * time.Second
	for _, c := range []struct {
		name  string
		iv    Intervals
		line  string
		tier  Tier
		every time.Duration
		begin int // the first run of the split
	}{
		{"fast tier", iv, "corp.test. A in 10.53.0.0/24", TierFast, iv.Fast, 0},
		{"fast tier, the split begins later", iv, "corp.test. A in 10.53.0.0/24", TierFast, iv.Fast, 7},
		{"other tier", iv, "www.corp.test. A in 10.53.0.0/24", TierOther, iv.Other, 0},
		{"other tier, the split begins later", iv, "www.corp.test. A in 10.53.0.0/24", TierOther, iv.Other, 7},
		{"a tier whose 11 runs are short of the limit", fastHalf, "corp.test. A in 10.53.0.0/24", TierFast, fastHalf.Fast, 0},
		{"a tier whose 11 runs are short of the limit, later", fastHalf, "corp.test. A in 10.53.0.0/24", TierFast, fastHalf.Fast, 7},
	} {
		t.Run(c.name, func(t *testing.T) {
			g := newDngRig(t, c.line, c.tier, c.iv)
			// Decide sees run i one second after its start.
			limit := 2 * c.iv.Other
			wait := max(DisagreeRuns-1, int((limit-time.Second+c.every-1)/c.every))
			want := c.begin + wait
			const splitRuns, agreeRuns = 60, 30
			for i := range c.begin {
				g.feed(schT0.Add(time.Duration(i)*c.every), "81", "81", "81")
			}
			for i := c.begin; i < c.begin+splitRuns; i++ {
				g.feed(schT0.Add(time.Duration(i)*c.every), "81", "88", "81")
			}
			if len(g.opens) != 1 || g.opens[0] != want || len(g.updates) != 0 || len(g.resolve) != 0 {
				t.Fatalf("while the split lasts: opens %v (want [%d]), updates %v, resolves %v", g.opens, want, g.updates, g.resolve)
			}
			end := c.begin + splitRuns
			// The servers agree from run end on; the alert ends at the 11th such
			// run, not before.
			ends := end + DisagreeRuns - 1
			for i := end; i < end+agreeRuns; i++ {
				g.feed(schT0.Add(time.Duration(i)*c.every), "81", "81", "81")
				if want := i >= ends; (len(g.resolve) == 1) != want {
					t.Fatalf("run %d of agreement: resolves %v, want the resolve at run %d", i, g.resolve, ends)
				}
			}
			if len(g.opens) != 1 || len(g.updates) != 0 || len(g.resolve) != 1 || g.resolve[0] != ends {
				t.Errorf("when the servers agree: opens %v, updates %v, resolves %v (want [%d])", g.opens, g.updates, g.resolve, ends)
			}
		})
	}
}

// A server that gives another allowed answer in two runs of three, or in
// nine of ten, never makes a steady split.
func TestServerThatDiffersNowAndThenOpensNothing(t *testing.T) {
	fast, other := dngTiers()
	for _, day := range []dngDay{fast, other} {
		for _, c := range []struct {
			name string
			odd  func(run int) bool
		}{
			{"two runs of three", func(run int) bool { return run%3 != 2 }},
			{"nine runs of ten", func(run int) bool { return run%10 != 9 }},
			{"every other run", func(run int) bool { return run%2 == 0 }},
		} {
			t.Run(day.name+", "+c.name, func(t *testing.T) {
				g := newDngRig(t, day.line, day.tier, Defaults())
				runs := int(30 * 24 * time.Hour / day.every)
				for i := range runs {
					second := "81"
					if c.odd(i) {
						second = "66"
					}
					g.feed(schT0.Add(time.Duration(i)*day.every), "81", second)
				}
				if g.events() != 0 {
					t.Errorf("%d runs gave %d opens (at %v), %d updates, %d resolves", runs, len(g.opens), g.opens, len(g.updates), len(g.resolve))
				}
			})
		}
	}
}

// Order and duplicates make no difference.
func TestOrderAndDuplicatesAreNoDifference(t *testing.T) {
	_, other := dngTiers()
	g := newDngRig(t, other.line, other.tier, Defaults())
	for i := range 50 {
		g.feed(schT0.Add(time.Duration(i)*other.every), "81,82", "82,81,82", "81,82,81")
	}
	if g.events() != 0 {
		t.Errorf("order or a duplicate gave %d opens, %d updates, %d resolves", len(g.opens), len(g.updates), len(g.resolve))
	}
}

// A line that is taken out and put back starts a new series: the alert does
// not open on its first run, however long the servers differed before.
func TestALineThatComesBackStartsANewSeries(t *testing.T) {
	_, other := dngTiers()
	g := newDngRig(t, other.line, other.tier, Defaults())
	next := func() time.Time { return schT0.Add(time.Duration(g.run) * other.every) }
	for range 10 {
		g.feed(next(), "81", "88")
	}
	g.s.Replace(schFile(t, "mail.corp.test. A 10.53.0.82"))
	g.s.Replace(g.file)
	for i := range 10 {
		g.feed(next(), "81", "88")
		if len(g.opens) != 0 {
			t.Fatalf("an alert opened at run %d after the line came back, the 1st run of its series was run 10", i+1)
		}
	}
	g.feed(next(), "81", "88")
	if len(g.opens) != 1 || g.opens[0] != 20 {
		t.Errorf("opens %v, want one at run 20, the 11th run after the line came back", g.opens)
	}
}

// A line that stays keeps its series, so the alert opens at the 11th run
// although the file was replaced in between.
func TestASeriesGoesOnThroughAReplaceOfTheFile(t *testing.T) {
	_, other := dngTiers()
	g := newDngRig(t, other.line, other.tier, Defaults())
	next := func() time.Time { return schT0.Add(time.Duration(g.run) * other.every) }
	for range 10 {
		g.feed(next(), "81", "88")
	}
	g.s.Replace(schFile(t, other.line, "mail.corp.test. A 10.53.0.82"))
	g.feed(next(), "81", "88")
	if len(g.opens) != 1 || g.opens[0] != 10 {
		t.Errorf("opens %v, want one at run 10", g.opens)
	}
}

// An address that reaches a stale instance in 3 runs of 4 looks like a server
// whose answer changes, and every change starts the split again. The alert
// may open and end a few times in a day; it never changes, and it ends only
// after 11 runs without a split that went on.
func TestAnycastAddressWithAStaleInstance(t *testing.T) {
	fast, _ := dngTiers()
	g := newDngRig(t, fast.line, fast.tier, Defaults())
	rng := rand.New(rand.NewPCG(11, 12))
	const runs = 24 * 60
	for i := range runs {
		second := "81"
		if rng.IntN(4) != 0 {
			second = "88"
		}
		g.feed(schT0.Add(time.Duration(i)*fast.every), "81", second)
	}
	t.Logf("%d runs: opens at %v, resolves at %v, updates at %v", runs, g.opens, g.resolve, g.updates)
	if len(g.opens) > 3 || len(g.resolve) > 2 || len(g.updates) != 0 {
		t.Errorf("opens at %v, resolves at %v, updates at %v: want at most 3 opens, 2 resolves and no update", g.opens, g.resolve, g.updates)
	}
}

// Each of two servers keeps a weighted pick of two addresses for some runs,
// then picks again. At no moment are two alerts open, and none changes.
func TestServersThatKeepAPickForSomeRuns(t *testing.T) {
	fast, _ := dngTiers()
	const runs = 30 * 24 * 60
	for _, c := range []struct {
		keep     int
		mostOpen int
	}{{2, dngMostOpens2}, {3, dngMostOpens3}, {5, dngMostOpens5}} {
		t.Run(fmt.Sprintf("kept for %d runs", c.keep), func(t *testing.T) {
			g := newDngRig(t, fast.line, fast.tier, Defaults())
			rng := rand.New(rand.NewPCG(uint64(20+c.keep), 21))
			pick := []string{"81", "82"}
			picks := make([]string, 2)
			for i := range runs {
				for sv := range picks {
					if (i+sv)%c.keep == 0 || picks[sv] == "" {
						picks[sv] = pick[rng.IntN(2)]
					}
				}
				g.feed(schT0.Add(time.Duration(i)*fast.every), picks...)
			}
			t.Logf("%d runs: %d opens, %d resolves, %d updates", runs, len(g.opens), len(g.resolve), len(g.updates))
			if len(g.opens) > c.mostOpen || len(g.updates) != 0 {
				t.Errorf("%d opens (want at most %d), %d updates (want none)", len(g.opens), c.mostOpen, len(g.updates))
			}
		})
	}
}

// A stale server that fails every other run is heard in half of the runs;
// the runs without its answer tell nothing, so the split lasts and the alert
// opens once, at the 11th run in which the stale server answered.
func TestStaleServerThatFailsEveryOtherRun(t *testing.T) {
	fast, other := dngTiers()
	for _, day := range []dngDay{fast, other} {
		t.Run(day.name, func(t *testing.T) {
			g := newDngRig(t, day.line, day.tier, Defaults())
			for i := range 200 {
				second := "88"
				if i%2 == 1 {
					second = "x"
				}
				g.feed(schT0.Add(time.Duration(i)*day.every), "81", second)
			}
			if len(g.opens) != 1 || g.opens[0] != 2*(DisagreeRuns-1) || len(g.updates) != 0 || len(g.resolve) != 0 {
				t.Errorf("opens %v (want [%d]), updates %v, resolves %v", g.opens, 2*(DisagreeRuns-1), g.updates, g.resolve)
			}
		})
	}
}

// Rotating answers never make a steady split, so an alert that is open in
// the store ends once 11 runs in a row have no split that went on.
func TestRotatingAnswersEndAnOpenAlertAfterElevenQuietRuns(t *testing.T) {
	fast, _ := dngTiers()
	g := newDngRig(t, fast.line, fast.tier, Defaults())
	g.open = []decide.Finding{{Rule: decide.RuleDisagree, Severity: decide.SeverityMedium, Check: g.key, Expected: "in 10.53.0.0/24", Value: "81"}}
	rng := rand.New(rand.NewPCG(31, 32))
	pool := []string{"81", "82", "83", "84"}
	words := make([]string, 4)
	for i := range 60 {
		for sv := range words {
			p := rng.Perm(len(pool))
			words[sv] = pool[p[0]] + "," + pool[p[1]]
		}
		g.feed(schT0.Add(time.Duration(i)*fast.every), words...)
	}
	if want := []int{DisagreeRuns - 1}; !slices.Equal(g.resolve, want) || len(g.opens) != 0 || len(g.updates) != 0 {
		t.Errorf("opens %v, updates %v, resolves %v (want [%d])", g.opens, g.updates, g.resolve, want[0])
	}
}

// ---- the fast tier of the challenge names ----

func TestPlanFastForEveryChallengeNameUnderTheDomain(t *testing.T) {
	f := schFile(t,
		"_acme-challenge.corp.test. TXT none",
		"_ACME-Challenge.Corp.Test. A none",
		"_acme-challenge.www.corp.test. TXT none",
		"_acme-challenge.www.corp.test. CNAME none",
		"_Acme-Challenge.deep.www.corp.test. TXT none",
		"_acme-challenge.sub.corp.test. TXT none",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"x._acme-challenge.corp.test. TXT none",
		"_acme-challenge-old.corp.test. TXT none",
		"_acme-challenge2.corp.test. TXT none",
		"acme-challenge.corp.test. TXT none",
		"__acme-challenge.corp.test. TXT none",
		"_acme-challenge.shop.test. TXT none",
		"_acme-challenge.edge.dnshost.test. TXT none",
		"www.corp.test. TXT none",
		"corp.test. TXT none",
	)
	want := map[string]string{
		"_acme-challenge.corp.test. TXT":          "tier3 zone true",
		"_acme-challenge.corp.test. A":            "tier3 zone true",
		"_acme-challenge.www.corp.test. TXT":      "tier3 zone true",
		"_acme-challenge.www.corp.test. CNAME":    "tier3 zone true",
		"_acme-challenge.deep.www.corp.test. TXT": "tier3 zone true",
		"_acme-challenge.sub.corp.test. TXT":      "tier3 zone false",
		"sub.corp.test. NS":                       "tier4 zone false",
		"ns1.sub.corp.test. A":                    "tier4 zone false",
		"x._acme-challenge.corp.test. TXT":        "tier4 zone true",
		"_acme-challenge-old.corp.test. TXT":      "tier4 zone true",
		"_acme-challenge2.corp.test. TXT":         "tier4 zone true",
		"acme-challenge.corp.test. TXT":           "tier4 zone true",
		"__acme-challenge.corp.test. TXT":         "tier4 zone true",
		"_acme-challenge.shop.test. TXT":          "tier4 zone false",
		"_acme-challenge.edge.dnshost.test. TXT":  "tier4 zone false",
		"www.corp.test. TXT":                      "tier4 zone true",
		"corp.test. TXT":                          "tier4 zone true",
	}
	got := schTierOf(t, Plan(f, nil, schIv))
	if len(got) != len(want) {
		t.Fatalf("records checks:\n got %v\nwant %v", got, want)
	}
	for k, w := range want {
		if got[k] != w {
			t.Errorf("%s: got %q, want %q", k, got[k], w)
		}
	}
	// A name given to --fast stays fast, and the challenge rule adds to it.
	fast := schNames(t, "www.corp.test.")
	if got := schTierOf(t, Plan(f, fast, schIv)); got["www.corp.test. TXT"] != "tier3 zone true" || got["_acme-challenge.www.corp.test. TXT"] != "tier3 zone true" {
		t.Errorf("fast names with challenge lines: %v", got)
	}
}

// ---- ownNotice ----

func TestChallengeChangeExplainsTheRoundAsRecordSetDoes(t *testing.T) {
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
		s := schMoved(t)
		for i, k := range schZoneKeys(t) {
			var changes []decide.Change
			if i == 0 {
				changes = []decide.Change{{Op: op, Finding: decide.Finding{Rule: decide.RuleChallenge, Check: k}, At: schSec(9)}}
			}
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
			schWantJudged(t, fmt.Sprintf("%s challenge, then %s", op, k), moves, ok, false, nil)
		}
	}
}

func TestDisagreeChangeLeavesTheRoundUnexplained(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleDisagree, decide.RuleCheckFailing, decide.RuleZoneChanged, decide.RuleGlue, decide.RuleDS, decide.RuleGone} {
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

func TestOwnNoticeIsTheRulesOfTheLinesOfTheZone(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleInvalidFile, decide.RuleNotCovered, decide.RuleZone, decide.RuleNameServers, decide.RuleRecordSet,
		decide.RuleCheckFailing, decide.RuleZoneChanged, decide.RuleGlue, decide.RuleDS, decide.RuleGone, decide.RuleDisagree, decide.RuleChallenge, decide.RuleWildcard,
		decide.RuleSPF, decide.RuleDMARC, decide.RuleDKIM, decide.RuleMTASTS} {
		want := rule == decide.RuleRecordSet || rule == decide.RuleZone || rule == decide.RuleChallenge || rule == decide.RuleWildcard ||
			rule == decide.RuleSPF || rule == decide.RuleDMARC || rule == decide.RuleDKIM || rule == decide.RuleMTASTS
		for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
			c := decide.Change{Op: op, Finding: decide.Finding{Rule: rule}}
			if got := ownNotice(c); got != want {
				t.Errorf("ownNotice of %s %s is %v, want %v", op, rule, got, want)
			}
		}
	}
}

// A stale server that is taken out of the set of nameservers, or that gets
// another address, is no longer asked. Its runs are quiet, so the alert that
// it opened ends at the 11th of them; a server that is still asked and still
// stale keeps it open, also at another address.
func TestStaleServerThatIsNoLongerAskedEndsTheAlert(t *testing.T) {
	fast, other := dngTiers()
	const gone = 15 // the first run without the stale server at its address
	for _, day := range []dngDay{fast, other} {
		for _, c := range []struct {
			name   string
			after  []string
			resolv []int
		}{
			{"taken out of the set", []string{"81", "81", "-"}, []int{gone + DisagreeRuns - 1}},
			{"renumbered and fixed", []string{"81", "81", "-", "81"}, []int{gone + DisagreeRuns - 1}},
			{"renumbered and still stale", []string{"81", "81", "-", "88"}, nil},
		} {
			t.Run(day.name+", "+c.name, func(t *testing.T) {
				g := newDngRig(t, day.line, day.tier, Defaults())
				for i := range 60 {
					words := []string{"81", "81", "88"}
					if i >= gone {
						words = c.after
					}
					g.feed(schT0.Add(time.Duration(i)*day.every), words...)
				}
				if !slices.Equal(g.opens, []int{DisagreeRuns - 1}) || !slices.Equal(g.resolve, c.resolv) || len(g.updates) != 0 {
					t.Errorf("opens %v (want [%d]), resolves %v (want %v), updates %v", g.opens, DisagreeRuns-1, g.resolve, c.resolv, g.updates)
				}
			})
		}
	}
}

// The healthy server dies for good after the alert opened: the failing runs
// keep the alert, and when the stale server is fixed the alert ends, although
// a server that it shows still fails.
func TestHealthyServerDiesThenTheStaleOneIsFixed(t *testing.T) {
	fast, _ := dngTiers()
	g := newDngRig(t, fast.line, fast.tier, Defaults())
	const dies, fixed = 12, 22
	for i := range 60 {
		words := []string{"81", "88"}
		switch {
		case i >= fixed:
			words = []string{"x", "81"}
		case i >= dies:
			words = []string{"x", "88"}
		}
		g.feed(schT0.Add(time.Duration(i)*fast.every), words...)
	}
	if want := []int{fixed + DisagreeRuns - 1}; !slices.Equal(g.opens, []int{DisagreeRuns - 1}) || !slices.Equal(g.resolve, want) || len(g.updates) != 0 {
		t.Errorf("opens %v, resolves %v (want %v), updates %v", g.opens, g.resolve, want, g.updates)
	}
}

// A stale server that dies keeps the alert open: no run shows that the
// servers agree.
func TestStaleServerThatDiesKeepsTheAlertOpen(t *testing.T) {
	fast, _ := dngTiers()
	g := newDngRig(t, fast.line, fast.tier, Defaults())
	for i := range 200 {
		second := "88"
		if i >= 12 {
			second = "x"
		}
		g.feed(schT0.Add(time.Duration(i)*fast.every), "81", second)
	}
	if !slices.Equal(g.opens, []int{DisagreeRuns - 1}) || len(g.resolve) != 0 || len(g.updates) != 0 {
		t.Errorf("opens %v, resolves %v, updates %v", g.opens, g.resolve, g.updates)
	}
}

// The most opens in 30 days that the simulation of servers that keep a pick
// for 2, 3 and 5 runs may give. The rules gave 11, 75 and 231; the bounds
// leave a margin, and they stay far below the 43200 runs: an alert that opens
// and ends at almost every split would give about as many as the runs.
const (
	dngMostOpens2 = 15
	dngMostOpens3 = 90
	dngMostOpens5 = 260
)
