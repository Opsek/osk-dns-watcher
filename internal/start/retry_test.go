package start

import (
	"context"
	"errors"
	"maps"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// stfRunner is the observer of the retry tests. The nth run of a check gives
// the nth entry of its list in seq, the last entry again after the end of the
// list, and the fake world for a nil entry or a check with no list.
type stfRunner struct {
	seq    map[string][][]obs.Answer
	broken map[string]int // a check in it gives an error from its nth run on
	mu     sync.Mutex
	calls  map[string]int
	total  int
	seen   []obs.Observation
}

func (r *stfRunner) Run(_ context.Context, c observe.Check) (obs.Observation, error) {
	key := c.Key.String()
	r.mu.Lock()
	n := r.calls[key]
	r.calls[key]++
	r.total++
	r.mu.Unlock()
	if from, ok := r.broken[key]; ok && n >= from {
		return obs.Observation{}, errors.New("the check did not run")
	}
	answers := iniBase(c.Key)
	if list := r.seq[key]; len(list) > 0 {
		if a := list[min(n, len(list)-1)]; a != nil {
			answers = a
		}
	}
	zone := c.Key.Domain
	if c.Key.Kind == obs.KindDelegation || c.Key.Kind == obs.KindDS {
		zone = zone.Parent()
	}
	o := obs.Observation{Key: c.Key, Zone: zone, Answers: answers}
	r.mu.Lock()
	r.seen = append(r.seen, o)
	r.mu.Unlock()
	return o, nil
}

// observations gives every observation that a run gave, both runs of a
// check that ran twice.
func (r *stfRunner) observations() []obs.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

func (r *stfRunner) runs(key string) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.calls[key]
}

func (r *stfRunner) all() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.total
}

// stfNew is a setup whose observer is an stfRunner with the lists seq.
func stfNew(t *testing.T, seq map[string][][]obs.Answer, answers ...string) (*iniSetup, *stfRunner) {
	t.Helper()
	s := iniNew(t, answers...)
	r := &stfRunner{seq: seq, calls: map[string]int{}}
	s.init.Observer = r
	return s, r
}

// stfCounts checks that each check of the domains ran once, except those in
// twice, which ran twice, and that nothing else ran.
func stfCounts(t *testing.T, r *stfRunner, domains []string, twice ...string) {
	t.Helper()
	total := 0
	for _, d := range domains {
		for _, k := range iniKeys(d, true) {
			want := 1
			if slices.Contains(twice, k) {
				want = 2
			}
			if got := r.runs(k); got != want {
				t.Errorf("check %s ran %d times; want %d", k, got, want)
			}
			total += want
		}
	}
	if got := r.all(); got != total {
		t.Errorf("%d checks ran; want %d", got, total)
	}
}

func stfWarning(d string) string {
	return "warning osk-dns-watcher cannot watch the nameservers of " + d + " yet. Until its file has an NS line, " +
		"a change of the nameservers gives no critical alert, only an update of the alert about the missing line; osk-dns-watcher sends that alert at its first check.\n"
}

// stfBlock is iniBlock of a domain that has no NS line: its warning ends it.
func stfBlock(d string, lines []string, skips ...string) string {
	return iniBlock(d, lines, skips...) + stfWarning(d)
}

// stfWithout gives the lines without the one of the apex set of the type kind.
func stfWithout(lines []string, kind string) []string {
	d := strings.TrimPrefix(lines[0], "domain ")
	return slices.DeleteFunc(slices.Clone(lines), func(l string) bool { return strings.HasPrefix(l, d+" "+kind+" ") })
}

// stfOneDead is the answer of a set whose second server gives none.
func stfOneDead(owner string, t dnswire.Type, why obs.Reason, data ...string) []obs.Answer {
	return []obs.Answer{
		iniAt("ns1.example.net.", iniNS1Addr, iniRecords(owner, t, data...)),
		iniAt("ns2.example.net.", iniNS2Addr, iniFail(why)),
	}
}

func stfParentFails() []obs.Answer {
	return []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniFail(obs.ReasonTimeout))}
}

// A check with a failure answer in its first observation runs once more, and
// the second observation is the one that init shows and writes. It holds
// for each kind of check and also when only one of the servers failed.
func TestInitRunsACheckWithAFailureAnswerOnceMore(t *testing.T) {
	d := "example.com."
	a99 := iniBoth(iniRecords(d, dnswire.TypeA, "192.0.2.99"))
	moved := slices.Clone(iniLines(d))
	moved[1] = d + " A 192.0.2.99"
	for _, c := range []struct {
		name         string
		key          string
		first, again []obs.Answer // again is nil for the fake world
		lines        []string
	}{
		{"delegation", obs.DelegationKey(iniName(d)).String(), stfParentFails(), nil, iniLines(d)},
		{"delegation, one parent server of two", obs.DelegationKey(iniName(d)).String(), []obs.Answer{
			iniAt("a.parent.example.", "192.0.2.1:53", iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
			iniAt("b.parent.example.", "192.0.2.2:53", iniFail(obs.ReasonNetwork)),
		}, nil, iniLines(d)},
		{"ds", obs.DSKey(iniName(d)).String(), stfParentFails(), nil, iniLines(d)},
		{"apex NS", iniKey(d, d, dnswire.TypeNS), stfOneDead(d, dnswire.TypeNS, obs.ReasonTimeout, "ns1.example.net.", "ns2.example.net."), nil, iniLines(d)},
		{"A, with a second observation that differs", iniKey(d, d, dnswire.TypeA),
			stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"), a99, moved},
		{"A, every server failed", iniKey(d, d, dnswire.TypeA),
			iniBoth(iniFail(obs.ReasonNetwork)), nil, iniLines(d)},
		{"www", iniKey(d, "www."+d, dnswire.TypeA),
			[]obs.Answer{iniAt("ns1.example.net.", iniNS1Addr, iniFail(obs.ReasonRefused))}, nil, iniLines(d)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{c.key: {c.first, c.again}}, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, c.lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
			stfCounts(t, r, []string{d}, c.key)
			iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(c.lines, "\n")+"\n")
		})
	}
}

func TestInitRunsEachCheckOnceWhenNoneHoldsAFailureAnswer(t *testing.T) {
	s, r := stfNew(t, nil, "example.com", iniURL, "yes")
	code, _ := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	stfCounts(t, r, []string{"example.com."})
}

// A check that failed twice is run twice and used as it is.
func TestInitUsesACheckThatFailedTwiceAsItIs(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeA)
	dead := stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10")
	s, r := stfNew(t, map[string][][]obs.Answer{key: {dead}}, "example.com", iniURL, "yes")
	code, out := s.run()
	lines := stfWithout(iniLines(d), "A")
	skips := []string{d + " A: " + iniNS2Addr + " ns2.example.net. gave no answer (timeout)", iniAliasSkip(d)}
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, skips...))+"yes\n"+s.wrote(d))
	stfCounts(t, r, []string{d}, key)
	iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
}

// The refusals stay: a delegation that still fails after the retry stops the
// run as before, and the second observation decides when it differs.
func TestInitRefusesAfterTheRetryOfTheDelegation(t *testing.T) {
	d := "example.com."
	key := obs.DelegationKey(iniName(d)).String()
	for _, c := range []struct {
		name  string
		list  [][]obs.Answer
		why   string
		times int
	}{
		{"fails twice", [][]obs.Answer{stfParentFails()}, iniNoAnswer(d, "timeout"), 2},
		{"fails with another reason the second time", [][]obs.Answer{stfParentFails(),
			{iniAt(iniParentHost, iniParentAddr, iniFail(obs.ReasonRefused))}}, iniNoAnswer(d, "refused"), 2},
		{"fails, then the parent denies", [][]obs.Answer{stfParentFails(),
			{iniAt(iniParentHost, iniParentAddr, iniNoName("com."))}}, iniDenied(d), 2},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{key: c.list}, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, s.refused("example.com", c.why))
			if got := r.runs(key); got != c.times {
				t.Errorf("the delegation ran %d times; want %d", got, c.times)
			}
			s.nothingWritten()
		})
	}
}

// Each domain has its own retries.
func TestInitRetriesTheChecksOfEachDomain(t *testing.T) {
	com, org := "example.com.", "example.org."
	keyA := iniKey(com, com, dnswire.TypeA)
	keyDS := obs.DSKey(iniName(org)).String()
	s, r := stfNew(t, map[string][][]obs.Answer{
		keyA:  {stfOneDead(com, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"), nil},
		keyDS: {stfParentFails(), nil},
	}, "example.com example.org", iniURL, "yes")
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	stfCounts(t, r, []string{com, org}, keyA, keyDS)
	iniSame(t, "the dialogue", out, s.shown("example.com example.org",
		iniBlock(com, iniLines(com), iniAliasSkip(com)), iniBlock(org, iniLines(org), iniAliasSkip(org)))+"yes\n"+s.wrote(com, org))
}

// stfNoNSSet is the apex NS set of d when its second server says that the
// apex has none, with r: no set that an NS line could accept.
func stfNoNSSet(d string, r obs.Result) []obs.Answer {
	return []obs.Answer{
		iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
		iniAt("ns2.example.net.", iniNS2Addr, r),
	}
}

// stfNoNSSkip is the reason of the NS set of stfNoNSSet with no data or no
// such name.
func stfNoNSSkip(d string) string {
	return d + " NS: servers disagree: " + iniParentAddr + " " + iniParentHost + " gives ns1.example.net. | ns2.example.net.; " +
		iniNS2Addr + " ns2.example.net. gives none"
}

// A set without an NS line means that osk-dns-watcher cannot see a change of the
// nameservers: init says so under the sets that it leaves out. A server of
// the domain that gives the apex no NS set, or another type, leaves no set
// that a line could accept. Nothing failed, so nothing runs twice.
func TestInitWarnsWhenTheApexNSSetGetsNoLine(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeNS)
	lines := stfWithout(iniLines(d), "NS")
	for _, c := range []struct {
		name string
		r    obs.Result
		why  string
	}{
		{"no data", iniNoData(d), stfNoNSSkip(d)},
		{"no such name", iniNoName(d), stfNoNSSkip(d)},
		{"a CNAME", iniRecords(d, dnswire.TypeCNAME, "ns.other.example."),
			d + " NS: " + iniNS2Addr + " ns2.example.net. answers with a CNAME record; snapshot " + d + " CNAME instead"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{key: {stfNoNSSet(d, c.r)}}, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", stfBlock(d, lines, c.why, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
			stfCounts(t, r, []string{d})
			iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
		})
	}
}

// stfNSNoAnswer is the warning of a domain whose NS line rests without the
// servers given, each as "<addr> <host> (<reason>)".
func stfNSNoAnswer(d string, servers ...string) string {
	return "warning " + strings.Join(servers, ", ") + " gave no answer about the nameservers of " + d +
		", so its NS line holds what the other servers gave. If they hold another set, osk-dns-watcher alerts at its first check.\n"
}

// A failed answer of a server of the domain is left out of the NS line, even
// after its second run: the line holds the set of the parent zone and of the
// servers that answered, and a warning names each server left out, since a
// set it holds would give an alert at the first check.
func TestInitWritesTheNSLineWhenAServerOfTheDomainFailsTwice(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeNS)
	for _, c := range []struct {
		name    string
		answers []obs.Answer
		warning string
	}{
		{"one server of two", stfOneDead(d, dnswire.TypeNS, obs.ReasonTimeout, "ns1.example.net.", "ns2.example.net."),
			stfNSNoAnswer(d, iniNS2Addr+" ns2.example.net. (timeout)")},
		{"every server: the line is the parent's set alone", iniBoth(iniFail(obs.ReasonRefused)),
			stfNSNoAnswer(d, iniNS1Addr+" ns1.example.net. (refused)", iniNS2Addr+" ns2.example.net. (refused)")},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{key: {c.answers}}, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))+c.warning)+"yes\n"+s.wrote(d))
			stfCounts(t, r, []string{d}, key)
			data := s.written(d)["example.com.expect"]
			iniSame(t, "example.com.expect", data, iniStamp+strings.Join(iniLines(d), "\n")+"\n")
			iniNoFindings(t, data, r.observations())
		})
	}
}

// Servers that give different NS sets give a line that accepts each set, and
// no retry: nothing failed. The warning after the block names each set and
// the servers that gave it, so a set that is not the owner's is seen before
// the question.
func TestInitWarnsWhenTheServersGiveDifferentNSSets(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeNS)
	differ := []obs.Answer{
		iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
		iniAt("ns2.example.net.", iniNS2Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns.other.example.")),
	}
	s, r := stfNew(t, map[string][][]obs.Answer{key: {differ}}, "example.com", iniURL, "yes")
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	stfCounts(t, r, []string{d})
	lines := slices.Clone(iniLines(d))
	lines[2] = d + " NS ns.other.example. | ns1.example.net. || ns1.example.net. | ns2.example.net."
	warning := iniSetsWarning(d,
		expect.NSSource{Text: "ns.other.example. | ns1.example.net.", Zone: []string{iniNS2Addr + " ns2.example.net."}},
		expect.NSSource{Text: "ns1.example.net. | ns2.example.net.", Parent: []string{iniParentAddr + " " + iniParentHost},
			Zone: []string{iniNS1Addr + " ns1.example.net."}})
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d))+warning)+"yes\n"+s.wrote(d))
	if strings.Contains(out, "warning osk-dns-watcher cannot watch") {
		t.Errorf("the output holds the warning about a missing NS line:\n%s", out)
	}
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
	iniNoFindings(t, data, r.observations())
}

// With an NS line there is no warning, whatever else is left out, and a
// retry that gets the line back leaves no trace.
func TestInitDoesNotWarnWhenTheApexNSSetHasALine(t *testing.T) {
	d := "example.com."
	for _, c := range []struct {
		name string
		seq  map[string][][]obs.Answer
		line string // the set that the file lacks, "" for none
	}{
		{"the fake world", nil, ""},
		{"NS failed once", map[string][][]obs.Answer{
			iniKey(d, d, dnswire.TypeNS): {stfOneDead(d, dnswire.TypeNS, obs.ReasonTimeout, "ns1.example.net.", "ns2.example.net."), nil},
		}, ""},
		{"MX failed twice", map[string][][]obs.Answer{
			iniKey(d, d, dnswire.TypeMX): {stfOneDead(d, dnswire.TypeMX, obs.ReasonTimeout, "10 mail.example.com.")},
		}, "MX"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := stfNew(t, c.seq, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if strings.Contains(out, "cannot watch the nameservers") {
				t.Errorf("the output holds the warning:\n%s", out)
			}
			if lines, _ := iniShown(out, d); !slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, " NS ") }) {
				t.Errorf("init showed no NS line:\n%s", out)
			}
			if lines, _ := iniShown(out, d); c.line != "" && slices.ContainsFunc(lines, func(l string) bool { return strings.Contains(l, " "+c.line+" ") }) {
				t.Errorf("init showed a %s line that failed twice:\n%s", c.line, out)
			}
		})
	}
}

// Of two domains only the one without an NS line gets the warning, and the
// files are written for both.
func TestInitWarnsOnlyForTheDomainWithoutAnNSLine(t *testing.T) {
	com, org := "example.com.", "example.org."
	noSet := stfNoNSSet(org, iniNoData(org))
	linesOrg := stfWithout(iniLines(org), "NS")
	for _, answer := range []string{"example.com example.org", "example.org example.com"} {
		t.Run(answer, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{iniKey(org, org, dnswire.TypeNS): {noSet}}, answer, iniURL, "yes")
			code, out := s.run()
			orgSkips := []string{stfNoNSSkip(org), iniAliasSkip(org)}
			blocks := []string{iniBlock(com, iniLines(com), iniAliasSkip(com)), stfBlock(org, linesOrg, orgSkips...)}
			domains := []string{com, org}
			if answer == "example.org example.com" {
				blocks[0], blocks[1] = blocks[1], blocks[0]
				domains = []string{org, com}
			}
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown(answer, blocks...)+"yes\n"+s.wrote(domains...))
			stfCounts(t, r, []string{com, org})
			texts := s.written(domains...)
			iniSame(t, "example.org.expect", texts["example.org.expect"], iniStamp+strings.Join(linesOrg, "\n")+"\n")
		})
	}
}

// An address that this machine has no route to is not worth a second try
// when another answer is usable: another run gives the same. Any other
// failure is, and so is a check with no usable answer at all.
func TestInitRetriesAFailureAnswerExceptAnAddressWithNoRoute(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeA)
	a := iniRecords(d, dnswire.TypeA, "192.0.2.10")
	for _, c := range []struct {
		name    string
		answers []obs.Answer
		twice   bool
	}{
		{"an IPv6 address, no route", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
			iniAt("ns2.example.net.", iniNS2Addr, a),
		}, false},
		{"only IPv6 addresses, no route", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
			iniAt("ns2.example.net.", iniNS2v6Addr, iniFail(obs.ReasonNoRoute)),
		}, true},
		{"an IPv6 address, no route, and an IPv4 address that timed out", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
			iniAt("ns2.example.net.", iniNS2Addr, iniFail(obs.ReasonTimeout)),
		}, true},
		{"an IPv6 address, network", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNetwork)),
			iniAt("ns2.example.net.", iniNS2Addr, a),
		}, true},
		{"an IPv6 address, timeout", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonTimeout)),
			iniAt("ns2.example.net.", iniNS2Addr, a),
		}, true},
		{"an IPv4 address, network", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a),
			iniAt("ns2.example.net.", iniNS2Addr, iniFail(obs.ReasonNetwork)),
		}, true},
		{"a walk that failed", []obs.Answer{{Result: iniFail(obs.ReasonWalk)}}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{key: {c.answers}}, "example.com", iniURL, "yes")
			code, _ := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if c.twice {
				stfCounts(t, r, []string{d}, key)
			} else {
				stfCounts(t, r, []string{d})
			}
		})
	}
}

// The second observation replaces the first only when it holds no more
// failure answers, so a retry never makes the look worse. The reason word in
// the skip line shows which observation init used.
func TestInitUsesTheSecondObservationOnlyWhenItIsNotWorse(t *testing.T) {
	d := "example.com."
	key := iniKey(d, d, dnswire.TypeA)
	skip := func(why string) string {
		return d + " A: " + iniNS2Addr + " ns2.example.net. gave no answer (" + why + ")"
	}
	both := iniBoth(iniFail(obs.ReasonNetwork))
	lines := stfWithout(iniLines(d), "A")
	for _, c := range []struct {
		name         string
		first, again []obs.Answer
		broken       bool // the second run gives an error
		why          string
	}{
		{"more failure answers keeps the first", stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"), both, false, "timeout"},
		{"the same number replaces the first", stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"),
			stfOneDead(d, dnswire.TypeA, obs.ReasonRefused, "192.0.2.10"), false, "refused"},
		{"fewer replaces the first", both, stfOneDead(d, dnswire.TypeA, obs.ReasonRefused, "192.0.2.10"), false, "refused"},
		{"an error keeps the first", stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"), nil, true, "timeout"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{key: {c.first, c.again}}, "example.com", iniURL, "yes")
			if c.broken {
				r.broken = map[string]int{key: 1}
			}
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, skip(c.why), iniAliasSkip(d)))+"yes\n"+s.wrote(d))
			stfCounts(t, r, []string{d}, key)
		})
	}
	// A delegation where one parent server of two answered the first time and
	// both fail the second time is not a refusal: the first look stands.
	t.Run("a delegation that gets worse is not refused", func(t *testing.T) {
		dkey := obs.DelegationKey(iniName(d)).String()
		first := []obs.Answer{
			iniAt("a.parent.example.", "192.0.2.1:53", iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
			iniAt("b.parent.example.", "192.0.2.2:53", iniFail(obs.ReasonTimeout)),
		}
		worse := []obs.Answer{
			iniAt("a.parent.example.", "192.0.2.1:53", iniFail(obs.ReasonTimeout)),
			iniAt("b.parent.example.", "192.0.2.2:53", iniFail(obs.ReasonTimeout)),
		}
		s, r := stfNew(t, map[string][][]obs.Answer{dkey: {first, worse}}, "example.com", iniURL, "yes")
		code, out := s.run()
		if code != 0 {
			t.Errorf("exit code %d; want 0; output:\n%s", code, out)
		}
		if strings.Contains(out, "got no answer about") || !strings.Contains(out, d+" as osk-dns-watcher sees it now.") {
			t.Errorf("init refused the domain, or did not show it:\n%s", out)
		}
		stfCounts(t, r, []string{d}, dkey)
		s.written(d)
	})
}

// stfTail gives the lines of the output that follow the lines and the skips
// of the block of d.
func stfTail(out, d string) []string {
	all := strings.Split(out, "\n")
	i := slices.Index(all, d+" as osk-dns-watcher sees it now. Once you confirm, osk-dns-watcher alerts when the servers differ from these lines:")
	if i < 0 {
		return nil
	}
	lines, skips := iniShown(out, d)
	at := i + 1 + len(lines)
	if len(skips) > 0 {
		at += 1 + len(skips)
	}
	return all[at:]
}

func stfNothingCompared(d string) string {
	return "warning osk-dns-watcher watches no record set of " + d + " yet: each one is listed above with its reason. " +
		"Until its file has those lines, a change of them gives no alert.\n"
}

// stfDead fails twice each check of the records of d that is not in keep, the
// ones under the apex too.
func stfDead(d string, keep ...string) map[string][][]obs.Answer {
	seq := map[string][][]obs.Answer{}
	keys := []string{
		iniKey(d, "www."+d, dnswire.TypeA), iniKey(d, "*."+d, dnswire.TypeA),
		iniKey(d, "_dmarc."+d, dnswire.TypeTXT), iniKey(d, "_mta-sts."+d, dnswire.TypeTXT),
		iniKey(d, "_acme-challenge."+d, dnswire.TypeTXT), iniKey(d, "_acme-challenge.www."+d, dnswire.TypeTXT),
	}
	for _, ty := range []dnswire.Type{dnswire.TypeNS, dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCAA} {
		keys = append(keys, iniKey(d, d, ty))
	}
	for _, k := range keys {
		if !slices.Contains(keep, k) {
			seq[k] = [][]obs.Answer{iniBoth(iniFail(obs.ReasonTimeout))}
		}
	}
	return seq
}

// stfNoNS gives seq with the apex NS set of d of stfNoNSSet: no NS line,
// although the parent zone answers.
func stfNoNS(seq map[string][][]obs.Answer, d string) map[string][][]obs.Answer {
	seq[iniKey(d, d, dnswire.TypeNS)] = [][]obs.Answer{stfNoNSSet(d, iniNoData(d))}
	return seq
}

// When a file holds no line but NS and DS, osk-dns-watcher compares nothing: init says
// so after the warning about the nameservers, when both apply. A failed NS
// set of the apex still gets the line of the parent's set, and its warning
// names the servers that gave no answer.
func TestInitWarnsWhenTheFileHoldsNoRecordSet(t *testing.T) {
	com, org := "example.com.", "example.org."
	noNS := stfWarning(com)
	noAnswer := stfNSNoAnswer(com, iniNS1Addr+" ns1.example.net. (timeout)", iniNS2Addr+" ns2.example.net. (timeout)")
	for _, c := range []struct {
		name string
		seq  map[string][][]obs.Answer
		ns   string // the warning about the nameservers, "" for none
		sets bool   // the warning about the record sets
	}{
		{"only DS", stfNoNS(stfDead(com), com), noNS, true},
		{"NS of the parent alone and DS", stfDead(com), noAnswer, true},
		{"NS and DS", stfDead(com, iniKey(com, com, dnswire.TypeNS)), "", true},
		{"DS and one more line", stfNoNS(stfDead(com, iniKey(com, com, dnswire.TypeA)), com), noNS, false},
		{"DS and a none line of a name under the apex", stfNoNS(stfDead(com, iniKey(com, "*."+com, dnswire.TypeA)), com), noNS, false},
		{"DS and the none line of a challenge name", stfNoNS(stfDead(com, iniKey(com, "_acme-challenge."+com, dnswire.TypeTXT)), com), noNS, false},
		{"DS and the none line of the DMARC name", stfNoNS(stfDead(com, iniKey(com, "_dmarc."+com, dnswire.TypeTXT)), com), noNS, false},
		{"DS and the none line of the MTA-STS name", stfNoNS(stfDead(com, iniKey(com, "_mta-sts."+com, dnswire.TypeTXT)), com), noNS, false},
		{"NS, DS and one more line", stfDead(com, iniKey(com, com, dnswire.TypeNS), iniKey(com, com, dnswire.TypeMX)), "", false},
		{"NS, DS and a none line of a name under the apex", stfDead(com, iniKey(com, com, dnswire.TypeNS), iniKey(com, "_acme-challenge.www."+com, dnswire.TypeTXT)), "", false},
		{"the fake world", nil, "", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := stfNew(t, c.seq, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			var want []string
			if c.ns != "" {
				want = append(want, strings.TrimSuffix(c.ns, "\n"))
			}
			if c.sets {
				want = append(want, strings.TrimSuffix(stfNothingCompared(com), "\n"))
			}
			tail := stfTail(out, com)
			if len(tail) < len(want) || !slices.Equal(tail[:len(want)], want) {
				t.Errorf("after the sets that are left out, the output reads %q; want it to start with %q", tail, want)
			}
			for _, w := range []string{noNS, noAnswer, stfNothingCompared(com)} {
				if n, wanted := strings.Count(out, w), slices.Contains(want, strings.TrimSuffix(w, "\n")); (n == 1) != wanted || n > 1 {
					t.Errorf("the warning %q is in the output %d times; wanted: %v", w, n, wanted)
				}
			}
			s.written(com)
		})
	}
	t.Run("two domains, each block has its own", func(t *testing.T) {
		seq := stfNoNS(stfDead(com), com)
		maps.Copy(seq, stfDead(org, iniKey(org, org, dnswire.TypeNS)))
		s, _ := stfNew(t, seq, "example.com example.org", iniURL, "yes")
		code, out := s.run()
		if code != 0 {
			t.Errorf("exit code %d; want 0", code)
		}
		wantCom := []string{strings.TrimSuffix(stfWarning(com), "\n"), strings.TrimSuffix(stfNothingCompared(com), "\n")}
		if tail := stfTail(out, com); len(tail) < 2 || !slices.Equal(tail[:2], wantCom) {
			t.Errorf("the block of %s ends with %q; want %q", com, tail, wantCom)
		}
		if tail := stfTail(out, org); len(tail) < 1 || tail[0] != strings.TrimSuffix(stfNothingCompared(org), "\n") {
			t.Errorf("the block of %s ends with %q; want its second warning alone", org, tail)
		}
		if strings.Contains(out, stfWarning(org)) || strings.Count(out, "warning osk-dns-watcher ") != 3 {
			t.Errorf("the output holds the wrong warnings:\n%s", out)
		}
	})
}
