package expect

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The NS set of the domain is judged twice: at the parent zone (the
// delegation) and at the domain's own servers. When their answers differ,
// the line accepts each set that a server gave, so that a domain whose
// servers disagree a little still has an alarm for a change of its
// nameservers. Anything that no alternative can state gives no line.

const (
	nslParent2Addr = "10.53.0.4:53"
	nslNS3Addr     = "10.53.0.13:53"
	nslNS4Addr     = "10.53.0.14:53"
)

func nslDelegation(t testing.TB, answers ...obs.Answer) obs.Observation {
	t.Helper()
	return expObs(t, obs.DelegationKey(expName(t, "corp.test.")), "test.", answers...)
}

func nslApex(t testing.TB, answers ...obs.Answer) obs.Observation {
	t.Helper()
	return expObs(t, expRecordsKey(t, "corp.test.", dnswire.TypeNS), "corp.test.", answers...)
}

// nslSet is the NS set of corp.test. with the hosts nsN.corp.test. of each N.
func nslSet(ns ...int) []string {
	var hosts []string
	for _, n := range ns {
		hosts = append(hosts, fmt.Sprintf("ns%d.corp.test.", n))
	}
	return hosts
}

func nslText(ns ...int) string { return strings.Join(nslSet(ns...), " | ") }

func nslParent(t testing.TB, ns ...int) obs.Answer {
	return expApexNS(t, "ns.test.", expParentAddr, nslSet(ns...)...)
}

func nslParent2(t testing.TB, ns ...int) obs.Answer {
	return expApexNS(t, "ns2.test.", nslParent2Addr, nslSet(ns...)...)
}

// nslAt is the answer of server nsK.corp.test. of the domain.
func nslAt(t testing.TB, k int, r obs.Result) obs.Answer {
	addrs := map[int]string{1: expNS1Addr, 2: expNS2Addr, 3: nslNS3Addr, 4: nslNS4Addr}
	return expAnswer(t, fmt.Sprintf("ns%d.corp.test.", k), addrs[k], r)
}

func nslGives(t testing.TB, k int, ns ...int) obs.Answer {
	return nslAt(t, k, expRecords(t, dnswire.TypeNS, "corp.test.", nslSet(ns...)...))
}

// The server texts of the sources, as the warning of init shows them.
const (
	nslP  = "10.53.0.3:53 ns.test."
	nslP2 = "10.53.0.4:53 ns2.test."
	nslC1 = "10.53.0.11:53 ns1.corp.test."
	nslC2 = "10.53.0.12:53 ns2.corp.test."
	nslC3 = "10.53.0.13:53 ns3.corp.test."
)

// nslNSLine gives the NS line of corp.test. as File.String prints it, or "".
func nslNSLine(f *File) string {
	for line := range strings.Lines(f.String()) {
		if strings.HasPrefix(line, "corp.test. NS ") {
			return strings.TrimSuffix(line, "\n")
		}
	}
	return ""
}

func TestSnapshotNSLineAcceptsEachSetTheServersGave(t *testing.T) {
	cname := expRecords(t, dnswire.TypeCNAME, "corp.test.", "alias.other.test.")
	stray := obs.RecordsResult(obs.Records{Set: []dnswire.Record{
		expRecord(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test."),
		expRecord(t, "corp.test.", dnswire.TypeTXT, `"stray"`),
	}})
	for _, c := range []struct {
		name    string
		obs     []obs.Observation
		line    string // "" for no NS line
		skips   []string
		sources []NSSource
	}{
		{"parent and apex agree: one set, no sources",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 2, 1))},
			"corp.test. NS " + nslText(1, 2), nil, nil},
		{"parent {ns1,ns2}, apex {ns1,ns2,ns3}: two alternatives, each with the servers that gave it",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2, 3), nslGives(t, 2, 1, 2, 3))},
			"corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 2, 3), nil,
			[]NSSource{{Text: nslText(1, 2), Parent: []string{nslP}}, {Text: nslText(1, 2, 3), Zone: []string{nslC1, nslC2}}}},
		{"servers of the domain that differ among themselves",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 3))},
			"corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 3), nil,
			[]NSSource{{Text: nslText(1, 2), Parent: []string{nslP}, Zone: []string{nslC1}}, {Text: nslText(1, 3), Zone: []string{nslC2}}}},
		{"two servers of the parent zone that differ",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2), nslParent2(t, 1, 3)), nslApex(t, nslGives(t, 1, 1, 2))},
			"corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 3), nil,
			[]NSSource{{Text: nslText(1, 2), Parent: []string{nslP}, Zone: []string{nslC1}}, {Text: nslText(1, 3), Parent: []string{nslP2}}}},
		{"four sets: a line of four",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1), nslGives(t, 2, 2), nslGives(t, 3, 1, 2, 3))},
			"corp.test. NS " + nslText(1) + " || " + nslText(1, 2) + " || " + nslText(1, 2, 3) + " || " + nslText(2), nil,
			[]NSSource{{Text: nslText(1), Zone: []string{nslC1}}, {Text: nslText(1, 2), Parent: []string{nslP}},
				{Text: nslText(1, 2, 3), Zone: []string{nslC3}}, {Text: nslText(2), Zone: []string{nslC2}}}},
		{"five sets: no line, the reason of servers that disagree",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1), nslGives(t, 2, 2), nslGives(t, 3, 1, 2, 3), nslGives(t, 4, 3))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives " + nslText(1, 2) + "; " + nslC1 + " gives " + nslText(1)}, nil},
		{"five answers but four sets: a line of four",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1), nslGives(t, 2, 2), nslGives(t, 3, 1, 2, 3), nslGives(t, 4, 2))},
			"corp.test. NS " + nslText(1) + " || " + nslText(1, 2) + " || " + nslText(1, 2, 3) + " || " + nslText(2), nil,
			[]NSSource{{Text: nslText(1), Zone: []string{nslC1}}, {Text: nslText(1, 2), Parent: []string{nslP}},
				{Text: nslText(1, 2, 3), Zone: []string{nslC3}}, {Text: nslText(2), Zone: []string{nslC2, "10.53.0.14:53 ns4.corp.test."}}}},
		{"the parent failed, the apex agrees: no line",
			[]obs.Observation{nslDelegation(t, expAnswer(t, "ns.test.", expParentAddr, expFailure(obs.ReasonTimeout))),
				nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: " + nslP + " gave no answer (timeout)"}, nil},
		{"the parent failed, the apex servers differ: no line",
			[]obs.Observation{nslDelegation(t, expAnswer(t, "ns.test.", expParentAddr, expFailure(obs.ReasonServFail))),
				nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 3))},
			"", []string{"corp.test. NS: " + nslP + " gave no answer (servfail)"}, nil},
		{"the parent gave no data: no line",
			[]obs.Observation{nslDelegation(t, expAnswer(t, "ns.test.", expParentAddr, expNoData(t, "test."))),
				nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives none; " + nslC1 + " gives " + nslText(1, 2)}, nil},
		{"the parent gave no such name: no line",
			[]obs.Observation{nslDelegation(t, expAnswer(t, "ns.test.", expParentAddr, expNoName(t, "test."))),
				nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives none; " + nslC1 + " gives " + nslText(1, 2)}, nil},
		{"no answer of the parent zone was asked for: apex answers that differ give no line",
			[]obs.Observation{nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 3))},
			"", []string{"corp.test. NS: servers disagree: " + nslC1 + " gives " + nslText(1, 2) + "; " + nslC2 + " gives " + nslText(1, 3)}, nil},
		// The line rests on the parent alone, and nothing in the file or the
		// skips says that the servers of the domain did not answer.
		{"every server of the domain failed: the parent's set alone, no skip",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
				nslApex(t, nslAt(t, 1, expFailure(obs.ReasonTimeout)), nslAt(t, 2, expFailure(obs.ReasonRefused)))},
			"corp.test. NS " + nslText(1, 2), nil, nil},
		{"a failed server of the domain is left out",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2, 3), nslAt(t, 2, expFailure(obs.ReasonLame)))},
			"corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 2, 3), nil,
			[]NSSource{{Text: nslText(1, 2), Parent: []string{nslP}}, {Text: nslText(1, 2, 3), Zone: []string{nslC1}}}},
		{"a server of the domain gives no data: no line",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), nslAt(t, 2, expNoData(t, "corp.test.")))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives " + nslText(1, 2) + "; " + nslC2 + " gives none"}, nil},
		{"a server of the domain gives no such name: no line",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslAt(t, 1, expNoName(t, "corp.test.")), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives " + nslText(1, 2) + "; " + nslC1 + " gives none"}, nil},
		{"no data beside sets that differ: no line",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 3), nslAt(t, 2, expNoData(t, "corp.test.")))},
			"", []string{"corp.test. NS: servers disagree: " + nslP + " gives " + nslText(1, 2) + "; " + nslC1 + " gives " + nslText(1, 3)}, nil},
		{"a server of the domain gives a CNAME: no line",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslAt(t, 1, cname), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: " + nslC1 + " answers with a CNAME record; snapshot corp.test. CNAME instead"}, nil},
		{"a server of the domain adds a record of another type: no line",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslAt(t, 1, stray), nslGives(t, 2, 1, 2))},
			"", []string{"corp.test. NS: " + nslC1 + " answers with a TXT record; snapshot corp.test. TXT instead"}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, c.obs...)
			if got := nslNSLine(f); got != c.line {
				t.Errorf("NS line %q; want %q\nfile:\n%s", got, c.line, f.String())
			}
			if !slices.Equal(skips, c.skips) {
				t.Errorf("skips %q; want %q", skips, c.skips)
			}
			if got := NSSources(expName(t, "corp.test."), c.obs); !reflect.DeepEqual(got, c.sources) {
				t.Errorf("NSSources:\n%#v\nwant:\n%#v", got, c.sources)
			}
			if g := expParse(t, f.String()); g.String() != f.String() {
				t.Errorf("the file %q parses again as %q", f.String(), g.String())
			}
			nslNoFinding(t, f, c.obs)
		})
	}
}

// A walk that failed on its way to the servers of the domain is a failed
// answer: it is left out as any other, and the parent's set makes the line.
// A run with no usable answer says nothing about a cut, whatever zone it
// ended in: when every query fails, the walk stops at a cut learned earlier
// or at the root, and asks the servers there.
func TestSnapshotKeepsTheParentSetWhenTheWalkToTheDomainFailed(t *testing.T) {
	apex := expRecordsKey(t, "corp.test.", dnswire.TypeNS)
	fail := func(host, addr string, why obs.Reason) obs.Answer { return expAnswer(t, host, addr, expFailure(why)) }
	for _, c := range []struct {
		name string
		obs  []obs.Observation
		line string
	}{
		{"the walk alone", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), expFailedWalk(apex)},
			"corp.test. NS " + nslText(1, 2)},
		{"every root server failed", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			expObs(t, apex, ".", fail("", "10.53.0.2:53", obs.ReasonNetwork), fail("", "[fd53::2]:53", obs.ReasonNoRoute))},
			"corp.test. NS " + nslText(1, 2)},
		{"every server of the parent failed", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			expObs(t, apex, "test.", fail("ns2.test.", nslParent2Addr, obs.ReasonTimeout))},
			"corp.test. NS " + nslText(1, 2)},
		{"beside a run that answered with another set", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			expFailedWalk(apex), nslApex(t, nslGives(t, 1, 1, 2, 3))},
			"corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 2, 3)},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, c.obs...)
			if got := nslNSLine(f); got != c.line || len(skips) != 0 {
				t.Errorf("NS line %q, skips %q; want %q and no skip", got, skips, c.line)
			}
		})
	}
}

// Only an answer from no server at all is a failed walk. A server known by
// its address alone (a given root server) or by its name alone still found a
// zone, and an answer from another zone than the file expects keeps no line:
// kept, it would trust that zone and report a changed zone at the first
// check.
func TestSnapshotJudgesTheZoneOfAServerKnownByHalf(t *testing.T) {
	www := expRecordsKey(t, "www.corp.test.", dnswire.TypeA)
	a := expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.80")
	for _, c := range []struct {
		name, host, addr string
	}{
		{"a server known by its address alone keeps no line from the root zone", "", "10.53.0.2:53"},
		{"a server known by its name alone keeps no line from the root zone", "ns1.corp.test.", ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, expObs(t, www, ".", expAnswer(t, c.host, c.addr, a)))
			want := []string{"www.corp.test. A: lies in zone .; add the pair . NS"}
			if len(f.Expectations) != 0 || !slices.Equal(skips, want) {
				t.Errorf("file %q, skips %q; want no line and %q", f.String(), skips, want)
			}
		})
	}
}

// Two checks that judge each other: the NS line of sub.corp.test. makes a
// cut that the check of www.sub.corp.test. did not find, and the check of
// that NS set found it in corp.test. itself. Which lines go must not depend
// on which check comes first, and no line that stays lies in another zone
// than the file expects.
func TestSnapshotDropsForeignZonesTheSameInEitherOrder(t *testing.T) {
	sub := expObs(t, expRecordsKey(t, "sub.corp.test.", dnswire.TypeNS), "corp.test.",
		nslAt(t, 1, expRecords(t, dnswire.TypeNS, "sub.corp.test.", "ns1.sub.corp.test.")))
	www := expObs(t, expRecordsKey(t, "www.sub.corp.test.", dnswire.TypeA), "corp.test.",
		nslAt(t, 1, expRecords(t, dnswire.TypeA, "www.sub.corp.test.", "10.53.0.90")))
	f1, skips1 := expSnapshot(t, sub, www)
	f2, skips2 := expSnapshot(t, www, sub)
	if f1.String() != f2.String() || !slices.Equal(skips1, skips2) {
		t.Errorf("the order of the checks changes the file:\n%s%q\nand\n%s%q", f1.String(), skips1, f2.String(), skips2)
	}
	for _, o := range []obs.Observation{sub, www} {
		if _, ok := f1.Find(o.Key.Name, o.Key.Type); ok && !o.Zone.Equal(f1.Zone(o.Key.Name)) {
			t.Errorf("the line of %s stays, but its check lies in zone %s, not %s", o.Key, o.Zone, f1.Zone(o.Key.Name))
		}
	}
}

// nslNoFinding checks the line against each answer it was made from, as the
// delegation and the records check judge it: every answer that is not a
// failure matches.
func nslNoFinding(t *testing.T, f *File, observations []obs.Observation) {
	t.Helper()
	e, ok := f.Find(expName(t, "corp.test."), dnswire.TypeNS)
	if !ok {
		return
	}
	for _, o := range observations {
		for _, a := range o.Answers {
			if set, ok := expAnswerSet(a); ok && !e.Match(set) {
				t.Errorf("%s does not match %q of %s", e.String(), expRecordTexts(set), serverText(a.Server))
			}
		}
	}
}

// NSNoAnswer names each server whose failed answer the NS line rests
// without, so that the operator learns that a set may be missing; only when
// the line is written, and never an address that this machine has no route
// to, which the snapshot counts apart.
func TestNSNoAnswerNamesEachServerTheLineRestsWithout(t *testing.T) {
	fails := func(k int, why obs.Reason) obs.Answer { return nslAt(t, k, expFailure(why)) }
	evil, err := dnswire.NameFromLabels([]string{"ns2\x1b[2J\n", "corp", "test"})
	if err != nil {
		t.Fatal(err)
	}
	evilAnswer := obs.Answer{Proof: obs.Proof{Server: obs.Server{Name: evil, Addr: netip.MustParseAddrPort(expNS2Addr)}},
		Result: expFailure(obs.ReasonTimeout)}
	for _, c := range []struct {
		name string
		obs  []obs.Observation
		want []string
	}{
		{"every server answered", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 3))}, nil},
		{"one server of the domain", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), fails(2, obs.ReasonTimeout))},
			[]string{nslC2 + " (timeout)"}},
		{"every server of the domain, in answer order", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, fails(2, obs.ReasonRefused), fails(1, obs.ReasonLame))}, []string{nslC2 + " (refused)", nslC1 + " (lame)"}},
		{"a server of the parent zone", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2),
			expAnswer(t, "ns2.test.", nslParent2Addr, expFailure(obs.ReasonServFail))), nslApex(t, nslGives(t, 1, 1, 2))},
			[]string{nslP2 + " (servfail)"}},
		{"a failed walk", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), expFailedWalk(expRecordsKey(t, "corp.test.", dnswire.TypeNS))},
			[]string{NoPath}},
		{"two failed walks and a server: the walk is named once", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			expFailedWalk(expRecordsKey(t, "corp.test.", dnswire.TypeNS)), expFailedWalk(expRecordsKey(t, "corp.test.", dnswire.TypeNS)),
			nslApex(t, fails(1, obs.ReasonTimeout))}, []string{NoPath, nslC1 + " (timeout)"}},
		{"an address with no route is not named", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1, 2), expAnswer(t, "ns1.corp.test.", "[fd53::11]:53", expFailure(obs.ReasonNoRoute)))}, nil},
		{"an IPv6 address with a network failure is named", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1, 2), expAnswer(t, "ns1.corp.test.", "[fd53::11]:53", expFailure(obs.ReasonNetwork)))},
			[]string{"[fd53::11]:53 ns1.corp.test. (network)"}},
		{"an IPv6 address that timed out is named", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1, 2), expAnswer(t, "ns1.corp.test.", "[fd53::11]:53", expFailure(obs.ReasonTimeout)))},
			[]string{"[fd53::11]:53 ns1.corp.test. (timeout)"}},
		{"no line: five sets beside a failure", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1), nslGives(t, 2, 2), nslGives(t, 3, 1, 2, 3), nslGives(t, 4, 3), fails(1, obs.ReasonTimeout))}, nil},
		{"no line: no data beside a failure", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslAt(t, 1, expNoData(t, "corp.test.")), fails(2, obs.ReasonTimeout))}, nil},
		{"no line: the parent failed", []obs.Observation{nslDelegation(t, expAnswer(t, "ns.test.", expParentAddr, expFailure(obs.ReasonTimeout))),
			nslApex(t, nslGives(t, 1, 1, 2))}, nil},
		{"a server whose name is hostile", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), evilAnswer)},
			[]string{expNS2Addr + ` ns2\027[2j\010.corp.test. (timeout)`}},
		// observe gives a host for which the walk found no address as a
		// named server without an address. Such a host is the dangling
		// nameserver that a stranger can register, so it is named, not
		// hidden behind the failed walk.
		{"a nameserver host with no address is named, not hidden as no path", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1, 2), expAnswer(t, "ns3.corp.test.", "", expFailure(obs.ReasonWalk)))},
			[]string{"- ns3.corp.test. (walk)"}},
		{"a failed answer of the parent zone from no server is not said to be the path to the servers of the domain",
			[]obs.Observation{nslDelegation(t, nslParent(t, 1, 2), expAnswer(t, "", "", expFailure(obs.ReasonWalk))), nslApex(t, nslGives(t, 1, 1, 2))},
			[]string{"- - (walk)"}},
		{"records from no named server count as a set, not as a failed walk", []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)),
			nslApex(t, nslGives(t, 1, 1, 2), expAnswer(t, "", "", expRecords(t, dnswire.TypeNS, "corp.test.", nslSet(1, 2, 3)...)))}, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := NSNoAnswer(expName(t, "corp.test."), c.obs)
			if !slices.Equal(got, c.want) {
				t.Errorf("NSNoAnswer %q; want %q", got, c.want)
			}
			f, _ := expSnapshot(t, c.obs...)
			if _, ok := f.Find(expName(t, "corp.test."), dnswire.TypeNS); !ok && got != nil {
				t.Errorf("NSNoAnswer %q for a file without an NS line", got)
			}
			if got := NSNoAnswer(expName(t, "other.test."), c.obs); got != nil {
				t.Errorf("NSNoAnswer of another domain: %q", got)
			}
		})
	}
}

// NSSources reads the observations of its own domain only.
func TestNSSourcesOfAnotherDomainIsNil(t *testing.T) {
	observations := []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2, 3))}
	if got := NSSources(expName(t, "other.test."), observations); got != nil {
		t.Errorf("NSSources of other.test.: %#v; want nil", got)
	}
	if got := NSSources(expName(t, "corp.test."), observations); len(got) != 2 {
		t.Errorf("NSSources of corp.test.: %#v; want two sets", got)
	}
}

// An address that this machine has no route to is left out of the NS line
// of several sets as of any other line, and Unreached names it.
func TestSnapshotNSLineOfSeveralSetsCountsAnAddressWithNoRoute(t *testing.T) {
	v6 := expAnswer(t, "ns1.corp.test.", "[fd53::11]:53", expFailure(obs.ReasonNoRoute))
	observations := []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2, 3), v6)}
	f, skips := expSnapshot(t, observations...)
	if want := "corp.test. NS " + nslText(1, 2) + " || " + nslText(1, 2, 3); nslNSLine(f) != want || len(skips) != 0 {
		t.Errorf("NS line %q, skips %q; want %q and no skip", nslNSLine(f), skips, want)
	}
	if got := Unreached(observations); len(got) != 1 || got[0].Addr != netip.MustParseAddrPort("[fd53::11]:53") {
		t.Errorf("Unreached %v; want the IPv6 address", got)
	}
}

// nslHostile gives names that a lying server could put in its NS set: each
// octet that a terminal or the line format could take for something else.
func nslHostile(t testing.TB) []dnswire.Name {
	t.Helper()
	var names []dnswire.Name
	for _, label := range []string{
		"bel\x07", "esc\x1b[2J\x1b[1;1H", "new\nline", "cr\rx", "nul\x00", "del\x7f", "bar|x", "bars||x", "q\"x",
		"back\\x", "sp ace", "#hash", "semi;x", "dot.in", "\xff\xfe", "tab\tx",
	} {
		n, err := dnswire.NameFromLabels([]string{label, "attacker", "example"})
		if err != nil {
			t.Fatalf("label %q: %v", label, err)
		}
		names = append(names, n)
	}
	long, err := dnswire.NameFromLabels([]string{strings.Repeat("\x1b", 63), strings.Repeat("|", 63), strings.Repeat("\n", 63), strings.Repeat("a", 61)})
	if err != nil {
		t.Fatalf("the longest name: %v", err)
	}
	return append(names, long)
}

// nslNames gives the NS records of corp.test. for names.
func nslNames(names []dnswire.Name) obs.Result {
	var set []dnswire.Record
	for _, n := range names {
		set = append(set, dnswire.Record{Name: dnswire.Name{}, Class: dnswire.ClassINET, TTL: 300, Data: dnswire.NS{Host: n}})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

// nslPrintable reports whether s holds only printable ASCII and line ends.
func nslPrintable(s string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return r != '\n' && (r < 0x20 || r > 0x7e) })
}

// A lying server of the domain gives a set of names built to break a
// terminal or the line. Its set becomes one alternative of the line, which
// states each octet so that the file parses back to the same line, and the
// sources name it in the same text as the line, with nothing to print raw.
func TestSnapshotNSLineStatesHostileNames(t *testing.T) {
	hostile := nslHostile(t)
	var hundred []dnswire.Name
	for i := range 100 {
		hundred = append(hundred, expName(t, fmt.Sprintf("n%03d\\027.attacker.example.", i)))
	}
	evilServer, err := dnswire.NameFromLabels([]string{"ns2\x1b]0;title\x07", "corp", "test"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name   string
		names  []dnswire.Name
		server dnswire.Name
	}{
		{"one of each hostile octet", hostile, expName(t, "ns2.corp.test.")},
		{"each name alone", hostile[:1], expName(t, "ns2.corp.test.")},
		{"a hundred names", hundred, expName(t, "ns2.corp.test.")},
		{"from a server whose own name is hostile", hostile, evilServer},
	} {
		t.Run(c.name, func(t *testing.T) {
			lie := obs.Answer{Proof: obs.Proof{Server: obs.Server{Name: c.server, Addr: netip.MustParseAddrPort(expNS2Addr)}}, Result: nslNames(c.names)}
			observations := []obs.Observation{nslDelegation(t, nslParent(t, 1, 2)), nslApex(t, nslGives(t, 1, 1, 2), lie)}
			f, skips := expSnapshot(t, observations...)
			e, ok := f.Find(expName(t, "corp.test."), dnswire.TypeNS)
			if !ok || len(e.Sets) != 2 || len(skips) != 0 {
				t.Fatalf("NS line %v, skips %q; want a line of two sets\n%q", ok, skips, f.String())
			}
			text := f.String()
			if !nslPrintable(text) {
				t.Errorf("the file holds an octet that is not printable:\n%q", text)
			}
			if strings.Count(text, "\n") != len(f.Expectations)+1 {
				t.Errorf("the file has %d line ends for %d lines:\n%q", strings.Count(text, "\n"), len(f.Expectations)+1, text)
			}
			g := expParse(t, text)
			if g.String() != text {
				t.Errorf("the file %q parses again as %q", text, g.String())
			}
			parsed, _ := g.Find(expName(t, "corp.test."), dnswire.TypeNS)
			if set, _ := expAnswerSet(lie); !parsed.Match(set) {
				t.Errorf("the parsed line %q does not hold the set that the server gave", parsed.String())
			}
			sources := NSSources(expName(t, "corp.test."), observations)
			var texts []string
			for _, s := range sources {
				texts = append(texts, s.Text)
				for _, part := range slices.Concat([]string{s.Text}, s.Parent, s.Zone) {
					if !nslPrintable(part) || strings.Contains(part, "\n") {
						t.Errorf("a source holds an octet to print raw: %q", part)
					}
				}
			}
			if got := strings.Join(texts, " || "); got != e.FormText() {
				t.Errorf("the sources read %q; the line reads %q", got, e.FormText())
			}
		})
	}
}

// The same answers in another order, and a second run, give the same file
// octet for octet, and the sets in the same order.
func TestSnapshotNSLineDoesNotDependOnTheOrderOfTheAnswers(t *testing.T) {
	glue := func(addr string, ns ...int) obs.Answer {
		var set []dnswire.Record
		for _, h := range nslSet(ns...) {
			set = append(set, expRecord(t, "corp.test.", dnswire.TypeNS, h))
		}
		r := obs.RecordsResult(obs.Records{Set: set, Glue: []dnswire.Record{
			expRecord(t, "ns1.corp.test.", dnswire.TypeA, "10.53.0.11"), expRecord(t, "ns2.corp.test.", dnswire.TypeA, "10.53.0.12")}})
		return expAnswer(t, "ns.test.", addr, r)
	}
	both := func(name string, typ dnswire.Type, r obs.Result) obs.Observation {
		return expObs(t, expRecordsKey(t, name, typ), "corp.test.", nslAt(t, 1, r), nslAt(t, 2, r), nslAt(t, 3, r))
	}
	base := []obs.Observation{
		nslDelegation(t, glue(expParentAddr, 1, 2), glue(nslParent2Addr, 2, 1, 3)),
		nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2, 3), nslGives(t, 3, 2), nslAt(t, 3, expFailure(obs.ReasonTimeout))),
		both("ns1.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "ns1.corp.test.", "10.53.0.11")),
		both("ns2.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "ns2.corp.test.", "10.53.0.12")),
		both("ns1.corp.test.", dnswire.TypeAAAA, expNoData(t, "corp.test.")),
		both("ns2.corp.test.", dnswire.TypeAAAA, expNoName(t, "corp.test.")),
	}
	want, _ := expSnapshot(t, base...)
	wantSources := NSSources(expName(t, "corp.test."), base)
	if len(wantSources) != 3 || nslNSLine(want) == "" {
		t.Fatalf("test fault: the base gives %d sets and the file\n%s", len(wantSources), want.String())
	}
	rng := rand.New(rand.NewPCG(expSeed, 7))
	for i := range 200 {
		shuffled := expShuffled(rng, base)
		for j := range shuffled {
			shuffled[j].Answers = expShuffled(rng, shuffled[j].Answers)
		}
		f, _ := expSnapshot(t, shuffled...)
		if f.String() != want.String() {
			t.Fatalf("seed %d case %d: the file\n%s\nwant, as for the answers in their first order:\n%s", expSeed, i, f.String(), want.String())
		}
		sources := NSSources(expName(t, "corp.test."), shuffled)
		if len(sources) != len(wantSources) {
			t.Fatalf("seed %d case %d: %d sets; want %d", expSeed, i, len(sources), len(wantSources))
		}
		for k, s := range sources {
			w := wantSources[k]
			if s.Text != w.Text || !slices.Equal(slices.Sorted(slices.Values(s.Parent)), slices.Sorted(slices.Values(w.Parent))) ||
				!slices.Equal(slices.Sorted(slices.Values(s.Zone)), slices.Sorted(slices.Values(w.Zone))) {
				t.Fatalf("seed %d case %d: set %d is %#v; want %#v", expSeed, i, k, s, w)
			}
		}
	}
}

// --- the address lines of the nameserver hosts and the glue ---

// nslHostChecks are the checks of the addresses of ns1 and ns2.corp.test.:
// ns1 has 10.53.0.11 and no IPv6 address, ns2 has 10.53.0.12 and fd53::12.
func nslHostChecks(t testing.TB) []obs.Observation {
	both := func(name string, typ dnswire.Type, r obs.Result) obs.Observation {
		return expObs(t, expRecordsKey(t, name, typ), "corp.test.", nslAt(t, 1, r), nslAt(t, 2, r))
	}
	return []obs.Observation{
		both("ns1.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "ns1.corp.test.", "10.53.0.11")),
		both("ns1.corp.test.", dnswire.TypeAAAA, expNoData(t, "corp.test.")),
		both("ns2.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "ns2.corp.test.", "10.53.0.12")),
		both("ns2.corp.test.", dnswire.TypeAAAA, expRecords(t, dnswire.TypeAAAA, "ns2.corp.test.", "fd53::12")),
	}
}

// nslGlued is the parent's answer of {ns1, ns2} with the glue records given
// as "<host> <TYPE> <data>".
func nslGlued(t testing.TB, host, addr string, glue ...string) obs.Answer {
	var g []dnswire.Record
	for _, x := range glue {
		f := strings.Fields(x)
		typ, err := dnswire.ParseType(f[1])
		if err != nil {
			t.Fatal(err)
		}
		g = append(g, expRecord(t, f[0], typ, f[2]))
	}
	set := []dnswire.Record{expRecord(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test."), expRecord(t, "corp.test.", dnswire.TypeNS, "ns2.corp.test.")}
	return expAnswer(t, host, addr, obs.RecordsResult(obs.Records{Set: set, Glue: g}))
}

// The address lines of a host stay only when the glue at the parent zone is
// what they allow, so that the delegation check of a new file finds nothing.
// Both lines of a host go, because glue of a type with no line differs too.
func TestSnapshotDropsTheAddressLinesOfAHostWhoseGlueDiffers(t *testing.T) {
	ns1 := []string{"ns1.corp.test. A 10.53.0.11", "ns1.corp.test. AAAA none"}
	ns2 := []string{"ns2.corp.test. A 10.53.0.12", "ns2.corp.test. AAAA fd53::12"}
	good := []string{"ns1.corp.test. A 10.53.0.11", "ns2.corp.test. A 10.53.0.12", "ns2.corp.test. AAAA fd53::12"}
	other := func(server, host string, what string) []string {
		why := ": the parent zone gives other glue: " + server + " gives " + what
		return []string{host + " A" + why, host + " AAAA" + why}
	}
	for _, c := range []struct {
		name   string
		parent []obs.Answer
		lines  []string // the host lines that stay
		skips  []string
	}{
		{"glue as the hosts answer", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr, good...)}, slices.Concat(ns1, ns2), nil},
		{"no glue", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr)}, slices.Concat(ns1, ns2), nil},
		{"another address of ns2", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr, good[0], "ns2.corp.test. A 10.53.0.99", good[2])},
			ns1, other(nslP, "ns2.corp.test.", "A 10.53.0.99")},
		{"one more address of ns1", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr, good[0], "ns1.corp.test. A 10.53.0.66", good[1], good[2])},
			ns2, other(nslP, "ns1.corp.test.", "A 10.53.0.11 | 10.53.0.66")},
		{"IPv6 glue of a host whose line is none", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr, good[0], "ns1.corp.test. AAAA fd53::66", good[1], good[2])},
			ns2, other(nslP, "ns1.corp.test.", "AAAA fd53::66")},
		{"a second parent server with other glue", []obs.Answer{nslGlued(t, "ns.test.", expParentAddr, good...),
			nslGlued(t, "ns2.test.", nslParent2Addr, good[0], "ns2.corp.test. A 10.53.0.99", good[2])},
			ns1, other(nslP2, "ns2.corp.test.", "A 10.53.0.99")},
	} {
		t.Run(c.name, func(t *testing.T) {
			observations := slices.Concat([]obs.Observation{nslDelegation(t, c.parent...), nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))},
				nslHostChecks(t))
			f, skips := expSnapshot(t, observations...)
			want := "domain corp.test.\ncorp.test. NS " + nslText(1, 2) + "\n" + strings.Join(c.lines, "\n") + "\n"
			if f.String() != want {
				t.Errorf("the file\n%s\nwant:\n%s", f.String(), want)
			}
			if !slices.Equal(skips, c.skips) {
				t.Errorf("skips %q; want %q", skips, c.skips)
			}
			nslGlueMatches(t, f, observations)
		})
	}
}

// nslGlueMatches judges the glue of each delegation answer as the delegation
// check does: each group of a host that has an address line must match the
// line of its type.
func nslGlueMatches(t *testing.T, f *File, observations []obs.Observation) {
	t.Helper()
	for _, o := range observations {
		if o.Key.Kind != obs.KindDelegation {
			continue
		}
		for _, a := range o.Answers {
			glue := glueOf(a)
			for _, r := range glue {
				_, hasA := f.Find(r.Name, dnswire.TypeA)
				_, hasAAAA := f.Find(r.Name, dnswire.TypeAAAA)
				if !hasA && !hasAAAA {
					continue
				}
				group := slices.DeleteFunc(slices.Clone(glue), func(x dnswire.Record) bool { return x.Type() != r.Type() || !x.Name.Equal(r.Name) })
				if e, ok := f.Find(r.Name, r.Type()); !ok || !e.Match(group) {
					t.Errorf("glue %s %s of %s is not what the file allows", r.Name, SetText(r.Type(), group), serverText(a.Server))
				}
			}
		}
	}
}

// The lines of the file are in the order of the checks until the end, so a
// host whose address check comes first has the first line. That line goes
// as well when the glue differs: kept, it would give the glue alert at the
// first check.
func TestSnapshotDropsTheFirstLineOfTheFileWhenItsGlueDiffers(t *testing.T) {
	observations := slices.Concat(nslHostChecks(t), []obs.Observation{
		nslDelegation(t, nslGlued(t, "ns.test.", expParentAddr, "ns1.corp.test. A 10.53.0.99", "ns2.corp.test. A 10.53.0.12")),
		nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))})
	if observations[0].Key.Name.String() != "ns1.corp.test." || observations[0].Key.Type != dnswire.TypeA {
		t.Fatalf("test fault: the first check is %s", observations[0].Key)
	}
	f, skips := expSnapshot(t, observations...)
	want := "domain corp.test.\ncorp.test. NS " + nslText(1, 2) + "\nns2.corp.test. A 10.53.0.12\nns2.corp.test. AAAA fd53::12\n"
	if f.String() != want {
		t.Errorf("the file\n%s\nwant:\n%s", f.String(), want)
	}
	why := ": the parent zone gives other glue: " + nslP + " gives A 10.53.0.99"
	if wantSkips := []string{"ns1.corp.test. A" + why, "ns1.corp.test. AAAA" + why}; !slices.Equal(skips, wantSkips) {
		t.Errorf("skips %q; want %q", skips, wantSkips)
	}
	nslGlueMatches(t, f, observations)
}

// A host whose address of one type has no agreed answer gets no line of that
// type. Glue of that type at the parent then has no line to be compared
// with, so the other line of the host goes too, and the reason says so. Glue
// of a type the host has a line for is compared as usual.
func TestSnapshotDropsTheOtherAddressLineOfAHostWhoseAnswerFailed(t *testing.T) {
	unread := func(host, t string) string {
		return host + " " + map[string]string{"A": "AAAA", "AAAA": "A"}[t] + ": the " + t +
			" address of the host could not be read, so its glue at the parent zone cannot be compared"
	}
	failed := func(name string, typ dnswire.Type) obs.Observation {
		return expObs(t, expRecordsKey(t, name, typ), "corp.test.",
			nslAt(t, 1, expFailure(obs.ReasonTimeout)), nslAt(t, 2, expFailure(obs.ReasonTimeout)))
	}
	glueA := []string{"ns1.corp.test. A 10.53.0.11", "ns2.corp.test. A 10.53.0.12"}
	for _, c := range []struct {
		name  string
		host  int // the check of nslHostChecks to replace
		by    obs.Observation
		glue  []string
		lines []string // the host lines that stay
		skips []string
	}{
		{"an A answer that failed", 0, failed("ns1.corp.test.", dnswire.TypeA), glueA,
			[]string{"ns2.corp.test. A 10.53.0.12", "ns2.corp.test. AAAA fd53::12"},
			[]string{"ns1.corp.test. A: " + nslC1 + " gave no answer (timeout)", unread("ns1.corp.test.", "A")}},
		{"A answers that differ", 0, expObs(t, expRecordsKey(t, "ns1.corp.test.", dnswire.TypeA), "corp.test.",
			nslAt(t, 1, expRecords(t, dnswire.TypeA, "ns1.corp.test.", "10.53.0.11")),
			nslAt(t, 2, expRecords(t, dnswire.TypeA, "ns1.corp.test.", "10.53.0.66"))), glueA,
			[]string{"ns2.corp.test. A 10.53.0.12", "ns2.corp.test. AAAA fd53::12"},
			[]string{"ns1.corp.test. A: servers disagree: " + nslC1 + " gives 10.53.0.11; " + nslC2 + " gives 10.53.0.66",
				unread("ns1.corp.test.", "A")}},
		{"an AAAA answer that failed, no IPv6 glue", 3, failed("ns2.corp.test.", dnswire.TypeAAAA), glueA,
			[]string{"ns1.corp.test. A 10.53.0.11", "ns1.corp.test. AAAA none", "ns2.corp.test. A 10.53.0.12"},
			[]string{"ns2.corp.test. AAAA: " + nslC1 + " gave no answer (timeout)"}},
		{"an AAAA answer that failed, IPv6 glue", 3, failed("ns2.corp.test.", dnswire.TypeAAAA),
			append(slices.Clone(glueA), "ns2.corp.test. AAAA fd53::12"),
			[]string{"ns1.corp.test. A 10.53.0.11", "ns1.corp.test. AAAA none"},
			[]string{unread("ns2.corp.test.", "AAAA"), "ns2.corp.test. AAAA: " + nslC1 + " gave no answer (timeout)"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			hosts := nslHostChecks(t)
			hosts[c.host] = c.by
			observations := slices.Concat([]obs.Observation{
				nslDelegation(t, nslGlued(t, "ns.test.", expParentAddr, c.glue...)),
				nslApex(t, nslGives(t, 1, 1, 2), nslGives(t, 2, 1, 2))}, hosts)
			f, skips := expSnapshot(t, observations...)
			want := "domain corp.test.\ncorp.test. NS " + nslText(1, 2) + "\n" + strings.Join(c.lines, "\n") + "\n"
			if f.String() != want {
				t.Errorf("the file\n%s\nwant:\n%s", f.String(), want)
			}
			if !slices.Equal(skips, c.skips) {
				t.Errorf("skips %q; want %q", skips, c.skips)
			}
			nslGlueMatches(t, f, observations)
		})
	}
}
