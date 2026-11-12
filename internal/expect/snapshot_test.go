package expect

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	expParentAddr = "10.53.0.3:53"
	expNS1Addr    = "10.53.0.11:53"
	expNS2Addr    = "10.53.0.12:53"
)

// expAnswer is the answer of one server; an empty host or address leaves
// that part of the server zero.
func expAnswer(t testing.TB, host, addr string, r obs.Result) obs.Answer {
	t.Helper()
	var s obs.Server
	if host != "" {
		s.Name = expName(t, host)
	}
	if addr != "" {
		s.Addr = netip.MustParseAddrPort(addr)
	}
	return obs.Answer{Proof: obs.Proof{Server: s}, Result: r}
}

func expRecords(t testing.TB, typ dnswire.Type, owner string, data ...string) obs.Result {
	t.Helper()
	var set []dnswire.Record
	for _, d := range data {
		set = append(set, expRecord(t, owner, typ, d))
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

func expSOA(t testing.TB, zone string) dnswire.Record {
	t.Helper()
	return expRecord(t, zone, dnswire.TypeSOA, "ns1."+zone+" hostmaster."+zone+" 1 3600 600 86400 300")
}

func expNoData(t testing.TB, zone string) obs.Result {
	t.Helper()
	return obs.NoDataResult(obs.NoData{SOA: expSOA(t, zone)})
}

func expNoName(t testing.TB, zone string) obs.Result {
	t.Helper()
	return obs.NoNameResult(obs.NoName{SOA: expSOA(t, zone)})
}

func expFailure(reason obs.Reason) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: reason, Detail: "detail for people"})
}

func expObs(t testing.TB, key obs.Key, zone string, answers ...obs.Answer) obs.Observation {
	t.Helper()
	return obs.Observation{Key: key, Zone: expName(t, zone), Answers: answers}
}

// expFailedWalk is what observe gives when the walk from the root failed:
// one answer from a zero server, and the root as zone.
func expFailedWalk(key obs.Key) obs.Observation {
	return obs.Observation{Key: key, Answers: []obs.Answer{{Result: expFailure(obs.ReasonWalk)}}}
}

func expRecordsKey(t testing.TB, name string, typ dnswire.Type) obs.Key {
	t.Helper()
	return obs.RecordsKey(expName(t, "corp.test."), expName(t, name), typ)
}

// expSkipTexts gives each skip as "<name> <TYPE>: <why>".
func expSkipTexts(skips []Skip) []string {
	var s []string
	for _, k := range skips {
		s = append(s, k.Name.Lower().String()+" "+k.Type.String()+": "+k.Why)
	}
	return s
}

func expSnapshot(t testing.TB, observations ...obs.Observation) (*File, []string) {
	t.Helper()
	f, skips := Snapshot(expName(t, "corp.test."), observations)
	if f == nil {
		t.Fatal("Snapshot gave no file")
	}
	if !f.Domain.Equal(expName(t, "corp.test.")) {
		t.Errorf("Snapshot file domain %v; want corp.test.", f.Domain)
	}
	return f, expSkipTexts(skips)
}

func expApexNS(t testing.TB, host, addr string, hosts ...string) obs.Answer {
	t.Helper()
	return expAnswer(t, host, addr, expRecords(t, dnswire.TypeNS, "corp.test.", hosts...))
}

func TestSnapshotAgreement(t *testing.T) {
	d := expName(t, "corp.test.")
	parentNS := obs.RecordsResult(obs.Records{
		Set:  []dnswire.Record{expRecord(t, "corp.test.", dnswire.TypeNS, "ns2.corp.test."), expRecord(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.")},
		Glue: []dnswire.Record{expRecord(t, "ns1.corp.test.", dnswire.TypeA, "10.53.0.11"), expRecord(t, "ns2.corp.test.", dnswire.TypeA, "10.53.0.12")},
	})
	// The same set from the second server: other order, case and TTL.
	ns2Set := []dnswire.Record{expRecord(t, "CORP.test.", dnswire.TypeNS, "NS2.Corp.Test."), expRecord(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.")}
	ns2Set[0].TTL = 7
	f, skips := expSnapshot(t,
		expObs(t, obs.DelegationKey(d), "test.", expAnswer(t, "ns.test.", expParentAddr, parentNS)),
		expObs(t, obs.DSKey(d), "test.", expAnswer(t, "ns.test.", expParentAddr, expNoData(t, "test."))),
		expObs(t, expRecordsKey(t, "corp.test.", dnswire.TypeNS), "corp.test.",
			expApexNS(t, "ns1.corp.test.", expNS1Addr, "ns1.corp.test.", "ns2.corp.test."),
			expAnswer(t, "ns2.corp.test.", expNS2Addr, obs.RecordsResult(obs.Records{Set: ns2Set}))),
		expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeA), "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.81")),
			expAnswer(t, "ns2.corp.test.", expNS2Addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.81"))),
	)
	want := "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\nwww.corp.test. A 10.53.0.81\n"
	if got := f.String(); got != want {
		t.Errorf("String():\n%s\nwant:\n%s", got, want)
	}
	if len(skips) != 0 {
		t.Errorf("skips %q; want none", skips)
	}
	for _, e := range f.Expectations {
		if e.Line != 0 {
			t.Errorf("%s has Line %d; want 0, it was not read from text", e.String(), e.Line)
		}
	}
	if e, ok := f.Find(d, dnswire.TypeDS); !ok || e.Form != FormNone {
		t.Errorf("DS expectation %v, %v; want the form none", e, ok)
	}
	if e, ok := f.Find(d, dnswire.TypeNS); !ok || e.Form != FormSets {
		t.Errorf("NS expectation %v, %v; want the exact form", e, ok)
	}
}

// No data and no such name both read as no records, so they agree.
func TestSnapshotNegativeAnswersAreNone(t *testing.T) {
	f, skips := expSnapshot(t, expObs(t, expRecordsKey(t, "gone.corp.test.", dnswire.TypeA), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expNoName(t, "corp.test.")),
		expAnswer(t, "ns2.corp.test.", expNS2Addr, expNoData(t, "corp.test."))))
	if want := "domain corp.test.\ngone.corp.test. A none\n"; f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

func TestSnapshotSetOfSeveralRecords(t *testing.T) {
	f, skips := expSnapshot(t, expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeA), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.82", "10.53.0.81")),
		expAnswer(t, "ns2.corp.test.", expNS2Addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.81", "10.53.0.82"))))
	if want := "domain corp.test.\nwww.corp.test. A 10.53.0.81 | 10.53.0.82\n"; f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

func expManyA(t testing.TB, n int) obs.Result {
	t.Helper()
	var data []string
	for i := range n {
		data = append(data, expAddr4(i))
	}
	return expRecords(t, dnswire.TypeA, "big.corp.test.", data...)
}

func TestSnapshotRecordLimit(t *testing.T) {
	key := expRecordsKey(t, "big.corp.test.", dnswire.TypeA)
	f, skips := expSnapshot(t, expObs(t, key, "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expManyA(t, 1000)), expAnswer(t, "ns2.corp.test.", expNS2Addr, expManyA(t, 1000))))
	if e, ok := f.Find(key.Name, dnswire.TypeA); !ok || len(e.Sets) != 1 || len(e.Sets[0]) != 1000 || len(skips) != 0 {
		t.Errorf("1000 records: %v, skips %q; want a line of 1000 records", ok, skips)
	}
	f, skips = expSnapshot(t, expObs(t, key, "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expManyA(t, 1001)), expAnswer(t, "ns2.corp.test.", expNS2Addr, expManyA(t, 1001))))
	if _, ok := f.Find(key.Name, dnswire.TypeA); ok || !slices.Equal(skips, []string{"big.corp.test. A: more than 1000 records"}) {
		t.Errorf("1001 records: line %v, skips %q; want only the skip", ok, skips)
	}
}

func TestSnapshotSkips(t *testing.T) {
	www := expRecordsKey(t, "www.corp.test.", dnswire.TypeA)
	at := func(host, addr, data string) obs.Answer {
		return expAnswer(t, host, addr, expRecords(t, dnswire.TypeA, "www.corp.test.", data))
	}
	for _, c := range []struct {
		name string
		obs  []obs.Observation
		want string
	}{
		{"a server that timed out", []obs.Observation{expObs(t, www, "corp.test.",
			at("ns1.corp.test.", expNS1Addr, "10.53.0.81"),
			expAnswer(t, "NS2.Corp.Test.", expNS2Addr, expFailure(obs.ReasonTimeout)))},
			"www.corp.test. A: 10.53.0.12:53 ns2.corp.test. gave no answer: timeout"},
		{"a query the deadline stopped", []obs.Observation{expObs(t, www, "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expFailure(obs.ReasonDeadline)))},
			"www.corp.test. A: 10.53.0.11:53 ns1.corp.test. gave no answer: deadline"},
		{"a host without an address", []obs.Observation{expObs(t, www, "corp.test.",
			at("ns1.corp.test.", expNS1Addr, "10.53.0.81"),
			expAnswer(t, "ns3.corp.test.", "", expFailure(obs.ReasonWalk)))},
			"www.corp.test. A: - ns3.corp.test. gave no answer: walk"},
		{"a failed walk", []obs.Observation{expFailedWalk(www)},
			"www.corp.test. A: - - gave no answer: walk"},
		{"an answer of another type", []obs.Observation{expObs(t, www, "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeCNAME, "www.corp.test.", "web.dnshost.test.")),
			expAnswer(t, "ns2.corp.test.", expNS2Addr, expRecords(t, dnswire.TypeCNAME, "www.corp.test.", "web.dnshost.test.")))},
			"www.corp.test. A: 10.53.0.11:53 ns1.corp.test. answers with a CNAME record; snapshot www.corp.test. CNAME instead"},
		{"servers that disagree", []obs.Observation{expObs(t, www, "corp.test.",
			at("ns1.corp.test.", expNS1Addr, "10.53.0.81"), at("ns2.corp.test.", expNS2Addr, "10.53.0.99"))},
			"www.corp.test. A: servers disagree: 10.53.0.11:53 ns1.corp.test. gives 10.53.0.81; 10.53.0.12:53 ns2.corp.test. gives 10.53.0.99"},
		{"no data against records", []obs.Observation{expObs(t, www, "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expNoData(t, "corp.test.")), at("ns2.corp.test.", expNS2Addr, "10.53.0.99"))},
			"www.corp.test. A: servers disagree: 10.53.0.11:53 ns1.corp.test. gives none; 10.53.0.12:53 ns2.corp.test. gives 10.53.0.99"},
		{"two checks of one set that disagree", []obs.Observation{
			expObs(t, www, "corp.test.", at("ns1.corp.test.", expNS1Addr, "10.53.0.81")),
			expObs(t, www, "corp.test.", at("ns2.corp.test.", expNS2Addr, "10.53.0.99"))},
			"www.corp.test. A: servers disagree: 10.53.0.11:53 ns1.corp.test. gives 10.53.0.81; 10.53.0.12:53 ns2.corp.test. gives 10.53.0.99"},
		{"parent and apex NS sets that differ", []obs.Observation{
			expObs(t, obs.DelegationKey(expName(t, "corp.test.")), "test.",
				expAnswer(t, "ns.test.", expParentAddr, expRecords(t, dnswire.TypeNS, "corp.test.", "ns1.corp.test.", "ns2.corp.test."))),
			expObs(t, expRecordsKey(t, "corp.test.", dnswire.TypeNS), "corp.test.",
				expApexNS(t, "ns1.corp.test.", expNS1Addr, "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."),
				expApexNS(t, "ns2.corp.test.", expNS2Addr, "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."))},
			"corp.test. NS: servers disagree: 10.53.0.3:53 ns.test. gives ns1.corp.test. | ns2.corp.test.; 10.53.0.11:53 ns1.corp.test. gives ns1.corp.test. | ns2.corp.test. | ns3.corp.test."},
		{"a name in a subzone without its NS pair", []obs.Observation{
			expObs(t, expRecordsKey(t, "www.sub.corp.test.", dnswire.TypeA), "sub.corp.test.",
				expAnswer(t, "ns1.sub.corp.test.", "10.53.0.13:53", expRecords(t, dnswire.TypeA, "www.sub.corp.test.", "10.53.0.90")))},
			"www.sub.corp.test. A: lies in zone sub.corp.test.; add the pair sub.corp.test. NS"},
		{"a cut that a server invents", []obs.Observation{expObs(t, www, "www.corp.test.",
			at("ns1.corp.test.", expNS1Addr, "10.53.0.81"), at("ns2.corp.test.", expNS2Addr, "10.53.0.81"))},
			"www.corp.test. A: lies in zone www.corp.test.; add the pair www.corp.test. NS"},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, c.obs...)
			if !slices.Equal(skips, []string{c.want}) {
				t.Errorf("skips %q; want [%q]", skips, c.want)
			}
			if len(f.Expectations) != 0 {
				t.Errorf("the file holds %q; want no line", f.String())
			}
		})
	}
}

// A delegation or ds check asks the parent zone, so its zone is never the
// domain, and it keeps its line.
func TestSnapshotParentChecksKeepTheirLine(t *testing.T) {
	d := expName(t, "corp.test.")
	f, skips := expSnapshot(t,
		expObs(t, obs.DelegationKey(d), "test.",
			expAnswer(t, "ns.test.", expParentAddr, expRecords(t, dnswire.TypeNS, "corp.test.", "ns1.corp.test.", "ns2.corp.test."))),
		expObs(t, obs.DSKey(d), "test.",
			expAnswer(t, "ns.test.", expParentAddr, expRecords(t, dnswire.TypeDS, "corp.test.", "12345 13 2 "+strings.Repeat("AB", 32)))))
	want := "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS 12345 13 2 " + strings.Repeat("AB", 32) + "\n"
	if f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

func TestSnapshotSubzoneWithItsNSPair(t *testing.T) {
	f, skips := expSnapshot(t,
		expObs(t, expRecordsKey(t, "www.sub.corp.test.", dnswire.TypeA), "sub.corp.test.",
			expAnswer(t, "ns1.sub.corp.test.", "10.53.0.13:53", expRecords(t, dnswire.TypeA, "www.sub.corp.test.", "10.53.0.90"))),
		expObs(t, expRecordsKey(t, "sub.corp.test.", dnswire.TypeNS), "sub.corp.test.",
			expAnswer(t, "ns1.sub.corp.test.", "10.53.0.13:53", expRecords(t, dnswire.TypeNS, "sub.corp.test.", "ns1.sub.corp.test."))))
	want := "domain corp.test.\nsub.corp.test. NS ns1.sub.corp.test.\nwww.sub.corp.test. A 10.53.0.90\n"
	if f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

// Outside the domain nothing tells which zone is right, so the zone of the
// check does not count.
func TestSnapshotNameOutsideTheDomain(t *testing.T) {
	f, skips := expSnapshot(t, expObs(t, expRecordsKey(t, "mail.other.test.", dnswire.TypeA), "other.test.",
		expAnswer(t, "ns.other.test.", "10.53.0.20:53", expRecords(t, dnswire.TypeA, "mail.other.test.", "10.53.0.25"))))
	if want := "domain corp.test.\nmail.other.test. A 10.53.0.25\n"; f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

func TestSnapshotIgnoresSerialAndOtherKinds(t *testing.T) {
	d := expName(t, "corp.test.")
	soa := obs.RecordsResult(obs.Records{Set: []dnswire.Record{expSOA(t, "corp.test.")}})
	other := expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeA), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.81")))
	other.Key.Kind = 9
	f, skips := expSnapshot(t,
		expObs(t, obs.SerialKey(d), "corp.test.", expAnswer(t, "ns1.corp.test.", expNS1Addr, soa)),
		expObs(t, obs.SerialKey(d), "corp.test.", expAnswer(t, "ns2.corp.test.", expNS2Addr, expFailure(obs.ReasonTimeout))),
		other)
	if len(f.Expectations) != 0 || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want no line and no skip", f.String(), skips)
	}
}

func expTimedOut(t testing.TB, name string, typ dnswire.Type) obs.Observation {
	t.Helper()
	return expObs(t, expRecordsKey(t, name, typ), "corp.test.", expAnswer(t, "ns1.corp.test.", expNS1Addr, expFailure(obs.ReasonTimeout)))
}

func TestSnapshotSkipsSortedByType(t *testing.T) {
	_, skips := expSnapshot(t,
		expTimedOut(t, "corp.test.", dnswire.TypeAAAA),
		expTimedOut(t, "corp.test.", dnswire.TypeTXT),
		expTimedOut(t, "corp.test.", dnswire.TypeMX),
		expTimedOut(t, "corp.test.", dnswire.TypeA))
	const why = ": 10.53.0.11:53 ns1.corp.test. gave no answer: timeout"
	want := []string{"corp.test. A" + why, "corp.test. MX" + why, "corp.test. TXT" + why, "corp.test. AAAA" + why}
	if !slices.Equal(skips, want) {
		t.Errorf("skips %q; want %q", skips, want)
	}
}

// Names sort in canonical name order, as the lines of the file do.
func TestSnapshotSkipsSortedByName(t *testing.T) {
	_, skips := expSnapshot(t,
		expTimedOut(t, "www.corp.test.", dnswire.TypeA),
		expTimedOut(t, "a.corp.test.", dnswire.TypeA),
		expTimedOut(t, "corp.test.", dnswire.TypeA))
	const why = " A: 10.53.0.11:53 ns1.corp.test. gave no answer: timeout"
	want := []string{"corp.test." + why, "a.corp.test." + why, "www.corp.test." + why}
	if !slices.Equal(skips, want) {
		t.Errorf("skips %q; want %q", skips, want)
	}
}

// --- TestSnapshotInvariant ---

// expCandidate is one set that a generated snapshot may observe.
type expCandidate struct {
	key     obs.Key
	zones   []string // the right zone first
	servers [][2]string
	pool    []string
	none    bool // the set may be empty
}

func expCandidates(t testing.TB) []expCandidate {
	d := expName(t, "corp.test.")
	parents := [][2]string{{"ns.test.", expParentAddr}, {"ns2.test.", "10.53.0.4:53"}}
	corp := [][2]string{{"ns1.corp.test.", expNS1Addr}, {"ns2.corp.test.", expNS2Addr}}
	sub := [][2]string{{"ns1.sub.corp.test.", "10.53.0.13:53"}, {"ns2.sub.corp.test.", "10.53.0.14:53"}}
	apex := []string{"ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."}
	addrs := []string{"10.53.0.81", "10.53.0.82", "10.53.0.83"}
	return []expCandidate{
		{obs.DelegationKey(d), []string{"test."}, parents, apex, false},
		{obs.DSKey(d), []string{"test."}, parents, []string{"12345 13 2 " + strings.Repeat("AB", 32), "54321 8 1 " + strings.Repeat("CD", 20)}, true},
		{expRecordsKey(t, "corp.test.", dnswire.TypeNS), []string{"corp.test."}, corp, apex, false},
		{expRecordsKey(t, "www.corp.test.", dnswire.TypeA), []string{"corp.test.", "www.corp.test."}, corp, addrs, true},
		{expRecordsKey(t, "corp.test.", dnswire.TypeMX), []string{"corp.test."}, corp, []string{"10 mail.corp.test.", "20 mx.other.test."}, true},
		{expRecordsKey(t, "sub.corp.test.", dnswire.TypeNS), []string{"sub.corp.test."}, sub, []string{"ns1.sub.corp.test.", "ns2.sub.corp.test."}, false},
		{expRecordsKey(t, "www.sub.corp.test.", dnswire.TypeA), []string{"sub.corp.test.", "corp.test."}, sub, addrs, true},
		{expRecordsKey(t, "mail.other.test.", dnswire.TypeA), []string{"other.test."}, [][2]string{{"ns.other.test.", "10.53.0.20:53"}}, addrs, true},
		{obs.SerialKey(d), []string{"corp.test."}, corp, []string{"ns1.corp.test. hostmaster.corp.test. 1 3600 600 86400 300"}, false},
	}
}

func expSetKey(name dnswire.Name, typ dnswire.Type) string { return name.Key() + "/" + typ.String() }

// expPickValue is the data of a set: 1 or 2 texts of the pool, or nil for
// no records.
func expPickValue(rng *rand.Rand, p expCandidate) []string {
	if p.none && rng.IntN(4) == 0 {
		return nil
	}
	return expShuffled(rng, p.pool)[:1+rng.IntN(min(2, len(p.pool)))]
}

// expValueResult gives a value as one server would: records in any order,
// case and TTL, or no data or no such name for no records.
func expValueResult(t testing.TB, rng *rand.Rand, typ dnswire.Type, owner string, value []string) obs.Result {
	if len(value) == 0 {
		if rng.IntN(2) == 0 {
			return expNoData(t, "corp.test.")
		}
		return expNoName(t, "corp.test.")
	}
	var set []dnswire.Record
	for _, v := range expShuffled(rng, value) {
		r := expRecord(t, owner, typ, v)
		r.Data = expFoldCase(rng, r.Data)
		r.TTL = rng.Uint32N(86400)
		set = append(set, r)
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

// expBadResult is an answer that breaks agreement, or may.
func expBadResult(t testing.TB, rng *rand.Rand, p expCandidate, owner string, value []string) obs.Result {
	switch rng.IntN(5) {
	case 0:
		return expFailure(expPick(rng, []obs.Reason{obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonLame, obs.ReasonDeadline, obs.ReasonServFail}))
	case 1:
		return expValueResult(t, rng, p.key.Type, owner, expPickValue(rng, p))
	case 2:
		return expRecords(t, dnswire.TypeCNAME, owner, "alias.other.test.")
	case 3:
		set := []dnswire.Record{expRecord(t, owner, dnswire.TypeTXT, `"stray"`)}
		for _, v := range value {
			set = append(set, expRecord(t, owner, p.key.Type, v))
		}
		return obs.RecordsResult(obs.Records{Set: set})
	}
	if len(value) == 0 {
		return expValueResult(t, rng, p.key.Type, owner, p.pool[:1])
	}
	return expValueResult(t, rng, p.key.Type, owner, nil)
}

func expGenObservations(t testing.TB, rng *rand.Rand, candidates []expCandidate) []obs.Observation {
	values := map[string][]string{}
	var out []obs.Observation
	for _, p := range candidates {
		k := expSetKey(p.key.Name, p.key.Type)
		if _, ok := values[k]; !ok {
			values[k] = expPickValue(rng, p)
		}
		for range expPick(rng, []int{0, 1, 1, 1, 1, 1, 2}) {
			if rng.IntN(12) == 0 {
				out = append(out, expFailedWalk(p.key))
				continue
			}
			zone := p.zones[0]
			if rng.IntN(5) == 0 {
				zone = expPick(rng, p.zones)
			}
			o := obs.Observation{Key: p.key, Zone: expName(t, zone)}
			owner := p.key.Name.String()
			for _, s := range p.servers {
				o.Answers = append(o.Answers, expAnswer(t, s[0], s[1], expValueResult(t, rng, p.key.Type, owner, values[k])))
			}
			if rng.IntN(3) == 0 {
				i := rng.IntN(len(o.Answers))
				o.Answers[i].Result = expBadResult(t, rng, p, owner, values[k])
			}
			out = append(out, o)
		}
	}
	return expShuffled(rng, out)
}

// expAnswerSet reads an answer: its records, none for no data or no such
// name, and ok false for a failure.
func expAnswerSet(a obs.Answer) (set []dnswire.Record, ok bool) {
	type read struct {
		set []dnswire.Record
		ok  bool
	}
	r := obs.Match(a.Result,
		func(r obs.Records) read { return read{r.Set, true} },
		func(obs.NoData) read { return read{nil, true} },
		func(obs.NoName) read { return read{nil, true} },
		func(obs.Failure) read { return read{nil, false} })
	return r.set, r.ok
}

func expWalkFailed(o obs.Observation) bool {
	return len(o.Answers) == 1 && o.Answers[0].Server.Name.LabelCount() == 0 && !o.Answers[0].Server.Addr.IsValid()
}

// expDeepestZone is the zone a name under domain must lie in: the deepest of
// domain and the given NS owners strictly under it that holds the name.
func expDeepestZone(domain dnswire.Name, cuts []dnswire.Name, name dnswire.Name) dnswire.Name {
	z := domain
	for _, c := range cuts {
		if c.IsSubdomainOf(domain) && !c.Equal(domain) && name.IsSubdomainOf(c) && c.LabelCount() > z.LabelCount() {
			z = c
		}
	}
	return z
}

type expGroup struct {
	name dnswire.Name
	typ  dnswire.Type
	obs  []obs.Observation
}

// expAgree applies the agreement rule: every answer a non-failure with
// records of the set's type only, all with the same canonical data, at most
// 1000 records. It gives whether they agree and whether the data is empty.
func expAgree(g *expGroup) (agree, empty bool) {
	var first map[string]bool
	for _, o := range g.obs {
		for _, a := range o.Answers {
			set, ok := expAnswerSet(a)
			if !ok || len(set) > 1000 || slices.ContainsFunc(set, func(r dnswire.Record) bool { return r.Type() != g.typ }) {
				return false, false
			}
			k := expKeys(set)
			if first == nil {
				first = k
			} else if !expSameKeys(first, k) {
				return false, false
			}
		}
	}
	return true, len(first) == 0
}

// expGroups groups observations by set, as the snapshot does: delegation
// with (domain, NS), ds with (domain, DS), records by (Name, Type).
func expGroups(observations []obs.Observation) []*expGroup {
	var groups []*expGroup
	byKey := map[string]*expGroup{}
	for _, o := range observations {
		if o.Key.Kind != obs.KindDelegation && o.Key.Kind != obs.KindDS && o.Key.Kind != obs.KindRecords {
			continue
		}
		k := expSetKey(o.Key.Name, o.Key.Type)
		g := byKey[k]
		if g == nil {
			g = &expGroup{name: o.Key.Name, typ: o.Key.Type}
			byKey[k] = g
			groups = append(groups, g)
		}
		g.obs = append(g.obs, o)
	}
	return groups
}

// expLineSets decides which sets get a line: those that agree, less the ones
// with a records check under the domain whose zone is not the expected zone
// of the NS lines that agree.
func expLineSets(domain dnswire.Name, groups []*expGroup) map[*expGroup]bool {
	lines := map[*expGroup]bool{}
	var cuts []dnswire.Name
	for _, g := range groups {
		agree, empty := expAgree(g)
		lines[g] = agree
		if agree && !empty && g.typ == dnswire.TypeNS {
			cuts = append(cuts, g.name)
		}
	}
	for _, g := range groups {
		for _, o := range g.obs {
			if o.Key.Kind == obs.KindRecords && o.Key.Name.IsSubdomainOf(domain) && !expWalkFailed(o) &&
				!o.Zone.Equal(expDeepestZone(domain, cuts, o.Key.Name)) {
				lines[g] = false
			}
		}
	}
	return lines
}

func TestSnapshotInvariant(t *testing.T) {
	rng := rand.New(rand.NewPCG(expSeed, 3))
	domain := expName(t, "corp.test.")
	candidates := expCandidates(t)
	var written, skipped int
	report := expFailer(t)
	for i := range 1000 {
		fail := func(format string, args ...any) {
			t.Helper()
			report(i, format, args...)
		}
		observations := expGenObservations(t, rng, candidates)
		f, skips := Snapshot(domain, observations)
		if f == nil {
			fail("Snapshot gave no file")
			continue
		}
		groups := expGroups(observations)
		lines := expLineSets(domain, groups)
		var cuts []dnswire.Name
		for _, e := range f.Expectations {
			if e.Type == dnswire.TypeNS && e.Form != FormNone {
				cuts = append(cuts, e.Name)
			}
		}
		lineCount := 0
		for _, g := range groups {
			e, found := f.Find(g.name, g.typ)
			isSkipped := slices.ContainsFunc(skips, func(s Skip) bool { return s.Name.Equal(g.name) && s.Type == g.typ })
			if found != lines[g] || isSkipped == lines[g] {
				fail("%s %v: line %v, skipped %v; want a line %v\nfile:\n%s\nskips %q", g.name, g.typ, found, isSkipped, lines[g], f.String(), expSkipTexts(skips))
				continue
			}
			if !found {
				continue
			}
			lineCount++
			// The invariant: a set that got a line gives no finding.
			for _, o := range g.obs {
				for _, a := range o.Answers {
					if set, ok := expAnswerSet(a); !ok || !e.Match(set) {
						fail("%s does not match %q from %v", e.String(), expRecordTexts(set), a.Server.Addr)
					}
				}
				if o.Key.Kind == obs.KindRecords && o.Key.Name.IsSubdomainOf(domain) && !o.Zone.Equal(expDeepestZone(domain, cuts, o.Key.Name)) {
					fail("%s got a line, but its check lies in zone %v", e.String(), o.Zone)
				}
			}
		}
		if len(f.Expectations) != lineCount || len(skips) != len(groups)-lineCount {
			fail("%d lines and %d skips for %d sets, %d of them with a line", len(f.Expectations), len(skips), len(groups), lineCount)
		}
		for _, s := range skips {
			if s.Why == "" {
				fail("skip of %v %v gives no reason", s.Name, s.Type)
			}
		}
		if g, err := Parse([]byte(f.String())); err != nil || g == nil || g.String() != f.String() {
			fail("the snapshot %q does not parse to itself: %v", f.String(), err)
		}
		written += lineCount
		skipped += len(groups) - lineCount
	}
	if !t.Failed() && (written < 500 || skipped < 500) {
		t.Errorf("test fault: %d lines and %d skips; both must come up often", written, skipped)
	}
}
