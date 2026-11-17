package expect

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

func TestEscapeBarsKeepsABackslashThatEndsTheText(t *testing.T) {
	for _, c := range []struct{ in, want string }{
		{`a|b\`, `a\|b\`},
		{`|\`, `\|\`},
		{`a\|b`, `a\|b`},
	} {
		if got := escapeBars(c.in); got != c.want {
			t.Errorf("escapeBars(%q) = %q; want %q", c.in, got, c.want)
		}
	}
}

func TestParseTakesTheRootAsALikePattern(t *testing.T) {
	f := expParse(t, "domain corp.test.\ncorp.test. MX like .\n")
	if got, want := f.String(), "domain corp.test.\ncorp.test. MX like .\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	e := f.Expectations[0]
	if !e.Match(expSet(t, dnswire.TypeMX, "0 .")) {
		t.Error("the pattern . does not match the root as exchange")
	}
	if e.Match(expSet(t, dnswire.TypeMX, "10 mail.corp.test.")) {
		t.Error("the pattern . matches another exchange")
	}
}

func TestParseKeepsABlankInsideQuotesInAField(t *testing.T) {
	f := expParse(t, "domain corp.test.\n\"a b\".corp.test. A 192.0.2.1\n")
	if len(f.Expectations) != 1 || f.Expectations[0].Type != dnswire.TypeA {
		t.Errorf("a blank inside quotes in the owner gave %d expectations; want the one A line", len(f.Expectations))
	}
}

func TestParseAcceptsTildeAndRejectsDelete(t *testing.T) {
	expParse(t, "domain corp.test.\nx~.corp.test. A 192.0.2.1\n")
	ps := expProblems(t, "domain corp.test.\nx\x7F.corp.test. A 192.0.2.1\n")
	if len(ps) != 1 || ps[0].Text != "octet 0x7F is not printable ASCII" {
		t.Errorf("a DEL octet gave %v; want the problem for octet 0x7F", ps)
	}
}

func TestSnapshotSortsItsLinesWhateverTheOrderOfTheObservations(t *testing.T) {
	both := func(name, addr string) obs.Observation {
		return expObs(t, expRecordsKey(t, name, dnswire.TypeA), "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeA, name, addr)))
	}
	f, _ := expSnapshot(t,
		both("www.corp.test.", "10.53.0.81"),
		both("api.corp.test.", "10.53.0.82"),
		expObs(t, expRecordsKey(t, "corp.test.", dnswire.TypeNS), "corp.test.", expApexNS(t, "ns1.corp.test.", expNS1Addr, "ns1.corp.test.")),
	)
	var got []string
	for _, e := range f.Expectations {
		got = append(got, e.String())
	}
	want := []string{"corp.test. NS ns1.corp.test.", "api.corp.test. A 10.53.0.82", "www.corp.test. A 10.53.0.81"}
	if !slices.Equal(got, want) {
		t.Errorf("Expectations = %q; want %q", got, want)
	}
}

func TestSnapshotIgnoresObservationsOfAnotherDomain(t *testing.T) {
	other := expName(t, "other.test.")
	key := obs.RecordsKey(other, expName(t, "www.other.test."), dnswire.TypeA)
	f, skips := expSnapshot(t, expObs(t, key, "other.test.",
		expAnswer(t, "ns1.other.test.", expNS1Addr, expRecords(t, dnswire.TypeA, "www.other.test.", "10.53.0.81"))))
	if len(f.Expectations) != 0 || len(skips) != 0 {
		t.Errorf("an observation of another domain gave %d lines and the skips %q; want none", len(f.Expectations), skips)
	}
}

// The line of x lies in a zone that the NS line of sub declares, so it stays
// while that NS line stands. The NS line goes because its own check ended in
// the parent zone, and then the zone that the file expects for x changes.
func TestSnapshotDropsALineWhoseZoneChangesWhenAnNSLineGoes(t *testing.T) {
	one := func(name string, typ dnswire.Type, zone, data string) obs.Observation {
		return expObs(t, expRecordsKey(t, name, typ), zone,
			expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, typ, name, data)))
	}
	f, skips := expSnapshot(t,
		one("x.sub.corp.test.", dnswire.TypeA, "sub.corp.test.", "10.53.0.81"),
		one("sub.corp.test.", dnswire.TypeNS, "corp.test.", "ns1.sub.corp.test."),
	)
	if len(f.Expectations) != 0 {
		t.Errorf("Expectations = %q; want none", f.String())
	}
	want := []string{
		"sub.corp.test. NS: lies in zone corp.test.; add the pair corp.test. NS",
		"x.sub.corp.test. A: lies in zone sub.corp.test.; add the pair sub.corp.test. NS",
	}
	if !slices.Equal(skips, want) {
		t.Errorf("skips %q; want %q", skips, want)
	}
}

const (
	expV6Addr1 = "[fd00::11]:53"
	expV6Addr2 = "[fd00::12]:53"
)

func expWWW(t *testing.T, answers ...obs.Answer) obs.Observation {
	t.Helper()
	return expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeA), "corp.test.", answers...)
}

func expWWWAnswer(t *testing.T, host, addr string) obs.Answer {
	t.Helper()
	return expAnswer(t, host, addr, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.81"))
}

// A machine without IPv6 gets the failure network from every IPv6 address.
// The set still gets its line from the servers that answered, and the
// address that was left out is reported.
func TestSnapshotLeavesOutAnIPv6ServerThatCannotBeReached(t *testing.T) {
	o := expWWW(t,
		expWWWAnswer(t, "ns1.corp.test.", expNS1Addr),
		expAnswer(t, "ns2.corp.test.", expV6Addr2, expFailure(obs.ReasonNetwork)))
	f, skips := expSnapshot(t, o)
	if got, want := f.String(), "domain corp.test.\nwww.corp.test. A 10.53.0.81\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	if len(skips) != 0 {
		t.Errorf("skips %q; want none", skips)
	}
	got := Unreached([]obs.Observation{o})
	if len(got) != 1 || got[0].Addr != netip.MustParseAddrPort(expV6Addr2) {
		t.Errorf("Unreached = %v; want the one address %s", got, expV6Addr2)
	}
}

// Only an IPv6 address that failed with network is left out: a timeout, or
// a network failure of an IPv4 address, still blocks the line.
func TestSnapshotKeepsOtherFailuresOfServers(t *testing.T) {
	for _, c := range []struct {
		name   string
		answer obs.Answer
		want   string
	}{
		{"an IPv6 timeout", expAnswer(t, "ns2.corp.test.", expV6Addr2, expFailure(obs.ReasonTimeout)),
			"www.corp.test. A: [fd00::12]:53 ns2.corp.test. gave no answer: timeout"},
		{"an IPv4 network failure", expAnswer(t, "ns2.corp.test.", expNS2Addr, expFailure(obs.ReasonNetwork)),
			"www.corp.test. A: 10.53.0.12:53 ns2.corp.test. gave no answer: network"},
	} {
		o := expWWW(t, expWWWAnswer(t, "ns1.corp.test.", expNS1Addr), c.answer)
		f, skips := expSnapshot(t, o)
		if len(f.Expectations) != 0 || !slices.Equal(skips, []string{c.want}) {
			t.Errorf("%s: lines %q, skips %q; want no line and the skip %q", c.name, f.String(), skips, c.want)
		}
		if got := Unreached([]obs.Observation{o}); len(got) != 0 {
			t.Errorf("%s: Unreached = %v; want none", c.name, got)
		}
	}
}

// When no server gave a usable answer, no server is left out: the skip
// names the first answer, even an IPv6 one that failed with network.
func TestSnapshotLeavesNoServerOutWhenNoneAnswered(t *testing.T) {
	o := expWWW(t,
		expAnswer(t, "ns2.corp.test.", expV6Addr2, expFailure(obs.ReasonNetwork)),
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expFailure(obs.ReasonTimeout)))
	_, skips := expSnapshot(t, o)
	want := []string{"www.corp.test. A: [fd00::12]:53 ns2.corp.test. gave no answer: network"}
	if !slices.Equal(skips, want) {
		t.Errorf("skips %q; want %q", skips, want)
	}
	if got := Unreached([]obs.Observation{o}); len(got) != 0 {
		t.Errorf("Unreached = %v; want none", got)
	}
}

// Unreached lists each address once, in address order, whatever the order of
// the sets; and it skips a set that gets no line.
func TestUnreachedIsSortedAndHasNoDuplicates(t *testing.T) {
	down := func(host, addr string) obs.Answer {
		return expAnswer(t, host, addr, expFailure(obs.ReasonNetwork))
	}
	api := expObs(t, expRecordsKey(t, "api.corp.test.", dnswire.TypeA), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, expRecords(t, dnswire.TypeA, "api.corp.test.", "10.53.0.82")),
		down("ns1.corp.test.", expV6Addr1), down("ns4.corp.test.", "[fd00::14]:53"))
	// No server answered for this set, so it gets no line and leaves nothing out.
	mail := expObs(t, expRecordsKey(t, "mail.corp.test.", dnswire.TypeA), "corp.test.",
		down("ns3.corp.test.", "[fd00::13]:53"))
	got := Unreached([]obs.Observation{
		expWWW(t, expWWWAnswer(t, "ns1.corp.test.", expNS1Addr), down("ns2.corp.test.", expV6Addr2)),
		mail,
		api,
		expWWW(t, down("ns2.corp.test.", expV6Addr2)),
	})
	want := []string{expV6Addr1, expV6Addr2, "[fd00::14]:53"}
	if len(got) != len(want) {
		t.Fatalf("Unreached = %v; want %v", got, want)
	}
	for i := range want {
		if got[i].Addr != netip.MustParseAddrPort(want[i]) {
			t.Errorf("Unreached[%d] = %v; want %s", i, got[i].Addr, want[i])
		}
	}
}
