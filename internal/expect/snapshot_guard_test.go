package expect

import (
	"slices"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// crtOddReason is the whole reason for a CAA record whose tag holds a
// hyphen: the codec prints it as bad\045tag, which the file parser refuses.
const crtOddReason = `holds a record that a line cannot state: bad data: dnswire: malformed message: ` +
	`CAA data "0 bad\\045tag \"x\"": CAA tag octet 4 is not an ASCII letter or digit`

func crtCAA(t testing.TB, owner string, caa ...dnswire.CAA) obs.Result {
	t.Helper()
	var set []dnswire.Record
	for _, c := range caa {
		set = append(set, dnswire.Record{Name: expName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: c})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

var (
	crtOdd  = dnswire.CAA{Tag: "bad-tag", Value: "x"}
	crtGood = dnswire.CAA{Tag: "issue", Value: "ca.test"}
)

// crtSnapshot also checks that the file always parses again.
func crtSnapshot(t *testing.T, observations ...obs.Observation) (*File, []string) {
	t.Helper()
	f, skips := expSnapshot(t, observations...)
	g := expParse(t, f.String())
	if g.String() != f.String() {
		t.Errorf("the file %q parses again as %q", f.String(), g.String())
	}
	return f, skips
}

func TestSnapshotSkipsASetThatALineCannotState(t *testing.T) {
	odd := crtCAA(t, "www.corp.test.", crtOdd)
	f, skips := crtSnapshot(t, expBothAnswer(t, "www.corp.test.", dnswire.TypeCAA, odd))
	if want := []string{"www.corp.test. CAA: " + crtOddReason}; !slices.Equal(skips, want) {
		t.Errorf("skips %q; want %q", skips, want)
	}
	if len(f.Expectations) != 0 {
		t.Errorf("String() %q; want no line", f.String())
	}
}

func TestSnapshotSkipsASetWithAnOddRecordBesideAGoodOne(t *testing.T) {
	both := crtCAA(t, "www.corp.test.", crtGood, crtOdd)
	f, skips := crtSnapshot(t, expBothAnswer(t, "www.corp.test.", dnswire.TypeCAA, both))
	if want := []string{"www.corp.test. CAA: " + crtOddReason}; !slices.Equal(skips, want) || len(f.Expectations) != 0 {
		t.Errorf("skips %q, String() %q; want %q and no line", skips, f.String(), want)
	}
}

func TestSnapshotWritesTheOtherPairsBesideAnOddOne(t *testing.T) {
	f, skips := crtSnapshot(t,
		expBothAnswer(t, "www.corp.test.", dnswire.TypeCAA, crtCAA(t, "www.corp.test.", crtOdd)),
		expBothAnswer(t, "corp.test.", dnswire.TypeCAA, crtCAA(t, "corp.test.", crtGood)),
		expBothAnswer(t, "www.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.80")))
	want := "domain corp.test.\ncorp.test. CAA 0 issue \"ca.test\"\nwww.corp.test. A 10.53.0.80\n"
	if f.String() != want {
		t.Errorf("String() %q; want %q", f.String(), want)
	}
	if wantSkips := []string{"www.corp.test. CAA: " + crtOddReason}; !slices.Equal(skips, wantSkips) {
		t.Errorf("skips %q; want %q", skips, wantSkips)
	}
}

func TestSnapshotWritesTheSamePairWithoutTheOddRecord(t *testing.T) {
	f, skips := crtSnapshot(t, expBothAnswer(t, "www.corp.test.", dnswire.TypeCAA, crtCAA(t, "www.corp.test.", crtGood)))
	if want := "domain corp.test.\nwww.corp.test. CAA 0 issue \"ca.test\"\n"; f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}
