package expect

import (
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// crtOddReason is the whole reason for a CAA record whose tag holds a
// hyphen: the codec prints it as bad\045tag, which the file parser refuses.
const crtOddReason = `the file cannot hold this line: bad data: dnswire: malformed message: ` +
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

// Every rule of the parser holds for a snapshot, not only the rules on the
// form of the data: a set that one rule would refuse gets no line, with the
// parser's own reason, and the sets beside it keep theirs. One refused line
// would make the whole file invalid.
func TestSnapshotDropsALineThatTheFileRefuses(t *testing.T) {
	refused := "the file cannot hold this line: "
	one := func(owner string, d dnswire.RData) obs.Result {
		return obs.RecordsResult(obs.Records{Set: []dnswire.Record{{Name: expName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: d}}})
	}
	for _, c := range []struct {
		name  string
		obs   obs.Observation
		why   string // the reason, or its start when it ends with the codec's words
		exact bool
	}{
		{"a DS set below the domain", expBothAnswer(t, "sub.corp.test.", dnswire.TypeDS, expNoData(t, "corp.test.")),
			refused + "a DS set is checked only at the domain", true},
		{"DS data below the domain", expBothAnswer(t, "sub.corp.test.", dnswire.TypeDS,
			one("sub.corp.test.", dnswire.DS{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: []byte("0123456789abcdef0123456789abcdef")})),
			refused + "a DS set is checked only at the domain", true},
		{"a DS set outside the domain", expBothAnswer(t, "other.test.", dnswire.TypeDS, expNoData(t, "other.test.")),
			refused + "a DS set is checked only at the domain", true},
		{"a type that the file cannot check", expBothAnswer(t, "www.corp.test.", dnswire.TypeNXNAME, expNoData(t, "corp.test.")),
			refused + "type TYPE128 cannot be checked", true},
		{"the type ANY", expBothAnswer(t, "www.corp.test.", dnswire.TypeANY, expNoData(t, "corp.test.")),
			refused + "type ANY cannot be checked", true},
		{"a TXT record with no string", expBothAnswer(t, "txt.corp.test.", dnswire.TypeTXT, one("txt.corp.test.", dnswire.TXT{})),
			refused + "want <owner> <type> <form>", true},
		{"a CAA record with no tag", expBothAnswer(t, "corp.test.", dnswire.TypeCAA, one("corp.test.", dnswire.CAA{})),
			refused + "bad data: ", false},
	} {
		t.Run(c.name, func(t *testing.T) {
			www := expBothAnswer(t, "www.corp.test.", dnswire.TypeA, expRecords(t, dnswire.TypeA, "www.corp.test.", "10.53.0.80"))
			f, skips := crtSnapshot(t, c.obs, www)
			if want := "domain corp.test.\nwww.corp.test. A 10.53.0.80\n"; f.String() != want {
				t.Errorf("String() %q; want %q", f.String(), want)
			}
			text := c.obs.Key.Name.Lower().String() + " " + c.obs.Key.Type.String() + ": " + c.why
			if len(skips) != 1 || c.exact && skips[0] != text || !strings.HasPrefix(skips[0], text) {
				t.Errorf("skips %q; want one, %q", skips, text)
			}
		})
	}
}
