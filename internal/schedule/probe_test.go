package schedule

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The checks that every plan starts with, as schText gives them at schIv.
var dngqHead = []string{
	"serial corp.test. corp.test. SOA tier1 every 7s zone false",
	"delegation corp.test. corp.test. NS tier2 every 1m1s zone false",
	"ds corp.test. corp.test. DS tier2 every 1m1s zone false",
}

// dngqPlan gives the checks of a file of corp.test. with the given lines
// and fast names, as schText prints them, with the head first.
func dngqPlan(t *testing.T, fast []string, lines ...string) []string {
	t.Helper()
	return schTexts(Plan(schFile(t, lines...), schNames(t, fast...), schIv))
}

func dngqSame(t *testing.T, got []string, tail ...string) {
	t.Helper()
	if want := append(slices.Clone(dngqHead), tail...); !slices.Equal(got, want) {
		t.Fatalf("Plan gave%s\nwant%s", schShow(got), schShow(want))
	}
}

// The probes follow every records check, in the order of Targets, not of the
// names; a name in the zone of the domain gets no probe.
func TestPlanProbesTheTargetsAfterTheRecordsChecksInTheOrderOfTargets(t *testing.T) {
	got := dngqPlan(t, nil,
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. MX 10 mx.zeta.test.",
		`corp.test. TXT "v=spf1 include:spf.alpha.test. -all"`,
		"cdn.corp.test. CNAME edge.dnshost.test.",
		"www.corp.test. A 10.53.0.81",
	)
	dngqSame(t, got,
		"records corp.test. corp.test. NS tier4 every 5m0s zone true",
		"records corp.test. corp.test. MX tier3 every 43s zone true",
		"records corp.test. corp.test. TXT tier4 every 5m0s zone true",
		"records corp.test. cdn.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. www.corp.test. A tier4 every 5m0s zone true",
		"records corp.test. mx.zeta.test. A tier4 every 5m0s zone false",
		"records corp.test. spf.alpha.test. A tier4 every 5m0s zone false",
		"records corp.test. edge.dnshost.test. A tier4 every 5m0s zone false",
	)
}

func TestPlanGivesNoProbeForNamesInTheZoneOfTheDomain(t *testing.T) {
	got := dngqPlan(t, nil,
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. MX 10 mail.corp.test.",
		`corp.test. TXT "v=spf1 include:spf.corp.test. -all"`,
		"cdn.corp.test. CNAME www.corp.test.",
	)
	dngqSame(t, got,
		"records corp.test. corp.test. NS tier4 every 5m0s zone true",
		"records corp.test. corp.test. MX tier3 every 43s zone true",
		"records corp.test. corp.test. TXT tier4 every 5m0s zone true",
		"records corp.test. cdn.corp.test. CNAME tier4 every 5m0s zone true",
	)
}

// A line "<target> A ..." is the check of the probe: one key, at the place
// and with the tier of the line, however many lines point at the target and
// in whatever case. A line of another type at the target is not that check.
func TestPlanTakesALineOfTypeAForTheProbeOfItsName(t *testing.T) {
	got := dngqPlan(t, []string{"edge.dnshost.test."},
		"corp.test. MX 10 edge.dnshost.test.",
		"cdn.corp.test. CNAME EDGE.dnshost.test.",
		"www.corp.test. CNAME api.dnshost.test.",
		"api.dnshost.test. AAAA none",
		"edge.dnshost.test. A 10.53.0.84",
		"edge.dnshost.test. AAAA fd53::84",
	)
	dngqSame(t, got,
		"records corp.test. corp.test. MX tier3 every 43s zone true",
		"records corp.test. cdn.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. www.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. api.dnshost.test. AAAA tier4 every 5m0s zone false",
		"records corp.test. edge.dnshost.test. A tier3 every 43s zone false",
		"records corp.test. edge.dnshost.test. AAAA tier3 every 43s zone false",
		"records corp.test. api.dnshost.test. A tier4 every 5m0s zone false",
	)
}

func TestPlanTakesANoneLineOfTypeAForTheProbeOfItsName(t *testing.T) {
	got := dngqPlan(t, nil,
		"cdn.corp.test. CNAME gone.dnshost.test.",
		"gone.dnshost.test. A none",
	)
	dngqSame(t, got,
		"records corp.test. cdn.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. gone.dnshost.test. A tier4 every 5m0s zone false",
	)
}

// A probe is tier other and outside the zone of the domain, whatever its
// name: a fast name, a challenge name in a cut, a host in a cut.
func TestPlanProbeIsTierOtherAndOutsideTheZoneForEveryName(t *testing.T) {
	got := dngqPlan(t, []string{"mail.dnshost.test.", "ns1.sub.corp.test."},
		"corp.test. MX 10 mail.dnshost.test.",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"www.corp.test. CNAME _acme-challenge.sub.corp.test.",
	)
	dngqSame(t, got,
		"records corp.test. corp.test. MX tier3 every 43s zone true",
		"records corp.test. sub.corp.test. NS tier4 every 5m0s zone false",
		"records corp.test. www.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. mail.dnshost.test. A tier4 every 5m0s zone false",
		"records corp.test. ns1.sub.corp.test. A tier4 every 5m0s zone false",
		"records corp.test. _acme-challenge.sub.corp.test. A tier4 every 5m0s zone false",
	)
}

// A file with no target and no * line plans as it did without the probes.
func TestPlanOfAFileWithNoTargetAndNoWildcardHasOnlyItsLines(t *testing.T) {
	got := dngqPlan(t, nil,
		"corp.test. A 10.53.0.80",
		"corp.test. DS none",
		"corp.test. TXT none",
		"www.corp.test. A 10.53.0.81",
		"corp.test. NS none",
	)
	dngqSame(t, got,
		"records corp.test. corp.test. A tier3 every 43s zone true",
		"records corp.test. corp.test. NS tier4 every 5m0s zone true",
		"records corp.test. corp.test. TXT tier4 every 5m0s zone true",
		"records corp.test. www.corp.test. A tier4 every 5m0s zone true",
	)
	dngqSame(t, dngqPlan(t, nil))
}

// Only the line "*.<zone> A none" is the wildcard line: the wildcard check
// takes its place. Every other line at a wildcard owner keeps its records
// check.
func TestPlanLeavesTheWildcardLineToTheWildcardCheck(t *testing.T) {
	// A name has at most 255 octets in wire form, and the random label adds
	// 27. The zone below takes n+1 octets for its first label, 3 × 64 for the
	// others and 1 for the root: 228 octets for n = 34, which leave room, and
	// 229 for n = 35, which do not.
	zone := func(n int) string {
		return strings.Repeat("b", n) + strings.Repeat("."+strings.Repeat("a", 63), 3) + "."
	}
	for _, c := range []struct {
		name  string
		fast  []string
		lines []string
		want  []string
	}{
		{"the line in the zone of the domain", []string{"corp.test."},
			[]string{"*.corp.test. A none", "www.corp.test. A 10.53.0.81"},
			[]string{
				"records corp.test. www.corp.test. A tier4 every 5m0s zone true",
				"wildcard corp.test. corp.test. A tier4 every 5m0s zone true",
			}},
		{"a zone below the domain, in its zone", nil,
			[]string{"*.www.corp.test. A none"},
			[]string{"wildcard corp.test. www.corp.test. A tier4 every 5m0s zone true"}},
		{"a type that is not A", nil,
			[]string{"*.corp.test. MX none"},
			[]string{"records corp.test. *.corp.test. MX tier4 every 5m0s zone true"}},
		{"the line beside another none line", nil,
			[]string{"*.corp.test. A none", "*.corp.test. MX none"},
			[]string{
				"records corp.test. *.corp.test. MX tier4 every 5m0s zone true",
				"wildcard corp.test. corp.test. A tier4 every 5m0s zone true",
			}},
		{"the line beside a line with data", nil,
			[]string{"*.corp.test. A none", `*.corp.test. TXT "x"`},
			[]string{
				`records corp.test. *.corp.test. TXT tier4 every 5m0s zone true`,
				"wildcard corp.test. corp.test. A tier4 every 5m0s zone true",
			}},
		{"data of type A", nil,
			[]string{"*.corp.test. A 10.53.0.99"},
			[]string{"records corp.test. *.corp.test. A tier4 every 5m0s zone true"}},
		{"AAAA none", nil,
			[]string{"*.corp.test. AAAA none"},
			[]string{"records corp.test. *.corp.test. AAAA tier4 every 5m0s zone true"}},
		{"a cut", nil,
			[]string{"sub.corp.test. NS ns1.sub.corp.test.", "*.sub.corp.test. A none"},
			[]string{
				"records corp.test. sub.corp.test. NS tier4 every 5m0s zone false",
				"records corp.test. ns1.sub.corp.test. A tier4 every 5m0s zone false",
				"wildcard corp.test. sub.corp.test. A tier4 every 5m0s zone false",
			}},
		{"a zone outside the domain", nil,
			[]string{"*.shop.test. A none"},
			[]string{"wildcard corp.test. shop.test. A tier4 every 5m0s zone false"}},
		{"a zone with room for the label", nil,
			[]string{"*." + zone(34) + " A none"},
			[]string{"wildcard corp.test. " + zone(34) + " A tier4 every 5m0s zone false"}},
		{"a zone with no room for the label", nil,
			[]string{"*." + zone(35) + " A none"},
			[]string{"records corp.test. *." + zone(35) + " A tier4 every 5m0s zone false"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dngqSame(t, dngqPlan(t, c.fast, c.lines...), c.want...)
		})
	}
}

// The wildcard checks come last, in the order of Wildcards, which is that of
// the lines and not that of the names.
func TestPlanPutsTheWildcardChecksLastInTheOrderOfWildcards(t *testing.T) {
	got := dngqPlan(t, nil,
		"*.a.z.test. A none",
		"*.b.y.test. A none",
		"*.corp.test. A none",
		"cdn.corp.test. CNAME edge.dnshost.test.",
	)
	dngqSame(t, got,
		"records corp.test. cdn.corp.test. CNAME tier4 every 5m0s zone true",
		"records corp.test. edge.dnshost.test. A tier4 every 5m0s zone false",
		"wildcard corp.test. corp.test. A tier4 every 5m0s zone true",
		"wildcard corp.test. b.y.test. A tier4 every 5m0s zone false",
		"wildcard corp.test. a.z.test. A tier4 every 5m0s zone false",
	)
}

// A moved serial starts the wildcard check with the checks of the zone, and a
// wildcard change in that round explains it, as a change of a set does.
func dngqWildcardMoved(t *testing.T) (*Schedule, []obs.Key) {
	t.Helper()
	f := schFile(t, "corp.test. A 10.53.0.80", "*.corp.test. A none")
	keys := []obs.Key{schKey(t, "corp.test.", dnswire.TypeA), obs.WildcardKey(f.Domain, f.Domain)}
	s := New(f, nil, schIv)
	schSettle(t, s)
	schStart(t, s, schSec(7), schSerialKey(t))
	schEnd(t, s, schSerialObs(t, schSec(7), 2, 2), schSec(8))
	return s, keys
}

func TestMoveMakesTheWildcardCheckDueAtOnceWithTheZoneChecks(t *testing.T) {
	s, keys := dngqWildcardMoved(t)
	want := schKeyTexts([]Check{{Key: keys[0]}, {Key: keys[1]}})
	if got := schKeyTexts(s.Due(schSec(8))); !slices.Equal(got, want) {
		t.Fatalf("Due right after the move gave%s\nwant%s", schShow(got), schShow(want))
	}
}

func TestWildcardChangeExplainsTheRoundOfAMove(t *testing.T) {
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
		s, keys := dngqWildcardMoved(t)
		schStart(t, s, schSec(8), keys...)
		for i, k := range keys {
			var changes []decide.Change
			if i == 1 {
				changes = []decide.Change{{Op: op, Finding: decide.Finding{Rule: decide.RuleWildcard, Check: k}, At: schSec(9)}}
			}
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
			schWantJudged(t, fmt.Sprintf("%s wildcard, then %s", op, k), moves, ok, false, nil)
		}
	}
}
