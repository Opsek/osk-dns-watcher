package schedule

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The property tests draw their inputs from a fixed seed, so a failure can
// be replayed; every message names the seed and the case.
const (
	schSeed  = 20261113
	schCases = 1000
)

func schRand(c int) *rand.Rand { return rand.New(rand.NewPCG(schSeed, uint64(c))) }

func schPick[T any](rng *rand.Rand, xs ...T) T { return xs[rng.IntN(len(xs))] }

// schIv gives each tier its own interval, so a check that gets the interval
// or the failure limit of another tier shows.
var schIv = Intervals{Serial: 7 * time.Second, Parent: 61 * time.Second, Fast: 43 * time.Second, Other: 300 * time.Second}

func schName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func schNames(t testing.TB, ss ...string) []dnswire.Name {
	t.Helper()
	var names []dnswire.Name
	for _, s := range ss {
		names = append(names, schName(t, s))
	}
	return names
}

// schFile parses a file of the domain corp.test. with the given lines.
func schFile(t testing.TB, lines ...string) *expect.File {
	t.Helper()
	text := "domain corp.test.\n" + strings.Join(lines, "\n") + "\n"
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return f
}

// schText gives every field of a check; the key text is its identity.
func schText(c Check) string {
	return fmt.Sprintf("%s tier%d every %v zone %v", c.Key, uint8(c.Tier), c.Interval, c.Zone)
}

func schTexts(cs []Check) []string {
	texts := make([]string, len(cs))
	for i, c := range cs {
		texts[i] = schText(c)
	}
	return texts
}

func schKeyTexts(cs []Check) []string {
	texts := make([]string, len(cs))
	for i, c := range cs {
		texts[i] = c.Key.String()
	}
	return texts
}

func schShow(texts []string) string {
	if len(texts) == 0 {
		return " (none)"
	}
	return "\n\t" + strings.Join(texts, "\n\t")
}

// schSameChecks fails the test unless got holds the checks of want, in order.
func schSameChecks(t testing.TB, what string, got, want []Check) {
	t.Helper()
	if g, w := schTexts(got), schTexts(want); !slices.Equal(g, w) {
		t.Fatalf("%s gave%s\nwant%s", what, schShow(g), schShow(w))
	}
}

// schEvery is the interval of each tier, read from the fields of iv.
func schEvery(iv Intervals) map[Tier]time.Duration {
	return map[Tier]time.Duration{TierSerial: iv.Serial, TierParent: iv.Parent, TierFast: iv.Fast, TierOther: iv.Other}
}

var schFastTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCAA, dnswire.TypeMX}

// schPlanBefore is the plan of a file that names no target and no wildcard:
// the serial check, the two parent checks, then one records check for each
// line that is not DS, in the order of the file.
func schPlanBefore(t testing.TB, f *expect.File, fast []dnswire.Name, iv Intervals) []Check {
	t.Helper()
	d := f.Domain
	plan := []Check{
		{Key: obs.SerialKey(d), Tier: TierSerial, Interval: iv.Serial},
		{Key: obs.DelegationKey(d), Tier: TierParent, Interval: iv.Parent},
		{Key: obs.DSKey(d), Tier: TierParent, Interval: iv.Parent},
	}
	for _, e := range f.Expectations {
		if e.Type == dnswire.TypeDS {
			continue
		}
		plan = append(plan, schRecordsCheck(f, e, fast, iv))
	}
	return plan
}

func schRecordsCheck(f *expect.File, e expect.Expectation, fast []dnswire.Name, iv Intervals) Check {
	d := f.Domain
	tier := TierOther
	if e.Name.Equal(d) && slices.Contains(schFastTypes, e.Type) || dngChallengeOwner(e.Name, d) ||
		slices.ContainsFunc(fast, e.Name.Equal) {
		tier = TierFast
	}
	return Check{Key: obs.RecordsKey(d, e.Name, e.Type), Tier: tier, Interval: schEvery(iv)[tier],
		Zone: e.Name.IsSubdomainOf(d) && f.Zone(e.Name).Equal(d)}
}

// schIsWildcardLine says whether e is the line "*.<zone> A none", the only
// line that a wildcard check takes the place of.
func schIsWildcardLine(e expect.Expectation) bool {
	labels := e.Name.Labels()
	return len(labels) > 0 && labels[0] == "*" && e.Type == dnswire.TypeA && e.Form == expect.FormNone
}

// schWildcardZones are the zones of the wildcard lines whose zone has room
// for the random label, in the order of the lines, each once.
func schWildcardZones(f *expect.File) []dnswire.Name {
	var zones []dnswire.Name
	for _, e := range f.Expectations {
		zone := e.Name.Parent()
		label := strings.Repeat("a", obs.WildcardLabel)
		if _, err := dnswire.NameFromLabels(append([]string{label}, zone.Labels()...)); err != nil ||
			!schIsWildcardLine(e) || slices.ContainsFunc(zones, zone.Equal) {
			continue
		}
		zones = append(zones, zone)
	}
	return zones
}

// schModelPlan is the plan as the rules state it: the serial check, the two
// parent checks, a records check for each line in the order of the file
// (none for DS, and none for a wildcard line whose zone has a wildcard
// check), a records check of type A for each target that no line already
// checks, and a wildcard check for each wildcard zone, which is a check of
// the zone when the zone of the domain holds it.
func schModelPlan(t testing.TB, f *expect.File, fast []dnswire.Name, iv Intervals) []Check {
	t.Helper()
	d := f.Domain
	wild := schWildcardZones(f)
	plan := []Check{
		{Key: obs.SerialKey(d), Tier: TierSerial, Interval: iv.Serial},
		{Key: obs.DelegationKey(d), Tier: TierParent, Interval: iv.Parent},
		{Key: obs.DSKey(d), Tier: TierParent, Interval: iv.Parent},
	}
	for _, e := range f.Expectations {
		if e.Type == dnswire.TypeDS || schIsWildcardLine(e) && slices.ContainsFunc(wild, e.Name.Parent().Equal) {
			continue
		}
		plan = append(plan, schRecordsCheck(f, e, fast, iv))
	}
	for _, target := range decide.Targets(f) {
		key := obs.RecordsKey(d, target.Name, dnswire.TypeA)
		if !slices.ContainsFunc(plan, func(c Check) bool { return c.Key.String() == key.String() }) {
			plan = append(plan, Check{Key: key, Tier: TierOther, Interval: iv.Other})
		}
	}
	for _, zone := range wild {
		plan = append(plan, Check{Key: obs.WildcardKey(d, zone), Tier: TierOther, Interval: iv.Other,
			Zone: zone.IsSubdomainOf(d) && f.Zone(zone).Equal(d)})
	}
	return plan
}

func TestTierWordsAndUnknownTier(t *testing.T) {
	for tier, want := range map[Tier]string{TierSerial: "serial", TierParent: "parent", TierFast: "fast",
		TierOther: "other", 0: "tier0", 5: "tier5", 255: "tier255"} {
		if got := tier.String(); got != want {
			t.Errorf("Tier(%d).String() = %q, want %q", uint8(tier), got, want)
		}
	}
}

func TestDefaultsAre15s60s60s5m(t *testing.T) {
	want := Intervals{Serial: 15 * time.Second, Parent: time.Minute, Fast: time.Minute, Other: 5 * time.Minute}
	if got := Defaults(); got != want {
		t.Fatalf("Defaults() = %+v, want %+v", got, want)
	}
}

func TestFloorCeilingAndRunningCap(t *testing.T) {
	if Floor != 5*time.Second || Ceiling != 24*time.Hour || MaxRunning != 16 {
		t.Fatalf("Floor %v, Ceiling %v, MaxRunning %d; want 5s, 24h0m0s, 16", Floor, Ceiling, MaxRunning)
	}
}

func TestOfGivesEachTierItsOwnInterval(t *testing.T) {
	for tier, want := range schEvery(schIv) {
		if got := schIv.Of(tier); got != want {
			t.Errorf("Of(%d) = %v, want %v", uint8(tier), got, want)
		}
	}
}

func TestFailLimitIsFiveThreeOrSixtyIntervals(t *testing.T) {
	cases := []struct {
		iv   Intervals
		tier Tier
		want time.Duration
	}{
		{schIv, TierParent, 5 * schIv.Parent},
		{schIv, TierFast, 5 * schIv.Fast},
		{schIv, TierOther, 3 * schIv.Other},
		{schIv, TierSerial, 60 * schIv.Serial},
		// At the defaults: 5 minutes in the 60 s tiers, 15 minutes in the others.
		{Defaults(), TierParent, 5 * time.Minute},
		{Defaults(), TierFast, 5 * time.Minute},
		{Defaults(), TierOther, 15 * time.Minute},
		{Defaults(), TierSerial, 15 * time.Minute},
		{Intervals{Serial: Ceiling, Parent: Ceiling, Fast: Ceiling, Other: Ceiling}, TierSerial, 60 * Ceiling},
	}
	for _, c := range cases {
		if got := c.iv.FailLimit(c.tier); got != c.want {
			t.Errorf("%+v FailLimit(%d) = %v, want %v", c.iv, uint8(c.tier), got, c.want)
		}
	}
}

// The file keeps its lines in canonical order (names from the right, then
// type numbers), which differs from the order of the key texts.
func TestPlanIsSerialThenParentThenRecordsInFileOrderWithoutDS(t *testing.T) {
	f := schFile(t,
		"a.www.corp.test. A 10.53.0.87",
		"www.corp.test. A 10.53.0.81",
		"corp.test. DS none",
		"mail.corp.test. A 10.53.0.82",
		"corp.test. AAAA fd53::80",
		"b.corp.test. A 10.53.0.88",
		"corp.test. TXT none",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. A 10.53.0.80",
	)
	var got []string
	for _, c := range Plan(f, nil, schIv) {
		got = append(got, fmt.Sprintf("%s tier%d", c.Key, uint8(c.Tier)))
	}
	want := []string{
		"serial corp.test. corp.test. SOA tier1",
		"delegation corp.test. corp.test. NS tier2",
		"ds corp.test. corp.test. DS tier2",
		"records corp.test. corp.test. A tier3",
		"records corp.test. corp.test. NS tier4",
		"records corp.test. corp.test. TXT tier4",
		"records corp.test. corp.test. AAAA tier3",
		"records corp.test. b.corp.test. A tier4",
		"records corp.test. mail.corp.test. A tier4",
		"records corp.test. www.corp.test. A tier4",
		"records corp.test. a.www.corp.test. A tier4",
	}
	if !slices.Equal(got, want) {
		t.Fatalf("Plan gave%s\nwant%s", schShow(got), schShow(want))
	}
}

// schTierOf gives the tier and zone of each records check of Plan, by name
// and type.
func schTierOf(t *testing.T, plan []Check) map[string]string {
	t.Helper()
	out := map[string]string{}
	for _, c := range plan {
		if c.Key.Kind == obs.KindRecords {
			out[c.Key.Name.Lower().String()+" "+c.Key.Type.String()] = fmt.Sprintf("tier%d zone %v", uint8(c.Tier), c.Zone)
		}
	}
	return out
}

func TestPlanFastTiers(t *testing.T) {
	f := schFile(t,
		"corp.test. A 10.53.0.80",
		"corp.test. AAAA fd53::80",
		"corp.test. CAA 0 issue \"ca.test\"",
		"corp.test. MX 10 mail.corp.test.",
		"corp.test. TXT \"v=spf1 mx -all\"",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"_acme-challenge.corp.test. TXT none",
		"_ACME-Challenge.Corp.Test. CNAME none",
		"_acme-challenge.www.corp.test. TXT none",
		"www.corp.test. A 10.53.0.81",
		"mail.corp.test. A 10.53.0.82",
		"mail.corp.test. TXT none",
		"api.dnshost.test. A 10.53.0.83",
		"edge.dnshost.test. A 10.53.0.84",
		"_acme-challenge.shop.test. TXT none",
	)
	// The names of --fast in another case than the file.
	fast := schNames(t, "MAIL.Corp.Test.", "api.DNSHOST.test.", "nothere.corp.test.")
	fastTier, other := "tier3", "tier4"
	want := map[string]string{
		"corp.test. A":                       fastTier + " zone true",
		"corp.test. AAAA":                    fastTier + " zone true",
		"corp.test. CAA":                     fastTier + " zone true",
		"corp.test. MX":                      fastTier + " zone true",
		"corp.test. TXT":                     other + " zone true",
		"corp.test. NS":                      other + " zone true",
		"_acme-challenge.corp.test. TXT":     fastTier + " zone true",
		"_acme-challenge.corp.test. CNAME":   fastTier + " zone true",
		"_acme-challenge.www.corp.test. TXT": fastTier + " zone true",
		"www.corp.test. A":                   other + " zone true",
		"mail.corp.test. A":                  fastTier + " zone true",
		"mail.corp.test. TXT":                fastTier + " zone true",
		"api.dnshost.test. A":                fastTier + " zone false",
		"edge.dnshost.test. A":               other + " zone false",
		"_acme-challenge.shop.test. TXT":     other + " zone false",
	}
	plan := Plan(f, fast, schIv)
	if got := schTierOf(t, plan); !reflect.DeepEqual(got, want) {
		t.Fatalf("records checks:\n got %v\nwant %v", got, want)
	}
	every := schEvery(schIv)
	for _, c := range plan {
		if c.Interval != every[c.Tier] {
			t.Errorf("%s in tier %d runs every %v, want %v", c.Key, uint8(c.Tier), c.Interval, every[c.Tier])
		}
	}
}

func TestPlanZoneOnlyForNamesInTheDomainsOwnZone(t *testing.T) {
	f := schFile(t,
		"corp.test. A 10.53.0.80",
		"www.corp.test. A 10.53.0.81",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"www.sub.corp.test. A 10.53.0.85",
		"old.corp.test. NS none",
		"x.old.corp.test. A 10.53.0.86",
		"edge.dnshost.test. A 10.53.0.84",
	)
	want := map[string]bool{
		"serial corp.test. corp.test. SOA":        false,
		"delegation corp.test. corp.test. NS":     false,
		"ds corp.test. corp.test. DS":             false,
		"records corp.test. corp.test. A":         true,
		"records corp.test. www.corp.test. A":     true,
		"records corp.test. sub.corp.test. NS":    false, // the cut belongs to the subzone
		"records corp.test. www.sub.corp.test. A": false,
		"records corp.test. old.corp.test. NS":    true, // a none line declares no zone
		"records corp.test. x.old.corp.test. A":   true,
		"records corp.test. edge.dnshost.test. A": false,
		// The host of the cut is a target: it lies in the cut, not in the
		// zone of the domain.
		"records corp.test. ns1.sub.corp.test. A": false,
	}
	got := map[string]bool{}
	for _, c := range Plan(f, nil, schIv) {
		got[c.Key.String()] = c.Zone
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("zone of each check:\n got %v\nwant %v", got, want)
	}
}

func TestUnusedGivesFastNamesWithoutLineInGivenOrder(t *testing.T) {
	f := schFile(t,
		"www.corp.test. A 10.53.0.81",
		"mail.corp.test. TXT none",
		"edge.dnshost.test. A 10.53.0.84",
	)
	fast := schNames(t, "nothere.corp.test.", "MAIL.corp.test.", "zz.corp.test.", "Edge.Dnshost.Test.", "aa.test.")
	var got []string
	for _, n := range Unused(f, fast) {
		got = append(got, n.Lower().String())
	}
	if want := []string{"nothere.corp.test.", "zz.corp.test.", "aa.test."}; !slices.Equal(got, want) {
		t.Fatalf("Unused gave %q, want %q", got, want)
	}
	if got := Unused(f, schNames(t, "www.corp.test.")); len(got) != 0 {
		t.Fatalf("Unused of a name with a line gave %v", got)
	}
	if got := Unused(f, nil); len(got) != 0 {
		t.Fatalf("Unused of no names gave %v", got)
	}
}

// Owners of the random files: the lab names, a challenge name above and
// below the domain, a cut, a name under a cut, names outside the domain and
// wildcard owners in the zone of the domain, in a cut and outside.
var schOwners = []string{
	"corp.test.", "www.corp.test.", "mail.corp.test.", "cdn.corp.test.", "_dmarc.corp.test.",
	"_acme-challenge.corp.test.", "_acme-challenge.www.corp.test.", "sub.corp.test.", "www.sub.corp.test.",
	"deep.www.corp.test.", "edge.dnshost.test.", "shop.test.",
	"ns1.sub.corp.test.", "mail.dnshost.test.", "mail.sub.corp.test.",
	"*.corp.test.", "*.corp.test.", "*.sub.corp.test.", "*.www.corp.test.", "*.shop.test.",
}

// schTypes are the types that a line may have. Every type takes the form
// none; DS only at the domain.
var schTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCAA, dnswire.TypeMX, dnswire.TypeTXT,
	dnswire.TypeNS, dnswire.TypeCNAME, dnswire.TypeSOA, dnswire.TypePTR, dnswire.TypeDNAME, dnswire.TypeSPF,
	dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeDNSKEY, dnswire.TypeNSEC3, dnswire.TypeNSEC3PARAM, dnswire.TypeDS}

// schData are the forms with data that a line of a type may take, besides
// none: names in the zone of the domain, in a cut and outside the domain,
// and SPF records with and without an include.
var schData = map[dnswire.Type][]string{
	dnswire.TypeA:     {"10.53.0.99"},
	dnswire.TypeNS:    {"ns1.corp.test.", "ns1.sub.corp.test.", "ns1.dnshost.test. | ns2.dnshost.test.", "ns1.shop.test."},
	dnswire.TypeCNAME: {"edge.dnshost.test.", "www.corp.test.", "cdn.sub.corp.test.", "ns1.sub.corp.test."},
	dnswire.TypeDNAME: {"edge.dnshost.test.", "www.corp.test."},
	dnswire.TypeMX:    {"10 mail.dnshost.test.", "10 mail.corp.test.", "10 mail.sub.corp.test."},
	dnswire.TypeTXT: {`"v=spf1 include:spf.dnshost.test. -all"`, `"v=spf1 include:spf.corp.test. -all"`,
		`"v=spf1 mx -all"`, `"hello"`},
}

var schFastPool = []string{"mail.corp.test.", "MAIL.CORP.TEST.", "www.sub.corp.test.", "edge.dnshost.test.",
	"nothere.corp.test.", "corp.test.", "_acme-challenge.corp.test.", "Www.Corp.Test.", "other.test."}

// schShout gives s with random letters in capitals.
func schShout(rng *rand.Rand, s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'a' <= c && c <= 'z' && rng.IntN(4) == 0 {
			b[i] = c - 'a' + 'A'
		}
	}
	return string(b)
}

// schRandomLines gives up to most lines of corp.test. whose owner and type
// are not in seen. A line takes the form none or, for the types of schData,
// data; the parser takes every such file.
func schRandomLines(rng *rand.Rand, most int, seen map[string]bool) []string {
	var lines []string
	for range rng.IntN(most + 1) {
		owner, typ := schPick(rng, schOwners...), schPick(rng, schTypes...)
		if typ == dnswire.TypeDS && owner != "corp.test." || seen[owner+typ.String()] {
			continue
		}
		seen[owner+typ.String()] = true
		form := "none"
		if data := schData[typ]; data != nil && rng.IntN(3) > 0 {
			form = schShout(rng, schPick(rng, data...))
		}
		lines = append(lines, schShout(rng, owner)+" "+typ.String()+" "+form)
	}
	return lines
}

func schRandomFile(t testing.TB, rng *rand.Rand, most int) *expect.File {
	t.Helper()
	return schFile(t, schRandomLines(rng, most, map[string]bool{})...)
}

func schRandomFast(t testing.TB, rng *rand.Rand) []dnswire.Name {
	t.Helper()
	var fast []dnswire.Name
	for range rng.IntN(4) {
		// A name given twice is left out: what Unused gives for it is open.
		if n := schName(t, schPick(rng, schFastPool...)); !slices.ContainsFunc(fast, n.Equal) {
			fast = append(fast, n)
		}
	}
	return fast
}

// schOwnsOnlyDS reports a name whose only lines are DS lines; whether such a
// name owns a line in the sense of Unused is left open.
func schOwnsOnlyDS(f *expect.File, n dnswire.Name) bool {
	owns := false
	for _, e := range f.Expectations {
		if e.Name.Equal(n) {
			if e.Type != dnswire.TypeDS {
				return false
			}
			owns = true
		}
	}
	return owns
}

// schKinds counts the cases of TestPlanProperty by what their file holds, so
// that a generator that stops making a kind shows.
type schKinds struct{ plain, probes, shared, wildcards, owned, kept int }

// add counts the kinds of f and checks the plan of a file with no target
// and no wildcard owner against the plan that such a file had before.
func (k *schKinds) add(t testing.TB, where string, f *expect.File, fast []dnswire.Name, iv Intervals, got []Check) {
	t.Helper()
	targets, wild := decide.Targets(f), schWildcardZones(f)
	owner := slices.ContainsFunc(f.Expectations, func(e expect.Expectation) bool {
		labels := e.Name.Labels()
		return len(labels) > 0 && labels[0] == "*"
	})
	if len(targets) == 0 && !owner {
		k.plain++
		if g, w := schTexts(got), schTexts(schPlanBefore(t, f, fast, iv)); !slices.Equal(g, w) {
			t.Fatalf("%s: file\n%s--fast %v\nPlan gave%s\nwant the plan of before%s", where, f, fast, schShow(g), schShow(w))
		}
	}
	for _, target := range targets {
		if slices.ContainsFunc(f.Expectations, func(e expect.Expectation) bool {
			return e.Type == dnswire.TypeA && e.Name.Equal(target.Name)
		}) {
			k.shared++
		} else {
			k.probes++
		}
	}
	k.wildcards += len(wild)
	for _, e := range f.Expectations {
		if schIsWildcardLine(e) && slices.ContainsFunc(wild, e.Name.Parent().Equal) {
			k.owned++
		} else if labels := e.Name.Labels(); len(labels) > 0 && labels[0] == "*" {
			k.kept++
		}
	}
}

func TestPlanProperty(t *testing.T) {
	fastSeen, zoneSeen, outsideSeen := 0, 0, 0
	var kinds schKinds
	for c := range schCases {
		rng := schRand(c)
		where := fmt.Sprintf("seed %d case %d", schSeed, c)
		f := schRandomFile(t, rng, 30)
		fast := schRandomFast(t, rng)
		iv := Intervals{Serial: schPick(rng, 5*time.Second, 7*time.Second, 15*time.Second),
			Parent: schPick(rng, 10*time.Second, 61*time.Second), Fast: schPick(rng, 6*time.Second, 43*time.Second),
			Other: schPick(rng, 20*time.Second, 300*time.Second)}
		got := Plan(f, fast, iv)
		want := schModelPlan(t, f, fast, iv)
		if g, w := schTexts(got), schTexts(want); !slices.Equal(g, w) {
			t.Fatalf("%s: file\n%s--fast %v\nPlan gave%s\nwant%s", where, f, fast, schShow(g), schShow(w))
		}
		keys := schKeyTexts(got)
		if len(slices.Compact(slices.Sorted(slices.Values(keys)))) != len(keys) {
			t.Fatalf("%s: Plan holds a key twice:%s", where, schShow(keys))
		}
		if again := Plan(f, fast, iv); !reflect.DeepEqual(again, got) {
			t.Fatalf("%s: a second Plan gave%s\nthe first%s", where, schShow(schTexts(again)), schShow(schTexts(got)))
		}
		kinds.add(t, where, f, fast, iv, got)
		for _, ch := range got[3:] {
			if ch.Tier == TierFast {
				fastSeen++
			}
			if ch.Zone {
				zoneSeen++
			} else {
				outsideSeen++
			}
		}
		if slices.ContainsFunc(fast, func(n dnswire.Name) bool { return schOwnsOnlyDS(f, n) }) {
			continue
		}
		var unused []string
		for _, n := range fast {
			if !slices.ContainsFunc(f.Expectations, func(e expect.Expectation) bool { return e.Name.Equal(n) }) {
				unused = append(unused, n.Lower().String())
			}
		}
		var gotUnused []string
		for _, n := range Unused(f, fast) {
			gotUnused = append(gotUnused, n.Lower().String())
		}
		if !slices.Equal(gotUnused, unused) {
			t.Fatalf("%s: file\n%s--fast %v\nUnused gave %q, want %q", where, f, fast, gotUnused, unused)
		}
	}
	if fastSeen == 0 || zoneSeen == 0 || outsideSeen == 0 {
		t.Fatalf("seed %d: fast %d, zone %d, outside %d records checks: the cases miss a kind", schSeed,
			fastSeen, zoneSeen, outsideSeen)
	}
	if kinds.plain < 100 || kinds.probes < 200 || kinds.shared < 20 || kinds.wildcards < 40 || kinds.owned < 40 || kinds.kept < 100 {
		t.Fatalf("seed %d: %+v: the cases miss a kind", schSeed, kinds)
	}
}
