package schedule

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// ---- A small reference for which names get a CAA check ----

// caaExactLine is the CAA line of n when it states data.
func caaExactLine(f *expect.File, n dnswire.Name) (expect.Expectation, bool) {
	e, ok := f.Find(n, dnswire.TypeCAA)
	return e, ok && e.Form == expect.FormSets
}

// caaFileSets is the climb of RFC 8659 over the lines of the file: the
// alternatives of the nearest exact CAA line at or above n, up to the domain;
// a line "none" and a name without a line both go on to the parent.
func caaFileSets(f *expect.File, n dnswire.Name) ([][]dnswire.RData, bool) {
	for ; n.IsSubdomainOf(f.Domain); n = n.Parent() {
		if e, ok := caaExactLine(f, n); ok {
			return e.Sets, true
		}
	}
	return nil, false
}

func caaOpen(p decide.Policy) bool { return p.Name.Any && p.Wild.Any }

var caaReadings = []decide.Reading{decide.StrictReading, decide.PermissiveReading}

// caaClosed says that n has a file policy that is guarded: under some reading
// no alternative of it is open. Below an open policy nothing can be weaker.
func caaClosed(f *expect.File, n dnswire.Name) bool {
	sets, ok := caaFileSets(f, n)
	if !ok {
		return false
	}
	return slices.ContainsFunc(caaReadings, func(r decide.Reading) bool {
		return !slices.ContainsFunc(sets, func(set []dnswire.RData) bool {
			p, ok := decide.PolicyOf(set, r)
			return !ok || caaOpen(p)
		})
	})
}

// caaCertName says that no label of n below the domain starts with "_" or is
// "*": no certificate holds such a name, and a wildcard is judged at its
// parent.
func caaCertName(n, d dnswire.Name) bool {
	for _, label := range n.Labels()[:n.LabelCount()-d.LabelCount()] {
		if strings.HasPrefix(label, "_") || label == "*" {
			return false
		}
	}
	return true
}

// caaModelNames are the names whose CAA set a check must see: the domain and
// every name on the way from a line of the file up to the domain, left out
// when it has a "_" or "*" label or no closed policy; each once, in canonical
// order.
func caaModelNames(f *expect.File) []dnswire.Name {
	d := f.Domain
	byKey := map[string]dnswire.Name{}
	consider := func(n dnswire.Name) {
		if caaCertName(n, d) && caaClosed(f, n) {
			byKey[n.Key()] = n
		}
	}
	consider(d)
	for _, e := range f.Expectations {
		for n := e.Name; n.IsSubdomainOf(d); n = n.Parent() {
			consider(n)
		}
	}
	names := make([]dnswire.Name, 0, len(byKey))
	for _, n := range byKey {
		names = append(names, n)
	}
	slices.SortFunc(names, dnswire.Compare)
	return names
}

// caaModelProbes are the CAA checks of the names of caaModelNames that no
// CAA line of the file checks.
func caaModelProbes(f *expect.File, fast []dnswire.Name, iv Intervals) []Check {
	d := f.Domain
	var probes []Check
	for _, n := range caaModelNames(f) {
		if _, ok := f.Find(n, dnswire.TypeCAA); ok {
			continue
		}
		tier := TierOther
		if slices.ContainsFunc(fast, n.Equal) {
			tier = TierFast
		}
		probes = append(probes, Check{Key: obs.RecordsKey(d, n, dnswire.TypeCAA), Tier: tier, Interval: schEvery(iv)[tier],
			Zone: n.IsSubdomainOf(d) && f.Zone(n).Equal(d)})
	}
	return probes
}

// ---- Rows: which names get a probe ----

// caaCheck is the text of a records check of corp.test. as schText gives it
// at schIv.
func caaCheck(name, typ string, fast bool, zone bool) string {
	tier := "tier4 every 5m0s"
	if fast {
		tier = "tier3 every 43s"
	}
	return fmt.Sprintf("records corp.test. %s %s %s zone %v", name, typ, tier, zone)
}

const caaApexLine = `corp.test. CAA 0 issue "ca.test"`

func TestCAAProbeRows(t *testing.T) {
	rows := []struct {
		name  string
		fast  []string
		lines []string
		want  []string // after the three checks that every plan starts with
	}{
		{
			name:  "no CAA line gives no probe",
			lines: []string{"www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("mail.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "A", false, true),
			},
		},
		{
			name:  "the apex line alone has no name below it to probe",
			lines: []string{caaApexLine},
			want:  []string{caaCheck("corp.test.", "CAA", true, true)},
		},
		{
			name:  "names below the apex line get a probe each, in canonical order, other tier",
			lines: []string{caaApexLine, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("mail.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "A", false, true),
				caaCheck("mail.corp.test.", "CAA", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "a name of --fast, in another case, gets the fast tier and interval",
			fast:  []string{"MAIL.Corp.Test."},
			lines: []string{caaApexLine, "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("mail.corp.test.", "A", true, true),
				caaCheck("www.corp.test.", "A", false, true),
				caaCheck("mail.corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "owners in capitals give the probe of the lower-case name",
			lines: []string{caaApexLine, "WWW.Corp.TEST. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "a name reached from two owners gets one probe, and its parent one too",
			lines: []string{caaApexLine, "a.www.corp.test. A 10.53.0.81", "b.www.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("a.www.corp.test.", "A", false, true),
				caaCheck("b.www.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
				caaCheck("a.www.corp.test.", "CAA", false, true),
				caaCheck("b.www.corp.test.", "CAA", false, true),
			},
		},
		{
			name: "a line none and a line with data are their own check; the names under them still get a probe",
			lines: []string{caaApexLine, "www.corp.test. CAA none", "a.www.corp.test. A 10.53.0.81",
				"mail.corp.test. CAA 0 issue \"other.test\"", "b.mail.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("mail.corp.test.", "CAA", false, true),
				caaCheck("b.mail.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
				caaCheck("a.www.corp.test.", "A", false, true),
				caaCheck("b.mail.corp.test.", "CAA", false, true),
				caaCheck("a.www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "a line below the apex with no apex line: only the names under that line get a probe",
			lines: []string{`www.corp.test. CAA 0 issue "ca.test"`, "a.www.corp.test. A 10.53.0.81", "x.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("www.corp.test.", "CAA", false, true),
				caaCheck("a.www.corp.test.", "A", false, true),
				caaCheck("x.corp.test.", "A", false, true),
				caaCheck("a.www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "an apex line none states no policy: no probe",
			lines: []string{"corp.test. CAA none", "www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "A", false, true),
			},
		},
		{
			name:  "an apex line that restricts nothing gives no probe",
			lines: []string{`corp.test. CAA 0 iodef "mailto:sec@corp.test"`, "www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "A", false, true),
			},
		},
		{
			name:  "a line that is open under both readings gives no probe",
			lines: []string{`corp.test. CAA 0 iodef "mailto:sec@corp.test" || 0 issue "ca.test; accounturi=a; accounturi=b" | 0 iodef "x"`, "www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "A", false, true),
			},
		},
		{
			name:  "one alternative that restricts nothing gives no probe",
			lines: []string{`corp.test. CAA 0 issue "ca.test" || 0 iodef "mailto:sec@corp.test"`, "www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("www.corp.test.", "A", false, true),
			},
		},
		{
			name: "below an open apex only the names under a restricting line get a probe",
			lines: []string{`corp.test. CAA 0 iodef "mailto:sec@corp.test"`, `www.corp.test. CAA 0 issue "ca.test"`,
				"a.www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("mail.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
				caaCheck("a.www.corp.test.", "A", false, true),
				caaCheck("a.www.corp.test.", "CAA", false, true),
			},
		},
		{
			name: "no probe for a name with a label that starts with an underscore; its parent gets one",
			lines: []string{caaApexLine, "_dmarc.corp.test. TXT none", "deep._dmarc.corp.test. TXT none",
				"_acme-challenge.www.corp.test. TXT none", "x._y.www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("_dmarc.corp.test.", "TXT", false, true),
				caaCheck("deep._dmarc.corp.test.", "TXT", false, true),
				caaCheck("_acme-challenge.www.corp.test.", "TXT", true, true),
				caaCheck("x._y.www.corp.test.", "A", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
			},
		},
		{
			name:  "no probe for a wildcard owner; its parent gets one",
			lines: []string{caaApexLine, "*.shop.corp.test. A 10.53.0.5", "*.corp.test. TXT none"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("*.corp.test.", "TXT", false, true),
				caaCheck("*.shop.corp.test.", "A", false, true),
				caaCheck("shop.corp.test.", "CAA", false, true),
			},
		},
		{
			name: "a name under a cut is probed with zone false; a name outside the domain and the host of a cut get none",
			fast: []string{"WWW.Corp.Test."},
			lines: []string{caaApexLine, "sub.corp.test. NS ns1.sub.corp.test.", "www.sub.corp.test. A 10.53.0.85",
				"edge.dnshost.test. A 10.53.0.84", "a.www.corp.test. A 10.53.0.81"},
			want: []string{
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("sub.corp.test.", "NS", false, false),
				caaCheck("www.sub.corp.test.", "A", false, false),
				caaCheck("a.www.corp.test.", "A", false, true),
				caaCheck("edge.dnshost.test.", "A", false, false),
				caaCheck("ns1.sub.corp.test.", "A", false, false),
				caaCheck("sub.corp.test.", "CAA", false, false),
				caaCheck("www.sub.corp.test.", "CAA", false, false),
				caaCheck("www.corp.test.", "CAA", true, true),
				caaCheck("a.www.corp.test.", "CAA", false, true),
			},
		},
		{
			name: "the probes come last: after the records checks, the target probes and the wildcard checks",
			lines: []string{caaApexLine, "corp.test. MX 10 mx.zeta.test.", "*.corp.test. A none", "www.corp.test. A 10.53.0.81",
				"deep.www.corp.test. A 10.53.0.83", "mail.corp.test. TXT none"},
			want: []string{
				caaCheck("corp.test.", "MX", true, true),
				caaCheck("corp.test.", "CAA", true, true),
				caaCheck("mail.corp.test.", "TXT", false, true),
				caaCheck("www.corp.test.", "A", false, true),
				caaCheck("deep.www.corp.test.", "A", false, true),
				caaCheck("mx.zeta.test.", "A", false, false),
				"wildcard corp.test. corp.test. A tier4 every 5m0s zone true",
				caaCheck("mail.corp.test.", "CAA", false, true),
				caaCheck("www.corp.test.", "CAA", false, true),
				caaCheck("deep.www.corp.test.", "CAA", false, true),
			},
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			dngqSame(t, dngqPlan(t, r.fast, r.lines...), r.want...)
		})
	}
}

// The domain has its own fast check when it has a CAA line; a probe of it
// would ask the same question twice.
func TestCAAProbeNeverAsksTheDomainOrTheSameKeyTwice(t *testing.T) {
	f := schFile(t, caaApexLine, "www.corp.test. A 10.53.0.81", "a.www.corp.test. CAA none", "b.www.corp.test. A 10.53.0.82")
	seen := map[string]int{}
	for _, c := range Plan(f, nil, schIv) {
		seen[c.Key.String()]++
	}
	for key, n := range seen {
		if n != 1 {
			t.Errorf("Plan holds %q %d times", key, n)
		}
	}
	if seen["records corp.test. corp.test. CAA"] != 1 {
		t.Errorf("the apex CAA check is not in the plan once: %v", seen)
	}
}

// ---- Rows: a change of the CAA policy explains a move of the serial ----

func TestCAAChangeExplainsTheRoundAsRecordSetDoes(t *testing.T) {
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
		s := schMoved(t)
		for i, k := range schZoneKeys(t) {
			var changes []decide.Change
			if i == 0 {
				changes = []decide.Change{{Op: op, Finding: decide.Finding{Rule: decide.RuleCAA, Check: k}, At: schSec(9)}}
			}
			_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i), changes...)
			schWantJudged(t, fmt.Sprintf("%s caa, then %s", op, k), moves, ok, false, nil)
		}
	}
}

// The control of the test above: the same round with no change reports the
// moves.
func TestRoundWithoutAChangeReportsTheMoves(t *testing.T) {
	s := schMoved(t)
	for i, k := range schZoneKeys(t) {
		_, moves, ok := schEnd(t, s, schUsable(t, k, schSec(8)), schSec(9+i))
		if i == 2 {
			schWantJudged(t, "a round without change", moves, ok, true, schBothMoved)
		}
	}
}

func TestOwnNoticeHoldsCAAInEveryOp(t *testing.T) {
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate, decide.OpResolve} {
		if !ownNotice(decide.Change{Op: op, Finding: decide.Finding{Rule: decide.RuleCAA}}) {
			t.Errorf("ownNotice of %s caa is false", op)
		}
	}
}

// ---- The composed property: a weakened CAA set is seen, a true zone is quiet ----

const (
	caaSeed  = 20261117
	caaCases = 1500
)

func caaRand(c int) *rand.Rand { return rand.New(rand.NewPCG(caaSeed, uint64(c))) }

func caaRR(flags uint8, tag, value string) dnswire.CAA {
	return dnswire.CAA{Flags: flags, Tag: tag, Value: value}
}

// caaPool are the sets of a file line and of the world: stricter and weaker
// than each other, with and without a wildcard part, an account, a method, a
// critical unknown tag, and sets that restrict nothing.
var caaPool = [][]dnswire.CAA{
	{caaRR(0, "issue", "ca1.test")},
	{caaRR(0, "issue", "ca2.test")},
	{caaRR(0, "issue", "ca1.test"), caaRR(0, "issue", "ca2.test")},
	{caaRR(0, "issue", ";")},
	{caaRR(0, "issue", "ca1.test; accounturi=https://ca1.test/acct/1")},
	{caaRR(0, "issue", "ca1.test"), caaRR(0, "issuewild", "ca2.test")},
	{caaRR(0, "issuewild", "ca1.test")},
	{caaRR(0, "issue", "ca1.test; validationmethods=dns-01")},
	{caaRR(0, "iodef", "mailto:sec@corp.test")},
	{caaRR(0, "issue", "ca1.test"), caaRR(0, "iodef", "mailto:sec@corp.test")},
	{caaRR(128, "tbs", "x"), caaRR(0, "issue", "ca1.test")},
	// The values below are read one way by a strict authority and another by
	// a permissive one: a critical unknown tag, a repeated or empty
	// accounturi, a repeated validationmethods, a method list with an empty
	// label.
	{caaRR(128, "tbs", "x"), caaRR(0, "iodef", "mailto:sec@corp.test")},
	{caaRR(0, "issue", "ca1.test; accounturi=a; accounturi=b")},
	{caaRR(0, "issue", "ca1.test; accounturi=")},
	{caaRR(0, "issue", "ca1.test; validationmethods=dns-01; validationmethods=http-01")},
	{caaRR(0, "issue", "ca1.test; validationmethods=dns-01,,http-01")},
	{caaRR(0, "issue", "ca2.test"), caaRR(128, "tbs", "x")},
}

// caaEvil is weaker than every set of the pool that restricts anything.
var caaEvil = []dnswire.CAA{caaRR(0, "issue", "evil.test")}

func caaRData(set []dnswire.CAA) []dnswire.RData {
	data := make([]dnswire.RData, len(set))
	for i, r := range set {
		data[i] = r
	}
	return data
}

func caaSetText(set []dnswire.CAA) string {
	texts := make([]string, len(set))
	for i, r := range set {
		texts[i] = fmt.Sprintf("%d %s %q", r.Flags, r.Tag, r.Value)
	}
	return strings.Join(texts, " | ")
}

// caaLabels are the labels of the random names; "*" and the ones with an
// underscore are no names of certificates.
var caaLabels = []string{"www", "mail", "api", "a", "b", "_dmarc", "_acme-challenge", "*"}

const (
	caaNone  = iota // the server has no set at the name
	caaSet          // the server gives the set
	caaAlias        // the name is an alias: the answer is a CNAME
)

type caaAnswer struct {
	kind int
	set  []dnswire.CAA
}

// caaWorld is what both servers answer at each name, by the lower-case name
// text; a name that is not there has no set.
type caaWorld map[string]caaAnswer

// caaCase is one random file and its list of names.
// names are the domain and then the names of the tree, in lower case; exact
// maps a name to the pool numbers of the alternatives of its exact CAA line.
type caaCase struct {
	names []string
	lines []string
	exact map[string][][]int
	file  *expect.File
}

// caaGenerate makes a tree of 1 to 6 names under corp.test. (at most 3 labels
// deep, some with "_" or "*" labels), a CAA line for some names, and an A
// line for each leaf.
func caaGenerate(t testing.TB, rng *rand.Rand) *caaCase {
	t.Helper()
	const domain = "corp.test."
	depth := func(n string) int { return strings.Count(n, ".") - 2 }
	var tree []string
	for range 1 + rng.IntN(6) {
		parents := []string{domain}
		for _, p := range tree {
			if depth(p) < 3 && !strings.HasPrefix(p, "*.") {
				parents = append(parents, p)
			}
		}
		name := schPick(rng, caaLabels...) + "." + schPick(rng, parents...)
		if !slices.Contains(tree, name) {
			tree = append(tree, name)
		}
	}
	c := &caaCase{names: append([]string{domain}, tree...), exact: map[string][][]int{}}
	leaf := func(n string) bool {
		return !slices.ContainsFunc(tree, func(o string) bool { return strings.HasSuffix(o, "."+n) })
	}
	for _, n := range c.names {
		line := ""
		switch r := rng.IntN(100); {
		case strings.HasPrefix(n, "*.") && r < 20:
			// An exact line at a wildcard owner is judged by the climb of its
			// parent, not as a line of its own.
			line = "none"
		case strings.HasPrefix(n, "*."):
		case r < 35:
			c.exact[n] = [][]int{{rng.IntN(len(caaPool))}}
		case r < 50:
			a := rng.IntN(len(caaPool))
			c.exact[n] = [][]int{{a}, {(a + 1 + rng.IntN(len(caaPool)-1)) % len(caaPool)}}
		case r < 70:
			line = "none"
		}
		if alts := c.exact[n]; alts != nil {
			texts := make([]string, len(alts))
			for i, alt := range alts {
				texts[i] = caaSetText(caaPool[alt[0]])
			}
			line = strings.Join(texts, " || ")
		}
		if line != "" {
			c.lines = append(c.lines, schShout(rng, n)+" CAA "+line)
		}
		if n != domain && leaf(n) {
			c.lines = append(c.lines, schShout(rng, n)+" A 10.53.0.99")
		}
	}
	c.file = schFile(t, c.lines...)
	return c
}

// caaMatchingWorld is the world that the file expects: each name with an exact
// line holds one of its alternatives, every other name no set.
func caaMatchingWorld(rng *rand.Rand, c *caaCase) caaWorld {
	w := caaWorld{}
	for _, n := range c.names {
		if alts := c.exact[n]; alts != nil {
			w[n] = caaAnswer{kind: caaSet, set: caaPool[schPick(rng, alts...)[0]]}
		}
	}
	return w
}

func caaRandomAnswer(rng *rand.Rand) caaAnswer {
	switch r := rng.IntN(10); {
	case r < 4:
		return caaAnswer{kind: caaSet, set: schPick(rng, caaPool...)}
	case r < 7:
		return caaAnswer{kind: caaNone}
	}
	return caaAnswer{kind: caaAlias}
}

// caaPerturb changes the answer at one or two names of w: the weakest set,
// no set, an alias or a set of the pool.
func caaPerturb(rng *rand.Rand, c *caaCase, w caaWorld) {
	for range 1 + rng.IntN(2) {
		n := schPick(rng, c.names...)
		switch r := rng.IntN(10); {
		case r < 5:
			w[n] = caaAnswer{kind: caaSet, set: caaEvil}
		case r < 6:
			w[n] = caaAnswer{kind: caaNone}
		case r < 7:
			w[n] = caaAnswer{kind: caaAlias}
		default:
			w[n] = caaAnswer{kind: caaSet, set: schPick(rng, caaPool...)}
		}
	}
}

// caaRelevant is RelevantCAASet of RFC 8659: the first set on the way from x
// up to the domain, read as an open policy when there is none. An alias is no
// set, and nothing above the domain is read.
func caaRelevant(w caaWorld, d, x dnswire.Name, r decide.Reading) decide.Policy {
	for n := x; n.IsSubdomainOf(d); n = n.Parent() {
		if a := w[n.Lower().String()]; a.kind == caaSet {
			p, _ := decide.PolicyOf(caaRData(a.set), r)
			return p
		}
	}
	return decide.OpenPolicy
}

func caaResult(t testing.TB, rng *rand.Rand, name string, a caaAnswer) obs.Result {
	t.Helper()
	n := schName(t, name)
	switch a.kind {
	case caaSet:
		var set []dnswire.Record
		for _, r := range a.set {
			set = append(set, dnswire.Record{Name: n, Class: dnswire.ClassINET, TTL: 300, Data: r})
		}
		return obs.RecordsResult(obs.Records{Set: set})
	case caaAlias:
		return obs.RecordsResult(obs.Records{Set: []dnswire.Record{{Name: n, Class: dnswire.ClassINET, TTL: 300,
			Data: dnswire.CNAME{Target: schName(t, "edge.dnshost.test.")}}}})
	}
	if rng.IntN(2) == 0 {
		return schNoData(t, 1)
	}
	return schNoName(t, 1)
}

// caaFindings runs the check of k against the world and gives the rules of
// its findings.
func caaFindings(t testing.TB, rng *rand.Rand, f *expect.File, w caaWorld, k obs.Key) []decide.Rule {
	t.Helper()
	name := k.Name.Lower().String()
	o := schObs(k, schT0,
		schAt(t, "ns1.corp.test.", schNS1, schSec(1), caaResult(t, rng, name, w[name])),
		schAt(t, "ns2.corp.test.", schNS2, schSec(2), caaResult(t, rng, name, w[name])))
	var rules []decide.Rule
	for _, found := range decide.Findings(f, o) {
		rules = append(rules, found.Rule)
	}
	return rules
}

func caaIsCAACheck(c Check) bool {
	return c.Key.Kind == obs.KindRecords && c.Key.Type == dnswire.TypeCAA
}

// caaKinds counts the cases by what they hold, so that a generator that stops
// making a kind shows.
type caaKinds struct {
	matching, weakened, random int
	// demanded: cases where a name has a relevant set weaker than the file's
	// policy; at a probe, or from a name above that holds the set.
	demanded, demandedAtProbe, demandedFromAbove int
	probes, aliasAtLine, setAtNone               int
	quietWithLines, twoAlternatives              int
	// demandedByOneReading: a name that counts under one reading only;
	// quietDiffering: a world equal to a file that holds a value that the
	// readings read differently.
	demandedByOneReading, quietDiffering int
}

// caaDiffers says that the two readings give another policy for set.
func caaDiffers(set []dnswire.CAA) bool {
	strict, _ := decide.PolicyOf(caaRData(set), decide.StrictReading)
	permissive, _ := decide.PolicyOf(caaRData(set), decide.PermissiveReading)
	return !reflect.DeepEqual(strict, permissive)
}

func TestCAAClimbComposedProperty(t *testing.T) {
	var kinds caaKinds
	for n := range caaCases {
		rng := caaRand(n)
		where := fmt.Sprintf("seed %d case %d", caaSeed, n)
		c := caaGenerate(t, rng)
		text := "domain corp.test.\n" + strings.Join(c.lines, "\n")
		d := c.file.Domain

		var fast []dnswire.Name
		for range rng.IntN(4) {
			fast = append(fast, schName(t, schShout(rng, schPick(rng, c.names...))))
		}
		iv := Intervals{Serial: schPick(rng, 5*time.Second, 7*time.Second), Parent: schPick(rng, 10*time.Second, 61*time.Second),
			Fast: schPick(rng, 6*time.Second, 43*time.Second), Other: schPick(rng, 20*time.Second, 300*time.Second)}
		plan := Plan(c.file, fast, iv)

		// The plan: the model of every check, one CAA check for each name of
		// CAANames, each key once, a name of the domain's own zone in the zone.
		if g, w := schTexts(plan), schTexts(schModelPlan(t, c.file, fast, iv)); !slices.Equal(g, w) {
			t.Fatalf("%s: file\n%s\n--fast %v\nPlan gave%s\nwant%s", where, text, fast, schShow(g), schShow(w))
		}
		keys := schKeyTexts(plan)
		if len(slices.Compact(slices.Sorted(slices.Values(keys)))) != len(keys) {
			t.Fatalf("%s: Plan holds a key twice:%s", where, schShow(keys))
		}
		names := caaModelNames(c.file)
		var got []string
		for _, n := range decide.CAANames(c.file) {
			got = append(got, n.Lower().String())
		}
		var want []string
		for _, n := range names {
			want = append(want, n.Lower().String())
		}
		if !slices.Equal(got, want) {
			t.Fatalf("%s: file\n%s\nCAANames gave %q, the climb gives %q", where, text, got, want)
		}
		var caaKeys, wantKeys []string
		for _, ch := range plan {
			if caaIsCAACheck(ch) {
				caaKeys = append(caaKeys, ch.Key.Name.Lower().String())
				if !ch.Zone {
					t.Fatalf("%s: file\n%s\nthe CAA check of %s is not in the zone of the domain", where, text, ch.Key.Name)
				}
			}
		}
		for _, n := range names {
			wantKeys = append(wantKeys, n.Lower().String())
		}
		for _, e := range c.file.Expectations {
			if e.Type == dnswire.TypeCAA {
				wantKeys = append(wantKeys, e.Name.Lower().String())
			}
		}
		slices.Sort(caaKeys)
		slices.Sort(wantKeys)
		if !slices.Equal(slices.Compact(wantKeys), caaKeys) {
			t.Fatalf("%s: file\n%s\nthe CAA checks of the plan are %q, want one for each name of CAANames and each line: %q",
				where, text, caaKeys, slices.Compact(wantKeys))
		}
		if len(caaModelProbes(c.file, fast, iv)) > 0 {
			kinds.probes++
		}

		// The world.
		w := caaWorld{}
		kind := n % 3
		switch kind {
		case 0:
			for _, name := range c.names {
				if a := caaRandomAnswer(rng); a.kind != caaNone {
					w[name] = a
				}
			}
			kinds.random++
		case 1:
			w = caaMatchingWorld(rng, c)
			kinds.matching++
		case 2:
			w = caaMatchingWorld(rng, c)
			caaPerturb(rng, c, w)
			kinds.weakened++
		}

		// No miss: when a name of CAANames has a relevant set that is weaker
		// than every alternative of the file's policy, some CAA check gives caa.
		// Like with like: under some reading R, the relevant set read by R
		// permits more than every alternative of the policy read by R.
		demanded := false
		for _, name := range names {
			sets, _ := caaFileSets(c.file, name)
			var under [2]bool
			for i, r := range caaReadings {
				rel := caaRelevant(w, d, name, r)
				under[i] = true
				for _, set := range sets {
					alt, _ := decide.PolicyOf(set, r)
					if _, ok := decide.Weaker(rel, alt); !ok {
						under[i] = false
					}
				}
			}
			if !under[0] && !under[1] {
				continue
			}
			if under[0] != under[1] {
				kinds.demandedByOneReading++
			}
			demanded = true
			if _, own := caaExactLine(c.file, name); !own {
				kinds.demandedAtProbe++
			}
			if w[name.Lower().String()].kind != caaSet {
				kinds.demandedFromAbove++
			}
		}
		gave, falseAlert := false, ""
		for _, ch := range plan {
			if !caaIsCAACheck(ch) {
				continue
			}
			for _, rule := range caaFindings(t, rng, c.file, w, ch.Key) {
				if rule == decide.RuleCAA {
					gave = true
				}
				if rule == decide.RuleCAA || rule == decide.RuleRecordSet || rule == decide.RuleNotCovered {
					falseAlert = fmt.Sprintf("%s gave %s", ch.Key, rule)
				}
			}
		}
		if demanded {
			kinds.demanded++
			if !gave {
				t.Fatalf("%s: file\n%s\nworld %s\na name has a relevant set that is weaker than the file's policy, and no check gave caa",
					where, text, caaShowWorld(w))
			}
		}

		// No false alert: when the world equals the file, nothing is reported.
		if kind == 1 {
			if falseAlert != "" {
				t.Fatalf("%s: file\n%s\nthe world equals the file, and %s", where, text, falseAlert)
			}
			if len(c.exact) > 0 {
				kinds.quietWithLines++
			}
			for _, a := range w {
				if caaDiffers(a.set) {
					kinds.quietDiffering++
					break
				}
			}
		}
		for name, a := range w {
			if _, line := caaExactLine(c.file, schName(t, name)); line && a.kind == caaAlias {
				kinds.aliasAtLine++
			}
			if e, ok := c.file.Find(schName(t, name), dnswire.TypeCAA); ok && e.Form == expect.FormNone && a.kind == caaSet {
				kinds.setAtNone++
			}
		}
		for _, alts := range c.exact {
			if len(alts) == 2 {
				kinds.twoAlternatives++
				break
			}
		}
	}
	t.Logf("seed %d: %+v", caaSeed, kinds)
	if kinds.demanded < 200 || kinds.demandedAtProbe < 50 || kinds.demandedFromAbove < 50 || kinds.probes < 200 ||
		kinds.aliasAtLine < 100 || kinds.setAtNone < 30 || kinds.quietWithLines < 250 || kinds.twoAlternatives < 150 ||
		kinds.demandedByOneReading < 50 || kinds.quietDiffering < 100 {
		t.Fatalf("seed %d: %+v: the cases miss a kind", caaSeed, kinds)
	}
}

func caaShowWorld(w caaWorld) string {
	var parts []string
	for _, name := range slices.Sorted(maps.Keys(w)) {
		a := w[name]
		switch a.kind {
		case caaSet:
			parts = append(parts, name+" "+caaSetText(a.set))
		case caaAlias:
			parts = append(parts, name+" alias")
		}
	}
	return "{" + strings.Join(parts, "; ") + "}"
}
