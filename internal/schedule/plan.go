// Package schedule says which checks a file of expectations has, how often
// each runs, which are due, how long a check has been failing, and which
// checks a moved zone serial starts. It reads no clock: the caller passes
// every time, so the same calls with the same times give the same results.
package schedule

import (
	"slices"
	"strconv"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Tier is how often a check runs.
type Tier uint8

const (
	TierSerial Tier = iota + 1
	TierParent
	TierFast
	TierOther
	TierCertificates
)

var tierWords = map[Tier]string{
	TierSerial:       "serial",
	TierParent:       "parent",
	TierFast:         "fast",
	TierOther:        "other",
	TierCertificates: "certificates",
}

func (t Tier) String() string {
	if w, ok := tierWords[t]; ok {
		return w
	}
	return "tier" + strconv.Itoa(int(t))
}

// Intervals are the times between two starts of a check, one per tier.
// Certificates 0 turns the certificate check off.
type Intervals struct{ Serial, Parent, Fast, Other, Certificates time.Duration }

func Defaults() Intervals {
	return Intervals{Serial: 15 * time.Second, Parent: time.Minute, Fast: time.Minute, Other: 5 * time.Minute}
}

const (
	Floor      = 5 * time.Second // protects the servers: one check sends one query to each address
	Ceiling    = 24 * time.Hour  // keeps 60 × an interval far from the overflow of time.Duration
	MaxRunning = 16              // checks in flight at once: below observe's burst of 20 for one address
)

func (iv Intervals) Of(t Tier) time.Duration {
	switch t {
	case TierSerial:
		return iv.Serial
	case TierParent:
		return iv.Parent
	case TierFast:
		return iv.Fast
	case TierOther:
		return iv.Other
	case TierCertificates:
		return iv.Certificates
	}
	return 0
}

// FailLimit is how long the runs of a check may give no usable answer before
// it is reported. The limit follows the interval; at the defaults it is 5
// minutes for the 60 s tiers and 15 minutes for the others.
func (iv Intervals) FailLimit(t Tier) time.Duration {
	switch t {
	case TierSerial:
		return 60 * iv.Serial
	case TierParent:
		return 5 * iv.Parent
	case TierFast:
		return 5 * iv.Fast
	case TierOther:
		return 3 * iv.Other
	case TierCertificates:
		return 3 * iv.Certificates
	}
	return 0
}

type Check struct {
	Key      obs.Key
	Tier     Tier
	Interval time.Duration // iv.Of(Tier)
	Zone     bool          // a records or wildcard check of a name in the domain's own zone
}

// fastTypes at the domain itself: where it receives its web and mail
// traffic, and which certificate authorities may issue for it.
var fastTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCAA, dnswire.TypeMX}

// Plan gives the checks of f: the serial, delegation and DS checks of its
// domain, a records check for each expectation in file order, an address
// check for each name that a line points at, and a wildcard check for each
// zone that the file says has no wildcard, a policy check when it has an
// mta-sts line, a CAA check for each name whose CAA policy the file states
// only through a parent, and last the certificate check when its interval is
// set.
func Plan(f *expect.File, fast []dnswire.Name, iv Intervals) []Check {
	d := f.Domain
	checks := []Check{
		{Key: obs.SerialKey(d), Tier: TierSerial, Interval: iv.Of(TierSerial)},
		{Key: obs.DelegationKey(d), Tier: TierParent, Interval: iv.Of(TierParent)},
		{Key: obs.DSKey(d), Tier: TierParent, Interval: iv.Of(TierParent)},
	}
	wildcards := decide.Wildcards(f)
	for _, e := range f.Expectations {
		// The DS check judges the DS line, the only place a file may hold DS.
		if e.Type == dnswire.TypeDS {
			continue
		}
		// The wildcard check judges the line "*.<zone> A none"; a records
		// check as well would report one added wildcard twice. A line of
		// another type at a "*" owner is judged by its own records check
		// only: the wildcard check asks for A.
		if decide.IsWildcardOwner(e.Name) && e.Type == dnswire.TypeA && e.Form == expect.FormNone &&
			slices.ContainsFunc(wildcards, e.Name.Parent().Equal) {
			continue
		}
		tier := TierOther
		if e.Name.Equal(d) && slices.Contains(fastTypes, e.Type) || slices.ContainsFunc(fast, e.Name.Equal) || decide.IsChallenge(d, e.Name) {
			tier = TierFast
		}
		checks = append(checks, Check{
			Key:      obs.RecordsKey(d, e.Name, e.Type),
			Tier:     tier,
			Interval: iv.Of(tier),
			// A name outside the domain or in a declared subzone has another
			// serial than the domain's.
			Zone: e.Name.IsSubdomainOf(d) && f.Zone(e.Name).Equal(d),
		})
	}
	for _, t := range decide.Targets(f) {
		// A line "<target> A …" is the same check.
		if !slices.ContainsFunc(checks, func(c Check) bool {
			return c.Key.Kind == obs.KindRecords && c.Key.Type == dnswire.TypeA && c.Key.Name.Equal(t.Name)
		}) {
			checks = append(checks, Check{Key: obs.RecordsKey(d, t.Name, dnswire.TypeA), Tier: TierOther, Interval: iv.Of(TierOther)})
		}
	}
	for _, z := range wildcards {
		checks = append(checks, Check{
			Key:      obs.WildcardKey(d, z),
			Tier:     TierOther,
			Interval: iv.Of(TierOther),
			Zone:     z.IsSubdomainOf(d) && f.Zone(z).Equal(d),
		})
	}
	if policy, ok := obs.PolicyKey(d); ok && f.Policy != nil {
		// A policy update moves the id at _mta-sts.<d>, so the round that the
		// serial starts fetches the policy at once. That owner is one octet
		// longer than the host of the fetch, so it may not exist.
		record, err := dnswire.NameFromLabels(append([]string{"_mta-sts"}, d.Labels()...))
		checks = append(checks, Check{
			Key:      policy,
			Tier:     TierOther,
			Interval: iv.Of(TierOther),
			Zone:     err == nil && f.Zone(record).Equal(d),
		})
	}
	// A CAA set is inherited down the tree, so a name with no CAA line of its
	// own is still read: a policy added or removed there changes what a
	// certificate authority may issue for it.
	hasCAALine := map[string]bool{} // Name.Key() of each owner of a CAA line
	for _, e := range f.Expectations {
		if e.Type == dnswire.TypeCAA {
			hasCAALine[e.Name.Key()] = true
		}
	}
	for _, n := range decide.CAANames(f) {
		if hasCAALine[n.Key()] {
			continue
		}
		tier := TierOther
		if slices.ContainsFunc(fast, n.Equal) {
			tier = TierFast
		}
		checks = append(checks, Check{
			Key:      obs.RecordsKey(d, n, dnswire.TypeCAA),
			Tier:     tier,
			Interval: iv.Of(tier),
			Zone:     f.Zone(n).Equal(d),
		})
	}
	if iv.Certificates > 0 {
		checks = append(checks, Check{Key: obs.CertificatesKey(d), Tier: TierCertificates, Interval: iv.Certificates})
	}
	return checks
}

// Unused gives the names of fast that own no line of f, in the given order,
// so that the caller can report a name that was probably mistyped.
func Unused(f *expect.File, fast []dnswire.Name) []dnswire.Name {
	var unused []dnswire.Name
	for _, n := range fast {
		if !slices.ContainsFunc(f.Expectations, func(e expect.Expectation) bool { return e.Name.Equal(n) }) {
			unused = append(unused, n)
		}
	}
	return unused
}
