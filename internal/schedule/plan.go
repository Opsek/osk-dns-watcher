// Package schedule says which checks a file of expectations has, how often
// each runs, which are due, how long a check has been failing, and which
// checks a moved zone serial starts. It reads no clock: the caller passes
// every time, so the same calls with the same times give the same results.
package schedule

import (
	"slices"
	"strconv"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Tier is how often a check runs.
type Tier uint8

const (
	TierSerial Tier = iota + 1
	TierParent
	TierFast
	TierOther
)

var tierWords = map[Tier]string{
	TierSerial: "serial",
	TierParent: "parent",
	TierFast:   "fast",
	TierOther:  "other",
}

func (t Tier) String() string {
	if w, ok := tierWords[t]; ok {
		return w
	}
	return "tier" + strconv.Itoa(int(t))
}

// Intervals are the times between two starts of a check, one per tier.
type Intervals struct{ Serial, Parent, Fast, Other time.Duration }

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
	}
	return 0
}

type Check struct {
	Key      obs.Key
	Tier     Tier
	Interval time.Duration // iv.Of(Tier)
	Zone     bool          // a records check of a name in the domain's own zone
}

// fastTypes at the domain itself: where it receives its web and mail
// traffic, and which certificate authorities may issue for it.
var fastTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCAA, dnswire.TypeMX}

// Plan gives the checks of f: the serial, delegation and DS checks of its
// domain, then a records check for each expectation in file order.
func Plan(f *expect.File, fast []dnswire.Name, iv Intervals) []Check {
	d := f.Domain
	checks := []Check{
		{Key: obs.SerialKey(d), Tier: TierSerial, Interval: iv.Of(TierSerial)},
		{Key: obs.DelegationKey(d), Tier: TierParent, Interval: iv.Of(TierParent)},
		{Key: obs.DSKey(d), Tier: TierParent, Interval: iv.Of(TierParent)},
	}
	owners := fastOwners(d, fast)
	for _, e := range f.Expectations {
		// The DS check judges the DS line, the only place a file may hold DS.
		if e.Type == dnswire.TypeDS {
			continue
		}
		tier := TierOther
		if e.Name.Equal(d) && slices.Contains(fastTypes, e.Type) || slices.ContainsFunc(owners, e.Name.Equal) {
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
	return checks
}

// fastOwners are the names whose lines are all fast: the given names, and
// the owner of the ACME DNS challenge of the domain (RFC 8555 section 8.4),
// where the challenge record, or an alias that hands it to another zone, lets
// whoever controls it obtain a certificate for the domain.
func fastOwners(d dnswire.Name, fast []dnswire.Name) []dnswire.Name {
	owners := slices.Clone(fast)
	// A domain too long for the challenge name cannot have that line.
	if acme, err := dnswire.NameFromLabels(append([]string{"_acme-challenge"}, d.Labels()...)); err == nil {
		owners = append(owners, acme)
	}
	return owners
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
