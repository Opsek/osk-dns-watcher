package start

import (
	"context"
	"slices"
	"sync"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// checkInterval is the interval of each check, as osk snapshot gives it: a
// check ends after three quarters of it.
const checkInterval = 60 * time.Second

// view is what init learned of one domain.
type view struct {
	domain     dnswire.Name
	delegation obs.Observation
	file       *expect.File
	skips      []expect.Skip
	unreached  int // IPv6 addresses left out of the lines
}

// lookAll looks at every domain at once. Each check ends by itself and runs
// at most twice; the one limit holds the whole look whatever the Runner does.
func lookAll(ctx context.Context, r Runner, domains []dnswire.Name) []view {
	ctx, cancel := context.WithTimeout(ctx, 2*checkInterval)
	defer cancel()
	views := make([]view, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Go(func() { views[i] = look(ctx, r, d) })
	}
	wg.Wait()
	return views
}

// look runs the checks of one domain at once and makes its snapshot. A
// server that misses one query would leave its set out of the file for good,
// so each DNS check with such a failure answer runs once more. The second
// observation is used only when it holds no more failure answers than the
// first, so the retry never makes the look worse.
func look(ctx context.Context, r Runner, domain dnswire.Name) view {
	keys := lookKeys(domain)
	observations := runKeys(ctx, r, keys)
	// A domain that has set up no MTA-STS record is not asked for a policy
	// file: osk must not connect to a host that the domain never set up.
	if policy, ok := WantsPolicy(domain, observations); ok {
		observations = append(observations, runKeys(ctx, r, []obs.Key{policy})...)
	}
	file, skips := expect.Snapshot(domain, observations)
	return view{domain: domain, delegation: observations[0], file: file, skips: skips,
		unreached: len(expect.Unreached(observations))}
}

// WantsPolicy gives the check of the MTA-STS policy file of domain when the
// observations show that its _mta-sts record is on: one record that reads,
// which every server gave. A record that a provider hosts through a CNAME
// gets no line in a snapshot, so it gets no fetch either.
func WantsPolicy(domain dnswire.Name, observations []obs.Observation) (obs.Key, bool) {
	policy, ok := obs.PolicyKey(domain)
	if !ok {
		return obs.Key{}, false
	}
	file, _ := expect.Snapshot(domain, observations)
	for _, e := range file.Expectations {
		if e.Type == dnswire.TypeTXT && e.Name.Parent().Equal(domain) && expect.MailKindOf(e.Name) == expect.MailMTASTS {
			return policy, e.Form == expect.FormSets && len(e.Sets) == 1 && expect.STSOn(e.Sets[0])
		}
	}
	return obs.Key{}, false
}

// runKeys runs the checks of keys at once. A check with a failure answer,
// other than a policy check, runs once more, and the second observation is
// used only when it holds no more failure answers than the first. After
// Ctrl-C or the limit, no query is sent again.
func runKeys(ctx context.Context, r Runner, keys []obs.Key) []obs.Observation {
	observations := make([]obs.Observation, len(keys))
	atOnce(len(keys), func(i int) {
		o, err := r.Run(ctx, observe.Check{Key: keys[i], Interval: checkInterval})
		if err != nil {
			// Only a check that is not valid or already running fails,
			// and nothing was sent: it reads as a set with no answer.
			o = obs.Observation{Key: keys[i], Answers: []obs.Answer{{}}}
		}
		observations[i] = o
	})
	// After Ctrl-C or the limit, no query is sent again.
	if ctx.Err() == nil {
		atOnce(len(keys), func(i int) {
			first := observations[i]
			// A second fetch of a policy file seconds after the first tells
			// nothing new.
			if keys[i].Kind == obs.KindPolicy || !slices.ContainsFunc(first.Answers, worthRetry) {
				return
			}
			o, err := r.Run(ctx, observe.Check{Key: keys[i], Interval: checkInterval})
			if err == nil && failures(o) <= failures(first) {
				observations[i] = o
			}
		})
	}
	return observations
}

// atOnce calls f(i) for each i below n, each in its own goroutine, and waits
// for all of them.
func atOnce(n int, f func(int)) {
	var wg sync.WaitGroup
	for i := range n {
		wg.Go(func() { f(i) })
	}
	wg.Wait()
}

// failures counts the failure answers of o.
func failures(o obs.Observation) int {
	n := 0
	for _, a := range o.Answers {
		n += obs.Match(a.Result,
			func(obs.Records) int { return 0 },
			func(obs.NoData) int { return 0 },
			func(obs.NoName) int { return 0 },
			func(obs.Failure) int { return 1 })
	}
	return n
}

// worthRetry reports a failure answer that a second run could change. An
// IPv6 address that failed with network is not one: the snapshot leaves it
// out, and on a machine without IPv6 every check would run twice for nothing.
func worthRetry(a obs.Answer) bool {
	return obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(f obs.Failure) bool { return f.Reason != obs.ReasonNetwork || !a.Server.Addr.Addr().Is6() })
}

// lookKeys gives the delegation first, then the checks that osk snapshot
// makes of "<d> A <d> AAAA <d> MX <d> TXT <d> CAA www.<d> A
// _dmarc.<d> TXT _mta-sts.<d> TXT", then the names where a wildcard or a certificate challenge would show. A name longer than
// a name may be is left out.
func lookKeys(domain dnswire.Name) []obs.Key {
	keys := []obs.Key{obs.DelegationKey(domain), obs.DSKey(domain), obs.RecordsKey(domain, domain, dnswire.TypeNS)}
	for _, t := range []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCAA} {
		keys = append(keys, obs.RecordsKey(domain, domain, t))
	}
	for _, p := range []struct {
		prefix []string
		t      dnswire.Type
	}{
		{[]string{"www"}, dnswire.TypeA},
		{[]string{"_dmarc"}, dnswire.TypeTXT},
		{[]string{"_mta-sts"}, dnswire.TypeTXT},
		{[]string{"_acme-challenge"}, dnswire.TypeTXT},
		{[]string{"_acme-challenge", "www"}, dnswire.TypeTXT},
		{[]string{"*"}, dnswire.TypeA},
	} {
		if n, err := dnswire.NameFromLabels(append(slices.Clone(p.prefix), domain.Labels()...)); err == nil {
			keys = append(keys, obs.RecordsKey(domain, n, p.t))
		}
	}
	return keys
}
