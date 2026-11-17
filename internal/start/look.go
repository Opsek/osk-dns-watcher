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
// so each check with such a failure answer runs once more. The second
// observation is used only when it holds no more failure answers than the
// first, so the retry never makes the look worse.
func look(ctx context.Context, r Runner, domain dnswire.Name) view {
	keys := lookKeys(domain)
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
			if !slices.ContainsFunc(first.Answers, worthRetry) {
				return
			}
			o, err := r.Run(ctx, observe.Check{Key: keys[i], Interval: checkInterval})
			if err == nil && failures(o) <= failures(first) {
				observations[i] = o
			}
		})
	}
	file, skips := expect.Snapshot(domain, observations)
	return view{domain: domain, delegation: observations[0], file: file, skips: skips,
		unreached: len(expect.Unreached(observations))}
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
// makes of "<d> A <d> AAAA <d> MX <d> TXT <d> CAA www.<d> A", then the names
// where a wildcard or a certificate challenge would show. A name longer than
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
