// Package observe finds the authoritative servers of a name by its own walk
// down from the root servers, asks every address of them, and returns each
// answer with the proof of what was received. It never asks a resolver: its
// only way to the network is dnswire.Exchange. A check of kind policy is not
// DNS: it is handed to Config.Policy.
package observe

import (
	"cmp"
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Config holds the settings of an Observer. The zero Config asks the
// built-in root servers and public addresses only.
type Config struct {
	RootServers  []netip.AddrPort // empty: the built-in root servers; port 0 means 53
	ExtraRanges  []netip.Prefix   // addresses outside the public internet that may be asked, as in a lab
	QueryTimeout time.Duration    // one exchange, its TCP retry included; 0 means 2s
	RateInterval time.Duration    // per server address, after the burst; 0 means 50ms
	RateBurst    int              // 0 means 20
	// Policy runs a check of kind policy. nil: such a check gives one
	// failure answer, reason not-permitted.
	Policy func(ctx context.Context, k obs.Key) obs.Answer
}

// Check is one observation to make. The caller runs it every Interval, so a
// run ends after three quarters of it, before the next one is due.
type Check struct {
	Key      obs.Key
	Interval time.Duration // at least 1s
}

var (
	ErrInvalidCheck = errors.New("observe: invalid check")
	ErrRunning      = errors.New("observe: check already running")
)

type exchangeFunc func(ctx context.Context, server netip.AddrPort, q dnswire.Query, tcp bool) (*dnswire.Response, error)

// Observer runs checks. Checks share only the rate limits, the cookies and
// the cache of zone cuts, each under its own lock; no check waits for another.
type Observer struct {
	cfg      Config
	roots    []obs.Server
	exchange exchangeFunc     // replaceable, so tests need no network
	now      func() time.Time // replaceable, so tests need no real clock
	label    func() string    // the random label of a wildcard check; replaceable, so tests know the name asked
	limit    *limiter
	cookies  *cookieJar
	cache    *cutCache
	mu       sync.Mutex      // guards running
	running  map[string]bool // Key.String() of the checks in progress
}

// New checks cfg and fills in its defaults.
func New(cfg Config) (*Observer, error) {
	if cfg.QueryTimeout < 0 || cfg.RateInterval < 0 || cfg.RateBurst < 0 {
		return nil, fmt.Errorf("observe: negative setting: query timeout %v, rate interval %v, rate burst %d",
			cfg.QueryTimeout, cfg.RateInterval, cfg.RateBurst)
	}
	roots := builtinRoots()
	if len(cfg.RootServers) > 0 {
		var err error
		if cfg.RootServers, roots, err = rootServers(cfg.RootServers); err != nil {
			return nil, err
		}
	}
	ranges := make([]netip.Prefix, 0, len(cfg.ExtraRanges))
	for _, p := range cfg.ExtraRanges {
		if !p.IsValid() {
			return nil, fmt.Errorf("observe: invalid extra range %v", p)
		}
		ranges = append(ranges, p.Masked())
	}
	cfg.ExtraRanges = ranges
	cfg.QueryTimeout = cmp.Or(cfg.QueryTimeout, 2*time.Second)
	cfg.RateInterval = cmp.Or(cfg.RateInterval, 50*time.Millisecond)
	cfg.RateBurst = cmp.Or(cfg.RateBurst, 20)
	return &Observer{
		cfg:      cfg,
		roots:    roots,
		exchange: dnswire.Exchange,
		now:      time.Now,
		// rand.Text gives at least 26 characters, so the cut cannot fail; it
		// keeps a longer text of a later Go from making Run refuse a key that
		// Validate accepted.
		label:   func() string { return strings.ToLower(rand.Text())[:obs.WildcardLabel] },
		limit:   newLimiter(cfg.RateInterval, cfg.RateBurst),
		cookies: newCookieJar(),
		cache:   newCutCache(),
		running: make(map[string]bool),
	}, nil
}

// rootServers checks the configured root servers. Their names are not
// known, so each is a server named by the root.
func rootServers(addrs []netip.AddrPort) ([]netip.AddrPort, []obs.Server, error) {
	var fixed []netip.AddrPort
	var servers []obs.Server
	for _, a := range addrs {
		if !a.Addr().IsValid() || a.Addr().IsUnspecified() {
			return nil, nil, fmt.Errorf("observe: invalid root server %v", a)
		}
		if a.Port() == 0 {
			a = netip.AddrPortFrom(a.Addr(), 53)
		}
		if slices.Contains(fixed, a) {
			continue
		}
		fixed = append(fixed, a)
		servers = append(servers, obs.Server{Addr: a})
	}
	return fixed, servers, nil
}

// Run makes one observation. Its only errors are ErrInvalidCheck and
// ErrRunning, and then nothing was sent; every other outcome is in the
// Observation.
func (o *Observer) Run(ctx context.Context, c Check) (obs.Observation, error) {
	if err := c.Validate(); err != nil {
		return obs.Observation{}, err
	}
	key := c.Key.String()
	o.mu.Lock()
	if o.running[key] {
		o.mu.Unlock()
		return obs.Observation{}, ErrRunning
	}
	o.running[key] = true
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		delete(o.running, key)
		o.mu.Unlock()
	}()
	q, err := o.question(c.Key)
	if err != nil {
		return obs.Observation{}, err
	}

	// Three quarters of the interval; Interval*3 could overflow.
	limit := c.Interval - c.Interval/4
	start := o.now()
	ob := obs.Observation{Key: c.Key, Start: start, Deadline: start.Add(limit)}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	if c.Key.Kind == obs.KindPolicy {
		ob.Zone = c.Key.Domain
		ob.Answers = []obs.Answer{o.policy(ctx, c.Key, q)}
		return ob, nil
	}

	f := &finder{
		o:        o,
		s:        o.newSession(ob.Deadline),
		ctx:      ctx,
		interval: c.Interval,
		descent:  count{queries: descentQueries, steps: stepsPerQuery * descentQueries},
		lookups:  count{queries: lookupQueries, steps: stepsPerQuery * lookupQueries},
		active:   make(map[string]bool),
		done:     make(map[string]hostAddrs),
		logged:   make(map[zoneAddr]bool),
		shown:    make(map[string]bool),
	}
	f.use(&f.descent)
	parent := c.Key.Kind == obs.KindDelegation || c.Key.Kind == obs.KindDS
	z, fail := f.walk(c.Key.Name, parent)
	ob.Walk = f.log
	if fail != nil {
		ob.Answers = []obs.Answer{{Proof: obs.Proof{Question: q, Received: o.now()}, Result: obs.FailureResult(*fail)}}
		return ob, nil
	}
	ob.Zone = z.name
	ob.Answers = f.fanOut(c.Key.Kind, z, q)
	return ob, nil
}

func (o *Observer) policy(ctx context.Context, k obs.Key, q dnswire.Question) obs.Answer {
	if o.cfg.Policy == nil {
		return obs.Answer{
			Proof:  obs.Proof{Server: obs.Server{Name: k.Name}, Question: q, Received: o.now()},
			Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonNotPermitted, Detail: "no policy client"}),
		}
	}
	return o.cfg.Policy(ctx, k)
}

// question is what the fan-out asks. A wildcard check asks a name drawn anew
// for each run, so that no one can create that one name ahead of it. Only
// the fan-out asks it: the walk asks the servers on its way down for the NS
// set of Key.Name.
func (o *Observer) question(k obs.Key) (dnswire.Question, error) {
	q := dnswire.Question{Name: k.Name, Type: k.Type, Class: dnswire.ClassINET}
	if k.Kind != obs.KindWildcard {
		return q, nil
	}
	label := o.label()
	name, err := childName(label, k.Name)
	if err != nil {
		return dnswire.Question{}, fmt.Errorf("%w: the random label %q makes no name under %v: %v", ErrInvalidCheck, label, k.Name, err)
	}
	q.Name = name
	return q, nil
}

func childName(label string, parent dnswire.Name) (dnswire.Name, error) {
	return dnswire.NameFromLabels(append([]string{label}, parent.Labels()...))
}

// notRecordSets are the types that a records check cannot ask: they are not
// record sets of a zone, or, for DS, the set lives at the parent and has a
// check of its own.
var notRecordSets = map[dnswire.Type]bool{
	0:                  true,
	dnswire.TypeOPT:    true,
	dnswire.TypeTSIG:   true,
	dnswire.TypeAXFR:   true,
	dnswire.TypeIXFR:   true,
	dnswire.TypeANY:    true,
	dnswire.TypeNXNAME: true,
	dnswire.TypeDS:     true,
}

// Validate returns the error that Run would give c, wrapping ErrInvalidCheck,
// so that a caller can refuse a set of checks before any of them sends.
func (c Check) Validate() error {
	k := c.Key
	var want dnswire.Type
	switch k.Kind {
	case obs.KindDelegation:
		want = dnswire.TypeNS
	case obs.KindDS:
		want = dnswire.TypeDS
	case obs.KindSerial:
		want = dnswire.TypeSOA
	case obs.KindRecords:
		if notRecordSets[k.Type] {
			return fmt.Errorf("%w: Type %v cannot be checked as a record set", ErrInvalidCheck, k.Type)
		}
	case obs.KindWildcard:
		want = dnswire.TypeA
		if _, err := childName(strings.Repeat("a", obs.WildcardLabel), k.Name); err != nil {
			return fmt.Errorf("%w: Name %v leaves no room for a label of %d octets", ErrInvalidCheck, k.Name, obs.WildcardLabel)
		}
	case obs.KindCertificates:
		return fmt.Errorf("%w: kind certificates is not a check of the DNS", ErrInvalidCheck)
	case obs.KindPolicy:
		// The fetch goes to the host that Name gives, so Name must be the
		// one that the domain fixes.
		want = dnswire.TypeTXT
		if p, ok := obs.PolicyKey(k.Domain); !ok || k.String() != p.String() {
			return fmt.Errorf("%w: not the policy key of %v", ErrInvalidCheck, k.Domain)
		}
	default:
		return fmt.Errorf("%w: Kind %v", ErrInvalidCheck, k.Kind)
	}
	switch {
	case k.Domain.LabelCount() == 0:
		return fmt.Errorf("%w: Domain is the root", ErrInvalidCheck)
	case k.Kind != obs.KindRecords && k.Kind != obs.KindWildcard && k.Kind != obs.KindPolicy && !k.Name.Equal(k.Domain):
		return fmt.Errorf("%w: Name %v differs from Domain %v", ErrInvalidCheck, k.Name, k.Domain)
	case k.Kind != obs.KindRecords && k.Type != want:
		return fmt.Errorf("%w: Type %v, but a %v check asks %v", ErrInvalidCheck, k.Type, k.Kind, want)
	case c.Interval < time.Second:
		return fmt.Errorf("%w: Interval %v is below 1s", ErrInvalidCheck, c.Interval)
	}
	return nil
}

// fanOut asks the first fanOutAddrs distinct addresses of z the question of
// the check, all at once, and gives each (host, address) of z the answer of
// its address; a later address gets budget. Each address may be asked twice,
// for a new cookie, so the fan-out sends without a count.
func (f *finder) fanOut(kind obs.Kind, z zoneServers, q dnswire.Question) []obs.Answer {
	f.s.spendFrom(nil)
	asked := uniqueAddrs(z.servers)
	got := make([]obs.Answer, len(asked))
	index := make(map[netip.AddrPort]int, len(asked))
	var wg sync.WaitGroup
	for i, srv := range asked {
		index[srv.Addr] = i
		if i >= fanOutAddrs {
			got[i] = obs.Answer{
				Proof:  obs.Proof{Server: srv, Question: q, Received: f.o.now()},
				Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonBudget, Detail: fmt.Sprintf("a check asks %d addresses of a zone", fanOutAddrs)}),
			}
			continue
		}
		wg.Go(func() {
			proof, m, fail := f.s.ask(f.ctx, srv, q)
			var r obs.Result
			if fail != nil {
				r = obs.FailureResult(*fail)
			} else {
				r = classify(kind, z.name, q, m)
			}
			got[i] = obs.Answer{Proof: proof, Result: r}
		})
	}
	wg.Wait()

	answers := make([]obs.Answer, 0, len(z.servers))
	for _, srv := range z.servers {
		i, ok := index[srv.Addr]
		if !ok {
			answers = append(answers, obs.Answer{
				Proof:  obs.Proof{Server: srv, Question: q, Received: f.o.now()},
				Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonWalk, Detail: "no address for " + srv.Name.String()}),
			})
			continue
		}
		a := got[i]
		a.Server = srv
		answers = append(answers, a)
	}
	slices.SortFunc(answers, func(a, b obs.Answer) int {
		return cmp.Or(dnswire.Compare(a.Server.Name, b.Server.Name), a.Server.Addr.Compare(b.Server.Addr))
	})
	return answers
}

// uniqueAddrs returns one server for each address of servers, and leaves out
// the hosts without address. It gives the first address of every host, then
// the second of every host, and so on: a host with many addresses cannot
// push those of the other hosts out of what a check asks.
func uniqueAddrs(servers []obs.Server) []obs.Server {
	seen := make(map[netip.AddrPort]bool, len(servers))
	rank := make(map[string]int, len(servers)) // addresses taken so far, for each host
	var byRank [][]obs.Server
	for _, s := range servers {
		if !s.Addr.IsValid() || seen[s.Addr] {
			continue
		}
		seen[s.Addr] = true
		r := rank[s.Name.Key()]
		rank[s.Name.Key()]++
		if r == len(byRank) {
			byRank = append(byRank, nil)
		}
		byRank[r] = append(byRank[r], s)
	}
	return slices.Concat(byRank...)
}
