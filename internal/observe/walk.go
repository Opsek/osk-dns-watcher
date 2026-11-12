package observe

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The walk cannot loop, because a referral is followed only when it leads
// strictly down toward the name asked. These bounds keep a lying server from
// making it long or wide.
const (
	maxReferrals = 16 // followed in one walk or sub-walk
	maxHosts     = 32 // NS hosts taken from one referral
	maxAddrs     = 16 // addresses kept for one host
	maxDepth     = 3  // sub-walks nested in one another
	// One entry names the hosts of a referral that had more addresses than
	// the walk keeps; its text stops at this length.
	maxNote = 1024
	// A check has three counts of queries, and none borrows from another, so
	// that what servers do in one part cannot starve another part.
	descentQueries = 32  // the walk's own questions toward the name of the check
	lookupQueries  = 128 // all the sub-walks that look for the addresses of hosts
	fanOutAddrs    = 32  // addresses of the final zone that are asked
	subWalkQueries = 16  // at most, for one sub-walk that the walk starts
	// The descent and the look-ups have 4 walk steps for each query. A step
	// is one entry of the Walk. Replays count: an answer from earlier in the
	// check sends nothing but takes memory.
	stepsPerQuery = 4
)

// zoneServers is a zone and its servers, one per (host, address); a host
// without address has the zero Addr.
type zoneServers struct {
	name    dnswire.Name
	servers []obs.Server
	// learned is when the oldest cut that the list rests on was learned: a
	// list found through cached cuts is as old as they are.
	learned time.Time
	proof   []obs.Answer // the referral and the addresses it dropped, for a walk that starts here
}

// delegation is a referral that the walk follows.
type delegation struct {
	name  dnswire.Name
	hosts []dnswire.Name
	glue  []dnswire.Record
	ttl   uint32     // smallest TTL of its NS records
	entry obs.Answer // the referral, as logged
}

// hostAddrs are the addresses of one host, the smallest TTL of the records
// that gave them, and when the list of the servers that gave them was learned.
type hostAddrs struct {
	addrs   []netip.Addr
	ttl     uint32
	dropped int // distinct addresses after the first maxAddrs
	learned time.Time
}

// count is what one part of a check may still use.
type count struct{ queries, steps int }

// part is what a sub-walk that the walk starts may use: an even part of c
// for the n hosts that need one, and at most the part of one host.
func (c count) part(n int) count {
	return count{
		queries: min(subWalkQueries, c.queries/n),
		steps:   min(stepsPerQuery*subWalkQueries, c.steps/n),
	}
}

type zoneAddr struct {
	zone string // dnswire.Name.Key
	addr netip.AddrPort
}

// finder holds the walk of one check. It runs in a single goroutine.
type finder struct {
	o        *Observer
	s        *session
	ctx      context.Context
	interval time.Duration
	log      []obs.Answer // every answer tried or used, in order
	descent  count
	lookups  count
	cur      *count               // of the walk or sub-walk in progress
	active   map[string]bool      // hosts whose sub-walk is in progress
	done     map[string]hostAddrs // hosts whose sub-walk has ended
	logged   map[zoneAddr]bool    // addresses whose failure is in the log, for each zone
	shown    map[string]bool      // cuts whose proof is in the log
	// incomplete: a skipped or cut sub-walk may have missed an address. No
	// cut is cached after that, or later walks would miss it too.
	incomplete bool
}

// walk goes down toward target from the deepest fresh cut in the cache, or
// from the root servers. It returns the zone that holds target or, with
// parent, the zone that delegates target. When no address of a zone gives
// a usable answer, the walk ends at that zone, so the fan-out shows each
// address's own failure.
func (f *finder) walk(target dnswire.Name, parent bool) (zoneServers, *obs.Failure) {
	z := f.start(target, parent)
	for referrals := 0; ; referrals++ {
		next, fail := f.descend(z, target, parent, referrals)
		if fail != nil || next == nil {
			return z, fail
		}
		z = *next
	}
}

// start gives the deepest cut in the cache that holds target and is fresh
// for the check, else the root. The first time in a check that it gives a
// cut, it logs how the cut was learned; without room for that, it gives the
// root.
func (f *finder) start(target dnswire.Name, parent bool) zoneServers {
	now := f.o.now()
	z, ok := f.o.cache.get(target, parent, now, f.interval)
	shown := ok && f.shown[z.name.Key()]
	if !ok || !shown && !f.step(len(z.proof)) {
		return zoneServers{servers: f.o.roots, learned: now}
	}
	if !shown {
		f.shown[z.name.Key()] = true
		f.log = append(f.log, z.proof...)
	}
	return z
}

// descend asks the addresses of z, one at a time in random order, for the
// NS set of target. It returns the zone of the referral it follows, or nil
// when the walk ends at z. A referral whose hosts have no address is not
// followed. One whose addresses may not be asked is followed only when no
// other address of z gives a better answer, so that the fan-out shows them.
func (f *finder) descend(z zoneServers, target dnswire.Name, parent bool, referrals int) (*zoneServers, *obs.Failure) {
	q := dnswire.Question{Name: target, Type: dnswire.TypeNS, Class: dnswire.ClassINET}
	var fallback *zoneServers
	var noAddress *obs.Failure
	for _, srv := range f.order(z) {
		proof, m, end := f.ask(z.name, srv, q)
		if end != nil {
			return nil, end
		}
		if m == nil {
			continue
		}
		cut, hosts, glue, ok := referral(z.name, target, m)
		if !ok {
			if _, ok := f.authority(z.name, q, proof, m); ok {
				return nil, nil
			}
			continue
		}
		ns := obs.Records{Set: rrset(m.Authority, cut, dnswire.TypeNS), Glue: glue}
		entry := obs.Answer{Proof: proof, Result: obs.RecordsResult(ns)}
		f.add(entry)
		switch {
		case parent && cut.Equal(target):
			return nil, nil
		case referrals == maxReferrals:
			return nil, failWalk("more than %d referrals toward %v", maxReferrals, target)
		}
		next, askable := f.follow(z, delegation{name: cut, hosts: hosts, glue: glue, ttl: ns.TTL(), entry: entry})
		switch {
		case askable:
			return next, nil
		case next == nil:
			noAddress = failWalk("no address for any server of %v", cut)
		case fallback == nil:
			fallback = next
		}
	}
	if fallback != nil {
		return fallback, nil
	}
	return nil, noAddress
}

// follow finds the servers of d, a referral from a server of z, and caches
// the cut when its list is complete. next is nil when no host has an
// address; askable reports that some address may be asked.
func (f *finder) follow(z zoneServers, d delegation) (next *zoneServers, askable bool) {
	found, ttl := f.servers(z, d)
	if !slices.ContainsFunc(found.servers, func(s obs.Server) bool { return s.Addr.IsValid() }) {
		return nil, false
	}
	askable = slices.ContainsFunc(found.servers, func(s obs.Server) bool {
		return s.Addr.IsValid() && permitted(s.Addr.Addr(), f.o.cfg.ExtraRanges)
	})
	// After the deadline, a host may lack an address because its look-up was cut.
	if askable && !f.incomplete && f.ctx.Err() == nil {
		f.o.cache.put(found, d.entry.Received, ttl)
		f.shown[d.name.Key()] = true
	}
	return &found, askable
}

// servers finds the addresses of the hosts of d, a referral from a server
// of z: from the glue, or else from a sub-walk.
func (f *finder) servers(z zoneServers, d delegation) (next zoneServers, ttl uint32) {
	hosts := d.hosts[:min(len(d.hosts), maxHosts)]
	pending := 0 // hosts without glue, which share the look-ups
	for _, host := range hosts {
		if !slices.ContainsFunc(d.glue, func(r dnswire.Record) bool { return r.Name.Equal(host) }) {
			pending++
		}
	}
	next = zoneServers{name: d.name, learned: z.learned, proof: []obs.Answer{d.entry}}
	ttl = d.ttl
	var lost []string // hosts that had more addresses than the walk keeps
	for _, host := range hosts {
		found := hostGlue(host, d)
		if len(found.addrs) == 0 {
			found = f.subwalk(host, pending)
			pending--
		}
		if found.dropped > 0 {
			lost = append(lost, fmt.Sprintf("%v lost %d", host, found.dropped))
		}
		if len(found.addrs) == 0 {
			next.servers = append(next.servers, obs.Server{Name: host})
			continue
		}
		ttl = min(ttl, found.ttl)
		if found.learned.Before(next.learned) {
			next.learned = found.learned
		}
		for _, a := range found.addrs {
			next.servers = append(next.servers, obs.Server{Name: host, Addr: netip.AddrPortFrom(a, 53)})
		}
	}
	// One entry tells it for the whole referral, so the proof of a cut is
	// at most two entries. Without a step for it, the cut is not cached.
	if len(lost) > 0 && f.step(1) {
		detail := fmt.Sprintf("kept the first %d addresses of each host: %s", maxAddrs, strings.Join(lost, ", "))
		e := obs.Answer{
			Proof:  obs.Proof{Question: d.entry.Question, Received: f.o.now()},
			Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonWalk, Detail: detail[:min(len(detail), maxNote)]}),
		}
		f.add(e)
		next.proof = append(next.proof, e)
	}
	return next, ttl
}

// hostGlue returns the addresses that the glue of d gives host. The glue
// holds only records under the zone of the server that sent it.
func hostGlue(host dnswire.Name, d delegation) hostAddrs {
	h := hostAddrs{learned: d.entry.Received}
	for _, r := range d.glue {
		if r.Name.Equal(host) {
			h.add(r)
		}
	}
	return h
}

// subwalk finds the addresses of a host that came without glue: it walks to
// the zone that holds host and asks that zone for the A and AAAA sets. A
// host gets one sub-walk in a check. One that the walk starts uses its part
// of the look-ups left for the n hosts that need one; a nested one uses the
// part of the sub-walk that started it. A host gets none, and no address,
// when its own sub-walk is in progress (a cycle), when it would be nested
// too deep, or when its part is used up.
func (f *finder) subwalk(host dnswire.Name, n int) hostAddrs {
	key := host.Key()
	if h, ok := f.done[key]; ok {
		return h
	}
	top := len(f.active) == 0
	share := *f.cur
	if top {
		share = f.lookups.part(n)
	}
	if f.active[key] || len(f.active) >= maxDepth || share.queries == 0 || share.steps == 0 {
		f.incomplete = true
		return hostAddrs{}
	}
	if top {
		f.lookups.queries -= share.queries
		f.lookups.steps -= share.steps
		f.use(&share)
	}
	f.active[key] = true
	z, fail := f.walk(host, false)
	h := hostAddrs{learned: z.learned}
	if fail == nil {
		for _, t := range []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA} {
			for _, r := range f.lookup(z, host, t) {
				h.add(r)
			}
		}
	}
	delete(f.active, key)
	if top {
		f.use(&f.descent)
		f.lookups.queries += share.queries
		f.lookups.steps += share.steps
	}
	f.done[key] = h
	return h
}

// lookup asks the addresses of z, one at a time in random order, for the set
// of name and type, until one answers with authority, and returns that set.
// A CNAME gives no address (RFC 2181 §10.3), so only A and AAAA are used.
func (f *finder) lookup(z zoneServers, name dnswire.Name, t dnswire.Type) []dnswire.Record {
	q := dnswire.Question{Name: name, Type: t, Class: dnswire.ClassINET}
	for _, srv := range f.order(z) {
		proof, m, end := f.ask(z.name, srv, q)
		if end != nil {
			return nil
		}
		if m == nil {
			continue
		}
		if set, ok := f.authority(z.name, q, proof, m); ok {
			return set
		}
	}
	return nil
}

// ask asks srv, a server of zone, the question q, and logs a failure; the
// caller logs an answer. It returns the failure that ends the walk or
// sub-walk in progress when that has no step or no query left.
func (f *finder) ask(zone dnswire.Name, srv obs.Server, q dnswire.Question) (obs.Proof, *dnswire.Message, *obs.Failure) {
	if !f.step(1) {
		return obs.Proof{}, nil, failWalk("the walk has taken all the steps it may take, in zone %v", zone)
	}
	p, m, fail := f.s.ask(f.ctx, srv, q)
	if fail == nil {
		return p, m, nil
	}
	f.add(obs.Answer{Proof: p, Result: obs.FailureResult(*fail)})
	if fail.Reason == obs.ReasonBudget {
		f.incomplete = true
		return p, nil, failWalk("the walk has sent all the queries it may send, in zone %v", zone)
	}
	f.logged[zoneAddr{zone.Key(), srv.Addr}] = true
	return p, nil, nil
}

// authority logs m, the answer of a server of zone to q, and reports whether
// it comes from a server that holds the name, with its records, if any.
func (f *finder) authority(zone dnswire.Name, q dnswire.Question, p obs.Proof, m *dnswire.Message) ([]dnswire.Record, bool) {
	r := classify(obs.KindRecords, zone, q, m)
	f.add(obs.Answer{Proof: p, Result: r})
	var set []dnswire.Record
	ok := obs.Match(r,
		func(x obs.Records) bool { set = x.Set; return true },
		func(obs.NoData) bool { return true },
		func(obs.NoName) bool { return true },
		func(obs.Failure) bool { return false })
	return set, ok
}

// step takes n walk steps from the count in use. When not that many are
// left, it takes none, and the walk in progress must stop.
func (f *finder) step(n int) bool {
	if f.cur.steps < n {
		f.incomplete = true
		return false
	}
	f.cur.steps -= n
	return true
}

func (f *finder) use(c *count) {
	f.cur = c
	f.s.spendFrom(&c.queries)
}

// order returns the addresses of z as uniqueAddrs ranks them, shuffled first
// so that no single server is always asked first. It leaves out an address
// that is down and already logged for z, which would only log it again.
func (f *finder) order(z zoneServers) []obs.Server {
	zone := z.name.Key()
	var s []obs.Server
	for _, srv := range z.servers {
		if !f.logged[zoneAddr{zone, srv.Addr}] || !f.s.isDown(srv.Addr) {
			s = append(s, srv)
		}
	}
	rand.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
	return uniqueAddrs(s)
}

func (f *finder) add(a obs.Answer) {
	f.log = append(f.log, a)
}

func (h *hostAddrs) add(r dnswire.Record) {
	var a netip.Addr
	switch d := r.Data.(type) {
	case dnswire.A:
		a = d.Addr
	case dnswire.AAAA:
		a = d.Addr
	default:
		return
	}
	if slices.Contains(h.addrs, a) {
		return
	}
	// A referral can carry thousands of addresses; each would be asked.
	if len(h.addrs) == maxAddrs {
		h.dropped++
		return
	}
	if len(h.addrs) == 0 || r.TTL < h.ttl {
		h.ttl = r.TTL
	}
	h.addrs = append(h.addrs, a)
}

func failWalk(format string, args ...any) *obs.Failure {
	return &obs.Failure{Reason: obs.ReasonWalk, Detail: fmt.Sprintf(format, args...)}
}
