package observe

import (
	"slices"
	"sync"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// These bound the memory of the cache, and how long a cut stays in it,
// whatever the servers send.
const (
	maxCuts = 4096
	maxTTL  = 7 * 24 * time.Hour
)

// cutCache holds the zone cuts that earlier checks learned, so a walk need
// not start at the root every time. It keeps cuts and their addresses only,
// never answers.
type cutCache struct {
	mu   sync.Mutex
	cuts map[string]cutEntry // by Name.Key() of the cut
}

type cutEntry struct {
	zone   zoneServers
	expiry time.Time
}

func newCutCache() *cutCache {
	return &cutCache{cuts: make(map[string]cutEntry)}
}

// get returns the deepest cut that holds target (strictly under it, with
// parent) and is fresh for a check run every interval. Fresh means within
// the TTL, and learned less than one interval ago: so a changed delegation
// reaches the walk of every check within that check's own interval.
func (c *cutCache) get(target dnswire.Name, parent bool, now time.Time, interval time.Duration) (zoneServers, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	name := target
	if parent {
		name = target.Parent()
	}
	for ; name.LabelCount() > 0; name = name.Parent() {
		e, ok := c.cuts[name.Key()]
		if ok && now.Before(e.expiry) && now.Sub(e.zone.learned) < interval {
			return e.zone, true
		}
	}
	return zoneServers{}, false
}

// put stores z, received at the time given and valid for ttl seconds from
// then, in place of any older entry for the same cut. When the cache is
// full, the entry learned first makes room, so no entry stays for good.
func (c *cutCache) put(z zoneServers, received time.Time, ttl uint32) {
	c.mu.Lock()
	defer c.mu.Unlock()
	key := z.name.Key()
	if _, ok := c.cuts[key]; !ok && len(c.cuts) >= maxCuts {
		c.dropOldest()
	}
	z.servers = slices.Clone(z.servers)
	z.proof = slices.Clone(z.proof)
	c.cuts[key] = cutEntry{zone: z, expiry: received.Add(min(time.Duration(ttl)*time.Second, maxTTL))}
}

func (c *cutCache) dropOldest() {
	var oldest string
	var learned time.Time
	for k, e := range c.cuts {
		if oldest == "" || e.zone.learned.Before(learned) {
			oldest, learned = k, e.zone.learned
		}
	}
	delete(c.cuts, oldest)
}
