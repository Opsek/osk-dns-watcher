package observe

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// walkCut is the cut name with one server, learned at the time given.
func walkCut(t *testing.T, name string, learned time.Time) zoneServers {
	t.Helper()
	return zoneServers{
		name:    walkName(t, name),
		servers: []obs.Server{{Name: walkName(t, "ns."+name), Addr: walkAddr(t, "10.0.1.1")}},
		learned: learned,
	}
}

// TestWalkCacheEvictsOldest: a full cache makes room for a new cut by
// dropping the cut learned first, also when no cut has expired.
func TestWalkCacheEvictsOldest(t *testing.T) {
	c := newCutCache()
	for i := range maxCuts {
		at := walkT0.Add(time.Duration(i) * time.Second)
		c.put(walkCut(t, fmt.Sprintf("z%d.test.", i), at), at, math.MaxUint32)
	}
	now := walkT0.Add(maxCuts * time.Second)
	c.put(walkCut(t, "new.test.", now), now, 300)
	if len(c.cuts) != maxCuts {
		t.Errorf("the cache holds %d cuts, want %d", len(c.cuts), maxCuts)
	}
	for name, want := range map[string]bool{"www.new.test.": true, "www.z0.test.": false, "www.z1.test.": true} {
		if _, ok := c.get(walkName(t, name), false, now, math.MaxInt64); ok != want {
			t.Errorf("a cut for %s found: %v, want %v", name, ok, want)
		}
	}
}

// TestWalkCacheTTLAtMostSevenDays: a TTL above seven days counts as seven
// days, so a cut cannot stay for good.
func TestWalkCacheTTLAtMostSevenDays(t *testing.T) {
	c := newCutCache()
	c.put(walkCut(t, "corp.test.", walkT0), walkT0, 30*24*3600)
	week := 7 * 24 * time.Hour
	for _, tt := range []struct {
		at   time.Duration
		want bool
	}{{week - time.Second, true}, {week, false}} {
		if _, ok := c.get(walkName(t, "www.corp.test."), false, walkT0.Add(tt.at), math.MaxInt64); ok != tt.want {
			t.Errorf("after %v the cut is found: %v, want %v", tt.at, ok, tt.want)
		}
	}
}
