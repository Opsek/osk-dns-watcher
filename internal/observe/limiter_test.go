package observe

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"sync"
	"testing"
	"time"
)

// askRule is the rate rule written out: per server a time tat, zero at
// first; t = max(tat, now), sendAt = max(now, t-(B-1)T), tat = t+T.
type askRule struct {
	interval time.Duration
	burst    int
	tat      map[netip.AddrPort]time.Time
}

func (r *askRule) reserve(s netip.AddrPort, now time.Time) time.Time {
	t := r.tat[s]
	if now.After(t) {
		t = now
	}
	sendAt := t.Add(-time.Duration(r.burst-1) * r.interval)
	if sendAt.Before(now) {
		sendAt = now
	}
	r.tat[s] = t.Add(r.interval)
	return sendAt
}

var askServers = []netip.AddrPort{
	netip.MustParseAddrPort("10.53.7.11:53"),
	netip.MustParseAddrPort("10.53.7.11:5353"),
	netip.MustParseAddrPort("[fd53:0:0:7::11]:53"),
}

// TestAskLimiterFollowsRule compares the limiter with the rule on random
// sequences of requests in time order.
func TestAskLimiterFollowsRule(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 7))
	for round := range 50 {
		interval := time.Duration(1+rng.IntN(1000)) * time.Millisecond
		burst := 1 + rng.IntN(25)
		l := newLimiter(interval, burst)
		rule := &askRule{interval: interval, burst: burst, tat: map[netip.AddrPort]time.Time{}}
		now := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
		for i := range 300 {
			if rng.IntN(10) >= 4 {
				now = now.Add(time.Duration(rng.Int64N(int64(3 * interval))))
			}
			s := askServers[rng.IntN(len(askServers))]
			if got, want := l.reserve(s, now), rule.reserve(s, now); !got.Equal(want) {
				t.Fatalf("round %d (T %v, B %d), request %d to %v at %v: send at %v, want %v",
					round, interval, burst, i, s, now.Format(time.StampMilli), got.Sub(now), want.Sub(now))
			}
		}
	}
}

func TestAskLimiterProperties(t *testing.T) {
	const interval = 100 * time.Millisecond
	const burst = 5
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	s, other, port := askServers[0], askServers[2], askServers[1]

	t.Run("burst, then one per interval", func(t *testing.T) {
		l := newLimiter(interval, burst)
		for i := range burst + 3 {
			want := base.Add(time.Duration(max(0, i-burst+1)) * interval)
			if got := l.reserve(s, base); !got.Equal(want) {
				t.Errorf("request %d at one instant: send at +%v, want +%v", i+1, got.Sub(base), want.Sub(base))
			}
		}
		// The server was last booked for base+8T; from then on its full
		// burst is back.
		later := base.Add((burst + 3) * interval)
		for i := range burst {
			if got := l.reserve(s, later); !got.Equal(later) {
				t.Errorf("request %d after the server was idle: send at +%v, want at once", i+1, got.Sub(later))
			}
		}
		if got := l.reserve(s, later); !got.Equal(later.Add(interval)) {
			t.Errorf("request %d after the server was idle: send at +%v, want +%v", burst+1, got.Sub(later), interval)
		}
	})

	t.Run("servers do not affect each other", func(t *testing.T) {
		l := newLimiter(interval, burst)
		for range 3 * burst {
			l.reserve(s, base)
		}
		for _, x := range []netip.AddrPort{other, port} {
			for i := range burst {
				if got := l.reserve(x, base); !got.Equal(base) {
					t.Errorf("%v, request %d: send at +%v, want at once", x, i+1, got.Sub(base))
				}
			}
		}
	})

	t.Run("spacing", func(t *testing.T) {
		rng := rand.New(rand.NewPCG(1, 2))
		l := newLimiter(interval, burst)
		now := base
		var sendAt []time.Time
		for range 200 {
			now = now.Add(time.Duration(rng.Int64N(int64(interval))))
			at := l.reserve(s, now)
			if at.Before(now) {
				t.Fatalf("send at %v is before now %v", at, now)
			}
			sendAt = append(sendAt, at)
		}
		for i := range sendAt {
			for j := i + 1; j < len(sendAt); j++ {
				if least := time.Duration(j-i-(burst-1)) * interval; sendAt[j].Sub(sendAt[i]) < least {
					t.Fatalf("requests %d and %d: %v apart, want at least %v", i, j, sendAt[j].Sub(sendAt[i]), least)
				}
			}
		}
	})
}

// TestAskLimiterDropsPassedEntries: a server whose time has passed holds no
// entry, so the table keeps only the servers still being spaced.
func TestAskLimiterDropsPassedEntries(t *testing.T) {
	const interval = 100 * time.Millisecond
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	l := newLimiter(interval, 5)
	for i := range 1000 {
		l.reserve(netip.AddrPortFrom(askServers[0].Addr(), uint16(1000+i)), base)
	}
	later := base.Add(interval)
	if got := l.reserve(askServers[0], later); !got.Equal(later) {
		t.Errorf("request after the others' time passed: send at +%v, want at once", got.Sub(later))
	}
	if n := len(l.tat); n != 1 {
		t.Errorf("%d entries once the time of 1000 of them has passed, want 1", n)
	}
}

func TestAskLimiterConcurrent(t *testing.T) {
	const interval = 10 * time.Millisecond
	const burst = 10
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	l := newLimiter(interval, burst)
	var mu sync.Mutex
	var got []time.Duration
	var wg sync.WaitGroup
	for range 100 {
		wg.Go(func() {
			d := l.reserve(askServers[0], base).Sub(base)
			mu.Lock()
			got = append(got, d)
			mu.Unlock()
		})
	}
	wg.Wait()
	slices.Sort(got)
	for k, d := range got {
		if want := time.Duration(max(0, k-burst+1)) * interval; d != want {
			t.Fatalf("sorted request %d sends at +%v, want +%v", k+1, d, want)
		}
	}
}

func TestAskLimiterSettings(t *testing.T) {
	base := time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		cfg      Config
		interval time.Duration
		burst    int
	}{
		{Config{}, 50 * time.Millisecond, 20},
		{Config{RateInterval: 200 * time.Millisecond, RateBurst: 2}, 200 * time.Millisecond, 2},
	} {
		o, err := New(c.cfg)
		if err != nil {
			t.Fatal(err)
		}
		for i := range c.burst + 2 {
			want := base.Add(time.Duration(max(0, i-c.burst+1)) * c.interval)
			if got := o.limit.reserve(askServers[0], base); !got.Equal(want) {
				t.Errorf("RateInterval %v RateBurst %d, request %d: send at +%v, want +%v",
					c.cfg.RateInterval, c.cfg.RateBurst, i+1, got.Sub(base), want.Sub(base))
			}
		}
	}
}
