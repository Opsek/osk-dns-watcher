package observe

import (
	"net/netip"
	"sync"
	"time"
)

// limiter spaces the queries to each server address: a burst, then one
// query per interval (the generic cell rate algorithm). It reads no clock:
// the caller gives the time and does the waiting.
type limiter struct {
	interval time.Duration
	burst    int
	mu       sync.Mutex
	tat      map[netip.AddrPort]time.Time // when the next query would be due at the steady rate
}

func newLimiter(interval time.Duration, burst int) *limiter {
	return &limiter{interval: interval, burst: burst, tat: map[netip.AddrPort]time.Time{}}
}

// reserve books a slot for one query to server and returns when it may be
// sent, never before now. A slot that goes unused stays booked, so a caller
// that gives up cannot raise the rate.
func (l *limiter) reserve(server netip.AddrPort, now time.Time) time.Time {
	l.mu.Lock()
	defer l.mu.Unlock()
	// A time that has passed spaces nothing more, so its entry is dropped;
	// this keeps the table as small as the set of servers asked lately.
	for s, t := range l.tat {
		if !t.After(now) {
			delete(l.tat, s)
		}
	}
	t := l.tat[server]
	if t.Before(now) {
		t = now
	}
	l.tat[server] = t.Add(l.interval)
	sendAt := t.Add(-time.Duration(l.burst-1) * l.interval)
	if sendAt.Before(now) {
		return now
	}
	return sendAt
}
