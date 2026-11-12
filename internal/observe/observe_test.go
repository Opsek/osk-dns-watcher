package observe

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

func TestWalkNewConfig(t *testing.T) {
	bad := map[string]Config{
		"zero root address":        {RootServers: []netip.AddrPort{{}}},
		"unspecified IPv4 root":    {RootServers: []netip.AddrPort{netip.MustParseAddrPort("0.0.0.0:53")}},
		"unspecified IPv6 root":    {RootServers: []netip.AddrPort{netip.MustParseAddrPort("[::]:53")}},
		"invalid prefix":           {ExtraRanges: []netip.Prefix{{}}},
		"negative query timeout":   {QueryTimeout: -time.Nanosecond},
		"negative rate interval":   {RateInterval: -time.Nanosecond},
		"negative burst":           {RateBurst: -1},
		"one bad root among valid": {RootServers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.1:53"), {}}},
	}
	for name, cfg := range bad {
		if _, err := New(cfg); err == nil {
			t.Errorf("New with %s: no error", name)
		}
	}
	if _, err := New(Config{}); err != nil {
		t.Errorf("New(Config{}): %v", err)
	}

	// A root server given without a port is asked on port 53.
	w := walkBase(t)
	o, err := New(Config{
		RootServers:  []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("10.0.0.1"), 0)},
		ExtraRanges:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		RateInterval: time.Nanosecond,
		RateBurst:    1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.exchange = w.exchange
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	if asked := w.queries(); len(asked) == 0 || asked[0].server != walkAddr(t, "10.0.0.1") {
		t.Errorf("first query went to %v, want 10.0.0.1:53", asked)
	}
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW})
}

// TestWalkRunValidation: a check that cannot be run is refused before any
// packet, with an error that names the wrong field.
func TestWalkRunValidation(t *testing.T) {
	corp, www := walkName(t, "corp.test."), walkName(t, "www.corp.test.")
	records := func(typ dnswire.Type) obs.Key { return obs.RecordsKey(corp, www, typ) }
	tests := []struct {
		name     string
		key      obs.Key
		interval time.Duration
		field    string
	}{
		{"kind 0", obs.Key{Domain: corp, Name: corp, Type: dnswire.TypeNS}, time.Minute, "kind"},
		{"kind 5", obs.Key{Kind: 5, Domain: corp, Name: corp, Type: dnswire.TypeNS}, time.Minute, "kind"},
		{"delegation of the root", obs.DelegationKey(dnswire.Name{}), time.Minute, "domain"},
		{"records under the root domain", obs.RecordsKey(dnswire.Name{}, www, dnswire.TypeA), time.Minute, "domain"},
		{"delegation of another name", obs.Key{Kind: obs.KindDelegation, Domain: corp, Name: www, Type: dnswire.TypeNS}, time.Minute, "name"},
		{"serial of another name", obs.Key{Kind: obs.KindSerial, Domain: corp, Name: www, Type: dnswire.TypeSOA}, time.Minute, "name"},
		{"delegation of type A", obs.Key{Kind: obs.KindDelegation, Domain: corp, Name: corp, Type: dnswire.TypeA}, time.Minute, "type"},
		{"ds of type NS", obs.Key{Kind: obs.KindDS, Domain: corp, Name: corp, Type: dnswire.TypeNS}, time.Minute, "type"},
		{"serial of type NS", obs.Key{Kind: obs.KindSerial, Domain: corp, Name: corp, Type: dnswire.TypeNS}, time.Minute, "type"},
		{"records of type 0", records(0), time.Minute, "type"},
		{"records of OPT", records(dnswire.TypeOPT), time.Minute, "type"},
		{"records of TSIG", records(dnswire.TypeTSIG), time.Minute, "type"},
		{"records of AXFR", records(dnswire.TypeAXFR), time.Minute, "type"},
		{"records of IXFR", records(dnswire.TypeIXFR), time.Minute, "type"},
		{"records of ANY", records(dnswire.TypeANY), time.Minute, "type"},
		{"records of NXNAME", records(dnswire.TypeNXNAME), time.Minute, "type"},
		{"records of DS", records(dnswire.TypeDS), time.Minute, "type"},
		{"interval below 1s", records(dnswire.TypeA), time.Second - time.Nanosecond, "interval"},
		{"interval 0", records(dnswire.TypeA), 0, "interval"},
		{"negative interval", records(dnswire.TypeA), -time.Minute, "interval"},
	}
	w := walkBase(t)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	for _, tt := range tests {
		ob, err := o.Run(context.Background(), Check{Key: tt.key, Interval: tt.interval})
		if !errors.Is(err, ErrInvalidCheck) {
			t.Errorf("%s: error %v, want ErrInvalidCheck", tt.name, err)
			continue
		}
		if !strings.Contains(strings.ToLower(err.Error()), tt.field) {
			t.Errorf("%s: error %q does not name the field %s", tt.name, err, tt.field)
		}
		if len(ob.Answers) != 0 || len(ob.Walk) != 0 {
			t.Errorf("%s: an observation came with the error", tt.name)
		}
	}
	if n := len(w.queries()); n != 0 {
		t.Errorf("invalid checks sent %d queries", n)
	}

	valid := []struct {
		name     string
		key      obs.Key
		interval time.Duration
	}{
		{"interval of exactly 1s", records(dnswire.TypeA), time.Second},
		{"records of CNAME", records(dnswire.TypeCNAME), time.Minute},
		{"records of an unknown type", records(dnswire.Type(65280)), time.Minute},
		{"records of a name outside the domain", obs.RecordsKey(corp, walkName(t, "edge.dnshost.test."), dnswire.TypeA), time.Minute},
		{"delegation whose name differs only in case", obs.Key{Kind: obs.KindDelegation, Domain: corp, Name: walkName(t, "CORP.test."), Type: dnswire.TypeNS}, time.Minute},
	}
	for _, tt := range valid {
		if _, err := o.Run(context.Background(), Check{Key: tt.key, Interval: tt.interval}); err != nil {
			t.Errorf("%s: %v", tt.name, err)
		}
	}
}

// TestWalkRunTwice: while a check runs, the same check is refused at once
// and sends nothing; another check of the same zone runs to its end.
func TestWalkRunTwice(t *testing.T) {
	w := walkBase(t)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	www := walkName(t, "www.corp.test.")
	for _, a := range []string{"10.0.1.1", "10.0.1.2"} {
		server := walkAddr(t, a)
		w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			if q.Name.Equal(www) && q.Type == dnswire.TypeA {
				select {
				case entered <- struct{}{}:
				default:
				}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return w.answer(server, q), nil
		})
	}
	o := walkObserver(t, w, &walkClock{}, 10*time.Second)
	key := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)

	type result struct {
		ob  obs.Observation
		err error
	}
	first := make(chan result, 1)
	go func() {
		ob, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute})
		first <- result{ob, err}
	}()
	// Both servers of corp.test. hold the first check's last questions.
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("the first check never asked both servers of corp.test.")
		}
	}

	before := len(w.queries())
	start := time.Now()
	for _, k := range []obs.Key{key, walkRecordsKey(t, "CORP.test.", "WWW.corp.test.", dnswire.TypeA)} {
		if _, err := o.Run(context.Background(), Check{Key: k, Interval: time.Minute}); !errors.Is(err, ErrRunning) {
			t.Errorf("second Run of %v: %v, want ErrRunning", k, err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the second Run took %v, want an answer at once", d)
	}
	if n := len(w.queries()) - before; n != 0 {
		t.Errorf("the refused Run sent %d queries", n)
	}

	other := walkRun(t, o, walkRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "other check", walkAnswers(other.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 records mail.corp.test. 300 IN A 10.9.0.82",
		"ns2.corp.test. 10.0.1.2:53 records mail.corp.test. 300 IN A 10.9.0.82",
	})

	close(release)
	r := <-first
	if r.err != nil {
		t.Fatalf("first Run: %v", r.err)
	}
	walkWant(t, "first check", walkAnswers(r.ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW})
	if _, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute}); err != nil {
		t.Errorf("Run after the first ended: %v", err)
	}
}

// TestWalkDeadline: a check ends at three quarters of its interval, also
// when the query timeout is longer. The walk asks one server of corp.test.,
// whose query the deadline cuts; the other is not asked before the deadline.
// Both read deadline: the check, not the server, ran out of time.
func TestWalkDeadline(t *testing.T) {
	w := walkBase(t)
	w.handle("10.0.1.1", walkDead)
	w.handle("10.0.1.2", walkDead)
	o := walkObserver(t, w, &walkClock{}, 10*time.Second)

	start := time.Now()
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Second)
	if d := time.Since(start); d > 750*time.Millisecond+500*time.Millisecond {
		t.Errorf("Run took %v, want 750ms and the time to assemble the result", d)
	}
	if !ob.Start.Equal(walkT0) || ob.Deadline.Sub(ob.Start) != 750*time.Millisecond {
		t.Errorf("Start %v, Deadline %v; want the observer's clock and 750ms later", ob.Start, ob.Deadline)
	}
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 failure deadline",
		"ns2.corp.test. 10.0.1.2:53 failure deadline",
	})
}

// TestWalkDeadlineLongInterval: the deadline of the longest intervals still
// lies three quarters of the interval ahead; its computation cannot overflow.
func TestWalkDeadlineLongInterval(t *testing.T) {
	for _, interval := range []time.Duration{math.MaxInt64, 1 << 62} {
		w := walkBase(t)
		ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), interval)
		if d := ob.Deadline.Sub(ob.Start); d != interval-interval/4 {
			t.Errorf("interval %v: Deadline - Start = %v, want %v", interval, d, interval-interval/4)
		}
		walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW})
	}
}

// TestWalkAnswersSorted: one answer for each host and address, sorted by
// host in canonical order, then by address; an address shared by two hosts
// is asked once.
func TestWalkAnswersSorted(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.2", "test.", walkTLD(
		"corp.test. 300 NS ns3.corp.test.", "corp.test. 300 NS b.corp.test.", "corp.test. 300 NS a.z.corp.test.",
		"ns3.corp.test. 300 A 10.0.1.10", "ns3.corp.test. 300 A 10.0.1.9",
		"b.corp.test. 300 A 10.0.1.9", "a.z.corp.test. 300 A 10.0.1.10")...)
	w.serve("10.0.1.9 10.0.1.10", "corp.test.", walkCorpZone...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"b.corp.test. 10.0.1.9:53 " + walkWWW,
		"ns3.corp.test. 10.0.1.9:53 " + walkWWW,
		"ns3.corp.test. 10.0.1.10:53 " + walkWWW,
		"a.z.corp.test. 10.0.1.10:53 " + walkWWW,
	})
	for _, a := range []string{"10.0.1.9", "10.0.1.10"} {
		if n := w.count(a, "www.corp.test.", dnswire.TypeA); n != 1 {
			t.Errorf("%s was asked www.corp.test. A %d times, want once", a, n)
		}
	}
}

// TestWalkFanOutConcurrent: the addresses of the zone are asked at once.
// Each server holds its answer until all four questions have arrived, which
// happens only when they are in flight together.
func TestWalkFanOutConcurrent(t *testing.T) {
	w := walkBase(t)
	addrs := []string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4"}
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "ns1.corp.test. 300 A 10.0.1.1",
		"ns1.corp.test. 300 A 10.0.1.2", "ns1.corp.test. 300 A 10.0.1.3", "ns1.corp.test. 300 A 10.0.1.4")...)
	w.serve(strings.Join(addrs, " "), "corp.test.", walkCorpZone...)
	var mu sync.Mutex
	arrived, together := 0, make(chan struct{})
	for _, a := range addrs {
		server := walkAddr(t, a)
		w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			if q.Type == dnswire.TypeA {
				mu.Lock()
				if arrived++; arrived == len(addrs) {
					close(together)
				}
				mu.Unlock()
				select {
				case <-together:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return w.answer(server, q), nil
		})
	}
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	for _, a := range ob.Answers {
		if walkCase(a.Result) != walkWWW {
			t.Errorf("%s: %s; the questions to the zone were not in flight together", walkServer(a.Server), walkCase(a.Result))
		}
	}
	if len(ob.Answers) != len(addrs) {
		t.Errorf("%d answers, want %d", len(ob.Answers), len(addrs))
	}
}
