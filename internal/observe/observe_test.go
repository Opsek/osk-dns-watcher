package observe

import (
	"context"
	"errors"
	"math"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
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
		{"kind 8", obs.Key{Kind: 8, Domain: corp, Name: corp, Type: dnswire.TypeNS}, time.Minute, "kind"},
		{"certificates", obs.CertificatesKey(corp), time.Minute, "kind"},
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

// The certificate check reads no DNS, so the observer refuses it, and says
// so whatever else is wrong with the key.
func TestValidateRefusesCertificates(t *testing.T) {
	corp := walkName(t, "corp.test.")
	want := ErrInvalidCheck.Error() + ": kind certificates is not a check of the DNS"
	for _, c := range []Check{
		{Key: obs.CertificatesKey(corp), Interval: time.Minute},
		{Key: obs.CertificatesKey(corp), Interval: 0},
		{Key: obs.CertificatesKey(dnswire.Name{}), Interval: time.Minute},
	} {
		err := c.Validate()
		if !errors.Is(err, ErrInvalidCheck) || err.Error() != want {
			t.Errorf("Validate of %v: %v; want %q", c, err, want)
		}
	}
}

// mtsObserver asks the fake world for DNS, with its clock standing at walkT0,
// and hands a check of kind policy to policy.
func mtsObserver(t *testing.T, w *walkWorld, policy func(context.Context, obs.Key) obs.Answer) *Observer {
	t.Helper()
	o, err := New(Config{
		RootServers:  []netip.AddrPort{walkAddr(t, "10.0.0.1")},
		ExtraRanges:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		RateInterval: time.Nanosecond,
		RateBurst:    1000,
		Policy:       policy,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.exchange = w.exchange
	o.now = (&walkClock{}).get
	return o
}

func mtsPolicyKey(t *testing.T, domain string) obs.Key {
	t.Helper()
	k, ok := obs.PolicyKey(walkName(t, domain))
	if !ok {
		t.Fatalf("PolicyKey(%s): not ok", domain)
	}
	return k
}

// A check of kind policy fetches from the host that its Name gives, so only
// the key that its domain fixes is valid. Any other is refused before Policy
// is called, with a text that names the domain.
func TestValidatePolicy(t *testing.T) {
	corp := walkName(t, "corp.test.")
	k := mtsPolicyKey(t, "corp.test.")
	for _, key := range []obs.Key{
		k,
		mtsPolicyKey(t, "Corp.TEST."),
		{Kind: obs.KindPolicy, Domain: corp, Name: walkName(t, "MTA-STS.Corp.test."), Type: dnswire.TypeTXT},
	} {
		if err := (Check{Key: key, Interval: time.Second}).Validate(); err != nil {
			t.Errorf("Validate(%v): %v", key, err)
		}
	}

	withName := func(name string) obs.Key { c := k; c.Name = walkName(t, name); return c }
	withType := func(typ dnswire.Type) obs.Key { c := k; c.Type = typ; return c }
	// Labels of 63, 63, 63 and 61 octets: the domain fits, its policy host does not.
	long, err := dnswire.NameFromLabels([]string{strings.Repeat("a", 63), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)})
	if err != nil {
		t.Fatal(err)
	}
	notPolicy := func(domain string) string { return ErrInvalidCheck.Error() + ": not the policy key of " + domain }
	for _, c := range []struct {
		name     string
		key      obs.Key
		interval time.Duration
		want     string // the whole text; "" when only ErrInvalidCheck is asserted
	}{
		{"the domain as Name", withName("corp.test."), time.Minute, notPolicy("corp.test.")},
		{"the host of another domain", withName("mta-sts.shop.test."), time.Minute, notPolicy("corp.test.")},
		{"a name under the host", withName("x.mta-sts.corp.test."), time.Minute, notPolicy("corp.test.")},
		{"a name without the first label", withName("mta-sts.test."), time.Minute, notPolicy("corp.test.")},
		{"type A", withType(dnswire.TypeA), time.Minute, notPolicy("corp.test.")},
		{"type 0", withType(0), time.Minute, notPolicy("corp.test.")},
		{"another domain with this host", obs.Key{Kind: obs.KindPolicy, Domain: walkName(t, "shop.test."), Name: k.Name, Type: dnswire.TypeTXT},
			time.Minute, notPolicy("shop.test.")},
		{"a domain whose host is too long", obs.Key{Kind: obs.KindPolicy, Domain: long, Name: long, Type: dnswire.TypeTXT},
			time.Minute, notPolicy(long.String())},
		{"the root", mtsPolicyKey(t, "."), time.Minute, ""},
		{"interval below 1s", k, time.Second - time.Nanosecond, ""},
	} {
		err := (Check{Key: c.key, Interval: c.interval}).Validate()
		if !errors.Is(err, ErrInvalidCheck) || c.want != "" && err.Error() != c.want {
			t.Errorf("%s: Validate gives %v; want ErrInvalidCheck %q", c.name, err, c.want)
		}

		w := walkBase(t)
		var calls atomic.Int64
		o := mtsObserver(t, w, func(context.Context, obs.Key) obs.Answer { calls.Add(1); return obs.Answer{} })
		ob, runErr := o.Run(context.Background(), Check{Key: c.key, Interval: c.interval})
		if !errors.Is(runErr, ErrInvalidCheck) || err != nil && runErr.Error() != err.Error() {
			t.Errorf("%s: Run gives %v; want the error of Validate, %v", c.name, runErr, err)
		}
		if calls.Load() != 0 || len(ob.Answers) != 0 || len(w.queries()) != 0 {
			t.Errorf("%s: Policy called %d times, %d answers, %d queries; want none", c.name, calls.Load(), len(ob.Answers), len(w.queries()))
		}
	}
}

// Run hands a check of kind policy to Policy once, with the key as given and
// a context of the caller that ends at the check's deadline, and returns its
// answer unchanged, in the zone of the domain. It walks nothing and sends no
// DNS query.
func TestRunPolicy(t *testing.T) {
	w := walkBase(t)
	k := mtsPolicyKey(t, "Corp.TEST.")
	host := walkName(t, "mta-sts.corp.test.")
	answer := obs.Answer{
		Proof: obs.Proof{
			Server:   obs.Server{Name: host, Addr: netip.MustParseAddrPort("192.0.2.25:443")},
			Question: dnswire.Question{Name: host, Type: dnswire.TypeTXT, Class: dnswire.ClassINET},
			Sent:     walkT0.Add(time.Second),
			Received: walkT0.Add(2 * time.Second),
			TCP:      true,
		},
		Result: obs.RecordsResult(obs.Records{Set: []dnswire.Record{
			{Name: host, Class: dnswire.ClassINET, Data: dnswire.TXT{Strings: []string{"version: STSv1"}}},
		}}),
	}
	type ctxKey struct{}
	var (
		calls    atomic.Int64
		got      obs.Key
		deadline time.Duration
		bounded  bool
		value    any
	)
	o := mtsObserver(t, w, func(ctx context.Context, key obs.Key) obs.Answer {
		calls.Add(1)
		got = key
		var dl time.Time
		dl, bounded = ctx.Deadline()
		deadline = time.Until(dl)
		value = ctx.Value(ctxKey{})
		return answer
	})
	ob, err := o.Run(context.WithValue(context.Background(), ctxKey{}, "caller"), Check{Key: k, Interval: 4 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if n := calls.Load(); n != 1 || got.String() != k.String() || !got.Name.Equal(k.Name) || !got.Domain.Equal(k.Domain) {
		t.Errorf("Policy called %d times with %v; want once with %v", n, got, k)
	}
	if !bounded || deadline <= 2*time.Second || deadline > 3*time.Second || value != "caller" {
		t.Errorf("Policy got a context with deadline %v (set %v) and value %v; want three quarters of 4s ahead, in the caller's context", deadline, bounded, value)
	}
	if ob.Key.String() != k.String() || !ob.Zone.Equal(k.Domain) || len(ob.Walk) != 0 ||
		!ob.Start.Equal(walkT0) || !ob.Deadline.Equal(walkT0.Add(3*time.Second)) {
		t.Errorf("observation key %v, zone %v, %d walk answers, start %v, deadline %v; want the key, zone corp.test., no walk, %v and 3s later",
			ob.Key, ob.Zone, len(ob.Walk), ob.Start, ob.Deadline, walkT0)
	}
	if len(ob.Answers) != 1 {
		t.Fatalf("%d answers, want the one of Policy", len(ob.Answers))
	}
	a := ob.Answers[0]
	if walkServer(a.Server) != walkServer(answer.Server) || !a.Question.Name.Equal(host) || a.Question.Type != dnswire.TypeTXT ||
		a.Question.Class != dnswire.ClassINET || !a.Sent.Equal(answer.Sent) ||
		!a.Received.Equal(answer.Received) || a.Wire != nil || !a.TCP || walkCase(a.Result) != walkCase(answer.Result) {
		t.Errorf("answer %s %v %v %v %v %s; want the answer of Policy unchanged",
			walkServer(a.Server), a.Question, a.Sent, a.Received, a.TCP, walkCase(a.Result))
	}
	if n := len(w.queries()); n != 0 {
		t.Errorf("a policy check sent %d DNS queries", n)
	}
}

// While a policy check runs, the same check is refused at once, also when
// its names differ in case, and Policy is not called again; the policy check
// of another domain runs meanwhile.
func TestRunPolicyRunningGuard(t *testing.T) {
	w := walkBase(t)
	corp := walkName(t, "corp.test.")
	entered, release := make(chan struct{}, 1), make(chan struct{})
	var calls atomic.Int64
	o := mtsObserver(t, w, func(ctx context.Context, key obs.Key) obs.Answer {
		calls.Add(1)
		if key.Domain.Equal(corp) {
			select {
			case entered <- struct{}{}:
			default:
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
		}
		return obs.Answer{Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout, Detail: "timeout"})}
	})
	k := mtsPolicyKey(t, "corp.test.")
	first := make(chan error, 1)
	go func() {
		_, err := o.Run(context.Background(), Check{Key: k, Interval: time.Minute})
		first <- err
	}()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		close(release)
		t.Fatal("the first check never reached Policy")
	}

	start := time.Now()
	for _, key := range []obs.Key{
		k,
		mtsPolicyKey(t, "CORP.test."),
		{Kind: obs.KindPolicy, Domain: corp, Name: walkName(t, "MTA-STS.CORP.TEST."), Type: dnswire.TypeTXT},
	} {
		if _, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute}); !errors.Is(err, ErrRunning) {
			t.Errorf("second Run of %v: %v, want ErrRunning", key, err)
		}
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the refused Runs took %v, want an answer at once", d)
	}
	if n := calls.Load(); n != 1 {
		t.Errorf("Policy called %d times while the check ran, want once", n)
	}
	if _, err := o.Run(context.Background(), Check{Key: mtsPolicyKey(t, "shop.test."), Interval: time.Minute}); err != nil {
		t.Errorf("the policy check of another domain: %v", err)
	}

	close(release)
	if err := <-first; err != nil {
		t.Fatalf("first Run: %v", err)
	}
	if _, err := o.Run(context.Background(), Check{Key: k, Interval: time.Minute}); err != nil {
		t.Errorf("Run after the first ended: %v", err)
	}
	if n := calls.Load(); n != 3 {
		t.Errorf("Policy called %d times in all, want 3", n)
	}
}

// Without a policy client a policy check gives one failure answer, not
// permitted, and sends nothing.
func TestRunPolicyWithoutClient(t *testing.T) {
	w := walkBase(t)
	k := mtsPolicyKey(t, "corp.test.")
	ob := walkRun(t, mtsObserver(t, w, nil), k, time.Minute)
	if len(ob.Answers) != 1 {
		t.Fatalf("%d answers, want one", len(ob.Answers))
	}
	a := ob.Answers[0]
	f := walkFailure(a.Result)
	if walkCase(a.Result) != "failure not-permitted" || f.Detail != "no policy client" {
		t.Errorf("result %s %q; want failure not-permitted %q", walkCase(a.Result), f.Detail, "no policy client")
	}
	q := dnswire.Question{Name: k.Name, Type: dnswire.TypeTXT, Class: dnswire.ClassINET}
	if !a.Server.Name.Equal(k.Name) || a.Server.Addr.IsValid() || !a.Question.Name.Equal(q.Name) || a.Question.Type != q.Type ||
		a.Question.Class != q.Class || !a.Sent.IsZero() || a.Wire != nil {
		t.Errorf("proof %s %v, sent %v, wire %v; want %v without address, %v, nothing sent", walkServer(a.Server), a.Question, a.Sent, a.Wire, k.Name, q)
	}
	if !ob.Zone.Equal(k.Domain) || len(ob.Walk) != 0 || len(w.queries()) != 0 {
		t.Errorf("zone %v, %d walk answers, %d queries; want corp.test., none, none", ob.Zone, len(ob.Walk), len(w.queries()))
	}
}
