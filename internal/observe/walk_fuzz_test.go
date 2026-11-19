package observe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The lab range that the test permits; the servers of the fake network live
// in it.
var walkFuzzLab = netip.MustParsePrefix("10.53.0.0/16")

// Addresses that the walk must never ask: outside the public internet and
// outside the lab range, or a lab address in another form.
var walkFuzzRefused = func() []netip.Addr {
	var addrs []netip.Addr
	for _, s := range []string{
		"127.0.0.1", "10.0.0.1", "192.168.0.1", "172.16.0.1", "169.254.0.1", "0.0.0.0", "224.0.0.1", "192.0.2.1",
		"100.64.0.1", "::1", "fe80::1", "fc00::1", "::ffff:10.53.0.1", "64:ff9b::a35:1", "2002:a35:1::1", "2001:db8::1",
	} {
		addrs = append(addrs, netip.MustParseAddr(s))
	}
	return addrs
}()

// A referral beside every zone of the walk.
var walkFuzzOther = fuzzNames[fuzzIndex("example.")]

// Messages stay near the size that fits in 65535 octets.
const walkFuzzMaxRecords = 2000

type walkFuzzQuery struct {
	server netip.AddrPort
	typ    dnswire.Type
}

// walkFuzzWidth is the room of one answer in a script. A script of one such
// part gives every answer from it; one of three parts gives NS questions the
// first, A and AAAA questions the second, and others the third.
const walkFuzzWidth = 16

// walkFuzzNet is a hostile network behind the exchange hook. The server at
// 10.53.D.K plays every zone of D labels: for a question, its zone is the
// ancestor of the name asked that has D labels. Its answer comes from the
// script, at an offset chosen by D, by K odd or even, by whether the name
// asked is a host of a referral, and by the type asked. So two servers of a
// zone may disagree, and the answer to a question does not depend on when it
// is asked.
type walkFuzzNet struct {
	script []byte
	mu     sync.Mutex
	asked  []walkFuzzQuery
}

func (n *walkFuzzNet) exchange(_ context.Context, server netip.AddrPort, q dnswire.Query, _ bool) (*dnswire.Response, error) {
	n.mu.Lock()
	n.asked = append(n.asked, walkFuzzQuery{server, q.Type})
	n.mu.Unlock()
	if !server.Addr().Is4() || !walkFuzzLab.Contains(server.Addr()) {
		return nil, errors.New("no server at this address")
	}
	a := server.Addr().As4()
	depth := int(a[2])
	slot := ((depth*2+int(a[3]%2))*2 + walkFuzzIsHost(q.Name)) * 3
	if q.Type == dnswire.TypeA || q.Type == dnswire.TypeAAAA {
		slot++
	} else if q.Type != dnswire.TypeNS {
		slot += 2
	}
	r := &fuzzReader{}
	if len(n.script) > 0 {
		r.b = n.script[slot*walkFuzzWidth%len(n.script):]
	}
	zone := walkFuzzAncestor(q.Name, depth)
	soa := dnswire.Record{Name: zone, Class: dnswire.ClassINET, TTL: 60, Data: dnswire.SOA{MName: zone, Minimum: 60}}
	m := &dnswire.Message{Header: dnswire.Header{Response: true, Authoritative: true}}
	switch r.next() % 10 {
	case 0: // a referral one, two or three levels down, to the zone itself, or up
		m.Authoritative = false
		cut := walkFuzzAncestor(q.Name, depth+[]int{1, 2, 3, 0, -1}[r.next()%5])
		m.Authority, m.Additional = walkFuzzHosts(r, cut, zone)
	case 1: // the set asked; for NS, the hosts with their glue
		if q.Type == dnswire.TypeNS {
			m.Answer, m.Additional = walkFuzzHosts(r, q.Name, zone)
		} else {
			m.Answer = walkFuzzAddrs(r, q.Name, q.Name.LabelCount()-1, int(r.next()+1)%101)
		}
	case 2:
		m.Authority = []dnswire.Record{soa}
	case 3:
		m.Rcode = 3
		m.Authority = []dnswire.Record{soa}
	case 4: // a chain of aliases
		owner := q.Name
		for i := range int(r.next() % 8) {
			target := walkFuzzChild("c"+strconv.Itoa(i), zone)
			m.Answer = append(m.Answer, dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: 60, Data: dnswire.CNAME{Target: target}})
			owner = target
		}
	case 5:
		return nil, []error{context.DeadlineExceeded, fmt.Errorf("%w: from the test", dnswire.ErrMalformed),
			errors.New("connection refused")}[r.next()%3]
	case 6:
		m.Truncated = true
	case 7:
		m.Rcode = []dnswire.Rcode{2, 5, 1}[r.next()%3]
	case 8: // lame: no authority and nothing else
		m.Authoritative = false
	default: // a referral to a zone beside the walk
		m.Authoritative = false
		m.Authority, m.Additional = walkFuzzHosts(r, walkFuzzOther, zone)
	}
	return &dnswire.Response{Msg: m}, nil
}

// walkFuzzHosts reads a TTL, a count of 1 to 100 hosts, where they live, a
// count of 0 to 100 addresses for each, and where those point; it returns
// the NS records of owner and their glue. Hosts live under owner, beside the
// walk, or in zone, the zone of the server that sends them.
func walkFuzzHosts(r *fuzzReader, owner, zone dnswire.Name) (ns, glue []dnswire.Record) {
	ttl := uint32(r.next())
	count := 1 + int(r.next())%100
	place := int(r.next())
	addrs := int(r.next()+1) % 101
	for i := range count {
		parent := []dnswire.Name{owner, walkFuzzOther, zone}[(place+i)%3]
		host := walkFuzzChild("h"+strconv.Itoa(i), parent)
		ns = append(ns, dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: ttl, Data: dnswire.NS{Host: host}})
		glue = append(glue, walkFuzzAddrs(r, host, owner.LabelCount(), min(addrs, walkFuzzMaxRecords-len(glue)))...)
	}
	return ns, glue
}

// walkFuzzAddrs reads where count address records of owner point: half of
// the choices are servers of depth, of the zone above it (a loop back) or of
// the zone below; the other half are refused addresses.
func walkFuzzAddrs(r *fuzzReader, owner dnswire.Name, depth, count int) []dnswire.Record {
	base := int(r.next())
	ttl := uint32(r.next())
	var records []dnswire.Record
	for j := range count {
		v := (base + 7*j) % 32
		a := netip.AddrFrom4([4]byte{10, 53, byte(depth + []int{0, -1, 1}[v%3]), byte(v)})
		if v >= 16 {
			a = walkFuzzRefused[v-16]
		}
		rec := dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: ttl, Data: dnswire.A{Addr: a}}
		if a.Is6() {
			rec.Data = dnswire.AAAA{Addr: a}
		}
		records = append(records, rec)
	}
	return records
}

// walkFuzzAncestor is the ancestor of name with that many labels, at most
// name itself and at least the root.
func walkFuzzAncestor(name dnswire.Name, labels int) dnswire.Name {
	l := name.Labels()
	n, err := dnswire.NameFromLabels(l[len(l)-min(max(labels, 0), len(l)):])
	if err != nil {
		panic(err)
	}
	return n
}

// walkFuzzChild is label under parent, or parent when the name would be too
// long.
func walkFuzzChild(label string, parent dnswire.Name) dnswire.Name {
	n, err := dnswire.NameFromLabels(append([]string{label}, parent.Labels()...))
	if err != nil {
		return parent
	}
	return n
}

func walkFuzzIsHost(name dnswire.Name) int {
	if l := name.Labels(); len(l) > 0 && l[0][0] == 'h' {
		return 1
	}
	return 0
}

// An input of FuzzWalk is a kind octet (records, delegation or serial), a
// length octet for the name of the check (1 to 24 labels, each one deeper
// zone), and the script of walkFuzzNet.
func FuzzWalk(f *testing.F) {
	seed := func(kind, length byte, parts ...[]byte) {
		b := []byte{kind, length}
		for _, p := range parts {
			b = append(b, p...)
			b = append(b, make([]byte, walkFuzzWidth-len(p))...)
		}
		f.Add(b)
	}
	// Each zone refers one level down, to one host with its glue: to the
	// zone of the name, past the referrals a walk may follow, to the parent,
	// to the zone of the domain.
	seed(0, 4)
	seed(0, 22)
	seed(1, 4)
	seed(2, 4)
	// Referrals to 100 hosts without glue, and with 100 addresses each.
	seed(0, 8, []byte{0, 0, 60, 99, 0, 100})
	seed(1, 8, []byte{0, 0, 60, 99, 1, 99})
	// Glue at refused addresses, a referral up, a referral beside the walk.
	seed(0, 8, []byte{0, 0, 60, 3, 0, 9, 16, 60, 16, 60, 16, 60, 16, 60})
	seed(0, 8, []byte{0, 4, 60, 1, 0, 0, 0, 60})
	seed(0, 8, []byte{9, 60, 1, 0, 0, 0, 60})
	// Hosts without glue whose addresses are a chain of aliases, or whose
	// servers time out.
	seed(0, 8, []byte{0, 0, 60, 1, 0, 100}, []byte{4, 7}, []byte{2})
	seed(0, 8, []byte{0, 0, 60, 1, 0, 100}, []byte{5, 0}, []byte{5, 2})
	// The zone answers its NS set; the others are truncated or fail.
	seed(2, 8, []byte{1, 60, 1, 0, 1, 0, 60}, []byte{6}, []byte{7, 0})
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &fuzzReader{b: b}
		kind, length := r.next()%3, 1+int(r.next())%24
		labels := []string{"test"}
		for range length - 1 {
			labels = append([]string{"a"}, labels...)
		}
		name, err := dnswire.NameFromLabels(labels)
		if err != nil {
			t.Fatal(err)
		}
		k := []obs.Key{
			obs.RecordsKey(fuzzNames[fuzzIndex("test.")], name, dnswire.TypeMX),
			obs.DelegationKey(name),
			obs.SerialKey(name),
		}[kind]
		world := &walkFuzzNet{script: r.b}
		o, err := New(Config{
			RootServers: []netip.AddrPort{netip.MustParseAddrPort("10.53.0.1:53"), netip.MustParseAddrPort("10.53.0.2:53")},
			ExtraRanges: []netip.Prefix{walkFuzzLab},
			// No query waits for a slot: the fake clock stands still.
			RateInterval: time.Nanosecond,
			RateBurst:    1000,
		})
		if err != nil {
			t.Fatal(err)
		}
		o.exchange = world.exchange
		o.now = func() time.Time { return time.Date(2026, 11, 18, 12, 0, 0, 0, time.UTC) }

		ob, err := o.Run(context.Background(), Check{Key: k, Interval: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		walkFuzzCheck(t, k, world.asked, ob)
	})
}

// walkFuzzCheck holds the bounds of a check against a hostile network. A
// check sends at most 32 queries of its own walk and 128 to look up hosts;
// its fan-out asks at most 32 addresses, each once; its Walk holds at most 4
// entries for each query of the first two counts. It asks only permitted
// addresses, and the zone it ends at has at most 32 hosts with at most 16
// addresses each.
func walkFuzzCheck(t *testing.T, k obs.Key, asked []walkFuzzQuery, ob obs.Observation) {
	t.Helper()
	walk, fanOut := 0, map[netip.AddrPort]int{}
	for _, a := range asked {
		if !a.server.Addr().Is4() || !walkFuzzLab.Contains(a.server.Addr()) || a.server.Port() != 53 {
			t.Fatalf("a query to %v, which may not be asked", a.server)
		}
		if a.typ == dnswire.TypeMX {
			fanOut[a.server]++
		} else {
			walk++
		}
	}
	switch {
	case len(asked) > 32+128+32:
		t.Fatalf("%d queries sent", len(asked))
	case k.Kind == obs.KindRecords && walk > 32+128:
		t.Fatalf("%d queries sent by the walk", walk)
	case len(fanOut) > 32:
		t.Fatalf("the fan-out asked %d addresses", len(fanOut))
	case len(ob.Walk) > 4*(32+128):
		t.Fatalf("%d walk entries", len(ob.Walk))
	case len(ob.Answers) == 0:
		t.Fatal("no answer")
	}
	for a, n := range fanOut {
		if n > 1 {
			t.Fatalf("the fan-out asked %v %d times", a, n)
		}
	}

	hosts := map[string]map[netip.AddrPort]bool{}
	for _, a := range append(ob.Walk, ob.Answers...) {
		obs.Match(a.Result,
			func(obs.Records) any { return nil },
			func(obs.NoData) any { return nil },
			func(obs.NoName) any { return nil },
			func(f obs.Failure) any {
				if f.Reason < obs.ReasonTimeout || f.Reason > obs.ReasonDeadline {
					t.Fatalf("a failure of reason %v: %q", f.Reason, f.Detail)
				}
				return nil
			})
	}
	for _, a := range ob.Answers {
		key := a.Server.Name.Key()
		if hosts[key] == nil {
			hosts[key] = map[netip.AddrPort]bool{}
		}
		if a.Server.Addr.IsValid() {
			hosts[key][a.Server.Addr] = true
		}
	}
	if len(hosts) > 32 {
		t.Fatalf("the zone %v has %d hosts", ob.Zone, len(hosts))
	}
	for host, addrs := range hosts {
		if len(addrs) > 16 {
			t.Fatalf("host %q of the zone %v has %d addresses", host, ob.Zone, len(addrs))
		}
	}
}
