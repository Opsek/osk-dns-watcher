package observe

import (
	"context"
	"encoding/binary"
	"fmt"
	"net/netip"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// walkWorld is a fake DNS behind the exchange seam. Each address answers for
// its zones the way an authoritative server does; a handler replaces an
// address to play a lie, a slow server or one that never answers. An address
// with neither fails at once, like a closed port.
type walkWorld struct {
	t        *testing.T
	mu       sync.Mutex
	zones    map[netip.AddrPort][]walkZone
	handlers map[netip.AddrPort]walkHandler
	asked    []walkAsked
}

type walkHandler func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error)

type walkZone struct {
	origin  dnswire.Name
	records []dnswire.Record
}

type walkAsked struct {
	server netip.AddrPort
	query  dnswire.Query
}

func walkNewWorld(t *testing.T) *walkWorld {
	return &walkWorld{t: t, zones: map[netip.AddrPort][]walkZone{}, handlers: map[netip.AddrPort]walkHandler{}}
}

// serve makes each address of addrs (separated by spaces, port 53) answer for
// the zone origin, replacing an earlier zone of that origin. Records are in
// the form "owner ttl type data"; an SOA is added. A record outside the
// origin is still sent as glue, so a test can plant data out of bailiwick.
func (w *walkWorld) serve(addrs, origin string, records ...string) {
	w.t.Helper()
	apex := strings.TrimPrefix(origin, ".")
	z := walkZone{origin: walkName(w.t, origin)}
	z.records = append(z.records, walkRR(w.t, origin+" 300 SOA ns."+apex+" hostmaster."+apex+" 1 3600 600 86400 300"))
	for _, r := range records {
		z.records = append(z.records, walkRR(w.t, r))
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, a := range strings.Fields(addrs) {
		server := walkAddr(w.t, a)
		kept := slices.DeleteFunc(slices.Clone(w.zones[server]), func(x walkZone) bool { return x.origin.Equal(z.origin) })
		w.zones[server] = append(kept, z)
	}
}

func (w *walkWorld) handle(addr string, h walkHandler) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.handlers[walkAddr(w.t, addr)] = h
}

// answer is what the zones of server give for q, also when a handler
// replaces it.
func (w *walkWorld) answer(server netip.AddrPort, q dnswire.Query) *dnswire.Message {
	w.mu.Lock()
	zones := w.zones[server]
	w.mu.Unlock()
	return walkAuthoritative(zones, q)
}

func (w *walkWorld) exchange(ctx context.Context, server netip.AddrPort, q dnswire.Query, _ bool) (*dnswire.Response, error) {
	w.mu.Lock()
	w.asked = append(w.asked, walkAsked{server, q})
	h, served := w.handlers[server], w.zones[server] != nil
	w.mu.Unlock()
	var m *dnswire.Message
	switch {
	case h != nil:
		var err error
		if m, err = h(ctx, q); err != nil {
			return nil, err
		}
	case served:
		m = w.answer(server, q)
	default:
		return nil, fmt.Errorf("nothing answers at %v", server)
	}
	wire := walkPack(m, q)
	msg, err := dnswire.Parse(wire)
	if err != nil {
		w.t.Errorf("the fake answer from %v does not parse: %v", server, err)
		return nil, err
	}
	return &dnswire.Response{Msg: msg, Wire: wire}, nil
}

// queries returns what the seam was asked, in order.
func (w *walkWorld) queries() []walkAsked {
	w.mu.Lock()
	defer w.mu.Unlock()
	return slices.Clone(w.asked)
}

// count is the number of queries sent to addr, for name and type when given.
func (w *walkWorld) count(addr, name string, t dnswire.Type) int {
	n := 0
	for _, a := range w.queries() {
		if a.server == walkAddr(w.t, addr) && (name == "" || a.query.Name.Equal(walkName(w.t, name))) && (t == 0 || a.query.Type == t) {
			n++
		}
	}
	return n
}

// walkAuthoritative answers q from zones: a referral below a cut (the DS of
// a cut is the parent's), else an authoritative answer, NODATA or NXDOMAIN,
// and REFUSED for a name in none of them.
func walkAuthoritative(zones []walkZone, q dnswire.Query) *dnswire.Message {
	m := &dnswire.Message{}
	var z *walkZone
	for i := range zones {
		if q.Name.IsSubdomainOf(zones[i].origin) && (z == nil || zones[i].origin.LabelCount() > z.origin.LabelCount()) {
			z = &zones[i]
		}
	}
	if z == nil {
		m.Rcode = 5
		return m
	}
	if cut, ok := z.cut(q.Name); ok && !(q.Type == dnswire.TypeDS && q.Name.Equal(cut)) {
		m.Authority = z.find(cut, dnswire.TypeNS)
		for _, ns := range m.Authority {
			host := ns.Data.(dnswire.NS).Host
			m.Additional = append(m.Additional, z.find(host, dnswire.TypeA)...)
			m.Additional = append(m.Additional, z.find(host, dnswire.TypeAAAA)...)
		}
		return m
	}
	m.Authoritative = true
	if m.Answer = z.find(q.Name, q.Type); len(m.Answer) == 0 {
		m.Answer = z.find(q.Name, dnswire.TypeCNAME)
	}
	if len(m.Answer) > 0 {
		return m
	}
	m.Authority = z.find(z.origin, dnswire.TypeSOA)
	if !z.exists(q.Name) {
		m.Rcode = 3
	}
	return m
}

// cut is the delegation of the zone that holds name, nearest the apex.
func (z *walkZone) cut(name dnswire.Name) (dnswire.Name, bool) {
	var cut dnswire.Name
	found := false
	for _, r := range z.records {
		if r.Type() == dnswire.TypeNS && !r.Name.Equal(z.origin) && name.IsSubdomainOf(r.Name) &&
			(!found || r.Name.LabelCount() < cut.LabelCount()) {
			cut, found = r.Name, true
		}
	}
	return cut, found
}

func (z *walkZone) find(name dnswire.Name, t dnswire.Type) []dnswire.Record {
	var out []dnswire.Record
	for _, r := range z.records {
		if r.Name.Equal(name) && r.Type() == t {
			out = append(out, r)
		}
	}
	return out
}

// exists also holds for an empty non-terminal.
func (z *walkZone) exists(name dnswire.Name) bool {
	for _, r := range z.records {
		if r.Name.IsSubdomainOf(name) {
			return true
		}
	}
	return false
}

// walkPack writes m as an answer to q, with an OPT record that has DO set.
// dnswire builds queries only, so the answer is put together here.
func walkPack(m *dnswire.Message, q dnswire.Query) []byte {
	flags := uint16(1<<15) | uint16(m.Rcode&0xf)
	if m.Authoritative {
		flags |= 1 << 10
	}
	b := binary.BigEndian.AppendUint16(nil, 0x5157)
	for _, n := range []int{int(flags), 1, len(m.Answer), len(m.Authority), len(m.Additional) + 1} {
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	b = q.Name.AppendWire(b)
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, uint16(dnswire.ClassINET))
	for _, section := range [][]dnswire.Record{m.Answer, m.Authority, m.Additional} {
		for _, r := range section {
			b = dnswire.AppendRecord(b, r)
		}
	}
	return append(b, 0, 0, 41, 0x04, 0xd0, 0, 0, 0x80, 0, 0, 0)
}

func walkName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func walkAddr(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	a, err := netip.ParseAddr(s)
	if err != nil {
		t.Fatalf("ParseAddr(%q): %v", s, err)
	}
	return netip.AddrPortFrom(a, 53)
}

// walkRR reads "owner ttl type data", class IN.
func walkRR(t *testing.T, s string) dnswire.Record {
	t.Helper()
	f := strings.SplitN(s, " ", 4)
	if len(f) != 4 {
		t.Fatalf("record %q: want owner ttl type data", s)
	}
	ttl, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		t.Fatalf("record %q: %v", s, err)
	}
	typ, err := dnswire.ParseType(f[2])
	if err != nil {
		t.Fatalf("record %q: %v", s, err)
	}
	data, err := dnswire.ParseRData(typ, f[3])
	if err != nil {
		t.Fatalf("record %q: %v", s, err)
	}
	return dnswire.Record{Name: walkName(t, f[0]), Class: dnswire.ClassINET, TTL: uint32(ttl), Data: data}
}

// walkReferral is a handler that answers every query with the same
// referral: NS records go to the authority section, the rest to the
// additional section.
func walkReferral(t *testing.T, records ...string) walkHandler {
	m := &dnswire.Message{}
	for _, s := range records {
		r := walkRR(t, s)
		if r.Type() == dnswire.TypeNS {
			m.Authority = append(m.Authority, r)
		} else {
			m.Additional = append(m.Additional, r)
		}
	}
	return func(context.Context, dnswire.Query) (*dnswire.Message, error) { return m, nil }
}

// walkDead never answers: the query ends with its context.
func walkDead(ctx context.Context, _ dnswire.Query) (*dnswire.Message, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

// walkClock is the fake time of an observer; it moves only when a test sets it.
type walkClock struct {
	mu  sync.Mutex
	now time.Time
}

var walkT0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

func (c *walkClock) get() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.now.IsZero() {
		return walkT0
	}
	return c.now
}

func (c *walkClock) set(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = walkT0.Add(d)
}

// walkObserver asks the fake world, with 10.0.0.1 as the only root server.
// The rate limit lets every query go at once, because the fake clock stands
// still and a wait for a slot would never end in fake time.
func walkObserver(t *testing.T, w *walkWorld, c *walkClock, queryTimeout time.Duration) *Observer {
	t.Helper()
	o, err := New(Config{
		RootServers:  []netip.AddrPort{walkAddr(t, "10.0.0.1")},
		ExtraRanges:  []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		QueryTimeout: queryTimeout,
		RateInterval: time.Nanosecond,
		RateBurst:    1000,
	})
	if err != nil {
		t.Fatal(err)
	}
	o.exchange = w.exchange
	o.now = c.get
	return o
}

func walkRun(t *testing.T, o *Observer, k obs.Key, interval time.Duration) obs.Observation {
	t.Helper()
	ob, err := o.Run(context.Background(), Check{Key: k, Interval: interval})
	if err != nil {
		t.Fatalf("Run(%v): %v", k, err)
	}
	return ob
}

func walkRecordsKey(t *testing.T, domain, name string, typ dnswire.Type) obs.Key {
	return obs.RecordsKey(walkName(t, domain), walkName(t, name), typ)
}

// walkCase gives a result as text: the case, then the data sorted, because
// servers order a record set as they like.
func walkCase(r obs.Result) string {
	return obs.Match(r,
		func(x obs.Records) string {
			s := "records " + walkJoin(x.Set)
			if len(x.Glue) > 0 {
				s += " glue " + walkJoin(x.Glue)
			}
			return s
		},
		func(x obs.NoData) string { return "nodata " + x.SOA.Name.String() },
		func(x obs.NoName) string {
			if x.Compact {
				return "noname-compact " + x.SOA.Name.String()
			}
			return "noname " + x.SOA.Name.String()
		},
		func(f obs.Failure) string { return "failure " + f.Reason.String() })
}

// walkFailure is the failure of r, or the zero Failure for any other case.
func walkFailure(r obs.Result) obs.Failure {
	none := obs.Failure{}
	return obs.Match(r,
		func(obs.Records) obs.Failure { return none },
		func(obs.NoData) obs.Failure { return none },
		func(obs.NoName) obs.Failure { return none },
		func(f obs.Failure) obs.Failure { return f })
}

func walkJoin(rs []dnswire.Record) string {
	var lines []string
	for _, r := range rs {
		lines = append(lines, strings.ReplaceAll(r.String(), "\t", " "))
	}
	slices.Sort(lines)
	return strings.Join(lines, "; ")
}

func walkServer(s obs.Server) string {
	if !s.Addr.IsValid() {
		return s.Name.String() + " -"
	}
	return s.Name.String() + " " + s.Addr.String()
}

// walkAnswers gives each answer as "host address case", in the order of
// the observation.
func walkAnswers(answers []obs.Answer) []string {
	var out []string
	for _, a := range answers {
		out = append(out, walkServer(a.Server)+" "+walkCase(a.Result))
	}
	return out
}

func walkWant(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s:\n got  %q\n want %q", what, got, want)
	}
}

// walkNoRepeat holds when no address was asked the same question twice in
// one check.
func walkNoRepeat(t *testing.T, w *walkWorld) {
	t.Helper()
	seen := map[string]bool{}
	for _, a := range w.queries() {
		k := a.server.String() + " " + a.query.Name.Key() + " " + a.query.Type.String()
		if seen[k] {
			t.Errorf("%s asked twice in one check", k)
		}
		seen[k] = true
	}
}

var walkCorpDelegation = []string{
	"corp.test. 300 NS ns1.corp.test.",
	"corp.test. 300 NS ns2.corp.test.",
	"ns1.corp.test. 300 A 10.0.1.1",
	"ns2.corp.test. 300 A 10.0.1.2",
}

var walkCorpZone = []string{
	"corp.test. 300 NS ns1.corp.test.",
	"corp.test. 300 NS ns2.corp.test.",
	"ns1.corp.test. 300 A 10.0.1.1",
	"ns2.corp.test. 300 A 10.0.1.2",
	"www.corp.test. 300 A 10.9.0.81",
	"mail.corp.test. 300 A 10.9.0.82",
	"cdn.corp.test. 300 CNAME edge.dnshost.test.",
}

// walkTLD is the zone test. with the delegation of corp.test. given apart,
// so a test can change it.
func walkTLD(corp ...string) []string {
	return append([]string{
		"dnshost.test. 300 NS ns1.dnshost.test.",
		"dnshost.test. 300 NS ns2.dnshost.test.",
		"ns1.dnshost.test. 300 A 10.0.2.1",
		"ns2.dnshost.test. 300 A 10.0.2.2",
		"shop.test. 300 NS ns1.dnshost.test.",
		"shop.test. 300 NS ns2.dnshost.test.",
		"signed.test. 300 NS ns1.corp.test.",
		"signed.test. 300 DS 12345 13 2 3F1B0C6E9A2D4F5E6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B",
	}, corp...)
}

// walkBase is a small copy of the DNS: a root, the parent zone test., and
// child zones whose servers hold their own copies.
func walkBase(t *testing.T) *walkWorld {
	w := walkNewWorld(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2")
	w.serve("10.0.0.2", "test.", walkTLD(walkCorpDelegation...)...)
	w.serve("10.0.1.1 10.0.1.2", "corp.test.", walkCorpZone...)
	w.serve("10.0.2.1 10.0.2.2", "dnshost.test.",
		"dnshost.test. 300 NS ns1.dnshost.test.",
		"dnshost.test. 300 NS ns2.dnshost.test.",
		"ns1.dnshost.test. 300 A 10.0.2.1",
		"ns2.dnshost.test. 300 A 10.0.2.2",
		"alias.dnshost.test. 300 CNAME ns2.dnshost.test.",
		"edge.dnshost.test. 300 A 10.9.0.83")
	w.serve("10.0.2.1 10.0.2.2", "shop.test.",
		"shop.test. 300 NS ns1.dnshost.test.",
		"shop.test. 300 NS ns2.dnshost.test.",
		"shop.test. 300 A 10.9.0.84")
	return w
}

const (
	walkWWW  = "records www.corp.test. 300 IN A 10.9.0.81"
	walkShop = "records shop.test. 300 IN A 10.9.0.84"
)

func TestWalkNormalPath(t *testing.T) {
	w := walkBase(t)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)

	if !ob.Zone.Equal(walkName(t, "corp.test.")) {
		t.Errorf("Zone = %v, want corp.test.", ob.Zone)
	}
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
		"ns2.corp.test. 10.0.1.2:53 " + walkWWW,
	})
	for _, a := range ob.Answers {
		q := a.Question
		if !q.Name.Equal(walkName(t, "www.corp.test.")) || q.Type != dnswire.TypeA || q.Class != dnswire.ClassINET {
			t.Errorf("answer question = %v %v %v, want www.corp.test. A IN", q.Name, q.Type, q.Class)
		}
		if m, err := dnswire.Parse(a.Wire); err != nil || len(m.Answer) != 1 || a.Sent.IsZero() || a.TCP {
			t.Errorf("answer of %v: Wire does not hold the answer (%v), or Sent %v, TCP %v", a.Server.Addr, err, a.Sent, a.TCP)
		}
	}

	// The walk asks (target, NS) from the root down, one address of each zone.
	if len(ob.Walk) != 3 {
		t.Fatalf("Walk has %d entries, want 3: %q", len(ob.Walk), walkAnswers(ob.Walk))
	}
	walkWant(t, "walk", walkAnswers(ob.Walk[:2]), []string{
		". 10.0.0.1:53 records test. 300 IN NS ns.test. glue ns.test. 300 IN A 10.0.0.2",
		"ns.test. 10.0.0.2:53 records corp.test. 300 IN NS ns1.corp.test.; corp.test. 300 IN NS ns2.corp.test. glue ns1.corp.test. 300 IN A 10.0.1.1; ns2.corp.test. 300 IN A 10.0.1.2",
	})
	if got := walkCase(ob.Walk[2].Result); got != "nodata corp.test." || !strings.HasSuffix(ob.Walk[2].Server.Name.String(), ".corp.test.") {
		t.Errorf("last walk entry = %s %s, want nodata corp.test. from a server of corp.test.", walkServer(ob.Walk[2].Server), got)
	}
	for _, e := range ob.Walk {
		q := e.Question
		if !q.Name.Equal(walkName(t, "www.corp.test.")) || q.Type != dnswire.TypeNS || q.Class != dnswire.ClassINET {
			t.Errorf("walk question = %v %v %v, want www.corp.test. NS IN", q.Name, q.Type, q.Class)
		}
	}

	asked := w.queries()
	if len(asked) != 5 {
		t.Fatalf("%d queries sent, want 5 (root, test., one of corp.test., then both): %v", len(asked), asked)
	}
	if asked[0].server != walkAddr(t, "10.0.0.1") || asked[1].server != walkAddr(t, "10.0.0.2") {
		t.Errorf("first queries went to %v and %v, want the root, then test.", asked[0].server, asked[1].server)
	}
	for _, a := range asked {
		if a.query.RecursionDesired || !a.query.DNSSECOK {
			t.Errorf("query %v %v to %v: RD %v DO %v, want RD 0 DO 1", a.query.Name, a.query.Type, a.server, a.query.RecursionDesired, a.query.DNSSECOK)
		}
	}
	walkNoRepeat(t, w)
}

// TestWalkZoneOfEachKind: delegation and ds stop at the parent, records goes
// to the zone of the name, also outside the domain, and serial to the zone
// of the domain.
func TestWalkZoneOfEachKind(t *testing.T) {
	corp := walkName(t, "corp.test.")
	tests := []struct {
		key  obs.Key
		zone string
		want []string
	}{
		{obs.DelegationKey(corp), "test.", []string{
			"ns.test. 10.0.0.2:53 records corp.test. 300 IN NS ns1.corp.test.; corp.test. 300 IN NS ns2.corp.test. glue ns1.corp.test. 300 IN A 10.0.1.1; ns2.corp.test. 300 IN A 10.0.1.2"}},
		{obs.DSKey(corp), "test.", []string{"ns.test. 10.0.0.2:53 nodata test."}},
		{obs.DSKey(walkName(t, "signed.test.")), "test.", []string{
			"ns.test. 10.0.0.2:53 records signed.test. 300 IN DS 12345 13 2 3F1B0C6E9A2D4F5E6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B"}},
		{obs.DelegationKey(walkName(t, "absent.test.")), "test.", []string{"ns.test. 10.0.0.2:53 noname test."}},
		{obs.SerialKey(corp), "corp.test.", []string{
			"ns1.corp.test. 10.0.1.1:53 records corp.test. 300 IN SOA ns.corp.test. hostmaster.corp.test. 1 3600 600 86400 300",
			"ns2.corp.test. 10.0.1.2:53 records corp.test. 300 IN SOA ns.corp.test. hostmaster.corp.test. 1 3600 600 86400 300"}},
		{walkRecordsKey(t, "corp.test.", "corp.test.", dnswire.TypeMX), "corp.test.", []string{
			"ns1.corp.test. 10.0.1.1:53 nodata corp.test.", "ns2.corp.test. 10.0.1.2:53 nodata corp.test."}},
		{walkRecordsKey(t, "corp.test.", "nx.corp.test.", dnswire.TypeA), "corp.test.", []string{
			"ns1.corp.test. 10.0.1.1:53 noname corp.test.", "ns2.corp.test. 10.0.1.2:53 noname corp.test."}},
		{walkRecordsKey(t, "corp.test.", "cdn.corp.test.", dnswire.TypeA), "corp.test.", []string{
			"ns1.corp.test. 10.0.1.1:53 records cdn.corp.test. 300 IN CNAME edge.dnshost.test.",
			"ns2.corp.test. 10.0.1.2:53 records cdn.corp.test. 300 IN CNAME edge.dnshost.test."}},
		{walkRecordsKey(t, "corp.test.", "edge.dnshost.test.", dnswire.TypeA), "dnshost.test.", []string{
			"ns1.dnshost.test. 10.0.2.1:53 records edge.dnshost.test. 300 IN A 10.9.0.83",
			"ns2.dnshost.test. 10.0.2.2:53 records edge.dnshost.test. 300 IN A 10.9.0.83"}},
	}
	for _, tt := range tests {
		t.Run(tt.key.String(), func(t *testing.T) {
			w := walkBase(t)
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), tt.key, time.Minute)
			if ob.Key.String() != tt.key.String() {
				t.Errorf("Key = %v, want %v", ob.Key, tt.key)
			}
			if !ob.Zone.Equal(walkName(t, tt.zone)) {
				t.Errorf("Zone = %v, want %s", ob.Zone, tt.zone)
			}
			walkWant(t, "answers", walkAnswers(ob.Answers), tt.want)
			if tt.zone == "test." && w.count("10.0.1.1", "", 0)+w.count("10.0.1.2", "", 0) > 0 {
				t.Errorf("a check of the parent asked a server of corp.test.")
			}
			walkNoRepeat(t, w)
		})
	}
}

// TestWalkGluelessHost: a host without glue gets its address from a sub-walk;
// a host that is an alias or does not exist gets none.
func TestWalkGluelessHost(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.2", "test.",
		"dnshost.test. 300 NS ns1.dnshost.test.",
		"dnshost.test. 300 NS ns2.dnshost.test.",
		"ns2.dnshost.test. 300 A 10.0.2.2",
		"shop.test. 300 NS ns1.dnshost.test.",
		"shop.test. 300 NS ns2.dnshost.test.",
		"shop.test. 300 NS alias.dnshost.test.",
		"shop.test. 300 NS gone.dnshost.test.")
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "shop.test.", "shop.test.", dnswire.TypeA), time.Minute)

	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"alias.dnshost.test. - failure walk",
		"gone.dnshost.test. - failure walk",
		"ns1.dnshost.test. 10.0.2.1:53 " + walkShop,
		"ns2.dnshost.test. 10.0.2.2:53 " + walkShop,
	})
	for _, a := range ob.Answers[:2] {
		if f := walkFailure(a.Result); !strings.Contains(f.Detail, a.Server.Name.String()) {
			t.Errorf("Detail %q does not name the host %v", f.Detail, a.Server.Name)
		}
	}
	if !walkSubWalked(ob, walkName(t, "ns1.dnshost.test."), "records ns1.dnshost.test. 300 IN A 10.0.2.1") {
		t.Errorf("Walk holds no answer ns1.dnshost.test. A 10.0.2.1: %q", walkAnswers(ob.Walk))
	}
	walkNoRepeat(t, w)
}

// TestWalkHostLookedUpOnce: corp.test. is served by ns.a.other. and
// ns.b.example., neither with glue, and other. is served by ns.b.example.
// The sub-walk for ns.a.other. looks up ns.b.example. on its way; the
// referral of corp.test. then uses that look-up instead of a second one.
func TestWalkHostLookedUpOnce(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2",
		"example. 300 NS ns.example.", "ns.example. 300 A 10.0.3.1", "other. 300 NS ns.b.example.")
	w.serve("10.0.3.1", "example.", "example. 300 NS ns.example.", "ns.example. 300 A 10.0.3.1", "ns.b.example. 300 A 10.0.1.1")
	w.serve("10.0.1.1", "other.", "other. 300 NS ns.b.example.", "ns.a.other. 300 A 10.0.1.2")
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns.a.other.", "corp.test. 300 NS ns.b.example.")...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns.b.example. 10.0.1.1:53 " + walkWWW, "ns.a.other. 10.0.1.2:53 " + walkWWW})
	host := walkName(t, "ns.b.example.")
	n := 0
	for _, e := range ob.Walk {
		if e.Question.Name.Equal(host) && e.Question.Type == dnswire.TypeA {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Walk holds %d look-ups of %v A, want 1: %q", n, host, walkAnswers(ob.Walk))
	}
}

// walkSubWalked holds when the walk asked host A and got the result want.
func walkSubWalked(ob obs.Observation, host dnswire.Name, want string) bool {
	for _, e := range ob.Walk {
		if e.Question.Name.Equal(host) && e.Question.Type == dnswire.TypeA && walkCase(e.Result) == want {
			return true
		}
	}
	return false
}

// TestWalkOutOfZoneGlueDropped: glue for a host outside the zone of the
// server that sent it is not used; the host's address comes from its own zone.
func TestWalkOutOfZoneGlueDropped(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".",
		"test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2",
		"example. 300 NS ns.example.", "ns.example. 300 A 10.0.3.1")
	w.serve("10.0.3.1", "example.", "example. 300 NS ns.example.", "ns.example. 300 A 10.0.3.1", "ns.evil.example. 300 A 10.0.3.9")
	w.serve("10.0.3.9", "corp.test.", walkCorpZone...)
	w.serve("10.0.0.2", "test.", walkTLD(append(walkCorpDelegation, "corp.test. 300 NS ns.evil.example.", "ns.evil.example. 300 A 10.6.6.6")...)...)
	o := walkObserver(t, w, &walkClock{}, time.Second)

	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns.evil.example. 10.0.3.9:53 " + walkWWW,
		"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
		"ns2.corp.test. 10.0.1.2:53 " + walkWWW,
	})
	for _, e := range ob.Walk {
		if strings.Contains(walkCase(e.Result), "10.6.6.6") {
			t.Errorf("walk entry from %s keeps the glue outside test.: %s", walkServer(e.Server), walkCase(e.Result))
		}
	}

	del := walkRun(t, o, obs.DelegationKey(walkName(t, "corp.test.")), time.Minute)
	for _, a := range del.Answers {
		if strings.Contains(walkCase(a.Result), "10.6.6.6") {
			t.Errorf("delegation answer keeps the glue outside test.: %s", walkCase(a.Result))
		}
	}
	if n := w.count("10.6.6.6", "", 0); n != 0 {
		t.Errorf("%d queries went to the address of the glue outside test.", n)
	}
}

// TestWalkLyingParent: a parent server with false glue is one answer of the
// delegation check; the other parent server keeps its own answer.
func TestWalkLyingParent(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "test. 300 NS ns2.test.", "ns.test. 300 A 10.0.0.2", "ns2.test. 300 A 10.0.0.3")
	w.serve("10.0.0.3", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns2.corp.test.",
		"ns1.corp.test. 300 A 10.0.6.6", "ns2.corp.test. 300 A 10.0.1.2")...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), obs.DelegationKey(walkName(t, "corp.test.")), time.Minute)
	set := "records corp.test. 300 IN NS ns1.corp.test.; corp.test. 300 IN NS ns2.corp.test. glue "
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns.test. 10.0.0.2:53 " + set + "ns1.corp.test. 300 IN A 10.0.1.1; ns2.corp.test. 300 IN A 10.0.1.2",
		"ns2.test. 10.0.0.3:53 " + set + "ns1.corp.test. 300 IN A 10.0.6.6; ns2.corp.test. 300 IN A 10.0.1.2",
	})
}

// TestWalkReferralLoop: servers of corp.test. that refer to their own zone or
// up to test. are lame; the walk does not follow them back.
func TestWalkReferralLoop(t *testing.T) {
	w := walkBase(t)
	w.handle("10.0.1.1", walkReferral(t, "corp.test. 300 NS ns1.corp.test.", "ns1.corp.test. 300 A 10.0.1.1"))
	w.handle("10.0.1.2", walkReferral(t, "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2"))
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	if !ob.Zone.Equal(walkName(t, "corp.test.")) {
		t.Errorf("Zone = %v, want corp.test.", ob.Zone)
	}
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 failure lame",
		"ns2.corp.test. 10.0.1.2:53 failure lame",
	})
	// root, test., both corp.test. servers for NS, both for A
	if n := len(w.queries()); n != 6 {
		t.Errorf("%d queries sent, want 6", n)
	}
	walkNoRepeat(t, w)
}

// TestWalkSubWalkCycle: x. is served by ns.y. and y. by ns.x., neither with
// glue. The host ns.x. gets no address, and the check still ends. The
// search for ns.y. does not start a second search for ns.x., which is in
// progress, so the walk asks for ns.x. once.
func TestWalkSubWalkCycle(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2", "x. 300 NS ns.y.", "y. 300 NS ns.x.")
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.x.", "ns1.corp.test. 300 A 10.0.1.1")...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
		"ns.x. - failure walk",
	})
	host, n := walkName(t, "ns.x."), 0
	for _, e := range ob.Walk {
		if e.Question.Name.Equal(host) {
			n++
		}
	}
	if n != 1 {
		t.Errorf("Walk asks for ns.x. %d times, want once: %q", n, walkAnswers(ob.Walk))
	}
	walkNoRepeat(t, w)
}

// walkChain serves a chain of glueless hosts under the root: corp.test. is
// served by ns.z1., z1. by ns.z2., and so on, up to z<n>., which is served by
// its own host with glue. Host ns.z<i>. is at 10.0.<i+2>.1. The address of
// ns.z1. needs n-1 nested sub-walks.
func walkChain(t *testing.T, n int) *walkWorld {
	w := walkBase(t)
	root := []string{"test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2"}
	for i := 1; i <= n; i++ {
		zone, own := fmt.Sprintf("z%d.", i), fmt.Sprintf("10.0.%d.1", i+2)
		host, server := fmt.Sprintf("ns.z%d.", i+1), fmt.Sprintf("10.0.%d.1", i+3)
		if i == n {
			host, server = fmt.Sprintf("ns.z%d.", i), own
			root = append(root, host+" 300 A "+own)
		}
		root = append(root, zone+" 300 NS "+host)
		w.serve(server, zone, zone+" 300 NS "+host, fmt.Sprintf("ns.z%d. 300 A %s", i, own))
	}
	w.serve("10.0.0.1", ".", root...)
	w.serve("10.0.3.1", "corp.test.", walkCorpZone...)
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.z1.", "ns1.corp.test. 300 A 10.0.1.1")...)
	return w
}

// TestWalkSubWalkDepth: three nested sub-walks find an address; a fourth is
// not started.
func TestWalkSubWalkDepth(t *testing.T) {
	for _, tt := range []struct {
		zones int
		want  string
	}{
		{4, "ns.z1. 10.0.3.1:53 " + walkWWW},
		{5, "ns.z1. - failure walk"},
	} {
		t.Run(fmt.Sprintf("%d nested", tt.zones-1), func(t *testing.T) {
			w := walkChain(t, tt.zones)
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
			walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, tt.want})
			walkNoRepeat(t, w)
		})
	}
}

// walkLadder delegates n zones, one under the other, from the root:
// l1., l2.l1., and so on. The name www.<deepest>. needs n referrals.
func walkLadder(t *testing.T, n int) (*walkWorld, dnswire.Name) {
	w := walkNewWorld(t)
	parent, parentAddr := ".", "10.0.0.1"
	for i := 1; i <= n; i++ {
		zone := fmt.Sprintf("l%d.", i)
		if parent != "." {
			zone += parent
		}
		addr := fmt.Sprintf("10.1.%d.1", i)
		records := []string{zone + " 300 NS ns." + zone, "ns." + zone + " 300 A " + addr}
		if parent == "." {
			w.serve(parentAddr, parent, records...)
		} else {
			w.serve(parentAddr, parent, append(records, "ns."+parent+" 300 A "+parentAddr)...)
		}
		parent, parentAddr = zone, addr
	}
	w.serve(parentAddr, parent, "ns."+parent+" 300 A "+parentAddr, "www."+parent+" 300 A 10.9.0.1")
	return w, walkName(t, "www."+parent)
}

// TestWalkReferralBound: a walk follows 16 referrals and fails at the 17th.
func TestWalkReferralBound(t *testing.T) {
	t.Run("16", func(t *testing.T) {
		w, name := walkLadder(t, 16)
		ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), obs.RecordsKey(name, name, dnswire.TypeA), time.Minute)
		if ob.Zone.LabelCount() != 16 || len(ob.Answers) != 1 || walkCase(ob.Answers[0].Result) != "records "+name.String()+" 300 IN A 10.9.0.1" {
			t.Errorf("Zone %v, answers %q; want the zone 16 levels down and its record", ob.Zone, walkAnswers(ob.Answers))
		}
	})
	t.Run("17", func(t *testing.T) {
		w, name := walkLadder(t, 17)
		ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), obs.RecordsKey(name, name, dnswire.TypeA), time.Minute)
		if ob.Zone.LabelCount() != 0 {
			t.Errorf("Zone = %v, want the root after a failed walk", ob.Zone)
		}
		walkWant(t, "answers", walkAnswers(ob.Answers), []string{". - failure walk"})
		if len(ob.Answers) == 1 {
			q := ob.Answers[0].Question
			if !q.Name.Equal(name) || q.Type != dnswire.TypeA || ob.Answers[0].Server.Name.LabelCount() != 0 || ob.Answers[0].Server.Addr.IsValid() {
				t.Errorf("the walk failure has question %v %v and server %v; want the checked name, A and a zero server", q.Name, q.Type, walkServer(ob.Answers[0].Server))
			}
		}
		if n := w.count("10.1.17.1", "", 0); n != 0 {
			t.Errorf("the 17th referral was followed: %d queries to its server", n)
		}
	})
}

// walkWide delegates big. from the root to hosts h01.big. to h<hosts>.big.,
// with addrs addresses dealt out to them in turn; every address serves big.
func walkWide(t *testing.T, hosts, addrs int) *walkWorld {
	w := walkNewWorld(t)
	var root, all []string
	for h := 1; h <= hosts; h++ {
		root = append(root, fmt.Sprintf("big. 300 NS h%02d.big.", h))
	}
	for i := range addrs {
		a := fmt.Sprintf("10.2.%d.%d", i/200, i%200+1)
		root = append(root, fmt.Sprintf("h%02d.big. 300 A %s", i%hosts+1, a))
		all = append(all, a)
	}
	w.serve("10.0.0.1", ".", root...)
	w.serve(strings.Join(all, " "), "big.", "www.big. 300 A 10.9.0.1")
	return w
}

// TestWalkHostBound: the first 32 hosts of a referral are used; a 33rd is
// never asked.
func TestWalkHostBound(t *testing.T) {
	for _, hosts := range []int{32, 33} {
		t.Run(strconv.Itoa(hosts), func(t *testing.T) {
			w := walkWide(t, hosts, hosts)
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "big.", "www.big.", dnswire.TypeA), time.Minute)
			var want []string
			for h := 1; h <= 32; h++ {
				want = append(want, fmt.Sprintf("h%02d.big. 10.2.0.%d:53 records www.big. 300 IN A 10.9.0.1", h, h))
			}
			walkWant(t, "answers", walkAnswers(ob.Answers), want)
			if n := w.count("10.2.0.33", "", 0); n != 0 {
				t.Errorf("the 33rd host was asked %d times", n)
			}
		})
	}
}

// TestWalkHostAddressBound: a host keeps its first 16 distinct addresses in
// the order of the message, whether they come as glue or from a sub-walk.
// The rest are never asked, and Walk records that they were dropped.
func TestWalkHostAddressBound(t *testing.T) {
	for _, host := range []string{"h.big.", "h.hosts."} {
		t.Run(host, func(t *testing.T) {
			var records, all []string
			for i := range 20 {
				a := fmt.Sprintf("10.2.0.%d", i+1)
				records = append(records, host+" 300 A "+a)
				if i == 2 {
					records = append(records, host+" 300 A 10.2.0.1") // a repeat is no address of its own
				}
				all = append(all, a)
			}
			w := walkNewWorld(t)
			if host == "h.big." {
				w.serve("10.0.0.1", ".", append([]string{"big. 300 NS h.big."}, records...)...)
			} else {
				w.serve("10.0.0.1", ".", "big. 300 NS h.hosts.", "hosts. 300 NS ns.hosts.", "ns.hosts. 300 A 10.0.5.1")
				w.serve("10.0.5.1", "hosts.", append([]string{"hosts. 300 NS ns.hosts.", "ns.hosts. 300 A 10.0.5.1"}, records...)...)
			}
			w.serve(strings.Join(all, " "), "big.", "www.big. 300 A 10.9.0.1")
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "big.", "www.big.", dnswire.TypeA), time.Minute)

			var want []string
			for i := 1; i <= 16; i++ {
				want = append(want, fmt.Sprintf("%s 10.2.0.%d:53 records www.big. 300 IN A 10.9.0.1", host, i))
			}
			walkWant(t, "answers", walkAnswers(ob.Answers), want)
			for _, a := range all[16:] {
				if n := w.count(a, "", 0); n != 0 {
					t.Errorf("%s, after the first 16 addresses, was asked %d times", a, n)
				}
			}
			if !slices.ContainsFunc(ob.Walk, func(e obs.Answer) bool {
				f := walkFailure(e.Result)
				return f.Reason == obs.ReasonWalk && strings.Contains(f.Detail, "16") && strings.Contains(f.Detail, host+" lost 4")
			}) {
				t.Errorf("Walk does not record the dropped addresses of %s: %q", host, walkAnswers(ob.Walk))
			}
		})
	}
}

// TestWalkReferralWithoutAddress: the server of test. asked first refers
// corp.test. to a host that does not exist. The walk asks the other server
// of test. before it fails, and fails when that one gives nothing either.
func TestWalkReferralWithoutAddress(t *testing.T) {
	for _, tt := range []struct {
		name string
		next walkHandler // the other server of test.
		want []string
	}{
		{"next answers", nil, []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW}},
		{"next dead", walkDead, []string{". - failure walk"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := walkBase(t)
			w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "test. 300 NS ns2.test.", "ns.test. 300 A 10.0.0.2", "ns2.test. 300 A 10.0.0.3")
			w.serve("10.0.0.3", "test.", walkTLD(walkCorpDelegation...)...)
			bad := walkReferral(t, "corp.test. 300 NS ns.gone.example.")
			var mu sync.Mutex
			asked := false
			for _, a := range []string{"10.0.0.2", "10.0.0.3"} {
				server := walkAddr(t, a)
				w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
					mu.Lock()
					first := !asked
					asked = true
					mu.Unlock()
					switch {
					case first:
						return bad(ctx, q)
					case tt.next != nil:
						return tt.next(ctx, q)
					}
					return w.answer(server, q), nil
				})
			}
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, 200*time.Millisecond), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
			walkWant(t, "answers", walkAnswers(ob.Answers), tt.want)
			if f := walkFailure(ob.Answers[0].Result); f.Reason == obs.ReasonWalk && !strings.Contains(f.Detail, "corp.test.") {
				t.Errorf("walk failure %q does not name corp.test.", f.Detail)
			}
		})
	}
}

// TestWalkFanOutTakesEachHostFirst: big. is served by three hosts with 16
// addresses each, then by one host with one address. The fan-out asks 32
// addresses: the first address of every host, then the second of every
// host, and so on. So the last host is asked, and the others get budget.
func TestWalkFanOutTakesEachHostFirst(t *testing.T) {
	w := walkNewWorld(t)
	root, all := []string{}, []string{}
	for h := 1; h <= 4; h++ {
		root = append(root, fmt.Sprintf("big. 300 NS h%d.big.", h))
		for a := 1; a <= 16 && (h < 4 || a == 1); a++ {
			addr := fmt.Sprintf("10.2.%d.%d", h, a)
			root = append(root, fmt.Sprintf("h%d.big. 300 A %s", h, addr))
			all = append(all, addr)
		}
	}
	w.serve("10.0.0.1", ".", root...)
	w.serve(strings.Join(all, " "), "big.", "www.big. 300 A 10.9.0.1")
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "big.", "www.big.", dnswire.TypeA), time.Minute)

	counts := map[string]int{}
	for _, a := range ob.Answers {
		counts[walkCase(a.Result)]++
		if walkCase(a.Result) == "failure budget" && (!a.Sent.IsZero() || a.Wire != nil) {
			t.Errorf("%v: over budget, but Sent %v and Wire %d octets, want neither", a.Server.Addr, a.Sent, len(a.Wire))
		}
	}
	want := map[string]int{"records www.big. 300 IN A 10.9.0.1": fanOutAddrs, "failure budget": len(all) - fanOutAddrs}
	if fmt.Sprint(counts) != fmt.Sprint(want) {
		t.Errorf("answers by case = %v, want %v", counts, want)
	}
	for _, a := range ob.Answers {
		if a.Server.Name.Equal(walkName(t, "h4.big.")) && walkCase(a.Result) != "records www.big. 300 IN A 10.9.0.1" {
			t.Errorf("the host with one address: %s, want its answer", walkCase(a.Result))
		}
	}
}

// TestWalkDeadZone: an address that never answers costs one query timeout
// per check and gives a timeout in its answer; the other address of the zone
// still answers, and a zone with no live address is no walk failure.
func TestWalkDeadZone(t *testing.T) {
	for _, tt := range []struct {
		name string
		dead []string
		want []string
	}{
		{"one", []string{"10.0.1.1"}, []string{"ns1.corp.test. 10.0.1.1:53 failure timeout", "ns2.corp.test. 10.0.1.2:53 " + walkWWW}},
		{"every", []string{"10.0.1.1", "10.0.1.2"}, []string{"ns1.corp.test. 10.0.1.1:53 failure timeout", "ns2.corp.test. 10.0.1.2:53 failure timeout"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := walkBase(t)
			for _, a := range tt.dead {
				w.handle(a, walkDead)
			}
			ob := walkRun(t, walkObserver(t, w, &walkClock{}, 200*time.Millisecond), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
			if !ob.Zone.Equal(walkName(t, "corp.test.")) {
				t.Errorf("Zone = %v, want corp.test.", ob.Zone)
			}
			walkWant(t, "answers", walkAnswers(ob.Answers), tt.want)
			// When the walk asked the dead address first, the answer replays
			// that failure: nothing was sent for its own question.
			for _, a := range ob.Answers {
				replay := a.Sent.IsZero() && strings.Contains(walkFailure(a.Result).Detail, "www.corp.test. NS")
				if walkCase(a.Result) == "failure timeout" && (a.Wire != nil || a.Sent.IsZero() && !replay) {
					t.Errorf("timeout of %v: Sent %v, Wire %d octets, Detail %q; want no Wire, and Sent set or the walk's question named",
						a.Server.Addr, a.Sent, len(a.Wire), walkFailure(a.Result).Detail)
				}
			}
			for _, a := range tt.dead {
				if n := w.count(a, "", 0); n != 1 {
					t.Errorf("dead %s was asked %d times, want once", a, n)
				}
			}
		})
	}
}

// walkStartAt runs a check and names the address of its first query: where
// its walk started. The first Walk entry cannot tell, because a walk that
// starts at a cached cut first logs the referral that gave the cut.
func walkStartAt(t *testing.T, o *Observer, w *walkWorld, k obs.Key, interval time.Duration) (obs.Observation, string) {
	t.Helper()
	sent := len(w.queries())
	ob := walkRun(t, o, k, interval)
	asked := w.queries()
	if len(asked) == sent {
		t.Fatalf("the check of %v sent nothing", k)
	}
	return ob, asked[sent].server.Addr().String()
}

// walkAtCorp holds for an address of a server of corp.test.
func walkAtCorp(addr string) bool {
	return addr == "10.0.1.1" || addr == "10.0.1.2"
}

// walkMove delegates corp.test. to ns3.corp.test. at 10.0.1.3, with this
// TTL on the glue.
func walkMove(w *walkWorld, ttl int) {
	w.serve("10.0.1.3", "corp.test.", walkCorpZone...)
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns3.corp.test.", fmt.Sprintf("ns3.corp.test. %d A 10.0.1.3", ttl))...)
}

// TestWalkCacheInterval: a cut learned by a walk serves later walks for less
// than one interval of the check that uses it, so a changed delegation
// reaches every check within its own interval.
func TestWalkCacheInterval(t *testing.T) {
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	mail := walkRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA)

	t.Run("same interval", func(t *testing.T) {
		w, clock := walkBase(t), &walkClock{}
		o := walkObserver(t, w, clock, time.Second)
		walkRun(t, o, www, time.Minute)
		walkMove(w, 300)

		clock.set(59 * time.Second)
		ob, first := walkStartAt(t, o, w, www, time.Minute)
		if !walkAtCorp(first) {
			t.Errorf("59s later the walk starts at %s, want a cached server of corp.test.", first)
		}
		walkWant(t, "answers 59s later", walkAnswers(ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW})

		clock.set(time.Minute)
		ob, first = walkStartAt(t, o, w, www, time.Minute)
		if first != "10.0.0.1" {
			t.Errorf("one interval later the walk starts at %s, want the root", first)
		}
		walkWant(t, "answers one interval later", walkAnswers(ob.Answers), []string{"ns3.corp.test. 10.0.1.3:53 " + walkWWW})
	})

	t.Run("shorter interval", func(t *testing.T) {
		w, clock := walkBase(t), &walkClock{}
		o := walkObserver(t, w, clock, time.Second)
		walkRun(t, o, www, time.Hour)
		clock.set(10 * time.Second)
		if _, first := walkStartAt(t, o, w, mail, time.Hour); !walkAtCorp(first) {
			t.Errorf("a check of interval 1h starts 10s later at %s, want a cached server of corp.test.", first)
		}
		if _, first := walkStartAt(t, o, w, mail, 10*time.Second); first != "10.0.0.1" {
			t.Errorf("a check of interval 10s starts 10s later at %s, want the root", first)
		}
	})
}

// TestWalkEveryQueryFails: when this machine sends no query out, as in an
// outage of its network, the walk does not fail. It ends where it started:
// at a cut learned less than one interval ago, and after that at the root.
// The fan-out then asks that zone, so the run holds one failure for each of
// its addresses, and its Zone is not the zone of the name.
func TestWalkEveryQueryFails(t *testing.T) {
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	w, clock := walkBase(t), &walkClock{}
	o := walkObserver(t, w, clock, time.Second)
	walkRun(t, o, www, time.Minute)
	o.exchange = func(context.Context, netip.AddrPort, dnswire.Query, bool) (*dnswire.Response, error) {
		return nil, fmt.Errorf("write: operation not permitted")
	}

	clock.set(45 * time.Second)
	ob := walkRun(t, o, www, time.Minute)
	if !ob.Zone.Equal(walkName(t, "corp.test.")) {
		t.Errorf("from the cut: Zone = %v, want corp.test.", ob.Zone)
	}
	walkWant(t, "answers from the cut", walkAnswers(ob.Answers),
		[]string{"ns1.corp.test. 10.0.1.1:53 failure network", "ns2.corp.test. 10.0.1.2:53 failure network"})

	clock.set(105 * time.Second)
	ob = walkRun(t, o, www, time.Minute)
	if ob.Zone.LabelCount() != 0 {
		t.Errorf("from the root: Zone = %v, want the root", ob.Zone)
	}
	walkWant(t, "answers from the root", walkAnswers(ob.Answers), []string{". 10.0.0.1:53 failure network"})
}

// TestWalkDeadSubzone: a server of corp.test. refers the name to a subzone
// whose only server fails. The walk ends at the subzone, and Walk holds the
// referral: the one of this run, or, when the walk starts from the cut that
// an earlier run learned, the referral of that run. A cut whose server may
// not be asked is not cached, so each run gets the referral anew.
func TestWalkDeadSubzone(t *testing.T) {
	key := walkRecordsKey(t, "corp.test.", "www.sub.corp.test.", dnswire.TypeA)
	for _, tt := range []struct {
		name, addr, failure string
		cached              bool
	}{
		{"closed port", "10.0.3.1", "failure network", true},
		{"refused", "10.0.3.2", "failure refused", true},
		{"not permitted", "192.0.2.1", "failure not-permitted", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, clock := walkBase(t), &walkClock{}
			w.serve("10.0.1.1 10.0.1.2", "corp.test.", append(slices.Clone(walkCorpZone),
				"sub.corp.test. 300 NS ns.sub.corp.test.", "ns.sub.corp.test. 300 A "+tt.addr)...)
			w.serve("10.0.3.2", "other.test.")
			o := walkObserver(t, w, clock, time.Second)
			for _, at := range []time.Duration{0, 30 * time.Second} {
				clock.set(at)
				ob := walkRun(t, o, key, time.Minute)
				if !ob.Zone.Equal(walkName(t, "sub.corp.test.")) {
					t.Errorf("at %v: Zone = %v, want sub.corp.test.", at, ob.Zone)
				}
				walkWant(t, fmt.Sprintf("answers at %v", at), walkAnswers(ob.Answers), []string{"ns.sub.corp.test. " + tt.addr + ":53 " + tt.failure})
				sent := walkT0.Add(at)
				if tt.cached {
					sent = walkT0
				}
				if !slices.ContainsFunc(ob.Walk, func(e obs.Answer) bool {
					return strings.HasPrefix(walkCase(e.Result), "records sub.corp.test. 300 IN NS ns.sub.corp.test.") && e.Sent.Equal(sent)
				}) {
					t.Errorf("at %v: Walk holds no referral into sub.corp.test. sent at %v: %q", at, sent, walkAnswers(ob.Walk))
				}
			}
		})
	}
}

// TestWalkCacheTTL: a cut expires with the smallest TTL of its NS records and
// of the addresses used, from the glue or from a sub-walk.
func TestWalkCacheTTL(t *testing.T) {
	for _, tt := range []struct {
		name string
		corp []string // the delegation of corp.test.
	}{
		{"glue", []string{"corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns2.corp.test.",
			"ns1.corp.test. 300 A 10.0.1.1", "ns2.corp.test. 30 A 10.0.1.2"}},
		{"ns set", []string{"corp.test. 300 NS ns1.corp.test.", "corp.test. 30 NS ns2.corp.test.",
			"ns1.corp.test. 300 A 10.0.1.1", "ns2.corp.test. 300 A 10.0.1.2"}},
		{"sub-walk", []string{"corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns9.dnshost.test.",
			"ns1.corp.test. 300 A 10.0.1.1"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, clock := walkBase(t), &walkClock{}
			w.serve("10.0.0.2", "test.", walkTLD(tt.corp...)...)
			w.serve("10.0.2.1 10.0.2.2", "dnshost.test.", "dnshost.test. 300 NS ns1.dnshost.test.",
				"dnshost.test. 300 NS ns2.dnshost.test.", "ns9.dnshost.test. 30 A 10.0.1.2")
			o := walkObserver(t, w, clock, time.Second)
			www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
			walkRun(t, o, www, time.Hour)
			walkMove(w, 300)

			clock.set(29 * time.Second)
			if _, first := walkStartAt(t, o, w, www, time.Hour); !walkAtCorp(first) {
				t.Errorf("29s later the walk starts at %s, want a cached server of corp.test.", first)
			}
			clock.set(30 * time.Second)
			ob, first := walkStartAt(t, o, w, www, time.Hour)
			if first != "10.0.0.2" {
				t.Errorf("30s later the walk starts at %s, want the server of test., whose cut is still fresh", first)
			}
			walkWant(t, "answers 30s later", walkAnswers(ob.Answers), []string{"ns3.corp.test. 10.0.1.3:53 " + walkWWW})
		})
	}
}

// TestWalkNonPermittedGlue: glue that points to an address that is neither
// public nor in the extra ranges is never asked.
func TestWalkNonPermittedGlue(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns2.corp.test.",
		"ns1.corp.test. 300 A 10.0.1.1", "ns2.corp.test. 300 A 192.0.2.1", "ns2.corp.test. 300 A 127.0.0.1")...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
		"ns2.corp.test. 127.0.0.1:53 failure not-permitted",
		"ns2.corp.test. 192.0.2.1:53 failure not-permitted",
	})
	for _, a := range ob.Answers[1:] {
		if !a.Sent.IsZero() || a.Wire != nil {
			t.Errorf("%v: Sent %v, Wire %d octets; want neither", a.Server.Addr, a.Sent, len(a.Wire))
		}
	}
	for _, a := range w.queries() {
		if !a.server.Addr().IsPrivate() {
			t.Errorf("a query went to %v", a.server)
		}
	}
}

// walkRootHints are the root servers of the IANA file named.root of
// 3 November 2026.
var walkRootHints = []string{
	"a.root-servers.net. 198.41.0.4", "a.root-servers.net. 2001:503:ba3e::2:30",
	"b.root-servers.net. 170.247.170.2", "b.root-servers.net. 2801:1b8:10::b",
	"c.root-servers.net. 192.33.4.12", "c.root-servers.net. 2001:500:2::c",
	"d.root-servers.net. 199.7.91.13", "d.root-servers.net. 2001:500:2d::d",
	"e.root-servers.net. 192.203.230.10", "e.root-servers.net. 2001:500:a8::e",
	"f.root-servers.net. 192.5.5.241", "f.root-servers.net. 2001:500:2f::f",
	"g.root-servers.net. 192.112.36.4", "g.root-servers.net. 2001:500:12::d0d",
	"h.root-servers.net. 198.97.190.53", "h.root-servers.net. 2001:500:1::53",
	"i.root-servers.net. 192.36.148.17", "i.root-servers.net. 2001:7fe::53",
	"j.root-servers.net. 192.58.128.30", "j.root-servers.net. 2001:503:c27::2:30",
	"k.root-servers.net. 193.0.14.129", "k.root-servers.net. 2001:7fd::1",
	"l.root-servers.net. 199.7.83.42", "l.root-servers.net. 2001:500:9f::42",
	"m.root-servers.net. 202.12.27.33", "m.root-servers.net. 2001:dc3::35",
}

// TestWalkBuiltInRoots: with no configured root, the walk asks the 26
// addresses of the root servers, each once; none answers here, so the root
// zone gives one failure per address.
func TestWalkBuiltInRoots(t *testing.T) {
	w := walkNewWorld(t)
	o, err := New(Config{QueryTimeout: time.Second, RateInterval: time.Nanosecond, RateBurst: 1000})
	if err != nil {
		t.Fatal(err)
	}
	o.exchange = w.exchange
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	var got []string
	for _, a := range ob.Answers {
		got = append(got, strings.ToLower(a.Server.Name.String())+" "+a.Server.Addr.Addr().String())
		if a.Server.Addr.Port() != 53 || walkCase(a.Result) != "failure network" {
			t.Errorf("%v: %s, want port 53 and a network failure", a.Server.Addr, walkCase(a.Result))
		}
	}
	want := slices.Clone(walkRootHints)
	slices.Sort(got)
	slices.Sort(want)
	walkWant(t, "root servers", got, want)
	if ob.Zone.LabelCount() != 0 {
		t.Errorf("Zone = %v, want the root", ob.Zone)
	}
	if n := len(w.queries()); n != 26 {
		t.Errorf("%d queries sent, want one to each of the 26 addresses", n)
	}
	walkNoRepeat(t, w)
}

// walkMeasure runs one check and gives the queries it sent and the octets it
// allocated.
func walkMeasure(t *testing.T, o *Observer, w *walkWorld, k obs.Key, interval time.Duration) (obs.Observation, int, uint64) {
	t.Helper()
	sent := len(w.queries())
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	ob := walkRun(t, o, k, interval)
	runtime.ReadMemStats(&after)
	return ob, len(w.queries()) - sent, after.TotalAlloc - before.TotalAlloc
}

// walkDeadCut is the delegation of dead.evil.test. to hosts with addresses
// in 127.0.0.0/8, which may not be asked: 32 hosts with 16 addresses each.
// With cached, 2 hosts with 17 addresses each, of which 16 are kept and
// the first is 10.0.9.9, which may be asked but never answers: such a cut
// is cached, and a walk that starts at it asks nothing.
func walkDeadCut(cached bool) []string {
	hosts, addrs := 32, 16
	if cached {
		hosts, addrs = 2, 17
	}
	var dead []string
	for h := 1; h <= hosts; h++ {
		host := fmt.Sprintf("d%02d.dead.evil.test.", h)
		dead = append(dead, "dead.evil.test. 300 NS "+host)
		for a := 1; a <= addrs; a++ {
			addr := fmt.Sprintf("127.0.%d.%d", h, a)
			if cached && h == 1 && a == 1 {
				addr = "10.0.9.9"
			}
			dead = append(dead, host+" 300 A "+addr)
		}
	}
	return dead
}

// walkEvil makes 10.0.9.1 the one server of a hostile zone evil.test.,
// delegated from test. It refers every name under dead.evil.test. to that
// cut, as dead gives it. It refers www.evil.test. to a host under the cut
// and to 31 hosts of its own zone, and each of those to 32 new hosts under
// the cut, all without glue.
func walkEvil(t *testing.T, w *walkWorld, dead []string) {
	plant := walkReferral(t, dead...)
	www := []string{"www.evil.test. 300 NS a.dead.evil.test."}
	for h := 2; h <= 32; h++ {
		www = append(www, fmt.Sprintf("www.evil.test. 300 NS h%02d.evil.test.", h))
	}
	toWWW := walkReferral(t, www...)
	soa := walkRR(t, "evil.test. 300 SOA ns.evil.test. hostmaster.evil.test. 1 3600 600 86400 300")
	cut, target := walkName(t, "dead.evil.test."), walkName(t, "www.evil.test.")
	w.handle("10.0.9.1", func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
		switch {
		case q.Type != dnswire.TypeNS:
			return &dnswire.Message{Authoritative: true, Authority: []dnswire.Record{soa}}, nil
		case q.Name.IsSubdomainOf(cut):
			return plant(ctx, q)
		case q.Name.Equal(target):
			return toWWW(ctx, q)
		}
		var more []string
		for h := 1; h <= 32; h++ {
			more = append(more, fmt.Sprintf("%s 300 NS %s-%02d.dead.evil.test.", q.Name, q.Name.Labels()[0], h))
		}
		return walkReferral(t, more...)(ctx, q)
	})
}

// TestWalkFreeStepsBounded: what costs no query still costs a walk step: an
// address that may not be asked or is known to be down, and a cut taken
// from the cache, whose referral is logged again. So the walk of one check
// stays small in steps and in memory.
func TestWalkFreeStepsBounded(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached %v", cached), func(t *testing.T) {
			w := walkNewWorld(t)
			w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2")
			w.serve("10.0.0.2", "test.", "evil.test. 300 NS ns.evil.test.", "ns.evil.test. 300 A 10.0.9.1")
			walkEvil(t, w, walkDeadCut(cached))
			o := walkObserver(t, w, &walkClock{}, time.Second)
			ob, sent, alloc := walkMeasure(t, o, w, walkRecordsKey(t, "evil.test.", "www.evil.test.", dnswire.TypeA), time.Minute)
			t.Logf("%d queries, %d walk entries, %d octets allocated", sent, len(ob.Walk), alloc)

			walkWant(t, "answers", walkAnswers(ob.Answers), []string{". - failure walk"})
			// Each entry of Walk is one step.
			if limit := stepsPerQuery * (descentQueries + lookupQueries); len(ob.Walk) > limit {
				t.Errorf("Walk holds %d entries, want at most %d", len(ob.Walk), limit)
			}
			// Each host gets its part of the look-ups, and here each answer
			// may be a referral to 512 addresses, about 300 KB to read and keep.
			if alloc > 32<<20 {
				t.Errorf("the check allocated %d octets, want at most 32 MiB", alloc)
			}
		})
	}
}

// TestWalkPlantedZoneCannotBlind: one server of corp.test. is a host in the
// hostile zone, whose addresses lie below a cut whose addresses may not be
// asked or never answer. Looking for them uses up the share of that host
// only, and the other server of corp.test. is still asked.
func TestWalkPlantedZoneCannotBlind(t *testing.T) {
	for _, cached := range []bool{false, true} {
		t.Run(fmt.Sprintf("cached %v", cached), func(t *testing.T) {
			w := walkBase(t)
			w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS a.dead.evil.test.",
				"ns1.corp.test. 300 A 10.0.1.1", "evil.test. 300 NS ns.evil.test.", "ns.evil.test. 300 A 10.0.9.1")...)
			walkEvil(t, w, walkDeadCut(cached))
			o := walkObserver(t, w, &walkClock{}, time.Second)
			ob, sent, alloc := walkMeasure(t, o, w, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
			t.Logf("%d queries, %d walk entries, %d octets allocated", sent, len(ob.Walk), alloc)
			walkWant(t, "answers", walkAnswers(ob.Answers), []string{
				"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
				"a.dead.evil.test. - failure walk",
			})
		})
	}
}

// TestWalkNameserverZoneCannotBlind: corp.test. is served by ns1.corp.test.,
// with glue, and by ns.a.x.test., without. In x.test., a.x.test. is served
// by 32 hosts in b.x.test., and b.x.test. by 32 hosts of x.test. that do not
// exist, none with glue: the address of ns.a.x.test. would cost more
// queries than a check may send. Its search gets a share of them, and
// ns1.corp.test. is still asked.
func TestWalkNameserverZoneCannotBlind(t *testing.T) {
	w := walkBase(t)
	x := []string{"x.test. 300 NS ns.x.test.", "ns.x.test. 300 A 10.0.7.1"}
	for i := 1; i <= 32; i++ {
		x = append(x, fmt.Sprintf("a.x.test. 300 NS h%02d.b.x.test.", i), fmt.Sprintf("b.x.test. 300 NS k%02d.x.test.", i))
	}
	w.serve("10.0.7.1", "x.test.", x...)
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.a.x.test.",
		"ns1.corp.test. 300 A 10.0.1.1", "x.test. 300 NS ns.x.test.", "ns.x.test. 300 A 10.0.7.1")...)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	ob, sent, alloc := walkMeasure(t, o, w, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	t.Logf("%d queries, %d walk entries, %d octets allocated, %d queries to ns1.corp.test.",
		sent, len(ob.Walk), alloc, w.count("10.0.1.1", "", 0))
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 " + walkWWW,
		"ns.a.x.test. - failure walk",
	})
}

// walkLame makes the 20 addresses 10.0.6.1 to 10.0.6.20 answer without
// authority, and returns the delegation of lame.test. to them.
func walkLame(w *walkWorld) []string {
	tld := []string{"lame.test. 300 NS h.lame.test."}
	for i := 1; i <= 20; i++ {
		a := fmt.Sprintf("10.0.6.%d", i)
		tld = append(tld, "h.lame.test. 300 A "+a)
		w.handle(a, func(context.Context, dnswire.Query) (*dnswire.Message, error) { return &dnswire.Message{}, nil })
	}
	return tld
}

// walkHostile makes 10.0.9.1 the one server of hostile.test. It answers the
// NS question of every name under it with a referral to 32 new hosts of
// its zone, none with glue, and every other question with no data. It
// returns the delegation of hostile.test.
func walkHostile(t *testing.T, w *walkWorld) []string {
	zone := walkName(t, "hostile.test.")
	soa := walkRR(t, "hostile.test. 300 SOA ns.hostile.test. hostmaster.hostile.test. 1 3600 600 86400 300")
	w.handle("10.0.9.1", func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
		if q.Type != dnswire.TypeNS || q.Name.Equal(zone) || !q.Name.IsSubdomainOf(zone) {
			return &dnswire.Message{Authoritative: true, Authority: []dnswire.Record{soa}}, nil
		}
		var hosts []string
		for h := 1; h <= 32; h++ {
			hosts = append(hosts, fmt.Sprintf("%s 300 NS %s-%02d.hostile.test.", q.Name, q.Name.Labels()[0], h))
		}
		return walkReferral(t, hosts...)(ctx, q)
	})
	return []string{"hostile.test. 300 NS ns.hostile.test.", "ns.hostile.test. 300 A 10.0.9.1"}
}

// TestWalkHostLookupsCannotBlind: corp.test. is served by ns1.corp.test.,
// with glue, and by 16 hosts of hostile.test., whose look-ups use all the
// queries that look-ups may take. The walk keeps its own queries, so it
// still goes down to the zone of the name, one or two cuts below corp.test.
func TestWalkHostLookupsCannotBlind(t *testing.T) {
	tld := []string{"corp.test. 300 NS ns1.corp.test.", "ns1.corp.test. 300 A 10.0.1.1"}
	hostile := []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW}
	for h := 1; h <= 16; h++ {
		tld = append(tld, fmt.Sprintf("corp.test. 300 NS h%02d.hostile.test.", h))
		hostile = append(hostile, fmt.Sprintf("h%02d.hostile.test. - failure walk", h))
	}
	for _, tt := range []struct {
		name string
		want []string
	}{
		{"www.corp.test.", hostile},
		{"www.sub.corp.test.", []string{"ns.sub.corp.test. 10.0.1.5:53 records www.sub.corp.test. 300 IN A 10.9.0.85"}},
		{"www.deep.sub.corp.test.", []string{"ns.deep.sub.corp.test. 10.0.1.6:53 records www.deep.sub.corp.test. 300 IN A 10.9.0.86"}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w := walkBase(t)
			w.serve("10.0.0.2", "test.", walkTLD(slices.Concat(tld, walkHostile(t, w))...)...)
			w.serve("10.0.1.1", "corp.test.", slices.Concat(walkCorpZone,
				[]string{"sub.corp.test. 300 NS ns.sub.corp.test.", "ns.sub.corp.test. 300 A 10.0.1.5"})...)
			w.serve("10.0.1.5", "sub.corp.test.", "www.sub.corp.test. 300 A 10.9.0.85",
				"deep.sub.corp.test. 300 NS ns.deep.sub.corp.test.", "ns.deep.sub.corp.test. 300 A 10.0.1.6")
			w.serve("10.0.1.6", "deep.sub.corp.test.", "www.deep.sub.corp.test. 300 A 10.9.0.86")
			o := walkObserver(t, w, &walkClock{}, time.Second)
			ob, sent, _ := walkMeasure(t, o, w, walkRecordsKey(t, "corp.test.", tt.name, dnswire.TypeA), time.Minute)
			t.Logf("%d queries, %d walk entries", sent, len(ob.Walk))
			walkWant(t, "answers", walkAnswers(ob.Answers), tt.want)
			if sent <= lookupQueries {
				t.Errorf("%d queries sent, want all %d of the look-ups and those of the walk", sent, lookupQueries)
			}
		})
	}
}

// TestWalkHostZoneCannotTakeAllSteps: corp.test. is served by four hosts
// without glue, each in a top-level zone of its own. The server of one of
// those zones refers its host to 32 hosts with 16 addresses each that may
// not be asked: two queries make the look-up log one step for each address.
// It uses up its own part of the steps only, wherever it comes in the
// referral, and the other three hosts are found and asked.
func TestWalkHostZoneCannotTakeAllSteps(t *testing.T) {
	for hostile := 1; hostile <= 4; hostile++ {
		t.Run(fmt.Sprintf("hostile host %d", hostile), func(t *testing.T) {
			w := walkBase(t)
			root := []string{"test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2"}
			var corp, want []string
			for n := 1; n <= 4; n++ {
				zone, server := fmt.Sprintf("t%d.", n), fmt.Sprintf("10.0.7.%d", n)
				root = append(root, zone+" 300 NS ns."+zone, "ns."+zone+" 300 A "+server)
				corp = append(corp, "corp.test. 300 NS ns."+zone)
				if n == hostile {
					want = append(want, "ns."+zone+" - failure walk")
					var dead []string
					for h := 1; h <= 32; h++ {
						host := fmt.Sprintf("d%02d.ns.%s", h, zone)
						dead = append(dead, "ns."+zone+" 300 NS "+host)
						for a := 1; a <= 16; a++ {
							dead = append(dead, fmt.Sprintf("%s 300 A 127.%d.%d.%d", host, n, h, a))
						}
					}
					w.handle(server, walkReferral(t, dead...))
					continue
				}
				addr := fmt.Sprintf("10.0.1.%d", n)
				w.serve(server, zone, fmt.Sprintf("ns.%s 300 A %s", zone, addr))
				w.serve(addr, "corp.test.", walkCorpZone...)
				want = append(want, fmt.Sprintf("ns.%s %s:53 %s", zone, addr, walkWWW))
			}
			w.serve("10.0.0.1", ".", root...)
			w.serve("10.0.0.2", "test.", walkTLD(corp...)...)
			o := walkObserver(t, w, &walkClock{}, time.Second)
			ob, sent, _ := walkMeasure(t, o, w, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
			asked := 0
			for _, a := range ob.Answers {
				if walkCase(a.Result) == walkWWW {
					asked++
				}
			}
			t.Logf("%d healthy hosts asked, %d queries, %d walk entries", asked, sent, len(ob.Walk))
			walkWant(t, "answers", walkAnswers(ob.Answers), want)
			if limit := stepsPerQuery * (descentQueries + lookupQueries); len(ob.Walk) > limit {
				t.Errorf("Walk holds %d entries, want at most %d", len(ob.Walk), limit)
			}
		})
	}
}

// TestWalkLookupsSharedEvenly: corp.test. is served by eight hosts of
// hostile.test., whose look-ups use all they get, and then by eight hosts
// of cheap.test., which take three queries each. Each host gets its part of
// the look-ups, so the hosts at the end still have their addresses.
func TestWalkLookupsSharedEvenly(t *testing.T) {
	w := walkBase(t)
	tld := slices.Concat(walkHostile(t, w), []string{"cheap.test. 300 NS ns.cheap.test.", "ns.cheap.test. 300 A 10.0.3.1"})
	var cheap, want []string
	for h := 1; h <= 8; h++ {
		tld = append(tld, fmt.Sprintf("corp.test. 300 NS h%02d.hostile.test.", h))
		want = append(want, fmt.Sprintf("c%d.cheap.test. 10.0.1.1:53 %s", h, walkWWW))
	}
	for h := 1; h <= 8; h++ {
		tld = append(tld, fmt.Sprintf("corp.test. 300 NS c%d.cheap.test.", h))
		cheap = append(cheap, fmt.Sprintf("c%d.cheap.test. 300 A 10.0.1.1", h))
		want = append(want, fmt.Sprintf("h%02d.hostile.test. - failure walk", h))
	}
	w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
	w.serve("10.0.3.1", "cheap.test.", cheap...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), want)
}

// TestWalkFanOutKeepsEveryHost: corp.test. is served by seven hosts without
// glue, which have 16 addresses each that refuse every question, and by
// ns1.corp.test., with glue. The walk and the fan-out ask the first address
// of every host before the second of any, so ns1.corp.test. answers in
// every run, although the zone has more addresses than a check asks.
func TestWalkFanOutKeepsEveryHost(t *testing.T) {
	answered := 0
	for range 100 {
		w := walkBase(t)
		tld := []string{"corp.test. 300 NS ns1.corp.test.", "ns1.corp.test. 300 A 10.0.1.1",
			"cheap.test. 300 NS ns.cheap.test.", "ns.cheap.test. 300 A 10.0.3.1"}
		var cheap []string
		for h := 1; h <= 7; h++ {
			tld = append(tld, fmt.Sprintf("corp.test. 300 NS r%d.cheap.test.", h))
			for a := 1; a <= 16; a++ {
				addr := fmt.Sprintf("10.4.%d.%d", h, a)
				cheap = append(cheap, fmt.Sprintf("r%d.cheap.test. 300 A %s", h, addr))
				w.handle(addr, func(context.Context, dnswire.Query) (*dnswire.Message, error) { return &dnswire.Message{Rcode: 5}, nil })
			}
		}
		w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
		w.serve("10.0.3.1", "cheap.test.", cheap...)
		ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
		if slices.Contains(walkAnswers(ob.Answers), "ns1.corp.test. 10.0.1.1:53 "+walkWWW) {
			answered++
		}
	}
	if answered != 100 {
		t.Errorf("ns1.corp.test. answered in %d of 100 runs, want every run", answered)
	}
}

// TestWalkLoneGluelessHostGetsFullShare: corp.test. is served by 31 hosts
// that share four addresses, all with glue, and by ns1.other.test., without.
// The one host to look up gets the full share of a host: it has its
// address, and the cut is cached.
func TestWalkLoneGluelessHostGetsFullShare(t *testing.T) {
	w := walkBase(t)
	tld := []string{"corp.test. 300 NS ns1.other.test.", "other.test. 300 NS ns.other.test.", "ns.other.test. 300 A 10.0.4.1"}
	for h := 1; h <= 31; h++ {
		tld = append(tld, fmt.Sprintf("corp.test. 300 NS g%02d.corp.test.", h))
		for a := 1; a <= 4; a++ {
			tld = append(tld, fmt.Sprintf("g%02d.corp.test. 300 A 10.0.1.%d", h, a))
		}
	}
	w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
	w.serve("10.0.4.1", "other.test.", "ns1.other.test. 300 A 10.0.1.9")
	w.serve("10.0.1.1 10.0.1.2 10.0.1.3 10.0.1.4 10.0.1.9", "corp.test.", walkCorpZone...)
	clock := &walkClock{}
	o := walkObserver(t, w, clock, time.Second)
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	ob := walkRun(t, o, www, time.Minute)
	if !slices.Contains(walkAnswers(ob.Answers), "ns1.other.test. 10.0.1.9:53 "+walkWWW) {
		t.Errorf("no answer from ns1.other.test. at 10.0.1.9: %q", walkAnswers(ob.Answers))
	}
	clock.set(time.Second)
	if _, first := walkStartAt(t, o, w, www, time.Minute); !slices.Contains([]string{"10.0.1.1", "10.0.1.2", "10.0.1.3", "10.0.1.4", "10.0.1.9"}, first) {
		t.Errorf("the next check starts at %s, want a cached server of corp.test.", first)
	}
}

// TestWalkCachedProofLoggedOnce: provider.test. is served by 32 hosts with
// 17 addresses each, so its proof is the referral and 32 entries for the
// dropped addresses. corp.test. is served by 16 hosts under provider.test.,
// none with glue. The look-ups of all 16 start at that cut, and its proof
// is logged once: every host has its address, and the cut is cached.
func TestWalkCachedProofLoggedOnce(t *testing.T) {
	w := walkBase(t)
	var tld, provider, addrs []string
	for h := 1; h <= 32; h++ {
		tld = append(tld, fmt.Sprintf("provider.test. 300 NS d%02d.provider.test.", h))
		for a := 1; a <= 17; a++ {
			tld = append(tld, fmt.Sprintf("d%02d.provider.test. 300 A 10.5.%d.%d", h, h, a))
			addrs = append(addrs, fmt.Sprintf("10.5.%d.%d", h, a))
		}
	}
	var want []string
	for h := 1; h <= 16; h++ {
		tld = append(tld, fmt.Sprintf("corp.test. 300 NS ns%02d.provider.test.", h))
		provider = append(provider, fmt.Sprintf("ns%02d.provider.test. 300 A 10.0.1.1", h))
		want = append(want, fmt.Sprintf("ns%02d.provider.test. 10.0.1.1:53 %s", h, walkWWW))
	}
	w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
	w.serve(strings.Join(addrs, " "), "provider.test.", provider...)
	clock := &walkClock{}
	o := walkObserver(t, w, clock, time.Second)
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	ob, sent, _ := walkMeasure(t, o, w, www, time.Minute)
	t.Logf("%d queries, %d walk entries", sent, len(ob.Walk))
	walkWant(t, "answers", walkAnswers(ob.Answers), want)
	shown := 0
	for _, e := range ob.Walk {
		if strings.HasPrefix(walkCase(e.Result), "records provider.test. ") {
			shown++
		}
	}
	if shown != 1 {
		t.Errorf("Walk holds the referral of provider.test. %d times, want once", shown)
	}
	clock.set(time.Second)
	if _, first := walkStartAt(t, o, w, www, time.Minute); first != "10.0.1.1" {
		t.Errorf("the next check starts at %s, want the cached server of corp.test.", first)
	}
}

// walkMovingHost serves shop.test., whose server ns1.dnshost.example. has
// no glue. Its address comes from dnshost.example., served at 10.0.2.1 and
// then at 10.0.4.1, which say 10.0.5.1 and 10.0.5.2. With nested, the server
// of dnshost.example. has no glue either: it is dns.infra.example., whose
// address comes from infra.example., served at 10.0.6.1 and then at 10.0.6.2.
// move puts the second servers in place. inner is the name whose look-up
// caches the innermost cut.
func walkMovingHost(t *testing.T, nested bool) (w *walkWorld, move func(), inner string) {
	w = walkNewWorld(t)
	w.serve("10.0.0.2", "test.", "shop.test. 300 NS ns1.dnshost.example.")
	w.serve("10.0.5.1 10.0.5.2", "shop.test.", "shop.test. 300 NS ns1.dnshost.example.", "shop.test. 300 A 10.9.0.84")
	w.serve("10.0.2.1", "dnshost.example.", "ns1.dnshost.example. 300 A 10.0.5.1")
	w.serve("10.0.4.1", "dnshost.example.", "ns1.dnshost.example. 300 A 10.0.5.2")
	root := func(at string) {
		w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2",
			"dnshost.example. 300 NS ns.dnshost.example.", "ns.dnshost.example. 300 A "+at)
	}
	if nested {
		w.serve("10.0.6.1", "infra.example.", "dns.infra.example. 300 A 10.0.2.1")
		w.serve("10.0.6.2", "infra.example.", "dns.infra.example. 300 A 10.0.4.1")
		root = func(at string) {
			w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2",
				"dnshost.example. 300 NS dns.infra.example.",
				"infra.example. 300 NS ns.infra.example.", "ns.infra.example. 300 A "+at)
		}
		root("10.0.6.1")
		return w, func() { root("10.0.6.2") }, "dns.infra.example."
	}
	root("10.0.2.1")
	return w, func() { root("10.0.4.1") }, "ns1.dnshost.example."
}

// TestWalkCacheKeepsAgeOfInnerCut: the servers of the zone of a server move
// at 1s. A check of interval 1h learns the cut shop.test. at 59s through the
// cut it cached at 0s; a check of interval 60s must not use that cut at 118s,
// because what it rests on was learned more than 60s before.
func TestWalkCacheKeepsAgeOfInnerCut(t *testing.T) {
	for _, nested := range []bool{false, true} {
		t.Run(fmt.Sprintf("nested %v", nested), func(t *testing.T) {
			w, move, inner := walkMovingHost(t, nested)
			clock := &walkClock{}
			o := walkObserver(t, w, clock, time.Second)
			walkRun(t, o, walkRecordsKey(t, "example.", inner, dnswire.TypeA), time.Hour)
			clock.set(time.Second)
			move()
			shop := walkRecordsKey(t, "shop.test.", "shop.test.", dnswire.TypeA)
			clock.set(59 * time.Second)
			walkWant(t, "answers at 59s", walkAnswers(walkRun(t, o, shop, time.Hour).Answers),
				[]string{"ns1.dnshost.example. 10.0.5.1:53 " + walkShop})

			clock.set(118 * time.Second)
			ob, sent, alloc := walkMeasure(t, o, w, shop, time.Minute)
			t.Logf("%d queries, %d walk entries, %d octets allocated", sent, len(ob.Walk), alloc)
			walkWant(t, "answers at 118s", walkAnswers(ob.Answers), []string{"ns1.dnshost.example. 10.0.5.2:53 " + walkShop})
		})
	}
}

// walkTwoParents gives test. a second server, 10.0.0.3, with the same data.
// The servers of test. named in liars refer corp.test. to a host whose only
// address may not be asked, while lie() holds.
func walkTwoParents(t *testing.T, w *walkWorld, lie func() bool, liars ...string) {
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "test. 300 NS ns2.test.", "ns.test. 300 A 10.0.0.2", "ns2.test. 300 A 10.0.0.3")
	w.serve("10.0.0.3", "test.", walkTLD(walkCorpDelegation...)...)
	bad := walkReferral(t, "corp.test. 300 NS ns.corp.test.", "ns.corp.test. 300 A 127.0.0.1")
	for _, a := range liars {
		server := walkAddr(t, a)
		w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			if lie() {
				return bad(ctx, q)
			}
			return w.answer(server, q), nil
		})
	}
}

// TestWalkNotPermittedReferral: a referral whose only address may not be
// asked is used only when no server of the zone gives a better answer, and
// it is never cached.
func TestWalkNotPermittedReferral(t *testing.T) {
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	truth := []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW}

	t.Run("one server lies", func(t *testing.T) {
		// Whichever server of test. a check asks first lies.
		var mu sync.Mutex
		first := true
		lie := func() bool {
			mu.Lock()
			defer mu.Unlock()
			l := first
			first = false
			return l
		}
		w, clock := walkBase(t), &walkClock{}
		walkTwoParents(t, w, lie, "10.0.0.2", "10.0.0.3")
		o := walkObserver(t, w, clock, time.Second)
		walkWant(t, "answers", walkAnswers(walkRun(t, o, www, time.Minute).Answers), truth)
		clock.set(30 * time.Second)
		mu.Lock()
		first = true
		mu.Unlock()
		walkWant(t, "answers 30s later", walkAnswers(walkRun(t, o, www, time.Minute).Answers), truth)
	})

	t.Run("every server lies", func(t *testing.T) {
		w, clock := walkBase(t), &walkClock{}
		walkTwoParents(t, w, func() bool { return true }, "10.0.0.2", "10.0.0.3")
		o := walkObserver(t, w, clock, time.Second)
		walkWant(t, "answers", walkAnswers(walkRun(t, o, www, time.Minute).Answers),
			[]string{"ns.corp.test. 127.0.0.1:53 failure not-permitted"})
		clock.set(30 * time.Second)
		if _, first := walkStartAt(t, o, w, www, time.Minute); first != "10.0.0.2" && first != "10.0.0.3" {
			t.Errorf("30s later the walk starts at %s, want a server of test.: the referral is not cached", first)
		}
	})
}

// TestWalkCacheHitShowsReferral: a walk that starts at a cached cut logs
// first the referral that gave it, with the address that it dropped.
func TestWalkCacheHitShowsReferral(t *testing.T) {
	w := walkBase(t)
	corp, addrs := []string{"corp.test. 300 NS ns1.corp.test."}, ""
	for i := 1; i <= 17; i++ {
		corp = append(corp, fmt.Sprintf("ns1.corp.test. 300 A 10.0.1.%d", i))
		addrs += fmt.Sprintf(" 10.0.1.%d", i)
	}
	w.serve("10.0.0.2", "test.", walkTLD(corp...)...)
	w.serve(addrs, "corp.test.", walkCorpZone...)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	learned := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute).Walk
	if len(learned) < 3 {
		t.Fatalf("Walk of the first check: %q", walkAnswers(learned))
	}
	// The root's referral, then that of test. and its dropped address.
	learned = learned[1:3]
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA), time.Minute)
	if len(ob.Walk) < 2 {
		t.Fatalf("Walk of the second check: %q", walkAnswers(ob.Walk))
	}
	walkWant(t, "start of the second walk", walkAnswers(ob.Walk[:2]), walkAnswers(learned))
	if !ob.Walk[0].Sent.Equal(learned[0].Sent) || !ob.Walk[0].Question.Name.Equal(learned[0].Question.Name) {
		t.Errorf("the referral from the cache was sent at %v for %v, want %v for %v",
			ob.Walk[0].Sent, ob.Walk[0].Question.Name, learned[0].Sent, learned[0].Question.Name)
	}
}

// TestWalkDelegationAfterRecordsCheck: a records check caches the cut of
// corp.test.; a delegation check of corp.test. still asks the parent only.
func TestWalkDelegationAfterRecordsCheck(t *testing.T) {
	w := walkBase(t)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	sent := len(w.queries())
	ob := walkRun(t, o, obs.DelegationKey(walkName(t, "corp.test.")), time.Minute)
	if !ob.Zone.Equal(walkName(t, "test.")) {
		t.Errorf("Zone = %v, want test.", ob.Zone)
	}
	for _, a := range w.queries()[sent:] {
		if walkAtCorp(a.server.Addr().String()) {
			t.Errorf("the delegation check asked %v, a server of corp.test.", a.server)
		}
	}
}

// TestWalkSubWalkLookupSkipsLame: the server of dnshost.test. asked first
// for the address of a host gives a lame answer; the look-up asks the other.
func TestWalkSubWalkLookupSkipsLame(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns9.dnshost.test.",
		"ns1.corp.test. 300 A 10.0.1.1")...)
	w.serve("10.0.2.1 10.0.2.2", "dnshost.test.", "ns9.dnshost.test. 300 A 10.0.1.2")
	host := walkName(t, "ns9.dnshost.test.")
	lame := &dnswire.Message{Answer: []dnswire.Record{walkRR(t, "ns9.dnshost.test. 300 A 10.6.6.6")}}
	var mu sync.Mutex
	first := true
	for _, a := range []string{"10.0.2.1", "10.0.2.2"} {
		server := walkAddr(t, a)
		w.handle(a, func(_ context.Context, q dnswire.Query) (*dnswire.Message, error) {
			mu.Lock()
			defer mu.Unlock()
			if first && q.Name.Equal(host) && q.Type == dnswire.TypeA {
				first = false
				return lame, nil
			}
			return w.answer(server, q), nil
		})
	}
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns9.dnshost.test. 10.0.1.2:53 " + walkWWW})
}

// TestWalkIncompleteCutNotCached: a cut is not cached when a host may lack
// an address because its sub-walk was skipped, ran out of its share, or was
// cut by the deadline. A check 1s later walks from the parent again.
func TestWalkIncompleteCutNotCached(t *testing.T) {
	for _, tt := range []struct {
		name     string
		world    func(t *testing.T, w *walkWorld)
		interval time.Duration
	}{
		{"skipped", func(t *testing.T, w *walkWorld) {
			w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2", "x. 300 NS ns.y.", "y. 300 NS ns.x.")
			w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.x.",
				"ns1.corp.test. 300 A 10.0.1.1")...)
		}, time.Minute},
		{"out of share", func(t *testing.T, w *walkWorld) {
			// The search for ns.lame.test. asks lame servers until its
			// queries run out.
			w.serve("10.0.0.2", "test.", walkTLD(append(walkLame(w), "corp.test. 300 NS ns1.corp.test.",
				"corp.test. 300 NS ns.lame.test.", "ns1.corp.test. 300 A 10.0.1.1")...)...)
		}, time.Minute},
		{"deadline", func(t *testing.T, w *walkWorld) {
			w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns9.dnshost.test.",
				"ns1.corp.test. 300 A 10.0.1.1")...)
			w.handle("10.0.2.1", walkDead)
			w.handle("10.0.2.2", walkDead)
		}, time.Second},
	} {
		t.Run(tt.name, func(t *testing.T) {
			w, clock := walkBase(t), &walkClock{}
			tt.world(t, w)
			o := walkObserver(t, w, clock, 10*time.Second)
			www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
			walkRun(t, o, www, tt.interval)
			clock.set(time.Second / 2)
			if _, first := walkStartAt(t, o, w, www, tt.interval); first != "10.0.0.2" {
				t.Errorf("the next check starts at %s, want the server of test.", first)
			}
		})
	}
}

// TestWalkSpentBudgetFailsWalk: when the walk has sent all the queries it
// may send toward the name, the walk fails, and no answer pretends that a
// zone was found.
func TestWalkSpentBudgetFailsWalk(t *testing.T) {
	// 130 addresses of big. that are not served: each costs one query.
	w := walkNewWorld(t)
	var root []string
	for h := 1; h <= 26; h++ {
		root = append(root, fmt.Sprintf("big. 300 NS h%02d.big.", h))
		for a := 1; a <= 5; a++ {
			root = append(root, fmt.Sprintf("h%02d.big. 300 A 10.2.%d.%d", h, h, a))
		}
	}
	w.serve("10.0.0.1", ".", root...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "big.", "www.big.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{". - failure walk"})
	if f := walkFailure(ob.Answers[0].Result); !strings.Contains(f.Detail, "queries") {
		t.Errorf("walk failure %q does not name the queries", f.Detail)
	}
	if n := len(w.queries()); n != descentQueries {
		t.Errorf("%d queries sent, want %d", n, descentQueries)
	}
}

// TestWalkServerOrderShuffled: the servers of a zone are asked in random
// order, so no single server is always asked first.
func TestWalkServerOrderShuffled(t *testing.T) {
	w := walkBase(t)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Hour)
	firsts := map[string]int{}
	for i := range 64 {
		_, first := walkStartAt(t, o, w, walkRecordsKey(t, "corp.test.", fmt.Sprintf("n%d.corp.test.", i), dnswire.TypeA), time.Hour)
		firsts[first]++
	}
	if firsts["10.0.1.1"] == 0 || firsts["10.0.1.2"] == 0 {
		t.Errorf("the first server asked in 64 walks: %v; want both servers of corp.test.", firsts)
	}
}
