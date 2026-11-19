package observe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

const (
	dngLabel1   = "qwertyuiopasdfghjklzxcvbnm"
	dngLabel2   = "mnbvcxzlkjhgfdsapoiuytrewq"
	dngWildAddr = "10.9.0.99"
)

// dngLongName gives a name whose wire form, root octet included, has wire
// octets.
func dngLongName(t *testing.T, wire int) dnswire.Name {
	t.Helper()
	left := wire - 1
	var labels []string
	if rest := left % 64; rest >= 2 {
		labels = append(labels, strings.Repeat("a", rest-1))
		left -= rest
	}
	for ; left >= 64; left -= 64 {
		labels = append(labels, strings.Repeat("b", 63))
	}
	if left != 0 {
		t.Fatalf("no name of %d wire octets", wire)
	}
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func dngKey(t *testing.T, domain, name string) obs.Key {
	return obs.WildcardKey(walkName(t, domain), walkName(t, name))
}

// dngObserver is an observer of the fake world whose label seam draws from
// labels, the last one again and again. The count of draws is returned. A
// packet that leaves before the first draw fails the test. With no labels the
// seam stays as New made it.
func dngObserver(t *testing.T, w *walkWorld, labels ...string) (*Observer, *atomic.Int32) {
	t.Helper()
	o := walkObserver(t, w, &walkClock{}, time.Second)
	draws := new(atomic.Int32)
	if len(labels) > 0 {
		o.label = func() string {
			i := int(draws.Add(1)) - 1
			return labels[min(i, len(labels)-1)]
		}
	}
	inner := o.exchange
	o.exchange = func(ctx context.Context, server netip.AddrPort, q dnswire.Query, tcp bool) (*dnswire.Response, error) {
		if len(labels) > 0 && draws.Load() == 0 {
			t.Errorf("a packet for %v %v went to %v before the label was drawn", q.Name, q.Type, server)
		}
		return inner(ctx, server, q, tcp)
	}
	return o, draws
}

// dngServe makes the server at addr treat a name that does not exist in a
// special way when it is asked for type A: mode "wildcard" answers it with
// an address, "nodata" says that the name exists without data, "refused"
// refuses. Every other question gets the answer of the zone.
func dngServe(w *walkWorld, addr, mode string) {
	server := walkAddr(w.t, addr)
	w.handle(addr, func(_ context.Context, q dnswire.Query) (*dnswire.Message, error) {
		m := w.answer(server, q)
		if q.Type != dnswire.TypeA || m.Rcode != 3 {
			return m, nil
		}
		switch mode {
		case "wildcard":
			return &dnswire.Message{Authoritative: true, Answer: []dnswire.Record{{
				Name: q.Name, Class: dnswire.ClassINET, TTL: 300, Data: dnswire.A{Addr: netip.MustParseAddr(dngWildAddr)}}}}, nil
		case "nodata":
			m.Rcode = 0
		case "referral":
			// A wildcard NS record: the name is a cut, and the server is no authority for it.
			return &dnswire.Message{Authority: []dnswire.Record{dngRecord(q.Name, dnswire.NS{Host: walkName(w.t, "ns1.dnshost.test.")})}}, nil
		case "cname":
			return &dnswire.Message{Authoritative: true, Answer: []dnswire.Record{
				dngRecord(q.Name, dnswire.CNAME{Target: walkName(w.t, "edge.dnshost.test.")})}}, nil
		case "dname":
			// A DNAME above the name, with the CNAME that the server makes from it.
			target, err := dnswire.NameFromLabels(append([]string{dngFirst(q.Name)}, walkName(w.t, "dnshost.test.").Labels()...))
			if err != nil {
				return nil, err
			}
			return &dnswire.Message{Authoritative: true, Answer: []dnswire.Record{
				dngRecord(walkName(w.t, "corp.test."), dnswire.DNAME{Target: walkName(w.t, "dnshost.test.")}),
				dngRecord(q.Name, dnswire.CNAME{Target: target})}}, nil
		case "compact":
			// Compact denial: NOERROR, and an NSEC at the name that lists type NXNAME.
			m.Rcode = 0
			m.Authority = append(m.Authority, dngRecord(q.Name, dnswire.NSEC{NextName: walkName(w.t, "corp.test."),
				Types: []dnswire.Type{dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeNXNAME}}))
		case "refused":
			return &dnswire.Message{Rcode: 5}, nil
		}
		return m, nil
	})
}

func dngRecord(owner dnswire.Name, data dnswire.RData) dnswire.Record {
	return dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: 300, Data: data}
}

// dngFirst is the leftmost label of name, as the octets it holds.
func dngFirst(name dnswire.Name) string {
	if l := name.Labels(); len(l) > 0 {
		return l[0]
	}
	return ""
}

// dngLabelQueries are the queries whose name starts with label.
func dngLabelQueries(w *walkWorld, label string) []walkAsked {
	var out []walkAsked
	for _, a := range w.queries() {
		if dngFirst(a.query.Name) == label {
			out = append(out, a)
		}
	}
	return out
}

func dngInAlphabet(s string) bool {
	return len(s) == 26 && strings.Trim(s, "abcdefghijklmnopqrstuvwxyz234567") == ""
}

func TestDngValidate(t *testing.T) {
	corp := walkName(t, "corp.test.")
	wild := func(name dnswire.Name) obs.Key { return obs.WildcardKey(corp, name) }
	typed := func(typ dnswire.Type) obs.Key { k := wild(corp); k.Type = typ; return k }

	valid := map[string]obs.Key{
		"name is the domain":               wild(corp),
		"name inside the domain":           wild(walkName(t, "www.corp.test.")),
		"name outside the domain":          wild(walkName(t, "edge.dnshost.test.")),
		"name in capitals":                 wild(walkName(t, "WWW.Corp.TEST.")),
		"name of 228 wire octets":          wild(dngLongName(t, 228)),
		"delegation of a long name":        obs.DelegationKey(dngLongName(t, 240)),
		"ds of a long name":                obs.DSKey(dngLongName(t, 240)),
		"serial of a long name":            obs.SerialKey(dngLongName(t, 240)),
		"records of a long name":           obs.RecordsKey(corp, dngLongName(t, 250), dnswire.TypeA),
		"records of the longest name":      obs.RecordsKey(corp, dngLongName(t, 255), dnswire.TypeTXT),
		"wildcard key written out in full": {Kind: obs.KindWildcard, Domain: corp, Name: corp, Type: dnswire.TypeA},
	}
	for name, k := range valid {
		if err := (Check{Key: k, Interval: time.Second}).Validate(); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}

	for _, typ := range []dnswire.Type{dnswire.TypeNS, dnswire.TypeAAAA, dnswire.TypeTXT, dnswire.TypeSOA, 0} {
		err := (Check{Key: typed(typ), Interval: time.Minute}).Validate()
		if !errors.Is(err, ErrInvalidCheck) || !strings.Contains(strings.ToLower(err.Error()), "type") {
			t.Errorf("wildcard of type %v: error %v, want ErrInvalidCheck naming the type", typ, err)
		}
	}

	// The room of a label of 26 octets and its length octet ends at 255.
	for _, wire := range []int{229, 230, 254, 255} {
		name := dngLongName(t, wire)
		want := fmt.Sprintf("%v: Name %v leaves no room for a label of 26 octets", ErrInvalidCheck, name)
		err := (Check{Key: wild(name), Interval: time.Minute}).Validate()
		if !errors.Is(err, ErrInvalidCheck) || err.Error() != want {
			t.Errorf("wildcard of a name of %d wire octets: error %q, want %q", wire, err, want)
		}
	}

	if err := (Check{Key: obs.WildcardKey(dnswire.Name{}, corp), Interval: time.Minute}).Validate(); !errors.Is(err, ErrInvalidCheck) ||
		!strings.Contains(strings.ToLower(err.Error()), "domain") {
		t.Errorf("wildcard under the root domain: error %v, want ErrInvalidCheck naming the domain", err)
	}
	for _, interval := range []time.Duration{0, time.Second - time.Nanosecond} {
		if err := (Check{Key: wild(corp), Interval: interval}).Validate(); !errors.Is(err, ErrInvalidCheck) ||
			!strings.Contains(strings.ToLower(err.Error()), "interval") {
			t.Errorf("wildcard with interval %v: error %v, want ErrInvalidCheck naming the interval", interval, err)
		}
	}

	// Only a wildcard check may have a Name unlike its Domain among the
	// kinds that are not records.
	www := walkName(t, "www.corp.test.")
	for _, k := range []obs.Key{
		{Kind: obs.KindDelegation, Domain: corp, Name: www, Type: dnswire.TypeNS},
		{Kind: obs.KindDS, Domain: corp, Name: www, Type: dnswire.TypeDS},
		{Kind: obs.KindSerial, Domain: corp, Name: www, Type: dnswire.TypeSOA},
	} {
		want := fmt.Sprintf("%v: Name %v differs from Domain %v", ErrInvalidCheck, www, corp)
		if err := (Check{Key: k, Interval: time.Minute}).Validate(); err == nil || err.Error() != want {
			t.Errorf("%v: error %v, want %q", k.Kind, err, want)
		}
	}
}

// A wildcard check that Validate refuses sends nothing.
func TestDngRunRefusesInvalidKey(t *testing.T) {
	w := walkBase(t)
	o, _ := dngObserver(t, w, dngLabel1)
	k := obs.WildcardKey(walkName(t, "corp.test."), dngLongName(t, 229))
	ob, err := o.Run(context.Background(), Check{Key: k, Interval: time.Minute})
	if !errors.Is(err, ErrInvalidCheck) || len(ob.Answers) != 0 || len(ob.Walk) != 0 {
		t.Errorf("Run: error %v, %d answers, %d walk entries; want ErrInvalidCheck and nothing else", err, len(ob.Answers), len(ob.Walk))
	}
	k = obs.WildcardKey(walkName(t, "corp.test."), walkName(t, "corp.test."))
	k.Type = dnswire.TypeNS
	if _, err := o.Run(context.Background(), Check{Key: k, Interval: time.Minute}); !errors.Is(err, ErrInvalidCheck) {
		t.Errorf("Run of a wildcard of type NS: error %v, want ErrInvalidCheck", err)
	}
	if n := len(w.queries()); n != 0 {
		t.Errorf("invalid checks sent %d queries", n)
	}
}

// TestDngLabelDrawnOnce: one draw for each run, before the first packet.
// The fake exchange of dngObserver fails the test for a packet that leaves
// earlier.
func TestDngLabelDrawnOnce(t *testing.T) {
	w := walkBase(t)
	o, draws := dngObserver(t, w, dngLabel1, dngLabel2)
	key := dngKey(t, "corp.test.", "corp.test.")

	walkRun(t, o, key, time.Minute)
	if n := draws.Load(); n != 1 {
		t.Errorf("one run drew %d labels, want 1", n)
	}
	if len(w.queries()) < 5 {
		t.Errorf("the run sent %d queries, want a walk and a fan-out", len(w.queries()))
	}
	walkRun(t, o, key, time.Minute)
	if n := draws.Load(); n != 2 {
		t.Errorf("two runs drew %d labels, want 2", n)
	}
}

// A failed walk has its label too: drawn once, before the first packet.
func TestDngLabelDrawnOnceWhenTheWalkFails(t *testing.T) {
	o, draws := dngObserver(t, walkNewWorld(t), dngLabel1)
	walkRun(t, o, dngKey(t, "corp.test.", "corp.test."), time.Minute)
	if n := draws.Load(); n != 1 {
		t.Errorf("a failed run drew %d labels, want 1", n)
	}
}

// TestDngFanOutQuestion: the question of every zone server is
// (label.Name, A); the walk asks (Name, NS) and no server above the zone ever
// sees the label.
func TestDngFanOutQuestion(t *testing.T) {
	tests := []struct {
		name    string
		key     string // Name of the wildcard key; its Domain is corp.test.
		zone    string
		servers []string // addresses of the servers of the zone
		answers []string
	}{
		{"name is the zone", "corp.test.", "corp.test.", []string{"10.0.1.1", "10.0.1.2"},
			[]string{"ns1.corp.test. 10.0.1.1:53 noname corp.test.", "ns2.corp.test. 10.0.1.2:53 noname corp.test."}},
		{"name below the apex, in no zone of its own", "sub.corp.test.", "corp.test.", []string{"10.0.1.1", "10.0.1.2"},
			[]string{"ns1.corp.test. 10.0.1.1:53 noname corp.test.", "ns2.corp.test. 10.0.1.2:53 noname corp.test."}},
		{"name in another zone", "shop.test.", "shop.test.", []string{"10.0.2.1", "10.0.2.2"},
			[]string{"ns1.dnshost.test. 10.0.2.1:53 noname shop.test.", "ns2.dnshost.test. 10.0.2.2:53 noname shop.test."}},
	}
	for _, tt := range tests {
		w := walkBase(t)
		o, draws := dngObserver(t, w, dngLabel1)
		ob := walkRun(t, o, dngKey(t, "corp.test.", tt.key), time.Minute)
		name, label := walkName(t, tt.key), dngLabel1+"."+tt.key
		asked := walkName(t, label)

		if !ob.Zone.Equal(walkName(t, tt.zone)) {
			t.Errorf("%s: Zone = %v, want %s", tt.name, ob.Zone, tt.zone)
		}
		walkWant(t, tt.name+": answers", walkAnswers(ob.Answers), tt.answers)
		for _, a := range ob.Answers {
			if q := a.Question; !q.Name.Equal(asked) || q.Type != dnswire.TypeA || q.Class != dnswire.ClassINET {
				t.Errorf("%s: answer of %v asks %v %v %v, want %v A IN", tt.name, a.Server.Addr, q.Name, q.Type, q.Class, asked)
			}
		}
		for _, e := range ob.Walk {
			if q := e.Question; !q.Name.Equal(name) || q.Type != dnswire.TypeNS {
				t.Errorf("%s: walk question %v %v, want %v NS", tt.name, q.Name, q.Type, name)
			}
		}

		zoneAddr := func(s netip.AddrPort) bool { return slices.Contains(tt.servers, s.Addr().String()) }
		for _, a := range w.queries() {
			isLabel := a.query.Name.Equal(asked)
			switch {
			case isLabel && (!zoneAddr(a.server) || a.query.Type != dnswire.TypeA):
				t.Errorf("%s: %v %v went to %v, which is no server of the zone, or is not type A", tt.name, a.query.Name, a.query.Type, a.server)
			case !isLabel && (!a.query.Name.Equal(name) || a.query.Type != dnswire.TypeNS):
				t.Errorf("%s: %v %v went to %v, want only the label at the zone and (%v, NS) in the walk", tt.name, a.query.Name, a.query.Type, a.server, name)
			}
			if !zoneAddr(a.server) && strings.Contains(strings.ToLower(a.query.Name.String()), dngLabel1) {
				t.Errorf("%s: the label reached %v, a server above the zone", tt.name, a.server)
			}
		}
		for _, addr := range tt.servers {
			if n := w.count(addr, label, dnswire.TypeA); n != 1 {
				t.Errorf("%s: %s was asked %s A %d times, want once", tt.name, addr, label, n)
			}
		}
		if n := len(dngLabelQueries(w, dngLabel1)); n != len(tt.servers) {
			t.Errorf("%s: %d questions hold the label, want %d", tt.name, n, len(tt.servers))
		}
		if draws.Load() != 1 {
			t.Errorf("%s: %d draws, want 1", tt.name, draws.Load())
		}
		walkNoRepeat(t, w)
	}
}

// TestDngFailedWalk: when no server answers, the one answer carries the
// question of the fan-out, label included.
func TestDngFailedWalk(t *testing.T) {
	w := walkNewWorld(t)
	o, _ := dngObserver(t, w, dngLabel1)
	ob := walkRun(t, o, dngKey(t, "corp.test.", "corp.test."), time.Minute)
	if len(ob.Answers) != 1 {
		t.Fatalf("%d answers, want 1: %q", len(ob.Answers), walkAnswers(ob.Answers))
	}
	a := ob.Answers[0]
	if !strings.HasPrefix(walkCase(a.Result), "failure ") {
		t.Errorf("the answer is %s, want a failure", walkCase(a.Result))
	}
	if q := a.Question; !q.Name.Equal(walkName(t, dngLabel1+".corp.test.")) || q.Type != dnswire.TypeA || q.Class != dnswire.ClassINET {
		t.Errorf("question %v %v %v, want %s.corp.test. A IN", q.Name, q.Type, q.Class, dngLabel1)
	}
	for _, e := range ob.Walk {
		if dngFirst(e.Question.Name) == dngLabel1 {
			t.Errorf("the walk asked the label of the check")
		}
	}
	if n := len(dngLabelQueries(w, dngLabel1)); n != 0 {
		t.Errorf("%d packets held the label of a walk that failed", n)
	}
}

// TestDngLabelNotInKey: the label is in the proof only. Two runs with other
// labels have the same key and the same answers except their questions.
func TestDngLabelNotInKey(t *testing.T) {
	w := walkBase(t)
	o, _ := dngObserver(t, w, dngLabel1, dngLabel2)
	key := dngKey(t, "corp.test.", "corp.test.")
	first := walkRun(t, o, key, time.Minute)
	sent := len(w.queries())
	second := walkRun(t, o, key, time.Minute)

	for i, ob := range []obs.Observation{first, second} {
		if got := ob.Key.String(); got != "wildcard corp.test. corp.test. A" {
			t.Errorf("run %d: key text %q", i+1, got)
		}
		if ob.Key.Kind != obs.KindWildcard || !ob.Key.Name.Equal(key.Name) || !ob.Key.Domain.Equal(key.Domain) || ob.Key.Type != dnswire.TypeA {
			t.Errorf("run %d: key %+v, want %+v", i+1, ob.Key, key)
		}
		for _, a := range ob.Answers {
			if strings.Contains(walkCase(a.Result), "qwerty") || strings.Contains(walkCase(a.Result), "mnbvcx") {
				t.Errorf("run %d: the result holds the label: %s", i+1, walkCase(a.Result))
			}
		}
	}
	walkWant(t, "answers of the two runs", walkAnswers(second.Answers), walkAnswers(first.Answers))
	for i, label := range []string{dngLabel1, dngLabel2} {
		for _, a := range []obs.Observation{first, second}[i].Answers {
			if want := walkName(t, label+".corp.test."); !a.Question.Name.Equal(want) {
				t.Errorf("run %d: question %v, want %v", i+1, a.Question.Name, want)
			}
		}
	}
	for i, a := range w.queries() {
		other := dngLabel1
		if i < sent {
			other = dngLabel2
		}
		if dngFirst(a.query.Name) == other {
			t.Errorf("query %d (%v) holds the label of the other run", i, a.query.Name)
		}
	}
	if n := len(dngLabelQueries(w, dngLabel2)); n != 2 {
		t.Errorf("%d questions hold the second label, want 2", n)
	}
}

// TestDngSeamLabelInvalid: a label that cannot make a name ends the run
// before any packet.
func TestDngSeamLabelInvalid(t *testing.T) {
	long := dngLongName(t, 200)
	tests := []struct {
		name  string
		label string
		under dnswire.Name // the Name of the key
	}{
		{"empty", "", walkName(t, "corp.test.")},
		{"64 octets", strings.Repeat("a", 64), walkName(t, "corp.test.")},
		{"63 octets under a name too long for it", strings.Repeat("a", 63), long},
	}
	for _, tt := range tests {
		w := walkBase(t)
		o, _ := dngObserver(t, w, tt.label)
		key := obs.WildcardKey(walkName(t, "corp.test."), tt.under)
		if err := (Check{Key: key, Interval: time.Minute}).Validate(); err != nil {
			t.Fatalf("%s: the key is not valid by itself: %v", tt.name, err)
		}
		ob, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute})
		if !errors.Is(err, ErrInvalidCheck) {
			t.Errorf("%s: error %v, want ErrInvalidCheck", tt.name, err)
		}
		if len(ob.Answers) != 0 || len(ob.Walk) != 0 {
			t.Errorf("%s: an observation came with the error", tt.name)
		}
		if n := len(w.queries()); n != 0 {
			t.Errorf("%s: %d packets sent", tt.name, n)
		}
		// A refused run leaves no mark: the same check runs when the label is good.
		if tt.under.LabelCount() == 2 {
			o.label = func() string { return dngLabel1 }
			if _, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute}); err != nil {
				t.Errorf("%s: the run after the refused one: %v", tt.name, err)
			}
		}
	}
}

// TestDngSeamLabelValid: any label that makes a name is asked as it is.
func TestDngSeamLabelValid(t *testing.T) {
	corp := walkName(t, "corp.test.")
	// A dot inside a label is one octet of that label.
	for _, label := range []string{"x", strings.Repeat("a", 63), "a-b_9", dngLabel1, "ab.cd", "."} {
		w := walkBase(t)
		o, _ := dngObserver(t, w, label)
		ob := walkRun(t, o, dngKey(t, "corp.test.", "corp.test."), time.Minute)
		if len(ob.Answers) != 2 {
			t.Errorf("label %q: %d answers, want 2", label, len(ob.Answers))
		}
		want, err := dnswire.NameFromLabels(append([]string{label}, corp.Labels()...))
		if err != nil {
			t.Fatal(err)
		}
		for _, addr := range []string{"10.0.1.1", "10.0.1.2"} {
			n := 0
			for _, a := range w.queries() {
				if a.server == walkAddr(t, addr) && a.query.Type == dnswire.TypeA && a.query.Name.Equal(want) {
					n++
				}
			}
			if n != 1 {
				t.Errorf("label %q: %s was asked the label %d times, want once", label, addr, n)
			}
		}
	}
}

// TestDngClassify: a wildcard check reads an answer as a records check of the
// same name does, and never as something of its own.
func TestDngClassify(t *testing.T) {
	const records = "records " + dngLabel1 + ".corp.test. 300 IN A " + dngWildAddr
	const cname = "records " + dngLabel1 + ".corp.test. 300 IN CNAME edge.dnshost.test."
	const viaDNAME = "records " + dngLabel1 + ".corp.test. 300 IN CNAME " + dngLabel1 + ".dnshost.test."
	tests := []struct {
		name     string
		ns1, ns2 string // mode of dngServe; "" keeps the zone
		want     []string
	}{
		{"no such name", "", "", []string{"ns1.corp.test. 10.0.1.1:53 noname corp.test.", "ns2.corp.test. 10.0.1.2:53 noname corp.test."}},
		{"no data", "nodata", "nodata", []string{"ns1.corp.test. 10.0.1.1:53 nodata corp.test.", "ns2.corp.test. 10.0.1.2:53 nodata corp.test."}},
		{"a wildcard answers", "wildcard", "wildcard", []string{"ns1.corp.test. 10.0.1.1:53 " + records, "ns2.corp.test. 10.0.1.2:53 " + records}},
		{"one server has a wildcard", "wildcard", "", []string{"ns1.corp.test. 10.0.1.1:53 " + records, "ns2.corp.test. 10.0.1.2:53 noname corp.test."}},
		{"one server has no data", "", "nodata", []string{"ns1.corp.test. 10.0.1.1:53 noname corp.test.", "ns2.corp.test. 10.0.1.2:53 nodata corp.test."}},
		{"one server refuses", "wildcard", "refused", []string{"ns1.corp.test. 10.0.1.1:53 " + records, "ns2.corp.test. 10.0.1.2:53 failure refused"}},
		// A cut is no answer of an authority: the referral at the random name is lame, as at any name.
		{"a referral at the name", "referral", "referral", []string{"ns1.corp.test. 10.0.1.1:53 failure lame", "ns2.corp.test. 10.0.1.2:53 failure lame"}},
		{"a CNAME answers", "cname", "cname", []string{"ns1.corp.test. 10.0.1.1:53 " + cname, "ns2.corp.test. 10.0.1.2:53 " + cname}},
		{"a DNAME covers the name", "dname", "dname", []string{"ns1.corp.test. 10.0.1.1:53 " + viaDNAME, "ns2.corp.test. 10.0.1.2:53 " + viaDNAME}},
		{"compact denial", "compact", "compact", []string{"ns1.corp.test. 10.0.1.1:53 noname-compact corp.test.", "ns2.corp.test. 10.0.1.2:53 noname-compact corp.test."}},
	}
	for _, tt := range tests {
		w := walkBase(t)
		for addr, mode := range map[string]string{"10.0.1.1": tt.ns1, "10.0.1.2": tt.ns2} {
			if mode != "" {
				dngServe(w, addr, mode)
			}
		}
		o, _ := dngObserver(t, w, dngLabel1)
		got := walkRun(t, o, dngKey(t, "corp.test.", "corp.test."), time.Minute)
		walkWant(t, tt.name, walkAnswers(got.Answers), tt.want)

		// The records check of the name that the label made gives the same.
		plain := walkRun(t, o, walkRecordsKey(t, "corp.test.", dngLabel1+".corp.test.", dnswire.TypeA), time.Minute)
		walkWant(t, tt.name+", as a records check", walkAnswers(plain.Answers), walkAnswers(got.Answers))
	}
}

// TestDngRecordsCheckUnchanged: a records check of the name of a wildcard
// check asks that name, draws no label and keeps its own key.
func TestDngRecordsCheckUnchanged(t *testing.T) {
	w := walkBase(t)
	o := walkObserver(t, w, &walkClock{}, time.Second)
	draws := new(atomic.Int32)
	o.label = func() string { draws.Add(1); return dngLabel1 }
	for _, c := range []struct {
		name string
		want []string
	}{
		{"corp.test.", []string{"ns1.corp.test. 10.0.1.1:53 nodata corp.test.", "ns2.corp.test. 10.0.1.2:53 nodata corp.test."}},
		{"www.corp.test.", []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW, "ns2.corp.test. 10.0.1.2:53 " + walkWWW}},
	} {
		key := walkRecordsKey(t, "corp.test.", c.name, dnswire.TypeA)
		ob := walkRun(t, o, key, time.Minute)
		walkWant(t, "records "+c.name, walkAnswers(ob.Answers), c.want)
		for _, a := range ob.Answers {
			if !a.Question.Name.Equal(walkName(t, c.name)) || a.Question.Type != dnswire.TypeA {
				t.Errorf("records %s: question %v %v", c.name, a.Question.Name, a.Question.Type)
			}
		}
		if got, want := ob.Key.String(), "records corp.test. "+c.name+" A"; got != want {
			t.Errorf("key text %q, want %q", got, want)
		}
	}
	if n := draws.Load(); n != 0 {
		t.Errorf("records checks drew %d labels, want 0", n)
	}
	if n := len(dngLabelQueries(w, dngLabel1)); n != 0 {
		t.Errorf("records checks sent the label %d times", n)
	}
}

// TestDngDefaultLabel: the label that New sets is 26 octets of a to z and 2
// to 7, and no two draws are the same.
func TestDngDefaultLabel(t *testing.T) {
	o, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 50 {
		l := o.label()
		if !dngInAlphabet(l) || len(l) != obs.WildcardLabel {
			t.Fatalf("label %q: want %d octets of a-z and 2-7", l, obs.WildcardLabel)
		}
		if seen[l] {
			t.Fatalf("label %q drawn twice", l)
		}
		seen[l] = true
	}
}

// TestDngDefaultLabelInRun: with the seam as New made it, a run asks one
// such label at every server of the zone and another label next time; no
// server above the zone sees either.
func TestDngDefaultLabelInRun(t *testing.T) {
	w := walkBase(t)
	o, _ := dngObserver(t, w)
	key := dngKey(t, "corp.test.", "corp.test.")
	var labels []string
	for range 2 {
		ob := walkRun(t, o, key, time.Minute)
		if len(ob.Answers) != 2 {
			t.Fatalf("%d answers, want 2", len(ob.Answers))
		}
		l := dngFirst(ob.Answers[0].Question.Name)
		if !dngInAlphabet(l) {
			t.Errorf("the label %q is not 26 octets of a-z and 2-7", l)
		}
		for _, a := range ob.Answers {
			if want := walkName(t, l+".corp.test."); !a.Question.Name.Equal(want) || a.Question.Type != dnswire.TypeA {
				t.Errorf("answer of %v asks %v %v, want %v A", a.Server.Addr, a.Question.Name, a.Question.Type, want)
			}
		}
		labels = append(labels, l)
	}
	if labels[0] == labels[1] {
		t.Errorf("two runs asked the same label %q", labels[0])
	}
	for _, a := range w.queries() {
		if l := dngFirst(a.query.Name); dngInAlphabet(l) && a.server.Addr().String() != "10.0.1.1" && a.server.Addr().String() != "10.0.1.2" {
			t.Errorf("the label %q went to %v, which is above the zone", l, a.server)
		}
	}
}

// TestDngFailedWalkAsksTheLabel: a walk that ends before any zone server is
// reached leaves one answer that names no address, and it still carries the
// question of the fan-out. The first server of test. refers corp.test. to a
// host that does not exist, and the other one never answers.
func TestDngFailedWalkAsksTheLabel(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "test. 300 NS ns2.test.", "ns.test. 300 A 10.0.0.2", "ns2.test. 300 A 10.0.0.3")
	bad := walkReferral(t, "corp.test. 300 NS ns.gone.example.")
	var mu sync.Mutex
	asked := false
	for _, a := range []string{"10.0.0.2", "10.0.0.3"} {
		w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			mu.Lock()
			first := !asked
			asked = true
			mu.Unlock()
			if first {
				return bad(ctx, q)
			}
			return walkDead(ctx, q)
		})
	}
	o := walkObserver(t, w, &walkClock{}, 200*time.Millisecond)
	o.label = func() string { return dngLabel1 }
	ob := walkRun(t, o, dngKey(t, "corp.test.", "corp.test."), time.Minute)
	if len(ob.Answers) != 1 {
		t.Fatalf("%d answers, want 1: %q", len(ob.Answers), walkAnswers(ob.Answers))
	}
	a := ob.Answers[0]
	if a.Server.Addr.IsValid() || walkCase(a.Result) != "failure walk" {
		t.Errorf("the answer is %s %s, want a failure of the walk with no address", walkServer(a.Server), walkCase(a.Result))
	}
	if q := a.Question; !q.Name.Equal(walkName(t, dngLabel1+".corp.test.")) || q.Type != dnswire.TypeA || q.Class != dnswire.ClassINET {
		t.Errorf("question %v %v %v, want %s.corp.test. A IN", q.Name, q.Type, q.Class, dngLabel1)
	}
	if n := len(dngLabelQueries(w, dngLabel1)); n != 0 {
		t.Errorf("%d packets held the label of a walk that failed", n)
	}
}

// TestDngRunningCheckDrawsNothing: a run that is refused because the same
// check runs already draws no label.
func TestDngRunningCheckDrawsNothing(t *testing.T) {
	w := walkBase(t)
	entered, release := make(chan struct{}, 2), make(chan struct{})
	for _, a := range []string{"10.0.1.1", "10.0.1.2"} {
		server := walkAddr(t, a)
		w.handle(a, func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			if q.Type == dnswire.TypeA {
				entered <- struct{}{}
				select {
				case <-release:
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			return w.answer(server, q), nil
		})
	}
	o, draws := dngObserver(t, w, dngLabel1, dngLabel2)
	key := dngKey(t, "corp.test.", "corp.test.")
	done := make(chan error, 1)
	go func() {
		_, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute})
		done <- err
	}()
	for range 2 {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("the first run never asked both servers")
		}
	}
	for range 3 {
		if _, err := o.Run(context.Background(), Check{Key: key, Interval: time.Minute}); !errors.Is(err, ErrRunning) {
			t.Errorf("second Run: %v, want ErrRunning", err)
		}
	}
	if n := draws.Load(); n != 1 {
		t.Errorf("%d labels drawn while one run was refused three times, want 1", n)
	}
	close(release)
	if err := <-done; err != nil {
		t.Errorf("first Run: %v", err)
	}
}

// TestDngDefaultLabelEveryPositionVaries: no part of the default label is
// fixed, so no one can guess it from its first octets.
func TestDngDefaultLabelEveryPositionVaries(t *testing.T) {
	o, err := New(Config{})
	if err != nil {
		t.Fatal(err)
	}
	var chars [obs.WildcardLabel]map[byte]bool
	for i := range chars {
		chars[i] = map[byte]bool{}
	}
	for range 200 {
		l := o.label()
		if len(l) != obs.WildcardLabel {
			t.Fatalf("label %q has %d octets, want %d", l, len(l), obs.WildcardLabel)
		}
		for i := range l {
			chars[i][l[i]] = true
		}
	}
	for i, set := range chars {
		if len(set) < 2 {
			t.Errorf("position %d of the label is always the same octet", i)
		}
	}
}
