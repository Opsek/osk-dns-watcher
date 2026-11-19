package observe

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The servers asked are not trusted, so these tests feed the code that reads
// their answers with any input. An input of FuzzClassify and FuzzReferral is
// four octets that choose the kind of check, the zone and the question, then
// one octet that says how the rest is read: odd, as the octets of an answer,
// through dnswire.Parse; even, as a short description that fuzzReader turns
// into a message, so that the fuzzer reaches deep cases without having to
// write a valid message first. Names come from a small pool, so that a name
// is often at, under or beside another one, in another case too.

var fuzzNameTexts = []string{
	".", "test.", "TEST.", "corp.test.", "Corp.TEST.", "www.corp.test.", "WWW.corp.test.", "x.www.corp.test.",
	"ns1.corp.test.", "ns2.corp.test.", "shop.test.", "ns1.dnshost.test.", "orp.test.", "corp.test.example.",
	"example.", `\000.www.corp.test.`,
}

var fuzzNames = func() []dnswire.Name {
	var names []dnswire.Name
	for _, s := range fuzzNameTexts {
		n, err := dnswire.ParseName(s)
		if err != nil {
			panic(err)
		}
		names = append(names, n)
	}
	return names
}()

var fuzzTypes = []dnswire.Type{
	dnswire.TypeA, dnswire.TypeNS, dnswire.TypeCNAME, dnswire.TypeSOA, dnswire.TypeAAAA, dnswire.TypeTXT,
	dnswire.TypeDS, dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeDNAME, dnswire.TypeMX, 65280,
}

// Values above 15 come from the OPT record: 0x100 and 0x103 hold NOERROR
// and NXDOMAIN in the bits of the header.
var fuzzRcodes = []dnswire.Rcode{0, 0, 0, 3, 3, 1, 2, 4, 5, 9, 16, 23, 19, 0x100, 0x103, 0xFFF}

// The type that a check of each kind asks.
var fuzzKindTypes = map[obs.Kind]dnswire.Type{
	obs.KindDelegation: dnswire.TypeNS,
	obs.KindDS:         dnswire.TypeDS,
	obs.KindSerial:     dnswire.TypeSOA,
	obs.KindWildcard:   dnswire.TypeA,
}

type fuzzReader struct{ b []byte }

// next returns the next octet, and 0 once the input is used up.
func (r *fuzzReader) next() byte {
	if len(r.b) == 0 {
		return 0
	}
	c := r.b[0]
	r.b = r.b[1:]
	return c
}

func (r *fuzzReader) name() dnswire.Name { return fuzzNames[int(r.next())%len(fuzzNames)] }

func (r *fuzzReader) typ() dnswire.Type { return fuzzTypes[int(r.next())%len(fuzzTypes)] }

// message reads a flags octet and an rcode octet, then records until the
// input ends.
func (r *fuzzReader) message() *dnswire.Message {
	flags := r.next()
	m := &dnswire.Message{Header: dnswire.Header{
		Response:           flags&1 != 0,
		Authoritative:      flags&2 != 0,
		Truncated:          flags&4 != 0,
		RecursionAvailable: flags&8 != 0,
		Rcode:              fuzzRcodes[int(r.next())%len(fuzzRcodes)],
	}}
	for len(r.b) > 0 {
		section := r.next() % 3
		rec := r.record()
		switch section {
		case 0:
			m.Answer = append(m.Answer, rec)
		case 1:
			m.Authority = append(m.Authority, rec)
		default:
			m.Additional = append(m.Additional, rec)
		}
	}
	return m
}

// record reads an owner, a class, a type and a TTL octet, then the octets
// that the data of its type needs.
func (r *fuzzReader) record() dnswire.Record {
	rec := dnswire.Record{Name: r.name(), Class: dnswire.ClassINET}
	switch r.next() % 8 {
	case 6:
		rec.Class = dnswire.ClassCHAOS
	case 7:
		rec.Class = dnswire.ClassANY
	}
	typ := r.next()
	rec.TTL = uint32(r.next())
	switch typ % 11 {
	case 0:
		rec.Data = dnswire.A{Addr: netip.AddrFrom4([4]byte{10, 53, 7, r.next()})}
	case 1:
		rec.Data = dnswire.AAAA{Addr: netip.AddrFrom16([16]byte{0: 0xfd, 1: 0x53, 15: r.next()})}
	case 2:
		rec.Data = dnswire.NS{Host: r.name()}
	case 3:
		rec.Data = dnswire.CNAME{Target: r.name()}
	case 4:
		rec.Data = dnswire.SOA{MName: r.name(), Serial: 1, Minimum: uint32(r.next())}
	case 5:
		rec.Data = dnswire.NSEC{NextName: r.name(), Types: r.bitmap()}
	case 6:
		rec.Data = dnswire.RRSIG{TypeCovered: r.typ(), Algorithm: 13, SignerName: r.name()}
	case 7:
		rec.Data = dnswire.TXT{Strings: []string{"x"}}
	case 8:
		rec.Data = dnswire.DNAME{Target: r.name()}
	case 9:
		rec.Data = dnswire.DS{KeyTag: 1, Algorithm: 13, DigestType: 2, Digest: make([]byte, 32)}
	default:
		rec.Data = dnswire.Unknown{TypeCode: 65280, Data: []byte{r.next()}}
	}
	return rec
}

// bitmap reads one octet whose bits choose the types of an NSEC record.
func (r *fuzzReader) bitmap() []dnswire.Type {
	bits := r.next()
	var types []dnswire.Type
	for i, t := range []dnswire.Type{dnswire.TypeA, dnswire.TypeNS, dnswire.TypeSOA, dnswire.TypeTXT,
		dnswire.TypeAAAA, dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeNXNAME} {
		if bits&(1<<i) != 0 {
			types = append(types, t)
		}
	}
	return types
}

type fuzzCase struct {
	kind obs.Kind
	zone dnswire.Name
	q    dnswire.Question
	m    *dnswire.Message // nil when the octets do not parse
}

func fuzzRead(b []byte) fuzzCase {
	r := &fuzzReader{b: b}
	c := fuzzCase{kind: obs.Kind(r.next()%5 + 1), zone: r.name()}
	c.q = dnswire.Question{Name: r.name(), Type: r.typ(), Class: dnswire.ClassINET}
	if t, ok := fuzzKindTypes[c.kind]; ok {
		c.q.Type = t
	}
	if r.next()%2 == 0 {
		c.m = r.message()
	} else if m, err := dnswire.Parse(r.b); err == nil {
		c.m = m
	}
	return c
}

func FuzzClassify(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c := fuzzRead(b)
		if c.m == nil {
			return
		}
		got := classify(c.kind, c.zone, c.q, c.m)
		text := fuzzResultText(got)
		if again := fuzzResultText(classify(c.kind, c.zone, c.q, c.m)); again != text {
			t.Fatalf("the same answer read twice gives %s, then %s", text, again)
		}
		// The answer is read against the question asked. What it says it
		// answers, its ID, its opcode and the flags that no rule reads change
		// nothing.
		other := *c.m
		other.ID = ^other.ID
		other.Opcode = (other.Opcode + 1) % 16
		other.Response = !other.Response
		other.RecursionDesired = !other.RecursionDesired
		other.RecursionAvailable = !other.RecursionAvailable
		other.AuthenticData = !other.AuthenticData
		other.CheckingDisabled = !other.CheckingDisabled
		other.Question = []dnswire.Question{{Name: c.zone, Type: dnswire.TypeANY, Class: dnswire.ClassCHAOS}}
		if changed := fuzzResultText(classify(c.kind, c.zone, c.q, &other)); changed != text {
			t.Fatalf("the header and question of the answer changed %s into %s", text, changed)
		}

		if want := fuzzWant(c); fuzzCaseOf(got) != want {
			t.Fatalf("%s %v %v from a server of %v: %s; the answer reads as %s",
				c.kind, c.q.Name, c.q.Type, c.zone, text, want)
		}
		obs.Match(got,
			func(r obs.Records) any {
				set, glue := fuzzWantRecords(c)
				if fuzzText(r.Set) != fuzzText(set) || fuzzText(r.Glue) != fuzzText(glue) {
					t.Fatalf("records %s glue %s; want %s glue %s", fuzzText(r.Set), fuzzText(r.Glue), fuzzText(set), fuzzText(glue))
				}
				return nil
			},
			func(n obs.NoData) any { return fuzzCheckSOA(t, c, n.SOA) },
			func(n obs.NoName) any { return fuzzCheckSOA(t, c, n.SOA) },
			func(f obs.Failure) any {
				if limit := fuzzDetailLimit(c.m); len(f.Detail) > limit {
					t.Fatalf("a detail of %d octets; the answer allows %d", len(f.Detail), limit)
				}
				return nil
			})
	})
}

// fuzzWant reads the answer by the rules of classify, in their order, and
// returns the case it must give: a failure reason, or records, nodata,
// noname or noname-compact. A truncated answer and an rcode other than
// NOERROR and NXDOMAIN are failures; only a referral to the asked name, in a
// delegation check, may give records without AA; a denial needs AA and one
// SOA between the zone and the name.
func fuzzWant(c fuzzCase) string {
	m, q := c.m, c.q
	cut, isReferral := fuzzReferral(c.zone, q.Name, m)
	cnames := len(fuzzSet(m.Answer, q.Name, dnswire.TypeCNAME))
	switch {
	case m.Truncated:
		return "truncated"
	case m.Rcode == 5:
		return "refused"
	case m.Rcode == 2:
		return "servfail"
	case m.Rcode != 0 && m.Rcode != 3:
		return "rcode"
	case c.kind == obs.KindDelegation && isReferral && cut.Equal(q.Name):
		return "records"
	case !m.Authoritative:
		return "lame"
	case len(fuzzSet(m.Answer, q.Name, q.Type)) > 0:
		return "records"
	case q.Type != dnswire.TypeCNAME && cnames > 1:
		return "bad-answer"
	case q.Type != dnswire.TypeCNAME && cnames == 1:
		return "records"
	}
	if _, ok := fuzzDenialSOA(c.zone, q.Name, m.Authority); !ok {
		return "bad-answer"
	}
	switch {
	case m.Rcode == 3:
		return "noname"
	case fuzzCompact(q.Name, m.Authority):
		return "noname-compact"
	}
	return "nodata"
}

// fuzzWantRecords returns the set and the glue of a records case: the NS set
// of the referral, or the records of the asked name and type in the answer
// section, or else its one CNAME.
func fuzzWantRecords(c fuzzCase) (set, glue []dnswire.Record) {
	m, q := c.m, c.q
	if cut, ok := fuzzReferral(c.zone, q.Name, m); ok && c.kind == obs.KindDelegation && cut.Equal(q.Name) {
		set = fuzzSet(m.Authority, q.Name, dnswire.TypeNS)
	} else if set = fuzzSet(m.Answer, q.Name, q.Type); len(set) == 0 {
		return fuzzSet(m.Answer, q.Name, dnswire.TypeCNAME), nil
	}
	if c.kind == obs.KindDelegation {
		glue = fuzzGlue(c.zone, fuzzHosts(set), m.Additional)
	}
	return set, glue
}

func fuzzCheckSOA(t *testing.T, c fuzzCase, soa dnswire.Record) any {
	t.Helper()
	if want, ok := fuzzDenialSOA(c.zone, c.q.Name, c.m.Authority); !ok || soa.String() != want.String() {
		t.Fatalf("a denial with the SOA %v; want %v", soa, want)
	}
	return nil
}

// fuzzDetailLimit bounds the detail of a failure: three names, each at most
// 1020 characters in escaped form, and the text of each extended error,
// quoted, at most four characters for each octet.
func fuzzDetailLimit(m *dnswire.Message) int {
	limit := 4096
	if m.EDNS != nil {
		for _, o := range m.EDNS.Options {
			limit += 16 + 4*len(o.Data)
		}
	}
	return limit
}

func FuzzReferral(f *testing.F) {
	for _, s := range fuzzSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		c := fuzzRead(b)
		if c.m == nil {
			return
		}
		zone, target, m := c.zone, c.q.Name, c.m
		cut, hosts, glue, ok := referral(zone, target, m)
		wantCut, wantOK := fuzzReferral(zone, target, m)
		if ok != wantOK {
			t.Fatalf("referral from a server of %v toward %v: ok %v, want %v", zone, target, ok, wantOK)
		}
		if ok {
			wantHosts := fuzzDistinct(fuzzHosts(fuzzSet(m.Authority, wantCut, dnswire.TypeNS)))
			if !cut.Equal(wantCut) || fmt.Sprint(hosts) != fmt.Sprint(wantHosts) {
				t.Fatalf("cut %v hosts %v; want %v %v", cut, hosts, wantCut, wantHosts)
			}
			if want := fuzzGlue(zone, wantHosts, m.Additional); fuzzText(glue) != fuzzText(want) {
				t.Fatalf("glue %s; want %s", fuzzText(glue), fuzzText(want))
			}
		}

		// glueOf alone, for every host that the answer names anywhere.
		hostsAnywhere := fuzzHosts(slices.Concat(m.Answer, m.Authority, m.Additional))
		if got, want := glueOf(zone, hostsAnywhere, m.Additional), fuzzGlue(zone, hostsAnywhere, m.Additional); fuzzText(got) != fuzzText(want) {
			t.Fatalf("glueOf from a server of %v for %v: %s; want %s", zone, hostsAnywhere, fuzzText(got), fuzzText(want))
		}
		soa, problem := negativeSOA(zone, target, m.Authority)
		if want, ok := fuzzDenialSOA(zone, target, m.Authority); (problem == "") != ok || ok && soa.String() != want.String() {
			t.Fatalf("negativeSOA from a server of %v for %v: %v %q; want %v %v", zone, target, soa, problem, want, ok)
		}
		if got, want := compactDenial(target, m.Authority), fuzzCompact(target, m.Authority); got != want {
			t.Fatalf("compactDenial for %v: %v, want %v", target, got, want)
		}
	})
}

// fuzzReferral reads m as a referral from a server of zone toward target: a
// NOERROR answer without AA and without answer records, whose NS records of
// class IN all have one owner, the cut. A cut at or above the zone, beside
// it, or not above the target, is refused: the walk only goes down.
func fuzzReferral(zone, target dnswire.Name, m *dnswire.Message) (cut dnswire.Name, ok bool) {
	var ns []dnswire.Record
	for _, r := range m.Authority {
		if r.Class == dnswire.ClassINET && r.Type() == dnswire.TypeNS {
			ns = append(ns, r)
		}
	}
	if m.Rcode != 0 || m.Authoritative || len(m.Answer) > 0 || len(ns) == 0 {
		return cut, false
	}
	cut = ns[0].Name
	for _, r := range ns {
		if !r.Name.Equal(cut) {
			return cut, false
		}
	}
	return cut, !cut.Equal(zone) && cut.IsSubdomainOf(zone) && target.IsSubdomainOf(cut)
}

// fuzzGlue returns the address records that a server of zone may give for
// hosts: class IN, type A or AAAA, an owner equal to a host and at or under
// the zone; in the order of the message.
func fuzzGlue(zone dnswire.Name, hosts []dnswire.Name, additional []dnswire.Record) []dnswire.Record {
	var glue []dnswire.Record
	for _, r := range additional {
		t := r.Type()
		if r.Class == dnswire.ClassINET && (t == dnswire.TypeA || t == dnswire.TypeAAAA) &&
			r.Name.IsSubdomainOf(zone) && slices.ContainsFunc(hosts, r.Name.Equal) {
			glue = append(glue, r)
		}
	}
	return glue
}

// fuzzDenialSOA returns the one SOA of class IN in authority, and whether
// it may deny name for a server of zone: its owner lies between the two.
func fuzzDenialSOA(zone, name dnswire.Name, authority []dnswire.Record) (dnswire.Record, bool) {
	var soas []dnswire.Record
	for _, r := range authority {
		if r.Class == dnswire.ClassINET && r.Type() == dnswire.TypeSOA {
			soas = append(soas, r)
		}
	}
	if len(soas) != 1 {
		return dnswire.Record{}, false
	}
	return soas[0], name.IsSubdomainOf(soas[0].Name) && soas[0].Name.IsSubdomainOf(zone)
}

func fuzzCompact(name dnswire.Name, authority []dnswire.Record) bool {
	for _, r := range authority {
		if d, ok := r.Data.(dnswire.NSEC); ok && r.Class == dnswire.ClassINET && r.Name.Equal(name) &&
			slices.Contains(d.Types, dnswire.TypeNXNAME) {
			return true
		}
	}
	return false
}

// fuzzSet returns the records of class IN, owner and type, in message order.
func fuzzSet(records []dnswire.Record, owner dnswire.Name, t dnswire.Type) []dnswire.Record {
	var set []dnswire.Record
	for _, r := range records {
		if r.Class == dnswire.ClassINET && r.Name.Equal(owner) && r.Type() == t {
			set = append(set, r)
		}
	}
	return set
}

func fuzzHosts(records []dnswire.Record) []dnswire.Name {
	var hosts []dnswire.Name
	for _, r := range records {
		if d, ok := r.Data.(dnswire.NS); ok {
			hosts = append(hosts, d.Host)
		}
	}
	return hosts
}

// fuzzDistinct keeps the first of names that are equal.
func fuzzDistinct(names []dnswire.Name) []dnswire.Name {
	var out []dnswire.Name
	for _, n := range names {
		if !slices.ContainsFunc(out, n.Equal) {
			out = append(out, n)
		}
	}
	return out
}

func fuzzText(records []dnswire.Record) string {
	var lines []string
	for _, r := range records {
		lines = append(lines, r.String())
	}
	return fmt.Sprintf("%q", lines)
}

func fuzzResultText(r obs.Result) string {
	return obs.Match(r,
		func(r obs.Records) string { return "records " + fuzzText(r.Set) + " glue " + fuzzText(r.Glue) },
		func(n obs.NoData) string { return "nodata " + n.SOA.String() },
		func(n obs.NoName) string { return "noname " + strconv.FormatBool(n.Compact) + " " + n.SOA.String() },
		func(f obs.Failure) string { return "failure " + f.Reason.String() + " " + strconv.Quote(f.Detail) })
}

func fuzzCaseOf(r obs.Result) string {
	return obs.Match(r,
		func(obs.Records) string { return "records" },
		func(obs.NoData) string { return "nodata" },
		func(n obs.NoName) string {
			if n.Compact {
				return "noname-compact"
			}
			return "noname"
		},
		func(f obs.Failure) string { return f.Reason.String() })
}

// fuzzAnswer is an answer to the question of a seed.
type fuzzAnswer struct {
	header                        dnswire.Header
	answer, authority, additional []dnswire.Record
	options                       []dnswire.Option
}

// fuzzWire writes the answer to q as a server sends it, with an OPT record
// that holds the options and the upper bits of the rcode.
func fuzzWire(q dnswire.Question, a fuzzAnswer) []byte {
	h := a.header
	flags := uint16(h.Opcode&0xF)<<11 | uint16(h.Rcode&0xF)
	for bit, on := range map[uint16]bool{0x8000: h.Response, 0x400: h.Authoritative, 0x200: h.Truncated,
		0x100: h.RecursionDesired, 0x80: h.RecursionAvailable, 0x20: h.AuthenticData, 0x10: h.CheckingDisabled} {
		if on {
			flags |= bit
		}
	}
	b := binary.BigEndian.AppendUint16(nil, h.ID)
	b = binary.BigEndian.AppendUint16(b, flags)
	for _, n := range []int{1, len(a.answer), len(a.authority), len(a.additional) + 1} {
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	b = q.Name.AppendWire(b)
	b = binary.BigEndian.AppendUint16(b, uint16(q.Type))
	b = binary.BigEndian.AppendUint16(b, uint16(q.Class))
	for _, r := range slices.Concat(a.answer, a.authority, a.additional) {
		b = dnswire.AppendRecord(b, r)
	}
	var options []byte
	for _, o := range a.options {
		options = binary.BigEndian.AppendUint16(options, o.Code)
		options = binary.BigEndian.AppendUint16(options, uint16(len(o.Data)))
		options = append(options, o.Data...)
	}
	b = append(b, 0) // the root, owner of the OPT record
	b = binary.BigEndian.AppendUint16(b, uint16(dnswire.TypeOPT))
	b = binary.BigEndian.AppendUint16(b, 1232)
	b = binary.BigEndian.AppendUint32(b, uint32(h.Rcode>>4)<<24|0x8000)
	b = binary.BigEndian.AppendUint16(b, uint16(len(options)))
	return append(b, options...)
}

// fuzzParsed is fuzzWire for a seed: a seed that does not parse would test
// nothing.
func fuzzParsed(q dnswire.Question, a fuzzAnswer) []byte {
	b := fuzzWire(q, a)
	if _, err := dnswire.Parse(b); err != nil {
		panic(err)
	}
	return b
}

// fuzzRR reads "owner ttl type data" as a record of class IN.
func fuzzRR(text string) dnswire.Record {
	f := strings.Fields(text)
	name, err := dnswire.ParseName(f[0])
	if err != nil {
		panic(err)
	}
	ttl, err := strconv.ParseUint(f[1], 10, 32)
	if err != nil {
		panic(err)
	}
	typ, err := dnswire.ParseType(f[2])
	if err != nil {
		panic(err)
	}
	data, err := dnswire.ParseRData(typ, strings.Join(f[3:], " "))
	if err != nil {
		panic(err)
	}
	return dnswire.Record{Name: name, Class: dnswire.ClassINET, TTL: uint32(ttl), Data: data}
}

func fuzzRRs(texts ...string) []dnswire.Record {
	var rs []dnswire.Record
	for _, s := range texts {
		rs = append(rs, fuzzRR(s))
	}
	return rs
}

func fuzzIndex(name string) byte {
	i := slices.Index(fuzzNameTexts, name)
	if i < 0 {
		panic("no name " + name + " in the pool")
	}
	return byte(i)
}

// fuzzSetup gives the first four octets of an input.
func fuzzSetup(kind obs.Kind, zone, name string, t dnswire.Type) []byte {
	return []byte{byte(kind - 1), fuzzIndex(zone), fuzzIndex(name), byte(slices.Index(fuzzTypes, t))}
}

// fuzzSeeds gives answers of each case that classify tells apart, and a few
// described messages.
func fuzzSeeds() [][]byte {
	rr := fuzzRRs
	corpNS := rr("corp.test. 3600 NS ns1.corp.test.", "corp.test. 3600 NS ns2.corp.test.")
	glue := rr("ns1.corp.test. 3600 A 10.53.7.11", "ns2.corp.test. 3600 AAAA fd53::12",
		"ns.example. 3600 A 192.0.2.53", "www.corp.test. 3600 A 10.53.7.81")
	soa := rr("corp.test. 300 SOA ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")
	www := "www.corp.test. 300 A 10.53.7.81"
	nxname := `www.corp.test. 300 NSEC \000.www.corp.test. RRSIG NSEC TYPE128`
	aa := dnswire.Header{Response: true, Authoritative: true}
	referral := dnswire.Header{Response: true}
	ede := dnswire.Option{Code: 15, Data: []byte("\x00\x16no \"reachable\" authority\xff")}
	cases := []struct {
		kind       obs.Kind
		zone, name string
		typ        dnswire.Type
		answer     fuzzAnswer
	}{
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa,
			answer: rr(www, "WWW.Corp.Test. 60 A 10.53.7.85", "mail.corp.test. 300 A 10.53.7.82",
				"www.corp.test. 300 RRSIG A 13 3 300 20261201000000 20261101000000 4711 corp.test. AAAA"),
			authority: corpNS, additional: glue}},
		{obs.KindDelegation, "test.", "corp.test.", dnswire.TypeNS, fuzzAnswer{header: referral, authority: corpNS, additional: glue}},
		{obs.KindDelegation, "test.", "corp.test.", dnswire.TypeNS, fuzzAnswer{header: aa, answer: corpNS, additional: glue}},
		{obs.KindRecords, "test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: referral, authority: corpNS, additional: glue}},
		{obs.KindRecords, ".", "www.corp.test.", dnswire.TypeNS, fuzzAnswer{header: referral,
			authority:  rr("test. 86400 NS ns.test.", "test. 86400 NS ns1.dnshost.test."),
			additional: rr("ns.test. 86400 A 10.53.7.3", "ns1.dnshost.test. 86400 AAAA fd53::3")}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Authoritative: true, Rcode: 3}, authority: soa}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa, authority: soa}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa, authority: append(rr(nxname), soa...)}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Authoritative: true, Rcode: 3},
			answer: rr("www.corp.test. 300 CNAME edge.example."), authority: soa}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa,
			answer: rr("www.corp.test. 300 CNAME edge.example.", "www.corp.test. 300 CNAME ns1.corp.test."), authority: soa}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Authoritative: true, Truncated: true}, answer: rr(www)}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Rcode: 2}, options: []dnswire.Option{ede, ede}}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Rcode: 5}, answer: rr(www)}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: dnswire.Header{Response: true, Authoritative: true, Rcode: 23}, authority: soa}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa,
			authority: rr("shop.test. 300 SOA ns1.dnshost.test. hostmaster.shop.test. 1 3600 600 604800 300")}},
		{obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA, fuzzAnswer{header: aa, authority: append(soa, soa...)}},
		{obs.KindSerial, "corp.test.", "corp.test.", dnswire.TypeSOA, fuzzAnswer{header: aa, answer: soa, authority: corpNS}},
	}
	var seeds [][]byte
	for _, c := range cases {
		q := dnswire.Question{Name: fuzzNames[fuzzIndex(c.name)], Type: c.typ, Class: dnswire.ClassINET}
		seeds = append(seeds, slices.Concat(fuzzSetup(c.kind, c.zone, c.name, c.typ), []byte{1}, fuzzParsed(q, c.answer)))
	}

	// Described: mode 0, flags (2 is AA), rcode index, then records of
	// section, owner, class, type and TTL octets and the data octets.
	rec := func(section byte, owner string, typ byte, data ...byte) []byte {
		return append([]byte{section, fuzzIndex(owner), 0, typ, 60}, data...)
	}
	const typA, typAAAA, typNS, typCNAME, typSOA, typNSEC = 0, 1, 2, 3, 4, 5
	records := fuzzSetup(obs.KindRecords, "corp.test.", "www.corp.test.", dnswire.TypeA)
	return append(seeds,
		slices.Concat(records, []byte{0, 2, 0}, rec(1, "corp.test.", typSOA, fuzzIndex("ns1.corp.test."), 30)),
		slices.Concat(records, []byte{0, 2, 0}, rec(1, "corp.test.", typSOA, fuzzIndex("ns1.corp.test."), 30),
			rec(1, "www.corp.test.", typNSEC, fuzzIndex("x.www.corp.test."), 0x80)),
		slices.Concat(records, []byte{0, 2, 3}, rec(0, "www.corp.test.", typCNAME, fuzzIndex("ns1.dnshost.test."))),
		slices.Concat(fuzzSetup(obs.KindDelegation, "test.", "corp.test.", dnswire.TypeNS), []byte{0, 0, 0},
			rec(1, "corp.test.", typNS, fuzzIndex("ns1.corp.test.")), rec(1, "Corp.TEST.", typNS, fuzzIndex("ns1.dnshost.test.")),
			rec(2, "ns1.corp.test.", typA, 11), rec(2, "ns1.dnshost.test.", typAAAA, 12), rec(2, "corp.test.example.", typA, 13)),
	)
}

// The client cookie of the server under test, fixed so that an answer in
// the seeds can echo it.
var fuzzClient = [8]byte{'c', 'l', 'i', 'e', 'n', 't', '0', '1'}

// Two ports of one address, and an IPv4 address in its mapped form, are
// other servers.
var fuzzServers = []netip.AddrPort{
	netip.MustParseAddrPort("192.0.2.1:53"),
	netip.MustParseAddrPort("192.0.2.1:5353"),
	netip.MustParseAddrPort("[2001:db8::1]:53"),
	netip.MustParseAddrPort("[::ffff:192.0.2.1]:53"),
}

// options reads a count octet, then for each option a code octet, a flag
// octet that puts client in front, and a length octet with that many octets.
// A count of 4 gives no OPT record.
func (r *fuzzReader) options(client []byte) *dnswire.EDNS {
	count := r.next() % 5
	if count == 4 {
		return nil
	}
	e := &dnswire.EDNS{UDPSize: 1232}
	for range count {
		code := []uint16{10, 10, 15, 3}[r.next()%4]
		var data []byte
		if r.next()%2 == 1 {
			data = slices.Clone(client)
		}
		for range r.next() % 48 {
			data = append(data, r.next())
		}
		e.Options = append(e.Options, dnswire.Option{Code: code, Data: data})
	}
	return e
}

// An input of FuzzCookieAccept is a server octet, a state octet, a mode
// octet, then options as fuzzReader.options reads them (mode even) or the
// octets of an answer (mode odd).
func FuzzCookieAccept(f *testing.F) {
	for _, s := range fuzzCookieSeeds() {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		r := &fuzzReader{b: b}
		i := int(r.next())
		server, other := fuzzServers[i%len(fuzzServers)], fuzzServers[(i+1)%len(fuzzServers)]
		state := r.next()
		jar := newCookieJar()
		jar.get(other)
		jar.servers[other].server = []byte("cookie of another server")
		jar.get(server)
		jar.servers[server].client = fuzzClient
		if state&1 != 0 {
			jar.servers[server].server = []byte("old server cookie")
		}
		sent, _ := jar.get(server)
		if state&2 != 0 {
			// The jar dropped the server while the query was out, and may
			// have made a new client cookie for it since.
			delete(jar.servers, server)
			jar.order = slices.DeleteFunc(jar.order, func(a netip.AddrPort) bool { return a == server })
			if state&4 != 0 {
				jar.get(server)
			}
		}
		m := &dnswire.Message{Header: dnswire.Header{Response: true}}
		if r.next()%2 == 0 {
			m.EDNS = r.options(fuzzClient[:])
		} else if parsed, err := dnswire.Parse(r.b); err == nil {
			m = parsed
		} else {
			return
		}

		before, order := fuzzJar(jar), slices.Clone(jar.order)
		pair, kept := jar.servers[server]
		stored, ok := jar.accept(server, sent, m)
		wantOK, wantStored := fuzzWantCookie(sent, m.EDNS)
		if !kept || pair.client != fuzzClient {
			wantStored = nil
		}
		if ok != wantOK || !bytes.Equal(stored, wantStored) || (stored == nil) != (wantStored == nil) {
			t.Fatalf("accept of %v: %x %v; want %x %v", m.EDNS, stored, ok, wantStored, wantOK)
		}
		want := maps.Clone(before)
		if wantStored != nil {
			want[server] = fuzzPair(fuzzClient[:], wantStored)
		}
		if after := fuzzJar(jar); !maps.Equal(after, want) || !slices.Equal(jar.order, order) {
			t.Fatalf("accept of %v left the jar %v %v; want %v %v", m.EDNS, after, jar.order, want, order)
		}
	})
}

// fuzzWantCookie applies the cookie rules to the options of an answer: no
// cookie option is fine; else there is one, of 8 or 16 to 40 octets, that
// starts with the client cookie sent. Its server cookie is the rest.
func fuzzWantCookie(sent []byte, e *dnswire.EDNS) (ok bool, server []byte) {
	var cookies [][]byte
	if e != nil {
		for _, o := range e.Options {
			if o.Code == 10 {
				cookies = append(cookies, o.Data)
			}
		}
	}
	if len(cookies) == 0 {
		return true, nil
	}
	c := cookies[0]
	if len(cookies) > 1 || len(c) != 8 && (len(c) < 16 || len(c) > 40) || !bytes.Equal(c[:8], sent[:8]) {
		return false, nil
	}
	if len(c) == 8 {
		return true, nil
	}
	return true, c[8:]
}

func fuzzJar(j *cookieJar) map[netip.AddrPort]string {
	s := map[netip.AddrPort]string{}
	for a, c := range j.servers {
		s[a] = fuzzPair(c.client[:], c.server)
	}
	return s
}

func fuzzPair(client, server []byte) string { return fmt.Sprintf("%x/%x", client, server) }

func fuzzCookieSeeds() [][]byte {
	echo := func(n int) []byte { return slices.Concat([]byte{1, byte(n)}, bytes.Repeat([]byte{0x5A}, n)) }
	foreign := []byte{0, 16, 'n', 'o', 't', ' ', 'o', 'u', 'r', 's', ' ', 's', 'e', 'r', 'v', 'e', 'r', '!'}
	seeds := [][]byte{
		// A new server cookie, the client cookie alone, the longest server
		// cookie, one octet too long, one octet too short.
		slices.Concat([]byte{0, 0, 0, 1, 0}, echo(8)),
		slices.Concat([]byte{0, 1, 0, 1, 0}, echo(0)),
		slices.Concat([]byte{1, 1, 0, 1, 0}, echo(32)),
		slices.Concat([]byte{1, 0, 0, 1, 0}, echo(33)),
		slices.Concat([]byte{2, 0, 0, 1, 0}, echo(7)),
		// The server was dropped, and came back with a new client cookie.
		slices.Concat([]byte{2, 2, 0, 1, 0}, echo(8)),
		slices.Concat([]byte{3, 6, 0, 1, 0}, echo(8)),
		// Two cookies, another client cookie, no OPT record, only an
		// extended error.
		slices.Concat([]byte{0, 0, 0, 2, 0}, echo(8), []byte{1}, echo(8)),
		slices.Concat([]byte{0, 0, 0, 1, 0}, foreign),
		{0, 0, 0, 4},
		slices.Concat([]byte{3, 1, 0, 1, 2}, echo(8)),
	}
	q := dnswire.Question{Name: fuzzNames[fuzzIndex("www.corp.test.")], Type: dnswire.TypeA, Class: dnswire.ClassINET}
	for _, data := range [][]byte{
		slices.Concat(fuzzClient[:], []byte("server cookie 01")),
		slices.Concat(fuzzClient[:], bytes.Repeat([]byte{'s'}, 33)),
		[]byte("not ours server cookie 1"),
	} {
		a := fuzzAnswer{header: dnswire.Header{Response: true, Authoritative: true}, options: []dnswire.Option{{Code: 10, Data: data}}}
		seeds = append(seeds, slices.Concat([]byte{0, 1, 1}, fuzzParsed(q, a)))
	}
	return seeds
}
