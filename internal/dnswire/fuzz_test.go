package dnswire_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// wireParseSeeds returns messages of every layout that the decoder reads and
// of every way a message breaks a limit; ok tells which is which.
func wireParseSeeds() []wireCase {
	example := wireLabels("example", "test")
	ns1 := wireLabels("ns1", "example", "test")
	q := wireQuestion(example, wireTypeA)
	plain := wireMessage(0x8400, [][]byte{q}, [][]byte{wireA(wirePointer(12))}, nil, nil)
	aaaa := []byte{0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1}
	soaTimes := wireCat(wireU32(2026111101), wireU32(7200), wireU32(3600), wireU32(1209600), wireU32(300))
	// Window 0 holds types 1 and 128, window 255 holds type 65280.
	bitmap := wireCat([]byte{0, 17, 0x40}, make([]byte, 15), []byte{0x80, 0xFF, 1, 0x80})

	cases := []wireCase{
		{"plain answer", plain, true},
		{"referral with glue", wireMessage(wireFlagQR,
			[][]byte{wireQuestion(wireLabels("www", "example", "test"), wireTypeA)}, nil,
			[][]byte{wireRR(example, wireTypeNS, wireClassIN, 3600, ns1)},
			[][]byte{wireA(ns1), wireRR(ns1, 28, wireClassIN, 3600, aaaa), wireOPT(1232, 0, 0, 0)}), true},
		{"compression in owners and data", wireMessage(0x8400, [][]byte{q}, [][]byte{
			wireRR(wirePointer(12), 5, wireClassIN, 300, wireLabelAndPointer("www", 12)),
			wireRR(wirePointer(12), wireTypeNS, wireClassIN, 300, wireLabelAndPointer("ns1", 12)),
			wireRR(wirePointer(12), 15, wireClassIN, 300, wireCat(wireU16(10), wireLabelAndPointer("mail", 12))),
			wireRR(wirePointer(12), wireTypeSOA, wireClassIN, 300,
				wireCat(wireLabelAndPointer("ns1", 12), wireLabelAndPointer("hostmaster", 12), soaTimes)),
			wireRR(wirePointer(12), wireTypePTR, wireClassIN, 300, wireLabelAndPointer("host", 12)),
		}, nil, nil), true},
		{"unknown type with data", wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(example, []byte{1, 2, 3, 4})}, nil, nil), true},
		{"unknown type without data", wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(example, nil)}, nil, nil), true},
		{"OPT with a cookie and two extended errors", wireMessage(wireFlagQR, [][]byte{q}, nil, nil, [][]byte{
			wireOPT(1232, 0, 0, 0x8000, wireOption(10, wireOctets(16)), wireOption(15, wireU16(6)),
				wireOption(15, wireCat(wireU16(22), []byte("no reachable authority")))),
		}), true},
		{"TSIG last", wireMessage(wireFlagQR, [][]byte{q}, [][]byte{wireA(wirePointer(12))}, nil,
			[][]byte{wireOPT(1232, 0, 0, 0), wireTSIG()}), true},
		{"255-octet name", wireMessage(wireFlagQR, nil, [][]byte{wireA(wireLongName())}, nil, nil), true},
		{"pointer loop", wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(wireLabelAndPointer("a", 12), nil)}, nil, nil), false},
		{"forward pointer", wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(wirePointer(24), nil), wirePrivate(wireLabels(), nil)}, nil, nil), false},
		{"pointer into the header", wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(wirePointer(11), nil)}, nil, nil), false},
		{"129 pointers", wirePointerChain(129), false},
		{"count too high", wireWithCounts(plain, 1, 2, 0, 0), false},
		{"trailing octet", append(bytes.Clone(plain), 0), false},
	}

	typed := []struct {
		name string
		typ  uint16
		data []byte
	}{
		{"A", 1, []byte{192, 0, 2, 1}},
		{"NS", 2, ns1},
		{"CNAME", 5, wireLabels("www", "example", "test")},
		{"SOA", 6, wireCat(ns1, wireLabels("hostmaster", "example", "test"), soaTimes)},
		{"PTR", 12, wireLabels("host", "example", "test")},
		{"MX", 15, wireCat(wireU16(10), wireLabels("mail", "example", "test"))},
		{"TXT", 16, wireCat([]byte{11}, []byte("v=spf1 -all"), []byte{0})},
		{"AAAA", 28, aaaa},
		{"DNAME", 39, wireLabels("example", "net")},
		{"DS", 43, wireCat(wireU16(12345), []byte{8, 2}, bytes.Repeat([]byte{0xD5}, 32))},
		{"RRSIG", 46, wireCat(wireU16(1), []byte{8, 2}, wireU32(300), wireU32(0x6A000000), wireU32(0x69000000),
			wireU16(12345), example, wireOctets(8))},
		{"NSEC with types 1, 128 and 65280", 47, wireCat(wireLabels("a", "example", "test"), bitmap)},
		{"DNSKEY", 48, wireCat(wireU16(257), []byte{3, 8}, wireOctets(8))},
		{"NSEC3", 50, wireCat([]byte{1, 0}, wireU16(0), []byte{2, 0xAB, 0xCD, 20}, bytes.Repeat([]byte{0x5A}, 20),
			[]byte{0, 6, 0x40, 0, 0, 0, 0, 0x02})},
		{"NSEC3PARAM", 51, wireCat([]byte{1, 0}, wireU16(0), []byte{2, 0xAB, 0xCD})},
		{"SPF", 99, wireCat([]byte{11}, []byte("v=spf1 -all"))},
		{"CAA", 257, wireCat([]byte{128, 5}, []byte("issue"), []byte("ca.example"))},
		{"CAA with an odd tag", 257, wireCat([]byte{128, 7}, []byte("bad-tag"), []byte("x"))},
	}
	for _, d := range typed {
		rr := wireRR(example, d.typ, wireClassIN, 3600, d.data)
		cases = append(cases, wireCase{"typed " + d.name, wireMessage(wireFlagQR, nil, [][]byte{rr}, nil, nil), true})
	}
	return cases
}

func TestParseSeedsAreValidOrMalformedAsBuilt(t *testing.T) {
	wireCheckCases(t, wireParseSeeds())
}

// wireCheckHeader compares the header with the raw octets; only the upper
// rcode bits come from elsewhere.
func wireCheckHeader(t *testing.T, b []byte, m *dnswire.Message) {
	t.Helper()
	low := dnswire.Rcode(b[3] & 0x0F)
	if m.Rcode&0x0F != low || (m.EDNS == nil && m.Rcode != low) {
		t.Fatalf("Rcode = %d; the header holds %d", uint16(m.Rcode), uint16(low))
	}
	want := dnswire.Header{
		ID:                 uint16(b[0])<<8 | uint16(b[1]),
		Response:           b[2]&0x80 != 0,
		Opcode:             dnswire.Opcode(b[2] >> 3 & 0x0F),
		Authoritative:      b[2]&0x04 != 0,
		Truncated:          b[2]&0x02 != 0,
		RecursionDesired:   b[2]&0x01 != 0,
		RecursionAvailable: b[3]&0x80 != 0,
		AuthenticData:      b[3]&0x20 != 0,
		CheckingDisabled:   b[3]&0x10 != 0,
		Rcode:              m.Rcode,
	}
	if m.Header != want {
		t.Fatalf("Header = %+v; the octets hold %+v", m.Header, want)
	}
}

// wireCheckSections requires the sections to hold every entry that the header
// counts, with OPT and TSIG only where they may be and left out of Additional.
func wireCheckSections(t *testing.T, b []byte, m *dnswire.Message) {
	t.Helper()
	raw, ok := wireSectionTypes(b)
	if !ok {
		t.Fatal("Parse accepted a message whose octets do not hold its counts")
	}
	if len(m.Question) > 1 || len(m.Question) != len(raw[0]) {
		t.Fatalf("%d questions; the header counts %d", len(m.Question), len(raw[0]))
	}
	for i, section := range [][]dnswire.Record{m.Answer, m.Authority} {
		for _, typ := range raw[i+1] {
			if typ == wireTypeOPT || typ == wireTypeTSIG {
				t.Fatalf("Parse accepted type %d in section %d", typ, i+1)
			}
		}
		wireCheckTypes(t, section, raw[i+1])
	}
	var rest []uint16
	opts, tsigs := 0, 0
	for i, typ := range raw[3] {
		switch typ {
		case wireTypeOPT:
			opts++
		case wireTypeTSIG:
			tsigs++
			if i != len(raw[3])-1 {
				t.Fatal("Parse accepted a TSIG record that is not the last one")
			}
		default:
			rest = append(rest, typ)
		}
	}
	if opts > 1 || tsigs > 1 || (opts == 1) != (m.EDNS != nil) {
		t.Fatalf("%d OPT and %d TSIG records; EDNS set: %v", opts, tsigs, m.EDNS != nil)
	}
	wireCheckTypes(t, m.Additional, rest)
}

func wireCheckTypes(t *testing.T, records []dnswire.Record, types []uint16) {
	t.Helper()
	if len(records) != len(types) {
		t.Fatalf("%d records; the octets hold %d", len(records), len(types))
	}
	for i, r := range records {
		if r.Data == nil {
			t.Fatalf("record %d has no data", i)
		}
		if r.Type() != dnswire.Type(types[i]) {
			t.Fatalf("record %d has type %v; the octets hold %d", i, r.Type(), types[i])
		}
	}
}

// wireCheckRecordAlone puts r alone in a message and requires it to print as
// before.
func wireCheckRecordAlone(t *testing.T, r dnswire.Record) {
	t.Helper()
	text := r.String()
	b := dnswire.AppendRecord(wireCat(wireU16(wireID), wireU16(wireFlagQR), wireU16(0), wireU16(1), wireU16(0), wireU16(0)), r)
	if len(b) > 65535 {
		// Names shared through pointers can expand past one message.
		return
	}
	m, err := dnswire.Parse(b)
	if err != nil {
		t.Fatalf("record %q alone in a message: %v", text, err)
	}
	if len(m.Answer) != 1 || m.Answer[0].String() != text {
		t.Fatalf("record %q alone in a message reads as %v", text, m.Answer)
	}
}

func FuzzParse(f *testing.F) {
	for _, c := range wireParseSeeds() {
		f.Add(c.msg)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		m, err := dnswire.Parse(b)
		if err != nil {
			if !errors.Is(err, dnswire.ErrMalformed) {
				t.Fatalf("Parse error %v does not wrap ErrMalformed", err)
			}
			return
		}
		wireCheckHeader(t, b, m)
		wireCheckSections(t, b, m)
		for _, section := range [][]dnswire.Record{m.Answer, m.Authority, m.Additional} {
			for _, r := range section {
				wireCheckRecordAlone(t, r)
			}
		}
	})
}

func FuzzParseName(f *testing.F) {
	for _, s := range []string{
		`x\@y\$z\;w\(\)\"q.odd.test.`, `weird\032name`, `\000\255`, `a\.b`, ".", "", "a..b", ".a",
		"Example.TEST", "*.example.test", `\\`, `\25`, `\256`, `a\`,
		wireTextName(63), wireTextName(64), wireTextName(63, 63, 63, 61), wireTextName(63, 63, 63, 62),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, err := dnswire.ParseName(s)
		if err != nil {
			if !errors.Is(err, dnswire.ErrInvalidName) {
				t.Fatalf("ParseName(%q) error %v does not wrap ErrInvalidName", s, err)
			}
			return
		}
		text := n.String()
		back, err := dnswire.ParseName(text)
		if err != nil || !back.Equal(n) || back.String() != text {
			t.Fatalf("ParseName(%q) = %q, %v; want %q back", text, back.String(), err, text)
		}
		fromLabels, err := dnswire.NameFromLabels(n.Labels())
		if err != nil || !fromLabels.Equal(n) || fromLabels.String() != text {
			t.Fatalf("NameFromLabels(%q) = %q, %v; want %q", n.Labels(), fromLabels.String(), err, text)
		}
		if w := n.AppendWire(nil); len(w) > 255 {
			t.Fatalf("ParseName(%q) gave a wire form of %d octets", s, len(w))
		}
	})
}

func wireCookieValid(c []byte) bool {
	return c == nil || len(c) == 8 || len(c) >= 16 && len(c) <= 40
}

func FuzzQueryPack(f *testing.F) {
	// flags: 1 RD, 2 CD, 4 DO, 8 send the cookie, 16 send the serial.
	f.Add("example.test", uint16(1), uint8(0), []byte(nil), uint32(0), uint16(0x1234))
	f.Add("Example.TEST.", uint16(251), uint8(0x1F), wireOctets(16), uint32(7), uint16(0xFFFF))
	f.Add(".", uint16(252), uint8(0x0F), wireOctets(8), uint32(0), uint16(0))
	f.Add(wireTextName(63, 63, 63, 61), uint16(65280), uint8(0x0C), wireOctets(40), uint32(0), uint16(1))
	f.Add("a.b", uint16(41), uint8(0), []byte(nil), uint32(0), uint16(2))
	f.Add("a.b", uint16(250), uint8(0), []byte(nil), uint32(0), uint16(3))
	f.Add("a", uint16(1), uint8(0x08), wireOctets(9), uint32(0), uint16(4))
	f.Add("a", uint16(1), uint8(0x10), []byte(nil), uint32(5), uint16(5))
	f.Fuzz(func(t *testing.T, name string, typ uint16, flags uint8, cookie []byte, serial uint32, id uint16) {
		n, err := dnswire.ParseName(name)
		if err != nil {
			return
		}
		q := dnswire.Query{Name: n, Type: dnswire.Type(typ),
			RecursionDesired: flags&1 != 0, CheckingDisabled: flags&2 != 0, DNSSECOK: flags&4 != 0}
		if flags&8 != 0 && len(cookie) > 0 {
			q.Cookie = cookie
		}
		if flags&16 != 0 {
			q.IXFRSerial = serial
		}
		b, err := q.Pack(id)
		if err != nil {
			if !errors.Is(err, dnswire.ErrInvalidQuery) {
				t.Fatalf("Pack error %v does not wrap ErrInvalidQuery", err)
			}
			return
		}
		ixfr := q.Type == dnswire.TypeIXFR
		if typ == wireTypeOPT || typ == wireTypeTSIG || !wireCookieValid(q.Cookie) || (q.IXFRSerial != 0 && !ixfr) {
			t.Fatalf("Pack accepted %+v", q)
		}
		wireCheckPackedQuery(t, q, id, b)
	})
}

// wireCheckPackedQuery requires b to be exactly a query for q: QR 0, opcode
// QUERY, one question, an SOA only for IXFR, one OPT and nothing else.
func wireCheckPackedQuery(t *testing.T, q dnswire.Query, id uint16, b []byte) {
	t.Helper()
	var rd, cd byte
	if q.RecursionDesired {
		rd = 0x01
	}
	if q.CheckingDisabled {
		cd = 0x10
	}
	if len(b) < 12 {
		t.Fatalf("Pack gave %d octets", len(b))
	}
	if b[2] != rd || b[3] != cd {
		t.Fatalf("header flags % X; want %02X %02X", b[2:4], rd, cd)
	}
	m, err := dnswire.Parse(b)
	if err != nil {
		t.Fatalf("Parse of a packed query: %v", err)
	}
	if m.ID != id || m.Response || m.Opcode != dnswire.OpcodeQuery || m.Rcode != 0 {
		t.Fatalf("header %+v; want a query with ID %d", m.Header, id)
	}
	if len(m.Question) != 1 {
		t.Fatalf("%d questions; want 1", len(m.Question))
	}
	got := m.Question[0]
	if !got.Name.Equal(q.Name) || got.Name.String() != q.Name.String() || got.Type != q.Type || got.Class != dnswire.ClassINET {
		t.Fatalf("question %s %v %v; want %s %v IN", got.Name, got.Type, got.Class, q.Name, q.Type)
	}
	if len(m.Answer) != 0 || len(m.Additional) != 0 {
		t.Fatalf("answer %v, additional %v; want none", m.Answer, m.Additional)
	}
	if raw, ok := wireSectionTypes(b); !ok || len(raw[3]) != 1 {
		t.Fatalf("additional section of %d entries; want only OPT", len(raw[3]))
	}
	wantAuthority := 0
	if q.Type == dnswire.TypeIXFR {
		wantAuthority = 1
	}
	if len(m.Authority) != wantAuthority {
		t.Fatalf("authority %v; want %d records", m.Authority, wantAuthority)
	}
	if wantAuthority == 1 {
		soa, ok := m.Authority[0].Data.(dnswire.SOA)
		if !ok || !m.Authority[0].Name.Equal(q.Name) || soa.Serial != q.IXFRSerial || soa.MName.LabelCount() != 0 || soa.RName.LabelCount() != 0 {
			t.Fatalf("authority %v; want an SOA for %s with serial %d", m.Authority[0], q.Name, q.IXFRSerial)
		}
	}
	e := m.EDNS
	if e == nil || e.UDPSize != 1232 || e.Version != 0 || e.DO != q.DNSSECOK {
		t.Fatalf("EDNS %+v; want size 1232, version 0, DO %v", e, q.DNSSECOK)
	}
	client, server, ok := e.Cookie()
	if ok != (q.Cookie != nil) || (ok && !bytes.Equal(wireCat(client, server), q.Cookie)) {
		t.Fatalf("cookie % X % X %v; want % X", client, server, ok, q.Cookie)
	}
}
