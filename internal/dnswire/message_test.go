package dnswire_test

import (
	"bytes"
	"errors"
	"math"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Raw codes, so that test messages are built without the code under test.
const (
	wireTypeA       = 1
	wireTypeNS      = 2
	wireTypeSOA     = 6
	wireTypePTR     = 12
	wireTypeMINFO   = 14
	wireTypeOPT     = 41
	wireTypeTSIG    = 250
	wireTypePrivate = 65280 // private use: no decoder looks inside its data
	wireClassIN     = 1
	wireClassANY    = 255
	wireFlagQR      = 0x8000
	wireID          = 0xBEEF
)

func wireU16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func wireU32(v uint32) []byte { return []byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)} }

func wireCat(parts ...[]byte) []byte {
	var b []byte
	for _, p := range parts {
		b = append(b, p...)
	}
	return b
}

func wireLabels(labels ...string) []byte {
	var b []byte
	for _, l := range labels {
		b = append(b, byte(len(l)))
		b = append(b, l...)
	}
	return append(b, 0)
}

func wirePointer(target int) []byte { return []byte{0xC0 | byte(target>>8), byte(target)} }

func wireLabelAndPointer(label string, target int) []byte {
	return wireCat([]byte{byte(len(label))}, []byte(label), wirePointer(target))
}

// wireLongName is a name of the longest wire form: 255 octets.
func wireLongName() []byte {
	l63 := strings.Repeat("x", 63)
	return wireLabels(l63, l63, l63, strings.Repeat("x", 61))
}

func wireRR(owner []byte, typ, class uint16, ttl uint32, rdata []byte) []byte {
	return wireCat(owner, wireU16(typ), wireU16(class), wireU32(ttl), wireU16(uint16(len(rdata))), rdata)
}

func wireQuestion(name []byte, typ uint16) []byte {
	return wireCat(name, wireU16(typ), wireU16(wireClassIN))
}

func wireA(owner []byte) []byte {
	return wireRR(owner, wireTypeA, wireClassIN, 300, []byte{192, 0, 2, 1})
}

func wirePrivate(owner, data []byte) []byte {
	return wireRR(owner, wireTypePrivate, wireClassIN, 0, data)
}

func wireOPT(udpSize uint16, extendedRcode, version uint8, flags uint16, options ...[]byte) []byte {
	ttl := uint32(extendedRcode)<<24 | uint32(version)<<16 | uint32(flags)
	return wireRR(wireLabels(), wireTypeOPT, udpSize, ttl, wireCat(options...))
}

func wireOption(code uint16, data []byte) []byte {
	return wireCat(wireU16(code), wireU16(uint16(len(data))), data)
}

// wireTSIG returns a complete hmac-sha256 TSIG record, so that only its
// position can make a message malformed.
func wireTSIG() []byte {
	rdata := wireCat(
		wireLabels("hmac-sha256"),
		[]byte{0, 0, 0x6A, 0x00, 0x00, 0x00}, // time signed: 48 bits
		wireU16(300),                         // fudge
		wireU16(32), bytes.Repeat([]byte{0xAB}, 32),
		wireU16(wireID), // original ID
		wireU16(0),      // error
		wireU16(0),      // other data length
	)
	return wireRR(wireLabels("xfr", "key"), wireTypeTSIG, wireClassANY, 0, rdata)
}

// wireMessage returns a header with the ID wireID and counts that match the
// sections, followed by the sections. The first section starts at offset 12.
func wireMessage(flags uint16, question, answer, authority, additional [][]byte) []byte {
	b := wireCat(wireU16(wireID), wireU16(flags),
		wireU16(uint16(len(question))), wireU16(uint16(len(answer))),
		wireU16(uint16(len(authority))), wireU16(uint16(len(additional))))
	for _, section := range [][][]byte{question, answer, authority, additional} {
		for _, entry := range section {
			b = append(b, entry...)
		}
	}
	return b
}

func wireWithCounts(b []byte, qd, an, ns, ar uint16) []byte {
	c := bytes.Clone(b)
	copy(c[4:12], wireCat(wireU16(qd), wireU16(an), wireU16(ns), wireU16(ar)))
	return c
}

// wireOfSize returns a valid message of exactly n octets, n >= 23.
func wireOfSize(n int) []byte {
	return wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(wireLabels(), make([]byte, n-23))}, nil, nil)
}

// wireChainData returns the data of a record at offset 12 whose owner is
// ownerLen octets long: pointers, the first to the owner and each next one to
// the one before. A pointer to last reaches the owner through links+1 pointers.
func wireChainData(ownerLen, links int) (data []byte, last int) {
	start := 12 + ownerLen + 10
	last = 12
	for i := range links {
		data = append(data, wirePointer(last)...)
		last = start + 2*i
	}
	return data, last
}

// wirePointerChain returns a message whose second record has an owner that
// reaches the name "a." through n pointers in a row.
func wirePointerChain(n int) []byte {
	owner := wireLabels("a")
	data, last := wireChainData(len(owner), n-1)
	return wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(owner, data), wirePrivate(wirePointer(last), nil)}, nil, nil)
}

// wireFill returns a message of 65535 octets: a private record at offset 12
// with the given owner and data, padded with zeros, then as many copies of rec
// as fit.
func wireFill(owner, data, rec []byte) []byte {
	room := 65535 - 12 - len(owner) - 10 - len(data)
	n := room / len(rec)
	answer := [][]byte{wirePrivate(owner, wireCat(data, make([]byte, room-n*len(rec))))}
	for range n {
		answer = append(answer, rec)
	}
	return wireMessage(0x8400, nil, answer, nil, nil)
}

// wireSectionTypes reads only the raw layout of b and returns the type of
// every entry of the four sections, or false when the counts and the octets
// disagree. It needs nothing from the code under test.
func wireSectionTypes(b []byte) (sections [4][]uint16, ok bool) {
	if len(b) < 12 {
		return sections, false
	}
	off := 12
	for s := range 4 {
		count := int(b[4+2*s])<<8 | int(b[5+2*s])
		fixed := 10
		if s == 0 {
			fixed = 4
		}
		for range count {
			off = wireSkipName(b, off)
			if off < 0 || off+fixed > len(b) {
				return sections, false
			}
			sections[s] = append(sections[s], uint16(b[off])<<8|uint16(b[off+1]))
			off += fixed
			if s > 0 {
				off += int(b[off-2])<<8 | int(b[off-1])
				if off > len(b) {
					return sections, false
				}
			}
		}
	}
	return sections, off == len(b)
}

// wireSkipName returns the offset after the name at off, or -1.
func wireSkipName(b []byte, off int) int {
	for off < len(b) {
		c := int(b[off])
		switch {
		case c == 0:
			return off + 1
		case c&0xC0 == 0xC0:
			if off+2 > len(b) {
				return -1
			}
			return off + 2
		case c&0xC0 != 0:
			return -1
		}
		off += 1 + c
	}
	return -1
}

type wireCase struct {
	name string
	msg  []byte
	ok   bool
}

// wireCheckCases requires each valid message to parse and each other one to
// fail with ErrMalformed.
func wireCheckCases(t *testing.T, cases []wireCase) {
	t.Helper()
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := dnswire.Parse(c.msg)
			if c.ok && err != nil {
				t.Fatalf("Parse: %v; want success", err)
			}
			if !c.ok && !errors.Is(err, dnswire.ErrMalformed) {
				t.Fatalf("Parse error = %v; want one that wraps ErrMalformed", err)
			}
		})
	}
}

func wireParseOK(t *testing.T, b []byte) *dnswire.Message {
	t.Helper()
	m, err := dnswire.Parse(b)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return m
}

// wireParseCost parses b a few times and returns the smallest heap growth and
// time seen, so that other goroutines of the test binary inflate neither.
func wireParseCost(b []byte) (allocated uint64, elapsed time.Duration) {
	allocated, elapsed = math.MaxUint64, time.Duration(math.MaxInt64)
	for range 3 {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		start := time.Now()
		_, _ = dnswire.Parse(b)
		d := time.Since(start)
		runtime.ReadMemStats(&after)
		allocated = min(allocated, after.TotalAlloc-before.TotalAlloc)
		elapsed = min(elapsed, d)
	}
	return allocated, elapsed
}

func TestParseRejectsMessagesOutsideTheSizeLimits(t *testing.T) {
	header := wireMessage(wireFlagQR, nil, nil, nil, nil)
	wireCheckCases(t, []wireCase{
		{"no octets", nil, false},
		{"11 octets", header[:11], false},
		{"12 octets", header, true},
		{"65535 octets", wireOfSize(65535), true},
		{"65536 octets", wireOfSize(65536), false},
	})
}

func TestParseReadsEveryHeaderField(t *testing.T) {
	cases := []struct {
		name  string
		flags uint16
		want  dnswire.Header
	}{
		{"no flags", 0, dnswire.Header{}},
		{"response", 0x8000, dnswire.Header{Response: true}},
		{"opcode STATUS", 0x1000, dnswire.Header{Opcode: 2}},
		{"opcode 15", 0x7800, dnswire.Header{Opcode: 15}},
		{"authoritative", 0x0400, dnswire.Header{Authoritative: true}},
		{"truncated", 0x0200, dnswire.Header{Truncated: true}},
		{"recursion desired", 0x0100, dnswire.Header{RecursionDesired: true}},
		{"recursion available", 0x0080, dnswire.Header{RecursionAvailable: true}},
		{"authentic data", 0x0020, dnswire.Header{AuthenticData: true}},
		{"checking disabled", 0x0010, dnswire.Header{CheckingDisabled: true}},
		{"rcode 15", 0x000F, dnswire.Header{Rcode: 15}},
		{"every flag but Z", 0xFFBF, dnswire.Header{Response: true, Opcode: 15, Authoritative: true,
			Truncated: true, RecursionDesired: true, RecursionAvailable: true, AuthenticData: true,
			CheckingDisabled: true, Rcode: 15}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			m := wireParseOK(t, wireMessage(c.flags, nil, nil, nil, nil))
			c.want.ID = wireID
			if m.Header != c.want {
				t.Errorf("Header = %+v; want %+v", m.Header, c.want)
			}
			if len(m.Question)+len(m.Answer)+len(m.Authority)+len(m.Additional) != 0 || m.EDNS != nil {
				t.Errorf("a bare header gave sections %+v", m)
			}
		})
	}
}

func TestParseAllowsAtMostOneQuestion(t *testing.T) {
	q := wireQuestion(wireLabels("example", "test"), wireTypeA)
	wireCheckCases(t, []wireCase{
		{"no question", wireMessage(wireFlagQR, nil, nil, nil, nil), true},
		{"one question", wireMessage(wireFlagQR, [][]byte{q}, nil, nil, nil), true},
		{"two questions", wireMessage(wireFlagQR, [][]byte{q, q}, nil, nil, nil), false},
	})
}

func TestParseReadsTheQuestionWithItsCase(t *testing.T) {
	q := wireCat(wireLabels("Example", "TEST"), wireU16(wireTypePrivate), wireU16(3))
	m := wireParseOK(t, wireMessage(0, [][]byte{q}, nil, nil, nil))
	if len(m.Question) != 1 {
		t.Fatalf("got %d questions; want 1", len(m.Question))
	}
	got := m.Question[0]
	if got.Name.String() != "Example.TEST." || got.Type != dnswire.Type(wireTypePrivate) || got.Class != dnswire.ClassCHAOS {
		t.Errorf("Question = %s %v %v; want Example.TEST. TYPE65280 CH", got.Name, got.Type, got.Class)
	}
}

func TestParseRejectsCountsThatTheOctetsDoNotHold(t *testing.T) {
	one := wireMessage(wireFlagQR, nil, [][]byte{wireA(wireLabels("example", "test"))}, nil, nil)
	smallest := wirePrivate(wireLabels(), nil)
	wireCheckCases(t, []wireCase{
		{"counts match the records", one, true},
		{"question count one too high", wireWithCounts(one, 1, 1, 0, 0), false},
		{"answer count one too high", wireWithCounts(one, 0, 2, 0, 0), false},
		{"authority count one too high", wireWithCounts(one, 0, 1, 1, 0), false},
		{"additional count one too high", wireWithCounts(one, 0, 1, 0, 1), false},
		{"one octet after the last record", append(bytes.Clone(one), 0), false},
		{"a record of all 11 octets that a record needs", wireMessage(wireFlagQR, nil, [][]byte{smallest}, nil, nil), true},
		{"a count of one over 10 octets", wireMessage(wireFlagQR, nil, [][]byte{smallest[:10]}, nil, nil), false},
		{"record data shorter than its length", one[:len(one)-1], false},
	})
}

func TestParseReservesMemoryFromTheOctetsNotTheCounts(t *testing.T) {
	b := wireWithCounts(wireMessage(wireFlagQR, nil, [][]byte{wireA(wireLabels("example", "test"))}, nil, nil),
		0, 0xFFFF, 0xFFFF, 0xFFFF)
	if _, err := dnswire.Parse(b); !errors.Is(err, dnswire.ErrMalformed) {
		t.Fatalf("Parse error = %v; want one that wraps ErrMalformed", err)
	}
	allocated, _ := wireParseCost(b)
	if limit := 64*uint64(len(b)) + 64<<10; allocated > limit {
		t.Errorf("Parse of %d octets that claim 196605 records allocated %d octets; the bound is %d",
			len(b), allocated, limit)
	}
}

func TestParseEnforcesLabelAndNameLengths(t *testing.T) {
	l63, l64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	owner := func(name []byte) []byte {
		return wireMessage(wireFlagQR, nil, [][]byte{wirePrivate(name, nil)}, nil, nil)
	}
	// The question at offset 12 holds three labels of 63 octets (193 octets);
	// the owner puts one more label in front of it through a pointer.
	viaPointer := func(first int) []byte {
		q := wireQuestion(wireLabels(l63, l63, l63), wireTypeA)
		rr := wirePrivate(wireLabelAndPointer(strings.Repeat("b", first), 12), nil)
		return wireMessage(wireFlagQR, [][]byte{q}, [][]byte{rr}, nil, nil)
	}
	wireCheckCases(t, []wireCase{
		{"label of 63 octets", owner(wireLabels(l63, "test")), true},
		{"label of 64 octets", owner(wireLabels(l64, "test")), false},
		{"label type 01", owner([]byte{0x41, 'a', 0}), false},
		{"label type 10", owner([]byte{0x81, 'a', 0}), false},
		{"name of 255 octets", owner(wireLongName()), true},
		{"name of 256 octets", owner(wireLabels(l63, l63, l63, strings.Repeat("x", 62))), false},
		{"name of 255 octets through a pointer", viaPointer(61), true},
		{"name of 256 octets through a pointer", viaPointer(62), false},
	})
}

func TestParseEnforcesPointerTargetsAndCount(t *testing.T) {
	answer := func(records ...[]byte) []byte { return wireMessage(wireFlagQR, nil, records, nil, nil) }
	rootQuestion := wireQuestion(wireLabels(), wireTypeA)
	wireCheckCases(t, []wireCase{
		{"pointer to offset 12", wireMessage(wireFlagQR, [][]byte{rootQuestion}, [][]byte{wirePrivate(wirePointer(12), nil)}, nil, nil), true},
		// Octet 11 is the low octet of a zero count, which would read as the root.
		{"pointer to offset 11 in the header", answer(wirePrivate(wirePointer(11), nil)), false},
		// The first record ends with a zero octet at offset 23, just before the pointer.
		{"pointer to the octet just before it", answer(wirePrivate(wireLabels(), []byte{0}), wirePrivate(wirePointer(23), nil)), true},
		{"pointer to itself", answer(wirePrivate(wirePointer(12), nil)), false},
		{"pointer back to an earlier owner", answer(wirePrivate(wireLabels(), nil), wirePrivate(wirePointer(12), nil)), true},
		{"pointer forward to a later owner", answer(wirePrivate(wirePointer(24), nil), wirePrivate(wireLabels(), nil)), false},
		{"pointer back into its own name", answer(wirePrivate(wireLabelAndPointer("a", 12), nil)), false},
		// Twelve octets pass the size check of a record before the pointer is read.
		{"pointer cut by the end of the message", answer(wireCat(wireLabels("aaaaaaaaaa")[:11], []byte{0xC0})), false},
		{"128 pointers for one name", wirePointerChain(128), true},
		{"129 pointers for one name", wirePointerChain(129), false},
	})
}

func TestParseExpandsCompressedOwners(t *testing.T) {
	q := wireQuestion(wireLabels("example", "test"), wireTypeA)
	m := wireParseOK(t, wireMessage(wireFlagQR, [][]byte{q},
		[][]byte{wireA(wirePointer(12)), wireA(wireLabelAndPointer("www", 12))}, nil, nil))
	if len(m.Answer) != 2 || m.Answer[0].Name.String() != "example.test." || m.Answer[1].Name.String() != "www.example.test." {
		t.Errorf("owners of %v; want example.test. and www.example.test.", m.Answer)
	}
	m = wireParseOK(t, wirePointerChain(128))
	if len(m.Answer) != 2 || m.Answer[1].Name.String() != "a." {
		t.Errorf("owner reached through 128 pointers in %v; want a.", m.Answer)
	}
}

func TestParseKeepsRecordsInTheirSectionsAndOrder(t *testing.T) {
	b := wireMessage(wireFlagQR,
		[][]byte{wireQuestion(wireLabels("q", "test"), wireTypeA)},
		[][]byte{wireRR(wireLabels("one", "test"), wireTypePrivate, 3, 3600, []byte{1, 2}), wireA(wireLabels("two", "test"))},
		[][]byte{wireRR(wireLabels("three", "test"), wireTypePrivate, 4, 7, nil)},
		[][]byte{wireA(wireLabels("four", "test")), wireOPT(1232, 0, 0, 0)},
	)
	m := wireParseOK(t, b)
	type rr struct {
		owner string
		typ   dnswire.Type
		class dnswire.Class
		ttl   uint32
	}
	want := [][]rr{
		{{"one.test.", wireTypePrivate, 3, 3600}, {"two.test.", dnswire.TypeA, dnswire.ClassINET, 300}},
		{{"three.test.", wireTypePrivate, 4, 7}},
		{{"four.test.", dnswire.TypeA, dnswire.ClassINET, 300}},
	}
	for i, section := range [][]dnswire.Record{m.Answer, m.Authority, m.Additional} {
		var got []rr
		for _, r := range section {
			got = append(got, rr{r.Name.String(), r.Type(), r.Class, r.TTL})
		}
		if len(got) != len(want[i]) {
			t.Errorf("section %d = %+v; want %+v", i+1, got, want[i])
			continue
		}
		for j := range got {
			if got[j] != want[i][j] {
				t.Errorf("section %d = %+v; want %+v", i+1, got, want[i])
			}
		}
	}
	if m.EDNS == nil {
		t.Error("EDNS is nil; the message has an OPT record")
	}
}

func TestParseResultsDoNotAliasTheInput(t *testing.T) {
	b := wireMessage(wireFlagQR,
		[][]byte{wireQuestion(wireLabels("q", "test"), wireTypeA)},
		[][]byte{wirePrivate(wireLabels("x", "test"), []byte{1, 2, 3})},
		nil,
		[][]byte{wireOPT(1232, 0, 0, 0, wireOption(12, []byte{0xAA, 0xBB}))})
	m := wireParseOK(t, b)
	question, record := m.Question[0].Name.String(), m.Answer[0].String()
	for i := range b {
		b[i] = 0xFF
	}
	if got := m.Question[0].Name.String(); got != question {
		t.Errorf("question name changed with the input: %q, was %q", got, question)
	}
	if got := m.Answer[0].String(); got != record {
		t.Errorf("record changed with the input: %q, was %q", got, record)
	}
	if got := m.EDNS.Options[0].Data; !bytes.Equal(got, []byte{0xAA, 0xBB}) {
		t.Errorf("option data changed with the input: % X", got)
	}
}

func TestParseAllowsTSIGOnlyAsTheLastAdditionalRecord(t *testing.T) {
	a := wireA(wireLabels("example", "test"))
	tsig, opt := wireTSIG(), wireOPT(1232, 0, 0, 0)
	msg := func(answer, authority, additional [][]byte) []byte {
		return wireMessage(wireFlagQR, nil, answer, authority, additional)
	}
	wireCheckCases(t, []wireCase{
		{"alone in additional", msg(nil, nil, [][]byte{tsig}), true},
		{"last after a record", msg([][]byte{a}, nil, [][]byte{a, tsig}), true},
		{"last after OPT", msg(nil, nil, [][]byte{opt, tsig}), true},
		{"before a record", msg(nil, nil, [][]byte{tsig, a}), false},
		{"before OPT", msg(nil, nil, [][]byte{tsig, opt}), false},
		{"two of them", msg(nil, nil, [][]byte{tsig, tsig}), false},
		{"in answer", msg([][]byte{tsig}, nil, nil), false},
		{"in authority", msg(nil, [][]byte{tsig}, nil), false},
	})
}

func TestParseLeavesOPTAndTSIGOutOfAdditional(t *testing.T) {
	m := wireParseOK(t, wireMessage(wireFlagQR, nil, nil, nil,
		[][]byte{wireA(wireLabels("glue", "test")), wireOPT(1232, 0, 0, 0), wireTSIG()}))
	if len(m.Additional) != 1 || m.Additional[0].Type() != dnswire.TypeA {
		t.Errorf("Additional = %v; want only the A record", m.Additional)
	}
	if m.EDNS == nil {
		t.Error("EDNS is nil; the message has an OPT record")
	}
}

func TestParseStaysWithinItsMemoryAndTimeBounds(t *testing.T) {
	long := wireLongName()
	chain, last := wireChainData(len(long), 127)
	cases := []struct {
		name  string
		msg   []byte
		valid bool
	}{
		{"MINFO records with two pointers each to a 255-octet name",
			wireFill(long, nil, wireRR(wirePointer(12), wireTypeMINFO, wireClassIN, 0, wireCat(wirePointer(12), wirePointer(12)))), false},
		{"PTR records with a pointer to a 255-octet name",
			wireFill(long, nil, wireRR(wirePointer(12), wireTypePTR, wireClassIN, 0, wirePointer(12))), false},
		{"owners that reach a 255-octet name through 128 pointers",
			wireFill(long, chain, wirePrivate(wirePointer(last), nil)), true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if len(c.msg) != 65535 {
				t.Fatalf("the test message has %d octets; want 65535", len(c.msg))
			}
			_, err := dnswire.Parse(c.msg)
			if c.valid && err != nil {
				t.Fatalf("Parse: %v; want success", err)
			}
			if err != nil && !errors.Is(err, dnswire.ErrMalformed) {
				t.Fatalf("Parse error = %v; want success or one that wraps ErrMalformed", err)
			}
			allocated, elapsed := wireParseCost(c.msg)
			if limit := 64*uint64(len(c.msg)) + 64<<10; allocated > limit {
				t.Errorf("Parse allocated %d octets; the bound is %d", allocated, limit)
			}
			if elapsed >= time.Second {
				t.Errorf("Parse took %v; the bound is 1s", elapsed)
			}
		})
	}
}

func TestTypeConstantsAndStrings(t *testing.T) {
	constants := []struct {
		typ  dnswire.Type
		code uint16
	}{{dnswire.TypeA, 1}, {dnswire.TypeNXNAME, 128}, {dnswire.TypeIXFR, 251}, {dnswire.TypeANY, 255}}
	for _, c := range constants {
		if uint16(c.typ) != c.code {
			t.Errorf("a type constant is %d; want %d", uint16(c.typ), c.code)
		}
	}
	cases := map[uint16]string{
		1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 39: "DNAME",
		41: "OPT", 43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM",
		250: "TSIG", 251: "IXFR", 252: "AXFR", 255: "ANY", 257: "CAA",
		0: "TYPE0", 13: "TYPE13", 128: "TYPE128", 65280: "TYPE65280", 65535: "TYPE65535",
	}
	for code, want := range cases {
		if got := dnswire.Type(code).String(); got != want {
			t.Errorf("Type(%d).String() = %q; want %q", code, got, want)
		}
	}
}

func TestParseTypeReadsMnemonicsInAnyCaseAndGenericForms(t *testing.T) {
	ok := map[string]uint16{
		"A": 1, "a": 1, "Mx": 15, "nsec3param": 51, "ptr": 12, "CAA": 257, "OPT": 41, "TSIG": 250,
		"ixfr": 251, "AXFR": 252, "ANY": 255, "TYPE0": 0, "TYPE1": 1, "TYPE128": 128, "TYPE65535": 65535,
	}
	for s, want := range ok {
		got, err := dnswire.ParseType(s)
		if err != nil || got != dnswire.Type(want) {
			t.Errorf("ParseType(%q) = %d, %v; want %d", s, got, err, want)
		}
	}
	for _, s := range []string{"", "TYPE", "TYPE65536", "TYPE-1", "TYPEx", "NXNAME", "BOGUS", "A "} {
		if _, err := dnswire.ParseType(s); !errors.Is(err, dnswire.ErrInvalidType) {
			t.Errorf("ParseType(%q) error = %v; want one that wraps ErrInvalidType", s, err)
		}
	}
}

func TestParseTypeReadsBackEveryTypeString(t *testing.T) {
	for code := range 65536 {
		typ := dnswire.Type(code)
		got, err := dnswire.ParseType(typ.String())
		if err != nil || got != typ {
			t.Fatalf("ParseType(%q) = %d, %v; want %d", typ.String(), got, err, code)
		}
	}
}

func TestClassConstantsAndStrings(t *testing.T) {
	cases := []struct {
		class dnswire.Class
		code  uint16
		want  string
	}{
		{dnswire.ClassINET, 1, "IN"},
		{dnswire.ClassCHAOS, 3, "CH"},
		{dnswire.ClassHESIOD, 4, "HS"},
		{dnswire.ClassNONE, 254, "NONE"},
		{dnswire.ClassANY, 255, "ANY"},
		{dnswire.Class(0), 0, "CLASS0"},
		{dnswire.Class(2), 2, "CLASS2"},
		{dnswire.Class(65535), 65535, "CLASS65535"},
	}
	for _, c := range cases {
		if uint16(c.class) != c.code || c.class.String() != c.want {
			t.Errorf("class %d prints %q; want %d %q", uint16(c.class), c.class.String(), c.code, c.want)
		}
	}
}

func TestOpcodeStrings(t *testing.T) {
	if dnswire.OpcodeQuery != 0 {
		t.Errorf("OpcodeQuery = %d; want 0", dnswire.OpcodeQuery)
	}
	cases := map[uint8]string{0: "QUERY", 1: "IQUERY", 2: "STATUS", 3: "RESERVED3", 4: "NOTIFY", 5: "UPDATE", 6: "RESERVED6", 15: "RESERVED15"}
	for code, want := range cases {
		if got := dnswire.Opcode(code).String(); got != want {
			t.Errorf("Opcode(%d).String() = %q; want %q", code, got, want)
		}
	}
}

func TestRcodeStrings(t *testing.T) {
	cases := map[uint16]string{
		0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN", 4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN",
		7: "YXRRSET", 8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 11: "11", 15: "15", 16: "BADVERS",
		17: "17", 23: "BADCOOKIE", 4095: "4095",
	}
	for code, want := range cases {
		if got := dnswire.Rcode(code).String(); got != want {
			t.Errorf("Rcode(%d).String() = %q; want %q", code, got, want)
		}
	}
}
