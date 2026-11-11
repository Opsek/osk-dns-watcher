package dnswire

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
)

// dataCase is one record data in its three forms. The wire and text forms
// agree with what BIND 9.20 reads and prints (named-rrchecker, dig +nosplit),
// except where a comment on the case says otherwise.
type dataCase struct {
	typ  Type
	wire string // hex; blanks only group the octets
	text string // String() of the data
	want RData
}

func dataName(t testing.TB, s string) Name {
	t.Helper()
	n, err := ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func dataHex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(strings.ReplaceAll(s, " ", ""))
	if err != nil {
		t.Fatalf("bad hex in test table %q: %v", s, err)
	}
	return b
}

// dataMessage returns a response with the question "example. <typ> IN" and one
// answer record "example. 3600 IN <typ>" whose data is rdata. The question
// name starts at offset 12, so C0 0C in rdata is a valid pointer to it.
func dataMessage(typ Type, rdata []byte) []byte {
	owner := []byte("\x07example\x00")
	b := []byte{0x12, 0x34, 0x84, 0x00, 0, 1, 0, 1, 0, 0, 0, 0}
	b = append(b, owner...)
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	b = binary.BigEndian.AppendUint16(b, uint16(ClassINET))
	b = append(b, owner...)
	b = binary.BigEndian.AppendUint16(b, uint16(typ))
	b = binary.BigEndian.AppendUint16(b, uint16(ClassINET))
	b = binary.BigEndian.AppendUint32(b, 3600)
	b = binary.BigEndian.AppendUint16(b, uint16(len(rdata)))
	return append(b, rdata...)
}

// dataParse decodes rdata the way Parse meets it: inside a whole message.
func dataParse(typ Type, rdata []byte) (Record, error) {
	m, err := Parse(dataMessage(typ, rdata))
	if err != nil {
		return Record{}, err
	}
	if len(m.Answer) != 1 {
		return Record{}, fmt.Errorf("%d answer records, want 1", len(m.Answer))
	}
	return m.Answer[0], nil
}

func dataSameName(a, b Name) bool {
	return bytes.Equal(a.AppendWire(nil), b.AppendWire(nil))
}

// dataEqual compares two record data field by field. Names must match octet
// for octet, case included, since decoding keeps the case as received. Nil
// and empty slices count as equal: the API does not say which one it returns.
func dataEqual(a, b RData) bool {
	switch x := a.(type) {
	case A:
		y, ok := b.(A)
		return ok && x == y
	case AAAA:
		y, ok := b.(AAAA)
		return ok && x == y
	case NS:
		y, ok := b.(NS)
		return ok && dataSameName(x.Host, y.Host)
	case CNAME:
		y, ok := b.(CNAME)
		return ok && dataSameName(x.Target, y.Target)
	case DNAME:
		y, ok := b.(DNAME)
		return ok && dataSameName(x.Target, y.Target)
	case PTR:
		y, ok := b.(PTR)
		return ok && dataSameName(x.Target, y.Target)
	case SOA:
		y, ok := b.(SOA)
		return ok && dataSameName(x.MName, y.MName) && dataSameName(x.RName, y.RName) &&
			x.Serial == y.Serial && x.Refresh == y.Refresh && x.Retry == y.Retry &&
			x.Expire == y.Expire && x.Minimum == y.Minimum
	case MX:
		y, ok := b.(MX)
		return ok && x.Preference == y.Preference && dataSameName(x.Exchange, y.Exchange)
	case TXT:
		y, ok := b.(TXT)
		return ok && slices.Equal(x.Strings, y.Strings)
	case SPF:
		y, ok := b.(SPF)
		return ok && slices.Equal(x.Strings, y.Strings)
	case CAA:
		y, ok := b.(CAA)
		return ok && x == y
	case DS:
		y, ok := b.(DS)
		return ok && x.KeyTag == y.KeyTag && x.Algorithm == y.Algorithm &&
			x.DigestType == y.DigestType && bytes.Equal(x.Digest, y.Digest)
	case DNSKEY:
		y, ok := b.(DNSKEY)
		return ok && x.Flags == y.Flags && x.Protocol == y.Protocol &&
			x.Algorithm == y.Algorithm && bytes.Equal(x.PublicKey, y.PublicKey)
	case RRSIG:
		y, ok := b.(RRSIG)
		return ok && x.TypeCovered == y.TypeCovered && x.Algorithm == y.Algorithm &&
			x.Labels == y.Labels && x.OriginalTTL == y.OriginalTTL &&
			x.Expiration == y.Expiration && x.Inception == y.Inception &&
			x.KeyTag == y.KeyTag && dataSameName(x.SignerName, y.SignerName) &&
			bytes.Equal(x.Signature, y.Signature)
	case NSEC:
		y, ok := b.(NSEC)
		return ok && dataSameName(x.NextName, y.NextName) && slices.Equal(x.Types, y.Types)
	case NSEC3:
		y, ok := b.(NSEC3)
		return ok && x.HashAlgorithm == y.HashAlgorithm && x.Flags == y.Flags &&
			x.Iterations == y.Iterations && bytes.Equal(x.Salt, y.Salt) &&
			bytes.Equal(x.NextHashed, y.NextHashed) && slices.Equal(x.Types, y.Types)
	case NSEC3PARAM:
		y, ok := b.(NSEC3PARAM)
		return ok && x.HashAlgorithm == y.HashAlgorithm && x.Flags == y.Flags &&
			x.Iterations == y.Iterations && bytes.Equal(x.Salt, y.Salt)
	case Unknown:
		y, ok := b.(Unknown)
		return ok && x.TypeCode == y.TypeCode && bytes.Equal(x.Data, y.Data)
	}
	return false
}

func dataRDataCases(t testing.TB) []dataCase {
	n := func(s string) Name { return dataName(t, s) }
	ip := netip.MustParseAddr
	xs, ys := strings.Repeat("x", 255), strings.Repeat("y", 255)
	return []dataCase{
		{TypeA, "C0000201", "192.0.2.1", A{ip("192.0.2.1")}},
		{TypeAAAA, "0000 0000 0000 0000 0000 0000 0102 0304", "::102:304", AAAA{ip("::102:304")}},
		{TypeAAAA, "0000 0000 0000 0000 0000 FFFF 0102 0304", "::ffff:1.2.3.4", AAAA{ip("::ffff:1.2.3.4")}},
		{TypeAAAA, "0001 0000 0000 0002 0000 0000 0003 0004", "1::2:0:0:3:4", AAAA{ip("1::2:0:0:3:4")}},
		{TypeAAAA, "0001 0000 0000 0001 0000 0000 0000 0001", "1:0:0:1::1", AAAA{ip("1:0:0:1::1")}},
		{TypeAAAA, "0000 0000 0000 0000 0000 0000 0000 0000", "::", AAAA{ip("::")}},
		{TypeAAAA, "0001 0002 0003 0004 0005 0006 0000 0008", "1:2:3:4:5:6:0:8", AAAA{ip("1:2:3:4:5:6:0:8")}},
		{TypeNS, "036E7331 076578616D706C65 00", "ns1.example.", NS{n("ns1.example.")}},
		{TypeNS, "034E5331 074578616D706C65 00", "NS1.Example.", NS{n("NS1.Example.")}},
		{TypeCNAME, "03777777 076578616D706C65 00", "www.example.", CNAME{n("www.example.")}},
		{TypeDNAME, "076578616D706C65 036E6574 00", "example.net.", DNAME{n("example.net.")}},
		{TypeSOA, "036E7331 076578616D706C65 00 0B686F73742E6D6173746572 076578616D706C65 00" +
			" FFFFFFFF 00001C20 00000E10 00127500 0000012C",
			`ns1.example. host\.master.example. 4294967295 7200 3600 1209600 300`,
			SOA{n("ns1.example."), n(`host\.master.example.`), 4294967295, 7200, 3600, 1209600, 300}},
		{TypeMX, "0000 00", "0 .", MX{0, n(".")}},
		{TypeMX, "000A 046D61696C 076578616D706C65 00", "10 mail.example.", MX{10, n("mail.example.")}},
		{TypeMX, "FFFF 044D61696C 074578616D706C65 00", "65535 Mail.Example.", MX{65535, n("Mail.Example.")}},
		{TypeTXT, "05 6122625C63 0A 73656D693B636F6C6F6E 05 7461620978 02 FF80 00",
			`"a\"b\\c" "semi;colon" "tab\009x" "\255\128" ""`,
			TXT{[]string{`a"b\c`, "semi;colon", "tab\tx", "\xff\x80", ""}}},
		{TypeTXT, "00", `""`, TXT{[]string{""}}},
		{TypeTXT, "FF" + strings.Repeat("78", 255) + "FF" + strings.Repeat("79", 255),
			`"` + xs + `" "` + ys + `"`, TXT{[]string{xs, ys}}},
		{TypeCAA, "80 05 6973737565 63612E6578616D706C653B206163636F756E743D3432",
			`128 issue "ca.example; account=42"`, CAA{128, "issue", "ca.example; account=42"}},
		{TypeCAA, "00 05 696F646566 6D61696C746F3A7365637572697479406578616D706C65",
			`0 iodef "mailto:security@example"`, CAA{0, "iodef", "mailto:security@example"}},
		{TypeCAA, "00 03 746273 6122625C6309FF", `0 tbs "a\"b\\c\009\255"`, CAA{0, "tbs", "a\"b\\c\t\xff"}},
		{TypeCAA, "00 05 6973737565", `0 issue ""`, CAA{0, "issue", ""}},
		{Type(65280), "0A000001", `\# 4 0A000001`, Unknown{Type(65280), []byte{10, 0, 0, 1}}},
		{Type(65280), "", `\# 0`, Unknown{Type(65280), nil}},
		{TypePTR, "03777777 076578616D706C65 00", "www.example.", PTR{n("www.example.")}},
		{TypeSPF, "0B 763D73706631202D616C6C 00", `"v=spf1 -all" ""`, SPF{[]string{"v=spf1 -all", ""}}},
		// A type with names but no typed form prints in the generic form,
		// as dig +unknownformat and named-rrchecker -u print it.
		{Type(7), "024D42 076578616D706C65 00", `\# 12 024D42076578616D706C6500`,
			Unknown{Type(7), dataHex(t, "024D42076578616D706C6500")}},
	}
}

// dataCheckDecode decodes each case from its wire form and prints it.
func dataCheckDecode(t *testing.T, cases []dataCase) {
	t.Helper()
	for _, c := range cases {
		r, err := dataParse(c.typ, dataHex(t, c.wire))
		if err != nil {
			t.Errorf("%v %s: %v", c.typ, c.wire, err)
			continue
		}
		if !dataEqual(r.Data, c.want) {
			t.Errorf("%v %s: data %#v, want %#v", c.typ, c.wire, r.Data, c.want)
		}
		if got := r.Data.String(); got != c.text {
			t.Errorf("%v %s: String() = %q, want %q", c.typ, c.wire, got, c.text)
		}
		if r.Type() != c.typ {
			t.Errorf("%v %s: Type() = %v", c.typ, c.wire, r.Type())
		}
		want := "example.\t3600\tIN\t" + c.typ.String() + "\t" + c.text
		if got := r.String(); got != want {
			t.Errorf("%v %s: record String() = %q, want %q", c.typ, c.wire, got, want)
		}
	}
}

func TestRDataDecode(t *testing.T) {
	dataCheckDecode(t, dataRDataCases(t))
}

func TestRDataRecordString(t *testing.T) {
	n := func(s string) Name { return dataName(t, s) }
	tests := []struct {
		r    Record
		typ  Type
		want string
	}{
		{Record{n("WWW.Example."), ClassINET, 3600, MX{10, n("mail.example.")}},
			TypeMX, "WWW.Example.\t3600\tIN\tMX\t10 mail.example."},
		{Record{n("version.bind."), ClassCHAOS, 0, TXT{[]string{"9.20.30"}}},
			TypeTXT, "version.bind.\t0\tCH\tTXT\t\"9.20.30\""},
		{Record{n(`weird\032name.example.`), ClassINET, 4294967295, Unknown{Type(65280), []byte{1}}},
			Type(65280), "weird\\032name.example.\t4294967295\tIN\tTYPE65280\t\\# 1 01"},
	}
	for _, tt := range tests {
		if got := tt.r.String(); got != tt.want {
			t.Errorf("String() = %q, want %q", got, tt.want)
		}
		if got := tt.r.Type(); got != tt.typ {
			t.Errorf("%q: Type() = %v, want %v", tt.want, got, tt.typ)
		}
	}
}

// Senders may compress the names in NS, CNAME, MX and SOA data (RFC 3597 §4);
// a compressed DNAME target is read as well.
func TestRDataPointers(t *testing.T) {
	tests := []struct {
		typ  Type
		wire string
		want string
	}{
		{TypeNS, "C00C", "example."},
		{TypeCNAME, "C00C", "example."},
		{TypeDNAME, "C00C", "example."},
		{TypeMX, "000A C00C", "10 example."},
		{TypeMX, "000A 046D61696C C00C", "10 mail.example."},
		{TypeSOA, "C00C 0A686F73746D6173746572 C00C 00000001 00000002 00000003 00000004 00000005",
			"example. hostmaster.example. 1 2 3 4 5"},
	}
	for _, tt := range tests {
		r, err := dataParse(tt.typ, dataHex(t, tt.wire))
		if err != nil {
			t.Errorf("%v %s: %v", tt.typ, tt.wire, err)
			continue
		}
		if got := r.Data.String(); got != tt.want {
			t.Errorf("%v %s: String() = %q, want %q", tt.typ, tt.wire, got, tt.want)
		}
	}
}

// A sender may compress the names in the data of the types of RFC 1035, and
// some senders compress those of later types too, which dig reads (RFC 3597
// §4 asks receivers to). Every type without a typed form whose data holds
// names is kept with its names expanded, so the record prints as dig
// +unknownformat prints it and survives AppendRecord.
func TestRDataExpandedNames(t *testing.T) {
	tests := []struct {
		typ        Type
		wire, text string // text: as named-rrchecker -u prints the data
	}{
		{Type(14), "05726D61696C C00C 05656D61696C C00C", // MINFO rmail.example. email.example.
			`\# 30 05726D61696C076578616D706C650005656D61696C076578616D706C6500`},
		{Type(3), "024D44 C00C", `\# 12 024D44076578616D706C6500`},                // MD MD.example.
		{Type(33), "0001 0002 0035 C00C", `\# 15 000100020035076578616D706C6500`}, // SRV 1 2 53 example.
		{Type(17), "046D626F78 C00C C00C", // RP mbox.example. example.
			`\# 23 046D626F78076578616D706C6500076578616D706C6500`},
		{Type(18), "0001 C00C", `\# 11 0001076578616D706C6500`}, // AFSDB 1 example.
		{Type(21), "000A C00C", `\# 11 000A076578616D706C6500`}, // RT 10 example.
		{Type(26), "000A C00C 03583430 C00C", // PX 10 example. X40.example.
			`\# 24 000A076578616D706C650003583430076578616D706C6500`},
		{Type(35), "0064 000A 0155 074532552B534950 00 C00C", // NAPTR 100 10 "U" "E2U+SIP" "" example.
			`\# 24 0064000A0155074532552B53495000076578616D706C6500`},
		{Type(36), "000A C00C", `\# 11 000A076578616D706C6500`}, // KX 10 example.
	}
	for _, tt := range tests {
		r, err := dataParse(tt.typ, dataHex(t, tt.wire))
		if err != nil {
			t.Errorf("%v %s: %v", tt.typ, tt.wire, err)
			continue
		}
		if got := r.Data.String(); got != tt.text {
			t.Errorf("%v %s: String() = %q, want %q", tt.typ, tt.wire, got, tt.text)
		}
		// The record alone, in a message whose offset 12 holds its owner.
		msg := append([]byte{0x12, 0x34, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0}, AppendRecord(nil, r)...)
		m, err := Parse(msg)
		if err != nil || len(m.Answer) != 1 || !dataEqual(m.Answer[0].Data, r.Data) || m.Answer[0].String() != r.String() {
			t.Errorf("%v %s: AppendRecord gives % X, which Parse reads as %v, %v", tt.typ, tt.wire, msg, m, err)
		}
	}
}

// PTR and SPF have mnemonics and typed data, so they print as dig prints
// them: PTR as its name, which a sender may compress, and SPF as TXT.
func TestRDataPTRAndSPF(t *testing.T) {
	tests := []struct{ typ, wire, text string }{
		{"PTR", "03777777 C00C", "www.example."},
		{"PTR", "03777777 076578616D706C65 00", "www.example."},
		{"SPF", "0B 763D73706631202D616C6C", `"v=spf1 -all"`},
		{"SPF", "03 613B62 00", `"a;b" ""`},
	}
	for _, tt := range tests {
		typ, err := ParseType(tt.typ)
		if err != nil {
			t.Errorf("ParseType(%q): %v", tt.typ, err)
			continue
		}
		r, err := dataParse(typ, dataHex(t, tt.wire))
		if err != nil {
			t.Errorf("%s %s: %v", tt.typ, tt.wire, err)
			continue
		}
		if want := "example.\t3600\tIN\t" + tt.typ + "\t" + tt.text; r.String() != want {
			t.Errorf("%s %s: String() = %q, want %q", tt.typ, tt.wire, r.String(), want)
		}
		if d, err := ParseRData(typ, tt.text); err != nil || d.String() != tt.text || !dataEqual(d, r.Data) {
			t.Errorf("ParseRData(%s, %q) = %v, %v; want the data of %s", tt.typ, tt.text, d, err, tt.wire)
		}
	}
}

// An error says once that the message or data is malformed, also when a
// name inside the data caused it.
func TestRDataErrorSaysMalformedOnce(t *testing.T) {
	_, parseErr := dataParse(TypeRRSIG, dataHex(t, "0001 08 02 0000012C 00000000 00000000 0001 C00C 000102"))
	_, textErr := ParseRData(Type(7), `\# 2 C00C`)
	for _, err := range []error{parseErr, textErr} {
		if !errors.Is(err, ErrMalformed) || strings.Count(err.Error(), "malformed message") != 1 {
			t.Errorf("error %q, want one that wraps ErrMalformed and says so once", err)
		}
	}
}

// dataBad is record data that makes the whole message malformed.
type dataBad struct {
	typ  Type
	wire string
	why  string
}

func dataCheckMalformed(t *testing.T, tests []dataBad) {
	t.Helper()
	for _, tt := range tests {
		_, err := Parse(dataMessage(tt.typ, dataHex(t, tt.wire)))
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("%v %s (%s): Parse error %v, want ErrMalformed", tt.typ, tt.wire, tt.why, err)
		}
	}
}

func TestRDataMalformed(t *testing.T) {
	dataCheckMalformed(t, []dataBad{
		{TypeA, "", "no octet"},
		{TypeA, "C00002", "3 octets"},
		{TypeA, "C0000201FF", "5 octets"},
		{TypeAAAA, strings.Repeat("00", 15), "15 octets"},
		{TypeAAAA, strings.Repeat("00", 17), "17 octets"},
		{TypeNS, "", "no name"},
		{TypeNS, "036E7331", "name without its end"},
		{TypeNS, "00 FF", "octet after the name"},
		{TypeCNAME, "00 FF", "octet after the name"},
		{TypeDNAME, "00 FF", "octet after the name"},
		{TypeSOA, "00 00" + strings.Repeat("00", 19), "numbers one octet short"},
		{TypeSOA, "00 00" + strings.Repeat("00", 21), "octet after the numbers"},
		{TypeMX, "00", "preference cut"},
		{TypeMX, "000A", "no exchange"},
		{TypeMX, "000A 00 FF", "octet after the exchange"},
		{TypeTXT, "", "no string"},
		{TypeTXT, "05 6162", "string longer than the data"},
		{TypeTXT, "01 61 02", "second string cut"},
		{TypeCAA, "00", "no tag"},
		{TypeCAA, "00 00 78", "empty tag"},
		{TypeCAA, "00 03 612D62 78", "tag with a hyphen"},
		{TypeCAA, "00 03 612062 78", "tag with a space"},
		{TypeCAA, "00 02 C3A9 78", "tag not ASCII"},
		{TypeCAA, "00 09 6973737565", "tag longer than the data"},
		{TypePTR, "", "PTR without a name"},
		{TypePTR, "C000", "PTR pointer into the header"},
		{TypePTR, "C00C FF", "octet after the PTR name"},
		{TypeSPF, "", "SPF without a string"},
		// Names that are expanded must be whole and fill the data.
		{Type(7), "C000", "MB pointer into the header"},
		{Type(7), "C00C FF", "octet after the MB name"},
		{Type(14), "C00C", "MINFO with one name"},
		{Type(33), "0001 0002 0035 C000", "SRV pointer into the header"},
	})
}

func TestRDataParseText(t *testing.T) {
	cases := append(dataRDataCases(t), dataDNSSECCases(t)...)
	for _, c := range cases {
		d, err := ParseRData(c.typ, c.text)
		if err != nil {
			t.Errorf("ParseRData(%v, %q): %v", c.typ, c.text, err)
			continue
		}
		if !dataEqual(d, c.want) {
			t.Errorf("ParseRData(%v, %q) = %#v, want %#v", c.typ, c.text, d, c.want)
		}
		if d.Type() != c.typ {
			t.Errorf("ParseRData(%v, %q): Type() = %v", c.typ, c.text, d.Type())
		}
		if got := d.String(); got != c.text {
			t.Errorf("ParseRData(%v, %q): String() = %q", c.typ, c.text, got)
		}
	}
}

func TestRDataParseTextErrors(t *testing.T) {
	tests := []struct {
		typ  Type
		text string
	}{
		{TypeA, ""},
		{TypeA, "192.0.2"},
		{TypeA, "192.0.2.256"},
		{TypeA, "::1"},
		{TypeAAAA, ""},
		{TypeAAAA, "1:2:3"},
		{TypeNS, ""},
		{TypeNS, "a..b."},
		{TypeCNAME, ""},
		{TypeDNAME, ""},
		{TypeSOA, "ns1.example. hostmaster.example. 1 2 3 4"},
		{TypeSOA, "ns1.example. hostmaster.example. 4294967296 2 3 4 5"},
		{TypeMX, "10"},
		{TypeMX, "ten mail.example."},
		{TypeMX, "65536 mail.example."},
		{TypeTXT, ""},
		{TypeTXT, `"abc`},
		{TypeTXT, `"\256"`},
		{TypeCAA, `0 issue`},
		{TypeCAA, `256 issue "x"`},
		{TypeCAA, `0 a-b "x"`},
		{TypeDS, "60485 5"},
		{TypeDS, "70000 5 1 2BB1"},
		{TypeDS, "60485 5 1 XYZ"},
		{TypeDNSKEY, "256 3"},
		{TypeDNSKEY, "256 3 5 !!!!"},
		{TypeRRSIG, "A 5 3 86400 2003032217310 20030220173103 2642 example.com. AAEC"},
		{TypeRRSIG, "A 5 3 86400 20031322173103 20030220173103 2642 example.com. AAEC"},
		{TypeRRSIG, "BOGUS 5 3 86400 20030322173103 20030220173103 2642 example.com. AAEC"},
		{TypeNSEC, ""},
		{TypeNSEC, "host.example. A BOGUS"},
		{TypeNSEC3, "1 1 12 AABBCCDD"},
		{TypeNSEC3, "1 1 12 ZZ 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A"},
		{TypeNSEC3, "1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJ! A"},
		{TypeNSEC3PARAM, "1 0 0"},
		{TypeNSEC3PARAM, "1 0 0 XYZ"},
		{Type(65280), ""},
		{Type(65280), "0A000001"},
		{Type(65280), `\# x 00`},
		{Type(65280), `\# 4 0A00`},
		{Type(65280), `\# 2 C00CC`},
		{Type(7), `\# 2 C00C`}, // an MB name must be whole
	}
	for _, tt := range tests {
		d, err := ParseRData(tt.typ, tt.text)
		if !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseRData(%v, %q) = %v, %v; want ErrMalformed", tt.typ, tt.text, d, err)
		}
	}
}

// FuzzRDataText checks that every text ParseRData accepts prints in a form
// that reads back to the same data.
func FuzzRDataText(f *testing.F) {
	for _, c := range append(dataRDataCases(f), dataDNSSECCases(f)...) {
		f.Add(uint16(c.typ), c.text)
	}
	f.Add(uint16(TypeTXT), `"a\0`)
	f.Add(uint16(TypeNSEC), `a. A A TYPE0`)
	f.Add(uint16(41), `\# 0`)
	f.Fuzz(func(t *testing.T, typ uint16, s string) {
		d, err := ParseRData(Type(typ), s)
		if err != nil {
			if !errors.Is(err, ErrMalformed) {
				t.Fatalf("ParseRData(%d, %q): error %v does not wrap ErrMalformed", typ, s, err)
			}
			return
		}
		text := d.String()
		again, err := ParseRData(Type(typ), text)
		if err != nil {
			t.Fatalf("ParseRData(%d, %q) prints %q, which does not read back: %v", typ, s, text, err)
		}
		if !dataEqual(again, d) || again.String() != text {
			t.Fatalf("ParseRData(%d, %q) = %#v; its text %q reads back as %#v, %q", typ, s, d, text, again, again.String())
		}
	})
}
