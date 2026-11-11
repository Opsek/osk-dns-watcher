package dnswire

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestCanonicalAppendRData(t *testing.T) {
	for _, c := range append(dataRDataCases(t), dataDNSSECCases(t)...) {
		want := dataHex(t, c.wire)
		if got := AppendRData(nil, c.want); !bytes.Equal(got, want) {
			t.Errorf("AppendRData(%v %q) = %X, want %X", c.typ, c.text, got, want)
		}
		got := AppendRData([]byte{0xAA, 0xBB}, c.want)
		if !bytes.Equal(got, append([]byte{0xAA, 0xBB}, want...)) {
			t.Errorf("AppendRData after two octets (%v %q) = %X", c.typ, c.text, got)
		}
	}
}

// A type bitmap lists each type once, in ascending order (RFC 4034 §4.1.2),
// whatever the order of Types.
func TestCanonicalAppendRDataSortsTypes(t *testing.T) {
	n := func(s string) Name { return dataName(t, s) }
	tests := []struct {
		d    RData
		wire string
	}{
		{NSEC{n("host.example.com."), []Type{TypeNSEC, Type(1234), TypeA, TypeRRSIG, TypeMX, TypeA, TypeNSEC}},
			dataNSECWire},
		{NSEC3{1, 1, 12, dataHex(t, "AABBCCDD"), dataHex(t, dataHash),
			[]Type{TypeNSEC3PARAM, TypeRRSIG, TypeNS, TypeDNSKEY, TypeMX, TypeSOA, TypeNS}},
			dataNSEC3Wire},
		{NSEC{n("a."), nil}, "0161 00"},
	}
	for _, tt := range tests {
		want := dataHex(t, tt.wire)
		if got := AppendRData(nil, tt.d); !bytes.Equal(got, want) {
			t.Errorf("AppendRData(%#v) = %X, want %X", tt.d, got, want)
		}
	}
}

// Names are written uncompressed and with their case (RFC 4034 §6.2 item 1).
func TestCanonicalAppendRecord(t *testing.T) {
	n := func(s string) Name { return dataName(t, s) }
	tests := []struct {
		r    Record
		wire string
	}{
		{Record{n("WWW.Example."), ClassINET, 3600, A{netip.MustParseAddr("192.0.2.1")}},
			"03575757 074578616D706C65 00 0001 0001 00000E10 0004 C0000201"},
		{Record{n("example."), ClassINET, 3600, MX{10, n("mail.example.")}},
			"076578616D706C65 00 000F 0001 00000E10 0010 000A 046D61696C 076578616D706C65 00"},
		{Record{n("x."), ClassCHAOS, 0, Unknown{Type(65280), nil}},
			"0178 00 FF00 0003 00000000 0000"},
	}
	for _, tt := range tests {
		want := dataHex(t, tt.wire)
		if got := AppendRecord(nil, tt.r); !bytes.Equal(got, want) {
			t.Errorf("AppendRecord(%q) = %X, want %X", tt.r.String(), got, want)
		}
		got := AppendRecord([]byte{0xAA}, tt.r)
		if !bytes.Equal(got, append([]byte{0xAA}, want...)) {
			t.Errorf("AppendRecord after one octet (%q) = %X", tt.r.String(), got)
		}
	}
}

// RFC 4034 §6.2 items 2 and 3 as RFC 6840 §5.1 amends them: the owner and the
// names in NS, CNAME, SOA, MX, DNAME, PTR and the RRSIG signer are lowercased;
// the NSEC next name, text, keys, signatures and the data of a type that item
// 3 does not list keep their octets.
func TestCanonicalRecord(t *testing.T) {
	n := func(s string) Name { return dataName(t, s) }
	sig := dataBase64(t, "AbCd")
	tests := []struct {
		r    Record
		want string
	}{
		{Record{n("WWW.Example."), ClassINET, 3600, A{netip.MustParseAddr("192.0.2.1")}},
			"www.example.\t3600\tIN\tA\t192.0.2.1"},
		{Record{n(`\195\132X.Example.`), ClassINET, 60, AAAA{netip.MustParseAddr("2001:DB8::1")}},
			"\\195\\132x.example.\t60\tIN\tAAAA\t2001:db8::1"},
		{Record{n("Example."), ClassINET, 3600, NS{n("NS1.Example.")}},
			"example.\t3600\tIN\tNS\tns1.example."},
		{Record{n("CDN.Example."), ClassINET, 3600, CNAME{n("Edge.Host.Example.")}},
			"cdn.example.\t3600\tIN\tCNAME\tedge.host.example."},
		{Record{n("Old.Example."), ClassINET, 3600, DNAME{n("New.Example.NET.")}},
			"old.example.\t3600\tIN\tDNAME\tnew.example.net."},
		{Record{n("1.2.0.192.IN-ADDR.ARPA."), ClassINET, 3600, PTR{n("Host.Example.COM.")}},
			"1.2.0.192.in-addr.arpa.\t3600\tIN\tPTR\thost.example.com."},
		{Record{n("Example."), ClassINET, 3600, SOA{n("NS1.Example."), n("Host.Master.Example."), 1, 2, 3, 4, 5}},
			"example.\t3600\tIN\tSOA\tns1.example. host.master.example. 1 2 3 4 5"},
		{Record{n("Example."), ClassINET, 3600, MX{10, n("Mail.Example.")}},
			"example.\t3600\tIN\tMX\t10 mail.example."},
		{Record{n("WWW.Example.COM."), ClassINET, 300, RRSIG{TypeA, 8, 3, 300, 0, 0, 1, n("Example.COM."), sig}},
			"www.example.com.\t300\tIN\tRRSIG\tA 8 3 300 19700101000000 19700101000000 1 example.com. AbCd"},
		{Record{n("Alfa.Example."), ClassINET, 300, NSEC{n("Host.Example."), []Type{TypeA}}},
			"alfa.example.\t300\tIN\tNSEC\tHost.Example. A"},
		{Record{n("Example."), ClassINET, 300, TXT{[]string{"v=spf1 MX -ALL"}}},
			"example.\t300\tIN\tTXT\t\"v=spf1 MX -ALL\""},
		{Record{n("Example."), ClassINET, 300, SPF{[]string{"v=spf1 MX -ALL"}}},
			"example.\t300\tIN\tSPF\t\"v=spf1 MX -ALL\""},
		{Record{n("Example."), ClassINET, 300, CAA{0, "issue", "CA.Example"}},
			"example.\t300\tIN\tCAA\t0 issue \"CA.Example\""},
		{Record{n("Example."), ClassINET, 300, DNSKEY{256, 3, 5, dataBase64(t, dataKey)}},
			"example.\t300\tIN\tDNSKEY\t256 3 5 " + dataKey},
		{Record{n("X.Example."), ClassINET, 300, Unknown{Type(65280), []byte("AB")}},
			"x.example.\t300\tIN\tTYPE65280\t\\# 2 4142"},
	}
	for _, tt := range tests {
		before := tt.r.String()
		if got := Canonical(tt.r).String(); got != tt.want {
			t.Errorf("Canonical(%q) = %q, want %q", before, got, tt.want)
		}
		if after := tt.r.String(); after != before {
			t.Errorf("Canonical changed its input from %q to %q", before, after)
		}
	}
}

// The types of RFC 4034 §6.2 item 3 that are held as Unknown, but for the
// obsolete SIG, NXT and A6, get the names in their data lowercased,
// and nothing else: not the SRV port 0x4142 ("AB"), not the NAPTR flags,
// service or regexp. The wire forms are those of named-rrchecker (BIND 9.20).
// Data that does not fit the type, such as a compressed name, stays as it is.
func TestCanonicalUnknownNames(t *testing.T) {
	tests := []struct {
		typ      Type
		in, want string
	}{
		{Type(33), // SRV 1 2 16706 Target.Example.COM.
			"0001 0002 4142 06546172676574 074578616D706C65 03434F4D 00",
			"0001 0002 4142 06746172676574 076578616D706C65 03636F6D 00"},
		{Type(35), // NAPTR 100 10 "U" "E2U+SIP" "!^.*$!sip:Info@Example.COM!" Repl.Example.COM.
			"0064 000A 0155 074532552B534950 1B215E2E2A24217369703A496E666F404578616D706C652E434F4D21" +
				" 045265706C 074578616D706C65 03434F4D 00",
			"0064 000A 0155 074532552B534950 1B215E2E2A24217369703A496E666F404578616D706C652E434F4D21" +
				" 047265706C 076578616D706C65 03636F6D 00"},
		{Type(14), // MINFO Rmail.Example. Email.Example.
			"05526D61696C 074578616D706C65 00 05456D61696C 074578616D706C65 00",
			"05726D61696C 076578616D706C65 00 05656D61696C 076578616D706C65 00"},
		{Type(26), // PX 10 Map822.Example. MapX400.Example.
			"000A 064D6170383232 074578616D706C65 00 074D617058343030 074578616D706C65 00",
			"000A 066D6170383232 076578616D706C65 00 076D617078343030 076578616D706C65 00"},
		{Type(18), // AFSDB 1 AFS.Example.
			"0001 03414653 074578616D706C65 00",
			"0001 03616673 076578616D706C65 00"},
		{Type(17), // RP Mbox.Example. TXT.Example.
			"044D626F78 074578616D706C65 00 03545854 074578616D706C65 00",
			"046D626F78 076578616D706C65 00 03747874 076578616D706C65 00"},
		{Type(21), // RT 10 Relay.Example.
			"000A 0552656C6179 074578616D706C65 00",
			"000A 0572656C6179 076578616D706C65 00"},
		{Type(36), // KX 10 KX.Example.
			"000A 024B58 074578616D706C65 00",
			"000A 026B78 076578616D706C65 00"},
		{Type(7), "024D42 074578616D706C65 00", "026D62 076578616D706C65 00"}, // MB MB.Example.
		{Type(8), "024D47 074578616D706C65 00", "026D67 076578616D706C65 00"}, // MG MG.Example.
		{Type(9), "024D52 074578616D706C65 00", "026D72 076578616D706C65 00"}, // MR MR.Example.
		{Type(3), "024D44 074578616D706C65 00", "026D64 076578616D706C65 00"}, // MD MD.Example.
		{Type(4), "024D46 074578616D706C65 00", "026D66 076578616D706C65 00"}, // MF MF.Example.
		// A pointer, also after a name that could be lowercased, a name
		// without its end, an octet after the last name, a NAPTR string
		// that runs past the data: the data stays as it is.
		{Type(7), "024142 C00C", "024142 C00C"},
		{Type(14), "05526D61696C 00 C00C", "05526D61696C 00 C00C"},
		{Type(7), "04486F7374", "04486F7374"},
		{Type(7), "04486F7374 00 FF", "04486F7374 00 FF"},
		{Type(35), "0064 000A 05 55", "0064 000A 05 55"},
		// A type that item 3 does not list keeps its octets.
		{Type(65280), "04486F7374 00", "04486F7374 00"},
	}
	for _, tt := range tests {
		in := Unknown{TypeCode: tt.typ, Data: dataHex(t, tt.in)}
		r := Record{Name: dataName(t, "X.Example."), Class: ClassINET, TTL: 300, Data: in}
		got, ok := Canonical(r).Data.(Unknown)
		if !ok || got.TypeCode != tt.typ || !bytes.Equal(got.Data, dataHex(t, tt.want)) {
			t.Errorf("Canonical of %v %s: data %#v, want %s", tt.typ, tt.in, Canonical(r).Data, tt.want)
		}
		if !bytes.Equal(in.Data, dataHex(t, tt.in)) {
			t.Errorf("Canonical of %v %s changed its input to %X", tt.typ, tt.in, in.Data)
		}
	}
}
