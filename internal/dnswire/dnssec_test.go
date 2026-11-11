package dnswire

import (
	"bytes"
	"encoding/base64"
	"errors"
	"strings"
	"testing"
)

// The key, the signature and the record sets are the examples of RFC 4034
// and RFC 5155, Appendix A.
const (
	dataKey    = "AQPSKmynfzW4kyBv015MUG2DeIQ3Cbl+BBZH4b/0PY1kxkmvHjcZc8nokfzj31GajIQKY+5CptLr3buXA10hWqTkF7H6RfoRqXQeogmMHfpftf6zMv1LyBUgia7za6ZEzOJBOztyvhjL742iU/TpPSEDhm2SNKLijfUppn1UaNvv4w=="
	dataKeyHex = "0103D22A6CA77F35B893206FD35E4C506D8378843709B97E041647E1BFF43D8D64C649AF1E371973C9E891FCE3DF519A8C840A63EE42A6D2EBDDBB97035D215AA4E417B1FA45FA11A9741EA2098C1DFA5FB5FEB332FD4BC8152089AEF36BA644CCE2413B3B72BE18CBEF8DA253F4E93D2103866D9234A2E28DF529A67D5468DBEFE3"
	dataSig    = "oJB1W6WNGv+ldvQ3WDG0MQkg5IEhjRip8WTrPYGv07h108dUKGMeDPKijVCHX3DDKdfb+v6oB9wfuh3DTJXUAfI/M0zmO/zz8bW0Rznl8O3tGNazPwQKkRN20XPXV6nwwfoXmJQbsLNrLfkGJ5D6fwFm8nN+6pBzeDQfsS3Ap3o="
	dataSigHex = "A090755BA58D1AFFA576F4375831B4310920E481218D18A9F164EB3D81AFD3B875D3C75428631E0CF2A28D50875F70C329D7DBFAFEA807DC1FBA1DC34C95D401F23F334CE63BFCF3F1B5B44739E5F0EDED18D6B33F040A911376D173D757A9F0C1FA1798941BB0B36B2DF9062790FA7F0166F2737EEA907378341FB12DC0A77A"
	dataHash   = "174EB2409FE28BCB4887A1836F957F0A8425E27B"
	// dataNSECWire is "host.example.com. A MX RRSIG NSEC TYPE1234".
	dataNSECWire = "04686F7374 076578616D706C65 03636F6D 00 0006 400100000003" +
		" 041B 00000000000000000000 00000000000000000000 000000000000 20"
	// dataNSEC3Wire is "1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM".
	dataNSEC3Wire = "01 01 000C 04 AABBCCDD 14 " + dataHash + " 0007 22010000000290"
)

func dataBase64(t testing.TB, s string) []byte {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		t.Fatalf("bad base64 in test table %q: %v", s, err)
	}
	return b
}

func dataDNSSECCases(t testing.TB) []dataCase {
	n := func(s string) Name { return dataName(t, s) }
	h := func(s string) []byte { return dataHex(t, s) }
	b64 := func(s string) []byte { return dataBase64(t, s) }
	return []dataCase{
		{TypeDS, "EC45 05 01 2BB183AF5F22588179A53B0A98631FAD1A292118",
			"60485 5 1 2BB183AF5F22588179A53B0A98631FAD1A292118",
			DS{60485, 5, 1, h("2BB183AF5F22588179A53B0A98631FAD1A292118")}},
		{TypeDNSKEY, "0100 03 05 " + dataKeyHex, "256 3 5 " + dataKey, DNSKEY{256, 3, 5, b64(dataKey)}},
		{TypeRRSIG, "0001 05 03 00015180 3E7C9DD7 3E5510D7 0A52 076578616D706C65 03636F6D 00 " + dataSigHex,
			"A 5 3 86400 20030322173103 20030220173103 2642 example.com. " + dataSig,
			RRSIG{TypeA, 5, 3, 86400, 0x3E7C9DD7, 0x3E5510D7, 2642, n("example.com."), b64(dataSig)}},
		// Times print as the unsigned 32-bit value, not within 68 years of
		// now as dig reads them, so a time after 2038 stays what it is.
		{TypeRRSIG, "FF00 08 02 00000000 00000000 FFFFFFFF FFFF 074578616D706C65 03434F4D 00 000102",
			"TYPE65280 8 2 0 19700101000000 21060207062815 65535 Example.COM. AAEC",
			RRSIG{Type(65280), 8, 2, 0, 0, 0xFFFFFFFF, 65535, n("Example.COM."), []byte{0, 1, 2}}},
		{TypeRRSIG, "0001 08 02 0000012C F4865700 00000000 0001 076578616D706C65 00 000102",
			"A 8 2 300 21000101000000 19700101000000 1 example. AAEC",
			RRSIG{TypeA, 8, 2, 300, 4102444800, 0, 1, n("example."), []byte{0, 1, 2}}},
		{TypeNSEC, dataNSECWire, "host.example.com. A MX RRSIG NSEC TYPE1234",
			NSEC{n("host.example.com."), []Type{TypeA, TypeMX, TypeRRSIG, TypeNSEC, Type(1234)}}},
		// The next name keeps its case; type 128 (NXNAME, RFC 9824) has no mnemonic.
		{TypeNSEC, "044E657874 074578616D706C65 00 0011 40" + strings.Repeat("00", 15) + "80 FF01 80",
			"Next.Example. A TYPE128 TYPE65280",
			NSEC{n("Next.Example."), []Type{TypeA, TypeNXNAME, Type(65280)}}},
		// 32 octets is the longest window.
		{TypeNSEC, "00 0120" + strings.Repeat("00", 31) + "01", ". TYPE511", NSEC{n("."), []Type{Type(511)}}},
		{TypeNSEC3, dataNSEC3Wire,
			"1 1 12 AABBCCDD 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR NS SOA MX RRSIG DNSKEY NSEC3PARAM",
			NSEC3{1, 1, 12, h("AABBCCDD"), h(dataHash),
				[]Type{TypeNS, TypeSOA, TypeMX, TypeRRSIG, TypeDNSKEY, TypeNSEC3PARAM}}},
		{TypeNSEC3, "01 00 0000 00 14 " + dataHash + " 0001 40",
			"1 0 0 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR A",
			NSEC3{1, 0, 0, nil, h(dataHash), []Type{TypeA}}},
		// An empty non-terminal is proven by an NSEC3 record without types.
		{TypeNSEC3, "01 00 FFFF 00 14 " + dataHash, "1 0 65535 - 2T7B4G4VSA5SMI47K61MV5BV1A22BOJR",
			NSEC3{1, 0, 65535, nil, h(dataHash), nil}},
		{TypeNSEC3PARAM, "01 00 0000 00", "1 0 0 -", NSEC3PARAM{1, 0, 0, nil}},
		{TypeNSEC3PARAM, "01 00 000A 02 ABCD", "1 0 10 ABCD", NSEC3PARAM{1, 0, 10, h("ABCD")}},
	}
}

func TestDNSSECDecode(t *testing.T) {
	dataCheckDecode(t, dataDNSSECCases(t))
}

// RFC 4034 §4.1.2 does not forbid an NSEC record without types, though BIND
// refuses one; the codec reads it rather than drop the whole message.
func TestDNSSECEmptyNSECBitmap(t *testing.T) {
	r, err := dataParse(TypeNSEC, dataHex(t, "04686F7374 076578616D706C65 00"))
	if err != nil {
		t.Fatal(err)
	}
	nsec, ok := r.Data.(NSEC)
	if !ok {
		t.Fatalf("data %#v, want NSEC", r.Data)
	}
	if nsec.NextName.String() != "host.example." || len(nsec.Types) != 0 {
		t.Errorf("NSEC = %#v, want host.example. without types", nsec)
	}
}

func TestDNSSECMalformed(t *testing.T) {
	dataCheckMalformed(t, []dataBad{
		{TypeDS, "EC45 05", "no digest type"},
		{TypeDNSKEY, "0100 03", "no algorithm"},
		{TypeRRSIG, strings.Repeat("00", 17), "fixed fields cut"},
		{TypeRRSIG, "0001 08 02 0000012C 00000000 00000000 0001 076578616D706C65", "signer without its end"},
		{TypeRRSIG, "0001 08 02 0000012C 00000000 00000000 0001 C00C 000102", "signer compressed"},
		{TypeNSEC, "", "no next name"},
		{TypeNSEC, "00 00", "window number without length"},
		{TypeNSEC, "00 0001 40 0001 40", "same window twice"},
		{TypeNSEC, "00 0101 40 0001 40", "windows descending"},
		{TypeNSEC, "00 0000", "window of no octet"},
		{TypeNSEC, "00 0021" + strings.Repeat("00", 32) + "01", "window of 33 octets"},
		{TypeNSEC, "00 0002 4000", "last octet of a window zero"},
		{TypeNSEC, "00 0004 40", "window longer than the data"},
		{TypeNSEC3, "01 00 0000 00 00", "empty hash"},
		{TypeNSEC3, "01 00 0000 05 AB", "salt longer than the data"},
		{TypeNSEC3, "01 00 0000 00 14 AB", "hash longer than the data"},
		{TypeNSEC3, "01 00 0000 00 14 " + dataHash + " 0002 4000", "last octet of a window zero"},
		{TypeNSEC3PARAM, "01 00 0000", "no salt length"},
		{TypeNSEC3PARAM, "01 00 0000 02 AB", "salt longer than the data"},
		{TypeNSEC3PARAM, "01 00 0000 00 FF", "octet after the salt"},
	})
}

// A digest, key, signature or hash that its algorithm cannot have makes the
// whole message malformed, and ParseRData refuses its text.
func TestDNSSECLengthsFitAlgorithm(t *testing.T) {
	digest := func(n int) string { return strings.Repeat("AB", n) }
	tests := []struct {
		typ        Type
		wire, text string
	}{
		{TypeDS, "EC45 05 01 " + digest(19), "60485 5 1 " + digest(19)},
		{TypeDS, "EC45 05 01 " + digest(32), "60485 5 1 " + digest(32)},
		{TypeDS, "EC45 05 02 " + digest(20), "60485 5 2 " + digest(20)},
		{TypeDS, "EC45 05 02 " + digest(33), "60485 5 2 " + digest(33)},
		{TypeDS, "EC45 0E 04 " + digest(32), "60485 14 4 " + digest(32)},
		{TypeDS, "EC45 05 03", "60485 5 3"},
		{TypeDNSKEY, "0100 03 05", "256 3 5"},
		{TypeRRSIG, "0001 05 03 00015180 3E7C9DD7 3E5510D7 0A52 076578616D706C65 03636F6D 00",
			"A 5 3 86400 20030322173103 20030220173103 2642 example.com."},
		{TypeNSEC3, "01 00 0000 00 13 " + dataHash[2:] + " 0001 40", "1 0 0 - " +
			nsec3HashEncoding.EncodeToString(dataHex(t, dataHash[2:])) + " A"},
	}
	for _, tt := range tests {
		dataCheckMalformed(t, []dataBad{{tt.typ, tt.wire, tt.text}})
		if d, err := ParseRData(tt.typ, tt.text); !errors.Is(err, ErrMalformed) {
			t.Errorf("ParseRData(%v, %q) = %v, %v; want ErrMalformed", tt.typ, tt.text, d, err)
		}
	}
	// Lengths that the digest type and the hash algorithm allow.
	for _, c := range []dataCase{
		{TypeDS, "EC45 0E 04 " + digest(48), "60485 14 4 " + digest(48), nil},
		{TypeDS, "EC45 05 03 AB", "60485 5 3 AB", nil},
		{TypeNSEC3, "02 00 0000 00 01 AB", "2 0 0 - LC", nil},
	} {
		if _, err := dataParse(c.typ, dataHex(t, c.wire)); err != nil {
			t.Errorf("%v %s: %v", c.typ, c.wire, err)
		}
		if _, err := ParseRData(c.typ, c.text); err != nil {
			t.Errorf("ParseRData(%v, %q): %v", c.typ, c.text, err)
		}
	}
}

// A sender must not compress the next name of NSEC (RFC 4034 §4.1.1), but
// dig reads such a record, so the codec reads it too, with the name expanded.
func TestDNSSECNSECCompressedNextName(t *testing.T) {
	r, err := dataParse(TypeNSEC, dataHex(t, "C00C 0001 40"))
	if err != nil {
		t.Fatal(err)
	}
	if got := r.Data.String(); got != "example. A" {
		t.Errorf("String() = %q, want %q", got, "example. A")
	}
	if got, want := AppendRData(nil, r.Data), dataHex(t, "076578616D706C6500 0001 40"); !bytes.Equal(got, want) {
		t.Errorf("AppendRData = % X, want % X", got, want)
	}
}
