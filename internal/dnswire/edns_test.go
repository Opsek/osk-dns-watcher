package dnswire_test

import (
	"bytes"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// wireOctets returns n distinct octets, so that a wrong slice of them shows.
func wireOctets(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i + 1)
	}
	return b
}

func TestParseAllowsOneOPTOwnedByTheRootInAdditional(t *testing.T) {
	a := wireA(wireLabels("example", "test"))
	opt := wireOPT(1232, 0, 0, 0)
	msg := func(answer, authority, additional [][]byte) []byte {
		return wireMessage(wireFlagQR, nil, answer, authority, additional)
	}
	wireCheckCases(t, []wireCase{
		{"one OPT in additional", msg(nil, nil, [][]byte{opt}), true},
		{"OPT after another additional record", msg(nil, nil, [][]byte{a, opt}), true},
		{"OPT in answer", msg([][]byte{opt}, nil, nil), false},
		{"OPT in authority", msg(nil, [][]byte{opt}, nil), false},
		{"two OPT", msg(nil, nil, [][]byte{opt, opt}), false},
		{"OPT owned by a name other than the root", msg(nil, nil, [][]byte{wireRR(wireLabels("a"), wireTypeOPT, 1232, 0, nil)}), false},
	})
}

func TestParseRequiresOPTOptionsToFillItsData(t *testing.T) {
	opt := func(data ...[]byte) []byte {
		return wireMessage(wireFlagQR, nil, nil, nil, [][]byte{wireRR(wireLabels(), wireTypeOPT, 1232, 0, wireCat(data...))})
	}
	cookie, ede := wireOption(10, wireOctets(8)), wireOption(15, wireU16(6))
	wireCheckCases(t, []wireCase{
		{"no options", opt(), true},
		{"two options that fill the data", opt(cookie, ede), true},
		{"an option of length zero", opt(wireOption(12, nil)), true},
		{"an option longer than the data", opt(wireU16(10), wireU16(9), wireOctets(8)), false},
		{"one octet left over", opt(cookie, []byte{0}), false},
		{"three octets left over", opt(cookie, []byte{0, 10, 0}), false},
	})
}

func TestParseKeepsEveryOptionInOrder(t *testing.T) {
	want := []dnswire.Option{
		{Code: 12, Data: []byte{0, 0}},
		{Code: 10, Data: wireOctets(8)},
		{Code: 65001, Data: []byte("x")},
		{Code: 15, Data: []byte{0, 1}},
		{Code: 3},
	}
	var options [][]byte
	for _, o := range want {
		options = append(options, wireOption(o.Code, o.Data))
	}
	m := wireParseOK(t, wireMessage(wireFlagQR, nil, nil, nil, [][]byte{wireOPT(1232, 0, 0, 0, options...)}))
	if m.EDNS == nil || len(m.EDNS.Options) != len(want) {
		t.Fatalf("EDNS = %+v; want the options %+v", m.EDNS, want)
	}
	for i, o := range m.EDNS.Options {
		if o.Code != want[i].Code || !bytes.Equal(o.Data, want[i].Data) {
			t.Errorf("option %d = %d % X; want %d % X", i, o.Code, o.Data, want[i].Code, want[i].Data)
		}
	}
}

func TestParseLeavesOptionContentsToTheAccessors(t *testing.T) {
	b := wireMessage(wireFlagQR, nil, nil, nil, [][]byte{
		wireOPT(1232, 0, 0, 0, wireOption(10, wireOctets(5)), wireOption(15, []byte{0})),
	})
	m := wireParseOK(t, b)
	if _, _, ok := m.EDNS.Cookie(); ok {
		t.Error("Cookie() accepted a cookie of 5 octets")
	}
	if got := m.EDNS.ExtendedErrors(); len(got) != 0 {
		t.Errorf("ExtendedErrors() = %+v from an option of one octet; want none", got)
	}
}

func TestParseReadsTheOPTHeaderFields(t *testing.T) {
	cases := []struct {
		udpSize uint16
		version uint8
		flags   uint16
		want    dnswire.EDNS
	}{
		{1232, 0, 0x8000, dnswire.EDNS{UDPSize: 1232, DO: true, Flags: 0x8000}},
		{512, 1, 0x0001, dnswire.EDNS{Version: 1, UDPSize: 512, Flags: 0x0001}},
		{65535, 255, 0xFFFF, dnswire.EDNS{Version: 255, UDPSize: 65535, DO: true, Flags: 0xFFFF}},
	}
	for _, c := range cases {
		m := wireParseOK(t, wireMessage(wireFlagQR, nil, nil, nil, [][]byte{wireOPT(c.udpSize, 0, c.version, c.flags)}))
		e := m.EDNS
		if e == nil {
			t.Fatalf("EDNS is nil for an OPT of size %d", c.udpSize)
		}
		if e.Version != c.want.Version || e.UDPSize != c.want.UDPSize || e.DO != c.want.DO || e.Flags != c.want.Flags || len(e.Options) != 0 {
			t.Errorf("EDNS = %+v; want %+v", *e, c.want)
		}
		if len(m.Additional) != 0 {
			t.Errorf("Additional = %v; want the OPT left out", m.Additional)
		}
	}
}

func TestParseWithoutOPTHasNoEDNS(t *testing.T) {
	m := wireParseOK(t, wireMessage(wireFlagQR, nil, nil, nil, [][]byte{wireA(wireLabels("glue", "test"))}))
	if m.EDNS != nil {
		t.Errorf("EDNS = %+v for a message without OPT; want nil", *m.EDNS)
	}
}

func TestParseTakesTheUpperRcodeBitsFromOPT(t *testing.T) {
	cases := []struct {
		header   uint16
		withOPT  bool
		extended uint8
		want     dnswire.Rcode
		text     string
	}{
		{3, false, 0, 3, "NXDOMAIN"},
		{3, true, 0, 3, "NXDOMAIN"},
		{0, true, 1, 16, "BADVERS"},
		{7, true, 1, 23, "BADCOOKIE"},
		{1, true, 0x10, 257, "257"},
		{15, true, 0xFF, 4095, "4095"},
	}
	for _, c := range cases {
		var additional [][]byte
		if c.withOPT {
			additional = [][]byte{wireOPT(1232, c.extended, 0, 0)}
		}
		m := wireParseOK(t, wireMessage(wireFlagQR|c.header, nil, nil, nil, additional))
		if m.Rcode != c.want || m.Rcode.String() != c.text {
			t.Errorf("header rcode %d, OPT %v %d: Rcode = %d %q; want %d %q",
				c.header, c.withOPT, c.extended, uint16(m.Rcode), m.Rcode.String(), uint16(c.want), c.text)
		}
	}
}

func TestEDNSCookieNeedsExactlyOneOptionOfAValidLength(t *testing.T) {
	c8, c16, c40 := wireOctets(8), wireOctets(16), wireOctets(40)
	cases := []struct {
		name           string
		options        []dnswire.Option
		ok             bool
		client, server []byte
	}{
		{"no option", nil, false, nil, nil},
		{"length 0", []dnswire.Option{{Code: 10}}, false, nil, nil},
		{"length 7", []dnswire.Option{{Code: 10, Data: wireOctets(7)}}, false, nil, nil},
		{"length 8", []dnswire.Option{{Code: 10, Data: c8}}, true, c8, nil},
		{"length 9", []dnswire.Option{{Code: 10, Data: wireOctets(9)}}, false, nil, nil},
		{"length 15", []dnswire.Option{{Code: 10, Data: wireOctets(15)}}, false, nil, nil},
		{"length 16", []dnswire.Option{{Code: 10, Data: c16}}, true, c16[:8], c16[8:]},
		{"length 40", []dnswire.Option{{Code: 10, Data: c40}}, true, c40[:8], c40[8:]},
		{"length 41", []dnswire.Option{{Code: 10, Data: wireOctets(41)}}, false, nil, nil},
		{"two cookie options", []dnswire.Option{{Code: 10, Data: c8}, {Code: 10, Data: c8}}, false, nil, nil},
		{"among other options", []dnswire.Option{{Code: 12, Data: []byte{0}}, {Code: 10, Data: c16}, {Code: 15, Data: []byte{0, 6}}}, true, c16[:8], c16[8:]},
	}
	for _, c := range cases {
		e := &dnswire.EDNS{Options: c.options}
		client, server, ok := e.Cookie()
		if ok != c.ok {
			t.Errorf("%s: Cookie() ok = %v; want %v", c.name, ok, c.ok)
			continue
		}
		if ok && (!bytes.Equal(client, c.client) || !bytes.Equal(server, c.server)) {
			t.Errorf("%s: Cookie() = % X, % X; want % X, % X", c.name, client, server, c.client, c.server)
		}
	}
}

func TestEDNSExtendedErrorsKeepsEveryOptionOfTwoOctetsOrMore(t *testing.T) {
	e := &dnswire.EDNS{Options: []dnswire.Option{
		{Code: 15},
		{Code: 15, Data: []byte{0}},
		{Code: 15, Data: []byte{0, 6}},
		{Code: 10, Data: wireOctets(8)},
		{Code: 15, Data: []byte{0x01, 0x02, 'n', 'o', 0xFF}},
	}}
	want := []dnswire.ExtendedError{{InfoCode: 6}, {InfoCode: 0x0102, ExtraText: "no\xff"}}
	got := e.ExtendedErrors()
	if len(got) != len(want) {
		t.Fatalf("ExtendedErrors() = %+v; want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("ExtendedErrors()[%d] = %+v; want %+v", i, got[i], want[i])
		}
	}
	if got := (&dnswire.EDNS{}).ExtendedErrors(); len(got) != 0 {
		t.Errorf("ExtendedErrors() without options = %+v; want none", got)
	}
}

func TestParseReadsACookieAndTwoExtendedErrors(t *testing.T) {
	c16 := wireOctets(16)
	b := wireMessage(wireFlagQR, nil, nil, nil, [][]byte{wireOPT(1232, 0, 0, 0x8000,
		wireOption(10, c16),
		wireOption(15, wireU16(6)),
		wireOption(15, wireCat(wireU16(22), []byte("no reachable authority"))),
	)})
	m := wireParseOK(t, b)
	client, server, ok := m.EDNS.Cookie()
	if !ok || !bytes.Equal(client, c16[:8]) || !bytes.Equal(server, c16[8:]) {
		t.Errorf("Cookie() = % X, % X, %v; want % X, % X, true", client, server, ok, c16[:8], c16[8:])
	}
	want := []dnswire.ExtendedError{{InfoCode: 6}, {InfoCode: 22, ExtraText: "no reachable authority"}}
	got := m.EDNS.ExtendedErrors()
	if len(got) != 2 || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("ExtendedErrors() = %+v; want %+v", got, want)
	}
}
