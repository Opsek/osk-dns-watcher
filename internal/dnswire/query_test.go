package dnswire_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

func TestQueryPackLayoutIsByteExact(t *testing.T) {
	header := func(id, flags, nscount uint16) []byte {
		return wireCat(wireU16(id), wireU16(flags), wireU16(1), wireU16(0), wireU16(nscount), wireU16(1))
	}
	question := wireQuestion(wireLabels("Example", "COM"), wireTypeA)
	opt := func(ttl uint32, options ...[]byte) []byte {
		return wireRR(wireLabels(), wireTypeOPT, 1232, ttl, wireCat(options...))
	}
	name := wireMustName(t, "Example.COM")
	corp := wireMustName(t, "corp.test.")
	c8, c40 := wireOctets(8), wireOctets(40)
	cases := []struct {
		name string
		q    dnswire.Query
		id   uint16
		want []byte
	}{
		{"plain query", dnswire.Query{Name: name, Type: dnswire.TypeA}, 0x1234, []byte{
			0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
			7, 'E', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'C', 'O', 'M', 0, 0x00, 0x01, 0x00, 0x01,
			0, 0x00, 0x29, 0x04, 0xD0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		}},
		{"recursion desired", dnswire.Query{Name: name, Type: dnswire.TypeA, RecursionDesired: true}, 1,
			wireCat(header(1, 0x0100, 0), question, opt(0))},
		{"checking disabled", dnswire.Query{Name: name, Type: dnswire.TypeA, CheckingDisabled: true}, 2,
			wireCat(header(2, 0x0010, 0), question, opt(0))},
		{"DNSSEC OK", dnswire.Query{Name: name, Type: dnswire.TypeA, DNSSECOK: true}, 3,
			wireCat(header(3, 0, 0), question, opt(0x8000))},
		{"every flag", dnswire.Query{Name: name, Type: dnswire.TypeA, RecursionDesired: true, CheckingDisabled: true, DNSSECOK: true}, 4,
			wireCat(header(4, 0x0110, 0), question, opt(0x8000))},
		{"client cookie", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: c8}, 5,
			wireCat(header(5, 0, 0), question, opt(0, wireOption(10, c8)))},
		{"client and server cookie of 40 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: c40}, 6,
			wireCat(header(6, 0, 0), question, opt(0, wireOption(10, c40)))},
		{"IXFR with the serial in an SOA", dnswire.Query{Name: corp, Type: dnswire.TypeIXFR, IXFRSerial: 7}, 7,
			wireCat(header(7, 0, 1), wireQuestion(wireLabels("corp", "test"), 251),
				wireRR(wireLabels("corp", "test"), wireTypeSOA, wireClassIN, 0,
					wireCat(wireLabels(), wireLabels(), wireU32(7), make([]byte, 16))),
				opt(0))},
		{"AXFR of the root", dnswire.Query{Type: dnswire.Type(252)}, 0,
			wireCat(header(0, 0, 0), wireQuestion(wireLabels(), 252), opt(0))},
		{"private type", dnswire.Query{Name: name, Type: wireTypePrivate}, 0xFFFF,
			wireCat(header(0xFFFF, 0, 0), wireQuestion(wireLabels("Example", "COM"), wireTypePrivate), opt(0))},
	}
	for _, c := range cases {
		got, err := c.q.Pack(c.id)
		if err != nil {
			t.Errorf("%s: Pack: %v", c.name, err)
			continue
		}
		if !bytes.Equal(got, c.want) {
			t.Errorf("%s: Pack =\n% X\nwant\n% X", c.name, got, c.want)
		}
	}
}

func TestQueryPackRejectsInvalidQueries(t *testing.T) {
	name := wireMustName(t, "example.test")
	cases := []struct {
		name string
		q    dnswire.Query
		ok   bool
	}{
		{"cookie of 7 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(7)}, false},
		{"cookie of 8 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(8)}, true},
		{"cookie of 9 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(9)}, false},
		{"cookie of 15 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(15)}, false},
		{"cookie of 16 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(16)}, true},
		{"cookie of 40 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(40)}, true},
		{"cookie of 41 octets", dnswire.Query{Name: name, Type: dnswire.TypeA, Cookie: wireOctets(41)}, false},
		{"serial with type A", dnswire.Query{Name: name, Type: dnswire.TypeA, IXFRSerial: 1}, false},
		{"serial with AXFR", dnswire.Query{Name: name, Type: dnswire.Type(252), IXFRSerial: 1}, false},
		{"serial with IXFR", dnswire.Query{Name: name, Type: dnswire.TypeIXFR, IXFRSerial: 1}, true},
		{"IXFR with serial 0", dnswire.Query{Name: name, Type: dnswire.TypeIXFR}, true},
		{"type OPT", dnswire.Query{Name: name, Type: dnswire.Type(41)}, false},
		{"type TSIG", dnswire.Query{Name: name, Type: dnswire.Type(250)}, false},
		{"type AXFR", dnswire.Query{Name: name, Type: dnswire.Type(252)}, true},
		{"type ANY", dnswire.Query{Name: name, Type: dnswire.TypeANY}, true},
		{"type NXNAME", dnswire.Query{Name: name, Type: dnswire.TypeNXNAME}, true},
	}
	for _, c := range cases {
		_, err := c.q.Pack(1)
		if c.ok && err != nil {
			t.Errorf("%s: Pack: %v", c.name, err)
		}
		if !c.ok && !errors.Is(err, dnswire.ErrInvalidQuery) {
			t.Errorf("%s: Pack error = %v; want one that wraps ErrInvalidQuery", c.name, err)
		}
	}
}
