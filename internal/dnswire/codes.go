package dnswire

import (
	"fmt"
	"strconv"
	"strings"
)

type Type uint16

const (
	TypeA          Type = 1
	TypeNS         Type = 2
	TypeCNAME      Type = 5
	TypeSOA        Type = 6
	TypePTR        Type = 12
	TypeMX         Type = 15
	TypeTXT        Type = 16
	TypeAAAA       Type = 28
	TypeDNAME      Type = 39
	TypeOPT        Type = 41
	TypeDS         Type = 43
	TypeRRSIG      Type = 46
	TypeNSEC       Type = 47
	TypeDNSKEY     Type = 48
	TypeNSEC3      Type = 50
	TypeNSEC3PARAM Type = 51
	TypeSPF        Type = 99
	TypeNXNAME     Type = 128 // no mnemonic: it prints as TYPE128, as dig does
	TypeTSIG       Type = 250
	TypeIXFR       Type = 251
	TypeAXFR       Type = 252
	TypeANY        Type = 255
	TypeCAA        Type = 257
)

var typeNames = map[Type]string{
	TypeA:          "A",
	TypeNS:         "NS",
	TypeCNAME:      "CNAME",
	TypeSOA:        "SOA",
	TypePTR:        "PTR",
	TypeMX:         "MX",
	TypeTXT:        "TXT",
	TypeAAAA:       "AAAA",
	TypeDNAME:      "DNAME",
	TypeOPT:        "OPT",
	TypeDS:         "DS",
	TypeRRSIG:      "RRSIG",
	TypeNSEC:       "NSEC",
	TypeDNSKEY:     "DNSKEY",
	TypeNSEC3:      "NSEC3",
	TypeNSEC3PARAM: "NSEC3PARAM",
	TypeSPF:        "SPF",
	TypeTSIG:       "TSIG",
	TypeIXFR:       "IXFR",
	TypeAXFR:       "AXFR",
	TypeANY:        "ANY",
	TypeCAA:        "CAA",
}

var typeByName = func() map[string]Type {
	m := make(map[string]Type, len(typeNames))
	for t, name := range typeNames {
		m[lowerASCII(name)] = t
	}
	return m
}()

func (t Type) String() string {
	if name, ok := typeNames[t]; ok {
		return name
	}
	return "TYPE" + strconv.Itoa(int(t))
}

// ParseType reads a mnemonic in any case, or TYPE<n> with n from 0 to 65535.
func ParseType(s string) (Type, error) {
	lower := lowerASCII(s)
	if t, ok := typeByName[lower]; ok {
		return t, nil
	}
	if digits, ok := strings.CutPrefix(lower, "type"); ok {
		if n, err := strconv.ParseUint(digits, 10, 16); err == nil {
			return Type(n), nil
		}
	}
	return 0, fmt.Errorf("%w: %q", ErrInvalidType, s)
}

type Class uint16

const (
	ClassINET   Class = 1
	ClassCHAOS  Class = 3
	ClassHESIOD Class = 4
	ClassNONE   Class = 254
	ClassANY    Class = 255
)

var classNames = map[Class]string{
	ClassINET:   "IN",
	ClassCHAOS:  "CH",
	ClassHESIOD: "HS",
	ClassNONE:   "NONE",
	ClassANY:    "ANY",
}

func (c Class) String() string {
	if name, ok := classNames[c]; ok {
		return name
	}
	return "CLASS" + strconv.Itoa(int(c))
}

type Opcode uint8

// OpcodeQuery is the only opcode this package sends.
const OpcodeQuery Opcode = 0

var opcodeNames = map[Opcode]string{
	OpcodeQuery: "QUERY",
	1:           "IQUERY",
	2:           "STATUS",
	4:           "NOTIFY",
	5:           "UPDATE",
}

func (o Opcode) String() string {
	if name, ok := opcodeNames[o]; ok {
		return name
	}
	return "RESERVED" + strconv.Itoa(int(o))
}

// Rcode is the 12-bit response code: the 4 bits of the header and, when the
// message has an OPT record, its 8 extended bits above them.
type Rcode uint16

var rcodeNames = map[Rcode]string{
	0:  "NOERROR",
	1:  "FORMERR",
	2:  "SERVFAIL",
	3:  "NXDOMAIN",
	4:  "NOTIMP",
	5:  "REFUSED",
	6:  "YXDOMAIN",
	7:  "YXRRSET",
	8:  "NXRRSET",
	9:  "NOTAUTH",
	10: "NOTZONE",
	16: "BADVERS",
	23: "BADCOOKIE",
}

func (r Rcode) String() string {
	if name, ok := rcodeNames[r]; ok {
		return name
	}
	return strconv.Itoa(int(r))
}
