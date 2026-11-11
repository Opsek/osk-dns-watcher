package dnswire

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// RData is the data of one record. The unexported method seals the interface:
// only the types of this package implement it.
type RData interface {
	Type() Type
	// String gives the presentation form, as dig prints it with +nosplit.
	String() string
	appendData(b []byte) []byte
}

type Record struct {
	Name  Name
	Class Class
	TTL   uint32
	Data  RData
}

func (r Record) Type() Type { return r.Data.Type() }

func (r Record) String() string {
	return fmt.Sprintf("%s\t%d\t%s\t%s\t%s", r.Name, r.TTL, r.Class, r.Type(), r.Data)
}

// A holds an IPv4 address.
type A struct{ Addr netip.Addr }

// AAAA holds an IPv6 address; an IPv4-mapped address stays in its IPv6 form.
type AAAA struct{ Addr netip.Addr }

type NS struct{ Host Name }

type CNAME struct{ Target Name }

type DNAME struct{ Target Name }

type PTR struct{ Target Name }

type SOA struct {
	MName, RName                            Name
	Serial, Refresh, Retry, Expire, Minimum uint32
}

type MX struct {
	Preference uint16
	Exchange   Name
}

// TXT holds at least one string of raw octets, each at most 255 octets long.
type TXT struct{ Strings []string }

// SPF has the form of TXT (RFC 7208 section 3.1).
type SPF struct{ Strings []string }

// CAA holds a tag of 1 to 255 ASCII letters and digits, and a value of raw octets.
type CAA struct {
	Flags      uint8
	Tag, Value string
}

// Unknown holds the data of every type that has no typed form here.
type Unknown struct {
	TypeCode Type
	Data     []byte
}

func (A) Type() Type         { return TypeA }
func (AAAA) Type() Type      { return TypeAAAA }
func (NS) Type() Type        { return TypeNS }
func (CNAME) Type() Type     { return TypeCNAME }
func (DNAME) Type() Type     { return TypeDNAME }
func (PTR) Type() Type       { return TypePTR }
func (SOA) Type() Type       { return TypeSOA }
func (MX) Type() Type        { return TypeMX }
func (TXT) Type() Type       { return TypeTXT }
func (SPF) Type() Type       { return TypeSPF }
func (CAA) Type() Type       { return TypeCAA }
func (d Unknown) Type() Type { return d.TypeCode }

func (d A) String() string     { return d.Addr.String() }
func (d AAAA) String() string  { return d.Addr.String() }
func (d NS) String() string    { return d.Host.String() }
func (d CNAME) String() string { return d.Target.String() }
func (d DNAME) String() string { return d.Target.String() }
func (d PTR) String() string   { return d.Target.String() }
func (d SPF) String() string   { return TXT(d).String() }

func (d SOA) String() string {
	return fmt.Sprintf("%s %s %d %d %d %d %d", d.MName, d.RName, d.Serial, d.Refresh, d.Retry, d.Expire, d.Minimum)
}

func (d MX) String() string { return fmt.Sprintf("%d %s", d.Preference, d.Exchange) }

func (d TXT) String() string {
	var b []byte
	for i, s := range d.Strings {
		if i > 0 {
			b = append(b, ' ')
		}
		b = appendQuoted(b, s)
	}
	return string(b)
}

func (d CAA) String() string {
	return fmt.Sprintf("%d %s %s", d.Flags, d.Tag, appendQuoted(nil, d.Value))
}

// String gives the generic form of RFC 3597.
func (d Unknown) String() string {
	if len(d.Data) == 0 {
		return `\# 0`
	}
	return fmt.Sprintf(`\# %d %s`, len(d.Data), upperHex(d.Data))
}

// appendQuoted writes s in double quotes the way dig does: quote and
// backslash escaped, octets outside printable ASCII as \DDD.
func appendQuoted(b []byte, s string) []byte {
	b = append(b, '"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"' || c == '\\':
			b = append(b, '\\', c)
		case c < 0x20 || c > 0x7e:
			b = append(b, '\\', '0'+c/100, '0'+c/10%10, '0'+c%10)
		default:
			b = append(b, c)
		}
	}
	return append(b, '"')
}

// AsSlice, because As4 panics on the zero Addr and on IPv6; such data then
// has the wrong length, which a reader rejects.
func (d A) appendData(b []byte) []byte { return append(b, d.Addr.AsSlice()...) }

func (d AAAA) appendData(b []byte) []byte {
	a := d.Addr.As16()
	return append(b, a[:]...)
}

func (d NS) appendData(b []byte) []byte    { return d.Host.AppendWire(b) }
func (d CNAME) appendData(b []byte) []byte { return d.Target.AppendWire(b) }
func (d DNAME) appendData(b []byte) []byte { return d.Target.AppendWire(b) }
func (d PTR) appendData(b []byte) []byte   { return d.Target.AppendWire(b) }
func (d SPF) appendData(b []byte) []byte   { return TXT(d).appendData(b) }

func (d SOA) appendData(b []byte) []byte {
	b = d.RName.AppendWire(d.MName.AppendWire(b))
	for _, v := range []uint32{d.Serial, d.Refresh, d.Retry, d.Expire, d.Minimum} {
		b = binary.BigEndian.AppendUint32(b, v)
	}
	return b
}

func (d MX) appendData(b []byte) []byte {
	return d.Exchange.AppendWire(binary.BigEndian.AppendUint16(b, d.Preference))
}

func (d TXT) appendData(b []byte) []byte {
	for _, s := range d.Strings {
		b = append(b, byte(len(s)))
		b = append(b, s...)
	}
	return b
}

func (d CAA) appendData(b []byte) []byte {
	b = append(b, d.Flags, byte(len(d.Tag)))
	b = append(b, d.Tag...)
	return append(b, d.Value...)
}

func (d Unknown) appendData(b []byte) []byte { return append(b, d.Data...) }

// rdataDecoders read the data of each typed type from b[off:], where b ends
// with the data. A type without an entry is read as Unknown.
var rdataDecoders = map[Type]func(b []byte, off int) (RData, error){
	TypeA:          decodeA,
	TypeAAAA:       decodeAAAA,
	TypeNS:         decodeNS,
	TypeCNAME:      decodeCNAME,
	TypeDNAME:      decodeDNAME,
	TypePTR:        decodePTR,
	TypeSOA:        decodeSOA,
	TypeMX:         decodeMX,
	TypeTXT:        decodeTXT,
	TypeSPF:        decodeSPF,
	TypeCAA:        decodeCAA,
	TypeDS:         decodeDS,
	TypeDNSKEY:     decodeDNSKEY,
	TypeRRSIG:      decodeRRSIG,
	TypeNSEC:       decodeNSEC,
	TypeNSEC3:      decodeNSEC3,
	TypeNSEC3PARAM: decodeNSEC3PARAM,
}

// Fields of record data in unknownNames: a positive number is that many
// octets of fixed fields.
const (
	fieldName = -1 // a domain name
	fieldText = -2 // a character-string: a length octet, then the octets
)

// unknownNames holds the layout of the data of the types that RFC 4034
// section 6.2 item 3 lists and that have no typed form here. A validator
// needs their names lowercased to check the signature of such a set. A
// sender may compress these names (RFC 3597 section 4), so they are read
// expanded: the data then holds no pointer into a message that is gone. The
// obsolete SIG, NXT and A6 of that list are left out.
var unknownNames = map[Type][]int{
	3:  {fieldName},                                     // MD
	4:  {fieldName},                                     // MF
	7:  {fieldName},                                     // MB
	8:  {fieldName},                                     // MG
	9:  {fieldName},                                     // MR
	14: {fieldName, fieldName},                          // MINFO
	17: {fieldName, fieldName},                          // RP
	18: {2, fieldName},                                  // AFSDB
	21: {2, fieldName},                                  // RT
	26: {2, fieldName, fieldName},                       // PX
	33: {6, fieldName},                                  // SRV
	35: {4, fieldText, fieldText, fieldText, fieldName}, // NAPTR
	36: {2, fieldName},                                  // KX
}

// expandNames returns the data in b[off:], where b ends with the data, with
// each name of layout uncompressed, and in lower case when lower is set.
// Names follow pointers back into b only when ptrOK. Data that does not fit
// the layout exactly is an error.
func expandNames(b []byte, off int, layout []int, ptrOK, lower bool) ([]byte, error) {
	// A name of two octets can expand to 255, so the data is built here, with
	// room for the two names of PX after its preference, and copied once at
	// its final length.
	var buf [2 + 2*maxNameLen]byte
	out := buf[:0]
	for _, field := range layout {
		if field == fieldName {
			start := len(out)
			var err error
			if out, off, err = appendName(out, b, off, ptrOK); err != nil {
				return nil, err
			}
			if lower {
				// Length octets are below 'A', so they stay as they are.
				for i, c := range out[start:] {
					out[start+i] = lowerByte(c)
				}
			}
			continue
		}
		start := off
		switch {
		case field > 0:
			off += field
		case off < len(b): // fieldText
			off += 1 + int(b[off])
		default:
			return nil, errors.New("data ends before a character-string")
		}
		if off > len(b) {
			return nil, errors.New("data ends inside a field")
		}
		out = append(out, b[start:off]...)
	}
	if off != len(b) {
		return nil, fmt.Errorf("%d octets after the last name", len(b)-off)
	}
	return copyOctets(out), nil
}

// decodeRData reads the data of type t in msg[off:end]. The whole message is
// passed so that names can follow pointers back into it.
func decodeRData(t Type, msg []byte, off, end int) (RData, error) {
	if off < 0 || off > end || end > len(msg) {
		return nil, fmt.Errorf("%w: %s data from offset %d to %d lies outside the message", ErrMalformed, t, off, end)
	}
	decode, ok := rdataDecoders[t]
	layout, hasNames := unknownNames[t]
	switch {
	case ok:
	case hasNames:
		decode = func(b []byte, off int) (RData, error) {
			data, err := expandNames(b, off, layout, true, false)
			return Unknown{TypeCode: t, Data: data}, err
		}
	default:
		return Unknown{TypeCode: t, Data: copyOctets(msg[off:end])}, nil
	}
	// A pointer always points before itself, so cutting the message at end
	// keeps every valid target and stops a name from running past its data.
	d, err := decode(msg[:end], off)
	if err != nil {
		return nil, malformed(fmt.Sprintf("%s data at offset %d", t, off), err)
	}
	return d, nil
}

// copyOctets gives nil for no data, so decoded and parsed values compare equal.
func copyOctets(b []byte) []byte { return append([]byte(nil), b...) }

func decodeA(b []byte, off int) (RData, error) {
	if len(b)-off != 4 {
		return nil, fmt.Errorf("%d octets, want 4", len(b)-off)
	}
	return A{Addr: netip.AddrFrom4([4]byte(b[off:]))}, nil
}

func decodeAAAA(b []byte, off int) (RData, error) {
	if len(b)-off != 16 {
		return nil, fmt.Errorf("%d octets, want 16", len(b)-off)
	}
	return AAAA{Addr: netip.AddrFrom16([16]byte(b[off:]))}, nil
}

// readLastName reads a name that must end the data.
func readLastName(b []byte, off int, ptrOK bool) (Name, error) {
	n, next, err := readName(b, off, ptrOK)
	if err == nil && next != len(b) {
		err = fmt.Errorf("%d octets after the name", len(b)-next)
	}
	return n, err
}

func decodeNS(b []byte, off int) (RData, error) {
	n, err := readLastName(b, off, true)
	if err != nil {
		return nil, err
	}
	return NS{Host: n}, nil
}

func decodeCNAME(b []byte, off int) (RData, error) {
	n, err := readLastName(b, off, true)
	if err != nil {
		return nil, err
	}
	return CNAME{Target: n}, nil
}

// decodeDNAME accepts a compressed target, although RFC 6672 section 2.5
// forbids senders to compress it.
func decodeDNAME(b []byte, off int) (RData, error) {
	n, err := readLastName(b, off, true)
	if err != nil {
		return nil, err
	}
	return DNAME{Target: n}, nil
}

func decodePTR(b []byte, off int) (RData, error) {
	n, err := readLastName(b, off, true)
	if err != nil {
		return nil, err
	}
	return PTR{Target: n}, nil
}

func decodeSOA(b []byte, off int) (RData, error) {
	mname, off, err := readName(b, off, true)
	if err != nil {
		return nil, err
	}
	rname, off, err := readName(b, off, true)
	if err != nil {
		return nil, err
	}
	if len(b)-off != 20 {
		return nil, fmt.Errorf("%d octets after the names, want 20", len(b)-off)
	}
	v := b[off:]
	return SOA{
		MName:   mname,
		RName:   rname,
		Serial:  binary.BigEndian.Uint32(v[0:]),
		Refresh: binary.BigEndian.Uint32(v[4:]),
		Retry:   binary.BigEndian.Uint32(v[8:]),
		Expire:  binary.BigEndian.Uint32(v[12:]),
		Minimum: binary.BigEndian.Uint32(v[16:]),
	}, nil
}

func decodeMX(b []byte, off int) (RData, error) {
	if len(b)-off < 2 {
		return nil, errors.New("no room for the preference")
	}
	n, err := readLastName(b, off+2, true)
	if err != nil {
		return nil, err
	}
	return MX{Preference: binary.BigEndian.Uint16(b[off:]), Exchange: n}, nil
}

func decodeTXT(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) == 0 {
		return nil, errors.New("no string")
	}
	// Count first, so that data of many empty strings costs one allocation.
	count, i := 0, 0
	for ; i < len(v); i += 1 + int(v[i]) {
		count++
	}
	if i != len(v) {
		return nil, fmt.Errorf("string %d runs past the data", count)
	}
	strs := make([]string, 0, count)
	for i := 0; i < len(v); i += 1 + int(v[i]) {
		strs = append(strs, string(v[i+1:i+1+int(v[i])]))
	}
	return TXT{Strings: strs}, nil
}

func decodeSPF(b []byte, off int) (RData, error) {
	d, err := decodeTXT(b, off)
	if err != nil {
		return nil, err
	}
	return SPF(d.(TXT)), nil
}

func decodeCAA(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 2 || len(v)-2 < int(v[1]) {
		return nil, errors.New("data ends inside the tag")
	}
	tag := string(v[2 : 2+int(v[1])])
	if err := checkCAATag(tag); err != nil {
		return nil, err
	}
	return CAA{Flags: v[0], Tag: tag, Value: string(v[2+int(v[1]):])}, nil
}

func checkCAATag(tag string) error {
	if len(tag) < 1 || len(tag) > 255 {
		return fmt.Errorf("CAA tag of %d octets, want 1 to 255", len(tag))
	}
	for i := 0; i < len(tag); i++ {
		c := tag[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') {
			return fmt.Errorf("CAA tag octet %d is not an ASCII letter or digit", i+1)
		}
	}
	return nil
}

// rdataParsers read the presentation form of each typed type.
var rdataParsers = map[Type]func(r *fieldReader) (RData, error){
	TypeA:          parseA,
	TypeAAAA:       parseAAAA,
	TypeNS:         func(r *fieldReader) (RData, error) { return NS{Host: r.name()}, r.done() },
	TypeCNAME:      func(r *fieldReader) (RData, error) { return CNAME{Target: r.name()}, r.done() },
	TypeDNAME:      func(r *fieldReader) (RData, error) { return DNAME{Target: r.name()}, r.done() },
	TypePTR:        func(r *fieldReader) (RData, error) { return PTR{Target: r.name()}, r.done() },
	TypeSOA:        parseSOA,
	TypeMX:         func(r *fieldReader) (RData, error) { return MX{Preference: r.uint16(), Exchange: r.name()}, r.done() },
	TypeTXT:        parseTXT,
	TypeSPF:        parseSPF,
	TypeCAA:        parseCAA,
	TypeDS:         parseDS,
	TypeDNSKEY:     parseDNSKEY,
	TypeRRSIG:      parseRRSIG,
	TypeNSEC:       parseNSEC,
	TypeNSEC3:      parseNSEC3,
	TypeNSEC3PARAM: parseNSEC3PARAM,
}

// ParseRData reads record data of type t in the form that its String method
// prints. A type without a typed form takes the generic form of RFC 3597,
// \# <length> <hex>. Hex and base64 at the end of the data may come in
// several fields, as in zone files.
func ParseRData(t Type, s string) (RData, error) {
	d, err := parseRData(t, s)
	if err != nil {
		return nil, malformed(fmt.Sprintf("%s data %q", t, s), err)
	}
	return d, nil
}

func parseRData(t Type, s string) (RData, error) {
	fields, err := splitDataFields(s)
	if err != nil {
		return nil, err
	}
	r := &fieldReader{fields: fields}
	parse, ok := rdataParsers[t]
	if !ok {
		return parseUnknown(t, r)
	}
	d, err := parse(r)
	if err != nil {
		return nil, err
	}
	if n := len(d.appendData(nil)); n > 0xffff {
		return nil, fmt.Errorf("%d octets of data, more than a record holds", n)
	}
	return d, nil
}

func parseA(r *fieldReader) (RData, error) {
	addr := r.addr()
	if err := r.done(); err != nil {
		return nil, err
	}
	if !addr.Is4() {
		return nil, errors.New("not an IPv4 address")
	}
	return A{Addr: addr}, nil
}

func parseAAAA(r *fieldReader) (RData, error) {
	addr := r.addr()
	if err := r.done(); err != nil {
		return nil, err
	}
	if !addr.Is6() || addr.Zone() != "" {
		return nil, errors.New("not an IPv6 address without a zone")
	}
	return AAAA{Addr: addr}, nil
}

func parseSOA(r *fieldReader) (RData, error) {
	return SOA{
		MName:   r.name(),
		RName:   r.name(),
		Serial:  r.uint32(),
		Refresh: r.uint32(),
		Retry:   r.uint32(),
		Expire:  r.uint32(),
		Minimum: r.uint32(),
	}, r.done()
}

func parseTXT(r *fieldReader) (RData, error) {
	if len(r.fields) == 0 {
		return nil, errors.New("no string")
	}
	strs := make([]string, len(r.fields))
	for i := range strs {
		strs[i] = r.quoted()
		if len(strs[i]) > 255 {
			r.fail(fmt.Errorf("string %d is longer than 255 octets", i+1))
		}
	}
	return TXT{Strings: strs}, r.done()
}

func parseSPF(r *fieldReader) (RData, error) {
	d, err := parseTXT(r)
	if err != nil {
		return nil, err
	}
	return SPF(d.(TXT)), nil
}

func parseCAA(r *fieldReader) (RData, error) {
	d := CAA{Flags: r.uint8(), Tag: r.next(), Value: r.quoted()}
	if err := r.done(); err != nil {
		return nil, err
	}
	return d, checkCAATag(d.Tag)
}

func parseUnknown(t Type, r *fieldReader) (RData, error) {
	if r.next() != `\#` {
		r.fail(errors.New(`want the generic form \# <length> <hex>`))
	}
	n := r.uint16()
	d := Unknown{TypeCode: t, Data: r.hex()}
	if err := r.done(); err != nil {
		return nil, err
	}
	if len(d.Data) != int(n) {
		return nil, fmt.Errorf("length %d, but %d octets of data", n, len(d.Data))
	}
	// Such data must hold its names in full, as Parse leaves it.
	if layout, ok := unknownNames[t]; ok {
		if _, err := expandNames(d.Data, 0, layout, false, false); err != nil {
			return nil, err
		}
	}
	return d, nil
}

// splitDataFields splits presentation text at blanks outside double quotes.
// A backslash keeps the next character, blank or quote, inside the field.
func splitDataFields(s string) ([]string, error) {
	var fields []string
	start, quoted := -1, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c == ' ' || c == '\t') && !quoted {
			if start >= 0 {
				fields = append(fields, s[start:i])
				start = -1
			}
			continue
		}
		if start < 0 {
			start = i
		}
		switch c {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		}
	}
	if quoted {
		return nil, errors.New("a quoted string has no end")
	}
	if start >= 0 {
		fields = append(fields, s[start:])
	}
	return fields, nil
}

// fieldReader hands out the fields of presentation text in order. The first
// error sticks, so that a parser checks once, at the end, with done.
type fieldReader struct {
	fields []string
	err    error
}

func (r *fieldReader) fail(err error) {
	if r.err == nil {
		r.err = err
	}
}

// done gives the first error, or an error when fields are left.
func (r *fieldReader) done() error {
	if len(r.fields) > 0 {
		r.fail(fmt.Errorf("%d fields too many", len(r.fields)))
	}
	return r.err
}

func (r *fieldReader) next() string {
	if r.err != nil {
		return ""
	}
	if len(r.fields) == 0 {
		r.fail(errors.New("too few fields"))
		return ""
	}
	s := r.fields[0]
	r.fields = r.fields[1:]
	return s
}

// rest gives the fields left, joined.
func (r *fieldReader) rest() string {
	s := strings.Join(r.fields, "")
	r.fields = nil
	return s
}

func (r *fieldReader) number(bits int) uint64 {
	s := r.next()
	if r.err != nil {
		return 0
	}
	n, err := strconv.ParseUint(s, 10, bits)
	r.fail(err)
	return n
}

func (r *fieldReader) uint8() uint8   { return uint8(r.number(8)) }
func (r *fieldReader) uint16() uint16 { return uint16(r.number(16)) }
func (r *fieldReader) uint32() uint32 { return uint32(r.number(32)) }

func (r *fieldReader) name() Name {
	s := r.next()
	if r.err != nil {
		return Name{}
	}
	n, err := ParseName(s)
	r.fail(err)
	return n
}

func (r *fieldReader) addr() netip.Addr {
	s := r.next()
	if r.err != nil {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	r.fail(err)
	return a
}

// quoted reads a field in double quotes, with the escapes \X and \DDD.
func (r *fieldReader) quoted() string {
	s := r.next()
	if r.err != nil {
		return ""
	}
	if len(s) < 2 || s[0] != '"' || s[len(s)-1] != '"' {
		r.fail(errors.New("want a string in double quotes"))
		return ""
	}
	s = s[1 : len(s)-1]
	b := make([]byte, 0, len(s))
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '"':
			r.fail(errors.New("unescaped quote inside a string"))
			return ""
		case '\\':
			octet, n, ok := readEscape(s[i+1:])
			if !ok {
				r.fail(fmt.Errorf("bad escape at index %d of the string", i))
				return ""
			}
			b = append(b, octet)
			i += n
		default:
			b = append(b, s[i])
		}
	}
	return string(b)
}

// hex reads the fields left as one hex string.
func (r *fieldReader) hex() []byte {
	s := r.rest()
	if r.err != nil {
		return nil
	}
	b, err := hex.DecodeString(s)
	r.fail(err)
	if len(b) == 0 {
		return nil
	}
	return b
}

func upperHex(b []byte) string { return strings.ToUpper(hex.EncodeToString(b)) }
