package dnswire

import (
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"math/bits"
	"slices"
	"strings"
	"time"
)

type DS struct {
	KeyTag                uint16
	Algorithm, DigestType uint8
	Digest                []byte
}

type DNSKEY struct {
	Flags               uint16
	Protocol, Algorithm uint8
	PublicKey           []byte
}

// RRSIG times are seconds since 1970 as unsigned 32-bit numbers, read
// without the serial arithmetic of RFC 4034 section 3.1.5.
type RRSIG struct {
	TypeCovered                        Type
	Algorithm, Labels                  uint8
	OriginalTTL, Expiration, Inception uint32
	KeyTag                             uint16
	SignerName                         Name
	Signature                          []byte
}

// NSEC lists its types in ascending order, without duplicates.
type NSEC struct {
	NextName Name
	Types    []Type
}

// NSEC3 lists its types in ascending order, without duplicates.
type NSEC3 struct {
	HashAlgorithm, Flags uint8
	Iterations           uint16
	Salt, NextHashed     []byte
	Types                []Type
}

type NSEC3PARAM struct {
	HashAlgorithm, Flags uint8
	Iterations           uint16
	Salt                 []byte
}

func (DS) Type() Type         { return TypeDS }
func (DNSKEY) Type() Type     { return TypeDNSKEY }
func (RRSIG) Type() Type      { return TypeRRSIG }
func (NSEC) Type() Type       { return TypeNSEC }
func (NSEC3) Type() Type      { return TypeNSEC3 }
func (NSEC3PARAM) Type() Type { return TypeNSEC3PARAM }

// nsec3HashEncoding is the form of NSEC3 hashes, RFC 5155 section 3.3.
var nsec3HashEncoding = base32.HexEncoding.WithPadding(base32.NoPadding)

const sigTimeLayout = "20060102150405"

func (d DS) String() string {
	return fmt.Sprintf("%d %d %d %s", d.KeyTag, d.Algorithm, d.DigestType, upperHex(d.Digest))
}

func (d DNSKEY) String() string {
	return fmt.Sprintf("%d %d %d %s", d.Flags, d.Protocol, d.Algorithm, base64.StdEncoding.EncodeToString(d.PublicKey))
}

func (d RRSIG) String() string {
	return fmt.Sprintf("%s %d %d %d %s %s %d %s %s", d.TypeCovered, d.Algorithm, d.Labels, d.OriginalTTL,
		formatSigTime(d.Expiration), formatSigTime(d.Inception), d.KeyTag, d.SignerName,
		base64.StdEncoding.EncodeToString(d.Signature))
}

func formatSigTime(t uint32) string { return time.Unix(int64(t), 0).UTC().Format(sigTimeLayout) }

func (d NSEC) String() string { return d.NextName.String() + typeList(d.Types) }

func (d NSEC3) String() string {
	return fmt.Sprintf("%d %d %d %s %s", d.HashAlgorithm, d.Flags, d.Iterations, saltText(d.Salt),
		nsec3HashEncoding.EncodeToString(d.NextHashed)) + typeList(d.Types)
}

func (d NSEC3PARAM) String() string {
	return fmt.Sprintf("%d %d %d %s", d.HashAlgorithm, d.Flags, d.Iterations, saltText(d.Salt))
}

func saltText(salt []byte) string {
	if len(salt) == 0 {
		return "-"
	}
	return upperHex(salt)
}

// typeList gives each type with a space before it.
func typeList(types []Type) string {
	var b []byte
	for _, t := range types {
		b = append(b, ' ')
		b = append(b, t.String()...)
	}
	return string(b)
}

func (d DS) appendData(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, d.KeyTag)
	b = append(b, d.Algorithm, d.DigestType)
	return append(b, d.Digest...)
}

func (d DNSKEY) appendData(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, d.Flags)
	b = append(b, d.Protocol, d.Algorithm)
	return append(b, d.PublicKey...)
}

func (d RRSIG) appendData(b []byte) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(d.TypeCovered))
	b = append(b, d.Algorithm, d.Labels)
	b = binary.BigEndian.AppendUint32(b, d.OriginalTTL)
	b = binary.BigEndian.AppendUint32(b, d.Expiration)
	b = binary.BigEndian.AppendUint32(b, d.Inception)
	b = binary.BigEndian.AppendUint16(b, d.KeyTag)
	b = d.SignerName.AppendWire(b)
	return append(b, d.Signature...)
}

func (d NSEC) appendData(b []byte) []byte {
	return appendTypeBitmap(d.NextName.AppendWire(b), d.Types)
}

func (d NSEC3) appendData(b []byte) []byte {
	b = append(b, d.HashAlgorithm, d.Flags)
	b = binary.BigEndian.AppendUint16(b, d.Iterations)
	b = append(b, byte(len(d.Salt)))
	b = append(b, d.Salt...)
	b = append(b, byte(len(d.NextHashed)))
	b = append(b, d.NextHashed...)
	return appendTypeBitmap(b, d.Types)
}

func (d NSEC3PARAM) appendData(b []byte) []byte {
	b = append(b, d.HashAlgorithm, d.Flags)
	b = binary.BigEndian.AppendUint16(b, d.Iterations)
	b = append(b, byte(len(d.Salt)))
	return append(b, d.Salt...)
}

// appendTypeBitmap writes the type bitmap of RFC 4034 section 4.1.2: per
// window of 256 types, the window number, the length and the bits.
func appendTypeBitmap(b []byte, types []Type) []byte {
	sorted := slices.Clone(types)
	slices.Sort(sorted)
	sorted = slices.Compact(sorted)
	for i := 0; i < len(sorted); {
		window := sorted[i] >> 8
		var bitmap [32]byte
		length := 0
		for ; i < len(sorted) && sorted[i]>>8 == window; i++ {
			low := sorted[i] & 0xff
			bitmap[low/8] |= 0x80 >> (low % 8)
			length = int(low/8) + 1
		}
		b = append(b, byte(window), byte(length))
		b = append(b, bitmap[:length]...)
	}
	return b
}

// readTypeBitmap reads the type bitmap of RFC 4034 section 4.1.2.
func readTypeBitmap(v []byte) ([]Type, error) {
	if len(v) == 0 {
		return nil, nil
	}
	// Each type is one set bit, so the set bits of the whole field bound the
	// count, and the slice is allocated once.
	count := 0
	for _, o := range v {
		count += bits.OnesCount8(o)
	}
	types := make([]Type, 0, count)
	last := -1
	for len(v) > 0 {
		if len(v) < 2 {
			return nil, errors.New("type bitmap ends inside a window header")
		}
		window, length := int(v[0]), int(v[1])
		if window <= last {
			return nil, fmt.Errorf("type bitmap window %d after window %d", window, last)
		}
		if length < 1 || length > 32 || length > len(v)-2 {
			return nil, fmt.Errorf("type bitmap window %d has length %d", window, length)
		}
		if v[1+length] == 0 {
			return nil, fmt.Errorf("type bitmap window %d ends with a zero octet", window)
		}
		for i, o := range v[2 : 2+length] {
			for bit := 0; bit < 8; bit++ {
				if o&(0x80>>bit) != 0 {
					types = append(types, Type(window<<8|i<<3|bit))
				}
			}
		}
		last = window
		v = v[2+length:]
	}
	return types, nil
}

// The lengths that a DS digest type (RFC 4034, 4509 and 6605) and an NSEC3
// hash algorithm (RFC 5155) fix.
var (
	digestLengths    = map[uint8]int{1: 20, 2: 32, 4: 48}
	nsec3HashLengths = map[uint8]int{1: 20}
)

// checkLength checks a field that algorithm alg fixes in lengths; a field of
// an algorithm not in lengths must not be empty.
func checkLength(field string, b []byte, alg uint8, lengths map[uint8]int) error {
	if want, ok := lengths[alg]; len(b) == 0 || ok && len(b) != want {
		return fmt.Errorf("%s of %d octets with algorithm %d", field, len(b), alg)
	}
	return nil
}

func decodeDS(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 4 {
		return nil, fmt.Errorf("%d octets, want at least 4", len(v))
	}
	if err := checkLength("digest", v[4:], v[3], digestLengths); err != nil {
		return nil, err
	}
	return DS{
		KeyTag:     binary.BigEndian.Uint16(v),
		Algorithm:  v[2],
		DigestType: v[3],
		Digest:     copyOctets(v[4:]),
	}, nil
}

func decodeDNSKEY(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 4 {
		return nil, fmt.Errorf("%d octets, want at least 4", len(v))
	}
	if err := checkLength("public key", v[4:], v[3], nil); err != nil {
		return nil, err
	}
	return DNSKEY{
		Flags:     binary.BigEndian.Uint16(v),
		Protocol:  v[2],
		Algorithm: v[3],
		PublicKey: copyOctets(v[4:]),
	}, nil
}

// decodeRRSIG reads the signer name without pointers: RFC 4034 section 3.1.7
// forbids compressing it.
func decodeRRSIG(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 18 {
		return nil, fmt.Errorf("%d octets, want at least 18 before the signer name", len(v))
	}
	signer, next, err := readName(b, off+18, false)
	if err != nil {
		return nil, err
	}
	if err := checkLength("signature", b[next:], v[2], nil); err != nil {
		return nil, err
	}
	return RRSIG{
		TypeCovered: Type(binary.BigEndian.Uint16(v)),
		Algorithm:   v[2],
		Labels:      v[3],
		OriginalTTL: binary.BigEndian.Uint32(v[4:]),
		Expiration:  binary.BigEndian.Uint32(v[8:]),
		Inception:   binary.BigEndian.Uint32(v[12:]),
		KeyTag:      binary.BigEndian.Uint16(v[16:]),
		SignerName:  signer,
		Signature:   copyOctets(b[next:]),
	}, nil
}

// decodeNSEC accepts a compressed next name, as dig does, although RFC 4034
// section 4.1.1 forbids senders to compress it.
func decodeNSEC(b []byte, off int) (RData, error) {
	next, end, err := readName(b, off, true)
	if err != nil {
		return nil, err
	}
	types, err := readTypeBitmap(b[end:])
	if err != nil {
		return nil, err
	}
	return NSEC{NextName: next, Types: types}, nil
}

func decodeNSEC3(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 5 || len(v) < 6+int(v[4]) {
		return nil, errors.New("data ends inside the salt")
	}
	salt := v[5 : 5+int(v[4])]
	rest := v[5+len(salt):]
	hashLen := int(rest[0])
	if len(rest) < 1+hashLen {
		return nil, errors.New("data ends inside the next hashed owner")
	}
	if err := checkLength("next hashed owner", rest[1:1+hashLen], v[0], nsec3HashLengths); err != nil {
		return nil, err
	}
	types, err := readTypeBitmap(rest[1+hashLen:])
	if err != nil {
		return nil, err
	}
	return NSEC3{
		HashAlgorithm: v[0],
		Flags:         v[1],
		Iterations:    binary.BigEndian.Uint16(v[2:]),
		Salt:          copyOctets(salt),
		NextHashed:    copyOctets(rest[1 : 1+hashLen]),
		Types:         types,
	}, nil
}

func decodeNSEC3PARAM(b []byte, off int) (RData, error) {
	v := b[off:]
	if len(v) < 5 || len(v) != 5+int(v[4]) {
		return nil, errors.New("data length does not match the salt length")
	}
	return NSEC3PARAM{
		HashAlgorithm: v[0],
		Flags:         v[1],
		Iterations:    binary.BigEndian.Uint16(v[2:]),
		Salt:          copyOctets(v[5:]),
	}, nil
}

func parseDS(r *fieldReader) (RData, error) {
	d := DS{KeyTag: r.uint16(), Algorithm: r.uint8(), DigestType: r.uint8(), Digest: r.hex()}
	r.fail(checkLength("digest", d.Digest, d.DigestType, digestLengths))
	return d, r.done()
}

func parseDNSKEY(r *fieldReader) (RData, error) {
	d := DNSKEY{Flags: r.uint16(), Protocol: r.uint8(), Algorithm: r.uint8(), PublicKey: r.base64()}
	r.fail(checkLength("public key", d.PublicKey, d.Algorithm, nil))
	return d, r.done()
}

func parseRRSIG(r *fieldReader) (RData, error) {
	d := RRSIG{
		TypeCovered: r.recordType(),
		Algorithm:   r.uint8(),
		Labels:      r.uint8(),
		OriginalTTL: r.uint32(),
		Expiration:  r.sigTime(),
		Inception:   r.sigTime(),
		KeyTag:      r.uint16(),
		SignerName:  r.name(),
		Signature:   r.base64(),
	}
	r.fail(checkLength("signature", d.Signature, d.Algorithm, nil))
	return d, r.done()
}

func parseNSEC(r *fieldReader) (RData, error) {
	return NSEC{NextName: r.name(), Types: r.types()}, r.done()
}

func parseNSEC3(r *fieldReader) (RData, error) {
	d := NSEC3{
		HashAlgorithm: r.uint8(),
		Flags:         r.uint8(),
		Iterations:    r.uint16(),
		Salt:          r.salt(),
		NextHashed:    r.base32Hex(),
		Types:         r.types(),
	}
	if len(d.NextHashed) > 255 {
		r.fail(fmt.Errorf("next hashed owner of %d octets, more than 255", len(d.NextHashed)))
	}
	r.fail(checkLength("next hashed owner", d.NextHashed, d.HashAlgorithm, nsec3HashLengths))
	return d, r.done()
}

func parseNSEC3PARAM(r *fieldReader) (RData, error) {
	d := NSEC3PARAM{HashAlgorithm: r.uint8(), Flags: r.uint8(), Iterations: r.uint16(), Salt: r.salt()}
	return d, r.done()
}

func (r *fieldReader) recordType() Type {
	s := r.next()
	if r.err != nil {
		return 0
	}
	t, err := ParseType(s)
	r.fail(err)
	return t
}

// types reads the fields left as types, sorted and without duplicates.
func (r *fieldReader) types() []Type {
	var types []Type
	for len(r.fields) > 0 && r.err == nil {
		types = append(types, r.recordType())
	}
	slices.Sort(types)
	return slices.Compact(types)
}

// sigTime reads a time in the form YYYYMMDDHHmmSS, UTC.
func (r *fieldReader) sigTime() uint32 {
	s := r.next()
	if r.err != nil {
		return 0
	}
	t, err := time.Parse(sigTimeLayout, s)
	switch {
	case err != nil:
		r.fail(err)
	case t.Format(sigTimeLayout) != s || t.Unix() < 0 || t.Unix() > math.MaxUint32:
		r.fail(fmt.Errorf("time %s is not between 19700101000000 and 21060207062815", s))
	}
	return uint32(t.Unix())
}

// base64 reads the fields left as one base64 string.
func (r *fieldReader) base64() []byte {
	s := r.rest()
	if r.err != nil {
		return nil
	}
	b, err := base64.StdEncoding.DecodeString(s)
	r.fail(err)
	if len(b) == 0 {
		return nil
	}
	return b
}

// base32Hex accepts lower case too, as some tools print hashes that way.
func (r *fieldReader) base32Hex() []byte {
	s := r.next()
	if r.err != nil {
		return nil
	}
	b, err := nsec3HashEncoding.DecodeString(strings.ToUpper(s))
	r.fail(err)
	return b
}

// salt reads "-" as no salt.
func (r *fieldReader) salt() []byte {
	s := r.next()
	if r.err != nil || s == "-" {
		return nil
	}
	b, err := hex.DecodeString(s)
	r.fail(err)
	if len(b) > 255 {
		r.fail(fmt.Errorf("salt of %d octets, more than 255", len(b)))
	}
	return b
}
