package dnswire

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"time"
)

// TSIGKey is a shared key for TSIG (RFC 8945). The algorithm is always
// hmac-sha256.
type TSIGKey struct {
	Name   Name
	Secret []byte
}

const (
	// hmacSHA256 is the algorithm name in lowercased wire form, as Name.Key
	// returns it.
	hmacSHA256 = "\x0bhmac-sha256\x00"
	queryFudge = 300
	// maxUnsigned is the number of unsigned messages in a row that RFC 8945
	// §5.3.1 lets a server send between two signed ones.
	maxUnsigned = 99
)

// sign appends a TSIG record to msg, a query made by Query.Pack, and returns
// the signed message and its MAC.
func sign(msg []byte, key *TSIGKey, now time.Time) ([]byte, []byte) {
	signed := uint64(now.Unix())
	h := hmac.New(sha256.New, key.Secret)
	h.Write(msg)
	h.Write(appendVariables(nil, key.Name, signed, queryFudge, 0, nil))
	mac := h.Sum(nil)

	binary.BigEndian.PutUint16(msg[10:], binary.BigEndian.Uint16(msg[10:])+1)
	rdata := append([]byte(nil), hmacSHA256...)
	rdata = appendTimers(rdata, signed, queryFudge)
	rdata = binary.BigEndian.AppendUint16(rdata, uint16(len(mac)))
	rdata = append(rdata, mac...)
	rdata = append(rdata, msg[0], msg[1])           // original ID
	rdata = binary.BigEndian.AppendUint32(rdata, 0) // error and other length

	msg = key.Name.AppendWire(msg)
	msg = binary.BigEndian.AppendUint16(msg, uint16(TypeTSIG))
	msg = binary.BigEndian.AppendUint16(msg, uint16(ClassANY))
	msg = binary.BigEndian.AppendUint32(msg, 0) // TTL
	msg = binary.BigEndian.AppendUint16(msg, uint16(len(rdata)))
	return append(msg, rdata...), mac
}

// appendVariables appends the TSIG variables that a MAC covers (RFC 8945
// §4.3.3), with the names in canonical form.
func appendVariables(b []byte, name Name, signed uint64, fudge, rcode uint16, other []byte) []byte {
	b = append(b, name.Key()...)
	b = binary.BigEndian.AppendUint16(b, uint16(ClassANY))
	b = binary.BigEndian.AppendUint32(b, 0) // TTL
	b = append(b, hmacSHA256...)
	b = appendTimers(b, signed, fudge)
	b = binary.BigEndian.AppendUint16(b, rcode)
	b = binary.BigEndian.AppendUint16(b, uint16(len(other)))
	return append(b, other...)
}

// appendTimers appends the 48-bit time signed and the fudge.
func appendTimers(b []byte, signed uint64, fudge uint16) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(signed>>32))
	b = binary.BigEndian.AppendUint32(b, uint32(signed))
	return binary.BigEndian.AppendUint16(b, fudge)
}

// tsigRecord is a TSIG record read from an answer.
type tsigRecord struct {
	at              int // the offset of the record: the MAC covers the octets before it
	name, algorithm Name
	signed          uint64
	fudge           uint16
	mac             []byte
	originalID      uint16
	rcode           uint16
	other           []byte
}

// readTSIG reads the TSIG record r of msg. Its data may hold no compression
// pointer.
func readTSIG(msg []byte, r rawRecord) (*tsigRecord, error) {
	t := &tsigRecord{at: r.start, name: r.name}
	bad := func(off int) error { return fmt.Errorf("%w: TSIG data at offset %d does not fit", ErrMalformed, off) }
	msg = msg[:r.end]
	var off int
	var err error
	if t.algorithm, off, err = readName(msg, r.dataOff, false); err != nil {
		return nil, err
	}
	if len(msg)-off < 10 {
		return nil, bad(off)
	}
	t.signed = uint64(binary.BigEndian.Uint16(msg[off:]))<<32 | uint64(binary.BigEndian.Uint32(msg[off+2:]))
	t.fudge = binary.BigEndian.Uint16(msg[off+6:])
	macLen := int(binary.BigEndian.Uint16(msg[off+8:]))
	off += 10
	if len(msg)-off < macLen+6 {
		return nil, bad(off)
	}
	t.mac = copyOctets(msg[off : off+macLen])
	off += macLen
	t.originalID = binary.BigEndian.Uint16(msg[off:])
	t.rcode = binary.BigEndian.Uint16(msg[off+2:])
	otherLen := int(binary.BigEndian.Uint16(msg[off+4:]))
	off += 6
	if len(msg)-off != otherLen {
		return nil, bad(off)
	}
	t.other = copyOctets(msg[off:])
	return t, nil
}

// verifier checks the answers to a signed query, in order. It holds back the
// unsigned messages until a signed one covers them.
type verifier struct {
	key     *TSIGKey
	prior   []byte   // the MAC of the query, then of the last signed answer
	signed  bool     // an answer was signed already
	pending [][]byte // the unsigned answers since then, as received
}

// add takes the next answer and returns the messages that a checked
// signature now covers, in order; with a key, only the last of them is
// signed. Without a key every message is returned at once.
func (v *verifier) add(wire []byte, m *Message, now time.Time) ([]*Message, error) {
	if v.key == nil {
		return []*Message{m}, nil
	}
	if m.tsig == nil {
		if !v.signed {
			return nil, fmt.Errorf("%w: the first message is not signed", ErrTSIG)
		}
		if len(v.pending) == maxUnsigned {
			return nil, fmt.Errorf("%w: more than %d unsigned messages in a row", ErrTSIG, maxUnsigned)
		}
		v.pending = append(v.pending, wire)
		return nil, nil
	}
	if err := v.check(wire, m.tsig, now); err != nil {
		return nil, err
	}
	var out []*Message
	for _, p := range v.pending {
		pm, err := Parse(p)
		if err != nil {
			return nil, err
		}
		out = append(out, pm)
	}
	v.prior = m.tsig.mac
	v.signed = true
	v.pending = nil
	return append(out, m), nil
}

// check verifies the TSIG t of the message wire and of the unsigned messages
// before it. The first answer covers all TSIG variables, later ones only the
// timers (RFC 8945 §4.3.1 and §5.3.1).
func (v *verifier) check(wire []byte, t *tsigRecord, now time.Time) error {
	switch {
	case !t.name.Equal(v.key.Name):
		return fmt.Errorf("%w: key %v, want %v", ErrTSIG, t.name, v.key.Name)
	case t.algorithm.Key() != hmacSHA256:
		return fmt.Errorf("%w: algorithm %v", ErrTSIG, t.algorithm)
	case t.rcode != 0:
		return fmt.Errorf("%w: error %d in the TSIG record", ErrTSIG, t.rcode)
	case len(t.mac) != sha256.Size:
		return fmt.Errorf("%w: MAC of %d octets", ErrTSIG, len(t.mac))
	}
	h := hmac.New(sha256.New, v.key.Secret)
	h.Write(binary.BigEndian.AppendUint16(nil, uint16(len(v.prior))))
	h.Write(v.prior)
	for _, p := range v.pending {
		h.Write(p)
	}
	writeUnsigned(h, wire, t.at, t.originalID)
	if v.signed {
		h.Write(appendTimers(nil, t.signed, t.fudge))
	} else {
		h.Write(appendVariables(nil, t.name, t.signed, t.fudge, t.rcode, t.other))
	}
	if !hmac.Equal(h.Sum(nil), t.mac) {
		return fmt.Errorf("%w: wrong MAC", ErrTSIG)
	}
	// The time is checked after the MAC, so it is known to come from the key holder.
	if diff := now.Unix() - int64(t.signed); diff > int64(t.fudge) || -diff > int64(t.fudge) {
		return fmt.Errorf("%w: signed at %d, %d s from now, fudge %d", ErrTSIG, t.signed, diff, t.fudge)
	}
	return nil
}

// writeUnsigned writes the message as it was before the server added the
// TSIG record: without it, one record fewer in ARCOUNT, and the original ID.
func writeUnsigned(h hash.Hash, wire []byte, at int, originalID uint16) {
	var head [12]byte
	copy(head[:], wire)
	binary.BigEndian.PutUint16(head[0:], originalID)
	binary.BigEndian.PutUint16(head[10:], binary.BigEndian.Uint16(wire[10:])-1)
	h.Write(head[:])
	h.Write(wire[12:at])
}
