package dnswire

import (
	"encoding/binary"
	"fmt"
)

// udpSize is the payload size every query offers: it keeps a UDP answer
// below common path MTUs, so a large answer comes truncated, not fragmented.
const udpSize = 1232

// Query is a question to send. Its class is always IN.
type Query struct {
	Name             Name
	Type             Type
	RecursionDesired bool
	CheckingDisabled bool
	DNSSECOK         bool
	Cookie           []byte // nil, 8 octets, or 16 to 40 octets
	IXFRSerial       uint32 // only with TypeIXFR: the serial the caller holds
}

// Pack returns the query as a message with the given ID: QR 0, opcode
// QUERY, one question, an OPT record, and for IXFR the SOA of the serial
// held in the authority section. It never compresses names.
func (q Query) Pack(id uint16) ([]byte, error) {
	if q.Type == TypeOPT || q.Type == TypeTSIG {
		return nil, fmt.Errorf("%w: type %v", ErrInvalidQuery, q.Type)
	}
	if q.IXFRSerial != 0 && q.Type != TypeIXFR {
		return nil, fmt.Errorf("%w: a serial with type %v", ErrInvalidQuery, q.Type)
	}
	if len(q.Cookie) != 0 && !validCookieLen(len(q.Cookie)) {
		return nil, fmt.Errorf("%w: cookie of %d octets", ErrInvalidQuery, len(q.Cookie))
	}
	var flags, nscount uint16
	if q.RecursionDesired {
		flags |= flagRD
	}
	if q.CheckingDisabled {
		flags |= flagCD
	}
	if q.Type == TypeIXFR {
		nscount = 1
	}
	be := binary.BigEndian
	b := make([]byte, 0, 512)
	b = be.AppendUint16(b, id)
	b = be.AppendUint16(b, flags)
	b = be.AppendUint16(b, 1) // questions
	b = be.AppendUint16(b, 0) // answers
	b = be.AppendUint16(b, nscount)
	b = be.AppendUint16(b, 1) // additional: the OPT record

	b = q.Name.AppendWire(b)
	b = be.AppendUint16(b, uint16(q.Type))
	b = be.AppendUint16(b, uint16(ClassINET))

	if q.Type == TypeIXFR {
		b = q.Name.AppendWire(b)
		b = be.AppendUint16(b, uint16(TypeSOA))
		b = be.AppendUint16(b, uint16(ClassINET))
		b = be.AppendUint32(b, 0)  // TTL
		b = be.AppendUint16(b, 22) // two root names and five 32-bit fields
		b = append(b, 0, 0)        // MNAME and RNAME
		b = be.AppendUint32(b, q.IXFRSerial)
		b = append(b, make([]byte, 16)...) // refresh, retry, expire, minimum
	}

	var ttl uint32
	if q.DNSSECOK {
		ttl = flagDO
	}
	b = append(b, 0) // the root owns the OPT record
	b = be.AppendUint16(b, uint16(TypeOPT))
	b = be.AppendUint16(b, udpSize)
	b = be.AppendUint32(b, ttl)
	if len(q.Cookie) == 0 {
		return be.AppendUint16(b, 0), nil
	}
	b = be.AppendUint16(b, uint16(4+len(q.Cookie)))
	b = be.AppendUint16(b, optionCookie)
	b = be.AppendUint16(b, uint16(len(q.Cookie)))
	return append(b, q.Cookie...), nil
}
