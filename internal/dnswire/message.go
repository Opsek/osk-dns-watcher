// Package dnswire reads and writes DNS messages. It builds queries only, and
// reads answers from servers it does not trust: every limit of a message is
// checked before the message is used, and memory follows the octets
// received, never the counts they claim.
package dnswire

import (
	"encoding/binary"
	"fmt"
)

const (
	headerLen      = 12
	maxMessageLen  = 65535
	minQuestionLen = 5  // the root name, type and class
	minRecordLen   = 11 // the root name, type, class, TTL and data length
)

const (
	flagQR = 1 << 15
	flagAA = 1 << 10
	flagTC = 1 << 9
	flagRD = 1 << 8
	flagRA = 1 << 7
	flagAD = 1 << 5
	flagCD = 1 << 4
)

// Header holds the header of a message, except the counts.
type Header struct {
	ID                 uint16
	Response           bool
	Opcode             Opcode
	Authoritative      bool
	Truncated          bool
	RecursionDesired   bool
	RecursionAvailable bool
	AuthenticData      bool
	CheckingDisabled   bool
	Rcode              Rcode
}

type Question struct {
	Name  Name
	Type  Type
	Class Class
}

type Message struct {
	Header
	Question                      []Question // 0 or 1
	Answer, Authority, Additional []Record   // Additional holds neither OPT nor TSIG
	EDNS                          *EDNS      // nil when the message has no OPT
	tsig                          *tsigRecord
}

// HasTSIG reports whether the message ends with a TSIG record. Only Transfer,
// with a key, checks its signature.
func (m *Message) HasTSIG() bool { return m.tsig != nil }

// rawRecord is a record whose data, msg[dataOff:end], is not decoded yet.
type rawRecord struct {
	name                Name
	typ                 Type
	class               Class
	ttl                 uint32
	start, dataOff, end int
}

// Parse reads a whole message. Any message that breaks a limit gives an
// error that wraps ErrMalformed, never a part of the message. The result
// shares no memory with b.
func Parse(b []byte) (*Message, error) {
	if len(b) < headerLen || len(b) > maxMessageLen {
		return nil, fmt.Errorf("%w: %d octets", ErrMalformed, len(b))
	}
	m := &Message{Header: readHeader(b)}
	qdcount := int(binary.BigEndian.Uint16(b[4:]))
	sections := []struct {
		name  string
		count int
		dst   *[]Record
	}{
		{"answer", int(binary.BigEndian.Uint16(b[6:])), &m.Answer},
		{"authority", int(binary.BigEndian.Uint16(b[8:])), &m.Authority},
		{"additional", int(binary.BigEndian.Uint16(b[10:])), &m.Additional},
	}
	if qdcount > 1 {
		return nil, fmt.Errorf("%w: %d questions", ErrMalformed, qdcount)
	}
	records := sections[0].count + sections[1].count + sections[2].count
	if qdcount*minQuestionLen+records*minRecordLen > len(b)-headerLen {
		return nil, fmt.Errorf("%w: %d questions and %d records cannot fit in %d octets",
			ErrMalformed, qdcount, records, len(b)-headerLen)
	}

	off := headerLen
	if qdcount == 1 {
		q, next, err := readQuestion(b, off)
		if err != nil {
			return nil, fmt.Errorf("question: %w", err)
		}
		m.Question = []Question{q}
		off = next
	}
	for _, s := range sections {
		for i := range s.count {
			r, err := readRecord(b, off)
			if err != nil {
				return nil, fmt.Errorf("%s record %d: %w", s.name, i, err)
			}
			off = r.end
			additional := s.dst == &m.Additional
			switch {
			case r.typ == TypeOPT:
				if !additional || m.EDNS != nil {
					return nil, fmt.Errorf("%w: %s record %d: OPT must be the only one, in the additional section",
						ErrMalformed, s.name, i)
				}
				if m.EDNS, err = readEDNS(b, r); err != nil {
					return nil, fmt.Errorf("%s record %d: %w", s.name, i, err)
				}
				m.Rcode |= Rcode(r.ttl>>24) << 4
			case r.typ == TypeTSIG:
				if !additional || i != s.count-1 {
					return nil, fmt.Errorf("%w: %s record %d: TSIG must be the last record of the additional section",
						ErrMalformed, s.name, i)
				}
				if m.tsig, err = readTSIG(b, r); err != nil {
					return nil, fmt.Errorf("%s record %d: %w", s.name, i, err)
				}
			default:
				data, err := decodeRData(r.typ, b, r.dataOff, r.end)
				if err != nil {
					return nil, fmt.Errorf("%s record %d: %w", s.name, i, err)
				}
				*s.dst = append(*s.dst, Record{Name: r.name, Class: r.class, TTL: r.ttl, Data: data})
			}
		}
	}
	if off != len(b) {
		return nil, fmt.Errorf("%w: %d octets after the last record", ErrMalformed, len(b)-off)
	}
	return m, nil
}

func readHeader(b []byte) Header {
	flags := binary.BigEndian.Uint16(b[2:])
	return Header{
		ID:                 binary.BigEndian.Uint16(b),
		Response:           flags&flagQR != 0,
		Opcode:             Opcode(flags >> 11 & 0xF),
		Authoritative:      flags&flagAA != 0,
		Truncated:          flags&flagTC != 0,
		RecursionDesired:   flags&flagRD != 0,
		RecursionAvailable: flags&flagRA != 0,
		AuthenticData:      flags&flagAD != 0,
		CheckingDisabled:   flags&flagCD != 0,
		Rcode:              Rcode(flags & 0xF),
	}
}

func readQuestion(msg []byte, off int) (Question, int, error) {
	name, next, err := readName(msg, off, true)
	if err != nil {
		return Question{}, 0, err
	}
	if next+4 > len(msg) {
		return Question{}, 0, fmt.Errorf("%w: question at offset %d runs past the end", ErrMalformed, off)
	}
	q := Question{
		Name:  name,
		Type:  Type(binary.BigEndian.Uint16(msg[next:])),
		Class: Class(binary.BigEndian.Uint16(msg[next+2:])),
	}
	return q, next + 4, nil
}

func readRecord(msg []byte, off int) (rawRecord, error) {
	name, next, err := readName(msg, off, true)
	if err != nil {
		return rawRecord{}, err
	}
	if next+10 > len(msg) {
		return rawRecord{}, fmt.Errorf("%w: record at offset %d runs past the end", ErrMalformed, off)
	}
	r := rawRecord{
		name:    name,
		typ:     Type(binary.BigEndian.Uint16(msg[next:])),
		class:   Class(binary.BigEndian.Uint16(msg[next+2:])),
		ttl:     binary.BigEndian.Uint32(msg[next+4:]),
		start:   off,
		dataOff: next + 10,
	}
	r.end = r.dataOff + int(binary.BigEndian.Uint16(msg[next+8:]))
	if r.end > len(msg) {
		return rawRecord{}, fmt.Errorf("%w: data of the record at offset %d runs past the end", ErrMalformed, off)
	}
	return r, nil
}
