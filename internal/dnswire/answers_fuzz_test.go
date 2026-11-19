package dnswire

import (
	"encoding/binary"
	"strings"
	"testing"
)

// Names that are the same but for ASCII case, and names that only look
// alike: an escaped dot inside a label, one label less or more, and 0xC0
// against 0xE0, which differ in Latin-1 case but not in ASCII case.
var answersFuzzNames = func() []Name {
	var names []Name
	for _, s := range []string{
		"www.corp.test.", "WWW.Corp.TEST.", `\087ww.corp.test.`, `www\.corp.test.`, "ww.corp.test.",
		"www.corp.test.example.", "corp.test.", ".", `\192.corp.test.`, `\224.corp.test.`,
	} {
		n, err := ParseName(s)
		if err != nil {
			panic(err)
		}
		names = append(names, n)
	}
	return names
}()

// 0x0201 and 0x0101 share their low octet with A and IN.
var answersFuzzTypes = []Type{TypeA, TypeAAAA, TypeNS, TypeMX, TypeCAA, 0, 0xFFFF, 0x0201}

var answersFuzzClasses = []Class{ClassINET, ClassCHAOS, ClassANY, 0, 0x0101}

// answersFuzzWire is a message with the ID, the flags and the questions, and
// nothing else.
func answersFuzzWire(id, flags uint16, questions ...Question) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, flags)
	b = binary.BigEndian.AppendUint16(b, uint16(len(questions)))
	b = append(b, 0, 0, 0, 0, 0, 0)
	for _, x := range questions {
		b = x.Name.AppendWire(b)
		b = binary.BigEndian.AppendUint16(b, uint16(x.Type))
		b = binary.BigEndian.AppendUint16(b, uint16(x.Class))
	}
	return b
}

// An input of FuzzAnswers is the sent query (ID, name and type octets), a
// later octet (a later message of a zone transfer), and a mode octet; then,
// with mode odd, the octets of the message received, read with Parse; with
// mode even, octets that change a message made to match the query: the ID,
// the flags, the opcode, whether it has a question, and its name, type and
// class.
func FuzzAnswers(f *testing.F) {
	in := func(name, typ int) Question {
		return Question{Name: answersFuzzNames[name], Type: answersFuzzTypes[typ], Class: ClassINET}
	}
	sent := []byte{0x12, 0x34, 0, 0, 0}
	for _, m := range [][]byte{
		answersFuzzWire(0x1234, 0x8400, in(0, 0)),
		answersFuzzWire(0x1234, 0x8000, in(1, 0)),
		answersFuzzWire(0x1234, 0x8000, in(2, 0)),
		answersFuzzWire(0x1234, 0x8000, in(3, 0)),
		answersFuzzWire(0x1235, 0x8000, in(0, 0)),
		answersFuzzWire(0x1234, 0x0400, in(0, 0)),
		answersFuzzWire(0x1234, 0x8000|4<<11, in(0, 0)),
		answersFuzzWire(0x1234, 0x8000|5<<11, in(0, 0)),
		answersFuzzWire(0x1234, 0x8000, in(0, 7)),
		answersFuzzWire(0x1234, 0x8000, Question{Name: answersFuzzNames[0], Type: TypeA, Class: 0x0101}),
		answersFuzzWire(0x1234, 0x8000, in(0, 0), in(0, 0)),
		answersFuzzWire(0x1234, 0x8000),
	} {
		f.Add(append(append(sent, 1), m...))
	}
	f.Add(append([]byte{0x12, 0x34, 0, 0, 1, 1}, answersFuzzWire(0x1234, 0x8000)...))
	f.Add(append([]byte{0x12, 0x34, 8, 0, 0, 1}, answersFuzzWire(0x1234, 0x8000, in(9, 0))...))
	f.Add(append(sent, 0))
	f.Add(append(sent, 0, 0, 0, 0, 3))
	f.Add(append(sent, 0, 0, 0, 0, 0, 1, 1, 1))
	f.Fuzz(func(t *testing.T, b []byte) {
		next := func() byte {
			if len(b) == 0 {
				return 0
			}
			c := b[0]
			b = b[1:]
			return c
		}
		id := uint16(next())<<8 | uint16(next())
		q := Query{
			Name: answersFuzzNames[int(next())%len(answersFuzzNames)],
			Type: answersFuzzTypes[int(next())%len(answersFuzzTypes)],
		}
		later := next()%2 == 1
		var m *Message
		if next()%2 == 1 {
			parsed, err := Parse(b)
			if err != nil {
				return
			}
			m = parsed
		} else {
			m = answersFuzzMessage(next, id, q)
		}

		got := answers(m, id, q, later)
		if again := answers(m, id, q, later); again != got {
			t.Fatalf("the same message read twice: %v, then %v", got, again)
		}
		want := m.ID == id && m.Response && m.Opcode == OpcodeQuery
		if len(m.Question) == 0 {
			want = want && later
		} else {
			// String escapes every octet outside printable ASCII, so EqualFold
			// can fold only ASCII case here.
			x := m.Question[0]
			want = want && len(m.Question) == 1 && x.Type == q.Type && x.Class == ClassINET &&
				strings.EqualFold(x.Name.String(), q.Name.String())
		}
		if got != want {
			t.Fatalf("answers(%+v, %#x, %v %v, later %v) = %v, want %v", m.Header, id, q.Name, q.Type, later, got, want)
		}
	})
}

// answersFuzzMessage makes a message that answers q, then changes what the
// octets of next say; octets of zero change nothing. Message holds at most
// one question, as Parse makes it.
func answersFuzzMessage(next func() byte, id uint16, q Query) *Message {
	x := next()
	flags := next()
	m := &Message{Header: Header{
		ID:            id ^ (uint16(x)<<8 | uint16(x)),
		Response:      flags&1 == 0,
		Authoritative: flags&2 != 0,
		Truncated:     flags&4 != 0,
		Rcode:         Rcode(flags >> 4),
		Opcode:        Opcode(next() % 16),
	}}
	if next()%4 == 3 {
		return m
	}
	question := Question{Name: q.Name, Type: q.Type, Class: ClassINET}
	if s := int(next()); s != 0 {
		question.Name = answersFuzzNames[s%len(answersFuzzNames)]
	}
	if s := int(next()); s != 0 {
		question.Type = answersFuzzTypes[s%len(answersFuzzTypes)]
	}
	if s := int(next()); s != 0 {
		question.Class = answersFuzzClasses[s%len(answersFuzzClasses)]
	}
	m.Question = []Question{question}
	return m
}
