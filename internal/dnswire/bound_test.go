package dnswire

import (
	"bytes"
	"encoding/binary"
	"runtime"
	"testing"
)

// boundLongNameMessage returns an answer of 65535 octets: a record whose
// owner is a name of 255 octets, then as many copies of rec as fit, each of
// which points to that name. The data of the first record takes the octets
// left over.
func boundLongNameMessage(rec []byte) []byte {
	const size = 65535
	var name []byte
	for _, n := range []int{63, 63, 63, 61} {
		name = append(name, byte(n))
		name = append(name, bytes.Repeat([]byte{'x'}, n)...)
	}
	name = append(name, 0)
	head := 12 + len(name) + 10
	count := (size - head - 10) / len(rec)
	pad := size - head - count*len(rec)

	b := []byte{0, 0, 0x84, 0, 0, 0}
	b = binary.BigEndian.AppendUint16(b, uint16(1+count))
	b = append(b, 0, 0, 0, 0)
	b = append(b, name...)
	b = append(b, 0xFF, 0, 0, 1, 0, 0, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(pad))
	b = append(b, make([]byte, pad)...)
	for range count {
		b = append(b, rec...)
	}
	return b
}

// Names that pointers repeat must not cost more memory than the bound of
// one message: 64 times its length plus 64 KiB.
func TestParseMemoryBoundWithRepeatedLongNames(t *testing.T) {
	cases := []struct {
		name string
		rec  string // hex
	}{
		// MINFO: the owner and both names of the data point to the long name.
		{"MINFO", "C00C 000E 0001 00000000 0004 C00C C00C"},
		{"PTR", "C00C 000C 0001 00000000 0002 C00C"},
		// PX: a preference and two names, the longest data of a layout.
		{"PX", "C00C 001A 0001 00000000 0006 000A C00C C00C"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			msg := boundLongNameMessage(dataHex(t, c.rec))
			if len(msg) != 65535 {
				t.Fatalf("message of %d octets, want 65535", len(msg))
			}
			m, err := Parse(msg)
			if err != nil {
				t.Fatal(err)
			}
			if r := m.Answer[len(m.Answer)-1]; r.Name.LabelCount() != 4 {
				t.Fatalf("last record %v does not have the long name", r)
			}
			const runs = 5
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			for range runs {
				if _, err := Parse(msg); err != nil {
					t.Fatal(err)
				}
			}
			runtime.ReadMemStats(&after)
			used := (after.TotalAlloc - before.TotalAlloc) / runs
			t.Logf("Parse allocates %d octets, %.1f times the message", used, float64(used)/float64(len(msg)))
			if limit := uint64(64*len(msg) + 64<<10); used > limit {
				t.Errorf("Parse allocates %d octets; the bound is %d", used, limit)
			}
		})
	}
}
