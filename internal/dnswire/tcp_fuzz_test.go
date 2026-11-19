package dnswire

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"testing"
)

var errTCPFuzzReset = errors.New("connection reset by the test")

// tcpFuzzConn is a TCP connection to a server that sends the octets of in,
// at most chunk in one Read, and then ends with end: with end nil, it sends
// 0xFF octets without end. It never gives more than one message of the
// greatest length with its prefix, so a reader that takes more cannot run
// for ever.
type tcpFuzzConn struct {
	net.Conn // nil: readTCP only reads
	in       []byte
	chunk    int
	end      error
	endEarly bool // the last octets come together with end
	given    int
}

func (c *tcpFuzzConn) Read(p []byte) (int, error) {
	n := min(len(p), c.chunk, 2+maxMessageLen-c.given)
	switch {
	case n == 0 && len(p) > 0:
		return 0, errors.New("read past the longest message")
	case len(c.in) > 0:
		n = copy(p[:n], c.in)
		c.in = c.in[n:]
	case c.end != nil:
		return 0, c.end
	default:
		for i := range p[:n] {
			p[i] = 0xFF
		}
	}
	c.given += n
	if len(c.in) == 0 && c.endEarly {
		return n, c.end
	}
	return n, nil
}

// FuzzReadTCP reads one framed message from a hostile server: the stream
// in, given in chunks of 1 to 65536 octets, and then (how) the end of the
// stream, the end with the last octets, a reset, or octets without end.
func FuzzReadTCP(f *testing.F) {
	framed := []byte{0, 12, 0x12, 0x34, 0x84, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	f.Add([]byte(nil), uint8(0), uint8(0))
	f.Add([]byte{0}, uint8(0), uint8(0))              // one octet of the length
	f.Add([]byte{0, 0}, uint8(16), uint8(0))          // length 0
	f.Add([]byte{0, 0}, uint8(16), uint8(3))          // length 0, then more
	f.Add(framed, uint8(0), uint8(0))                 // one octet at a time
	f.Add(framed, uint8(16), uint8(1))                // the last octets come with the end
	f.Add(framed[:9], uint8(2), uint8(2))             // cut inside the message, then a reset
	f.Add(framed[:2], uint8(2), uint8(1))             // the length alone
	f.Add(append(framed, 0, 12), uint8(16), uint8(0)) // another message behind
	f.Add([]byte{0xFF, 0xFF}, uint8(16), uint8(3))    // the longest message, from a stream without end
	f.Add([]byte(nil), uint8(0), uint8(3))            // the same, one octet at a time
	f.Fuzz(func(t *testing.T, in []byte, chunk, how uint8) {
		c := &tcpFuzzConn{in: bytes.Clone(in), chunk: 1 << (chunk % 17)}
		switch how % 4 {
		case 0:
			c.end = io.EOF
		case 1:
			c.end, c.endEarly = io.EOF, true
		case 2:
			c.end = errTCPFuzzReset
		}
		stream := in
		if c.end == nil {
			stream = append(bytes.Clone(in), bytes.Repeat([]byte{0xFF}, 2+maxMessageLen)...)
		}

		b, err := readTCP(c)
		if len(stream) < 2 {
			if err == nil || c.given != len(stream) {
				t.Fatalf("a stream of %d octets: error %v, %d octets read", len(stream), err, c.given)
			}
			return
		}
		size := int(binary.BigEndian.Uint16(stream))
		switch {
		case size == 0:
			if !errors.Is(err, ErrMalformed) || c.given != 2 {
				t.Fatalf("length 0: error %v, %d octets read; want ErrMalformed after the 2 of the length", err, c.given)
			}
		case len(stream) < 2+size:
			if err == nil || c.given != len(stream) {
				t.Fatalf("length %d, cut after %d octets: error %v, %d octets read", size, len(stream), err, c.given)
			}
		default:
			if err != nil || !bytes.Equal(b, stream[2:2+size]) || c.given != 2+size {
				t.Fatalf("length %d: error %v, %d octets returned, %d read; want the %d after the length, and no more",
					size, err, len(b), c.given, size)
			}
		}
	})
}
