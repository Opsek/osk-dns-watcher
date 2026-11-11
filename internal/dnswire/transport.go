package dnswire

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"time"
)

// Response is an answer that Exchange accepted.
type Response struct {
	Msg *Message
	// Wire is the answer as received, without the TCP length prefix. It is
	// opaque proof of what the server sent; read it only through Parse.
	Wire []byte
	TCP  bool
}

// Exchange sends q to server and returns the first answer that matches it:
// same ID, QR set, opcode QUERY and the same question. Over UDP a datagram
// that does not parse or does not match, and an ICMP error such as a refused
// port, is dropped and the wait goes on until ctx ends, because anyone on the
// path can send them. A truncated answer, also one cut inside a record, is
// asked again over TCP. With tcp set, TCP is used from the start.
func Exchange(ctx context.Context, server netip.AddrPort, q Query, tcp bool) (*Response, error) {
	if q.Type == TypeAXFR || q.Type == TypeIXFR {
		return nil, fmt.Errorf("%w: type %v needs a zone transfer", ErrInvalidQuery, q.Type)
	}
	// An invalid query, of type OPT or TSIG for one, fails here, before any
	// packet is sent.
	if _, err := q.Pack(0); err != nil {
		return nil, err
	}
	if !tcp {
		r, truncated, err := exchangeUDP(ctx, server, q)
		if err != nil || !truncated {
			return r, err
		}
	}
	return exchangeTCP(ctx, server, q)
}

// exchangeUDP returns the answer, or truncated when the answer has TC set.
func exchangeUDP(ctx context.Context, server netip.AddrPort, q Query) (r *Response, truncated bool, err error) {
	c, closeConn, err := dial(ctx, "udp", server)
	if err != nil {
		return nil, false, netError(ctx, server, err)
	}
	defer closeConn()
	id := newID()
	if _, err := writeQuery(c, q, id, nil, false); err != nil {
		return nil, false, netError(ctx, server, err)
	}
	buf := make([]byte, 65535)
	var dropped error
	for {
		n, err := c.Read(buf)
		// The system reports an ICMP error on the socket this way.
		var sysErr *os.SyscallError
		if errors.As(err, &sysErr) {
			dropped = err
			continue
		}
		if err != nil {
			if dropped != nil {
				err = fmt.Errorf("%w; last dropped datagram: %w", err, dropped)
			}
			return nil, false, netError(ctx, server, err)
		}
		m, err := Parse(buf[:n])
		if err != nil {
			// A server may cut a truncated answer inside a record.
			if n >= headerLen {
				if h := readHeader(buf[:n]); h.Truncated && replies(h, id) {
					return nil, true, nil
				}
			}
			dropped = err
			continue
		}
		if answers(m, id, q, false) {
			return &Response{Msg: m, Wire: slices.Clone(buf[:n])}, m.Truncated, nil
		}
	}
}

// exchangeTCP reads one answer. Unlike a datagram, a bad answer on the
// connection cannot come from a third party, so it ends the exchange.
func exchangeTCP(ctx context.Context, server netip.AddrPort, q Query) (*Response, error) {
	c, closeConn, err := dial(ctx, "tcp", server)
	if err != nil {
		return nil, netError(ctx, server, err)
	}
	defer closeConn()
	id := newID()
	if _, err := writeQuery(c, q, id, nil, true); err != nil {
		return nil, netError(ctx, server, err)
	}
	wire, err := readTCP(c)
	if err != nil {
		return nil, netError(ctx, server, err)
	}
	m, err := Parse(wire)
	if err != nil {
		return nil, err
	}
	if !answers(m, id, q, false) {
		return nil, fmt.Errorf("%w: TCP answer from %v", ErrMismatch, server)
	}
	return &Response{Msg: m, Wire: wire, TCP: true}, nil
}

// Transfer asks server for a zone transfer over TCP and passes each message
// of the answer to each, in order, until each returns done or an error. With
// a key, the query is signed and each sees a message only after the TSIG
// that covers it was checked (RFC 8945 §5.3.1). Without a key, TSIG records
// are ignored.
func Transfer(ctx context.Context, server netip.AddrPort, q Query, key *TSIGKey,
	each func(*Message) (done bool, err error)) error {
	if q.Type != TypeAXFR && q.Type != TypeIXFR {
		return fmt.Errorf("%w: type %v is not AXFR or IXFR", ErrInvalidQuery, q.Type)
	}
	if _, err := q.Pack(0); err != nil {
		return err
	}
	c, closeConn, err := dial(ctx, "tcp", server)
	if err != nil {
		return netError(ctx, server, err)
	}
	defer closeConn()
	id := newID()
	mac, err := writeQuery(c, q, id, key, true)
	if err != nil {
		return netError(ctx, server, err)
	}
	v := &verifier{key: key, prior: mac}
	for i := 0; ; i++ {
		wire, err := readTCP(c)
		if err != nil {
			if n := len(v.pending); n > 0 {
				err = fmt.Errorf("%w: %d messages after the last signed one: %w", ErrTSIG, n, err)
			}
			return netError(ctx, server, fmt.Errorf("message %d: %w", i, err))
		}
		m, err := Parse(wire)
		if err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
		if !answers(m, id, q, i > 0) {
			return fmt.Errorf("%w: message %d of the transfer from %v", ErrMismatch, i, server)
		}
		checked, err := v.add(wire, m, time.Now())
		if err != nil {
			return fmt.Errorf("message %d: %w", i, err)
		}
		for j, cm := range checked {
			done, err := each(cm)
			if err != nil {
				return err
			}
			if !done {
				continue
			}
			// Only the last checked message carries the signature.
			if key != nil && j < len(checked)-1 {
				return fmt.Errorf("%w: the last message is not signed", ErrTSIG)
			}
			return nil
		}
	}
}

// writeQuery is the only code that writes to a DNS socket. It makes the
// bytes itself from q, so nothing but a query made by Query.Pack is sent.
// It returns the MAC of the TSIG when key is set.
func writeQuery(c net.Conn, q Query, id uint16, key *TSIGKey, tcp bool) ([]byte, error) {
	msg, err := q.Pack(id)
	if err != nil {
		return nil, err
	}
	var mac []byte
	if key != nil {
		msg, mac = sign(msg, key, time.Now())
	}
	if tcp {
		msg = append(binary.BigEndian.AppendUint16(nil, uint16(len(msg))), msg...)
	}
	_, err = c.Write(msg)
	return mac, err
}

// answers reports whether m answers q, sent with this ID. A later message of
// a zone transfer may carry no question.
func answers(m *Message, id uint16, q Query, later bool) bool {
	if !replies(m.Header, id) {
		return false
	}
	if len(m.Question) == 0 {
		return later
	}
	x := m.Question[0]
	return x.Name.Equal(q.Name) && x.Type == q.Type && x.Class == ClassINET
}

// replies reports whether h is the header of an answer to a query with this ID.
func replies(h Header, id uint16) bool {
	return h.ID == id && h.Response && h.Opcode == OpcodeQuery
}

// dial connects from a port that the system picks, and makes every read and
// write on the connection fail once ctx ends.
func dial(ctx context.Context, network string, server netip.AddrPort) (net.Conn, func(), error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, network, server.String())
	if err != nil {
		return nil, nil, err
	}
	stop := context.AfterFunc(ctx, func() { _ = c.SetDeadline(time.Unix(1, 0)) })
	return c, func() {
		stop()
		_ = c.Close()
	}, nil
}

// readTCP reads one message with its two-octet length prefix (RFC 1035
// §4.2.2). The length is at most 65535, so the buffer is bounded.
func readTCP(c net.Conn) ([]byte, error) {
	var prefix [2]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		return nil, err
	}
	size := binary.BigEndian.Uint16(prefix[:])
	if size == 0 {
		return nil, fmt.Errorf("%w: TCP message of length 0", ErrMalformed)
	}
	b := make([]byte, size)
	if _, err := io.ReadFull(c, b); err != nil {
		return nil, err
	}
	return b, nil
}

// netError names the server and, once ctx has ended, wraps ctx.Err(), so a
// caller can tell a timeout from a network error.
func netError(ctx context.Context, server netip.AddrPort, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("dnswire: %v: %w: %w", server, ctx.Err(), err)
	}
	return fmt.Errorf("dnswire: %v: %w", server, err)
}

// newID returns a random message ID. An ID that an off-path sender cannot
// guess is part of the defense against forged answers.
func newID() uint16 {
	var b [2]byte
	_, _ = rand.Read(b[:]) // never fails: crypto/rand.Read crashes the program instead
	return binary.BigEndian.Uint16(b[:])
}
