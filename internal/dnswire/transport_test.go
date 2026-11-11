package dnswire

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"
)

// Flags in octets 2 and 3 of the header.
const (
	transportQR = 0x8000
	transportAA = 0x0400
	transportTC = 0x0200
)

// transportQuery is a query that a fake server received.
type transportQuery struct {
	wire []byte // without the TCP length
	tcp  bool
}

// transportServer is a fake DNS server on one port of 127.0.0.1, over UDP
// and TCP.
type transportServer struct {
	addr    netip.AddrPort
	queries chan transportQuery
}

// transportStart starts a fake server. udp gets each datagram and its
// sender, and returns the datagrams to send back. tcp gets the first message
// of each connection and returns the octets to write before the connection
// is closed. A nil function answers nothing. Neither is called for a query
// without a question, so they may take its question as given.
func transportStart(t *testing.T, udp func(q []byte, from net.Addr) [][]byte, tcp func(q []byte) []byte) *transportServer {
	t.Helper()
	pc, ln := transportListen(t)
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
	})
	s := &transportServer{
		addr:    netip.MustParseAddrPort(pc.LocalAddr().String()),
		queries: make(chan transportQuery, 200),
	}
	go s.serveUDP(pc, udp)
	go s.serveTCP(ln, tcp)
	return s
}

// transportListen opens a UDP and a TCP socket on the same port, as a DNS
// server has them.
func transportListen(t *testing.T) (net.PacketConn, net.Listener) {
	t.Helper()
	for range 20 {
		pc, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		ln, err := net.Listen("tcp", pc.LocalAddr().String())
		if err == nil {
			return pc, ln
		}
		_ = pc.Close()
	}
	t.Fatal("no port of 127.0.0.1 is free for both UDP and TCP")
	return nil, nil
}

func (s *transportServer) serveUDP(pc net.PacketConn, udp func([]byte, net.Addr) [][]byte) {
	buf := make([]byte, 65535)
	for {
		n, from, err := pc.ReadFrom(buf)
		if err != nil {
			return
		}
		q := bytes.Clone(buf[:n])
		s.record(q, false)
		if udp == nil || transportQuestionOf(q) == nil {
			continue
		}
		for _, d := range udp(q, from) {
			_, _ = pc.WriteTo(d, from)
		}
	}
}

func (s *transportServer) serveTCP(ln net.Listener, tcp func([]byte) []byte) {
	for {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = c.Close() }()
			q, err := transportReadTCP(c)
			if err != nil {
				return
			}
			s.record(q, true)
			if tcp != nil && transportQuestionOf(q) != nil {
				_, _ = c.Write(tcp(q))
			}
		}()
	}
}

func (s *transportServer) record(q []byte, tcp bool) {
	select {
	case s.queries <- transportQuery{q, tcp}:
	default:
	}
}

// next returns the next query that the server received.
func (s *transportServer) next(t *testing.T) transportQuery {
	t.Helper()
	select {
	case q := <-s.queries:
		return q
	case <-time.After(5 * time.Second):
		t.Fatal("the server received no query")
		return transportQuery{}
	}
}

func transportReadTCP(r io.Reader) ([]byte, error) {
	var n [2]byte
	if _, err := io.ReadFull(r, n[:]); err != nil {
		return nil, err
	}
	b := make([]byte, binary.BigEndian.Uint16(n[:]))
	_, err := io.ReadFull(r, b)
	return b, err
}

// transportFrame puts the two-octet length before each message, as TCP
// carries them.
func transportFrame(msgs ...[]byte) []byte {
	var b []byte
	for _, m := range msgs {
		b = binary.BigEndian.AppendUint16(b, uint16(len(m)))
		b = append(b, m...)
	}
	return b
}

func transportID(msg []byte) uint16 {
	return binary.BigEndian.Uint16(msg)
}

// transportWire returns the wire form of a name such as "corp.test.".
func transportWire(name string) []byte {
	var b []byte
	for _, l := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if l != "" {
			b = append(b, byte(len(l)))
			b = append(b, l...)
		}
	}
	return append(b, 0)
}

func transportQuestion(name string, typ, class uint16) []byte {
	b := transportWire(name)
	b = binary.BigEndian.AppendUint16(b, typ)
	return binary.BigEndian.AppendUint16(b, class)
}

// transportQuestionOf returns the question section of a query, whose name is
// uncompressed, or nil when the query has none.
func transportQuestionOf(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > len(q) {
		return nil
	}
	return q[12 : i+5]
}

// transportRR returns a record of class IN with TTL 300.
func transportRR(owner []byte, typ uint16, data []byte) []byte {
	b := bytes.Clone(owner)
	b = binary.BigEndian.AppendUint16(b, typ)
	b = binary.BigEndian.AppendUint16(b, 1)
	b = binary.BigEndian.AppendUint32(b, 300)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// transportMessage returns a message with the question, if one is given, and
// the records in the answer section.
func transportMessage(id, flags uint16, question []byte, answer ...[]byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, id)
	b = binary.BigEndian.AppendUint16(b, flags)
	if question != nil {
		b = binary.BigEndian.AppendUint16(b, 1)
	} else {
		b = binary.BigEndian.AppendUint16(b, 0)
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(answer)))
	b = append(b, 0, 0, 0, 0)
	b = append(b, question...)
	for _, r := range answer {
		b = append(b, r...)
	}
	return b
}

// transportReply answers the query q with its ID and question, the flags,
// and n records of type A whose owner points to the question name.
func transportReply(q []byte, flags uint16, n int) []byte {
	a := transportRR([]byte{0xC0, 12}, uint16(TypeA), []byte{192, 0, 2, 1})
	answer := make([][]byte, n)
	for i := range answer {
		answer[i] = a
	}
	return transportMessage(transportID(q), flags, transportQuestionOf(q), answer...)
}

func transportName(t *testing.T, s string) Name {
	t.Helper()
	n, err := ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func transportCtx(t *testing.T, d time.Duration) context.Context {
	ctx, cancel := context.WithTimeout(context.Background(), d)
	t.Cleanup(cancel)
	return ctx
}

// transportCheckSent fails the test unless the server received exactly what
// q.Pack makes with the ID that the received query carries.
func transportCheckSent(t *testing.T, got transportQuery, q Query, tcp bool) {
	t.Helper()
	if got.tcp != tcp {
		t.Fatalf("query over TCP: %v, want %v", got.tcp, tcp)
	}
	if len(got.wire) < 2 {
		t.Fatalf("query of %d octets", len(got.wire))
	}
	want, err := q.Pack(transportID(got.wire))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got.wire, want) {
		t.Fatalf("query\n got % x\nwant % x", got.wire, want)
	}
}

// transportCheckResponse fails the test unless r holds the answer want.
func transportCheckResponse(t *testing.T, r *Response, want []byte, tcp bool) {
	t.Helper()
	switch {
	case r == nil || r.Msg == nil:
		t.Fatalf("response %v without a message", r)
	case r.TCP != tcp:
		t.Fatalf("response over TCP: %v, want %v", r.TCP, tcp)
	case !bytes.Equal(r.Wire, want):
		t.Fatalf("answer\n got % x\nwant % x", r.Wire, want)
	case r.Msg.ID != transportID(want):
		t.Fatalf("message ID %d, want %d", r.Msg.ID, transportID(want))
	}
}

func TestExchangeUDP(t *testing.T) {
	s := transportStart(t, func(q []byte, _ net.Addr) [][]byte {
		return [][]byte{transportReply(q, transportQR|transportAA, 1)}
	}, nil)
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA, RecursionDesired: true}
	r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, false)
	if err != nil {
		t.Fatal(err)
	}
	sent := s.next(t)
	transportCheckSent(t, sent, q, false)
	transportCheckResponse(t, r, transportReply(sent.wire, transportQR|transportAA, 1), false)
	want := A{Addr: netip.MustParseAddr("192.0.2.1")}
	if len(r.Msg.Answer) != 1 || r.Msg.Answer[0].Data != RData(want) {
		t.Errorf("answer section %v, want one record with %v", r.Msg.Answer, want)
	}
}

// Each case sends a datagram that must be dropped, then the real answer.
func TestExchangeDropsWrongDatagrams(t *testing.T) {
	good := func(q []byte) []byte { return transportReply(q, transportQR, 1) }
	pointerA := transportRR([]byte{0xC0, 12}, uint16(TypeA), []byte{192, 0, 2, 9})
	other := func(q []byte, name string, typ, class uint16) []byte {
		return transportMessage(transportID(q), transportQR, transportQuestion(name, typ, class), pointerA)
	}
	cases := []struct {
		name    string
		bad     func(q []byte) []byte
		spoofed bool // sent from another port of 127.0.0.1
	}{
		{"wrong ID", func(q []byte) []byte {
			b := good(q)
			b[1] ^= 1
			return b
		}, false},
		{"QR 0", func(q []byte) []byte { return transportReply(q, 0, 1) }, false},
		{"opcode NOTIFY", func(q []byte) []byte { return transportReply(q, transportQR|4<<11, 1) }, false},
		{"other name", func(q []byte) []byte { return other(q, "www.corp.test.", uint16(TypeA), 1) }, false},
		{"other type", func(q []byte) []byte { return other(q, "corp.test.", uint16(TypeAAAA), 1) }, false},
		{"other class", func(q []byte) []byte { return other(q, "corp.test.", uint16(TypeA), 3) }, false},
		{"no message", func(q []byte) []byte { return []byte{1, 2, 3, 4, 5} }, false},
		{"record cut short", func(q []byte) []byte {
			b := good(q)
			return b[:len(b)-1]
		}, false},
		// A right answer from another port is dropped because the socket
		// is connected to the server.
		{"other port", func(q []byte) []byte { return transportReply(q, transportQR, 2) }, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			spoof, err := net.ListenPacket("udp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = spoof.Close() })
			s := transportStart(t, func(q []byte, from net.Addr) [][]byte {
				if c.spoofed {
					_, _ = spoof.WriteTo(c.bad(q), from)
					return [][]byte{good(q)}
				}
				return [][]byte{c.bad(q), good(q)}
			}, nil)
			q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
			r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, false)
			if err != nil {
				t.Fatal(err)
			}
			transportCheckResponse(t, r, good(s.next(t).wire), false)
		})
	}
}

// Names compare without regard to the case of ASCII letters.
func TestExchangeAcceptsNameInOtherCase(t *testing.T) {
	upper := func(q []byte) []byte {
		b := transportReply(q, transportQR, 1)
		end := 12 + len(transportQuestionOf(q)) - 4
		copy(b[12:end], bytes.ToUpper(b[12:end]))
		return b
	}
	s := transportStart(t, func(q []byte, _ net.Addr) [][]byte { return [][]byte{upper(q)} }, nil)
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
	r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, false)
	if err != nil {
		t.Fatal(err)
	}
	want := upper(s.next(t).wire)
	if !bytes.Contains(want, []byte("CORP")) {
		t.Fatalf("the answer % x has no name in upper case", want)
	}
	transportCheckResponse(t, r, want, false)
}

func TestExchangeOnlyMalformed(t *testing.T) {
	s := transportStart(t, func(q []byte, _ net.Addr) [][]byte {
		b := transportReply(q, transportQR, 1)
		return [][]byte{b[:len(b)-1], {0, 1, 2}}
	}, nil)
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
	_, err := Exchange(transportCtx(t, 300*time.Millisecond), s.addr, q, false)
	if !errors.Is(err, context.DeadlineExceeded) || !errors.Is(err, ErrMalformed) {
		t.Errorf("error %v, want one that wraps both the deadline and ErrMalformed", err)
	}
}

func TestExchangeContextEnds(t *testing.T) {
	cases := []struct {
		name string
		ctx  func() context.Context
		want error
	}{
		{"deadline", func() context.Context { return transportCtx(t, 200*time.Millisecond) }, context.DeadlineExceeded},
		{"cancel", func() context.Context {
			ctx, cancel := context.WithCancel(context.Background())
			time.AfterFunc(200*time.Millisecond, cancel)
			return ctx
		}, context.Canceled},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := transportStart(t, nil, nil)
			q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
			start := time.Now()
			_, err := Exchange(c.ctx(), s.addr, q, false)
			if !errors.Is(err, c.want) || errors.Is(err, ErrMalformed) {
				t.Errorf("error %v, want one that wraps %v and not ErrMalformed", err, c.want)
			}
			if d := time.Since(start); d > 3*time.Second {
				t.Errorf("Exchange returned %v after the start, long after the context ended", d)
			}
		})
	}
}

func TestExchangeTruncatedAsksOverTCP(t *testing.T) {
	s := transportStart(t,
		func(q []byte, _ net.Addr) [][]byte { return [][]byte{transportReply(q, transportQR|transportTC, 0)} },
		func(q []byte) []byte { return transportFrame(transportReply(q, transportQR, 3)) })
	q := Query{Name: transportName(t, "corp.test."), Type: TypeTXT, DNSSECOK: true}
	var udpIDs []uint16
	newID := false
	for range 3 {
		r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, false)
		if err != nil {
			t.Fatal(err)
		}
		udp, tcp := s.next(t), s.next(t)
		transportCheckSent(t, udp, q, false)
		transportCheckSent(t, tcp, q, true)
		transportCheckResponse(t, r, transportReply(tcp.wire, transportQR, 3), true)
		udpIDs = append(udpIDs, transportID(udp.wire))
		newID = newID || transportID(tcp.wire) != transportID(udp.wire)
	}
	// Random IDs fail these checks with a chance of 2^-32 and 2^-48.
	if udpIDs[0] == udpIDs[1] && udpIDs[1] == udpIDs[2] {
		t.Errorf("three queries had the same ID %d", udpIDs[0])
	}
	if !newID {
		t.Error("each query over TCP had the ID of the truncated query over UDP")
	}
}

// Anyone on the path can forge the ICMP message that refuses a port, so a
// refusal ends the wait no sooner than the context does.
func TestExchangeWaitsAfterRefusedPort(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := netip.MustParseAddrPort(pc.LocalAddr().String())
	// With the port closed, the system refuses the query.
	if err := pc.Close(); err != nil {
		t.Fatal(err)
	}
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
	start := time.Now()
	_, err = Exchange(transportCtx(t, 300*time.Millisecond), server, q, false)
	if !errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "refused") {
		t.Errorf("error %v after %v, want the deadline and the refusal", err, time.Since(start))
	}
}

// A server may cut a truncated answer inside a record. With the ID, QR,
// opcode and TC right, it still means: ask again over TCP.
func TestExchangeTruncatedCutInsideRecordAsksOverTCP(t *testing.T) {
	cut := func(q []byte) []byte {
		a := transportRR([]byte{0xC0, 12}, uint16(TypeA), []byte{1, 2, 3, 4})
		b := transportMessage(transportID(q), transportQR|transportAA|transportTC, transportQuestionOf(q), a, a)
		return b[:len(b)-5] // the second record stops inside its data length
	}
	s := transportStart(t,
		func(q []byte, _ net.Addr) [][]byte { return [][]byte{cut(q)} },
		func(q []byte) []byte { return transportFrame(transportReply(q, transportQR, 3)) })
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
	r, err := Exchange(transportCtx(t, 2*time.Second), s.addr, q, false)
	if err != nil {
		t.Fatal(err)
	}
	udp, tcp := s.next(t), s.next(t)
	if _, err := Parse(cut(udp.wire)); !errors.Is(err, ErrMalformed) {
		t.Fatalf("the cut answer parses: %v", err)
	}
	transportCheckSent(t, tcp, q, true)
	transportCheckResponse(t, r, transportReply(tcp.wire, transportQR, 3), true)
}

func TestExchangeTCP(t *testing.T) {
	cases := []struct {
		name string
		msg  func(q []byte) []byte // the one message the server sends
		want error                 // nil: the message is the answer
	}{
		{"answer", func(q []byte) []byte { return transportReply(q, transportQR, 1) }, nil},
		{"truncated", func(q []byte) []byte { return transportReply(q, transportQR|transportTC, 0) }, nil},
		{"length zero", func(q []byte) []byte { return []byte{} }, ErrMalformed},
		{"no message", func(q []byte) []byte { return []byte{1, 2, 3, 4, 5} }, ErrMalformed},
		{"wrong ID", func(q []byte) []byte {
			b := transportReply(q, transportQR, 1)
			b[0] ^= 0x80
			return b
		}, ErrMismatch},
		{"QR 0", func(q []byte) []byte { return transportReply(q, 0, 1) }, ErrMismatch},
		{"other question", func(q []byte) []byte {
			return transportMessage(transportID(q), transportQR, transportQuestion("www.corp.test.", uint16(TypeA), 1))
		}, ErrMismatch},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := transportStart(t, nil, func(q []byte) []byte { return transportFrame(c.msg(q)) })
			q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
			r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, true)
			sent := s.next(t)
			transportCheckSent(t, sent, q, true)
			if c.want != nil {
				if !errors.Is(err, c.want) {
					t.Fatalf("error %v, want %v", err, c.want)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := c.msg(sent.wire)
			transportCheckResponse(t, r, want, true)
			if tc := want[2]&0x02 != 0; r.Msg.Truncated != tc {
				t.Errorf("TC %v, want %v", r.Msg.Truncated, tc)
			}
		})
	}
}

// An answer far larger than the EDNS size of the query is still read whole.
func TestExchangeLargeDatagram(t *testing.T) {
	s := transportStart(t, func(q []byte, _ net.Addr) [][]byte {
		return [][]byte{transportReply(q, transportQR, 3000)}
	}, nil)
	q := Query{Name: transportName(t, "corp.test."), Type: TypeA}
	r, err := Exchange(transportCtx(t, 5*time.Second), s.addr, q, false)
	if err != nil {
		t.Fatal(err)
	}
	transportCheckResponse(t, r, transportReply(s.next(t).wire, transportQR, 3000), false)
	if len(r.Msg.Answer) != 3000 {
		t.Errorf("%d answer records, want 3000", len(r.Msg.Answer))
	}
}

func TestExchangeRefusesQueries(t *testing.T) {
	s := transportStart(t, nil, nil)
	n := transportName(t, "corp.test.")
	for _, q := range []Query{
		{Name: n, Type: TypeAXFR},
		{Name: n, Type: TypeIXFR, IXFRSerial: 1},
		{Name: n, Type: TypeOPT},
		{Name: n, Type: TypeTSIG},
		{Name: n, Type: TypeA, Cookie: []byte{1, 2, 3, 4, 5}},
	} {
		if _, err := Exchange(transportCtx(t, time.Second), s.addr, q, false); !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("Exchange of %v %v (cookie %x): error %v, want ErrInvalidQuery", q.Name, q.Type, q.Cookie, err)
		}
	}
	if len(s.queries) != 0 {
		t.Errorf("%d refused queries reached the server", len(s.queries))
	}
}

// transportZone returns the answer records of a transfer of n messages:
// message i holds the record h<i>.corp.test. A 192.0.2.<i>, the first one
// starts with the SOA, and the one at index end ends with it.
func transportZone(n, end int) [][][]byte {
	soa := transportWire("ns1.corp.test.")
	soa = append(soa, transportWire("hostmaster.corp.test.")...)
	for _, v := range []uint32{1, 3600, 600, 604800, 300} {
		soa = binary.BigEndian.AppendUint32(soa, v)
	}
	soaRR := transportRR(transportWire("corp.test."), uint16(TypeSOA), soa)
	msgs := make([][][]byte, n)
	for i := range msgs {
		owner := transportWire(fmt.Sprintf("h%d.corp.test.", i))
		msgs[i] = [][]byte{transportRR(owner, uint16(TypeA), []byte{192, 0, 2, byte(i)})}
	}
	msgs[0] = append([][]byte{soaRR}, msgs[0]...)
	msgs[end] = append(msgs[end], soaRR)
	return msgs
}

// transportCollect returns a function for Transfer that keeps each message
// and reports done at the second SOA record, which ends a full transfer.
func transportCollect(seen *[]*Message) func(*Message) (bool, error) {
	soas := 0
	return func(m *Message) (bool, error) {
		*seen = append(*seen, m)
		for _, r := range m.Answer {
			if r.Type() == TypeSOA {
				soas++
			}
		}
		return soas == 2, nil
	}
}

// transportCheckSeen fails the test unless seen holds the first n messages of
// a stream of transportZone, in order.
func transportCheckSeen(t *testing.T, seen []*Message, n int) {
	t.Helper()
	if len(seen) != n {
		t.Fatalf("each saw %d messages, want %d", len(seen), n)
	}
	for i, m := range seen {
		want := RData(A{Addr: netip.AddrFrom4([4]byte{192, 0, 2, byte(i)})})
		found := false
		for _, r := range m.Answer {
			found = found || r.Data == want
		}
		if !found {
			t.Fatalf("message %d that each saw has the records %v, want one with %v", i, m.Answer, want)
		}
	}
}

func TestTransferWithoutKey(t *testing.T) {
	for _, q := range []Query{{Type: TypeAXFR}, {Type: TypeIXFR, IXFRSerial: 7}} {
		t.Run(q.Type.String(), func(t *testing.T) {
			// TSIG records go unchecked without a key; these have no
			// valid MAC.
			junk := func(msg []byte, id uint16) []byte {
				return transportAppendTSIG(msg, transportTSIG{
					name: transportWire("xfr-key."), algorithm: transportWire("hmac-sha256."),
					time: uint64(time.Now().Unix()), fudge: 300, mac: make([]byte, 32), origID: id,
				})
			}
			zone := transportZone(3, 2)
			s := transportStart(t, nil, func(q []byte) []byte {
				id := transportID(q)
				question := transportQuestionOf(q)
				return transportFrame(
					junk(transportMessage(id, transportQR|transportAA, question, zone[0]...), id),
					junk(transportMessage(id, transportQR|transportAA, question, zone[1]...), id),
					junk(transportMessage(id, transportQR|transportAA, nil, zone[2]...), id))
			})
			q.Name = transportName(t, "corp.test.")
			var seen []*Message
			if err := Transfer(transportCtx(t, 5*time.Second), s.addr, q, nil, transportCollect(&seen)); err != nil {
				t.Fatal(err)
			}
			transportCheckSent(t, s.next(t), q, true)
			transportCheckSeen(t, seen, 3)
			for i, m := range seen {
				if len(m.Additional) != 0 {
					t.Errorf("message %d: additional section %v, want it empty", i, m.Additional)
				}
			}
		})
	}
}

func TestTransferRefusesTypes(t *testing.T) {
	s := transportStart(t, nil, nil)
	for _, typ := range []Type{TypeA, TypeSOA, TypeANY} {
		q := Query{Name: transportName(t, "corp.test."), Type: typ}
		err := Transfer(transportCtx(t, time.Second), s.addr, q, nil, func(*Message) (bool, error) { return true, nil })
		if !errors.Is(err, ErrInvalidQuery) {
			t.Errorf("Transfer of type %v: error %v, want ErrInvalidQuery", typ, err)
		}
	}
}

func TestTransferBadStream(t *testing.T) {
	zone := transportZone(3, 2)
	msg := func(id uint16, question []byte, i int) []byte {
		return transportMessage(id, transportQR|transportAA, question, zone[i]...)
	}
	stop := errors.New("stop")
	cases := []struct {
		name   string
		stream func(id uint16, question []byte) [][]byte
		each   error // what each returns with the first message
		want   error // nil: any error
		seen   int
	}{
		{"later message with another ID", func(id uint16, question []byte) [][]byte {
			return [][]byte{msg(id, question, 0), msg(id^1, nil, 1), msg(id, nil, 2)}
		}, nil, ErrMismatch, 1},
		{"first message without the question", func(id uint16, question []byte) [][]byte {
			return [][]byte{msg(id, nil, 0), msg(id, nil, 1), msg(id, nil, 2)}
		}, nil, ErrMismatch, 0},
		{"later message with another question", func(id uint16, question []byte) [][]byte {
			other := transportQuestion("www.corp.test.", uint16(TypeAXFR), 1)
			return [][]byte{msg(id, question, 0), msg(id, other, 1), msg(id, nil, 2)}
		}, nil, ErrMismatch, 1},
		{"message that does not parse", func(id uint16, question []byte) [][]byte {
			bad := msg(id, nil, 1)
			return [][]byte{msg(id, question, 0), bad[:len(bad)-1], msg(id, nil, 2)}
		}, nil, ErrMalformed, 1},
		{"stream that ends early", func(id uint16, question []byte) [][]byte {
			return [][]byte{msg(id, question, 0), msg(id, nil, 1)}
		}, nil, nil, 2},
		{"error from each", func(id uint16, question []byte) [][]byte {
			return [][]byte{msg(id, question, 0), msg(id, nil, 1), msg(id, nil, 2)}
		}, stop, stop, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			s := transportStart(t, nil, func(q []byte) []byte {
				return transportFrame(c.stream(transportID(q), transportQuestionOf(q))...)
			})
			q := Query{Name: transportName(t, "corp.test."), Type: TypeAXFR}
			var seen []*Message
			collect := transportCollect(&seen)
			each := func(m *Message) (bool, error) {
				done, _ := collect(m)
				return done, c.each
			}
			err := Transfer(transportCtx(t, 5*time.Second), s.addr, q, nil, each)
			if err == nil || c.want != nil && !errors.Is(err, c.want) {
				t.Errorf("error %v, want %v", err, c.want)
			}
			transportCheckSeen(t, seen, c.seen)
		})
	}
}
