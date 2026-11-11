package dnswire

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"testing"
	"time"
)

// transportTSIG is the data of a TSIG record (RFC 8945, section 4.2).
type transportTSIG struct {
	name, algorithm []byte // wire form
	time            uint64 // 48 bits
	fudge           uint16
	mac             []byte
	origID, errCode uint16
	other           []byte
}

func transportAppendTime(b []byte, t uint64) []byte {
	b = binary.BigEndian.AppendUint16(b, uint16(t>>32))
	return binary.BigEndian.AppendUint32(b, uint32(t))
}

// transportAppendTSIG adds the record to the end of the additional section.
func transportAppendTSIG(msg []byte, t transportTSIG) []byte {
	data := bytes.Clone(t.algorithm)
	data = transportAppendTime(data, t.time)
	data = binary.BigEndian.AppendUint16(data, t.fudge)
	data = binary.BigEndian.AppendUint16(data, uint16(len(t.mac)))
	data = append(data, t.mac...)
	data = binary.BigEndian.AppendUint16(data, t.origID)
	data = binary.BigEndian.AppendUint16(data, t.errCode)
	data = binary.BigEndian.AppendUint16(data, uint16(len(t.other)))
	data = append(data, t.other...)
	b := bytes.Clone(msg)
	binary.BigEndian.PutUint16(b[10:], binary.BigEndian.Uint16(b[10:])+1)
	b = append(b, t.name...)
	b = binary.BigEndian.AppendUint16(b, uint16(TypeTSIG))
	b = binary.BigEndian.AppendUint16(b, uint16(ClassANY))
	b = binary.BigEndian.AppendUint32(b, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...)
}

// transportVariables returns the TSIG variables that the MAC of a query and
// of the first answer cover (RFC 8945, section 4.3.3).
func transportVariables(t transportTSIG) []byte {
	b := bytes.Clone(t.name)
	b = binary.BigEndian.AppendUint16(b, uint16(ClassANY))
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, t.algorithm...)
	b = transportAppendTime(b, t.time)
	b = binary.BigEndian.AppendUint16(b, t.fudge)
	b = binary.BigEndian.AppendUint16(b, t.errCode)
	b = binary.BigEndian.AppendUint16(b, uint16(len(t.other)))
	return append(b, t.other...)
}

func transportMAC(secret []byte, parts ...[]byte) []byte {
	h := hmac.New(sha256.New, secret)
	for _, p := range parts {
		h.Write(p)
	}
	return h.Sum(nil)
}

// transportReader reads a message without ever reading past its end.
type transportReader struct {
	b   []byte
	off int
	bad bool
}

func (r *transportReader) take(n int) []byte {
	if r.bad || r.off+n > len(r.b) {
		r.bad = true
		return make([]byte, n)
	}
	r.off += n
	return r.b[r.off-n : r.off]
}

func (r *transportReader) u16() uint16 {
	return binary.BigEndian.Uint16(r.take(2))
}

// name returns the octets of the name as written; a pointer ends it.
func (r *transportReader) name() []byte {
	start := r.off
	for {
		l := r.take(1)[0]
		if l == 0 || r.bad {
			break
		}
		if l >= 0xC0 {
			r.take(1)
			break
		}
		r.take(int(l))
	}
	return bytes.Clone(r.b[start:min(r.off, len(r.b))])
}

// transportSplitTSIG reads the TSIG record at the end of msg. It returns msg
// without it and with the additional count one lower, as the MAC covers it.
func transportSplitTSIG(msg []byte) ([]byte, transportTSIG, bool) {
	var t transportTSIG
	r := &transportReader{b: msg}
	h := r.take(12)
	ar := int(binary.BigEndian.Uint16(h[10:]))
	if ar == 0 {
		return nil, t, false
	}
	for range binary.BigEndian.Uint16(h[4:]) {
		r.name()
		r.take(4)
	}
	for range int(binary.BigEndian.Uint16(h[6:])) + int(binary.BigEndian.Uint16(h[8:])) + ar - 1 {
		r.name()
		r.take(8)
		r.take(int(r.u16()))
	}
	start := r.off
	t.name = r.name()
	typ := r.u16()
	r.take(6)
	end := r.off + int(r.u16())
	t.algorithm = r.name()
	t.time = uint64(r.u16())<<32 | uint64(binary.BigEndian.Uint32(r.take(4)))
	t.fudge = r.u16()
	t.mac = bytes.Clone(r.take(int(r.u16())))
	t.origID = r.u16()
	t.errCode = r.u16()
	t.other = bytes.Clone(r.take(int(r.u16())))
	if r.bad || typ != uint16(TypeTSIG) || r.off != end || end != len(msg) {
		return nil, t, false
	}
	unsigned := bytes.Clone(msg[:start])
	binary.BigEndian.PutUint16(unsigned[10:], uint16(ar-1))
	return unsigned, t, true
}

// transportSig says how one answer of a stream is signed. The zero value
// signs it right.
type transportSig struct {
	unsigned bool
	skew     int64  // seconds added to the time signed
	keyName  string // instead of the name of the key
	alg      string // instead of hmac-sha256.
	errCode  uint16
	macLen   int  // octets of the MAC kept, when not 0
	flip     bool // one bit of the MAC changed
	chained  bool // the MAC of a later answer, also on the first one
}

// transportSigner signs the answers of a stream as a server does: the first
// MAC covers the MAC of the query, each later one the MAC before it, every
// message since and the timers (RFC 8945, sections 4.3.2 and 5.3.1). The
// first MAC also covers unsigned answers before it, so that only the rule
// "the first answer is signed" can reject such a stream.
type transportSigner struct {
	secret []byte
	mac    []byte // the last MAC sent, at first the MAC of the query
	since  []byte // the messages sent since the last MAC
	signed bool   // whether an answer was signed yet
}

func (s *transportSigner) sign(msg []byte, sig transportSig) []byte {
	if sig.unsigned {
		s.since = append(s.since, msg...)
		return msg
	}
	t := transportTSIG{
		name:      transportWire("xfr-key."),
		algorithm: transportWire("hmac-sha256."),
		time:      uint64(time.Now().Unix() + sig.skew),
		fudge:     300,
		origID:    transportID(msg),
		errCode:   sig.errCode,
	}
	if sig.keyName != "" {
		t.name = transportWire(sig.keyName)
	}
	if sig.alg != "" {
		t.algorithm = transportWire(sig.alg)
	}
	prior := binary.BigEndian.AppendUint16(nil, uint16(len(s.mac)))
	prior = append(prior, s.mac...)
	if s.signed || sig.chained {
		timers := binary.BigEndian.AppendUint16(transportAppendTime(nil, t.time), t.fudge)
		t.mac = transportMAC(s.secret, prior, s.since, msg, timers)
	} else {
		t.mac = transportMAC(s.secret, prior, s.since, msg, transportVariables(t))
	}
	if sig.macLen > 0 {
		t.mac = t.mac[:sig.macLen]
	}
	if sig.flip {
		t.mac[0] ^= 1
	}
	s.mac, s.since, s.signed = t.mac, nil, true
	return transportAppendTSIG(msg, t)
}

func transportKey(t *testing.T) *TSIGKey {
	return &TSIGKey{Name: transportName(t, "xfr-key."), Secret: []byte("0123456789abcdef0123456789abcdef")}
}

// transportCheckSigned fails the test unless the query is q.Pack with the ID
// it carries, then a TSIG record of the key with fudge 300, the time now and
// the right MAC.
func transportCheckSigned(t *testing.T, got transportQuery, q Query, key *TSIGKey) {
	t.Helper()
	unsigned, tsig, ok := transportSplitTSIG(got.wire)
	if !ok {
		t.Fatalf("the query has no TSIG record at its end: % x", got.wire)
	}
	transportCheckSent(t, transportQuery{unsigned, got.tcp}, q, true)
	now := time.Now().Unix()
	switch {
	case !bytes.Equal(tsig.name, transportWire("xfr-key.")):
		t.Errorf("key name % x, want xfr-key.", tsig.name)
	case !bytes.Equal(tsig.algorithm, transportWire("hmac-sha256.")):
		t.Errorf("algorithm % x, want hmac-sha256.", tsig.algorithm)
	case tsig.fudge != 300:
		t.Errorf("fudge %d, want 300", tsig.fudge)
	case int64(tsig.time) < now-60 || int64(tsig.time) > now+60:
		t.Errorf("time signed %d, want about %d", tsig.time, now)
	case tsig.origID != transportID(got.wire) || tsig.errCode != 0 || len(tsig.other) != 0:
		t.Errorf("original ID %d, error %d, other data %x; want %d, 0 and none",
			tsig.origID, tsig.errCode, tsig.other, transportID(got.wire))
	case !hmac.Equal(tsig.mac, transportMAC(key.Secret, unsigned, transportVariables(tsig))):
		t.Errorf("wrong MAC % x", tsig.mac)
	}
}

// transportSignedServer serves one transfer of transportZone with one
// message for each sig, and after messages behind the one that ends the zone.
func transportSignedServer(t *testing.T, key *TSIGKey, sigs []transportSig, after int) *transportServer {
	zone := transportZone(len(sigs), len(sigs)-1-after)
	return transportStart(t, nil, func(q []byte) []byte {
		_, tsig, ok := transportSplitTSIG(q)
		if !ok {
			return nil
		}
		s := &transportSigner{secret: key.Secret, mac: tsig.mac}
		var out []byte
		for i, recs := range zone {
			question := transportQuestionOf(q)
			if i > 0 {
				question = nil
			}
			msg := transportMessage(transportID(q), transportQR|transportAA, question, recs...)
			out = append(out, transportFrame(s.sign(msg, sigs[i]))...)
		}
		return out
	})
}

// transportSigs returns first, then n unsigned, then last.
func transportSigs(first transportSig, n int, last transportSig) []transportSig {
	sigs := []transportSig{first}
	for range n {
		sigs = append(sigs, transportSig{unsigned: true})
	}
	return append(sigs, last)
}

func TestTransferTSIG(t *testing.T) {
	var right transportSig
	none := transportSig{unsigned: true}
	cases := []struct {
		name  string
		sigs  []transportSig
		after int   // messages after the one that ends the zone
		ok    bool  // the transfer succeeds
		want  error // else the error, or nil for any
		seen  int   // the messages that each sees
	}{
		{name: "all signed", sigs: []transportSig{right, right, right}, ok: true, seen: 3},
		{name: "99 unsigned in a row", sigs: transportSigs(right, 99, right), ok: true, seen: 101},
		{name: "100 unsigned in a row", sigs: transportSigs(right, 100, right), want: ErrTSIG, seen: 1},
		{name: "first unsigned", sigs: []transportSig{none, right}, want: ErrTSIG},
		{name: "first unsigned, then a later MAC", sigs: []transportSig{none, {chained: true}}, want: ErrTSIG},
		{name: "bad MAC first", sigs: []transportSig{{flip: true}, right}, want: ErrTSIG},
		// each must not see the unsigned message that the bad MAC covers.
		{name: "bad MAC later", sigs: []transportSig{right, none, {flip: true}}, want: ErrTSIG, seen: 1},
		{name: "short MAC", sigs: []transportSig{{macLen: 16}}, want: ErrTSIG},
		{name: "time too old", sigs: []transportSig{{skew: -400}}, want: ErrTSIG},
		{name: "time too new", sigs: []transportSig{{skew: 400}}, want: ErrTSIG},
		{name: "time within fudge", sigs: []transportSig{{skew: -200}, {skew: 200}}, ok: true, seen: 2},
		{name: "other key name", sigs: []transportSig{{keyName: "other-key."}}, want: ErrTSIG},
		{name: "other algorithm", sigs: []transportSig{{alg: "hmac-sha1."}}, want: ErrTSIG},
		{name: "error field", sigs: []transportSig{{errCode: 18}}, want: ErrTSIG},
		// The stream stops with an unsigned message that no MAC covers.
		{name: "last unsigned", sigs: []transportSig{right, none}, seen: 1},
		// A later MAC covers the message that ends the zone, but that
		// message itself is unsigned.
		{name: "done on an unsigned message", sigs: []transportSig{right, none, right}, after: 1, want: ErrTSIG, seen: 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			key := transportKey(t)
			s := transportSignedServer(t, key, c.sigs, c.after)
			q := Query{Name: transportName(t, "corp.test."), Type: TypeAXFR}
			var seen []*Message
			err := Transfer(transportCtx(t, 10*time.Second), s.addr, q, key, transportCollect(&seen))
			switch {
			case c.ok && err != nil:
				t.Errorf("error %v, want none", err)
			case !c.ok && err == nil:
				t.Errorf("no error, want %v", c.want)
			case !c.ok && c.want != nil && !errors.Is(err, c.want):
				t.Errorf("error %v, want %v", err, c.want)
			}
			transportCheckSeen(t, seen, c.seen)
			transportCheckSigned(t, s.next(t), q, key)
		})
	}
}

// Parse reads the whole TSIG record, with a key or without one: a record
// whose fields do not fill its data makes the message malformed.
func TestParseReadsTSIG(t *testing.T) {
	msg := transportMessage(0x1234, transportQR, transportQuestion("corp.test.", uint16(TypeAXFR), 1))
	signed := transportAppendTSIG(msg, transportTSIG{
		name: transportWire("xfr-key."), algorithm: transportWire("hmac-sha256."),
		fudge: 300, mac: make([]byte, 32), origID: 0x1234,
	})
	m, err := Parse(signed)
	if err != nil || !m.HasTSIG() || len(m.Additional) != 0 {
		t.Errorf("Parse of a signed message: %v, %v; want a TSIG record outside the additional section", m, err)
	}
	if m, err := Parse(msg); err != nil || m.HasTSIG() {
		t.Errorf("Parse of an unsigned message: %v, %v; want no TSIG record", m, err)
	}
	bad := bytes.Clone(signed)
	bad[len(bad)-1] = 1 // other data of one octet, which the record lacks
	if _, err := Parse(bad); !errors.Is(err, ErrMalformed) {
		t.Errorf("Parse of a TSIG record with other data missing: %v, want ErrMalformed", err)
	}
}

// The MAC chain of a stream covers the unsigned messages in their place: a
// signer that skips them makes a MAC that must not check.
func TestTransferTSIGCoversUnsignedMessages(t *testing.T) {
	key := transportKey(t)
	zone := transportZone(3, 2)
	s := transportStart(t, nil, func(q []byte) []byte {
		_, tsig, ok := transportSplitTSIG(q)
		if !ok {
			return nil
		}
		signer := &transportSigner{secret: key.Secret, mac: tsig.mac}
		id := transportID(q)
		first := signer.sign(transportMessage(id, transportQR|transportAA, transportQuestionOf(q), zone[0]...), transportSig{})
		second := transportMessage(id, transportQR|transportAA, nil, zone[1]...)
		third := signer.sign(transportMessage(id, transportQR|transportAA, nil, zone[2]...), transportSig{})
		return transportFrame(first, second, third)
	})
	q := Query{Name: transportName(t, "corp.test."), Type: TypeAXFR}
	var seen []*Message
	err := Transfer(transportCtx(t, 5*time.Second), s.addr, q, key, transportCollect(&seen))
	if !errors.Is(err, ErrTSIG) {
		t.Errorf("error %v, want ErrTSIG", err)
	}
	transportCheckSeen(t, seen, 1)
}
