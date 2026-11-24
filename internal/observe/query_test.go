package observe

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// askClock is a clock that moves only when the test moves it.
type askClock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *askClock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *askClock) set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = t
}

// askCall is one call of the exchange seam.
type askCall struct {
	server      netip.AddrPort
	q           dnswire.Query
	tcp         bool
	deadline    time.Time
	hasDeadline bool
	at          time.Time // real time of the call
}

// askFake stands in for dnswire.Exchange and records every call.
type askFake struct {
	mu    sync.Mutex
	calls []askCall
	reply func(askCall) (*dnswire.Response, error)
}

func (f *askFake) exchange(ctx context.Context, server netip.AddrPort, q dnswire.Query, tcp bool) (*dnswire.Response, error) {
	dl, ok := ctx.Deadline()
	c := askCall{server: server, q: q, tcp: tcp, deadline: dl, hasDeadline: ok, at: time.Now()}
	c.q.Cookie = slices.Clone(q.Cookie)
	f.mu.Lock()
	f.calls = append(f.calls, c)
	reply := f.reply
	f.mu.Unlock()
	return reply(c)
}

func (f *askFake) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.calls)
}

func (f *askFake) call(t *testing.T, i int) askCall {
	t.Helper()
	f.mu.Lock()
	defer f.mu.Unlock()
	if i < 0 || i >= len(f.calls) {
		t.Fatalf("exchange was called %d times, want a call number %d", len(f.calls), i+1)
	}
	return f.calls[i]
}

// askObserver makes an Observer whose exchange is f and, when clock is not
// nil, whose time is clock.
func askObserver(t *testing.T, cfg Config, f *askFake, clock *askClock) *Observer {
	t.Helper()
	o, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	o.exchange = f.exchange
	if clock != nil {
		o.now = clock.now
	}
	return o
}

var askLab = []netip.Prefix{netip.MustParsePrefix("10.53.7.0/24")}

func askServer(t *testing.T, name, addr string) obs.Server {
	t.Helper()
	return obs.Server{Name: askName(t, name), Addr: netip.MustParseAddrPort(addr)}
}

// askWire writes m as a server would send it, without name compression.
func askWire(id uint16, m *dnswire.Message) []byte {
	flags := uint16(0x8000) | uint16(m.Rcode&0xf)
	for _, f := range []struct {
		set bool
		bit uint16
	}{{m.Authoritative, 0x0400}, {m.Truncated, 0x0200}, {m.RecursionDesired, 0x0100}, {m.RecursionAvailable, 0x0080}} {
		if f.set {
			flags |= f.bit
		}
	}
	additional := len(m.Additional)
	if m.EDNS != nil {
		additional++
	}
	be := binary.BigEndian
	b := be.AppendUint16(nil, id)
	b = be.AppendUint16(b, flags)
	for _, n := range []int{len(m.Question), len(m.Answer), len(m.Authority), additional} {
		b = be.AppendUint16(b, uint16(n))
	}
	for _, q := range m.Question {
		b = q.Name.AppendWire(b)
		b = be.AppendUint16(b, uint16(q.Type))
		b = be.AppendUint16(b, uint16(q.Class))
	}
	for _, s := range [][]dnswire.Record{m.Answer, m.Authority, m.Additional} {
		for _, r := range s {
			b = dnswire.AppendRecord(b, r)
		}
	}
	if e := m.EDNS; e != nil {
		var data []byte
		for _, o := range e.Options {
			data = be.AppendUint16(data, o.Code)
			data = be.AppendUint16(data, uint16(len(o.Data)))
			data = append(data, o.Data...)
		}
		b = append(b, 0) // the root owns the OPT record
		b = be.AppendUint16(b, uint16(dnswire.TypeOPT))
		b = be.AppendUint16(b, e.UDPSize)
		b = be.AppendUint32(b, uint32(m.Rcode>>4)<<24|uint32(e.Version)<<16|uint32(e.Flags))
		b = be.AppendUint16(b, uint16(len(data)))
		b = append(b, data...)
	}
	return b
}

// askResponse answers the question of c as Exchange would return it: the
// octets, and the message parsed from them.
func askResponse(t *testing.T, c askCall, r askReply, tcp bool) *dnswire.Response {
	t.Helper()
	q := dnswire.Question{Name: c.q.Name, Type: c.q.Type, Class: dnswire.ClassINET}
	wire := askWire(0x4d2, askMessage(q, r))
	m, err := dnswire.Parse(wire)
	if err != nil {
		t.Errorf("the test built an answer that does not parse: %v", err)
		return nil
	}
	return &dnswire.Response{Msg: m, Wire: wire, TCP: tcp}
}

// askAddress answers every question with one address record.
func askAddress(t *testing.T) func(askCall) (*dnswire.Response, error) {
	return func(c askCall) (*dnswire.Response, error) {
		a := dnswire.Record{Name: c.q.Name, Class: dnswire.ClassINET, TTL: 300,
			Data: dnswire.A{Addr: netip.MustParseAddr("10.53.7.81")}}
		return askResponse(t, c, askReply{answer: []dnswire.Record{a}}, false), nil
	}
}

// askDo calls ask and requires exactly one of message and failure.
func askDo(t *testing.T, ctx context.Context, s *session, srv obs.Server, q dnswire.Question) (obs.Proof, *dnswire.Message, *obs.Failure) {
	t.Helper()
	p, m, f := s.ask(ctx, srv, q)
	if (m == nil) == (f == nil) {
		t.Fatalf("ask %s %v at %v: message %v and failure %v, want exactly one", q.Name, q.Type, srv.Addr, m != nil, f)
	}
	return p, m, f
}

// askFailed requires a failure with the reason, and a proof that holds
// neither a sent time nor an answer when nothing went out.
func askFailed(t *testing.T, what string, p obs.Proof, f *obs.Failure, reason obs.Reason, sent bool) {
	t.Helper()
	switch {
	case f == nil:
		t.Errorf("%s: an answer, want failure %v", what, reason)
	case f.Reason != reason:
		t.Errorf("%s: failure %v (%q), want %v", what, f.Reason, f.Detail, reason)
	case p.Wire != nil || p.TCP:
		t.Errorf("%s: proof holds an answer of %d octets (TCP %v), want none", what, len(p.Wire), p.TCP)
	case p.Sent.IsZero() == sent:
		t.Errorf("%s: Sent %v, want it set: %v", what, p.Sent, sent)
	}
}

// askTarget requires the proof to name the server and question of this call.
func askTarget(t *testing.T, what string, p obs.Proof, srv obs.Server, q dnswire.Question) {
	t.Helper()
	if !p.Server.Name.Equal(srv.Name) || p.Server.Addr != srv.Addr {
		t.Errorf("%s: proof server %s %v, want %s %v", what, p.Server.Name, p.Server.Addr, srv.Name, srv.Addr)
	}
	if !p.Question.Name.Equal(q.Name) || p.Question.Type != q.Type || p.Question.Class != dnswire.ClassINET {
		t.Errorf("%s: proof question %s %v %v, want %s %v IN", what, p.Question.Name, p.Question.Type, p.Question.Class, q.Name, q.Type)
	}
}

func TestAskSendsQuery(t *testing.T) {
	base := time.Now()
	clock := &askClock{t: base}
	var resp *dnswire.Response
	f := &askFake{}
	f.reply = func(c askCall) (*dnswire.Response, error) {
		clock.set(base.Add(250 * time.Millisecond))
		resp = askResponse(t, c, askReply{answer: askRRs(t, "www.corp.test. 300 A 10.53.7.81")}, true)
		return resp, nil
	}
	o := askObserver(t, Config{ExtraRanges: askLab, QueryTimeout: 700 * time.Millisecond}, f, clock)
	s := o.newSession(base.Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)

	p, m, _ := askDo(t, context.Background(), s, srv, q)
	if f.count() != 1 {
		t.Fatalf("exchange called %d times, want 1", f.count())
	}
	c := f.call(t, 0)
	if c.server != srv.Addr || !c.q.Name.Equal(q.Name) || c.q.Type != q.Type {
		t.Errorf("sent %s %v to %v, want %s %v to %v", c.q.Name, c.q.Type, c.server, q.Name, q.Type, srv.Addr)
	}
	if c.q.RecursionDesired || c.q.CheckingDisabled || !c.q.DNSSECOK || c.tcp || c.q.IXFRSerial != 0 {
		t.Errorf("query RD %v CD %v DO %v IXFR serial %d, tcp %v; want RD 0, CD 0, DO 1, no serial, tcp false",
			c.q.RecursionDesired, c.q.CheckingDisabled, c.q.DNSSECOK, c.q.IXFRSerial, c.tcp)
	}
	if len(c.q.Cookie) != 8 {
		t.Errorf("first query to a server carries a cookie of %d octets, want the 8 of a client cookie", len(c.q.Cookie))
	}
	if !c.hasDeadline || c.deadline.Sub(c.at) > 700*time.Millisecond {
		t.Errorf("exchange context deadline %v (set %v), want at most the query timeout of 700ms after the call", c.deadline.Sub(c.at), c.hasDeadline)
	}

	askTarget(t, "answer", p, srv, q)
	if !p.Sent.Equal(base) || !p.Received.Equal(base.Add(250*time.Millisecond)) {
		t.Errorf("Sent %v Received %v, want the clock before (%v) and after (%v) the exchange",
			p.Sent, p.Received, base, base.Add(250*time.Millisecond))
	}
	if !bytes.Equal(p.Wire, resp.Wire) || !p.TCP {
		t.Errorf("proof holds %d octets with TCP %v, want the %d octets of the answer with TCP true", len(p.Wire), p.TCP, len(resp.Wire))
	}
	if !slices.Equal(askLines(m.Answer), askLines(resp.Msg.Answer)) {
		t.Errorf("message answer %q, want %q", askLines(m.Answer), askLines(resp.Msg.Answer))
	}
}

func TestAskUsesCallerContext(t *testing.T) {
	f := &askFake{reply: askAddress(t)}
	s := askObserver(t, Config{ExtraRanges: askLab, QueryTimeout: 700 * time.Millisecond}, f, nil).newSession(time.Now().Add(time.Minute))
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	parent, _ := ctx.Deadline()
	askDo(t, ctx, s, askServer(t, "ns1.corp.test.", "10.53.7.11:53"), askQuestion(t, "www.corp.test.", dnswire.TypeA))
	if c := f.call(t, 0); !c.hasDeadline || c.deadline.After(parent) {
		t.Errorf("exchange context deadline %v after the caller's %v, want the caller's context to bound the query", c.deadline, parent)
	}
}

func TestAskMapsErrors(t *testing.T) {
	malformed := fmt.Errorf("%w: 3 octets", dnswire.ErrMalformed)
	cases := []struct {
		name string
		err  error
		want obs.Reason
	}{
		{"malformed", malformed, obs.ReasonMalformed},
		{"mismatch over TCP", fmt.Errorf("%w: TCP answer from 10.53.7.11:53", dnswire.ErrMismatch), obs.ReasonMalformed},
		{"timeout after a dropped bad datagram",
			fmt.Errorf("read udp: %w; last dropped datagram: %w", context.DeadlineExceeded, malformed), obs.ReasonMalformed},
		{"timeout", fmt.Errorf("read udp 10.53.7.11:53: %w", context.DeadlineExceeded), obs.ReasonTimeout},
		{"canceled", fmt.Errorf("read udp 10.53.7.11:53: %w", context.Canceled), obs.ReasonTimeout},
		{"connection refused", &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}, obs.ReasonNetwork},
		{"anything else", errors.New("socket: too many open files"), obs.ReasonNetwork},
		{"no route", fmt.Errorf("%w to [fd53::11]:53: dial udp: connect: network is unreachable", dnswire.ErrNoRoute), obs.ReasonNoRoute},
	}
	for _, c := range cases {
		base := time.Now()
		f := &askFake{reply: func(askCall) (*dnswire.Response, error) { return nil, c.err }}
		o := askObserver(t, Config{ExtraRanges: askLab}, f, &askClock{t: base})
		srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
		p, _, fail := askDo(t, context.Background(), o.newSession(base.Add(time.Minute)), srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
		// Nothing leaves this machine when it has no route.
		askFailed(t, c.name, p, fail, c.want, c.want != obs.ReasonNoRoute)
		if fail != nil && !strings.Contains(fail.Detail, c.err.Error()) {
			t.Errorf("%s: Detail %q, want the error text %q", c.name, fail.Detail, c.err.Error())
		}
		if p.Received.IsZero() {
			t.Errorf("%s: Received is zero, want the time the query ended", c.name)
		}
	}
}

func TestAskRemembersTransportFailure(t *testing.T) {
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	same := askServer(t, "ns3.corp.test.", "10.53.7.11:53")
	other := askServer(t, "ns2.corp.test.", "10.53.7.12:53")
	q1 := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	q2 := askQuestion(t, "mail.corp.test.", dnswire.TypeAAAA)

	for _, c := range []struct {
		err  error
		want obs.Reason
	}{
		{fmt.Errorf("read: %w", context.DeadlineExceeded), obs.ReasonTimeout},
		{errors.New("connection refused"), obs.ReasonNetwork},
		{fmt.Errorf("%w to 10.53.7.11:53", dnswire.ErrNoRoute), obs.ReasonNoRoute},
	} {
		f := &askFake{reply: func(askCall) (*dnswire.Response, error) { return nil, c.err }}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		askDo(t, context.Background(), s, srv, q1)
		p, _, fail := askDo(t, context.Background(), s, same, q2)
		if f.count() != 1 {
			t.Errorf("%v: exchange called %d times, want 1: a later question to a failed address is not sent", c.want, f.count())
		}
		askFailed(t, c.want.String()+" remembered", p, fail, c.want, false)
		askTarget(t, c.want.String()+" remembered", p, same, q2)
		askDo(t, context.Background(), s, other, q1)
		if f.count() != 2 {
			t.Errorf("%v: exchange called %d times, want 2: another address is still asked", c.want, f.count())
		}
	}

	// A malformed answer is no transport failure: the address is asked
	// other questions, and only the same question reuses it.
	f := &askFake{}
	f.reply = func(c askCall) (*dnswire.Response, error) {
		if c.q.Name.Equal(q1.Name) {
			return nil, fmt.Errorf("%w: bad", dnswire.ErrMalformed)
		}
		return askAddress(t)(c)
	}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
	p, _, fail := askDo(t, context.Background(), s, srv, q1)
	askFailed(t, "malformed", p, fail, obs.ReasonMalformed, true)
	if _, m, _ := askDo(t, context.Background(), s, srv, q2); m == nil || f.count() != 2 {
		t.Errorf("after a malformed answer: exchange called %d times, want 2 and an answer to the other question", f.count())
	}
	p, _, fail = askDo(t, context.Background(), s, same, q1)
	askFailed(t, "malformed reused", p, fail, obs.ReasonMalformed, true)
	askTarget(t, "malformed reused", p, same, q1)
	if f.count() != 2 {
		t.Errorf("exchange called %d times, want 2: the same question is not sent again", f.count())
	}
}

// A wait that runs out after a bad datagram reads as malformed, but the
// address is down all the same: the next question to it is not sent, so it
// costs one query timeout in a check.
func TestAskRemembersTimeoutAfterBadDatagram(t *testing.T) {
	bad := fmt.Errorf("read udp: %w; last dropped datagram: %w", context.DeadlineExceeded,
		fmt.Errorf("%w: 3 octets", dnswire.ErrMalformed))
	f := &askFake{reply: func(askCall) (*dnswire.Response, error) { return nil, bad }}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	p, _, fail := askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	askFailed(t, "bad datagram, then no answer", p, fail, obs.ReasonMalformed, true)
	p, _, fail = askDo(t, context.Background(), s, srv, askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	askFailed(t, "next question", p, fail, obs.ReasonMalformed, false)
	if f.count() != 1 {
		t.Errorf("exchange called %d times, want 1: the address is down for the rest of the check", f.count())
	}
}

// Five servers of corp.test. are hosts of junk.test., whose one address
// sends junk and then nothing. With the query timeout and the deadline in the
// ratio 2s to 15s, that address costs one timeout, and ns1.corp.test. is
// still asked before the deadline.
func TestAskJunkAddressCostsOneTimeout(t *testing.T) {
	w := walkBase(t)
	corp := []string{"corp.test. 300 NS ns1.corp.test.", "ns1.corp.test. 300 A 10.0.1.1",
		"junk.test. 300 NS ns.junk.test.", "ns.junk.test. 300 A 10.0.8.1"}
	want := []string{"ns1.corp.test. 10.0.1.1:53 " + walkWWW}
	for i := 1; i <= 5; i++ {
		corp = append(corp, fmt.Sprintf("corp.test. 300 NS h%d.junk.test.", i))
		want = append(want, fmt.Sprintf("h%d.junk.test. - failure walk", i))
	}
	w.serve("10.0.0.2", "test.", walkTLD(corp...)...)
	w.handle("10.0.8.1", func(ctx context.Context, _ dnswire.Query) (*dnswire.Message, error) {
		<-ctx.Done()
		return nil, fmt.Errorf("read udp: %w; last dropped datagram: %w", ctx.Err(), fmt.Errorf("%w: junk", dnswire.ErrMalformed))
	})
	o := walkObserver(t, w, &walkClock{}, 200*time.Millisecond)
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), 2*time.Second)
	walkWant(t, "answers", walkAnswers(ob.Answers), want)
	if n := w.count("10.0.8.1", "", 0); n != 1 {
		t.Errorf("the junk address was asked %d times, want once", n)
	}
}

// The walk reaches corp.test. 500ms into a check whose deadline is 750ms,
// and both servers answer A in a second. Their queries are sent and then cut
// by the deadline of the check, not by their own timeout: that is no sign of
// a dead server, so the reason is deadline, and Sent stays set.
func TestAskQueryCutByCheckDeadline(t *testing.T) {
	w := walkBase(t)
	slow := func(server netip.AddrPort, d time.Duration, typ dnswire.Type) walkHandler {
		return func(ctx context.Context, q dnswire.Query) (*dnswire.Message, error) {
			if typ == 0 || q.Type == typ {
				select {
				case <-time.After(d):
				case <-ctx.Done():
					return nil, fmt.Errorf("read udp: %w", ctx.Err())
				}
			}
			return w.answer(server, q), nil
		}
	}
	w.handle("10.0.0.1", slow(walkAddr(t, "10.0.0.1"), 500*time.Millisecond, 0))
	for _, a := range []string{"10.0.1.1", "10.0.1.2"} {
		w.handle(a, slow(walkAddr(t, a), time.Second, dnswire.TypeA))
	}
	o := walkObserver(t, w, &walkClock{}, 10*time.Second)
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Second)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{
		"ns1.corp.test. 10.0.1.1:53 failure deadline",
		"ns2.corp.test. 10.0.1.2:53 failure deadline",
	})
	for _, a := range ob.Answers {
		if a.Sent.IsZero() || a.Wire != nil {
			t.Errorf("%v: Sent %v, Wire %d octets; want Sent set and no Wire", a.Server.Addr, a.Sent, len(a.Wire))
		}
	}
}

// A failure replayed for another question shows that this question was not
// sent, and names the one that was; the same question replayed keeps the time
// it was sent.
func TestAskReplayForAnotherQuestionIsNotSent(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: func(askCall) (*dnswire.Response, error) {
		return nil, fmt.Errorf("read udp: %w", context.DeadlineExceeded)
	}}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, &askClock{t: base}).newSession(base.Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	www, mail := askQuestion(t, "www.corp.test.", dnswire.TypeA), askQuestion(t, "mail.corp.test.", dnswire.TypeAAAA)
	first, _, _ := askDo(t, context.Background(), s, srv, www)

	p, _, fail := askDo(t, context.Background(), s, srv, mail)
	askFailed(t, "another question", p, fail, obs.ReasonTimeout, false)
	askTarget(t, "another question", p, srv, mail)
	if fail != nil && !strings.Contains(fail.Detail, "www.corp.test. A") {
		t.Errorf("Detail %q does not name the question that was sent, www.corp.test. A", fail.Detail)
	}
	p, _, _ = askDo(t, context.Background(), s, askServer(t, "ns3.corp.test.", "10.53.7.11:53"), www)
	if first.Sent.IsZero() || !p.Sent.Equal(first.Sent) {
		t.Errorf("the same question replayed: Sent %v, want %v, when it was sent", p.Sent, first.Sent)
	}
}

// No query slot before the deadline holds for every later question to the
// address in the check: none of them takes a query from the budget.
func TestAskRemembersRateLimited(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1, RateInterval: time.Hour}, f, &askClock{t: base})
	s := o.newSession(base.Add(time.Minute))
	left := 100
	s.spendFrom(&left)
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	p, _, fail := askDo(t, context.Background(), s, srv, askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	askFailed(t, "no slot", p, fail, obs.ReasonRateLimited, false)
	counted := left
	for i := range 5 {
		p, _, fail = askDo(t, context.Background(), s, srv, askQuestion(t, fmt.Sprintf("n%d.corp.test.", i), dnswire.TypeA))
		askFailed(t, "later question", p, fail, obs.ReasonRateLimited, false)
	}
	if left != counted {
		t.Errorf("%d queries left after five more questions, want %d: the address has no slot", left, counted)
	}
}

func TestAskMemo(t *testing.T) {
	base := time.Now()
	clock := &askClock{t: base}
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab}, f, clock)
	s := o.newSession(base.Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	same := askServer(t, "ns3.corp.test.", "10.53.7.11:53")
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)

	first, _, _ := askDo(t, context.Background(), s, srv, q)
	clock.set(base.Add(time.Second))
	p, m, _ := askDo(t, context.Background(), s, same, q)
	if f.count() != 1 {
		t.Fatalf("exchange called %d times, want 1: one address is asked one question once", f.count())
	}
	askTarget(t, "memo", p, same, q)
	if !bytes.Equal(p.Wire, first.Wire) || !p.Sent.Equal(first.Sent) || m == nil || len(m.Answer) != 1 {
		t.Errorf("memo gave %d octets sent at %v, want the stored %d octets sent at %v", len(p.Wire), p.Sent, len(first.Wire), first.Sent)
	}

	askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeAAAA))
	askDo(t, context.Background(), s, askServer(t, "ns2.corp.test.", "10.53.7.12:53"), q)
	if f.count() != 3 {
		t.Errorf("exchange called %d times, want 3: another type and another address are asked", f.count())
	}
	askDo(t, context.Background(), o.newSession(base.Add(time.Minute)), srv, q)
	if f.count() != 4 {
		t.Errorf("exchange called %d times, want 4: a new check asks again", f.count())
	}
}

func TestAskNotPermitted(t *testing.T) {
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab}, f, nil)
	s := o.newSession(time.Now().Add(time.Minute))
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	for _, a := range []string{"192.0.2.1:53", "127.0.0.1:53", "10.53.8.11:53", "172.16.0.1:53", "[::1]:53",
		"[fe80::1]:53", "[2001:db8::1]:53", "[fd53:0:0:7::11]:53", "[::ffff:10.53.7.11]:53", "[::ffff:8.8.8.8]:53"} {
		srv := askServer(t, "ns1.corp.test.", a)
		p, _, fail := askDo(t, context.Background(), s, srv, q)
		askFailed(t, a, p, fail, obs.ReasonNotPermitted, false)
		askTarget(t, a, p, srv, q)
	}
	if f.count() != 0 {
		t.Fatalf("exchange called %d times for addresses that are not permitted, want 0", f.count())
	}
	for _, a := range []string{"10.53.7.11:53", "8.8.8.8:53", "[2001:4860:4860::8888]:53"} {
		askDo(t, context.Background(), s, askServer(t, "ns1.corp.test.", a), q)
	}
	if f.count() != 3 {
		t.Errorf("exchange called %d times, want 3: a public address and one of an extra range are asked", f.count())
	}
}

// The session sends from the count it is given. Neither a refused address
// nor a memo hit takes from it. A question refused for lack of queries was
// not sent, so it is sent when a count allows it; with no count, as in the
// fan-out, nothing is counted.
func TestAskBudget(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: askAddress(t)}
	// The burst is large, so that the rate limit plays no part.
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1000}, f, &askClock{t: base})
	s := o.newSession(base.Add(time.Minute))
	left := 8
	s.spendFrom(&left)
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	name := func(i int) dnswire.Question { return askQuestion(t, fmt.Sprintf("n%d.corp.test.", i), dnswire.TypeA) }

	askDo(t, context.Background(), s, askServer(t, "ns9.corp.test.", "192.0.2.1:53"), name(0))
	for i := range 8 {
		if _, m, _ := askDo(t, context.Background(), s, srv, name(i)); m == nil {
			t.Fatalf("query %d gave no answer", i+1)
		}
		askDo(t, context.Background(), s, srv, name(0))
	}
	if f.count() != 8 || left != 0 {
		t.Fatalf("exchange called %d times, %d queries left; want 8 and none", f.count(), left)
	}
	p, _, fail := askDo(t, context.Background(), s, srv, name(8))
	askFailed(t, "query 9", p, fail, obs.ReasonBudget, false)
	p, _, fail = askDo(t, context.Background(), s, askServer(t, "ns2.corp.test.", "10.53.7.12:53"), name(0))
	askFailed(t, "query 9 to another address", p, fail, obs.ReasonBudget, false)
	if f.count() != 8 {
		t.Errorf("exchange called %d times, want 8", f.count())
	}

	other := 1
	s.spendFrom(&other)
	if _, m, _ := askDo(t, context.Background(), s, srv, name(8)); m == nil || f.count() != 9 || other != 0 {
		t.Errorf("with another count: exchange called %d times, %d left; want 9, none and an answer", f.count(), other)
	}
	s.spendFrom(nil)
	for i := 9; i < 20; i++ {
		if _, m, _ := askDo(t, context.Background(), s, srv, name(i)); m == nil {
			t.Fatalf("query %d without a count gave no answer", i+1)
		}
	}
}

func TestAskBudgetCountsCookieRetry(t *testing.T) {
	base := time.Now()
	f := &askFake{}
	f.reply = func(c askCall) (*dnswire.Response, error) {
		server := binary.BigEndian.AppendUint64(nil, uint64(f.count())) // new at each call
		return askResponse(t, c, askReply{rcode: 23, noAA: true, options: []dnswire.Option{askEcho(c, server)}}, false), nil
	}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1000}, f, &askClock{t: base})
	s := o.newSession(base.Add(time.Minute))
	left := 16
	s.spendFrom(&left)
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	for i := range 8 {
		if _, m, _ := askDo(t, context.Background(), s, srv, askQuestion(t, fmt.Sprintf("n%d.corp.test.", i), dnswire.TypeA)); m == nil {
			t.Fatalf("question %d gave no answer", i+1)
		}
		if f.count() != 2*(i+1) {
			t.Fatalf("after question %d exchange was called %d times, want %d: each answer asks for one retry", i+1, f.count(), 2*(i+1))
		}
	}
	p, _, fail := askDo(t, context.Background(), s, srv, askQuestion(t, "n8.corp.test.", dnswire.TypeA))
	askFailed(t, "question 9", p, fail, obs.ReasonBudget, false)
	if f.count() != 16 {
		t.Errorf("exchange called %d times, want 16", f.count())
	}
}

func TestAskRateLimited(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1, RateInterval: time.Hour}, f, &askClock{t: base})
	s := o.newSession(base.Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")

	// A query that waited for its slot instead would end with the context.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	askDo(t, ctx, s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	p, _, fail := askDo(t, ctx, s, srv, askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	askFailed(t, "second query within the hour", p, fail, obs.ReasonRateLimited, false)
	if f.count() != 1 {
		t.Errorf("exchange called %d times, want 1", f.count())
	}
	askDo(t, context.Background(), s, askServer(t, "ns2.corp.test.", "10.53.7.12:53"), askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	if f.count() != 2 {
		t.Errorf("exchange called %d times, want 2: another address has its own limit", f.count())
	}
}

func TestAskWaitsForRateSlot(t *testing.T) {
	const interval = 150 * time.Millisecond
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1, RateInterval: interval}, f, nil)
	s := o.newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	var sent []time.Time
	for _, n := range []string{"a.corp.test.", "b.corp.test.", "c.corp.test."} {
		p, _, _ := askDo(t, context.Background(), s, srv, askQuestion(t, n, dnswire.TypeA))
		sent = append(sent, p.Sent)
	}
	// Timers do not fire early; the margin covers the clock reads around them.
	for i := 1; i < 3; i++ {
		if gap := f.call(t, i).at.Sub(f.call(t, i-1).at); gap < interval-10*time.Millisecond {
			t.Errorf("query %d went %v after the one before, want at least %v", i+1, gap, interval)
		}
		if gap := sent[i].Sub(sent[i-1]); gap < interval-10*time.Millisecond {
			t.Errorf("Sent of query %d is %v after the one before, want at least %v", i+1, gap, interval)
		}
	}
	start := time.Now()
	askDo(t, context.Background(), s, askServer(t, "ns2.corp.test.", "10.53.7.12:53"), askQuestion(t, "a.corp.test.", dnswire.TypeA))
	if wait := time.Since(start); wait >= interval {
		t.Errorf("another address waited %v, want no wait", wait)
	}
}

func TestAskWaitEndsWithContext(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1, RateInterval: time.Hour}, f, &askClock{t: base})
	s := o.newSession(base.Add(2 * time.Hour))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	start := time.Now()
	p, _, fail := askDo(t, ctx, s, srv, askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	askFailed(t, "wait cut by the context", p, fail, obs.ReasonDeadline, false)
	if d := time.Since(start); d > 5*time.Second {
		t.Errorf("ask returned after %v, want soon after the context ended", d)
	}
	if f.count() != 1 {
		t.Errorf("exchange called %d times, want 1", f.count())
	}
}

func TestAskFormErrNotRetried(t *testing.T) {
	f := &askFake{}
	f.reply = func(c askCall) (*dnswire.Response, error) {
		return askResponse(t, c, askReply{rcode: 1, noAA: true}, false), nil
	}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	_, m, _ := askDo(t, context.Background(), s, askServer(t, "ns1.corp.test.", "10.53.7.11:53"), q)
	if f.count() != 1 {
		t.Errorf("exchange called %d times, want 1: FORMERR is not asked again without EDNS", f.count())
	}
	if m != nil {
		askCheck(t, "FORMERR", classify(obs.KindRecords, askName(t, "corp.test."), q, m),
			askWant{kind: "failure", reason: obs.ReasonRcode, detail: []string{"FORMERR"}})
	}
}

func TestAskNeverAsksOverTCPItself(t *testing.T) {
	for _, tcp := range []bool{true, false} {
		f := &askFake{}
		f.reply = func(c askCall) (*dnswire.Response, error) {
			return askResponse(t, c, askReply{tc: true}, tcp), nil
		}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		q := askQuestion(t, "big.corp.test.", dnswire.TypeTXT)
		p, m, _ := askDo(t, context.Background(), s, askServer(t, "ns1.corp.test.", "10.53.7.11:53"), q)
		if f.count() != 1 || f.call(t, 0).tcp {
			t.Errorf("TC answer with TCP %v: exchange called %d times, first with tcp %v; want once, without tcp", tcp, f.count(), f.call(t, 0).tcp)
		}
		if p.TCP != tcp || m == nil || !m.Truncated {
			t.Errorf("TC answer with TCP %v: proof TCP %v, message %v; want the truncated answer as it came", tcp, p.TCP, m != nil)
			continue
		}
		askCheck(t, "truncated", classify(obs.KindRecords, askName(t, "corp.test."), q, m), askWant{kind: "failure", reason: obs.ReasonTruncated})
	}
}

func TestAskConcurrent(t *testing.T) {
	f := &askFake{reply: askAddress(t)}
	s := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1000}, f, nil).newSession(time.Now().Add(time.Minute))
	var wg sync.WaitGroup
	for i := range 50 {
		srv := askServer(t, "ns.corp.test.", fmt.Sprintf("10.53.7.%d:53", 11+i%5))
		q := askQuestion(t, fmt.Sprintf("n%d.corp.test.", i), dnswire.TypeA)
		wg.Go(func() {
			p, m, f := s.ask(context.Background(), srv, q)
			if m == nil || f != nil {
				t.Errorf("query %d: failure %v, want an answer", i, f)
			}
			askTarget(t, fmt.Sprintf("query %d", i), p, srv, q)
		})
	}
	wg.Wait()
	if f.count() != 50 {
		t.Errorf("exchange called %d times, want 50", f.count())
	}
}
