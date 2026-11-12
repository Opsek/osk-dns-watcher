package observe

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// session is what the queries of one check share: what each address said,
// and the count that queries are sent from. Its methods may run
// concurrently.
type session struct {
	o        *Observer
	deadline time.Time
	mu       sync.Mutex
	count    *int // exchanges left; nil: no count, as for the fan-out
	memo     map[memoKey]*memoEntry
	down     map[netip.AddrPort]queryOutcome // the failure of each address that is down
}

type memoKey struct {
	server netip.AddrPort
	name   string // dnswire.Name.Key
	typ    dnswire.Type
}

// memoEntry is the outcome of one question to one address. done is closed
// once out is set, so that a concurrent caller waits instead of asking again.
type memoEntry struct {
	done chan struct{}
	out  queryOutcome
}

// queryOutcome holds an answer to classify, or a failure, never both.
type queryOutcome struct {
	proof obs.Proof
	msg   *dnswire.Message
	fail  *obs.Failure
	// down: the address may not be asked, or gave no answer in time. Every
	// later question to it in the check gets this outcome, so that a dead
	// address costs one query timeout in a check, not one for each question.
	down bool
}

func (o *Observer) newSession(deadline time.Time) *session {
	return &session{
		o:        o,
		deadline: deadline,
		memo:     map[memoKey]*memoEntry{},
		down:     map[netip.AddrPort]queryOutcome{},
	}
}

// ask asks srv the question q. Each address hears each question at most
// once in a check: a repeated question, or any question to an address that
// is down, gets the earlier outcome. Exactly one of the message and the
// failure is non-nil.
func (s *session) ask(ctx context.Context, srv obs.Server, q dnswire.Question) (obs.Proof, *dnswire.Message, *obs.Failure) {
	q.Class = dnswire.ClassINET
	key := memoKey{server: srv.Addr, name: q.Name.Key(), typ: q.Type}
	s.mu.Lock()
	e, asked := s.memo[key]
	down, isDown := s.down[srv.Addr]
	if !asked && !isDown {
		e = &memoEntry{done: make(chan struct{})}
		s.memo[key] = e
	}
	s.mu.Unlock()
	switch {
	case asked:
		<-e.done
		return e.out.as(srv, q)
	case isDown:
		return down.as(srv, q)
	}

	e.out = s.query(ctx, srv, q)
	s.mu.Lock()
	switch {
	case e.out.down:
		s.down[srv.Addr] = e.out
	case e.out.fail != nil && e.out.fail.Reason == obs.ReasonBudget:
		// Nothing was sent, and another count may still send it.
		delete(s.memo, key)
	}
	s.mu.Unlock()
	close(e.done)
	return e.out.as(srv, q)
}

// as returns the outcome as the answer to srv and q: an earlier outcome may
// come from another host with the same address, or another question. For
// another question nothing was sent, and the detail names the one that was.
func (out queryOutcome) as(srv obs.Server, q dnswire.Question) (obs.Proof, *dnswire.Message, *obs.Failure) {
	p := out.proof
	p.Server, p.Question = srv, q
	if out.fail == nil {
		return p, out.msg, nil
	}
	f := *out.fail
	if asked := out.proof.Question; asked.Type != q.Type || !asked.Name.Equal(q.Name) {
		p.Sent = time.Time{}
		f.Detail = fmt.Sprintf("not sent: %v %v to this address failed earlier in the check: %s", asked.Name, asked.Type, f.Detail)
	}
	return p, nil, &f
}

// spendFrom makes later exchanges take one each from *count, and fail with
// budget when it is zero; nil takes nothing.
func (s *session) spendFrom(count *int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.count = count
}

func (s *session) isDown(a netip.AddrPort) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, down := s.down[a]
	return down
}

// query sends q to srv, and once more with the new server cookie when the
// server answers BADCOOKIE with one (RFC 7873 §5.3).
func (s *session) query(ctx context.Context, srv obs.Server, q dnswire.Question) queryOutcome {
	if !permitted(srv.Addr.Addr(), s.o.cfg.ExtraRanges) {
		p := obs.Proof{Server: srv, Question: q, Received: s.o.now()}
		detail := srv.Addr.Addr().String() + " is neither public nor in a permitted range"
		return queryOutcome{proof: p, fail: &obs.Failure{Reason: obs.ReasonNotPermitted, Detail: detail}, down: true}
	}
	out, newCookie := s.send(ctx, srv, q)
	if newCookie && out.msg.Rcode == rcodeBadCookie {
		out, _ = s.send(ctx, srv, q)
	}
	return out
}

// send makes one exchange with srv, within the count of the session and the
// address's rate limit. newCookie reports that the answer brought a server
// cookie other than the one sent.
func (s *session) send(ctx context.Context, srv obs.Server, q dnswire.Question) (out queryOutcome, newCookie bool) {
	p := obs.Proof{Server: srv, Question: q}
	fail := func(reason obs.Reason, detail string, down bool) (queryOutcome, bool) {
		p.Received = s.o.now()
		return queryOutcome{proof: p, fail: &obs.Failure{Reason: reason, Detail: detail}, down: down}, false
	}
	if !s.spend() {
		return fail(obs.ReasonBudget, "this part of the check has sent all the queries it may send", false)
	}
	now := s.o.now()
	sendAt := s.o.limit.reserve(srv.Addr, now)
	if sendAt.After(s.deadline) {
		return fail(obs.ReasonRateLimited, "no query slot for "+srv.Addr.String()+" before the deadline", true)
	}
	if err := s.wait(ctx, sendAt.Sub(now)); err != nil {
		return fail(obs.ReasonDeadline, "the check ended before the query could be sent: "+err.Error(), true)
	}

	cookie, sentCookie := s.o.cookies.get(srv.Addr)
	query := dnswire.Query{
		Name: q.Name,
		Type: q.Type,
		// The server must answer from its own data, never by recursion.
		RecursionDesired: false,
		// Signatures and denial records come along, as proof.
		DNSSECOK: true,
		Cookie:   cookie,
	}
	qctx, cancel := context.WithTimeout(ctx, s.o.cfg.QueryTimeout)
	defer cancel()
	p.Sent = s.o.now()
	resp, err := s.o.exchange(qctx, srv.Addr, query, false)
	if err != nil {
		reason, down := exchangeFailure(ctx, err)
		return fail(reason, err.Error(), down)
	}
	p.Wire, p.TCP = resp.Wire, resp.TCP
	stored, ok := s.o.cookies.accept(srv.Addr, cookie, resp.Msg)
	if !ok {
		return fail(obs.ReasonMalformed, "the DNS cookie of the answer is broken or not ours", false)
	}
	p.Received = s.o.now()
	return queryOutcome{proof: p, msg: resp.Msg}, stored != nil && !bytes.Equal(stored, sentCookie)
}

func (s *session) spend() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.count == nil {
		return true
	}
	if *s.count == 0 {
		return false
	}
	*s.count--
	return true
}

func (s *session) wait(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// exchangeFailure gives the reason for an error of Exchange, sent within
// the check's context ctx, and whether the address is down for the rest of
// the check. When a UDP wait ends after a bad datagram was dropped, the error
// wraps both the timeout and the bad datagram: the bad datagram is the
// finding, and the wait still costs the same for the next question. A wait
// cut by the end of the check is no sign of a dead server.
func exchangeFailure(ctx context.Context, err error) (reason obs.Reason, down bool) {
	waited := errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled)
	switch {
	case errors.Is(err, dnswire.ErrMalformed), errors.Is(err, dnswire.ErrMismatch):
		return obs.ReasonMalformed, waited
	case ctx.Err() != nil:
		return obs.ReasonDeadline, true
	case waited:
		return obs.ReasonTimeout, true
	default:
		return obs.ReasonNetwork, true
	}
}
