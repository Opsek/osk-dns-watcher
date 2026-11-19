package observe

import (
	"context"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// An address that is no address, or that is tied to one link by a zone, is
// never public, even when it lies in the global unicast block.
func TestPublicRefusesInvalidAndZoned(t *testing.T) {
	if public(netip.Addr{}) {
		t.Errorf("the zero address is public")
	}
	for _, s := range []string{"2606:4700::1111%eth0", "2001:4860:4860::8888%lo0"} {
		if a := netip.MustParseAddr(s); public(a) {
			t.Errorf("%s is public, want an address with a zone refused", s)
		}
	}
	if !public(netip.MustParseAddr("2606:4700::1111")) {
		t.Errorf("2606:4700::1111 is not public")
	}
}

// Two hosts at one address are asked once; a second address of a host comes
// after the first address of every host.
func TestUniqueAddrsDropsRepeatedAddress(t *testing.T) {
	server := func(host, addr string) obs.Server {
		return obs.Server{Name: walkName(t, host), Addr: walkAddr(t, addr)}
	}
	got := uniqueAddrs([]obs.Server{
		server("a.corp.test.", "10.0.1.1"),
		server("b.corp.test.", "10.0.1.1"),
		server("a.corp.test.", "10.0.1.2"),
		{Name: walkName(t, "c.corp.test.")},
	})
	var lines []string
	for _, s := range got {
		lines = append(lines, walkServer(s))
	}
	walkWant(t, "servers", lines, []string{"a.corp.test. 10.0.1.1:53", "a.corp.test. 10.0.1.2:53"})
}

// obmCookieSession makes a session whose first answer gives the server
// cookie s1 and whose later answers are reply(call); it returns the session
// and the fake, which has seen one call.
func obmCookieSession(t *testing.T, reply func(c askCall) (*dnswire.Response, error)) (*session, *askFake, obs.Server) {
	t.Helper()
	s1 := []byte("server cookie 01")
	f := &askFake{}
	f.reply = func(c askCall) (*dnswire.Response, error) {
		if c.q.Name.String() == "a.corp.test." {
			return askCookieReply(t, func(c askCall) []dnswire.Option { return []dnswire.Option{askEcho(c, s1)} })(c)
		}
		return reply(c)
	}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	askDo(t, context.Background(), s, srv, askQuestion(t, "a.corp.test.", dnswire.TypeA))
	return s, f, srv
}

// BADCOOKIE is asked again only when the answer brought a server cookie
// other than the one that was sent.
func TestAskBadCookieNotRetriedWithoutNewCookie(t *testing.T) {
	s1 := []byte("server cookie 01")
	for _, tc := range []struct {
		name    string
		options func(c askCall) []dnswire.Option
	}{
		{"no cookie in the answer", func(askCall) []dnswire.Option { return nil }},
		{"the cookie that was sent", func(c askCall) []dnswire.Option { return []dnswire.Option{askEcho(c, s1)} }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, f, srv := obmCookieSession(t, func(c askCall) (*dnswire.Response, error) {
				return askResponse(t, c, askReply{rcode: 23, noAA: true, options: tc.options(c)}, false), nil
			})
			_, m, _ := askDo(t, context.Background(), s, srv, askQuestion(t, "b.corp.test.", dnswire.TypeA))
			if f.count() != 2 || m == nil || m.Rcode != 23 {
				t.Errorf("exchange called %d times, want 2 (one for each question) and the BADCOOKIE answer", f.count())
			}
		})
	}
}

// A failure that a later question to the same address must not repeat: the
// address is remembered as down, so the second question is not sent.
func obmNotSentAgain(t *testing.T, what string, s *session, srv obs.Server, f *askFake, calls int) {
	t.Helper()
	// A deadline of its own: a question that is wrongly sent waits for the rate limit.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	p, _, fail := askDo(t, ctx, s, srv, askQuestion(t, "second.corp.test.", dnswire.TypeA))
	if fail == nil || !strings.Contains(fail.Detail, "failed earlier in the check") {
		t.Errorf("%s: a second question gave %+v, want the earlier failure replayed", what, fail)
	}
	if !p.Sent.IsZero() || f.count() != calls {
		t.Errorf("%s: second question sent at %v, exchange called %d times, want nothing sent and %d calls", what, p.Sent, f.count(), calls)
	}
}

func TestAskRemembersAddressThatMayNotBeAsked(t *testing.T) {
	f := &askFake{reply: askAddress(t)}
	s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "192.0.2.1:53")
	askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	obmNotSentAgain(t, "not permitted", s, srv, f, 0)
}

func TestAskRemembersWaitCutByContext(t *testing.T) {
	base := time.Now()
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab, RateBurst: 1, RateInterval: time.Hour}, f, &askClock{t: base})
	s := o.newSession(base.Add(2 * time.Hour))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	askDo(t, context.Background(), s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, fail := askDo(t, ctx, s, srv, askQuestion(t, "mail.corp.test.", dnswire.TypeA))
	if fail == nil || fail.Reason != obs.ReasonDeadline {
		t.Fatalf("wait cut by the context gave %+v, want deadline", fail)
	}
	obmNotSentAgain(t, "wait cut", s, srv, f, 1)
}

func TestAskRemembersExchangeCutByContext(t *testing.T) {
	f := &askFake{}
	o := askObserver(t, Config{ExtraRanges: askLab, QueryTimeout: time.Minute}, f, nil)
	o.exchange = func(ctx context.Context, _ netip.AddrPort, _ dnswire.Query, _ bool) (*dnswire.Response, error) {
		f.mu.Lock()
		f.calls = append(f.calls, askCall{})
		f.mu.Unlock()
		<-ctx.Done()
		return nil, ctx.Err()
	}
	s := o.newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	_, _, fail := askDo(t, ctx, s, srv, askQuestion(t, "www.corp.test.", dnswire.TypeA))
	if fail == nil || fail.Reason != obs.ReasonDeadline {
		t.Fatalf("exchange cut by the context gave %+v, want deadline", fail)
	}
	obmNotSentAgain(t, "exchange cut", s, srv, f, 1)
}

// obmWalkFailures counts the entries of walk that are failures of server addr.
func obmWalkFailures(walk []obs.Answer, addr string) int {
	n := 0
	for _, e := range walk {
		if e.Server.Addr == netip.MustParseAddrPort(addr) && strings.HasPrefix(walkCase(e.Result), "failure") {
			n++
		}
	}
	return n
}

// A server that cannot be asked is in the Walk as a failure.
func TestWalkLogsFailedAsk(t *testing.T) {
	w := walkBase(t)
	for _, a := range []string{"10.0.1.1", "10.0.1.2"} {
		delete(w.zones, walkAddr(t, a))
	}
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	for _, a := range []string{"10.0.1.1:53", "10.0.1.2:53"} {
		if n := obmWalkFailures(ob.Walk, a); n != 1 {
			t.Errorf("Walk holds %d failures of %s, want 1: %q", n, a, walkAnswers(ob.Walk))
		}
	}
}

// A server that says the name does not exist ends the walk; the other
// servers of the zone are not asked for the same name.
func TestWalkNoNameEndsWalk(t *testing.T) {
	w := walkBase(t)
	walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "missing.corp.test.", dnswire.TypeA), time.Minute)
	n := 0
	for _, a := range []string{"10.0.1.1", "10.0.1.2"} {
		n += w.count(a, "missing.corp.test.", dnswire.TypeNS)
	}
	if n != 1 {
		t.Errorf("the walk asked %d servers of corp.test. for missing.corp.test. NS, want 1", n)
	}
}

// obmAddressList serves, from the root, the zone big. with n addresses for
// its hosts, 16 for each. The first can be asked and never answers; the rest
// lie in 127.0.0.0/8, which may not be asked. Asking each costs one walk step
// and, for the first, one query.
func obmAddressList(w *walkWorld, n int) {
	var root []string
	for i := range n {
		host, addr := fmt.Sprintf("h%02d.big.", i/16+1), fmt.Sprintf("127.0.%d.%d", i/16+1, i%16+1)
		if i == 0 {
			addr = "10.0.9.9"
		}
		if i%16 == 0 {
			root = append(root, "big. 300 NS "+host)
		}
		root = append(root, host+" 300 A "+addr)
	}
	w.serve("10.0.0.1", ".", root...)
}

// The walk of one check has 128 steps. Each address asked takes one, the
// first question to the root takes one, and so does a cut taken from the
// cache, whose referral is logged again.
func TestWalkStepBound(t *testing.T) {
	big := walkRecordsKey(t, "big.", "www.big.", dnswire.TypeA)
	for _, tc := range []struct {
		addrs  int
		failed bool
	}{{127, false}, {128, true}} {
		for _, run := range []string{"from the root", "from the cache"} {
			t.Run(fmt.Sprintf("%d addresses %s", tc.addrs, run), func(t *testing.T) {
				w := walkNewWorld(t)
				obmAddressList(w, tc.addrs)
				o := walkObserver(t, w, &walkClock{}, time.Second)
				ob := walkRun(t, o, big, time.Minute)
				if run == "from the cache" {
					ob = walkRun(t, o, big, time.Minute)
				}
				walked := len(ob.Answers) == 1 && !ob.Answers[0].Server.Addr.IsValid() &&
					walkFailure(ob.Answers[0].Result).Reason == obs.ReasonWalk
				if walked != tc.failed {
					t.Errorf("walk failed %v, want %v: %q", walked, tc.failed, walkAnswers(ob.Answers))
				}
			})
		}
	}
}

// The proof of a cut taken from the cache is logged once in a check, also
// when a sub-walk starts at the same cut.
func TestWalkCachedCutShownOnceForSubWalk(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.1.1 10.0.1.2", "corp.test.", append([]string{
		"a.corp.test. 300 NS ns.y.corp.test.",
		"y.corp.test. 300 NS ns.z.corp.test.",
		"ns.z.corp.test. 300 A 10.0.3.2",
	}, walkCorpZone...)...)
	w.serve("10.0.3.1", "a.corp.test.", "www.a.corp.test. 300 A 10.9.0.90")
	w.serve("10.0.3.2", "y.corp.test.", "ns.y.corp.test. 300 A 10.0.3.1")
	o := walkObserver(t, w, &walkClock{}, time.Second)
	walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	ob := walkRun(t, o, walkRecordsKey(t, "corp.test.", "www.a.corp.test.", dnswire.TypeA), time.Minute)
	walkWant(t, "answers", walkAnswers(ob.Answers), []string{"ns.y.corp.test. 10.0.3.1:53 records www.a.corp.test. 300 IN A 10.9.0.90"})
	shown := 0
	for _, e := range ob.Walk {
		if strings.HasPrefix(walkCase(e.Result), "records corp.test. ") {
			shown++
		}
	}
	if shown != 1 {
		t.Errorf("Walk holds the referral of corp.test. %d times, want once: %q", shown, walkAnswers(ob.Walk))
	}
}

// A cut whose host list is incomplete because a sub-walk ran out of walk
// steps is not cached.
func TestWalkStepsSpentSubWalkNotCached(t *testing.T) {
	w := walkBase(t)
	tld := []string{"corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.big.test.", "ns1.corp.test. 300 A 10.0.1.1"}
	for i := range 128 {
		host, addr := fmt.Sprintf("h%02d.big.test.", i/16+1), fmt.Sprintf("127.0.%d.%d", i/16+1, i%16+1)
		if i == 0 {
			addr = "10.0.9.9"
		}
		if i%16 == 0 {
			tld = append(tld, "big.test. 300 NS "+host)
		}
		tld = append(tld, host+" 300 A "+addr)
	}
	w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
	clock := &walkClock{}
	o := walkObserver(t, w, clock, time.Second)
	www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	walkRun(t, o, www, time.Minute)
	clock.set(time.Second / 2)
	if _, first := walkStartAt(t, o, w, www, time.Minute); first != "10.0.0.2" {
		t.Errorf("the next check starts at %s, want the server of test.", first)
	}
}

// An address that is down is asked again, and logged again, for another
// zone; for a zone where its failure is logged already it is left out.
func TestWalkDownAddressLoggedOncePerZone(t *testing.T) {
	w := walkBase(t)
	w.serve("10.0.0.1", ".", "test. 300 NS ns.test.", "ns.test. 300 A 10.0.0.2",
		"p. 300 NS d1.p.", "d1.p. 300 A 10.0.9.9", "q. 300 NS d2.q.", "d2.q. 300 A 10.0.9.9")
	w.serve("10.0.0.2", "test.", walkTLD("corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns.p.", "corp.test. 300 NS ns.q.",
		"ns1.corp.test. 300 A 10.0.1.1")...)
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	if n := obmWalkFailures(ob.Walk, "10.0.9.9:53"); n != 2 {
		t.Errorf("Walk holds %d failures of 10.0.9.9, want 2 (one for each zone): %q", n, walkAnswers(ob.Walk))
	}
}

// The cut of a referral expires with the smallest TTL of the addresses of
// its hosts, whatever their order.
func TestWalkCacheExpiresWithSmallestAddressTTL(t *testing.T) {
	for _, order := range [][2]int{{30, 3000}, {3000, 30}} {
		t.Run(fmt.Sprint(order), func(t *testing.T) {
			w := walkBase(t)
			w.serve("10.0.0.2", "test.", walkTLD("corp.test. 3000 NS ns1.corp.test.",
				fmt.Sprintf("ns1.corp.test. %d A 10.0.1.1", order[0]), fmt.Sprintf("ns1.corp.test. %d A 10.0.1.2", order[1]))...)
			clock := &walkClock{}
			o := walkObserver(t, w, clock, time.Second)
			www := walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
			walkRun(t, o, www, time.Hour)
			clock.set(time.Minute)
			if _, first := walkStartAt(t, o, w, www, time.Hour); first != "10.0.0.2" {
				t.Errorf("a minute later the walk starts at %s, want the server of test.: the address record lives 30s", first)
			}
		})
	}
}

// A sub-walk that has sent all its queries starts no nested sub-walk: its
// only question would fail for lack of queries and show as a failure in the
// Walk of an address that was never asked. Here the 16th query of the
// sub-walk for the glueless host of corp.test. brings a referral whose
// host has no glue either.
func TestWalkSpentSubWalkStartsNoNestedOne(t *testing.T) {
	w := walkBase(t)
	cut := func(i int) string { // d<i>.….d1.test.
		name := "test."
		for j := 1; j <= i; j++ {
			name = fmt.Sprintf("d%d.%s", j, name)
		}
		return name
	}
	tld := []string{"corp.test. 300 NS ns1.corp.test.", "corp.test. 300 NS ns." + cut(16), "ns1.corp.test. 300 A 10.0.1.1",
		"d1.test. 300 NS ns.d1.test.", "ns.d1.test. 300 A 10.7.1.1"}
	w.serve("10.0.0.2", "test.", walkTLD(tld...)...)
	for i := 1; i <= 15; i++ {
		next := []string{cut(i+1) + " 300 NS ns." + cut(i+1), fmt.Sprintf("ns.%s 300 A 10.7.%d.1", cut(i+1), i+1)}
		if i == 15 {
			next = []string{cut(16) + " 300 NS ns.other.test."}
		}
		w.serve(fmt.Sprintf("10.7.%d.1", i), cut(i), next...)
	}
	ob := walkRun(t, walkObserver(t, w, &walkClock{}, time.Second), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), time.Minute)
	for _, e := range ob.Walk {
		if walkCase(e.Result) == "failure budget" {
			t.Errorf("Walk holds a failure for lack of queries: %q", walkAnswers(ob.Walk))
			break
		}
	}
	if n := w.count("10.7.15.1", "", dnswire.TypeNS); n != 1 {
		t.Errorf("the 15th zone was asked %d times, want 1: the sub-walk did reach its 16th query", n)
	}
}
