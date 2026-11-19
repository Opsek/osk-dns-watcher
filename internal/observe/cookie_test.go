package observe

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

func askCookie(data []byte) dnswire.Option { return dnswire.Option{Code: 10, Data: data} }

// askEcho is the cookie option of a server that knows the client: the
// client cookie of the query, then server.
func askEcho(c askCall, server []byte) dnswire.Option {
	return askCookie(append(slices.Clone(c.q.Cookie[:min(8, len(c.q.Cookie))]), server...))
}

// askCookieReply answers with an address record and the cookie options
// that options makes from the call.
func askCookieReply(t *testing.T, options func(askCall) []dnswire.Option) func(askCall) (*dnswire.Response, error) {
	return func(c askCall) (*dnswire.Response, error) {
		a := dnswire.Record{Name: c.q.Name, Class: dnswire.ClassINET, TTL: 300,
			Data: dnswire.A{Addr: netip.MustParseAddr("10.53.7.81")}}
		return askResponse(t, c, askReply{answer: []dnswire.Record{a}, options: options(c)}, false), nil
	}
}

func askCat(parts ...[]byte) []byte { return bytes.Join(parts, nil) }

func TestAskClientCookie(t *testing.T) {
	f := &askFake{reply: askAddress(t)}
	o := askObserver(t, Config{ExtraRanges: askLab}, f, nil)
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	ask := func(o *Observer, addr string) []byte {
		t.Helper()
		askDo(t, context.Background(), o.newSession(time.Now().Add(time.Minute)), askServer(t, "ns.corp.test.", addr), q)
		c := f.call(t, f.count()-1)
		if len(c.q.Cookie) != 8 {
			t.Fatalf("query to %s carries a cookie of %d octets, want a client cookie of 8", addr, len(c.q.Cookie))
		}
		return c.q.Cookie
	}
	first := ask(o, "10.53.7.11:53")
	if bytes.Equal(first, make([]byte, 8)) {
		t.Errorf("client cookie is all zero, want random octets")
	}
	if again := ask(o, "10.53.7.11:53"); !bytes.Equal(again, first) {
		t.Errorf("client cookie of a server changed between two checks: %x, then %x", first, again)
	}
	for _, addr := range []string{"10.53.7.12:53", "10.53.7.11:5353"} {
		if other := ask(o, addr); bytes.Equal(other, first) {
			t.Errorf("%s got the client cookie of 10.53.7.11:53, want its own", addr)
		}
	}
	if other := ask(askObserver(t, Config{ExtraRanges: askLab}, f, nil), "10.53.7.11:53"); bytes.Equal(other, first) {
		t.Errorf("a new Observer reused the client cookie %x", first)
	}
}

func TestAskServerCookie(t *testing.T) {
	s1 := []byte("server cookie 01")         // 16 octets
	s2 := []byte("a longer server cookie 2") // 24 octets
	f := &askFake{}
	f.reply = askCookieReply(t, func(c askCall) []dnswire.Option {
		switch c.q.Name.String() {
		case "a.corp.test.":
			return []dnswire.Option{askEcho(c, s1)}
		case "c.corp.test.":
			return []dnswire.Option{askEcho(c, nil)}
		case "d.corp.test.":
			return []dnswire.Option{askEcho(c, s2)}
		}
		return nil
	})
	o := askObserver(t, Config{ExtraRanges: askLab}, f, nil)
	s := o.newSession(time.Now().Add(time.Minute))
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")

	var client []byte
	for i, c := range []struct {
		name string
		sent []byte // server cookie the query must carry
		why  string
	}{
		{"a.corp.test.", nil, "nothing is known yet"},
		{"b.corp.test.", s1, "the answer before held s1"},
		{"c.corp.test.", s1, "an answer without a cookie changes nothing"},
		{"d.corp.test.", s1, "an answer with only the client cookie changes nothing"},
		{"e.corp.test.", s2, "the last answer with a server cookie held s2"},
	} {
		if _, m, _ := askDo(t, context.Background(), s, srv, askQuestion(t, c.name, dnswire.TypeA)); m == nil {
			t.Fatalf("%s: no answer", c.name)
		}
		got := f.call(t, i).q.Cookie
		if i == 0 {
			client = got
		}
		if want := askCat(client, c.sent); !bytes.Equal(got, want) {
			t.Errorf("query for %s carried cookie %q, want %q: %s", c.name, got, want, c.why)
		}
	}
	askDo(t, context.Background(), s, askServer(t, "ns2.corp.test.", "10.53.7.12:53"), askQuestion(t, "a.corp.test.", dnswire.TypeAAAA))
	if got := f.call(t, 5).q.Cookie; len(got) != 8 {
		t.Errorf("another address got a cookie of %d octets, want only its own client cookie", len(got))
	}
}

func TestAskForeignCookie(t *testing.T) {
	good := []byte("server cookie 01")
	foreign := func(c askCall) []byte {
		b := slices.Clone(c.q.Cookie[:8])
		b[0] ^= 0xff
		return b
	}
	cases := []struct {
		name    string
		options func(askCall) []dnswire.Option
	}{
		{"foreign client cookie with a server cookie", func(c askCall) []dnswire.Option {
			return []dnswire.Option{askCookie(askCat(foreign(c), []byte("forged cookie!!!")))}
		}},
		{"foreign client cookie alone", func(c askCall) []dnswire.Option {
			return []dnswire.Option{askCookie(foreign(c))}
		}},
		{"cookie of 12 octets", func(c askCall) []dnswire.Option {
			return []dnswire.Option{askEcho(c, []byte("abcd"))}
		}},
		{"cookie of 5 octets", func(c askCall) []dnswire.Option {
			return []dnswire.Option{askCookie(c.q.Cookie[:5])}
		}},
		{"two cookie options", func(c askCall) []dnswire.Option {
			return []dnswire.Option{askEcho(c, []byte("forged cookie!!!")), askEcho(c, []byte("forged cookie!!!"))}
		}},
	}
	for _, tc := range cases {
		var bad *dnswire.Response
		f := &askFake{}
		f.reply = func(c askCall) (*dnswire.Response, error) {
			switch c.q.Name.String() {
			case "a.corp.test.":
				return askCookieReply(t, func(c askCall) []dnswire.Option { return []dnswire.Option{askEcho(c, good)} })(c)
			case "b.corp.test.":
				bad, _ = askCookieReply(t, tc.options)(c)
				return bad, nil
			}
			return askAddress(t)(c)
		}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")
		askDo(t, context.Background(), s, srv, askQuestion(t, "a.corp.test.", dnswire.TypeA))
		p, _, fail := askDo(t, context.Background(), s, srv, askQuestion(t, "b.corp.test.", dnswire.TypeA))
		if fail == nil || fail.Reason != obs.ReasonMalformed {
			t.Errorf("%s: failure %v, want malformed", tc.name, fail)
		}
		if !bytes.Equal(p.Wire, bad.Wire) || p.Sent.IsZero() {
			t.Errorf("%s: proof holds %d octets sent at %v, want the %d octets of the answer as proof", tc.name, len(p.Wire), p.Sent, len(bad.Wire))
		}
		askDo(t, context.Background(), s, srv, askQuestion(t, "c.corp.test.", dnswire.TypeA))
		if got, want := f.call(t, 2).q.Cookie, askCat(f.call(t, 0).q.Cookie, good); !bytes.Equal(got, want) {
			t.Errorf("%s: the next query carried cookie %q, want %q: a rejected answer stores nothing", tc.name, got, want)
		}
	}
}

func askCookieServer(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.MustParseAddr("10.53.7.11"), uint16(1000+i))
}

// TestAskCookieJarBounded: the jar holds 4096 servers; one more drops the
// server that was seen first.
func TestAskCookieJarBounded(t *testing.T) {
	j := newCookieJar()
	for i := range 4097 {
		j.get(askCookieServer(i))
	}
	if n := len(j.servers); n != 4096 {
		t.Errorf("the jar holds %d servers, want 4096", n)
	}
	if _, ok := j.servers[askCookieServer(0)]; ok {
		t.Errorf("the server seen first is still in the full jar")
	}
	for _, i := range []int{1, 4096} {
		if _, ok := j.servers[askCookieServer(i)]; !ok {
			t.Errorf("server %d was dropped, want only the first one dropped", i)
		}
	}
}

// TestAskCookieDroppedDuringQuery: an answer that echoes the client cookie
// sent is ours, also when the jar dropped the server while the query was out.
func TestAskCookieDroppedDuringQuery(t *testing.T) {
	f := &askFake{}
	var o *Observer
	f.reply = askCookieReply(t, func(c askCall) []dnswire.Option {
		for i := range 4096 {
			o.cookies.get(askCookieServer(i))
		}
		return []dnswire.Option{askEcho(c, []byte("server cookie 01"))}
	})
	o = askObserver(t, Config{ExtraRanges: askLab}, f, nil)
	s := o.newSession(time.Now().Add(time.Minute))
	_, m, fail := askDo(t, context.Background(), s, askServer(t, "ns1.corp.test.", "10.53.7.11:53"), askQuestion(t, "www.corp.test.", dnswire.TypeA))
	if m == nil {
		t.Errorf("failure %v, want the answer that echoes the cookie sent", fail)
	}
}

func TestAskBadCookieRetry(t *testing.T) {
	q := askQuestion(t, "www.corp.test.", dnswire.TypeA)
	srv := askServer(t, "ns1.corp.test.", "10.53.7.11:53")

	t.Run("new server cookie, then an answer", func(t *testing.T) {
		s1 := []byte("server cookie 01")
		var answer *dnswire.Response
		f := &askFake{}
		f.reply = func(c askCall) (*dnswire.Response, error) {
			if len(c.q.Cookie) == 8 {
				return askResponse(t, c, askReply{rcode: 23, noAA: true, options: []dnswire.Option{askEcho(c, s1)}}, false), nil
			}
			answer, _ = askCookieReply(t, func(c askCall) []dnswire.Option { return []dnswire.Option{askEcho(c, s1)} })(c)
			return answer, nil
		}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		p, m, _ := askDo(t, context.Background(), s, srv, q)
		if f.count() != 2 {
			t.Fatalf("exchange called %d times, want 2: BADCOOKIE with a new server cookie is asked once more", f.count())
		}
		if got, want := f.call(t, 1).q.Cookie, askCat(f.call(t, 0).q.Cookie, s1); !bytes.Equal(got, want) {
			t.Errorf("the retry carried cookie %q, want %q", got, want)
		}
		if m == nil || m.Rcode != 0 || !bytes.Equal(p.Wire, answer.Wire) {
			t.Errorf("ask gave rcode %v, want the answer to the retry", m)
		}
	})

	t.Run("BADCOOKIE again", func(t *testing.T) {
		f := &askFake{}
		f.reply = func(c askCall) (*dnswire.Response, error) {
			server := askCat([]byte("server cookie "), []byte{byte('0' + f.count())}, []byte("!"))
			return askResponse(t, c, askReply{rcode: 23, noAA: true, options: []dnswire.Option{askEcho(c, server)}}, false), nil
		}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		_, m, _ := askDo(t, context.Background(), s, srv, q)
		if f.count() != 2 {
			t.Errorf("exchange called %d times, want 2: the retry happens once", f.count())
		}
		if m == nil || m.Rcode != 23 {
			t.Errorf("ask gave %v, want the second BADCOOKIE answer", m)
		}
	})

	t.Run("BADCOOKIE without a cookie", func(t *testing.T) {
		f := &askFake{}
		f.reply = func(c askCall) (*dnswire.Response, error) {
			return askResponse(t, c, askReply{rcode: 23, noAA: true}, false), nil
		}
		s := askObserver(t, Config{ExtraRanges: askLab}, f, nil).newSession(time.Now().Add(time.Minute))
		_, m, _ := askDo(t, context.Background(), s, srv, q)
		if f.count() != 1 || m == nil || m.Rcode != 23 {
			t.Errorf("exchange called %d times, want 1 and the BADCOOKIE answer: no new server cookie, no retry", f.count())
		}
	})
}

// TestAskCookieOverUDP asks a real UDP server on 127.0.0.1, which sees what
// the lab cannot show: the source port of each query, and the server
// cookie that comes back to it.
func TestAskCookieOverUDP(t *testing.T) {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	type query struct {
		port   int
		id     uint16
		cookie []byte
	}
	queries := make(chan query, 100)
	serverCookie := func(k int) []byte { return fmt.Appendf(nil, "server cookie %02d", k) }
	go func() {
		buf := make([]byte, 65535)
		for k := 0; ; k++ {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			m, err := dnswire.Parse(buf[:n])
			if err != nil || len(m.Question) != 1 || m.EDNS == nil {
				continue
			}
			var cookie []byte
			for _, o := range m.EDNS.Options {
				if o.Code == 10 {
					cookie = o.Data
				}
			}
			queries <- query{port: from.(*net.UDPAddr).Port, id: m.ID, cookie: cookie}
			a := dnswire.Record{Name: m.Question[0].Name, Class: dnswire.ClassINET, TTL: 300,
				Data: dnswire.A{Addr: netip.MustParseAddr("127.0.0.1")}}
			opts := []dnswire.Option{askCookie(askCat(cookie[:min(8, len(cookie))], serverCookie(k)))}
			_, _ = pc.WriteTo(askWire(m.ID, askMessage(m.Question[0], askReply{answer: []dnswire.Record{a}, options: opts})), from)
		}
	}()

	o, err := New(Config{ExtraRanges: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	s := o.newSession(time.Now().Add(time.Minute))
	srv := obs.Server{Name: askName(t, "ns.local.test."), Addr: netip.MustParseAddrPort(pc.LocalAddr().String())}
	const n = 8
	var seen []query
	for i := range n {
		if _, m, _ := askDo(t, context.Background(), s, srv, askQuestion(t, fmt.Sprintf("n%d.local.test.", i), dnswire.TypeA)); m == nil {
			t.Fatalf("query %d: no answer", i+1)
		}
		seen = append(seen, <-queries)
	}
	ports := map[int]bool{}
	ids := map[uint16]bool{}
	for k, q := range seen {
		ports[q.port] = true
		ids[q.id] = true
		want := seen[0].cookie
		if k > 0 {
			want = askCat(seen[0].cookie, serverCookie(k-1))
		}
		if len(seen[0].cookie) != 8 || !bytes.Equal(q.cookie, want) {
			t.Errorf("query %d carried cookie %q, want %q: the client cookie, then the last server cookie", k+1, q.cookie, want)
		}
	}
	if len(ports) < 2 || len(ids) < 2 {
		t.Errorf("%d queries came from %d source ports with %d IDs, want a fresh port and ID for each", n, len(ports), len(ids))
	}
}
