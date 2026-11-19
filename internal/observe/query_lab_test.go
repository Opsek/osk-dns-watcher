//go:build lab

package observe

import (
	"bytes"
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// askLabAddr is the address of a host of the lab, by its last octet.
func askLabAddr(t *testing.T, host int) netip.Addr {
	t.Helper()
	a, err := netip.ParseAddr(fmt.Sprintf("10.53.%s.%d", os.Getenv("LAB_ID"), host))
	if err != nil {
		t.Fatalf("LAB_ID %q: %v", os.Getenv("LAB_ID"), err)
	}
	return a
}

// askLabObserver starts at the root of the lab, whose addresses are not
// public.
func askLabObserver(t *testing.T, cfg Config) *Observer {
	t.Helper()
	cfg.RootServers = []netip.AddrPort{netip.AddrPortFrom(askLabAddr(t, 2), 53)}
	cfg.ExtraRanges = []netip.Prefix{netip.PrefixFrom(askLabAddr(t, 0), 24)}
	o, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func askLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

func askLabRecords(t *testing.T, o *Observer, name string, typ dnswire.Type, interval time.Duration) obs.Observation {
	t.Helper()
	key := obs.RecordsKey(askName(t, "corp.test."), askName(t, name), typ)
	ob, err := o.Run(context.Background(), Check{Key: key, Interval: interval})
	if err != nil {
		t.Fatalf("%v: %v", key, err)
	}
	return ob
}

// askLabParse reads the proof of an answer; every query of these tests is
// answered, so a missing answer fails.
func askLabParse(t *testing.T, a obs.Answer) *dnswire.Message {
	t.Helper()
	if a.Wire == nil {
		t.Fatalf("%s %v at %v: no answer", a.Question.Name, a.Question.Type, a.Server.Addr)
	}
	m, err := dnswire.Parse(a.Wire)
	if err != nil {
		t.Fatalf("%s %v at %v: %v", a.Question.Name, a.Question.Type, a.Server.Addr, err)
	}
	return m
}

func askLabSet(a obs.Answer) []dnswire.Record {
	return obs.Match(a.Result,
		func(r obs.Records) []dnswire.Record { return r.Set },
		func(obs.NoData) []dnswire.Record { return nil },
		func(obs.NoName) []dnswire.Record { return nil },
		func(obs.Failure) []dnswire.Record { return nil })
}

func askLabFailure(a obs.Answer) *obs.Failure {
	return obs.Match(a.Result,
		func(obs.Records) *obs.Failure { return nil },
		func(obs.NoData) *obs.Failure { return nil },
		func(obs.NoName) *obs.Failure { return nil },
		func(f obs.Failure) *obs.Failure { return &f })
}

func TestEDNSAndTCPRetry(t *testing.T) {
	t.Cleanup(func() { askLabctl(t, "reset") })
	// 60 records of 50 octets each cannot fit the 1232 octets of a UDP
	// answer, so the servers set TC and the answer comes over TCP.
	args := []string{"set", "both", "big.corp.test.", "300", "TXT"}
	var want []string
	for i := range 60 {
		s := fmt.Sprintf("string %02d ", i) + strings.Repeat("x", 40)
		want = append(want, s)
		args = append(args, `"`+s+`"`)
	}
	askLabctl(t, args...)

	o := askLabObserver(t, Config{})
	big := askLabRecords(t, o, "big.corp.test.", dnswire.TypeTXT, 20*time.Second)
	www := askLabRecords(t, o, "www.corp.test.", dnswire.TypeA, 20*time.Second)
	for _, c := range []struct {
		ob  obs.Observation
		tcp bool
		n   int
	}{{big, true, 60}, {www, false, 1}} {
		if len(c.ob.Answers) != 2 {
			t.Fatalf("%v: %d answers, want one from each of ns1 and ns2", c.ob.Key, len(c.ob.Answers))
		}
		for _, a := range c.ob.Answers {
			if set := askLabSet(a); len(set) != c.n || a.TCP != c.tcp {
				t.Errorf("%v at %v: %d records over TCP %v (%v), want %d over TCP %v",
					c.ob.Key, a.Server.Addr, len(set), a.TCP, askLabFailure(a), c.n, c.tcp)
			}
		}
		for _, a := range append(slices.Clone(c.ob.Walk), c.ob.Answers...) {
			if m := askLabParse(t, a); m.EDNS == nil {
				t.Errorf("%s %v at %v: answer without OPT record, so the query had none", a.Question.Name, a.Question.Type, a.Server.Addr)
			}
		}
	}
	for _, a := range big.Answers {
		var got []string
		for _, r := range askLabSet(a) {
			got = append(got, strings.Join(r.Data.(dnswire.TXT).Strings, ""))
		}
		slices.Sort(got)
		if !slices.Equal(got, want) {
			t.Errorf("TXT at %v: %q, want the 60 strings set", a.Server.Addr, got)
		}
	}
}

func TestIDsAndCookies(t *testing.T) {
	t.Cleanup(func() { askLabctl(t, "reset") })
	o := askLabObserver(t, Config{})
	checks := []struct {
		name string
		typ  dnswire.Type
	}{
		{"www.corp.test.", dnswire.TypeA}, {"mail.corp.test.", dnswire.TypeA}, {"ns1.corp.test.", dnswire.TypeA},
		{"ns2.corp.test.", dnswire.TypeA}, {"corp.test.", dnswire.TypeA}, {"corp.test.", dnswire.TypeAAAA},
		{"corp.test.", dnswire.TypeMX}, {"corp.test.", dnswire.TypeTXT}, {"corp.test.", dnswire.TypeCAA},
		{"_dmarc.corp.test.", dnswire.TypeTXT},
	}
	var answers, all []obs.Answer
	for range 2 {
		for _, c := range checks {
			ob := askLabRecords(t, o, c.name, c.typ, 10*time.Second)
			answers = append(answers, ob.Answers...)
			all = append(append(all, ob.Walk...), ob.Answers...)
		}
	}
	if len(answers) != 40 {
		t.Fatalf("%d answers, want 40", len(answers))
	}

	var ids []int
	for _, a := range answers {
		ids = append(ids, int(askLabParse(t, a).ID))
	}
	slices.Sort(ids)
	byOne := true
	for i := 1; i < len(ids); i++ {
		byOne = byOne && ids[i] == ids[i-1]+1
	}
	if ids[0] == ids[len(ids)-1] || byOne {
		t.Errorf("IDs of the answers %v: all equal or consecutive, want random", ids)
	}

	// BIND sends a server cookie only to a query that carried a client
	// cookie, and it echoes that client cookie.
	clients := map[netip.AddrPort][]byte{}
	for _, a := range all {
		client, server, ok := askLabParse(t, a).EDNS.Cookie()
		if !ok || len(server) == 0 {
			t.Errorf("%s %v at %v: no cookie with a server part", a.Question.Name, a.Question.Type, a.Server.Addr)
			continue
		}
		if seen, ok := clients[a.Server.Addr]; ok && !bytes.Equal(seen, client) {
			t.Errorf("client cookie for %v changed from %x to %x", a.Server.Addr, seen, client)
		}
		clients[a.Server.Addr] = client
	}
	ns1 := clients[netip.AddrPortFrom(askLabAddr(t, 11), 53)]
	ns2 := clients[netip.AddrPortFrom(askLabAddr(t, 12), 53)]
	if ns1 == nil || ns2 == nil || bytes.Equal(ns1, ns2) {
		t.Errorf("client cookies of ns1 %x and ns2 %x, want two different ones", ns1, ns2)
	}
}

func TestRateLimitPerServer(t *testing.T) {
	t.Cleanup(func() { askLabctl(t, "reset") })
	const interval = 200 * time.Millisecond
	o := askLabObserver(t, Config{RateInterval: interval, RateBurst: 2})
	checks := []struct {
		name string
		typ  dnswire.Type
	}{
		{"www.corp.test.", dnswire.TypeA}, {"mail.corp.test.", dnswire.TypeA}, {"ns1.corp.test.", dnswire.TypeA},
		{"ns2.corp.test.", dnswire.TypeA}, {"corp.test.", dnswire.TypeA}, {"_dmarc.corp.test.", dnswire.TypeTXT},
		{"cdn.corp.test.", dnswire.TypeA}, {"nx.corp.test.", dnswire.TypeA},
	}
	observations := make([]obs.Observation, len(checks))
	var wg sync.WaitGroup
	for i, c := range checks {
		key := obs.RecordsKey(askName(t, "corp.test."), askName(t, c.name), c.typ)
		wg.Go(func() {
			ob, err := o.Run(context.Background(), Check{Key: key, Interval: 30 * time.Second})
			if err != nil {
				t.Errorf("%v: %v", key, err)
			}
			observations[i] = ob
		})
	}
	wg.Wait()

	// A memo hit repeats the Sent of the query it reuses, and a cut from the
	// cache that of the referral another check received; count each query once.
	type send struct {
		addr netip.AddrPort
		q    string
		at   time.Time
	}
	seen := map[send]bool{}
	sent := map[netip.AddrPort][]time.Time{}
	for _, ob := range observations {
		for _, a := range ob.Answers {
			if f := askLabFailure(a); f != nil {
				t.Errorf("%v at %v: failure %v (%q), want an answer", ob.Key, a.Server.Addr, f.Reason, f.Detail)
			}
		}
		for _, a := range append(slices.Clone(ob.Walk), ob.Answers...) {
			s := send{a.Server.Addr, a.Question.Name.Key() + " " + a.Question.Type.String(), a.Sent}
			if a.Sent.IsZero() || seen[s] {
				continue
			}
			seen[s] = true
			sent[a.Server.Addr] = append(sent[a.Server.Addr], a.Sent)
		}
	}
	ns1 := netip.AddrPortFrom(askLabAddr(t, 11), 53)
	if len(sent[ns1]) < len(checks) {
		t.Fatalf("%d queries sent to ns1, want at least one for each of the %d checks", len(sent[ns1]), len(checks))
	}
	for addr, times := range sent {
		slices.SortFunc(times, time.Time.Compare)
		for k := range times {
			// The first two queries are the burst; each later one waits one interval.
			if least := time.Duration(k-1)*interval - 20*time.Millisecond; times[k].Sub(times[0]) < least {
				t.Errorf("%v: query %d sent %v after the first, want at least %v", addr, k+1, times[k].Sub(times[0]), least)
			}
		}
	}
}
