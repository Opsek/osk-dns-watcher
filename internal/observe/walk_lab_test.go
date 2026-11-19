//go:build lab

package observe

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// walkLab is the start of every lab address, "10.53.<LAB_ID>.".
func walkLab(t *testing.T) string {
	t.Helper()
	prefix := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(prefix + "1"); err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	return prefix
}

// walkLabObserver starts at the lab's root server and may ask the lab's
// private range. A zero timeout keeps the default.
func walkLabObserver(t *testing.T, queryTimeout time.Duration) *Observer {
	t.Helper()
	lab := walkLab(t)
	o, err := New(Config{
		RootServers:  []netip.AddrPort{netip.MustParseAddrPort(lab + "2:53")},
		ExtraRanges:  []netip.Prefix{netip.MustParsePrefix(lab + "0/24")},
		QueryTimeout: queryTimeout,
	})
	if err != nil {
		t.Fatal(err)
	}
	return o
}

// walkLabStart puts the lab back into its base state when the test ends,
// also after a failure.
func walkLabStart(t *testing.T) {
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
}

func walkLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// walkLabWant compares answers with want, where @ stands for the start of
// the lab addresses.
func walkLabWant(t *testing.T, what string, got []string, want ...string) {
	t.Helper()
	var full []string
	for _, w := range want {
		full = append(full, strings.ReplaceAll(w, "@", walkLab(t)))
	}
	walkWant(t, what, got, full)
}

const (
	walkLabWWW     = "records www.corp.test. 300 IN A @81"
	walkLabCorpSet = "records corp.test. 300 IN NS ns1.corp.test.; corp.test. 300 IN NS ns2.corp.test."
	walkLabDS      = "12345 13 2 3F1B0C6E9A2D4F5E6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B"
)

func walkLabKeys(t *testing.T) (corp, www obs.Key) {
	return obs.DelegationKey(walkName(t, "corp.test.")), walkRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
}

func TestWalkFromLabRoot(t *testing.T) {
	walkLabStart(t)
	lab := walkLab(t)
	o := walkLabObserver(t, 0)
	del, www := walkLabKeys(t)

	ob := walkRun(t, o, del, time.Minute)
	if !ob.Zone.Equal(walkName(t, "test.")) {
		t.Errorf("delegation Zone = %v, want test.", ob.Zone)
	}
	if len(ob.Walk) == 0 || ob.Walk[0].Server.Addr != netip.MustParseAddrPort(lab+"2:53") {
		t.Errorf("the walk does not start at the lab root: %q", walkAnswers(ob.Walk))
	}

	ob = walkRun(t, o, www, time.Minute)
	if !ob.Zone.Equal(walkName(t, "corp.test.")) {
		t.Errorf("records Zone = %v, want corp.test.", ob.Zone)
	}
	walkLabWant(t, "www.corp.test. A", walkAnswers(ob.Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW)

	// Without its glue, ns1.dnshost.test. is found by a sub-walk; ns2 of the
	// same zone answers for it with AA.
	walkLabctl(t, "glue", "ns1.dnshost.test.")
	ob = walkRun(t, o, walkRecordsKey(t, "shop.test.", "shop.test.", dnswire.TypeA), time.Minute)
	walkLabWant(t, "shop.test. A", walkAnswers(ob.Answers),
		"ns1.dnshost.test. @11:53 records shop.test. 300 IN A @84",
		"ns2.dnshost.test. @12:53 records shop.test. 300 IN A @84")
	if !walkSubWalked(ob, walkName(t, "ns1.dnshost.test."), "records ns1.dnshost.test. 300 IN A "+lab+"11") {
		t.Errorf("Walk holds no answer ns1.dnshost.test. A %s11: %q", lab, walkAnswers(ob.Walk))
	}
}

func TestLyingResolverChangesNothing(t *testing.T) {
	walkLabStart(t)
	lab := walkLab(t)
	del, www := walkLabKeys(t)
	// Without its glue, ns1.dnshost.test. is a host whose address the walk
	// must find itself, for the servers of shop.test.
	walkLabctl(t, "glue", "ns1.dnshost.test.")
	shop := walkRecordsKey(t, "shop.test.", "shop.test.", dnswire.TypeA)
	observe := func() []string {
		o := walkLabObserver(t, 0)
		var out []string
		for _, k := range []obs.Key{del, www, shop} {
			ob := walkRun(t, o, k, time.Minute)
			out = append(out, walkAnswers(ob.Answers)...)
			for _, a := range slices.Concat(ob.Walk, ob.Answers) {
				if ip := a.Server.Addr.Addr().String(); ip == lab+"20" || ip == lab+"21" {
					t.Errorf("%v: a proof from the resolver %s", k, ip)
				}
			}
		}
		return out
	}
	base := observe()
	walkLabWant(t, "base state", base,
		"ns.test. @3:53 "+walkLabCorpSet+" glue ns1.corp.test. 300 IN A @11; ns2.corp.test. 300 IN A @12",
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW,
		"ns1.dnshost.test. @11:53 records shop.test. 300 IN A @84", "ns2.dnshost.test. @12:53 records shop.test. 300 IN A @84")

	walkLabctl(t, "lie", "www.corp.test.", "A", lab+"66")
	walkLabctl(t, "lie", "corp.test.", "NS", "ns1.lie.test.")
	walkLabctl(t, "lie", "ns1.corp.test.", "A", lab+"21")
	walkLabctl(t, "lie", "ns.test.", "A", lab+"21")
	walkLabctl(t, "lie", "ns1.dnshost.test.", "A", lab+"21")
	// Docker mounts this file: it can be rewritten in place, not replaced.
	const conf = "/etc/resolv.conf"
	saved, err := os.ReadFile(conf)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.WriteFile(conf, saved, 0o644); err != nil {
			t.Errorf("restore %s: %v", conf, err)
		}
	})
	if err := os.WriteFile(conf, []byte("nameserver "+lab+"21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, c := range [][2]string{{"www.corp.test.", lab + "66"}, {"ns1.dnshost.test.", lab + "21"}} {
		out, err := exec.Command("dig", "+short", c[0], "A").Output()
		if got := strings.TrimSpace(string(out)); err != nil || got != c[1] {
			t.Fatalf("the system resolver gives %q (%v) for %s, want the lie %s", got, err, c[0], c[1])
		}
	}
	// Go's own resolver reads the file again only when its last look is 5s
	// old; earlier, a lookup in this process would still miss the lie.
	time.Sleep(6 * time.Second)

	walkWant(t, "results with the lying resolver", observe(), base)
}

func TestParentServersAnswer(t *testing.T) {
	walkLabStart(t)
	o := walkLabObserver(t, 0)
	corp, shop := walkName(t, "corp.test."), walkName(t, "shop.test.")

	ob := walkRun(t, o, obs.DelegationKey(corp), time.Minute)
	if !ob.Zone.Equal(walkName(t, "test.")) {
		t.Errorf("Zone = %v, want test.", ob.Zone)
	}
	walkLabWant(t, "delegation", walkAnswers(ob.Answers),
		"ns.test. @3:53 "+walkLabCorpSet+" glue ns1.corp.test. 300 IN A @11; ns2.corp.test. 300 IN A @12")
	walkLabWant(t, "ds before", walkAnswers(walkRun(t, o, obs.DSKey(corp), time.Minute).Answers), "ns.test. @3:53 nodata test.")

	walkLabctl(t, "ds", "corp.test.", walkLabDS)
	walkLabWant(t, "ds after", walkAnswers(walkRun(t, o, obs.DSKey(corp), time.Minute).Answers),
		"ns.test. @3:53 records corp.test. 300 IN DS "+walkLabDS)

	walkLabctl(t, "undelegate", "shop.test.")
	for _, k := range []obs.Key{obs.DelegationKey(shop), obs.DSKey(shop)} {
		walkLabWant(t, k.String(), walkAnswers(walkRun(t, o, k, time.Minute).Answers), "ns.test. @3:53 noname test.")
	}
}

func TestEveryAuthoritativeAddress(t *testing.T) {
	walkLabStart(t)
	lab := walkLab(t)
	_, www := walkLabKeys(t)
	walkLabctl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test.")
	walkLabctl(t, "glue", "ns3.corp.test.", lab+"11", lab+"12")
	walkLabWant(t, "three hosts, four addresses", walkAnswers(walkRun(t, walkLabObserver(t, 0), www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW,
		"ns3.corp.test. @11:53 "+walkLabWWW, "ns3.corp.test. @12:53 "+walkLabWWW)

	// The parent refers a query for corp.test. back to corp.test. A new
	// observer, because the earlier one may still use the old cut.
	walkLabctl(t, "glue", "ns3.corp.test.", lab+"3")
	walkLabWant(t, "ns3 at the parent", walkAnswers(walkRun(t, walkLabObserver(t, 0), www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW, "ns3.corp.test. @3:53 failure lame")
}

// walkLabDeadShop delegates shop.test. to the lab address that never answers.
func walkLabDeadShop(t *testing.T) obs.Key {
	walkLabctl(t, "delegate", "shop.test.", "ns9.shop.test.")
	walkLabctl(t, "glue", "ns9.shop.test.", walkLab(t)+"99")
	return walkRecordsKey(t, "shop.test.", "shop.test.", dnswire.TypeA)
}

type walkLabResult struct {
	ob      obs.Observation
	err     error
	elapsed time.Duration
}

func walkLabRunAsync(o *Observer, k obs.Key, interval time.Duration) <-chan walkLabResult {
	done := make(chan walkLabResult, 1)
	start := time.Now()
	go func() {
		ob, err := o.Run(context.Background(), Check{Key: k, Interval: interval})
		done <- walkLabResult{ob, err, time.Since(start)}
	}()
	return done
}

func TestDeadlineAndSingleRun(t *testing.T) {
	walkLabStart(t)
	shop := walkLabDeadShop(t)
	_, www := walkLabKeys(t)
	o := walkLabObserver(t, 10*time.Second)
	first := walkLabRunAsync(o, shop, 4*time.Second)
	// By now the first run waits for the address that never answers.
	time.Sleep(300 * time.Millisecond)

	start := time.Now()
	if _, err := o.Run(context.Background(), Check{Key: shop, Interval: 4 * time.Second}); !errors.Is(err, ErrRunning) {
		t.Errorf("second Run: %v, want ErrRunning", err)
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("the second Run took %v, want an answer at once", d)
	}
	walkLabWant(t, "a different key", walkAnswers(walkRun(t, o, www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW)

	r := <-first
	if r.err != nil {
		t.Fatal(r.err)
	}
	if r.elapsed > 3500*time.Millisecond {
		t.Errorf("Run took %v, want at most 3.5s", r.elapsed)
	}
	if d := r.ob.Deadline.Sub(r.ob.Start); d != 3*time.Second {
		t.Errorf("Deadline - Start = %v, want 3s", d)
	}
	// The deadline of the check, 3s, comes before the query timeout, 10s.
	walkLabWant(t, "dead shop.test.", walkAnswers(r.ob.Answers), "ns9.shop.test. @99:53 failure deadline")
}

func TestChecksIndependent(t *testing.T) {
	walkLabStart(t)
	shop := walkLabDeadShop(t)
	_, www := walkLabKeys(t)
	o := walkLabObserver(t, 5*time.Second)
	dead := walkLabRunAsync(o, shop, 10*time.Second)
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	ob := walkRun(t, o, www, time.Minute)
	if d := time.Since(start); d >= time.Second {
		t.Errorf("the corp.test. check took %v next to the dead one, want under 1s", d)
	}
	select {
	case <-dead:
		t.Errorf("the dead check ended before the corp.test. check")
	default:
	}
	walkLabWant(t, "corp.test.", walkAnswers(ob.Answers), "ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW)
	r := <-dead
	if r.err != nil {
		t.Fatal(r.err)
	}
	walkLabWant(t, "dead shop.test.", walkAnswers(r.ob.Answers), "ns9.shop.test. @99:53 failure timeout")
}

func TestGlueSwapSeen(t *testing.T) {
	walkLabStart(t)
	walkLabctl(t, "glue", "ns2.corp.test.", walkLab(t)+"11")
	o := walkLabObserver(t, 0)
	del, www := walkLabKeys(t)
	walkLabWant(t, "delegation", walkAnswers(walkRun(t, o, del, time.Minute).Answers),
		"ns.test. @3:53 "+walkLabCorpSet+" glue ns1.corp.test. 300 IN A @11; ns2.corp.test. 300 IN A @11")
	walkLabWant(t, "records", walkAnswers(walkRun(t, o, www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @11:53 "+walkLabWWW)
}

func TestDelegationChangeSeen(t *testing.T) {
	walkLabStart(t)
	o := walkLabObserver(t, 0)
	del, www := walkLabKeys(t)
	walkLabWant(t, "records before", walkAnswers(walkRun(t, o, www, 2*time.Second).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW)
	learned := time.Now()

	walkLabctl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	walkLabWant(t, "delegation at once", walkAnswers(walkRun(t, o, del, time.Minute).Answers),
		"ns.test. @3:53 records corp.test. 300 IN NS ns1.dnshost.test.; corp.test. 300 IN NS ns2.dnshost.test. glue ns1.dnshost.test. 300 IN A @11; ns2.dnshost.test. 300 IN A @12")

	time.Sleep(time.Until(learned.Add(2 * time.Second)))
	walkLabWant(t, "records one interval later", walkAnswers(walkRun(t, o, www, 2*time.Second).Answers),
		"ns1.dnshost.test. @11:53 "+walkLabWWW, "ns2.dnshost.test. @12:53 "+walkLabWWW)
}

func TestDeadServer(t *testing.T) {
	walkLabStart(t)
	walkLabctl(t, "glue", "ns2.corp.test.", walkLab(t)+"99")
	_, www := walkLabKeys(t)
	ob := walkRun(t, walkLabObserver(t, time.Second), www, time.Minute)
	walkLabWant(t, "records", walkAnswers(ob.Answers), "ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @99:53 failure timeout")
	// When the walk asked the dead server first, its answer replays that
	// failure: nothing was sent for its own question.
	if len(ob.Answers) == 2 {
		a := ob.Answers[1]
		replay := a.Sent.IsZero() && strings.Contains(walkFailure(a.Result).Detail, "www.corp.test. NS")
		if a.Wire != nil || a.Sent.IsZero() && !replay {
			t.Errorf("the dead server's answer has Wire %d octets, Sent %v, Detail %q; want no Wire, and Sent set or the walk's question named",
				len(a.Wire), a.Sent, walkFailure(a.Result).Detail)
		}
	}
}

func TestLameServer(t *testing.T) {
	walkLabStart(t)
	lab := walkLab(t)
	_, www := walkLabKeys(t)
	walkLabctl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test.")
	for _, tt := range []struct{ addr, want string }{
		{"3", "ns3.corp.test. @3:53 failure lame"},
		// the recursive resolver refuses a query without RD
		{"20", "ns3.corp.test. @20:53 failure refused"},
	} {
		walkLabctl(t, "glue", "ns3.corp.test.", lab+tt.addr)
		walkLabWant(t, "ns3 at "+tt.addr, walkAnswers(walkRun(t, walkLabObserver(t, 0), www, time.Minute).Answers),
			"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 "+walkLabWWW, tt.want)
	}
}

func TestServersDisagree(t *testing.T) {
	walkLabStart(t)
	walkLabctl(t, "set", "ns2", "www.corp.test.", "300", "A", walkLab(t)+"99")
	_, www := walkLabKeys(t)
	walkLabWant(t, "records", walkAnswers(walkRun(t, walkLabObserver(t, 0), www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns2.corp.test. @12:53 records www.corp.test. 300 IN A @99")
}

// walkLabXZone is the zone x.test. on ns1: a.x.test. is served by 32 hosts
// in b.x.test., and b.x.test. by 32 hosts of x.test. that do not exist, none
// with glue.
func walkLabXZone(t *testing.T) string {
	lab := walkLab(t)
	z := "$TTL 300\n" +
		"x.test. IN SOA ns.x.test. hostmaster.x.test. 1 3600 600 86400 300\n" +
		"x.test. IN NS ns.x.test.\n" +
		"ns.x.test. IN A " + lab + "11\n"
	for i := 1; i <= 32; i++ {
		z += fmt.Sprintf("a.x.test. IN NS h%02d.b.x.test.\nb.x.test. IN NS k%02d.x.test.\n", i, i)
	}
	file := filepath.Join(t.TempDir(), "x.zone")
	if err := os.WriteFile(file, []byte(z), 0o644); err != nil {
		t.Fatal(err)
	}
	return file
}

// TestNameserverZoneCannotBlind: corp.test. is served by ns1.corp.test. and
// by ns.a.x.test., whose address would cost more queries than a check may
// send. Its search gets a share of them, and ns1.corp.test. still answers.
func TestNameserverZoneCannotBlind(t *testing.T) {
	walkLabStart(t)
	lab := walkLab(t)
	walkLabctl(t, "load-zone", "ns1", "x.test.", walkLabXZone(t))
	walkLabctl(t, "delegate", "x.test.", "ns.x.test.")
	walkLabctl(t, "glue", "ns.x.test.", lab+"11")
	walkLabctl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns.a.x.test.")
	_, www := walkLabKeys(t)
	walkLabWant(t, "records", walkAnswers(walkRun(t, walkLabObserver(t, 0), www, time.Minute).Answers),
		"ns1.corp.test. @11:53 "+walkLabWWW, "ns.a.x.test. - failure walk")
}

func TestNonPublicAddressNotAsked(t *testing.T) {
	walkLabStart(t)
	walkLabctl(t, "glue", "ns2.corp.test.", "192.0.2.1", "127.0.0.1")
	_, www := walkLabKeys(t)
	ob := walkRun(t, walkLabObserver(t, 0), www, time.Minute)
	walkLabWant(t, "records", walkAnswers(ob.Answers), "ns1.corp.test. @11:53 "+walkLabWWW,
		"ns2.corp.test. 127.0.0.1:53 failure not-permitted", "ns2.corp.test. 192.0.2.1:53 failure not-permitted")
	for _, a := range slices.Concat(ob.Walk, ob.Answers) {
		if !strings.HasPrefix(a.Server.Addr.Addr().String(), walkLab(t)) && (!a.Sent.IsZero() || a.Wire != nil) {
			t.Errorf("%v: Sent %v, Wire %d octets; want nothing sent", a.Server.Addr, a.Sent, len(a.Wire))
		}
	}
}
