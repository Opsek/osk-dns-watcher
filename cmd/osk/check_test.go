package main

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// The tests ask one fake server on 127.0.0.1, given as the only root server.
// A glue address has no port, so a referral cannot lead to a second fake
// server. The fake server therefore answers with authority for every name
// under corp.test., which ends each walk at the root, and it delegates the
// zones under example. to servers that cannot be asked.

func cliName(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func cliRR(owner string, ttl uint32, data dnswire.RData) dnswire.Record {
	return dnswire.Record{Name: cliName(owner), Class: dnswire.ClassINET, TTL: ttl, Data: data}
}

func cliSOAOf(zone string, ttl uint32) dnswire.Record {
	return cliRR(zone, ttl, dnswire.SOA{MName: cliName("ns1." + zone), RName: cliName("hostmaster." + zone),
		Serial: 7, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300})
}

var (
	cliNS = []dnswire.Record{
		cliRR("corp.test.", 3600, dnswire.NS{Host: cliName("ns1.corp.test.")}),
		cliRR("corp.test.", 3600, dnswire.NS{Host: cliName("ns2.corp.test.")}),
	}
	cliGlue = []dnswire.Record{
		cliRR("ns1.corp.test.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.11")}),
		cliRR("ns2.corp.test.", 3600, dnswire.AAAA{Addr: netip.MustParseAddr("2001:db8::12")}),
	}
	// Its TTL is above MINIMUM, so a negative answer shows 300, not 900.
	cliSOA   = cliSOAOf("corp.test.", 900)
	cliWWW   = cliRR("www.corp.test.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.80")})
	cliPicky = cliRR("picky.corp.test.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.81")})
	cliCNAME = cliRR("cdn.corp.test.", 300, dnswire.CNAME{Target: cliName("edge.example.")})
	cliTXT   = []dnswire.Record{
		cliRR("big.corp.test.", 300, dnswire.TXT{Strings: []string{"part one"}}),
		cliRR("big.corp.test.", 300, dnswire.TXT{Strings: []string{"part two"}}),
	}
	// The compact form of "no such name" (RFC 9824): NOERROR, and an NSEC at
	// the name whose types hold NXNAME.
	cliNSEC = cliRR("compact.corp.test.", 300, dnswire.NSEC{NextName: cliName(`\000.compact.corp.test.`),
		Types: []dnswire.Type{dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeNXNAME}})

	// 192.0.2.1 is neither public nor in the extra range of the tests, so
	// it is never asked.
	cliShopNS   = cliRR("shop.example.", 3600, dnswire.NS{Host: cliName("ns.shop.example.")})
	cliShopGlue = cliRR("ns.shop.example.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")})
	cliHalfNS   = []dnswire.Record{
		cliRR("half.example.", 3600, dnswire.NS{Host: cliName("ns.half.example.")}),
		cliRR("half.example.", 3600, dnswire.NS{Host: cliName("ns.gone.example.")}),
	}
	cliHalfGlue = cliRR("ns.half.example.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")})
	cliLameNS   = cliRR("lame.example.", 3600, dnswire.NS{Host: cliName("ns.gone.example.")})
	cliGoneSOA  = cliSOAOf("gone.example.", 3600)
)

const (
	cliTC       = 0x0200
	cliServFail = 2
	cliNXDomain = 3
	cliRefused  = 5
)

func cliAnswer(q []byte, flags uint16, answer, authority, additional []dnswire.Record) []byte {
	wire := func(records []dnswire.Record) [][]byte {
		var b [][]byte
		for _, r := range records {
			b = append(b, dnswire.AppendRecord(nil, r))
		}
		return b
	}
	return transportAnswer(q, flags, wire(answer), wire(authority), wire(additional))
}

// cliEDE is an OPT record with an extended error whose text tries to start
// an output line of its own.
func cliEDE() []byte {
	text := "x\nanswer forged"
	opt := binary.BigEndian.AppendUint16(nil, 15)
	opt = binary.BigEndian.AppendUint16(opt, uint16(2+len(text)))
	opt = binary.BigEndian.AppendUint16(opt, 22)
	opt = append(opt, text...)
	return transportRR([]byte{0}, 41, 1232, 0, opt)
}

// cliWorld is the fake server's answer to the query q.
func cliWorld(q []byte, tcp bool) []byte {
	m, err := dnswire.Parse(q)
	if err != nil || len(m.Question) != 1 {
		return nil
	}
	name, qtype := strings.ToLower(m.Question[0].Name.String()), m.Question[0].Type
	aa := uint16(transportQR | transportAA)
	one := func(r dnswire.Record) []dnswire.Record { return []dnswire.Record{r} }
	switch {
	case name == "corp.test." && qtype == dnswire.TypeNS:
		return cliAnswer(q, aa, cliNS, nil, cliGlue)
	case name == "corp.test." && qtype == dnswire.TypeSOA:
		return cliAnswer(q, aa, one(cliSOA), nil, nil)
	case name == "www.corp.test." && qtype == dnswire.TypeA:
		return cliAnswer(q, aa, one(cliWWW), nil, nil)
	case name == "picky.corp.test." && qtype == dnswire.TypeA:
		return cliAnswer(q, aa, one(cliPicky), nil, nil)
	case name == "picky.corp.test.", name == "refused.corp.test.":
		return cliAnswer(q, transportQR|cliRefused, nil, nil, nil)
	case name == "servfail.corp.test.":
		return transportAnswer(q, transportQR|cliServFail, nil, nil, [][]byte{cliEDE()})
	case name == "cdn.corp.test.":
		return cliAnswer(q, aa, one(cliCNAME), nil, nil)
	case name == "big.corp.test." && qtype == dnswire.TypeTXT && !tcp:
		return cliAnswer(q, aa|cliTC, nil, nil, nil)
	case name == "big.corp.test." && qtype == dnswire.TypeTXT:
		return cliAnswer(q, aa, cliTXT, nil, nil)
	case name == "nx.corp.test.":
		return cliAnswer(q, aa|cliNXDomain, nil, one(cliSOA), nil)
	case name == "compact.corp.test.":
		return cliAnswer(q, aa, nil, []dnswire.Record{cliSOA, cliNSEC}, nil)
	case name == "corp.test.", strings.HasSuffix(name, ".corp.test."):
		return cliAnswer(q, aa, nil, one(cliSOA), nil)
	case strings.HasSuffix(name, ".shop.example."):
		return cliAnswer(q, transportQR, nil, one(cliShopNS), one(cliShopGlue))
	case strings.HasSuffix(name, ".half.example."):
		return cliAnswer(q, transportQR, nil, cliHalfNS, one(cliHalfGlue))
	case strings.HasSuffix(name, ".lame.example."):
		return cliAnswer(q, transportQR, nil, one(cliLameNS), nil)
	case strings.HasSuffix(name, ".gone.example."):
		return cliAnswer(q, aa|cliNXDomain, nil, one(cliGoneSOA), nil)
	}
	return nil
}

const cliTimeLayout = "2006-01-02T15:04:05.000Z"

// cliCheck runs "osk check" and returns the exit code, the lines of standard
// output and standard error. It checks the received time of each line and
// puts "T" in its place, and checks that each failure detail is one quoted
// string, so that text from the network cannot start a line.
func cliCheck(t *testing.T, args ...string) (int, []string, string) {
	t.Helper()
	start := time.Now()
	code, out, errOut := transportRun(append([]string{"check"}, args...)...)
	end := time.Now()
	if out == "" {
		return code, nil, errOut
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output does not end with a newline: %q", out)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		f := strings.SplitN(line, " ", 10)
		if len(f) != 10 {
			t.Errorf("line %q has fewer than ten fields", line)
			lines = append(lines, line)
			continue
		}
		reason, quoted := "", ""
		if f[8] == "failure" {
			reason, quoted, _ = strings.Cut(f[9], " ")
			if detail, err := strconv.Unquote(quoted); err != nil || strconv.Quote(detail) != quoted {
				t.Errorf("line %q: the detail is not one quoted string", line)
			}
		}
		// A query that was never sent has no time of its own to show.
		sent := !slices.Contains([]string{"not-permitted", "rate-limited", "budget", "walk", "deadline"}, reason)
		received, err := time.Parse(cliTimeLayout, f[6])
		switch {
		case err != nil || received.Format(cliTimeLayout) != f[6]:
			t.Errorf("line %q: received time %q is not in the form %s", line, f[6], cliTimeLayout)
		case sent && (received.Before(start.Truncate(time.Millisecond)) || received.After(end.Add(time.Millisecond))):
			t.Errorf("line %q: received time is outside the run, %s to %s", line,
				start.UTC().Format(cliTimeLayout), end.UTC().Format(cliTimeLayout))
		}
		f[6] = "T"
		lines = append(lines, strings.Join(f, " "))
	}
	return code, lines, errOut
}

// cliCompare compares output lines with the expected ones. An expected line
// that ends in "*" takes any detail in place of the star: the detail of most
// failures is free text, and cliCheck has checked its quoting.
func cliCompare(t *testing.T, got, want []string) {
	t.Helper()
	if !cliSame(got, want) {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func cliSame(got, want []string) bool {
	same := len(got) == len(want)
	for i := 0; same && i < len(got); i++ {
		if prefix, ok := strings.CutSuffix(want[i], "*"); ok {
			same = strings.HasPrefix(got[i], prefix)
		} else {
			same = got[i] == want[i]
		}
	}
	return same
}

// cliAt is the start of a line: role, kind, question, address, host, the
// place of the received time, and transport.
func cliAt(role, kind, qname, qtype, addr, host, transport string) string {
	return strings.Join([]string{role, kind, qname, qtype, addr, host, "T", transport}, " ")
}

func cliRecords(at string, set, glue []dnswire.Record) []string {
	var lines []string
	for _, r := range set {
		lines = append(lines, at+" records "+r.String())
	}
	for _, r := range glue {
		lines = append(lines, at+" glue "+r.String())
	}
	return lines
}

func cliOnly(role string, lines []string) []string {
	var keep []string
	for _, l := range lines {
		if strings.HasPrefix(l, role+" ") {
			keep = append(keep, l)
		}
	}
	return keep
}

// cliDomainLines are the lines of the delegation, ds and serial checks of
// corp.test. at the fake server.
func cliDomainLines(root string) []string {
	walk := func(kind string) []string {
		return cliRecords(cliAt("walk", kind, "corp.test.", "NS", root, ".", "udp"), cliNS, nil)
	}
	return slices.Concat(
		walk("delegation"),
		cliRecords(cliAt("answer", "delegation", "corp.test.", "NS", root, ".", "udp"), cliNS, cliGlue),
		walk("ds"),
		[]string{cliAt("answer", "ds", "corp.test.", "DS", root, ".", "udp") + " nodata 300 " + cliSOA.String()},
		walk("serial"),
		cliRecords(cliAt("answer", "serial", "corp.test.", "SOA", root, ".", "udp"), []dnswire.Record{cliSOA}, nil),
	)
}

// cliDomainFailed are the lines of the same checks when the one root server
// fails with reason.
func cliDomainFailed(root, reason string) []string {
	var lines []string
	for _, c := range [][2]string{{"delegation", "NS"}, {"ds", "DS"}, {"serial", "SOA"}} {
		lines = append(lines,
			cliAt("walk", c[0], "corp.test.", "NS", root, ".", "-")+" failure "+reason+" *",
			cliAt("answer", c[0], "corp.test.", c[1], root, ".", "-")+" failure "+reason+" *")
	}
	return lines
}

func TestCheckWrongUse(t *testing.T) {
	// A check that runs before the wrong use is found must send nothing:
	// 192.0.2.1 may not be asked.
	quiet := []string{"--root-server", "192.0.2.1", "--timeout", "1s"}
	cases := [][]string{
		{},
		{"corp.test.", "www.corp.test."},
		{"corp.test.", "www.corp.test.", "A", "mail.corp.test."},
		{"a..b"},
		{"corp.test.", "a..b", "A"},
		{"corp.test.", "www.corp.test.", "NOTATYPE"},
		{"."},
		{"corp.test.", "--timeout", "1s"}, // flags come first, and 1s is no type
		{"--root-server", "ns1.corp.test", "corp.test."},
		{"--root-server", "127.0.0.1:99999", "corp.test."},
		{"--extra-range", "10.0.0.1", "corp.test."},
		{"--timeout", "0s", "corp.test."},
		{"--timeout", "-1s", "corp.test."},
		{"--timeout", "soon", "corp.test."},
		{"--other", "corp.test."},
	}
	// Types that the codec reads but that no check may ask for.
	for _, qtype := range []string{"DS", "ANY", "OPT", "TSIG", "AXFR", "IXFR", "TYPE0", "TYPE128"} {
		cases = append(cases, []string{"corp.test.", "www.corp.test.", "A", "corp.test.", qtype})
	}
	for _, args := range append(cases, nil) {
		if args != nil {
			args = append(slices.Clone(quiet), args...)
		}
		code, out, errOut := transportRun(append([]string{"check"}, args...)...)
		if code != 2 || out != "" || !strings.Contains(strings.ToLower(errOut), "usage") || !strings.Contains(errOut, "osk check") {
			t.Errorf("check %q: exit code %d, output %q, errors %q; want 2, nothing and the usage", args, code, out, errOut)
		}
	}
}

// A pair that no check may ask is wrong use, found while the arguments are
// read, before any check runs: the root server, which may be asked and
// answers, gets no query.
func TestCheckWrongUseSendsNothing(t *testing.T) {
	s := transportStart(t, cliWorld)
	args := []string{"--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."}
	for i := range 8 {
		args = append(args, fmt.Sprintf("n%d.corp.test.", i), "A")
	}
	args = append(args, "x.corp.test.", "DS")
	if _, _, msg := parseCheck(args); msg == "" {
		t.Errorf("the arguments with the pair x.corp.test. DS read as valid")
	}
	code, out, errOut := transportRun(append([]string{"check"}, args...)...)
	if code != 2 || out != "" || !strings.Contains(errOut, "usage") {
		t.Errorf("exit code %d, output %q, errors %q; want 2, nothing and the usage", code, out, errOut)
	}
	// A query sent by a check that was then cancelled may arrive late.
	time.Sleep(200 * time.Millisecond)
	if n := len(s.queries); n != 0 {
		t.Errorf("the server received %d queries, want none", n)
	}
}

func TestCheckOutput(t *testing.T) {
	s := transportStart(t, cliWorld)
	code, lines, errOut := cliCheck(t, "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.",
		"www.corp.test.", "A", "nx.corp.test.", "A", "compact.corp.test.", "TXT", "cdn.corp.test.", "A",
		"big.corp.test.", "TXT", "picky.corp.test.", "A")
	if code != 0 {
		t.Errorf("exit code %d, errors %q; want 0", code, errOut)
	}
	walk := func(name string) string { return cliAt("walk", "records", name, "NS", s.addr, ".", "udp") }
	answer := func(name, qtype, transport string) string {
		return cliAt("answer", "records", name, qtype, s.addr, ".", transport)
	}
	nodata := " nodata 300 " + cliSOA.String()
	noname := " noname 300 " + cliSOA.String()
	compact := " noname-compact 300 " + cliSOA.String()
	want := slices.Concat(
		cliDomainLines(s.addr),
		[]string{walk("www.corp.test.") + nodata},
		cliRecords(answer("www.corp.test.", "A", "udp"), []dnswire.Record{cliWWW}, nil),
		[]string{walk("nx.corp.test.") + noname, answer("nx.corp.test.", "A", "udp") + noname},
		[]string{walk("compact.corp.test.") + compact, answer("compact.corp.test.", "TXT", "udp") + compact},
		cliRecords(walk("cdn.corp.test."), []dnswire.Record{cliCNAME}, nil),
		cliRecords(answer("cdn.corp.test.", "A", "udp"), []dnswire.Record{cliCNAME}, nil),
		[]string{walk("big.corp.test.") + nodata},
		cliRecords(answer("big.corp.test.", "TXT", "tcp"), cliTXT, nil),
		// A failed walk query does not set the exit code; only answers do.
		[]string{walk("picky.corp.test.") + " failure refused *"},
		cliRecords(answer("picky.corp.test.", "A", "udp"), []dnswire.Record{cliPicky}, nil),
	)
	cliCompare(t, lines, want)
}

func TestCheckFailures(t *testing.T) {
	s := transportStart(t, cliWorld)
	code, lines, _ := cliCheck(t, "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.",
		"refused.corp.test.", "A", "servfail.corp.test.", "A", "www.shop.example.", "A")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	walk := func(name string) string { return cliAt("walk", "records", name, "NS", s.addr, ".", "udp") }
	answer := func(name string) string { return cliAt("answer", "records", name, "A", s.addr, ".", "udp") }
	shop := func(role, qtype string) string {
		return cliAt(role, "records", "www.shop.example.", qtype, "192.0.2.1:53", "ns.shop.example.", "-")
	}
	want := slices.Concat(
		cliDomainLines(s.addr),
		[]string{
			walk("refused.corp.test.") + " failure refused *",
			answer("refused.corp.test.") + " failure refused *",
			walk("servfail.corp.test.") + " failure servfail *",
			answer("servfail.corp.test.") + " failure servfail *",
		},
		cliRecords(walk("www.shop.example."), []dnswire.Record{cliShopNS}, []dnswire.Record{cliShopGlue}),
		[]string{shop("walk", "NS") + " failure not-permitted *", shop("answer", "A") + " failure not-permitted *"},
	)
	cliCompare(t, lines, want)

	prefix := answer("servfail.corp.test.") + " failure servfail "
	for _, line := range lines {
		if quoted, ok := strings.CutPrefix(line, prefix); ok {
			if detail, _ := strconv.Unquote(quoted); !strings.Contains(detail, "22") || !strings.Contains(detail, "answer forged") {
				t.Errorf("servfail detail %q lacks the extended error, code 22 and its text", detail)
			}
		}
	}
}

func TestCheckNoAddress(t *testing.T) {
	s := transportStart(t, cliWorld)
	code, lines, _ := cliCheck(t, "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.",
		"www.half.example.", "A", "www.lame.example.", "A")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	half := func(addr, host string) string {
		return cliAt("answer", "records", "www.half.example.", "A", addr, host, "-")
	}
	lame := cliAt("answer", "records", "www.lame.example.", "A", "-", "-", "-") + " failure walk "
	want := slices.Concat(
		cliOnly("answer", cliDomainLines(s.addr)),
		[]string{
			// Sorted by host: gone before half.
			half("-", "ns.gone.example.") + ` failure walk "no address for ns.gone.example."`,
			half("192.0.2.1:53", "ns.half.example.") + " failure not-permitted *",
			lame + "*",
		},
	)
	answers := cliOnly("answer", lines)
	cliCompare(t, answers, want)

	for _, line := range answers {
		if quoted, ok := strings.CutPrefix(line, lame); ok {
			if detail, _ := strconv.Unquote(quoted); !strings.Contains(detail, "lame.example.") {
				t.Errorf("walk failure detail %q does not name the zone lame.example.", detail)
			}
		}
	}
}

func TestCheckTimeoutFlag(t *testing.T) {
	s := transportStart(t, nil)
	start := time.Now()
	code, lines, _ := cliCheck(t, "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--timeout", "300ms", "corp.test.")
	// With the default of 2s, it would take longer.
	if d := time.Since(start); d > 1500*time.Millisecond {
		t.Errorf("check took %v with a timeout of 300ms", d)
	}
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	cliCompare(t, lines, cliDomainFailed(s.addr, "timeout"))
}

// Without --extra-range, 127.0.0.1 is no public address: even a root server
// given on the command line is not asked.
func TestCheckRootNotPermitted(t *testing.T) {
	s := transportStart(t, cliWorld)
	code, lines, _ := cliCheck(t, "--root-server", s.addr, "corp.test.")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	cliCompare(t, lines, cliDomainFailed(s.addr, "not-permitted"))
	if n := len(s.queries); n != 0 {
		t.Errorf("the server received %d queries, want none", n)
	}
}

// Each root server given is asked. Both have the same name and address, and
// only their ports differ, so either may come first.
func TestCheckRootServersRepeat(t *testing.T) {
	a, b := transportStart(t, cliWorld), transportStart(t, cliWorld)
	code, lines, errOut := cliCheck(t, "--root-server", b.addr, "--root-server", a.addr, "--extra-range", "127.0.0.0/8", "corp.test.")
	if code != 0 {
		t.Errorf("exit code %d, errors %q; want 0", code, errOut)
	}
	// The answer lines of one root server, for each check in order.
	checks := []func(root string) []string{
		func(root string) []string {
			return cliRecords(cliAt("answer", "delegation", "corp.test.", "NS", root, ".", "udp"), cliNS, cliGlue)
		},
		func(root string) []string {
			return []string{cliAt("answer", "ds", "corp.test.", "DS", root, ".", "udp") + " nodata 300 " + cliSOA.String()}
		},
		func(root string) []string {
			return cliRecords(cliAt("answer", "serial", "corp.test.", "SOA", root, ".", "udp"), []dnswire.Record{cliSOA}, nil)
		},
	}
	rest := cliOnly("answer", lines)
	for _, of := range checks {
		ab, ba := slices.Concat(of(a.addr), of(b.addr)), slices.Concat(of(b.addr), of(a.addr))
		got := rest[:min(len(ab), len(rest))]
		rest = rest[len(got):]
		if !cliSame(got, ab) && !cliSame(got, ba) {
			t.Errorf("answers:\n%s\nwant these, for one root server after the other:\n%s",
				strings.Join(got, "\n"), strings.Join(ab, "\n"))
		}
	}
	if len(rest) > 0 {
		t.Errorf("more answers than the checks gave:\n%s", strings.Join(rest, "\n"))
	}
	for _, line := range cliOnly("walk", lines) {
		if f := strings.Fields(line); f[4] != a.addr && f[4] != b.addr {
			t.Errorf("walk line %q names no root server given", line)
		}
	}
}

type cliBrokenWriter struct{}

func (cliBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestCheckOutputFails(t *testing.T) {
	s := transportStart(t, cliWorld)
	var errOut strings.Builder
	code := run([]string{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."},
		cliBrokenWriter{}, &errOut)
	e := errOut.String()
	if code != 1 || !strings.HasPrefix(e, "osk: ") || !strings.Contains(e, "disk full") || strings.Count(e, "\n") != 1 ||
		!strings.HasSuffix(e, "\n") {
		t.Errorf("exit code %d, errors %q; want 1 and one line \"osk: ...disk full\"", code, e)
	}
}

// --- the checks of a file ---

func dngqParse(t *testing.T, lines ...string) *expect.File {
	t.Helper()
	f, err := expect.Parse([]byte("domain corp.test.\n" + strings.Join(lines, "\n") + "\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f
}

func dngqKeys(keys []obs.Key) []string {
	texts := []string{}
	for _, k := range keys {
		texts = append(texts, k.String())
	}
	return texts
}

// dngqOldKeys are the checks that osk gave a file before the probes: the
// delegation and DS checks, then a records check for each line but DS.
func dngqOldKeys(f *expect.File) []string {
	keys := []string{obs.DelegationKey(f.Domain).String(), obs.DSKey(f.Domain).String()}
	for _, e := range f.Expectations {
		if e.Type != dnswire.TypeDS {
			keys = append(keys, obs.RecordsKey(f.Domain, e.Name, e.Type).String())
		}
	}
	return keys
}

// The keys are the plan of the file without its serial check: the lines, the
// probes of the names that they point at, then the wildcard checks.
func TestExpectKeysAreThePlanWithoutTheSerialCheck(t *testing.T) {
	f := dngqParse(t,
		"corp.test. A 10.53.0.80",
		"corp.test. DS none",
		"corp.test. MX 10 mail.dnshost.test.",
		"cdn.corp.test. CNAME edge.dnshost.test.",
		"*.corp.test. A none",
		"*.sub.corp.test. A none",
		"sub.corp.test. NS ns1.sub.corp.test.",
		"www.corp.test. A 10.53.0.81",
		"edge.dnshost.test. A 10.53.0.84",
	)
	keys := expectKeys(f)
	want := []string{
		"delegation corp.test. corp.test. NS",
		"ds corp.test. corp.test. DS",
		"records corp.test. corp.test. A",
		"records corp.test. corp.test. MX",
		"records corp.test. cdn.corp.test. CNAME",
		"records corp.test. sub.corp.test. NS",
		"records corp.test. www.corp.test. A",
		"records corp.test. edge.dnshost.test. A",
		"records corp.test. mail.dnshost.test. A",
		"records corp.test. ns1.sub.corp.test. A",
		"wildcard corp.test. corp.test. A",
		"wildcard corp.test. sub.corp.test. A",
	}
	if got := dngqKeys(keys); !slices.Equal(got, want) {
		t.Errorf("expectKeys gave\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	for _, k := range keys {
		if err := (observe.Check{Key: k, Interval: checkInterval}).Validate(); err != nil {
			t.Errorf("%s: %v", k, err)
		}
	}
}

func TestExpectKeysOfAFileWithNoLine(t *testing.T) {
	want := []string{"delegation corp.test. corp.test. NS", "ds corp.test. corp.test. DS"}
	if got := dngqKeys(expectKeys(dngqParse(t))); !slices.Equal(got, want) {
		t.Errorf("expectKeys gave %q, want %q", got, want)
	}
}

// A file with no none line at a wildcard owner has its old checks first.
func TestExpectKeysKeepTheOldChecksFirst(t *testing.T) {
	for _, lines := range [][]string{
		{"corp.test. A 10.53.0.80", "www.corp.test. A 10.53.0.81"},
		{"corp.test. A 10.53.0.80", "corp.test. DS none", "corp.test. MX 10 mail.dnshost.test.", "*.corp.test. A 10.53.0.99"},
		{"cdn.corp.test. CNAME edge.dnshost.test.", "edge.dnshost.test. A 10.53.0.84", "sub.corp.test. NS ns1.sub.corp.test."},
		{"corp.test. NS ns1.corp.test. | ns2.corp.test.", `corp.test. TXT "v=spf1 include:spf.dnshost.test. -all"`},
	} {
		f := dngqParse(t, lines...)
		got, old := dngqKeys(expectKeys(f)), dngqOldKeys(f)
		if len(got) < len(old) || !slices.Equal(got[:len(old)], old) {
			t.Errorf("file %q: expectKeys gave\n%s\nwant these first\n%s", lines, strings.Join(got, "\n"), strings.Join(old, "\n"))
		}
	}
}

// The wildcard check takes the place of the none line at the wildcard owner.
func TestExpectKeysHaveNoRecordsCheckForANoneLineThatAWildcardCheckOwns(t *testing.T) {
	f := dngqParse(t, "*.corp.test. A none", "www.corp.test. A 10.53.0.81")
	want := []string{
		"delegation corp.test. corp.test. NS",
		"ds corp.test. corp.test. DS",
		"records corp.test. www.corp.test. A",
		"wildcard corp.test. corp.test. A",
	}
	if got := dngqKeys(expectKeys(f)); !slices.Equal(got, want) {
		t.Errorf("expectKeys gave\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// emlcWorld is cliWorld with an SPF record at corp.test. and a DMARC record
// at _dmarc.corp.test.
func emlcWorld(q []byte, tcp bool) []byte {
	m, err := dnswire.Parse(q)
	if err != nil || len(m.Question) != 1 {
		return nil
	}
	name, qtype := strings.ToLower(m.Question[0].Name.String()), m.Question[0].Type
	text := map[string]string{
		"corp.test.":        "v=spf1 mx include:evil.test ~all",
		"_dmarc.corp.test.": "v=DMARC1; p=none; rua=mailto:x@evil.test",
	}[name]
	if text == "" || qtype != dnswire.TypeTXT {
		return cliWorld(q, tcp)
	}
	record := cliRR(name, 300, dnswire.TXT{Strings: []string{text}})
	return cliAnswer(q, transportQR|transportAA, []dnswire.Record{record}, nil, nil)
}

// emlcFile expects a stricter SPF record and a stricter DMARC record than
// emlcWorld serves.
const emlcFile = "domain corp.test.\n" +
	"corp.test. NS ns1.corp.test. | ns2.corp.test.\n" +
	"corp.test. DS none\n" +
	"corp.test. TXT \"v=spf1 mx -all\"\n" +
	"_dmarc.corp.test. TXT \"v=DMARC1; p=reject\"\n"

// emlcBlock gives the text lines of the finding of rule at name: its first
// line and the lines that are indented after it.
func emlcBlock(t *testing.T, lines []string, rule, name string) []string {
	t.Helper()
	for i, l := range lines {
		if strings.HasPrefix(l, "finding medium "+rule+" records "+name+" TXT") {
			end := i + 1
			for end < len(lines) && strings.HasPrefix(lines[end], "  ") {
				end++
			}
			return lines[i:end]
		}
	}
	t.Errorf("no finding of %s at %s in:\n%s", rule, name, strings.Join(lines, "\n"))
	return nil
}

// A Value line "weaker <word>" prints as "  weaker <word>" after the lines of
// the servers.
func TestCheckExpectPrintsTheWordsOfAMailRule(t *testing.T) {
	s := transportStart(t, emlcWorld)
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", expFile(t, emlcFile))
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	seen := "  seen " + s.addr + " " + expRootHost + " "
	cliCompare(t, emlcBlock(t, lines, "spf", "corp.test."), []string{
		"finding medium spf records corp.test. TXT",
		`  expected "v=spf1 mx -all"`,
		seen + `"v=spf1 mx include:evil.test ~all"`,
		"  weaker all gives softfail in place of fail",
		"  weaker include:evil.test gives pass in place of fail",
	})
	cliCompare(t, emlcBlock(t, lines, "dmarc", "_dmarc.corp.test."), []string{
		"finding medium dmarc records _dmarc.corp.test. TXT",
		`  expected "v=DMARC1; p=reject"`,
		seen + `"v=DMARC1; p=none; rua=mailto:x@evil.test"`,
		"  weaker p=none in place of p=reject",
		"  weaker rua also sends reports to mailto:x@evil.test",
	})
	for _, l := range lines {
		if strings.HasPrefix(l, "  seen ") && strings.Contains(l, "weaker ") {
			t.Errorf("a word printed as a seen line: %q", l)
		}
	}
}

// A record that differs and permits nothing more gives the finding with no
// word and no "weaker" key: the file writes the same policy without spaces.
func TestCheckExpectPrintsNoWordForARecordThatPermitsNothingMore(t *testing.T) {
	s := transportStart(t, emlcWorld)
	file := expFile(t, strings.Replace(emlcFile, `"v=DMARC1; p=reject"`, `"v=DMARC1;p=none;rua=mailto:x@evil.test"`, 1))
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliCompare(t, emlcBlock(t, lines, "dmarc", "_dmarc.corp.test."), []string{
		"finding medium dmarc records _dmarc.corp.test. TXT",
		`  expected "v=DMARC1;p=none;rua=mailto:x@evil.test"`,
		"  seen " + s.addr + " " + expRootHost + ` "v=DMARC1; p=none; rua=mailto:x@evil.test"`,
	})
	_, out, _ := transportRun("check", "--json", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	n := 0
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, `"rule":"dmarc"`) {
			n++
			if strings.Contains(l, "weaker") {
				t.Errorf("the finding holds a weaker key although the record permits nothing more: %s", l)
			}
		}
	}
	if n != 1 {
		t.Errorf("%d dmarc findings in the JSON output; want 1:\n%s", n, out)
	}
}

// With --json the words are the list "weaker", after "seen", and the lines of
// the servers hold no word.
func TestCheckExpectJSONHasTheWordsOfAMailRule(t *testing.T) {
	s := transportStart(t, emlcWorld)
	code, out, errOut := transportRun("check", "--json", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", expFile(t, emlcFile))
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	found := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		var f struct {
			Type, Rule, Kind, Name, RType, Expected string
			Seen                                    []struct{ Address, Host, Text string }
			Weaker                                  []string
		}
		if err := json.Unmarshal([]byte(line), &f); err != nil {
			t.Fatalf("line %q: %v", line, err)
		}
		if f.Type != "finding" || (f.Rule != "spf" && f.Rule != "dmarc") {
			continue
		}
		found[f.Rule] = true
		var want []string
		var text, expected string
		if f.Rule == "spf" {
			want = []string{"all gives softfail in place of fail", "include:evil.test gives pass in place of fail"}
			text, expected = `"v=spf1 mx include:evil.test ~all"`, `"v=spf1 mx -all"`
		} else {
			want = []string{"p=none in place of p=reject", "rua also sends reports to mailto:x@evil.test"}
			text, expected = `"v=DMARC1; p=none; rua=mailto:x@evil.test"`, `"v=DMARC1; p=reject"`
		}
		if !slices.Equal(f.Weaker, want) || f.Expected != expected || len(f.Seen) != 1 || f.Seen[0].Text != text ||
			f.Seen[0].Address != s.addr || f.Seen[0].Host != "" || f.Kind != "records" || f.RType != "TXT" {
			t.Errorf("finding %s: %+v; want the words %q, expected %s and one seen %s", f.Rule, f, want, expected, text)
		}
		// The key comes after "seen" and the words are a list of strings.
		if i, j := strings.Index(line, `"seen":`), strings.Index(line, `"weaker":[`); i < 0 || j < i {
			t.Errorf("line %s: the key weaker does not follow seen", line)
		}
	}
	if !found["spf"] || !found["dmarc"] {
		t.Errorf("findings of %v; want spf and dmarc in:\n%s", found, out)
	}
}
