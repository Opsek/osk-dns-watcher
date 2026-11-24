package start

import (
	"cmp"
	"context"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The NS line of a new file and the address lines of the nameservers. The
// rule that these tests hold init to: a new file never alerts at once, and
// nothing is trusted without being shown before the question.

const nswD = "example.com."

// nswServer gives the server text "<addr> <host>" that the warning shows.
func nswServer(host, addr string) string { return addr + " " + host }

// nswChild are the servers of the domain: ns1 and ns2 of the fake world, and
// two more for the tests that need more sets.
var nswChild = [][2]string{
	{"ns1.example.net.", iniNS1Addr}, {"ns2.example.net.", iniNS2Addr},
	{"ns3.example.net.", "198.51.100.55:53"}, {"ns4.example.net.", "198.51.100.56:53"},
}

// nswApex gives the apex NS set of nswD from the servers of the domain, the
// set of the ith server in sets[i], each a list of hosts.
func nswApex(sets ...[]string) []obs.Answer {
	var answers []obs.Answer
	for i, hosts := range sets {
		answers = append(answers, iniAt(nswChild[i][0], nswChild[i][1], iniRecords(nswD, dnswire.TypeNS, hosts...)))
	}
	return answers
}

func nswNet(ns ...int) []string {
	var hosts []string
	for _, n := range ns {
		hosts = append(hosts, fmt.Sprintf("ns%d.example.net.", n))
	}
	return hosts
}

func nswText(hosts []string) string { return strings.Join(hosts, " | ") }

// nswLinesWith gives the lines of the fake world with the NS line ns and the
// host lines, which sort after the names under the apex that start with "_"
// and before www.
func nswLinesWith(ns string, hosts ...string) []string {
	lines := slices.Clone(iniLines(nswD))
	lines[2] = nswD + " NS " + ns
	return slices.Insert(lines, len(lines)-1, hosts...)
}

var (
	nswP  = nswServer(iniParentHost, iniParentAddr)
	nswC1 = nswServer("ns1.example.net.", iniNS1Addr)
	nswC2 = nswServer("ns2.example.net.", iniNS2Addr)
	nswC3 = nswServer("ns3.example.net.", "198.51.100.55:53")
)

// Each set that the servers give is one alternative of the line, and the
// warning names it with its servers; above four sets there is no line, and
// the warning of a missing line.
func TestInitShowsEachNSSetBeforeTheQuestion(t *testing.T) {
	d := nswD
	nsKey := iniKey(d, d, dnswire.TypeNS)
	for _, c := range []struct {
		name    string
		apex    []obs.Answer
		lines   []string
		skips   []string
		warning string
	}{
		{"one set: no warning", nswApex(nswNet(1, 2), nswNet(2, 1)), iniLines(d), []string{iniAliasSkip(d)}, ""},
		{"the servers of the domain give one more nameserver", nswApex(nswNet(1, 2, 3), nswNet(1, 2, 3)),
			nswLinesWith(nswText(nswNet(1, 2)) + " || " + nswText(nswNet(1, 2, 3))), []string{iniAliasSkip(d)},
			iniSetsWarning(d, expect.NSSource{Text: nswText(nswNet(1, 2)), Parent: []string{nswP}},
				expect.NSSource{Text: nswText(nswNet(1, 2, 3)), Zone: []string{nswC1, nswC2}})},
		{"the servers of the domain differ among themselves", nswApex(nswNet(1, 2), nswNet(1, 3)),
			nswLinesWith(nswText(nswNet(1, 2)) + " || " + nswText(nswNet(1, 3))), []string{iniAliasSkip(d)},
			iniSetsWarning(d, expect.NSSource{Text: nswText(nswNet(1, 2)), Parent: []string{nswP}, Zone: []string{nswC1}},
				expect.NSSource{Text: nswText(nswNet(1, 3)), Zone: []string{nswC2}})},
		{"four sets", nswApex(nswNet(1), nswNet(2), nswNet(1, 2, 3)),
			nswLinesWith(nswText(nswNet(1)) + " || " + nswText(nswNet(1, 2)) + " || " + nswText(nswNet(1, 2, 3)) + " || " + nswText(nswNet(2))),
			[]string{iniAliasSkip(d)},
			iniSetsWarning(d, expect.NSSource{Text: nswText(nswNet(1)), Zone: []string{nswC1}},
				expect.NSSource{Text: nswText(nswNet(1, 2)), Parent: []string{nswP}},
				expect.NSSource{Text: nswText(nswNet(1, 2, 3)), Zone: []string{nswC3}},
				expect.NSSource{Text: nswText(nswNet(2)), Zone: []string{nswC2}})},
		{"five sets: no line and the warning of a missing line", nswApex(nswNet(1), nswNet(2), nswNet(1, 2, 3), nswNet(3)),
			stfWithout(iniLines(d), "NS"),
			[]string{d + " NS: servers disagree: " + nswP + " gives " + nswText(nswNet(1, 2)) + "; " + nswC1 + " gives " + nswText(nswNet(1)), iniAliasSkip(d)},
			stfWarning(d)},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = map[string][]obs.Answer{nsKey: c.apex}
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, c.lines, c.skips...)+c.warning)+"yes\n"+s.wrote(d))
			data := s.written(d)["example.com.expect"]
			iniSame(t, "example.com.expect", data, iniStamp+strings.Join(c.lines, "\n")+"\n")
			iniNoFindings(t, data, s.runner.observations())
		})
	}
}

// nswEvil is the set that a lying server gives.
var nswEvil = []string{"evil1.attacker.example.", "evil2.attacker.example."}

// A lying server gets its set into the NS line only as an alternative, and
// the warning shows that set with the address of the server that gave it
// while init waits for the answer to the question. Without yes nothing is
// written.
func TestInitShowsTheSetOfALyingServerBeforeTheQuestion(t *testing.T) {
	d := nswD
	line := nswText(nswNet(1, 2)) + " || " + nswText(nswEvil)
	for _, c := range []struct {
		name    string
		over    map[string][]obs.Answer
		warning string
	}{
		{"a server of the domain", map[string][]obs.Answer{iniKey(d, d, dnswire.TypeNS): nswApex(nswNet(1, 2), nswEvil)},
			iniSetsWarning(d, expect.NSSource{Text: nswText(nswNet(1, 2)), Parent: []string{nswP}, Zone: []string{nswC1}},
				expect.NSSource{Text: nswText(nswEvil), Zone: []string{nswC2}})},
		{"a server of the parent zone", map[string][]obs.Answer{obs.DelegationKey(iniName(d)).String(): {
			iniAt(iniParentHost, iniParentAddr, iniRecords(d, dnswire.TypeNS, nswNet(1, 2)...)),
			iniAt("ns2.parent.example.", "192.0.2.54:53", iniRecords(d, dnswire.TypeNS, nswEvil...)),
		}},
			iniSetsWarning(d, expect.NSSource{Text: nswText(nswNet(1, 2)), Parent: []string{nswP}, Zone: []string{nswC1, nswC2}},
				expect.NSSource{Text: nswText(nswEvil), Parent: []string{nswServer("ns2.parent.example.", "192.0.2.54:53")}})},
	} {
		t.Run(c.name, func(t *testing.T) {
			lines := nswLinesWith(line)
			block := iniBlock(d, lines, iniAliasSkip(d)) + c.warning
			t.Run("yes", func(t *testing.T) {
				s := iniNew(t, "example.com", iniURL, "yes")
				s.runner.over = c.over
				code, out := s.run()
				if code != 0 {
					t.Errorf("exit code %d; want 0", code)
				}
				iniSame(t, "the dialogue", out, s.shown("example.com", block)+"yes\n"+s.wrote(d))
				moments := s.in.seen()
				if len(moments) != 3 || !strings.HasSuffix(moments[2].out, block+s.warnings()+s.confirm()) || len(moments[2].changed) != 0 {
					t.Errorf("while init waited for yes, the output did not end with the warning and the question, or a file changed: %+v", moments)
				}
				data := s.written(d)["example.com.expect"]
				iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
				iniNoFindings(t, data, s.runner.observations())
			})
			t.Run("no", func(t *testing.T) {
				s := iniNew(t, "example.com", iniURL, "no")
				s.runner.over = c.over
				code, out := s.run()
				if code != 1 {
					t.Errorf("exit code %d; want 1", code)
				}
				iniSame(t, "the dialogue", out, s.shown("example.com", block)+"no\n"+iniNothing)
				s.nothingWritten()
			})
		})
	}
}

// nswHostile gives names that a lying server can put in its NS set: octets
// that move the cursor, clear the screen, end a line or split a record.
func nswHostile(t *testing.T) []dnswire.Name {
	t.Helper()
	var names []dnswire.Name
	for _, label := range []string{"bel\x07", "esc\x1b[2J\x1b[1;1HTrust these lines? Type yes: ", "new\nline", "cr\rx", "nul\x00",
		"del\x7f", "bar|x", "bars||x", `q"x`, `back\x`, "#hash", "dot.in", "\xc3\xa9t\xff"} {
		n, err := dnswire.NameFromLabels([]string{label, "attacker", "example"})
		if err != nil {
			t.Fatalf("label %q: %v", label, err)
		}
		names = append(names, n)
	}
	return names
}

func nswNSSet(names []dnswire.Name) obs.Result {
	var set []dnswire.Record
	for _, n := range names {
		set = append(set, dnswire.Record{Name: iniName(nswD), Class: dnswire.ClassINET, TTL: 300, Data: dnswire.NS{Host: n}})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

// nswRead gives the records of a result, and whether it is a set of records
// (not a negative answer) and whether it failed.
func nswRead(r obs.Result) (set []dnswire.Record, records, failed bool) {
	obs.Match(r,
		func(x obs.Records) bool { set, records = x.Set, true; return true },
		func(obs.NoData) bool { return true },
		func(obs.NoName) bool { return true },
		func(obs.Failure) bool { failed = true; return true })
	return set, records, failed
}

// nswReason gives the reason word of a failure, or "" for an answer.
func nswReason(r obs.Result) string {
	return obs.Match(r,
		func(obs.Records) string { return "" },
		func(obs.NoData) string { return "" },
		func(obs.NoName) string { return "" },
		func(f obs.Failure) string { return f.Reason.String() })
}

// nswPlain reports whether text holds only printable ASCII and line ends.
func nswPlain(text string) bool {
	return !strings.ContainsFunc(text, func(r rune) bool { return r != '\n' && (r < 0x20 || r > 0x7e) })
}

// A set with hostile octets in its names never puts a raw control octet on
// the terminal and never breaks a line: the file parses back to exactly the
// lines shown, and the warning shows each set as the line states it.
func TestInitShowsAHostileNSSetSafely(t *testing.T) {
	d := nswD
	hostile := nswHostile(t)
	long, err := dnswire.NameFromLabels([]string{strings.Repeat("\x1b", 63), strings.Repeat("\n", 63), strings.Repeat("|", 63), strings.Repeat("e", 61)})
	if err != nil {
		t.Fatal(err)
	}
	var hundred []dnswire.Name
	for i := range 100 {
		n, err := dnswire.NameFromLabels([]string{fmt.Sprintf("n%03d\x1b[%dm", i, i), "attacker", "example"})
		if err != nil {
			t.Fatal(err)
		}
		hundred = append(hundred, n)
	}
	evilHost, err := dnswire.NameFromLabels([]string{"ns2\x1b]0;owned\x07\n", "example", "net"})
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name  string
		names []dnswire.Name
		host  dnswire.Name // the name of the lying server
	}{
		{"control octets, escapes and separators", hostile, iniName("ns2.example.net.")},
		{"the longest name", []dnswire.Name{long}, iniName("ns2.example.net.")},
		{"a hundred names", hundred, iniName("ns2.example.net.")},
		{"from a server whose own name is hostile", hostile, evilHost},
	} {
		t.Run(c.name, func(t *testing.T) {
			lie := obs.Answer{Proof: obs.Proof{Server: obs.Server{Name: c.host, Addr: netip.MustParseAddrPort(iniNS2Addr)}}, Result: nswNSSet(c.names)}
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeNS): {nswApex(nswNet(1, 2))[0], lie}}
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if !nswPlain(out) {
				t.Errorf("the output holds an octet that is not printable ASCII:\n%q", out)
			}
			data := strings.TrimPrefix(s.written(d)["example.com.expect"], iniStamp)
			if !nswPlain(data) {
				t.Errorf("the file holds an octet that is not printable ASCII:\n%q", data)
			}
			f, err := expect.Parse([]byte(data))
			if err != nil {
				t.Fatalf("the file does not parse: %v\n%s", err, data)
			}
			if f.String() != data {
				t.Errorf("the file parses back as\n%q\nwant\n%q", f.String(), data)
			}
			lines, _ := iniShown(out, d)
			if want := iniLinesOf(data); !slices.Equal(lines, want) {
				t.Errorf("init showed\n%q\nthe file holds\n%q", lines, want)
			}
			e, ok := f.Find(iniName(d), dnswire.TypeNS)
			if !ok || len(e.Sets) != 2 {
				t.Fatalf("the NS line %q; want two sets", e.String())
			}
			if set, _, _ := nswRead(lie.Result); !e.Match(set) {
				t.Errorf("the NS line %q does not hold the set that the server gave", e.String())
			}
			// The warning: a head line, then each set as the line states it,
			// then the servers of each, then the last line.
			all := strings.Split(out, "\n")
			at := slices.IndexFunc(all, func(l string) bool { return strings.HasPrefix(l, "warning the servers of "+d) })
			if at < 0 || at+7 >= len(all) {
				t.Fatalf("no warning of several sets:\n%s", out)
			}
			alts := strings.Split(e.FormText(), " || ")
			got := all[at+1 : at+7]
			want := []string{"  " + alts[0], "    given by the parent zone: " + nswP, "    given by the servers of " + d + ": " + nswC1,
				"  " + alts[1], "    given by the servers of " + d + ": " + iniNS2Addr + " " + c.host.Lower().String()}
			if !slices.Equal(got[:5], want) || !strings.HasPrefix(got[5], "If a name in these sets is not one of your nameservers") {
				t.Errorf("the warning reads\n%q\nwant\n%q", got, want)
			}
		})
	}
}

// The same answers in another order, and a second run, give the same file,
// octet for octet.
func TestInitWritesTheSameFileForTheSameAnswersInAnyOrder(t *testing.T) {
	d := nswD
	over := nswWorld(nswHosts, true)
	over[obs.DelegationKey(iniName(d)).String()] = append(over[obs.DelegationKey(iniName(d)).String()],
		iniAt("ns2.parent.example.", "192.0.2.54:53", nswDelegation(nswHosts[:1], true).Result))
	over[iniKey(d, d, dnswire.TypeNS)] = []obs.Answer{
		iniAt("ns1.example.com.", iniNS1Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.com.", "ns2.example.com.")),
		iniAt("ns2.example.com.", iniNS2Addr, iniRecords(d, dnswire.TypeNS, "ns2.example.com.", "ns1.example.com.", "ns3.example.net.")),
		iniAt("ns2.example.com.", "[2001:db8::54]:53", iniFail(obs.ReasonNoRoute)),
	}
	reversed := map[string][]obs.Answer{}
	for k, answers := range over {
		reversed[k] = slices.Clone(answers)
		slices.Reverse(reversed[k])
	}
	var files []string
	for _, o := range []map[string][]obs.Answer{over, over, reversed} {
		s := iniNew(t, "example.com", iniURL, "yes")
		s.runner.over = o
		if code, out := s.run(); code != 0 {
			t.Fatalf("exit code %d; want 0\n%s", code, out)
		}
		files = append(files, s.written(d)["example.com.expect"])
	}
	if !strings.Contains(files[0], " || ") {
		t.Fatalf("test fault: the NS line accepts one set:\n%s", files[0])
	}
	if files[1] != files[0] || files[2] != files[0] {
		t.Errorf("the files differ:\n%s\nsecond run:\n%s\nanswers in reverse order:\n%s", files[0], files[1], files[2])
	}
}

// A file whose NS line accepts two sets finds nothing in the answers it was
// made from. A move of the delegation to a third set is the critical alert;
// a move to the set that only the servers of the domain gave is not, which
// is the cost of accepting several sets.
func TestInitNSLineOfTwoSetsAlertsOnAThirdSetButNotOnTheOtherSet(t *testing.T) {
	d := nswD
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeNS): nswApex(nswNet(1, 2, 3), nswNet(1, 2, 3))}
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0\n%s", code, out)
	}
	data := s.written(d)["example.com.expect"]
	iniNoFindings(t, data, s.runner.observations())
	f, err := expect.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	delegation := func(hosts ...string) obs.Observation {
		return obs.Observation{Key: obs.DelegationKey(iniName(d)), Zone: iniName("com."),
			Answers: []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniRecords(d, dnswire.TypeNS, hosts...))}}
	}
	apex := func(hosts ...string) obs.Observation {
		return obs.Observation{Key: obs.RecordsKey(iniName(d), iniName(d), dnswire.TypeNS), Zone: iniName(d), Answers: nswApex(hosts, hosts)}
	}
	t.Run("a third set at the parent zone: critical", func(t *testing.T) {
		found := decide.Findings(f, delegation("ns.attacker.example.", "ns1.example.net."))
		if len(found) != 1 || found[0].Rule != decide.RuleNameServers || found[0].Severity != decide.SeverityCritical {
			t.Errorf("findings %+v; want one critical nameservers finding", found)
		}
	})
	t.Run("a third set at the servers of the domain: high", func(t *testing.T) {
		found := decide.Findings(f, apex("ns.attacker.example.", "ns1.example.net."))
		if len(found) != 1 || found[0].Rule != decide.RuleRecordSet || found[0].Severity != decide.SeverityHigh {
			t.Errorf("findings %+v; want one high record-set finding", found)
		}
	})
	t.Run("the cost: the parent zone moves to the set of the servers of the domain, and nothing is found", func(t *testing.T) {
		if found := decide.Findings(f, delegation(nswNet(1, 2, 3)...)); len(found) != 0 {
			t.Errorf("findings %+v; want none", found)
		}
	})
}

// nswWalkFails is the fake world, except that the walk to the servers of the
// domain fails for the check of key, as observe gives it: one answer from no
// server, and no zone.
type nswWalkFails struct {
	*iniRunner
	key string
}

func (r nswWalkFails) Run(ctx context.Context, c observe.Check) (obs.Observation, error) {
	o, err := r.iniRunner.Run(ctx, c)
	if c.Key.String() == r.key {
		o = obs.Observation{Key: c.Key, Answers: []obs.Answer{{Result: iniFail(obs.ReasonWalk)}}}
	}
	return o, err
}

// A walk that fails on its way to the servers of the domain is a failed
// answer like any other: the NS line holds the parent's set, the address
// checks of its hosts run, and the warning says that the line rests without
// the servers of the domain. The failed walk carries no zone, which tells
// nothing about a cut in the domain.
func TestInitWritesTheParentSetWhenTheWalkToTheServersOfTheDomainFails(t *testing.T) {
	d := nswD
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = nswWorld(nswHosts, true)
	s.init.Observer = nswWalkFails{s.runner, iniKey(d, d, dnswire.TypeNS)}
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	lines := nswLinesWith(nswNames(nswHosts), nswHostLines(nswHosts)...)
	noPath := "warning osk-dns-watcher could not reach the servers of " + d + " (the walk from the root found no path to them), " +
		"so its NS line holds what the parent zone gave. If the servers hold another set, osk-dns-watcher alerts at its first check.\n"
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d))+noPath)+"yes\n"+s.wrote(d))
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
	iniNoFindings(t, data, s.runner.observations())
}

// --- the addresses of the nameservers inside the domain ---

// nswHost is a nameserver inside the domain and its addresses; "" is no
// address of that type.
type nswHost struct{ name, a, aaaa string }

var nswHosts = []nswHost{{"ns1.example.com.", "192.0.2.1", "2001:db8::1"}, {"ns2.example.com.", "192.0.2.2", ""}}

// nswDelegation is the parent's answer for hosts, with their glue when glue.
func nswDelegation(hosts []nswHost, glue bool) obs.Answer {
	var r obs.Records
	for _, h := range hosts {
		r.Set = append(r.Set, iniRR(nswD, dnswire.TypeNS, h.name))
		if !glue {
			continue
		}
		if h.a != "" {
			r.Glue = append(r.Glue, iniRR(h.name, dnswire.TypeA, h.a))
		}
		if h.aaaa != "" {
			r.Glue = append(r.Glue, iniRR(h.name, dnswire.TypeAAAA, h.aaaa))
		}
	}
	return iniAt(iniParentHost, iniParentAddr, obs.RecordsResult(r))
}

// nswInZone is one result from both servers of the domain, which are its
// own hosts ns1 and ns2.
func nswInZone(r obs.Result) []obs.Answer {
	return []obs.Answer{iniAt("ns1.example.com.", iniNS1Addr, r), iniAt("ns2.example.com.", iniNS2Addr, r)}
}

// nswWorld gives the answers of a domain whose NS set is hosts, at the
// parent zone and at the apex, and the addresses of each host.
func nswWorld(hosts []nswHost, glue bool) map[string][]obs.Answer {
	d := nswD
	var names []string
	for _, h := range hosts {
		names = append(names, h.name)
	}
	over := map[string][]obs.Answer{
		obs.DelegationKey(iniName(d)).String(): {nswDelegation(hosts, glue)},
		iniKey(d, d, dnswire.TypeNS):           nswInZone(iniRecords(d, dnswire.TypeNS, names...)),
	}
	for _, h := range hosts {
		if !iniName(h.name).IsSubdomainOf(iniName(d)) {
			continue
		}
		for _, x := range []struct {
			t    dnswire.Type
			addr string
		}{{dnswire.TypeA, h.a}, {dnswire.TypeAAAA, h.aaaa}} {
			r := iniNoData(d)
			if x.addr != "" {
				r = iniRecords(h.name, x.t, x.addr)
			}
			over[iniKey(d, h.name, x.t)] = nswInZone(r)
		}
	}
	return over
}

// nswHostLines are the address lines of hosts as File.String prints them.
func nswHostLines(hosts []nswHost) []string {
	var lines []string
	for _, h := range hosts {
		lines = append(lines, h.name+" A "+cmp.Or(h.a, "none"), h.name+" AAAA "+cmp.Or(h.aaaa, "none"))
	}
	return lines
}

func nswNames(hosts []nswHost) string {
	var names []string
	for _, h := range hosts {
		names = append(names, h.name)
	}
	return strings.Join(names, " | ")
}

// nswHostKeys are the checks of the addresses of hosts.
func nswHostKeys(hosts []nswHost) []string {
	var keys []string
	for _, h := range hosts {
		keys = append(keys, iniKey(nswD, h.name, dnswire.TypeA), iniKey(nswD, h.name, dnswire.TypeAAAA))
	}
	return keys
}

// nswChecked fails unless the checks that ran are those of the fake world and
// extra, each once.
func nswChecked(t *testing.T, r *iniRunner, extra []string) {
	t.Helper()
	keys := r.keys()
	slices.Sort(keys)
	if want := slices.Sorted(slices.Values(slices.Concat(iniKeys(nswD, true), extra))); !slices.Equal(keys, want) {
		t.Errorf("checks %q; want each of %q once", keys, want)
	}
}

// Each nameserver inside the domain gets its A line and its AAAA line, none
// for a type it has no address of, so that its glue is watched; init asks
// for them after the first answers, and the parent's glue matches them.
func TestInitWritesTheAddressLinesOfEachNameServerInsideTheDomain(t *testing.T) {
	d := nswD
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = nswWorld(nswHosts, true)
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	lines := nswLinesWith(nswNames(nswHosts), nswHostLines(nswHosts)...)
	if !slices.Contains(lines, "ns2.example.com. AAAA none") {
		t.Fatalf("test fault: %q", lines)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
	iniNoFindings(t, data, s.runner.observations())
	nswChecked(t, s.runner, nswHostKeys(nswHosts))
}

// A host outside the domain gets no address line and no check: its glue is
// not the parent's to give, and its zone is not the owner's.
func TestInitAsksNoAddressOfANameServerOutsideTheDomain(t *testing.T) {
	d := nswD
	hosts := []nswHost{{"ns.other.example.", "", ""}, {"ns1.example.com.", "192.0.2.1", ""}, {"ns1.notexample.com.", "", ""}}
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = nswWorld(hosts, true)
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	lines := nswLinesWith("ns.other.example. | ns1.example.com. | ns1.notexample.com.", nswHostLines(hosts[1:2])...)
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	nswChecked(t, s.runner, nswHostKeys(hosts[1:2]))
}

func nswManyHosts(d string) string {
	return "warning osk-dns-watcher does not watch the addresses of the nameservers of " + d + ", because its NS line names more than 8 hosts " +
		"inside the domain. Add their A and AAAA lines by hand.\n"
}

// At most 8 hosts get address lines, 16 checks more; with 9 there is no
// address check and no address line, the NS line stays, and a warning says
// so.
func TestInitWatchesTheAddressesOfAtMostEightNameServers(t *testing.T) {
	d := nswD
	hosts := func(n int) []nswHost {
		var h []nswHost
		for i := 1; i <= n; i++ {
			h = append(h, nswHost{fmt.Sprintf("ns%d.example.com.", i), fmt.Sprintf("192.0.2.%d", i), ""})
		}
		return h
	}
	t.Run("8 hosts", func(t *testing.T) {
		h := hosts(8)
		s := iniNew(t, "example.com", iniURL, "yes")
		s.runner.over = nswWorld(h, true)
		code, out := s.run()
		if code != 0 {
			t.Errorf("exit code %d; want 0", code)
		}
		lines := nswLinesWith(nswNames(h), nswHostLines(h)...)
		iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
		nswChecked(t, s.runner, nswHostKeys(h))
		if n := s.runner.count(); n != 14+16 {
			t.Errorf("%d checks ran; want 30", n)
		}
		iniNoFindings(t, s.written(d)["example.com.expect"], s.runner.observations())
	})
	t.Run("9 hosts", func(t *testing.T) {
		h := hosts(9)
		s := iniNew(t, "example.com", iniURL, "yes")
		s.runner.over = nswWorld(h, true)
		code, out := s.run()
		if code != 0 {
			t.Errorf("exit code %d; want 0", code)
		}
		lines := nswLinesWith(nswNames(h))
		iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d))+nswManyHosts(d))+"yes\n"+s.wrote(d))
		nswChecked(t, s.runner, nil)
		iniNoFindings(t, s.written(d)["example.com.expect"], s.runner.observations())
	})
}

// Address lines that the parent's glue does not allow are left out, with
// the glue as the reason, so that the first check of the new file finds
// nothing. Kept, they would give the critical glue alert at once.
func TestInitDropsTheAddressLinesOfANameServerWhoseGlueDiffers(t *testing.T) {
	d := nswD
	why := func(what string) []string {
		r := ": the parent zone gives other glue: " + nswP + " gives " + what
		return []string{"ns2.example.com. A" + r, "ns2.example.com. AAAA" + r}
	}
	for _, c := range []struct {
		name string
		glue nswHost // the glue of ns2 at the parent zone
		skip []string
	}{
		{"another address", nswHost{"ns2.example.com.", "192.0.2.99", ""}, why("A 192.0.2.99")},
		{"an IPv6 address the host does not have", nswHost{"ns2.example.com.", "192.0.2.2", "2001:db8::66"}, why("AAAA 2001:db8::66")},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = nswWorld(nswHosts, true)
			delegation := obs.DelegationKey(iniName(d)).String()
			s.runner.over[delegation] = []obs.Answer{nswDelegation([]nswHost{nswHosts[0], c.glue}, true)}
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			lines := nswLinesWith(nswNames(nswHosts), nswHostLines(nswHosts[:1])...)
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, append(c.skip, iniAliasSkip(d))...))+"yes\n"+s.wrote(d))
			data := s.written(d)["example.com.expect"]
			iniNoFindings(t, data, s.runner.observations())
			// The lines that were left out would have made the delegation
			// check alert.
			kept, err := expect.Parse([]byte(data + strings.Join(nswHostLines(nswHosts[1:]), "\n") + "\n"))
			if err != nil {
				t.Fatal(err)
			}
			o := obs.Observation{Key: obs.DelegationKey(iniName(d)), Zone: iniName("com."), Answers: s.runner.over[delegation]}
			found := decide.Findings(kept, o)
			if len(found) != 1 || found[0].Rule != decide.RuleGlue || found[0].Severity != decide.SeverityCritical {
				t.Errorf("with the lines of ns2 the delegation check finds %+v; want the critical glue finding", found)
			}
		})
	}
}

// A host whose address answer failed twice gets no line of that type. Its
// glue of that type then has no line to be compared with, so its other line
// goes too, and its reason says so.
func TestInitLeavesOutTheAddressesOfANameServerWhoseAnswerFailed(t *testing.T) {
	d := nswD
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = nswWorld(nswHosts, true)
	failedKey := iniKey(d, "ns1.example.com.", dnswire.TypeA)
	s.runner.over[failedKey] = nswInZone(iniFail(obs.ReasonTimeout))
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	lines := nswLinesWith(nswNames(nswHosts), nswHostLines(nswHosts[1:])...)
	skips := []string{
		"ns1.example.com. A: " + nswServer("ns1.example.com.", iniNS1Addr) + " gave no answer: timeout",
		"ns1.example.com. AAAA: the A address of the host could not be read, so its glue at the parent zone cannot be compared",
		iniAliasSkip(d),
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, skips...))+"yes\n"+s.wrote(d))
	iniNoFindings(t, s.written(d)["example.com.expect"], s.runner.observations())
	runs := 0
	for _, k := range s.runner.keys() {
		if k == failedKey {
			runs++
		}
	}
	if runs != 2 {
		t.Errorf("the failed address check ran %d times; want 2", runs)
	}
}

// --- the checks of the addresses are bounded ---

// nswKeysOf gives the observations of the delegation and of the apex for the
// sets given: the first from the parent zone, each other from one server of
// the domain.
func nswKeysOf(sets ...[]string) []obs.Observation {
	d := iniName(nswD)
	parent := obs.Observation{Key: obs.DelegationKey(d), Zone: iniName("com."),
		Answers: []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniRecords(nswD, dnswire.TypeNS, sets[0]...))}}
	apex := obs.Observation{Key: obs.RecordsKey(d, d, dnswire.TypeNS), Zone: d}
	for i, hosts := range sets[1:] {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{198, 51, 100, byte(i + 1)}), 53)
		apex.Answers = append(apex.Answers, iniAt(fmt.Sprintf("s%d.example.net.", i), addr.String(), iniRecords(nswD, dnswire.TypeNS, hosts...)))
	}
	if len(apex.Answers) == 0 {
		apex.Answers = []obs.Answer{iniAt("s.example.net.", "198.51.100.9:53", iniRecords(nswD, dnswire.TypeNS, sets[0]...))}
	}
	return []obs.Observation{parent, apex}
}

func nswIn(ns ...int) []string {
	var hosts []string
	for _, n := range ns {
		hosts = append(hosts, fmt.Sprintf("ns%d.example.com.", n))
	}
	return hosts
}

func TestNameServerKeysIsBounded(t *testing.T) {
	d := iniName(nswD)
	var thousand []string
	for i := range 1000 {
		thousand = append(thousand, fmt.Sprintf("h%d.example.com.", i))
	}
	asked := func(names ...string) []obs.Observation {
		var o []obs.Observation
		for _, n := range names {
			f := strings.Fields(n)
			typ, _ := dnswire.ParseType(f[1])
			o = append(o, obs.Observation{Key: obs.RecordsKey(d, iniName(f[0]), typ), Zone: d})
		}
		return o
	}
	// keyTexts gives the keys as text, sorted: the order is not the point.
	keyTexts := func(keys []obs.Key) []string {
		var texts []string
		for _, k := range keys {
			texts = append(texts, k.String())
		}
		slices.Sort(texts)
		return texts
	}
	for _, c := range []struct {
		name  string
		obs   []obs.Observation
		hosts []string // the hosts whose two checks are given
		ok    bool
	}{
		{"8 hosts over 4 sets, repeated and in capitals: 16 checks",
			nswKeysOf(nswIn(1, 2, 3, 4), []string{"NS1.Example.COM.", "ns5.example.com."}, nswIn(6, 7), []string{"ns1.example.com.", "ns8.example.com.", "ns.other.example."}),
			nswIn(1, 2, 3, 4, 5, 6, 7, 8), true},
		{"9 hosts: none", nswKeysOf(nswIn(1, 2, 3, 4), nswIn(5, 6, 7, 8, 9)), nil, false},
		{"1000 hosts in one set: none", nswKeysOf(thousand, thousand), nil, false},
		{"hosts outside the domain only: none", nswKeysOf([]string{"ns1.example.net.", "ns1.notexample.com.", "ns1.example.com.evil."}), nil, true},
		{"five sets: no NS line, no check", nswKeysOf(nswIn(1, 2), nswIn(1), nswIn(2), nswIn(3), nswIn(1, 2, 3)), nil, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			keys, ok := NameServerKeys(d, c.obs)
			var want []string
			for _, h := range c.hosts {
				want = append(want, iniKey(nswD, h, dnswire.TypeA), iniKey(nswD, h, dnswire.TypeAAAA))
			}
			slices.Sort(want)
			if got := keyTexts(keys); ok != c.ok || len(keys) != len(want) || !slices.Equal(got, want) {
				t.Errorf("%d keys %q, ok %v; want %q, %v", len(keys), got, ok, want, c.ok)
			}
		})
	}
	// A check that the look makes already is not asked again: the apex and
	// www as nameservers.
	t.Run("the checks of the first look are not asked again", func(t *testing.T) {
		o := slices.Concat(nswKeysOf([]string{"example.com.", "www.example.com.", "ns1.example.com."}),
			asked("example.com. A", "example.com. AAAA", "www.example.com. A"))
		keys, ok := NameServerKeys(d, o)
		want := []string{iniKey(nswD, "www.example.com.", dnswire.TypeAAAA), iniKey(nswD, "ns1.example.com.", dnswire.TypeA), iniKey(nswD, "ns1.example.com.", dnswire.TypeAAAA)}
		slices.Sort(want)
		if got := keyTexts(keys); !ok || !slices.Equal(got, want) {
			t.Errorf("keys %q, ok %v; want %q", got, ok, want)
		}
	})
}

// --- the property ---

// nswGen makes the answers of one look: the delegation from one or two
// servers of the parent zone, the apex NS set from one to four servers of
// the domain, and then, for the checks that NameServerKeys gives, the
// addresses from two servers. Answers are mostly right, sometimes another
// set, a failure, no data, an alias, or glue that differs.
type nswGen struct {
	rng  *rand.Rand
	pool []string
	addr map[string][2][]string // host: its A and AAAA addresses
}

func (g *nswGen) set() []string {
	n := 1 + g.rng.IntN(3)
	s := slices.Clone(g.pool)
	g.rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
	return s[:n]
}

func (g *nswGen) records(owner string, t dnswire.Type, data []string) obs.Result {
	if len(data) == 0 {
		return iniNoData(nswD)
	}
	return iniRecords(owner, t, data...)
}

func (g *nswGen) delegation(sets [][]string) obs.Observation {
	o := obs.Observation{Key: obs.DelegationKey(iniName(nswD)), Zone: iniName("com.")}
	for i, set := range sets {
		server := [2]string{iniParentHost, iniParentAddr}
		if i == 1 {
			server = [2]string{"ns2.parent.example.", "192.0.2.54:53"}
		}
		if g.rng.IntN(8) == 0 {
			o.Answers = append(o.Answers, iniAt(server[0], server[1], iniFail(obs.ReasonTimeout)))
			continue
		}
		r := obs.Records{}
		for _, h := range set {
			r.Set = append(r.Set, iniRR(nswD, dnswire.TypeNS, h))
			if !iniName(h).IsSubdomainOf(iniName(nswD)) || g.rng.IntN(6) == 0 {
				continue
			}
			for k, t := range []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA} {
				addrs := g.addr[h][k]
				if g.rng.IntN(8) == 0 {
					addrs = []string{map[dnswire.Type]string{dnswire.TypeA: "192.0.2.99", dnswire.TypeAAAA: "2001:db8::99"}[t]}
				}
				for _, a := range addrs {
					r.Glue = append(r.Glue, iniRR(h, t, a))
				}
			}
		}
		o.Answers = append(o.Answers, iniAt(server[0], server[1], obs.RecordsResult(r)))
	}
	// init refuses a delegation without an answer; the property is about
	// the files that init writes.
	if decide.Failed(o) {
		o.Answers[0] = iniAt(iniParentHost, iniParentAddr, g.records(nswD, dnswire.TypeNS, sets[0]))
	}
	return o
}

func (g *nswGen) apex(sets [][]string) obs.Observation {
	d := iniName(nswD)
	o := obs.Observation{Key: obs.RecordsKey(d, d, dnswire.TypeNS), Zone: d}
	if g.rng.IntN(15) == 0 {
		// The walk to the servers of the domain failed: no server, no zone.
		return obs.Observation{Key: o.Key, Answers: []obs.Answer{{Result: iniFail(obs.ReasonWalk)}}}
	}
	for i := range 1 + g.rng.IntN(4) {
		var r obs.Result
		switch n := g.rng.IntN(20); {
		case n < 10:
			r = iniRecords(nswD, dnswire.TypeNS, sets[g.rng.IntN(len(sets))]...)
		case n < 15:
			r = iniRecords(nswD, dnswire.TypeNS, g.set()...)
		case n < 17:
			r = iniFail(obs.ReasonTimeout)
		case n == 17:
			r = iniNoData(nswD)
		case n == 18:
			r = iniNoName(nswD)
		default:
			r = iniRecords(nswD, dnswire.TypeCNAME, "alias.example.net.")
		}
		o.Answers = append(o.Answers, iniAt(fmt.Sprintf("c%d.example.net.", i), fmt.Sprintf("198.51.100.%d:53", 60+i), r))
	}
	return o
}

func (g *nswGen) host(k obs.Key) obs.Observation {
	o := obs.Observation{Key: k, Zone: iniName(nswD)}
	i := 0
	if k.Type == dnswire.TypeAAAA {
		i = 1
	}
	right := g.addr[k.Name.Lower().String()][i]
	for j := range 2 {
		var r obs.Result
		switch n := g.rng.IntN(10); {
		case n < 8:
			r = g.records(k.Name.String(), k.Type, right)
		case n == 8:
			r = iniFail(obs.ReasonRefused)
		default:
			r = g.records(k.Name.String(), k.Type, []string{map[dnswire.Type]string{dnswire.TypeA: "192.0.2.77", dnswire.TypeAAAA: "2001:db8::77"}[k.Type]})
		}
		o.Answers = append(o.Answers, iniAt(fmt.Sprintf("ns%d.example.com.", j+1), fmt.Sprintf("192.0.2.%d:53", 201+j), r))
	}
	return o
}

// nswNSModel says whether the NS set of the domain gets a line: when every
// answer agrees and none failed, or else when a server of the parent zone
// gave a set, every answer that did not fail is a set of NS records, and
// there are at most 4 sets.
func nswNSModel(observations []obs.Observation) bool {
	var texts []string
	failed, none, fromParent := false, false, false
	for _, o := range observations {
		for _, a := range o.Answers {
			set, _, bad := nswRead(a.Result)
			switch {
			case bad:
				failed = true
				continue
			case slices.ContainsFunc(set, func(x dnswire.Record) bool { return x.Type() != dnswire.TypeNS }):
				// No NS line can state a record of another type.
				return false
			case len(set) == 0:
				none = true
			case o.Key.Kind == obs.KindDelegation:
				fromParent = true
			}
			texts = append(texts, expect.SetText(dnswire.TypeNS, set))
		}
	}
	slices.Sort(texts)
	texts = slices.Compact(texts)
	if !failed && len(texts) == 1 {
		return true
	}
	return !none && fromParent && len(texts) <= 4
}

// For random answers: the NS line is written exactly when the rule says; the
// checks of the addresses are bounded; every file parses back to its own
// text, does not depend on the order of the answers, and finds nothing in
// the answers it was made from; and the sets that the warning names are
// those of the line.
func TestInitSnapshotProperty(t *testing.T) {
	const seed = 20261118
	rng := rand.New(rand.NewPCG(seed, 1))
	d := iniName(nswD)
	g := &nswGen{rng: rng,
		pool: []string{"ns1.example.com.", "ns2.example.com.", "ns3.example.com.", "ns1.example.net.", "ns2.example.net."},
		addr: map[string][2][]string{
			"ns1.example.com.": {{"192.0.2.1"}, {"2001:db8::1"}},
			"ns2.example.com.": {{"192.0.2.2"}, nil},
			"ns3.example.com.": {{"192.0.2.3", "192.0.2.33"}, nil},
		},
	}
	var lines, several, hostLines int
	failures := 0
	for i := range 2000 {
		fail := func(format string, args ...any) {
			t.Helper()
			t.Errorf("seed %d case %d: %s", seed, i, fmt.Sprintf(format, args...))
			if failures++; failures >= 10 {
				t.Fatalf("seed %d: stopped after %d failing cases", seed, failures)
			}
		}
		sets := [][]string{g.set()}
		if rng.IntN(4) == 0 {
			sets = append(sets, g.set())
		}
		first := []obs.Observation{g.delegation(sets), g.apex(sets)}
		keys, ok := NameServerKeys(d, first)
		if len(keys) > 16 || !ok && len(keys) > 0 {
			fail("NameServerKeys gives %d keys, ok %v", len(keys), ok)
		}
		seen := map[string]bool{}
		all := slices.Clone(first)
		for _, k := range keys {
			if seen[k.String()] || !k.Name.IsSubdomainOf(d) || k.Kind != obs.KindRecords ||
				k.Type != dnswire.TypeA && k.Type != dnswire.TypeAAAA {
				fail("NameServerKeys gives %s twice or for no host inside the domain", k)
			}
			seen[k.String()] = true
			all = append(all, g.host(k))
		}
		f, _ := expect.Snapshot(d, all)
		text := f.String()
		e, hasNS := f.Find(d, dnswire.TypeNS)
		if want := nswNSModel(first); hasNS != want {
			fail("NS line %v; want %v\n%s\nanswers %v", hasNS, want, text, first)
		}
		if p, err := expect.Parse([]byte(text)); err != nil || p.String() != text {
			fail("the file does not parse back to itself: %v\n%s", err, text)
		}
		for _, o := range all {
			if _, has := f.Find(o.Key.Name, o.Key.Type); !has {
				continue
			}
			if found := decide.Findings(f, o); len(found) != 0 {
				fail("check %s finds %s %s\n%s", o.Key, found[0].Rule, found[0].Value, text)
			}
		}
		shuffled := slices.Clone(all)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		for j := range shuffled {
			shuffled[j].Answers = slices.Clone(shuffled[j].Answers)
			answers := shuffled[j].Answers
			rng.Shuffle(len(answers), func(a, b int) { answers[a], answers[b] = answers[b], answers[a] })
		}
		if again, _ := expect.Snapshot(d, shuffled); again.String() != text {
			fail("the answers in another order give\n%s\nwant\n%s", again.String(), text)
		}
		// The warning names every failed answer that the NS line rests
		// without, and nothing when there is no line.
		var noAnswer []string
		for _, o := range first {
			for _, a := range o.Answers {
				why := nswReason(a.Result)
				switch {
				case !hasNS || why == "":
				case !a.Server.Addr.IsValid():
					// A failed walk names no server; it is said once.
					if !slices.Contains(noAnswer, expect.NoPath) {
						noAnswer = append(noAnswer, expect.NoPath)
					}
				default:
					noAnswer = append(noAnswer, a.Server.Addr.String()+" "+a.Server.Name.Lower().String()+" ("+why+")")
				}
			}
		}
		if got := expect.NSNoAnswer(d, all); !slices.Equal(got, noAnswer) {
			fail("NSNoAnswer %q; want %q\n%s", got, noAnswer, text)
		}
		sources := expect.NSSources(d, all)
		switch {
		case hasNS && len(e.Sets) > 1:
			var texts []string
			for _, s := range sources {
				texts = append(texts, s.Text)
			}
			if strings.Join(texts, " || ") != e.FormText() {
				fail("the warning names %q; the line holds %q", texts, e.FormText())
			}
			several++
		case sources != nil:
			fail("NSSources %+v for a line of one set or none\n%s", sources, text)
		}
		if hasNS {
			lines++
		}
		for _, x := range f.Expectations {
			if x.Name.IsSubdomainOf(d) && !x.Name.Equal(d) && (x.Type == dnswire.TypeA || x.Type == dnswire.TypeAAAA) {
				hostLines++
			}
		}
	}
	if !t.Failed() && (lines < 500 || several < 200 || hostLines < 500 || lines > 1900) {
		t.Errorf("test fault: %d NS lines, %d of several sets, %d address lines in 2000 cases; each must come up often", lines, several, hostLines)
	}
}
