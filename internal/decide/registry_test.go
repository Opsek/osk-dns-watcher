package decide

import (
	"cmp"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

var regDS2 = "54321 13 2 " + strings.Repeat("AB", 32)

// regServers are the servers of the parent zone, in the order that the tests
// name them.
var regServers = []struct{ host, addr string }{
	{"a.ns.test.", "10.53.0.3:53"},
	{"b.ns.test.", "10.53.0.4:53"},
	{"c.ns.test.", "10.53.0.5:53"},
	{"d.ns.test.", "10.53.0.6:53"},
}

// regAns describes the answer of one server of the parent zone. kind "" or
// "ns" is the NS set of corp.test. with glue (data: "owner=address"); "ds" is
// a DS set (data: DS text); the others are what their word says.
type regAns struct {
	srv  int
	kind string
	data []string
}

func regGlue(srv int, glue ...string) regAns { return regAns{srv: srv, data: glue} }
func regDown(srv int) regAns                 { return regAns{srv: srv, kind: "fail"} }

func regBuild(t testing.TB, specs []regAns) []obs.Answer {
	t.Helper()
	var out []obs.Answer
	for _, s := range specs {
		var r obs.Result
		switch s.kind {
		case "", "ns":
			var glue []dnswire.Record
			for _, g := range s.data {
				owner, addr, _ := strings.Cut(g, "=")
				typ := dnswire.TypeA
				if strings.Contains(addr, ":") {
					typ = dnswire.TypeAAAA
				}
				glue = append(glue, decRR(t, owner, typ, addr))
			}
			set := []dnswire.Record{decRR(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test."), decRR(t, "corp.test.", dnswire.TypeNS, "ns2.corp.test.")}
			r = decAs(t, obs.RecordsResult(obs.Records{Set: set, Glue: glue}), "records")
		case "ds":
			r = decSet(t, "corp.test.", dnswire.TypeDS, s.data...)
		case "nodata":
			r = decNoData(t, "test.")
		case "noname":
			r = decNoName(t, "test.")
		case "compact":
			r = decAs(t, obs.NoNameResult(obs.NoName{SOA: decSOA(t, "test."), Compact: true}), "noname")
		case "fail":
			r = decFailure(obs.ReasonTimeout)
		case "servfail":
			r = decFailure(obs.ReasonServFail)
		case "zero":
			r = obs.Result{}
		default:
			t.Fatalf("regBuild: unknown kind %q", s.kind)
		}
		out = append(out, decAnswer(t, regServers[s.srv].host, regServers[s.srv].addr, r))
	}
	return out
}

// regObserve is a check of the parent zone: delegation or ds of domain.
func regObserve(t testing.TB, kind obs.Kind, domain string, answers []obs.Answer) obs.Observation {
	t.Helper()
	key := obs.DelegationKey(decName(t, domain))
	if kind == obs.KindDS {
		key = obs.DSKey(decName(t, domain))
	}
	return decObservation(key, decName(t, "test."), nil, answers...)
}

const regNSLine = "corp.test. NS ns1.corp.test. | ns2.corp.test."

// regFile is the file of corp.test. with the given lines after its NS line
// and a DS line. The DS line matches no answer of a delegation check, so a
// rule that looked at the wrong check would show.
func regFile(t testing.TB, lines ...string) *expect.File {
	return regFileNS(t, regNSLine, lines...)
}

func regFileNS(t testing.TB, nsLine string, lines ...string) *expect.File {
	t.Helper()
	return decFile(t, append([]string{"domain corp.test.", nsLine, "corp.test. DS " + regDS2}, lines...)...)
}

type regSeen struct {
	answer int
	text   string
}

func regSeens(answers []obs.Answer, seen []regSeen) []Seen {
	var out []Seen
	for _, s := range seen {
		out = append(out, Seen{Answer: answers[s.answer], Text: s.text})
	}
	return out
}

// regValue is the Value of a finding: one line for each Seen.
func regValue(seen []Seen) string {
	lines := make([]string, len(seen))
	for i, s := range seen {
		addr, host := "-", "-"
		if s.Answer.Server.Addr.IsValid() {
			addr = s.Answer.Server.Addr.String()
		}
		if s.Answer.Server.Name.LabelCount() > 0 {
			host = s.Answer.Server.Name.Lower().String()
		}
		lines[i] = addr + " " + host + " " + s.Text
	}
	return strings.Join(lines, "\n")
}

// regCheck compares whole findings: the check is the key as it was given,
// and the Value is exactly one line for each Seen.
func regCheck(t *testing.T, got []Finding, key obs.Key, want ...decWant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d:%s", len(got), len(want), decShow(got))
	}
	for i, w := range want {
		g := got[i]
		if g.Rule != w.rule || g.Severity != w.severity || g.Expected != w.expected {
			t.Errorf("finding %d is %v %v expected %q, want %v %v expected %q", i, g.Rule, g.Severity, g.Expected, w.rule, w.severity, w.expected)
		}
		if !reflect.DeepEqual(g.Check, key) {
			t.Errorf("finding %d has check %+v, want %+v", i, g.Check, key)
		}
		if len(g.Seen) != len(w.seen) {
			t.Errorf("finding %d %v has %d seen, want %d:%s", i, g.Rule, len(g.Seen), len(w.seen), decShow(got))
			continue
		}
		for j := range w.seen {
			if !reflect.DeepEqual(g.Seen[j], w.seen[j]) {
				t.Errorf("finding %d %v, seen %d:\n got  %v %q\n want %v %q", i, g.Rule, j,
					g.Seen[j].Answer.Server, g.Seen[j].Text, w.seen[j].Answer.Server, w.seen[j].Text)
			}
		}
		if want := regValue(w.seen); g.Value != want {
			t.Errorf("finding %d %v has value %q, want %q", i, g.Rule, g.Value, want)
		}
	}
}

func TestRegistryRuleWordsAndNumbers(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		num  Rule
		word string
	}{
		{RuleGlue, 8, "glue"},
		{RuleDS, 9, "ds"},
		{RuleGone, 10, "gone"},
	} {
		if c.rule != c.num {
			t.Errorf("%s is rule number %d, want %d: the store keeps the number", c.word, c.rule, c.num)
		}
		if got := c.num.String(); got != c.word {
			t.Errorf("Rule(%d).String() is %q, want %q", c.num, got, c.word)
		}
	}
	if got := Rule(25).String(); got != "rule25" {
		t.Errorf("Rule(25).String() is %q, want rule25", got)
	}
}

// Each row is one answer set of the parent against the host lines of the
// file. The address lines of the hosts judge the glue of the delegation.
func TestGlueFinding(t *testing.T) {
	const (
		l1 = "ns1.corp.test. A 10.53.0.11"
		l2 = "ns2.corp.test. A 10.53.0.12"
	)
	for _, c := range []struct {
		name     string
		lines    []string
		answers  []regAns
		expected string // "": no glue finding
		seen     []regSeen
	}{
		{"every address as written", []string{l1, l2}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.12")}, "", nil},
		{"one address of several differs", []string{l1, l2}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99")},
			l2, []regSeen{{0, "ns2.corp.test. A 10.53.0.99"}}},
		{"every host differs, glue given in reverse order", []string{l1, l2}, []regAns{regGlue(0, "ns2.corp.test.=10.53.0.99", "ns1.corp.test.=10.53.0.98")},
			l1 + "; " + l2, []regSeen{{0, "ns1.corp.test. A 10.53.0.98"}, {0, "ns2.corp.test. A 10.53.0.99"}}},
		{"an address is added", []string{l1}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns1.corp.test.=10.53.0.99")},
			l1, []regSeen{{0, "ns1.corp.test. A 10.53.0.11 | 10.53.0.99"}}},
		{"an address is missing", []string{"ns1.corp.test. A 10.53.0.11 | 10.53.0.12"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11")},
			"ns1.corp.test. A 10.53.0.11 | 10.53.0.12", []regSeen{{0, "ns1.corp.test. A 10.53.0.11"}}},
		{"the same set in another order", []string{"ns1.corp.test. A 10.53.0.11 | 10.53.0.12"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.12", "ns1.corp.test.=10.53.0.11")}, "", nil},
		{"both families as written", []string{l1, "ns1.corp.test. AAAA fd53::11"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns1.corp.test.=fd53::11")}, "", nil},
		{"the IPv6 address differs, the IPv4 address does not", []string{l1, "ns1.corp.test. AAAA fd53::11"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns1.corp.test.=fd53::99")},
			"ns1.corp.test. AAAA fd53::11", []regSeen{{0, "ns1.corp.test. AAAA fd53::99"}}},
		{"both families differ, IPv6 given first", []string{l1, "ns1.corp.test. AAAA fd53::11"}, []regAns{regGlue(0, "ns1.corp.test.=fd53::98", "ns1.corp.test.=10.53.0.98")},
			l1 + "; ns1.corp.test. AAAA fd53::11", []regSeen{{0, "ns1.corp.test. A 10.53.0.98"}, {0, "ns1.corp.test. AAAA fd53::98"}}},
		{"AAAA glue is added where the file has only an A line", []string{l1}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns1.corp.test.=fd53::66")},
			"ns1.corp.test. AAAA (no line)", []regSeen{{0, "ns1.corp.test. AAAA fd53::66"}}},
		{"A glue where the file has only an AAAA line", []string{"ns1.corp.test. AAAA fd53::11"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11")},
			"ns1.corp.test. A (no line)", []regSeen{{0, "ns1.corp.test. A 10.53.0.11"}}},
		{"a host with no address line is not compared", []string{l1}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99")}, "", nil},
		{"a file with no address line compares no glue", nil, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99")}, "", nil},
		{"absent glue is not compared", []string{l1, l2}, []regAns{regGlue(0)}, "", nil},
		{"glue of only one watched host", []string{l1, l2}, []regAns{regGlue(0, "ns2.corp.test.=10.53.0.12")}, "", nil},
		{"none and no glue", []string{"ns1.corp.test. A none"}, []regAns{regGlue(0)}, "", nil},
		{"none and some glue", []string{"ns1.corp.test. A none"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11")},
			"ns1.corp.test. A none", []regSeen{{0, "ns1.corp.test. A 10.53.0.11"}}},
		{"an address inside the range", []string{"ns1.corp.test. A in 10.53.0.0/24"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11")}, "", nil},
		{"an address outside the range", []string{"ns1.corp.test. A in 10.53.0.0/24"}, []regAns{regGlue(0, "ns1.corp.test.=10.54.0.1")},
			"ns1.corp.test. A in 10.53.0.0/24", []regSeen{{0, "ns1.corp.test. A 10.54.0.1"}}},
		{"the owner of the glue in capitals", []string{l1}, []regAns{regGlue(0, "NS1.CORP.test.=10.53.0.11")}, "", nil},
		{"the owner of the glue in capitals, wrong address", []string{l1}, []regAns{regGlue(0, "Ns1.Corp.Test.=10.53.0.99")},
			l1, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}}},
		{"the owner of the line in capitals", []string{"NS1.Corp.Test. A 10.53.0.11"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99")},
			l1, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}}},
		{"two spellings of one host are one set", []string{"ns1.corp.test. A 10.53.0.11 | 10.53.0.12"}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11", "NS1.corp.test.=10.53.0.12")}, "", nil},
		{"a watched host outside the domain differs", []string{"ns1.dnshost.test. A 10.53.0.83"}, []regAns{regGlue(0, "ns1.dnshost.test.=10.53.0.99")},
			"ns1.dnshost.test. A 10.53.0.83", []regSeen{{0, "ns1.dnshost.test. A 10.53.0.99"}}},
		{"a watched host outside the domain as written", []string{"ns1.dnshost.test. A 10.53.0.83"}, []regAns{regGlue(0, "ns1.dnshost.test.=10.53.0.83")}, "", nil},
		{"a failure is no glue and no difference", []string{l1, l2},
			[]regAns{regDown(0), regGlue(1, "ns2.corp.test.=10.53.0.99"), {srv: 2, kind: "servfail"}},
			l2, []regSeen{{1, "ns2.corp.test. A 10.53.0.99"}}},
		{"only failures", []string{l1, l2}, []regAns{regDown(0), regDown(1), {srv: 2, kind: "zero"}}, "", nil},
		{"two servers that differ, each in the order of the answers", []string{l1, l2},
			[]regAns{regGlue(0, "ns1.corp.test.=10.53.0.99"), regGlue(1, "ns2.corp.test.=10.53.0.97", "ns1.corp.test.=10.53.0.98"), regGlue(2, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.12")},
			l1 + "; " + l2, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}, {1, "ns1.corp.test. A 10.53.0.98"}, {1, "ns2.corp.test. A 10.53.0.97"}}},
		// The parts of Expected are sorted by host; they do not follow the answers.
		{"each server differs on another host", []string{l1, l2}, []regAns{regGlue(0, "ns2.corp.test.=10.53.0.99"), regGlue(1, "ns1.corp.test.=10.53.0.98")},
			l1 + "; " + l2, []regSeen{{0, "ns2.corp.test. A 10.53.0.99"}, {1, "ns1.corp.test. A 10.53.0.98"}}},
		{"each server differs on another host, in the other order", []string{l1, l2}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.98"), regGlue(1, "ns2.corp.test.=10.53.0.99")},
			l1 + "; " + l2, []regSeen{{0, "ns1.corp.test. A 10.53.0.98"}, {1, "ns2.corp.test. A 10.53.0.99"}}},
		{"a part that two servers show is one part", []string{l1, l2},
			[]regAns{regGlue(0, "ns2.corp.test.=10.53.0.99"), regGlue(1, "ns2.corp.test.=10.53.0.99", "ns1.corp.test.=10.53.0.98"), regGlue(2, "ns2.corp.test.=10.53.0.97")},
			l1 + "; " + l2, []regSeen{{0, "ns2.corp.test. A 10.53.0.99"}, {1, "ns1.corp.test. A 10.53.0.98"}, {1, "ns2.corp.test. A 10.53.0.99"}, {2, "ns2.corp.test. A 10.53.0.97"}}},
		{"the parts are sorted by host, then by type", []string{"NS2.corp.test. A 10.53.0.12", "ns1.Corp.test. AAAA fd53::11", "Ns1.corp.test. A 10.53.0.11"},
			[]regAns{regGlue(0, "NS2.corp.test.=10.53.0.92", "ns1.corp.test.=fd53::91", "NS1.corp.test.=10.53.0.91")},
			l1 + "; ns1.corp.test. AAAA fd53::11; " + l2,
			[]regSeen{{0, "ns1.corp.test. A 10.53.0.91"}, {0, "ns1.corp.test. AAAA fd53::91"}, {0, "ns2.corp.test. A 10.53.0.92"}}},
		{"the hosts are sorted as names, not as text", []string{"B.a.corp.test. A 10.53.0.21", "a.b.corp.test. A 10.53.0.22", l1},
			[]regAns{regGlue(0, "ns1.corp.test.=10.53.0.91", "a.B.corp.test.=10.53.0.94", "B.A.corp.test.=10.53.0.93")},
			"b.a.corp.test. A 10.53.0.21; a.b.corp.test. A 10.53.0.22; " + l1,
			[]regSeen{{0, "b.a.corp.test. A 10.53.0.93"}, {0, "a.b.corp.test. A 10.53.0.94"}, {0, "ns1.corp.test. A 10.53.0.91"}}},
		{"a part with no line sorts among the others", []string{l1, "ns2.corp.test. AAAA fd53::12", l2},
			[]regAns{regGlue(0, "ns2.corp.test.=fd53::99", "ns2.corp.test.=10.53.0.99", "ns1.corp.test.=fd53::98")},
			"ns1.corp.test. AAAA (no line); " + l2 + "; ns2.corp.test. AAAA fd53::12",
			[]regSeen{{0, "ns1.corp.test. AAAA fd53::98"}, {0, "ns2.corp.test. A 10.53.0.99"}, {0, "ns2.corp.test. AAAA fd53::99"}}},
		{"a server that is right is not seen", []string{l1}, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.11"), regGlue(1, "ns1.corp.test.=10.53.0.99")},
			l1, []regSeen{{1, "ns1.corp.test. A 10.53.0.99"}}},
		{"seen follows the answers, not the server names", []string{l1}, []regAns{regGlue(2, "ns1.corp.test.=10.53.0.99"), regGlue(0, "ns1.corp.test.=10.53.0.98")},
			l1, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}, {1, "ns1.corp.test. A 10.53.0.98"}}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := regFile(t, c.lines...)
			answers := regBuild(t, c.answers)
			o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
			if c.expected == "" {
				regCheck(t, Findings(f, o), o.Key)
				return
			}
			regCheck(t, Findings(f, o), o.Key, decWant{RuleGlue, SeverityCritical, c.expected, regSeens(answers, c.seen)})
		})
	}
}

// Alternatives are one line of the file: the finding shows that line whole.
func TestGlueAlternatives(t *testing.T) {
	f := regFile(t, "ns1.corp.test. A 10.53.0.11 || 10.53.0.99")
	line, ok := f.Find(decName(t, "ns1.corp.test."), dnswire.TypeA)
	if !ok {
		t.Fatal("no line")
	}
	right := regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99")})
	regCheck(t, Findings(f, regObserve(t, obs.KindDelegation, "corp.test.", right)), obs.DelegationKey(decName(t, "corp.test.")))
	wrong := regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.98")})
	o := regObserve(t, obs.KindDelegation, "corp.test.", wrong)
	regCheck(t, Findings(f, o), o.Key, decWant{RuleGlue, SeverityCritical, line.String(), regSeens(wrong, []regSeen{{0, "ns1.corp.test. A 10.53.0.98"}})})
	if !strings.HasPrefix(line.String(), "ns1.corp.test. A ") {
		t.Errorf("the line prints as %q", line.String())
	}
}

func TestGlueNeedsAFileOfTheDomain(t *testing.T) {
	answers := regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99")})
	o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
	for _, c := range []struct {
		name string
		f    *expect.File
	}{
		{"no file", nil},
		{"file of another domain", decFile(t, "domain shop.test.", "shop.test. NS ns1.corp.test. | ns2.corp.test.", "ns1.corp.test. A 10.53.0.11")},
	} {
		t.Run(c.name, func(t *testing.T) {
			regCheck(t, Findings(c.f, o), o.Key, decWant{RuleNotCovered, SeverityMedium, "", regSeens(answers, []regSeen{{0, "ns1.corp.test. | ns2.corp.test."}})})
		})
	}
	t.Run("the domain in capitals", func(t *testing.T) {
		upper := regObserve(t, obs.KindDelegation, "CORP.Test.", answers)
		f := regFile(t, "ns1.corp.test. A 10.53.0.11")
		regCheck(t, Findings(f, upper), upper.Key, decWant{RuleGlue, SeverityCritical, "ns1.corp.test. A 10.53.0.11", regSeens(answers, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}})})
	})
}

// Only the delegation check holds glue that the file judges.
func TestGlueIsJudgedOnTheDelegationCheckOnly(t *testing.T) {
	corp := decName(t, "corp.test.")
	f := regFile(t, "ns1.corp.test. A 10.53.0.11", "www.corp.test. A 10.53.0.81")
	glue := []dnswire.Record{decRR(t, "ns1.corp.test.", dnswire.TypeA, "10.53.0.99")}
	records := func(typ dnswire.Type, owner, data string) obs.Answer {
		set := []dnswire.Record{decRR(t, owner, typ, data)}
		return decAnswer(t, "ns1.corp.test.", decNS1, decAs(t, obs.RecordsResult(obs.Records{Set: set, Glue: glue}), "records"))
	}
	for _, o := range []obs.Observation{
		decObservation(obs.DSKey(corp), decName(t, "test."), nil, records(dnswire.TypeDS, "corp.test.", regDS2)),
		decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), corp, nil, records(dnswire.TypeA, "www.corp.test.", "10.53.0.81")),
		decObservation(obs.SerialKey(corp), corp, nil, records(dnswire.TypeSOA, "corp.test.", "ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")),
	} {
		t.Run(o.Key.Kind.String(), func(t *testing.T) {
			regCheck(t, Findings(f, o), o.Key)
		})
	}
}

// Without an NS line the delegation is not covered, and glue and gone come
// beside not-covered; with an NS line that differs they come after
// nameservers.
func TestRegistryFindingsComeInRuleOrder(t *testing.T) {
	answers := regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99"), {srv: 1, kind: "noname"}, regDown(2)})
	o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
	glue := decWant{RuleGlue, SeverityCritical, "ns1.corp.test. A 10.53.0.11", regSeens(answers, []regSeen{{0, "ns1.corp.test. A 10.53.0.99"}})}
	gone := decWant{RuleGone, SeverityCritical, "", regSeens(answers, []regSeen{{1, "no such name"}})}

	t.Run("no NS line", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", "ns1.corp.test. A 10.53.0.11")
		regCheck(t, Findings(f, o), o.Key,
			decWant{RuleNotCovered, SeverityMedium, "", regSeens(answers, []regSeen{{0, "ns1.corp.test. | ns2.corp.test."}, {1, "none"}})}, glue, gone)
	})
	t.Run("an NS line that differs", func(t *testing.T) {
		f := decFile(t, "domain corp.test.", "corp.test. NS ns1.dnshost.test.", "ns1.corp.test. A 10.53.0.11")
		regCheck(t, Findings(f, o), o.Key,
			decWant{RuleNameServers, SeverityCritical, "ns1.dnshost.test.", regSeens(answers, []regSeen{{0, "ns1.corp.test. | ns2.corp.test."}, {1, "none"}})}, glue, gone)
	})
	t.Run("an NS line that matches the records", func(t *testing.T) {
		f := regFile(t, "ns1.corp.test. A 10.53.0.11")
		regCheck(t, Findings(f, o), o.Key,
			decWant{RuleNameServers, SeverityCritical, decFormText(t, f, "corp.test.", dnswire.TypeNS), regSeens(answers, []regSeen{{1, "none"}})}, glue, gone)
	})
}

func TestGoneFinding(t *testing.T) {
	file := regFile(t)
	nsText := decFormText(t, file, "corp.test.", dnswire.TypeNS)
	for _, c := range []struct {
		name    string
		f       *expect.File
		answers []regAns
		// The findings besides gone, as the seen lines of the nameservers
		// finding; empty when there is none.
		ns   []regSeen
		gone []int // answers that gone shows, by index
	}{
		{"no such name", file, []regAns{{srv: 0, kind: "noname"}}, []regSeen{{0, "none"}}, []int{0}},
		{"the compact form", file, []regAns{{srv: 0, kind: "compact"}}, []regSeen{{0, "none"}}, []int{0}},
		{"every server that says it, in order", file,
			[]regAns{regGlue(0), {srv: 1, kind: "noname"}, {srv: 2, kind: "nodata"}, {srv: 3, kind: "compact"}},
			[]regSeen{{1, "none"}, {2, "none"}, {3, "none"}}, []int{1, 3}},
		{"no data is not gone", file, []regAns{{srv: 0, kind: "nodata"}}, []regSeen{{0, "none"}}, nil},
		{"records are not gone", file, []regAns{regGlue(0)}, nil, nil},
		{"only failures", file, []regAns{regDown(0), {srv: 1, kind: "servfail"}, {srv: 2, kind: "zero"}}, nil, nil},
		{"a failure beside no such name", file, []regAns{regDown(0), {srv: 1, kind: "noname"}}, []regSeen{{1, "none"}}, []int{1}},
		{"an NS line of none", decFile(t, "domain corp.test.", "corp.test. NS none"), []regAns{{srv: 0, kind: "noname"}}, nil, []int{0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			answers := regBuild(t, c.answers)
			o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
			var want []decWant
			if len(c.ns) > 0 {
				want = append(want, decWant{RuleNameServers, SeverityCritical, nsText, regSeens(answers, c.ns)})
			}
			if len(c.gone) > 0 {
				var seen []regSeen
				for _, i := range c.gone {
					seen = append(seen, regSeen{i, "no such name"})
				}
				want = append(want, decWant{RuleGone, SeverityCritical, "", regSeens(answers, seen)})
			}
			regCheck(t, Findings(c.f, o), o.Key, want...)
		})
	}
}

// No line is needed for gone: the domain line of the file is the expectation.
func TestGoneNeedsAFileOfTheDomainOnly(t *testing.T) {
	answers := regBuild(t, []regAns{{srv: 0, kind: "noname"}})
	o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
	gone := decWant{RuleGone, SeverityCritical, "", regSeens(answers, []regSeen{{0, "no such name"}})}
	notCovered := decWant{RuleNotCovered, SeverityMedium, "", regSeens(answers, []regSeen{{0, "none"}})}

	t.Run("a file with no line", func(t *testing.T) {
		regCheck(t, Findings(decFile(t, "domain corp.test."), o), o.Key, notCovered, gone)
	})
	t.Run("no file", func(t *testing.T) {
		regCheck(t, Findings(nil, o), o.Key, notCovered)
	})
	t.Run("a file of another domain", func(t *testing.T) {
		regCheck(t, Findings(decFile(t, "domain shop.test.", regNSLine), o), o.Key, notCovered)
	})
	t.Run("the domain in capitals", func(t *testing.T) {
		upper := regObserve(t, obs.KindDelegation, "CORP.TEST.", answers)
		regCheck(t, Findings(regFileNS(t, "corp.test. NS none"), upper), upper.Key, gone)
	})
}

// The ds and the records checks see the same answer but do not raise gone.
func TestGoneIsRaisedByTheDelegationCheckOnly(t *testing.T) {
	corp := decName(t, "corp.test.")
	f := regFile(t, "www.corp.test. A 10.53.0.81")
	noName := func() obs.Answer { return regBuild(t, []regAns{{srv: 0, kind: "noname"}})[0] }

	ds := decObservation(obs.DSKey(corp), decName(t, "test."), nil, noName())
	regCheck(t, Findings(f, ds), ds.Key, decWant{RuleDS, SeverityHigh, decFormText(t, f, "corp.test.", dnswire.TypeDS), []Seen{{ds.Answers[0], "none"}}})

	www := decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), corp, nil, noName())
	regCheck(t, Findings(f, www), www.Key, decWant{RuleRecordSet, SeverityHigh, "10.53.0.81", []Seen{{www.Answers[0], "none"}}})

	serial := decObservation(obs.SerialKey(corp), corp, nil, noName())
	regCheck(t, Findings(f, serial), serial.Key)
}

func TestDSFinding(t *testing.T) {
	const (
		none = "corp.test. DS none"
	)
	one := "corp.test. DS " + decDS
	both := "corp.test. DS " + decDS + " | " + regDS2
	alt := "corp.test. DS " + decDS + " || " + regDS2
	ds1 := regAns{srv: 0, kind: "ds", data: []string{decDS}}
	ds2 := regAns{srv: 1, kind: "ds", data: []string{regDS2}}
	nodata := regAns{srv: 2, kind: "nodata"}
	noname := regAns{srv: 3, kind: "noname"}
	at := func(r regAns, srv int) regAns { r.srv = srv; return r }

	for _, c := range []struct {
		name    string
		line    string
		answers []regAns
		seen    []int // answers that the finding shows, by index; empty: no finding
	}{
		{"none, no data", none, []regAns{nodata}, nil},
		{"none, no such name", none, []regAns{noname}, nil},
		{"none, a DS appears", none, []regAns{ds1}, []int{0}},
		{"none, two servers differ", none, []regAns{ds1, at(nodata, 1), at(ds2, 2)}, []int{0, 2}},
		{"the DS as written", one, []regAns{ds1}, nil},
		{"another DS", one, []regAns{ds2}, []int{0}},
		{"the DS is gone: no data", one, []regAns{nodata}, []int{0}},
		{"the DS is gone: no such name", one, []regAns{noname}, []int{0}},
		{"one DS more", one, []regAns{{srv: 0, kind: "ds", data: []string{decDS, regDS2}}}, []int{0}},
		{"two DS as written, in another order", both, []regAns{{srv: 0, kind: "ds", data: []string{regDS2, decDS}}}, nil},
		{"two DS, one missing", both, []regAns{ds1}, []int{0}},
		{"servers that differ, in order", one, []regAns{ds1, at(ds2, 1), at(nodata, 2), at(noname, 3)}, []int{1, 2, 3}},
		{"a failure is neither none nor a difference", one, []regAns{regDown(0)}, nil},
		{"a failure beside another DS", one, []regAns{regDown(0), at(ds2, 1)}, []int{1}},
		{"a failure beside no data", one, []regAns{{srv: 0, kind: "servfail"}, at(nodata, 1)}, []int{1}},
		{"a failure beside the DS as written", one, []regAns{regDown(0), at(ds1, 1)}, nil},
		{"the zero result", one, []regAns{{srv: 0, kind: "zero"}}, nil},
		{"a failure with none", none, []regAns{regDown(0), {srv: 1, kind: "zero"}}, nil},
		{"one of two alternatives", alt, []regAns{ds2}, nil},
		{"the other alternative", alt, []regAns{ds1}, nil},
		{"both alternatives together", alt, []regAns{{srv: 0, kind: "ds", data: []string{decDS, regDS2}}}, []int{0}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := decFile(t, "domain corp.test.", regNSLine, c.line)
			answers := regBuild(t, c.answers)
			o := regObserve(t, obs.KindDS, "corp.test.", answers)
			if len(c.seen) == 0 {
				regCheck(t, Findings(f, o), o.Key)
				return
			}
			var seen []Seen
			for _, i := range c.seen {
				text := "none"
				obs.Match(answers[i].Result, func(r obs.Records) bool {
					text = expect.SetText(dnswire.TypeDS, r.Set)
					return true
				}, func(obs.NoData) bool { return true }, func(obs.NoName) bool { return true }, func(obs.Failure) bool { return true })
				seen = append(seen, Seen{Answer: answers[i], Text: text})
			}
			expected := decFormText(t, f, "corp.test.", dnswire.TypeDS)
			if c.line == none && expected != "none" {
				t.Fatalf("FormText of a none line is %q", expected)
			}
			regCheck(t, Findings(f, o), o.Key, decWant{RuleDS, SeverityHigh, expected, seen})
		})
	}
}

// A DS that is gone and a DS that is new show as text; the exact text of
// each is the one that the line would print.
func TestDSSeenText(t *testing.T) {
	f := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS none")
	answers := regBuild(t, []regAns{{srv: 0, kind: "ds", data: []string{regDS2, decDS}}, {srv: 1, kind: "nodata"}})
	o := regObserve(t, obs.KindDS, "corp.test.", answers)
	got := Findings(f, o)
	if len(got) != 1 || len(got[0].Seen) != 1 {
		t.Fatalf("want one finding with one seen:%s", decShow(got))
	}
	var set []dnswire.Record
	obs.Match(answers[0].Result, func(r obs.Records) bool { set = r.Set; return true },
		func(obs.NoData) bool { return false }, func(obs.NoName) bool { return false }, func(obs.Failure) bool { return false })
	text := expect.SetText(dnswire.TypeDS, set)
	if got[0].Seen[0].Text != text || !strings.Contains(text, " | ") {
		t.Errorf("seen text %q, want the two DS in one line %q", got[0].Seen[0].Text, text)
	}
	if want := "10.53.0.3:53 a.ns.test. " + text; got[0].Value != want {
		t.Errorf("value %q, want %q", got[0].Value, want)
	}
}

func TestDSWithoutALineIsOnlyNotCovered(t *testing.T) {
	answers := regBuild(t, []regAns{{srv: 0, kind: "ds", data: []string{decDS}}, regDown(1), {srv: 2, kind: "nodata"}})
	o := regObserve(t, obs.KindDS, "corp.test.", answers)
	seen := regSeens(answers, []regSeen{{0, expect.SetText(dnswire.TypeDS, []dnswire.Record{decRR(t, "corp.test.", dnswire.TypeDS, decDS)})}, {2, "none"}})
	want := decWant{RuleNotCovered, SeverityMedium, "", seen}
	for _, c := range []struct {
		name string
		f    *expect.File
	}{
		{"a file with no DS line", decFile(t, "domain corp.test.", regNSLine)},
		{"no file", nil},
		{"file of another domain", decFile(t, "domain shop.test.", "shop.test. DS none")},
	} {
		t.Run(c.name, func(t *testing.T) {
			regCheck(t, Findings(c.f, o), o.Key, want)
		})
	}
}

func TestDSLineOfTheCheckedDomainInCapitals(t *testing.T) {
	f := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS none")
	answers := regBuild(t, []regAns{{srv: 0, kind: "ds", data: []string{decDS}}})
	o := regObserve(t, obs.KindDS, "CORP.Test.", answers)
	regCheck(t, Findings(f, o), o.Key, decWant{RuleDS, SeverityHigh, "none", regSeens(answers, []regSeen{{0, expect.SetText(dnswire.TypeDS, []dnswire.Record{decRR(t, "corp.test.", dnswire.TypeDS, decDS)})}})})
}

// A DS line is judged on the ds check only: the delegation check of a file
// with a DS line never shows a ds finding, whatever its answers.
func TestDSIsJudgedOnTheDSCheckOnly(t *testing.T) {
	f := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS none")
	answers := regBuild(t, []regAns{regGlue(0)})
	o := regObserve(t, obs.KindDelegation, "corp.test.", answers)
	regCheck(t, Findings(f, o), o.Key)
}

func TestRegistryValueLines(t *testing.T) {
	f := regFile(t, "ns1.corp.test. A 10.53.0.11")
	answers := regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99"), regGlue(1, "ns1.corp.test.=10.53.0.98"), {srv: 2, kind: "noname"}, {srv: 3, kind: "compact"}})
	got := Findings(f, regObserve(t, obs.KindDelegation, "corp.test.", answers))
	values := map[Rule]string{}
	for _, g := range got {
		values[g.Rule] = g.Value
	}
	for rule, want := range map[Rule]string{
		RuleGlue: "10.53.0.3:53 a.ns.test. ns1.corp.test. A 10.53.0.99\n10.53.0.4:53 b.ns.test. ns1.corp.test. A 10.53.0.98",
		RuleGone: "10.53.0.5:53 c.ns.test. no such name\n10.53.0.6:53 d.ns.test. no such name",
	} {
		if values[rule] != want {
			t.Errorf("%v value %q, want %q", rule, values[rule], want)
		}
	}
	ds := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS none")
	o := regObserve(t, obs.KindDS, "corp.test.", regBuild(t, []regAns{{srv: 0, kind: "ds", data: []string{decDS}}}))
	if g := Findings(ds, o); len(g) != 1 || g[0].Value != "10.53.0.3:53 a.ns.test. "+g[0].Seen[0].Text {
		t.Errorf("ds finding:%s", decShow(g))
	}
}

// regWith gives f changed by change.
func regWith(f Finding, change func(*Finding)) Finding {
	change(&f)
	return f
}

func regCritical(f *Finding) { f.Severity = SeverityCritical }

func regChanges(t *testing.T, got, want []Change) {
	t.Helper()
	decSameChanges(t, got, want)
}

type regRow struct {
	name string
	f    *expect.File
	open []Finding
	o    obs.Observation
	ns   bool
	want []Change
}

func TestDSSeverityAcrossRuns(t *testing.T) {
	now := decT0.Add(time.Minute)
	f := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS "+decDS)
	corp, key := decName(t, "corp.test."), obs.DSKey(decName(t, "corp.test."))
	observe := func(specs ...regAns) obs.Observation {
		return regObserve(t, obs.KindDS, "corp.test.", regBuild(t, specs))
	}
	differ := observe(regAns{srv: 0, kind: "ds", data: []string{regDS2}})
	differ2 := observe(regAns{srv: 0, kind: "ds", data: []string{regDS2}}, regAns{srv: 1, kind: "nodata"})
	match := observe(regAns{srv: 0, kind: "ds", data: []string{decDS}})
	dead := observe(regDown(0), regDown(1))
	one := func(o obs.Observation) Finding {
		got := Findings(f, o)
		if len(got) != 1 || got[0].Rule != RuleDS || got[0].Severity != SeverityHigh {
			t.Fatalf("want one high ds finding:%s", decShow(got))
		}
		return got[0]
	}
	high, high2 := one(differ), one(differ2)
	crit, crit2 := regWith(high, regCritical), regWith(high2, regCritical)
	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }
	otherDomain := regWith(crit, func(f *Finding) { f.Check = obs.DSKey(decName(t, "shop.test.")) })
	nsAlert := Finding{Rule: RuleNameServers, Severity: SeverityCritical, Check: obs.DelegationKey(corp), Value: "x"}
	notCovered := Finding{Rule: RuleNotCovered, Severity: SeverityCritical, Check: key, Value: "x"}
	capitals := regWith(crit, func(f *Finding) { f.Check = obs.DSKey(decName(t, "CORP.TEST.")) })
	oldExpected := regWith(crit, func(f *Finding) { f.Expected = "none" })

	for _, c := range []regRow{
		{"opens at high", f, nil, differ, false, []Change{change(OpOpen, high)}},
		{"opens at critical beside an open nameservers alert", f, nil, differ, true, []Change{change(OpOpen, crit)}},
		{"high stays high", f, []Finding{high}, differ, false, nil},
		{"raised once the nameservers alert is open", f, []Finding{high}, differ, true, []Change{change(OpUpdate, crit)}},
		{"never lowered", f, []Finding{crit}, differ, false, nil},
		{"critical with the nameservers alert open raises nothing", f, []Finding{crit}, differ, true, nil},
		{"a new line while critical stays critical", f, []Finding{crit}, differ2, false, []Change{change(OpUpdate, crit2)}},
		{"a new line while critical and nameservers open", f, []Finding{crit}, differ2, true, []Change{change(OpUpdate, crit2)}},
		{"a new line at high", f, []Finding{high}, differ2, false, []Change{change(OpUpdate, high2)}},
		{"a new line and the raise together", f, []Finding{high}, differ2, true, []Change{change(OpUpdate, crit2)}},
		{"another expected text while critical", f, []Finding{oldExpected}, differ, false, []Change{change(OpUpdate, crit)}},
		{"resolves when the DS is as expected again", f, []Finding{crit}, match, false, []Change{change(OpResolve, crit)}},
		{"resolves at critical, nameservers open", f, []Finding{crit}, match, true, []Change{change(OpResolve, crit)}},
		{"resolves at high, nameservers open", f, []Finding{high}, match, true, []Change{change(OpResolve, high)}},
		{"nothing to resolve, nothing found", f, nil, match, true, nil},
		{"no usable answer does not resolve", f, []Finding{crit}, dead, false, nil},
		{"no usable answer does not resolve a high alert", f, []Finding{high}, dead, true, nil},
		{"no usable answer opens nothing", f, nil, dead, true, nil},
		{"a new alert after a resolve starts at high", f, nil, differ, false, []Change{change(OpOpen, high)}},
		{"the critical alert of another domain is not inherited", f, []Finding{otherDomain}, differ, false, []Change{change(OpOpen, high)}},
		{"the nameservers alert is another rule", f, []Finding{nsAlert}, differ, false, []Change{change(OpOpen, high)}},
		{"a critical alert of another rule on this check", f, []Finding{notCovered}, differ, false, []Change{change(OpOpen, high), change(OpResolve, notCovered)}},
		{"the same check in capitals", f, []Finding{capitals}, differ, false, nil},
		{"the first open alert of the check counts: high", f, []Finding{high, crit}, differ, false, nil},
		{"the first open alert of the check counts: critical", f, []Finding{crit, high}, differ, false, nil},
		{"the first open alert counts when it is high and nameservers is open", f, []Finding{high, crit}, differ, true, []Change{change(OpUpdate, crit)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			regChanges(t, Decide(Input{Expect: c.f, Open: c.open, Observation: c.o, Now: now, NameServersOpen: c.ns}), c.want)
		})
	}

	t.Run("not-covered is not raised", func(t *testing.T) {
		noLine := decFile(t, "domain corp.test.", regNSLine)
		got := Findings(noLine, differ)
		if len(got) != 1 || got[0].Rule != RuleNotCovered || got[0].Severity != SeverityMedium {
			t.Fatalf("want one medium not-covered finding:%s", decShow(got))
		}
		regChanges(t, Decide(Input{Expect: noLine, Observation: differ, Now: now, NameServersOpen: true}), []Change{change(OpOpen, got[0])})
	})
	t.Run("check-failing is not raised", func(t *testing.T) {
		regChanges(t, Decide(Input{Expect: f, Open: []Finding{crit}, Observation: dead, Now: now, NameServersOpen: true, FailingSince: decT0, FailLimit: timLimit}),
			[]Change{change(OpOpen, timFailing(key, timLimit))})
	})
}

// The nameservers alert matters to the ds check alone.
func TestNameServersOpenChangesNothingButDS(t *testing.T) {
	now := decT0.Add(time.Minute)
	f := regFile(t, "ns1.corp.test. A 10.53.0.11", "www.corp.test. A 10.53.0.81")
	corp := decName(t, "corp.test.")
	delegation := regObserve(t, obs.KindDelegation, "corp.test.", regBuild(t, []regAns{regGlue(0, "ns1.corp.test.=10.53.0.99"), {srv: 1, kind: "noname"}}))
	www := decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99")))
	serial := decObservation(obs.SerialKey(corp), corp, nil, decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "corp.test.", dnswire.TypeSOA, "ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")))
	for _, o := range []obs.Observation{delegation, www, serial} {
		t.Run(o.Key.Kind.String(), func(t *testing.T) {
			off := Decide(Input{Expect: f, Observation: o, Now: now})
			on := Decide(Input{Expect: f, Observation: o, Now: now, NameServersOpen: true})
			regChanges(t, on, off)
			if o.Key.Kind != obs.KindDelegation {
				return
			}
			wantRules := []Rule{RuleNameServers, RuleGlue, RuleGone}
			if len(off) != len(wantRules) {
				t.Fatalf("want nameservers, glue and gone to open:%s", decShowChanges(off))
			}
			for i, c := range off {
				if c.Op != OpOpen || c.Finding.Rule != wantRules[i] || c.Finding.Severity != SeverityCritical {
					t.Errorf("change %d is%s, want an open critical %v", i, decShowChanges([]Change{c}), wantRules[i])
				}
			}
		})
	}
}

func TestGlueAlertOpensUpdatesAndResolves(t *testing.T) {
	now := decT0.Add(time.Minute)
	const l1, l2 = "ns1.corp.test. A 10.53.0.11", "ns2.corp.test. A 10.53.0.12"
	f := regFile(t, l1, l2)
	observe := func(specs ...regAns) obs.Observation {
		return regObserve(t, obs.KindDelegation, "corp.test.", regBuild(t, specs))
	}
	right := []string{"ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.12"}
	bad := observe(regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99"))
	bad2 := observe(regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99"), regGlue(1, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.97"))
	badOther := observe(regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.98"))
	badOnB := observe(regDown(0), regGlue(1, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99"))
	badAndDown := observe(regGlue(0, "ns1.corp.test.=10.53.0.11", "ns2.corp.test.=10.53.0.99"), regDown(1))
	secondHost := observe(regGlue(0, "ns1.corp.test.=10.53.0.98", "ns2.corp.test.=10.53.0.99"))
	good := observe(regGlue(0, right...))
	noGlue := observe(regGlue(0))
	allDown := observe(regDown(0), regDown(1))
	aDownBGood := observe(regDown(0), regGlue(1, right...))
	aGoodBDown := observe(regGlue(0, right...), regDown(1))

	one := func(file *expect.File, o obs.Observation, rule Rule) Finding {
		for _, g := range Findings(file, o) {
			if g.Rule == rule {
				return g
			}
		}
		t.Fatalf("no %v finding in:%s", rule, decShow(Findings(file, o)))
		return Finding{}
	}
	glue, glue2, glueOther, glueB, glueSecond := one(f, bad, RuleGlue), one(f, bad2, RuleGlue), one(f, badOther, RuleGlue), one(f, badOnB, RuleGlue), one(f, secondHost, RuleGlue)
	otherExpected := regWith(glue, func(f *Finding) { f.Expected = l1 })
	otherCheck := regWith(glue, func(f *Finding) { f.Check = obs.DelegationKey(decName(t, "shop.test.")) })
	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }

	for _, c := range []regRow{
		{"opens once", f, nil, bad, false, []Change{change(OpOpen, glue)}},
		{"the same difference again", f, []Finding{glue}, bad, false, nil},
		{"a second server shows it", f, []Finding{glue}, bad2, false, []Change{change(OpUpdate, glue2)}},
		{"a server drops out", f, []Finding{glue2}, bad, false, nil},
		{"another server shows the same address", f, []Finding{glueB}, bad, false, nil},
		{"the same server gives another address", f, []Finding{glue}, badOther, false, []Change{change(OpUpdate, glueOther)}},
		{"a second host starts to differ", f, []Finding{glue}, secondHost, false, []Change{change(OpUpdate, glueSecond)}},
		{"a failure beside it is no news", f, []Finding{glue}, badAndDown, false, nil},
		{"the expected text changes", f, []Finding{otherExpected}, bad, false, []Change{change(OpUpdate, glue)}},
		{"resolves when the glue is as expected", f, []Finding{glue}, good, false, []Change{change(OpResolve, glue)}},
		{"resolves when there is no glue", f, []Finding{glue}, noGlue, false, []Change{change(OpResolve, glue)}},
		{"no usable answer does not resolve", f, []Finding{glue}, allDown, false, nil},
		{"the server that showed it fails", f, []Finding{glue}, aDownBGood, false, nil},
		{"another server fails", f, []Finding{glue}, aGoodBDown, false, []Change{change(OpResolve, glue)}},
		{"the alert of another check", f, []Finding{otherCheck}, bad, false, []Change{change(OpOpen, glue)}},
		{"nothing open, nothing found", f, nil, good, false, nil},
		{"the alert is critical whatever the nameservers alert says", f, nil, bad, true, []Change{change(OpOpen, glue)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			regChanges(t, Decide(Input{Expect: c.f, Open: c.open, Observation: c.o, Now: now, NameServersOpen: c.ns}), c.want)
		})
	}

	// Glue is one rule beside nameservers: each opens, stays and resolves by itself.
	other := regFileNS(t, "corp.test. NS ns1.dnshost.test.", l1, l2)
	both := bad
	nsF, glueF := one(other, both, RuleNameServers), one(other, both, RuleGlue)
	glueFine := good
	for _, c := range []regRow{
		{"both open", other, nil, both, false, []Change{change(OpOpen, nsF), change(OpOpen, glueF)}},
		{"glue opens beside an open nameservers alert", other, []Finding{nsF}, both, false, []Change{change(OpOpen, glueF)}},
		{"nameservers opens beside an open glue alert", other, []Finding{glueF}, both, false, []Change{change(OpOpen, nsF)}},
		{"both stay", other, []Finding{nsF, glueF}, both, false, nil},
		{"both stay, in the other order", other, []Finding{glueF, nsF}, both, false, nil},
		{"the glue is right again", other, []Finding{nsF, glueF}, glueFine, false, []Change{change(OpResolve, glueF)}},
		{"the nameservers are right again", f, []Finding{nsF, glueF}, both, false, []Change{change(OpResolve, regWith(nsF, func(x *Finding) { x.Expected = decFormText(t, f, "corp.test.", dnswire.TypeNS) }))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			regChanges(t, Decide(Input{Expect: c.f, Open: c.open, Observation: c.o, Now: now}), c.want)
		})
	}
}

func TestGoneAlertOpensUpdatesAndResolves(t *testing.T) {
	now := decT0.Add(time.Minute)
	f := regFile(t)
	observe := func(specs ...regAns) obs.Observation {
		return regObserve(t, obs.KindDelegation, "corp.test.", regBuild(t, specs))
	}
	gone1 := observe(regAns{srv: 0, kind: "noname"})
	gone2 := observe(regAns{srv: 0, kind: "noname"}, regAns{srv: 1, kind: "compact"})
	goneAndFail := observe(regAns{srv: 0, kind: "noname"}, regDown(1))
	goneAndFine := observe(regAns{srv: 0, kind: "noname"}, regGlue(1))
	exists := observe(regGlue(0), regGlue(1))
	noData := observe(regAns{srv: 0, kind: "nodata"})
	allDown := observe(regDown(0), regDown(1))
	aDownBFine := observe(regDown(0), regGlue(1))
	aFineBDown := observe(regGlue(0), regDown(1))
	find := func(o obs.Observation, rule Rule) Finding {
		for _, g := range Findings(f, o) {
			if g.Rule == rule {
				return g
			}
		}
		t.Fatalf("no %v finding in:%s", rule, decShow(Findings(f, o)))
		return Finding{}
	}
	ns1, gone := find(gone1, RuleNameServers), find(gone1, RuleGone)
	ns2, goneB := find(gone2, RuleNameServers), find(gone2, RuleGone)
	nsData := find(noData, RuleNameServers)
	otherCheck := regWith(gone, func(f *Finding) { f.Check = obs.DelegationKey(decName(t, "shop.test.")) })
	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }

	for _, c := range []regRow{
		{"opens beside nameservers, in rule order", f, nil, gone1, false, []Change{change(OpOpen, ns1), change(OpOpen, gone)}},
		{"stays", f, []Finding{ns1, gone}, gone1, false, nil},
		{"opens beside an open nameservers alert", f, []Finding{ns1}, gone1, false, []Change{change(OpOpen, gone)}},
		{"a second server says it too", f, []Finding{gone}, gone2, false, []Change{change(OpOpen, ns2)}},
		{"a second server says it too, both open", f, []Finding{ns1, gone}, gone2, false, nil},
		{"one of the two servers that said it fails", f, []Finding{ns2, goneB}, goneAndFail, false, nil},
		{"a failure beside it is no news", f, []Finding{ns1, gone}, goneAndFail, false, nil},
		{"a server that finds the domain is no news", f, []Finding{ns1, gone}, goneAndFine, false, nil},
		{"resolves when the domain exists, in open order", f, []Finding{ns1, gone}, exists, false, []Change{change(OpResolve, ns1), change(OpResolve, gone)}},
		{"resolves in open order, reversed", f, []Finding{gone, ns1}, exists, false, []Change{change(OpResolve, gone), change(OpResolve, ns1)}},
		{"no data is not gone", f, []Finding{gone}, noData, false, []Change{change(OpOpen, nsData), change(OpResolve, gone)}},
		{"no usable answer does not resolve", f, []Finding{ns1, gone}, allDown, false, nil},
		{"the server that showed it fails", f, []Finding{ns1, gone}, aDownBFine, false, nil},
		{"another server fails", f, []Finding{ns1, gone}, aFineBDown, false, []Change{change(OpResolve, ns1), change(OpResolve, gone)}},
		{"the alert of another check", f, []Finding{otherCheck}, gone1, false, []Change{change(OpOpen, ns1), change(OpOpen, gone)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			regChanges(t, Decide(Input{Expect: c.f, Open: c.open, Observation: c.o, Now: now, NameServersOpen: c.ns}), c.want)
		})
	}
}

// ---- the property test ----

const (
	regSeed  = 20261116
	regCases = 2000
)

var (
	regHostLines  = []string{"ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test.", "ns1.dnshost.test."}
	regGlueOwners = []string{"ns1.corp.test.", "NS1.CORP.TEST.", "ns2.corp.test.", "NS2.Corp.Test.", "ns3.corp.test.", "ns1.dnshost.test.", "ns9.corp.test."}
	regAForms     = []string{"10.53.0.11", "10.53.0.12 | 10.53.0.11", "10.53.0.99", "in 10.53.0.0/24", "none"}
	regAAAAForms  = []string{"fd53::11", "fd53::11 | fd53::12", "in fd53::/64", "none"}
	regAData      = []string{"10.53.0.11", "10.53.0.12", "10.53.0.99"}
	regAAAAData   = []string{"fd53::11", "fd53::12", "fd53::99"}
	regNSData     = []string{"ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."}
)

type regGen struct {
	t   testing.TB
	rng *rand.Rand
}

func regPick[T any](g *regGen, xs ...T) T { return xs[g.rng.IntN(len(xs))] }

func (g *regGen) file(domain string) *expect.File {
	lines := []string{"domain " + domain}
	if ns := regPick(g, "", "ns1.corp.test. | ns2.corp.test.", "none"); ns != "" {
		lines = append(lines, domain+" NS "+ns)
	}
	switch regPick(g, 0, 1, 2, 3) {
	case 1:
		lines = append(lines, domain+" DS none")
	case 2:
		lines = append(lines, domain+" DS "+decDS)
	case 3:
		lines = append(lines, domain+" DS "+decDS+" | "+regDS2)
	}
	for _, h := range regHostLines {
		if g.rng.IntN(2) == 0 {
			lines = append(lines, h+" A "+regPick(g, regAForms...))
		}
		if g.rng.IntN(3) == 0 {
			lines = append(lines, h+" AAAA "+regPick(g, regAAAAForms...))
		}
	}
	return decFile(g.t, lines...)
}

func (g *regGen) glue() []dnswire.Record {
	var glue []dnswire.Record
	for _, owner := range regGlueOwners {
		for range g.rng.IntN(3) / 2 * (1 + g.rng.IntN(2)) {
			glue = append(glue, decRR(g.t, owner, dnswire.TypeA, regPick(g, regAData...)))
		}
		if g.rng.IntN(5) == 0 {
			glue = append(glue, decRR(g.t, owner, dnswire.TypeAAAA, regPick(g, regAAAAData...)))
		}
	}
	g.rng.Shuffle(len(glue), func(i, j int) { glue[i], glue[j] = glue[j], glue[i] })
	return glue
}

func (g *regGen) set(kind obs.Kind) []dnswire.Record {
	var set []dnswire.Record
	for range 1 + g.rng.IntN(3) {
		switch kind {
		case obs.KindDelegation:
			set = append(set, decRR(g.t, "corp.test.", dnswire.TypeNS, regPick(g, regNSData...)))
		case obs.KindDS:
			set = append(set, decRR(g.t, "corp.test.", dnswire.TypeDS, regPick(g, decDS, regDS2)))
		case obs.KindRecords:
			set = append(set, decRR(g.t, "www.corp.test.", dnswire.TypeA, regPick(g, regAData...)))
		case obs.KindSerial:
			set = append(set, decRR(g.t, "corp.test.", dnswire.TypeSOA, "ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300"))
		case obs.KindWildcard, obs.KindCertificates, obs.KindPolicy:
			// The registry rules read no wildcard, certificate or policy check.
		}
	}
	return set
}

func (g *regGen) result(kind obs.Kind) obs.Result {
	switch g.rng.IntN(9) {
	case 0:
		return obs.NoDataResult(obs.NoData{SOA: decSOA(g.t, "test.")})
	case 1, 2:
		return obs.NoNameResult(obs.NoName{SOA: decSOA(g.t, "test."), Compact: g.rng.IntN(2) == 0})
	case 3:
		return obs.Result{}
	case 4:
		return obs.FailureResult(obs.Failure{Reason: obs.Reason(1 + g.rng.IntN(13)), Detail: "drawn"})
	}
	return obs.RecordsResult(obs.Records{Set: g.set(kind), Glue: g.glue()})
}

func (g *regGen) key(domain string) obs.Key {
	d := decName(g.t, domain)
	switch regPick(g, 0, 0, 0, 0, 1, 1, 1, 1, 2, 3) {
	case 0:
		return obs.DelegationKey(d)
	case 1:
		return obs.DSKey(d)
	case 2:
		return obs.RecordsKey(d, decName(g.t, "www.corp.test."), dnswire.TypeA)
	}
	return obs.SerialKey(d)
}

func (g *regGen) observation(key obs.Key) obs.Observation {
	start := decT0.Add(time.Duration(g.rng.IntN(1000)) * time.Minute)
	o := obs.Observation{Key: key, Start: start, Deadline: start.Add(45 * time.Second), Zone: decName(g.t, "test.")}
	q := dnswire.Question{Name: key.Name, Type: key.Type, Class: dnswire.ClassINET}
	servers := slices.Clone(regServers)
	g.rng.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
	for _, s := range servers[:1+g.rng.IntN(4)] {
		a := decAnswer(g.t, s.host, s.addr, g.result(key.Kind))
		a.Question = q
		o.Answers = append(o.Answers, a)
	}
	return o
}

// ---- the oracle: the formulas of the rules, written from their text ----

func regSetOf(a obs.Answer) (set []dnswire.Record, failure bool) {
	failure = obs.Match(a.Result, func(r obs.Records) bool { set = r.Set; return false },
		func(obs.NoData) bool { return false }, func(obs.NoName) bool { return false }, func(obs.Failure) bool { return true })
	return set, failure
}

func regIsNoName(a obs.Answer) bool {
	return obs.Match(a.Result, func(obs.Records) bool { return false }, func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return true }, func(obs.Failure) bool { return false })
}

func regGlueOf(a obs.Answer) []dnswire.Record {
	return obs.Match(a.Result, func(r obs.Records) []dnswire.Record { return r.Glue },
		func(obs.NoData) []dnswire.Record { return nil }, func(obs.NoName) []dnswire.Record { return nil },
		func(obs.Failure) []dnswire.Record { return nil })
}

type regGroup struct {
	host dnswire.Name
	typ  dnswire.Type
	recs []dnswire.Record
}

// regPart is one part of the Expected of a glue finding.
type regPart struct {
	host dnswire.Name
	typ  dnswire.Type
	text string
}

func regGroups(glue []dnswire.Record) []regGroup {
	var gs []regGroup
	for _, r := range glue {
		i := slices.IndexFunc(gs, func(g regGroup) bool { return g.host.Equal(r.Name) && g.typ == r.Type() })
		if i < 0 {
			gs = append(gs, regGroup{host: r.Name, typ: r.Type()})
			i = len(gs) - 1
		}
		gs[i].recs = append(gs[i].recs, r)
	}
	slices.SortStableFunc(gs, func(a, b regGroup) int {
		return cmp.Or(dnswire.Compare(a.host, b.host), cmp.Compare(a.typ, b.typ))
	})
	return gs
}

// regOracle is what the rules must give for (f, o): the findings of glue,
// gone and ds as Finding values (nil when absent), the parts of the glue
// Expected, and the rules that Findings must hold for a check of the parent.
type regOracle struct {
	glue, gone, ds *Finding
	glueParts      []string
	rules          []Rule // delegation and ds checks only
	nameServers    []Seen
}

func regOracleOf(f *expect.File, o obs.Observation) regOracle {
	var or regOracle
	key := o.Key
	cov := f != nil && key.Domain.Equal(f.Domain)
	line, covered := expect.Expectation{}, false
	if cov {
		line, covered = f.Find(key.Name, key.Type)
	}
	if !covered {
		or.rules = []Rule{RuleNotCovered}
	}

	if cov && key.Kind == obs.KindDelegation {
		var seen []Seen
		var parts []regPart
		for _, a := range o.Answers {
			for _, g := range regGroups(regGlueOf(a)) {
				_, a4 := f.Find(g.host, dnswire.TypeA)
				_, a6 := f.Find(g.host, dnswire.TypeAAAA)
				if !a4 && !a6 {
					continue
				}
				e, ok := f.Find(g.host, g.typ)
				if ok && e.Match(g.recs) {
					continue
				}
				host := g.host.Lower().String()
				seen = append(seen, Seen{Answer: a, Text: host + " " + g.typ.String() + " " + expect.SetText(g.typ, g.recs)})
				part := host + " " + g.typ.String() + " (no line)"
				if ok {
					part = e.String()
				}
				if !slices.ContainsFunc(parts, func(p regPart) bool { return p.host.Equal(g.host) && p.typ == g.typ }) {
					parts = append(parts, regPart{g.host, g.typ, part})
				}
			}
		}
		slices.SortFunc(parts, func(a, b regPart) int {
			return cmp.Or(dnswire.Compare(a.host, b.host), cmp.Compare(a.typ, b.typ))
		})
		for _, p := range parts {
			or.glueParts = append(or.glueParts, p.text)
		}
		if len(seen) > 0 {
			or.glue = &Finding{Rule: RuleGlue, Severity: SeverityCritical, Check: key, Expected: strings.Join(or.glueParts, "; "), Seen: seen, Value: regValue(seen)}
		}
		var gone []Seen
		for _, a := range o.Answers {
			if regIsNoName(a) {
				gone = append(gone, Seen{Answer: a, Text: "no such name"})
			}
		}
		if len(gone) > 0 {
			or.gone = &Finding{Rule: RuleGone, Severity: SeverityCritical, Check: key, Seen: gone, Value: regValue(gone)}
		}
	}

	if covered {
		var seen []Seen
		for _, a := range o.Answers {
			if set, failed := regSetOf(a); !failed && !line.Match(set) {
				seen = append(seen, Seen{Answer: a, Text: expect.SetText(key.Type, set)})
			}
		}
		switch key.Kind {
		case obs.KindDelegation:
			or.nameServers = seen
			if len(seen) > 0 {
				or.rules = append(or.rules, RuleNameServers)
			}
		case obs.KindDS:
			if len(seen) > 0 {
				or.ds = &Finding{Rule: RuleDS, Severity: SeverityHigh, Check: key, Expected: line.FormText(), Seen: seen, Value: regValue(seen)}
				or.rules = append(or.rules, RuleDS)
			}
		case obs.KindRecords, obs.KindSerial, obs.KindWildcard, obs.KindCertificates, obs.KindPolicy:
			// No registry-level rule reads these checks.
		}
	}
	if or.glue != nil {
		or.rules = append(or.rules, RuleGlue)
	}
	if or.gone != nil {
		or.rules = append(or.rules, RuleGone)
	}
	return or
}

func regFirstOpen(open []Finding, key obs.Key, r Rule) *Finding {
	for i := range open {
		if open[i].Rule == r && open[i].Check.String() == key.String() {
			return &open[i]
		}
	}
	return nil
}

// regNews is the update rule: another expected text (for glue: a part that
// was not there), another severity or a value that no Seen line showed.
func regNews(was, f Finding) bool {
	expected := was.Expected != f.Expected
	if f.Rule == RuleGlue {
		old := strings.Split(was.Expected, "; ")
		expected = slices.ContainsFunc(strings.Split(f.Expected, "; "), func(p string) bool { return !slices.Contains(old, p) })
	}
	return expected || was.Severity != f.Severity || decNewValue(was, f)
}

func regNoFailure(o obs.Observation) bool {
	for _, a := range o.Answers {
		if _, failed := regSetOf(a); failed {
			return false
		}
	}
	return true
}

// regOutcome is what Decide must do about the alert of rule r: its open or
// update change, and its resolve change when the general rule demands one.
type regOutcome struct {
	rule    Rule
	change  *Change
	resolve *Change
	// noResolve: Decide must give no resolve change of this rule; an open or
	// update change may still come
	noResolve bool
	critical  bool // ds: whether the raise rule gave critical
}

func regOutcomeOf(in Input, or regOracle, r Rule) regOutcome {
	out := regOutcome{rule: r}
	key := in.Observation.Key
	was := regFirstOpen(in.Open, key, r)
	var want *Finding
	switch r {
	case RuleGlue:
		want = or.glue
	case RuleGone:
		want = or.gone
	case RuleDS:
		if or.ds != nil {
			f := *or.ds
			if in.NameServersOpen || (was != nil && was.Severity == SeverityCritical) {
				f.Severity = SeverityCritical
				out.critical = true
			}
			want = &f
		}
	case RuleInvalidFile, RuleNotCovered, RuleZone, RuleNameServers, RuleRecordSet, RuleCheckFailing, RuleZoneChanged,
		RuleDisagree, RuleAliasTarget, RuleNameServerHost, RuleMailTarget, RuleChallenge, RuleWildcard, RuleCAA,
		RuleIssuer, RuleCertName, RuleHostnames, RuleSPF, RuleDMARC, RuleDKIM, RuleMTASTS:
		// Not registry-level rules: the oracle wants no finding.
	}
	switch {
	case want != nil:
		out.noResolve = true
		if was == nil {
			out.change = &Change{Op: OpOpen, Finding: *want, At: in.Now}
		} else if regNews(*was, *want) {
			out.change = &Change{Op: OpUpdate, Finding: *want, At: in.Now}
		}
	case was == nil:
		out.noResolve = true
	case regNoFailure(in.Observation):
		out.resolve = &Change{Op: OpResolve, Finding: rsvLineInForce(in.Expect, key, *was), At: in.Now}
	case !slices.ContainsFunc(in.Observation.Answers, func(a obs.Answer) bool { _, failed := regSetOf(a); return !failed }):
		out.noResolve = true
	}
	return out
}

// ---- inputs ----

// regInput draws one input from seed; equal seeds give equal inputs.
func regInput(t testing.TB, seed uint64) Input {
	g := &regGen{t: t, rng: rand.New(rand.NewPCG(seed, 11))}
	fileDomain := regPick(g, "corp.test.", "Corp.Test.", "shop.test.")
	keyDomain := fileDomain
	if g.rng.IntN(4) == 0 {
		keyDomain = regPick(g, "corp.test.", "CORP.TEST.", "shop.test.")
	}
	in := Input{NameServersOpen: g.rng.IntN(2) == 0}
	if g.rng.IntN(10) > 0 {
		in.Expect = g.file(fileDomain)
	}
	in.Observation = g.observation(g.key(keyDomain))
	in.Now = in.Observation.Deadline.Add(time.Duration(g.rng.IntN(60)) * time.Second)

	or := regOracleOf(in.Expect, in.Observation)
	var found []*Finding
	for _, f := range []*Finding{or.glue, or.gone, or.ds} {
		if f != nil {
			found = append(found, f)
		}
	}
	key := in.Observation.Key
	for range g.rng.IntN(5) {
		var f Finding
		if len(found) > 0 && g.rng.IntN(3) > 0 {
			// An alert that this run would open or keep: same text, and the
			// first line only, another expected text, or one more part.
			f = *regPick(g, found...)
			switch g.rng.IntN(4) {
			case 0:
				f.Value, _, _ = strings.Cut(f.Value, "\n")
			case 1:
				f.Expected = "old"
			case 2:
				f.Expected = "an extra part; " + f.Expected
			}
		} else {
			f = Finding{Rule: Rule(1 + g.rng.IntN(10)), Value: regPick(g, "10.53.0.3:53 a.ns.test. none", "x", "")}
			if g.rng.IntN(2) == 0 {
				f.Rule = regPick(g, RuleGlue, RuleDS, RuleGone, RuleNameServers)
			}
		}
		f.Severity = regPick(g, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical, SeverityCritical, Severity(0))
		f.Check = key
		switch g.rng.IntN(6) {
		case 0:
			f.Check.Domain = decName(t, strings.ToUpper(key.Domain.String()))
			f.Check.Name = decName(t, strings.ToUpper(key.Name.String()))
		case 1:
			f.Check = g.key(keyDomain)
		}
		in.Open = append(in.Open, f)
	}
	return in
}

func regShow(c []Change) string { return decShowChanges(c) }

func regSame(a, b []Change) bool { return (len(a) == 0 && len(b) == 0) || reflect.DeepEqual(a, b) }

// regCheckFindings holds Findings to the formulas of the three rules.
func regCheckFindings(t *testing.T, seed uint64, in Input) {
	t.Helper()
	f, o := in.Expect, in.Observation
	got := Findings(f, o)
	or := regOracleOf(f, o)
	byRule := func(r Rule) *Finding {
		for i := range got {
			if got[i].Rule == r {
				return &got[i]
			}
		}
		return nil
	}
	for i := 1; i < len(got); i++ {
		if got[i-1].Rule > got[i].Rule {
			t.Fatalf("seed %d: findings not in rule order:%s", seed, decShow(got))
		}
	}
	for _, r := range []Rule{RuleGlue, RuleGone, RuleDS} {
		var want *Finding
		switch r {
		case RuleGlue:
			want = or.glue
		case RuleGone:
			want = or.gone
		case RuleDS:
			want = or.ds
		case RuleInvalidFile, RuleNotCovered, RuleZone, RuleNameServers, RuleRecordSet, RuleCheckFailing, RuleZoneChanged,
			RuleDisagree, RuleAliasTarget, RuleNameServerHost, RuleMailTarget, RuleChallenge, RuleWildcard, RuleCAA,
			RuleIssuer, RuleCertName, RuleHostnames, RuleSPF, RuleDMARC, RuleDKIM, RuleMTASTS:
			t.Fatalf("seed %d: %v is not a registry-level rule", seed, r)
		}
		g := byRule(r)
		if (g == nil) != (want == nil) {
			t.Fatalf("seed %d: %v present %v, want %v:%s", seed, r, g != nil, want != nil, decShow(got))
		}
		if g == nil {
			continue
		}
		if g.Rule != want.Rule || g.Severity != want.Severity || !reflect.DeepEqual(g.Check, o.Key) || g.Value != want.Value || len(g.Seen) != len(want.Seen) {
			t.Fatalf("seed %d: %v is%s\nwant%s", seed, r, decShow([]Finding{*g}), decShow([]Finding{*want}))
		}
		for i := range want.Seen {
			if !reflect.DeepEqual(g.Seen[i], want.Seen[i]) {
				t.Fatalf("seed %d: %v seen %d is %v %q, want %v %q", seed, r, i, g.Seen[i].Answer.Server, g.Seen[i].Text, want.Seen[i].Answer.Server, want.Seen[i].Text)
			}
		}
		if g.Expected != want.Expected {
			t.Fatalf("seed %d: %v expected %q, want %q", seed, r, g.Expected, want.Expected)
		}
	}
	if o.Key.Kind != obs.KindDelegation && o.Key.Kind != obs.KindDS {
		for _, r := range []Rule{RuleGlue, RuleGone, RuleDS} {
			if byRule(r) != nil {
				t.Fatalf("seed %d: %v for a check of kind %v", seed, r, o.Key.Kind)
			}
		}
		return
	}
	if o.Key.Kind == obs.KindDS && (byRule(RuleGlue) != nil || byRule(RuleGone) != nil) {
		t.Fatalf("seed %d: glue or gone for the ds check", seed)
	}
	if o.Key.Kind == obs.KindDelegation && byRule(RuleDS) != nil {
		t.Fatalf("seed %d: ds for the delegation check", seed)
	}
	var rules []Rule
	for _, g := range got {
		rules = append(rules, g.Rule)
	}
	if !slices.Equal(rules, or.rules) {
		t.Fatalf("seed %d: rules %v, want %v:%s", seed, rules, or.rules, decShow(got))
	}
	// The nameservers finding is the match of Records.Set against its line.
	if ns := byRule(RuleNameServers); ns != nil {
		if len(ns.Seen) != len(or.nameServers) {
			t.Fatalf("seed %d: nameservers saw %d, want %d", seed, len(ns.Seen), len(or.nameServers))
		}
		for i := range ns.Seen {
			if !reflect.DeepEqual(ns.Seen[i], or.nameServers[i]) {
				t.Fatalf("seed %d: nameservers seen %d differs", seed, i)
			}
		}
	}
}

func regCheckDecide(t *testing.T, seed uint64, in Input, twin Input) {
	t.Helper()
	got := Decide(in)
	or := regOracleOf(in.Expect, in.Observation)
	for _, c := range got {
		if c.Finding.Check.String() != in.Observation.Key.String() {
			t.Fatalf("seed %d: a change of check %v", seed, c.Finding.Check)
		}
	}
	for _, r := range []Rule{RuleGlue, RuleGone, RuleDS} {
		out := regOutcomeOf(in, or, r)
		var opens, resolves []Change
		for _, c := range got {
			switch {
			case c.Finding.Rule != r:
			case c.Op == OpResolve:
				resolves = append(resolves, c)
			default:
				opens = append(opens, c)
			}
		}
		if out.change == nil && len(opens) != 0 || out.change != nil && !(len(opens) == 1 && reflect.DeepEqual(opens[0], *out.change)) {
			t.Fatalf("seed %d: %v opens or updates%s\nwant %+v", seed, r, regShow(opens), out.change)
		}
		if out.noResolve && len(resolves) != 0 {
			t.Fatalf("seed %d: %v resolved when it must not:%s", seed, r, regShow(resolves))
		}
		if out.resolve != nil && !(len(resolves) == 1 && reflect.DeepEqual(resolves[0], *out.resolve)) {
			t.Fatalf("seed %d: %v resolves%s\nwant %+v", seed, r, regShow(resolves), *out.resolve)
		}
		if r == RuleDS && out.change != nil {
			wantCritical := in.NameServersOpen || (regFirstOpen(in.Open, in.Observation.Key, RuleDS) != nil && regFirstOpen(in.Open, in.Observation.Key, RuleDS).Severity == SeverityCritical)
			if (out.change.Finding.Severity == SeverityCritical) != wantCritical {
				t.Fatalf("seed %d: ds severity %v with nameservers open %v", seed, out.change.Finding.Severity, in.NameServersOpen)
			}
		}
	}
	// Only a ds check reads the nameservers alert.
	if in.Observation.Key.Kind != obs.KindDS {
		twin.NameServersOpen = !twin.NameServersOpen
		if flipped := Decide(twin); !regSame(got, flipped) {
			t.Fatalf("seed %d: NameServersOpen changed the result for a %v check:%s\nand%s", seed, in.Observation.Key.Kind, regShow(got), regShow(flipped))
		}
	}
}

func TestRegistryRulesProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", regSeed, regCases)
	for i := range regCases {
		seed := uint64(regSeed + i)
		in := regInput(t, seed)
		regCheckFindings(t, seed, in)
		regCheckDecide(t, seed, in, regInput(t, seed))
	}
}

// Failure is unknown: its reason does not matter, and a failure beside an
// answer that is not one changes nothing.
func TestRegistryFailuresAreUnknownProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", regSeed, regCases)
	checked := 0
	for i := range regCases {
		seed := uint64(regSeed + i)
		in := regInput(t, seed)
		if k := in.Observation.Key.Kind; k != obs.KindDelegation && k != obs.KindDS {
			continue
		}
		want := Findings(in.Expect, in.Observation)

		other := regInput(t, seed)
		for j, a := range other.Observation.Answers {
			if _, failed := regSetOf(a); failed {
				other.Observation.Answers[j].Result = obs.FailureResult(obs.Failure{Reason: obs.ReasonRefused, Detail: "another reason"})
			}
		}
		if got := Findings(other.Expect, other.Observation); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: another reason of failure changed the findings:%s\nto%s", seed, decShow(want), decShow(got))
		}

		more := regInput(t, seed)
		usable := slices.ContainsFunc(more.Observation.Answers, func(a obs.Answer) bool { _, failed := regSetOf(a); return !failed })
		if !usable {
			continue
		}
		extra := decAnswer(t, "e.ns.test.", "10.53.0.7:53", decFailure(obs.ReasonTimeout))
		at := int(seed) % (len(more.Observation.Answers) + 1)
		more.Observation.Answers = slices.Insert(more.Observation.Answers, at, extra)
		if got := Findings(more.Expect, more.Observation); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: a failure beside a usable answer changed the findings:%s\nto%s", seed, decShow(want), decShow(got))
		}
		checked++
	}
	if checked < 100 {
		t.Errorf("only %d cases added a failure beside a usable answer", checked)
	}
}

// The inputs of the property tests must reach every outcome, or a rule that
// never fires would pass.
func TestRegistryInputsReachEveryOutcome(t *testing.T) {
	tally := map[string]int{}
	for i := range regCases {
		in := regInput(t, uint64(regSeed+i))
		or := regOracleOf(in.Expect, in.Observation)
		if len(or.glueParts) > 1 {
			tally["glue with several parts"]++
		}
		if or.glue != nil && len(or.glue.Seen) > 1 {
			tally["glue seen more than once"]++
		}
		for r, word := range map[Rule]string{RuleGlue: "glue", RuleGone: "gone", RuleDS: "ds"} {
			out := regOutcomeOf(in, or, r)
			if out.change != nil {
				tally[word+" "+out.change.Op.String()]++
			}
			if out.resolve != nil {
				tally[word+" resolve"]++
			}
			if out.noResolve && regFirstOpen(in.Open, in.Observation.Key, r) != nil {
				tally[word+" kept"]++
			}
			if out.critical {
				tally["ds critical"]++
				if !in.NameServersOpen {
					tally["ds critical by its own alert"]++
				}
			}
		}
		if in.Observation.Key.Kind == obs.KindDS && or.ds != nil && !in.NameServersOpen {
			if o := regFirstOpen(in.Open, in.Observation.Key, RuleDS); o != nil && o.Severity != SeverityCritical {
				tally["ds high stays high"]++
			}
		}
	}
	for _, want := range []string{
		"glue open", "glue update", "glue resolve", "glue kept", "glue with several parts", "glue seen more than once",
		"gone open", "gone update", "gone resolve", "gone kept",
		"ds open", "ds update", "ds resolve", "ds kept", "ds critical", "ds critical by its own alert", "ds high stays high",
	} {
		if tally[want] < 20 {
			t.Errorf("only %d cases of %q in %d", tally[want], want, regCases)
		}
	}
}

func TestRegistryPureProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", regSeed, regCases)
	for i := range regCases {
		seed := uint64(regSeed + i)
		a, b := regInput(t, seed), regInput(t, seed)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: one seed gave two inputs", seed)
		}
		found := Findings(a.Expect, a.Observation)
		got := Decide(a)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: Findings or Decide changed their input", seed)
		}
		if again := Findings(b.Expect, b.Observation); !reflect.DeepEqual(found, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, decShow(found), decShow(again))
		}
		if again := Decide(b); !regSame(got, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, regShow(got), regShow(again))
		}
		outs := make([][]Change, 4)
		var wg sync.WaitGroup
		for j := range outs {
			wg.Go(func() { outs[j] = Decide(a) })
		}
		wg.Wait()
		for j, out := range outs {
			if !regSame(out, got) {
				t.Fatalf("seed %d: goroutine %d gave%s\nwant%s", seed, j, regShow(out), regShow(got))
			}
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: Decide changed its input in a goroutine", seed)
		}
	}
}

// A part of Expected that is gone is no news for a glue alert: a parent server
// that fails for one run must not send "changed again". A part that the alert
// does not hold, a value that it does not show and another severity are news;
// a value that it shows at one more server is not.
func TestGlueNewsForAnOpenAlert(t *testing.T) {
	now := decT0.Add(time.Minute)
	const l1, l2 = "ns1.corp.test. A 10.53.0.11", "ns2.corp.test. A 10.53.0.12"
	f := regFile(t, l1, l2)
	const (
		bad1 = "ns1.corp.test.=10.53.0.98"
		bad2 = "ns2.corp.test.=10.53.0.99"
		ok1  = "ns1.corp.test.=10.53.0.11"
		ok2  = "ns2.corp.test.=10.53.0.12"
	)
	observe := func(specs ...regAns) obs.Observation {
		return regObserve(t, obs.KindDelegation, "corp.test.", regBuild(t, specs))
	}
	find := func(file *expect.File, o obs.Observation, rule Rule) Finding {
		for _, g := range Findings(file, o) {
			if g.Rule == rule {
				return g
			}
		}
		t.Fatalf("no %v finding in:%s", rule, decShow(Findings(file, o)))
		return Finding{}
	}
	two := observe(regGlue(0, bad1, ok2), regGlue(1, ok1, bad2))
	both := find(f, two, RuleGlue)
	if both.Expected != l1+"; "+l2 || strings.Count(both.Value, "\n") != 1 {
		t.Fatalf("the open alert has expected %q, value %q", both.Expected, both.Value)
	}
	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }
	run := func(file *expect.File, open Finding, o obs.Observation, want []Change) {
		t.Helper()
		regChanges(t, Decide(Input{Expect: file, Open: []Finding{open}, Observation: o, Now: now}), want)
	}

	t.Run("the server that showed one part fails: one part fewer, no update", func(t *testing.T) {
		o := observe(regDown(0), regGlue(1, ok1, bad2))
		if got := find(f, o, RuleGlue).Expected; got != l2 {
			t.Fatalf("expected %q, want %q", got, l2)
		}
		run(f, both, o, nil)
	})
	t.Run("the other server fails: no update", func(t *testing.T) {
		run(f, both, observe(regGlue(0, bad1, ok2), regDown(1)), nil)
	})
	t.Run("the part comes back: no update", func(t *testing.T) {
		run(f, both, two, nil)
	})
	t.Run("one part fewer because a server is right again: no update", func(t *testing.T) {
		run(f, both, observe(regGlue(0, bad1, ok2), regGlue(1, ok1, ok2)), nil)
	})
	t.Run("the alert holds the parts in the old order: no update", func(t *testing.T) {
		run(f, regWith(both, func(g *Finding) { g.Expected = l2 + "; " + l1 }), two, nil)
	})
	t.Run("a part that the alert does not hold: update", func(t *testing.T) {
		run(f, regWith(both, func(g *Finding) { g.Expected = l1 }), two, []Change{change(OpUpdate, both)})
	})
	t.Run("the alert holds only a prefix of the part: update", func(t *testing.T) {
		run(f, regWith(both, func(g *Finding) { g.Expected = "ns1.corp.test. A 10.53.0.1; " + l2 }), two, []Change{change(OpUpdate, both)})
	})
	t.Run("a part is gone and another is new: update", func(t *testing.T) {
		o := observe(regGlue(0, bad1, ok2))
		run(f, regWith(both, func(g *Finding) { g.Expected = l2 }), o, []Change{change(OpUpdate, find(f, o, RuleGlue))})
	})
	t.Run("the same parts and a value at one more server: no update", func(t *testing.T) {
		o := observe(regGlue(0, bad1, ok2), regGlue(1, ok1, bad2), regGlue(2, bad1, ok2))
		if more := find(f, o, RuleGlue); more.Expected != both.Expected || strings.Count(more.Value, "\n") != 2 {
			t.Fatalf("expected %q, value %q; want %q and three lines", more.Expected, more.Value, both.Expected)
		}
		run(f, both, o, nil)
	})
	t.Run("a part gone and a value at one more server: no update", func(t *testing.T) {
		run(f, both, observe(regDown(0), regGlue(1, ok1, bad2), regGlue(2, ok1, bad2)), nil)
	})
	t.Run("the same parts and a new value: update", func(t *testing.T) {
		o := observe(regGlue(0, bad1, ok2), regGlue(1, ok1, bad2), regGlue(2, "ns1.corp.test.=10.53.0.97", ok2))
		more := find(f, o, RuleGlue)
		if more.Expected != both.Expected {
			t.Fatalf("expected %q, want %q", more.Expected, both.Expected)
		}
		run(f, both, o, []Change{change(OpUpdate, more)})
	})
	t.Run("another severity: update", func(t *testing.T) {
		run(f, regWith(both, func(g *Finding) { g.Severity = SeverityHigh }), two, []Change{change(OpUpdate, both)})
	})
	t.Run("a severity that is the same and the same parts: no update", func(t *testing.T) {
		run(f, regWith(both, func(g *Finding) { g.Severity = SeverityCritical }), two, nil)
	})
}

// For every rule but glue, another Expected is news, also when the new text is
// a part of the old one.
func TestOtherRulesHearAnotherExpectedAsNews(t *testing.T) {
	now := decT0.Add(time.Minute)
	corp := decName(t, "corp.test.")
	nsFile := regFileNS(t, "corp.test. NS ns1.dnshost.test.")
	dsFile := decFile(t, "domain corp.test.", regNSLine, "corp.test. DS "+decDS)
	recFile := regFile(t, "www.corp.test. A 10.53.0.81")
	records := decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99")))
	for _, c := range []struct {
		name string
		f    *expect.File
		o    obs.Observation
		rule Rule
	}{
		{"nameservers", nsFile, regObserve(t, obs.KindDelegation, "corp.test.", regBuild(t, []regAns{regGlue(0)})), RuleNameServers},
		{"ds", dsFile, regObserve(t, obs.KindDS, "corp.test.", regBuild(t, []regAns{{srv: 0, kind: "ds", data: []string{regDS2}}})), RuleDS},
		{"record-set", recFile, records, RuleRecordSet},
	} {
		t.Run(c.name, func(t *testing.T) {
			var cur Finding
			for _, g := range Findings(c.f, c.o) {
				if g.Rule == c.rule {
					cur = g
				}
			}
			if cur.Rule != c.rule || cur.Expected == "" {
				t.Fatalf("no %v finding with an expected text in:%s", c.rule, decShow(Findings(c.f, c.o)))
			}
			// Same severity and Value, so the text of Expected is the only news.
			old := regWith(cur, func(g *Finding) { g.Expected += "; another part" })
			got := Decide(Input{Expect: c.f, Open: []Finding{old}, Observation: c.o, Now: now})
			regChanges(t, got, []Change{{Op: OpUpdate, Finding: cur, At: now}})
		})
	}
}
