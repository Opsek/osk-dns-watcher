package decide

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
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

var decT0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

const (
	decNS1 = "10.53.0.11:53"
	decNS2 = "10.53.0.12:53"
	decDS  = "12345 13 2 3F1B0C6E9A2D4F5E6A7B8C9D0E1F2A3B4C5D6E7F8091A2B3C4D5E6F708192A3B"
)

func decName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// decFile parses an expectations file made of lines, so the tests need no
// knowledge of how the package expect stores a file.
func decFile(t testing.TB, lines ...string) *expect.File {
	t.Helper()
	text := strings.Join(lines, "\n") + "\n"
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return f
}

func decRR(t testing.TB, owner string, typ dnswire.Type, data string) dnswire.Record {
	t.Helper()
	d, err := dnswire.ParseRData(typ, data)
	if err != nil {
		t.Fatalf("ParseRData(%v, %q): %v", typ, data, err)
	}
	return dnswire.Record{Name: decName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: d}
}

func decCase(r obs.Result) string {
	return obs.Match(r,
		func(obs.Records) string { return "records" },
		func(obs.NoData) string { return "nodata" },
		func(obs.NoName) string { return "noname" },
		func(f obs.Failure) string { return "failure " + f.Reason.String() })
}

// decAs fails the test when a constructor of obs turned r into another case
// than meant, so that no test of "no data" quietly tests a failure.
func decAs(t testing.TB, r obs.Result, want string) obs.Result {
	t.Helper()
	if got := decCase(r); got != want {
		t.Fatalf("built a %s result, want %s", got, want)
	}
	return r
}

// decSet is an answer of records, one for each datum.
func decSet(t testing.TB, owner string, typ dnswire.Type, data ...string) obs.Result {
	t.Helper()
	var set []dnswire.Record
	for _, d := range data {
		set = append(set, decRR(t, owner, typ, d))
	}
	return decAs(t, obs.RecordsResult(obs.Records{Set: set}), "records")
}

func decSOA(t testing.TB, zone string) dnswire.Record {
	t.Helper()
	return decRR(t, zone, dnswire.TypeSOA, "ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")
}

func decNoData(t testing.TB, zone string) obs.Result {
	t.Helper()
	return decAs(t, obs.NoDataResult(obs.NoData{SOA: decSOA(t, zone)}), "nodata")
}

func decNoName(t testing.TB, zone string) obs.Result {
	t.Helper()
	return decAs(t, obs.NoNameResult(obs.NoName{SOA: decSOA(t, zone)}), "noname")
}

func decFailure(reason obs.Reason) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: reason, Detail: "a reason for people"})
}

// decAnswer is the answer of host at addr; an empty addr is a host for which
// no address was found.
func decAnswer(t testing.TB, host, addr string, r obs.Result) obs.Answer {
	t.Helper()
	a := obs.Answer{Result: r}
	a.Server.Name = decName(t, host)
	if addr != "" {
		a.Server.Addr = netip.MustParseAddrPort(addr)
	}
	a.Sent = decT0.Add(time.Second)
	a.Received = decT0.Add(2 * time.Second)
	a.Wire = []byte{0x12, 0x34}
	return a
}

// decFailedWalk is the one answer of a check whose walk from the root failed.
func decFailedWalk() obs.Answer {
	return obs.Answer{Result: decFailure(obs.ReasonWalk)}
}

func decRecordsKey(t testing.TB, domain, name string, typ dnswire.Type) obs.Key {
	t.Helper()
	return obs.RecordsKey(decName(t, domain), decName(t, name), typ)
}

func decObservation(key obs.Key, zone dnswire.Name, walk []obs.Answer, answers ...obs.Answer) obs.Observation {
	return obs.Observation{Key: key, Start: decT0, Deadline: decT0.Add(45 * time.Second), Zone: zone, Walk: walk, Answers: answers}
}

func decShow(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "\n  %v %v %v expected %q seen %d value %q", f.Rule, f.Severity, f.Check, f.Expected, len(f.Seen), f.Value)
	}
	return b.String()
}

func decShowChanges(cs []Change) string {
	var b strings.Builder
	for _, c := range cs {
		fmt.Fprintf(&b, "\n  %v at %v:%s", c.Op, c.At, decShow([]Finding{c.Finding}))
	}
	return b.String()
}

// decWant is what a test states of one finding. Its Check is the key of the
// observation, its Value one line for each Seen.
type decWant struct {
	rule     Rule
	severity Severity
	expected string
	seen     []Seen
}

// decCheck compares findings with want. The exact form of a Value line is
// stated by TestValueIsOneLinePerSeen alone; here a line need only name the
// address and end with the Text, so one mistake there fails one test.
func decCheck(t *testing.T, got []Finding, key obs.Key, want ...decWant) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("got %d findings, want %d:%s", len(got), len(want), decShow(got))
	}
	for i, w := range want {
		g := got[i]
		if g.Rule != w.rule || g.Severity != w.severity || g.Expected != w.expected {
			t.Errorf("finding %d is %v %v expected %q, want %v %v expected %q", i, g.Rule, g.Severity, g.Expected, w.rule, w.severity, w.expected)
		}
		if g.Check.String() != key.String() {
			t.Errorf("finding %d has check %v, want %v", i, g.Check, key)
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
		if len(w.seen) == 0 {
			if g.Value != "" {
				t.Errorf("finding %d %v has value %q with nothing seen", i, g.Rule, g.Value)
			}
			continue
		}
		lines := strings.Split(g.Value, "\n")
		if len(lines) != len(w.seen) {
			t.Errorf("finding %d %v has value %q, want %d lines", i, g.Rule, g.Value, len(w.seen))
			continue
		}
		for j, s := range w.seen {
			if !strings.HasSuffix(lines[j], " "+s.Text) || !strings.Contains(lines[j], s.Answer.Server.Addr.Addr().String()) {
				t.Errorf("finding %d %v, value line %q does not show %v and %q", i, g.Rule, lines[j], s.Answer.Server.Addr, s.Text)
			}
		}
	}
}

func decFormText(t *testing.T, f *expect.File, name string, typ dnswire.Type) string {
	t.Helper()
	e, ok := f.Find(decName(t, name), typ)
	if !ok {
		t.Fatalf("the file has no line %s %v", name, typ)
	}
	return e.FormText()
}

func decSameChanges(t *testing.T, got, want []Change) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("changes:\n got %s\n want %s", decShowChanges(got), decShowChanges(want))
	}
}

func TestRuleSeverityAndOpWords(t *testing.T) {
	for _, c := range []struct{ got, want string }{
		{Rule(1).String(), "invalid-file"},
		{Rule(2).String(), "not-covered"},
		{Rule(3).String(), "zone"},
		{Rule(4).String(), "nameservers"},
		{Rule(5).String(), "record-set"},
		{Rule(0).String(), "rule0"},
		{Rule(25).String(), "rule25"},
		{Severity(1).String(), "low"},
		{Severity(2).String(), "medium"},
		{Severity(3).String(), "high"},
		{Severity(4).String(), "critical"},
		{Severity(0).String(), "severity0"},
		{Severity(5).String(), "severity5"},
		{Op(1).String(), "open"},
		{Op(2).String(), "update"},
		{Op(3).String(), "resolve"},
		{Op(0).String(), "op0"},
		{Op(4).String(), "op4"},
	} {
		if c.got != c.want {
			t.Errorf("got %q, want %q", c.got, c.want)
		}
	}
	if !slices.Equal([]Rule{RuleInvalidFile, RuleNotCovered, RuleZone, RuleNameServers, RuleRecordSet}, []Rule{1, 2, 3, 4, 5}) ||
		!slices.Equal([]Severity{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}, []Severity{1, 2, 3, 4}) ||
		!slices.Equal([]Op{OpOpen, OpUpdate, OpResolve}, []Op{1, 2, 3}) {
		t.Error("a constant has another value than its word")
	}
}

func TestNoLineGivesNotCoveredAndGoneOnNoSuchName(t *testing.T) {
	corp, test := decName(t, "corp.test."), decName(t, "test.")
	files := []struct {
		name string
		f    *expect.File
		gone bool // the file covers the domain, so a no such name is also gone
	}{
		{"no line", decFile(t, "domain corp.test.", "mail.corp.test. A 10.53.0.82"), true},
		{"no file", nil, false},
		// The lines are for the right names, but the check belongs to another domain.
		{"file of another domain", decFile(t, "domain shop.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.81"), false},
	}
	delegation := decObservation(obs.DelegationKey(corp), test, nil,
		decAnswer(t, "a.ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")),
		decAnswer(t, "b.ns.test.", "10.53.0.4:53", decFailure(obs.ReasonTimeout)),
		decAnswer(t, "c.ns.test.", "10.53.0.5:53", decNoName(t, "test.")))
	ds := decObservation(obs.DSKey(corp), test, nil,
		decAnswer(t, "a.ns.test.", "10.53.0.3:53", decNoData(t, "test.")),
		decAnswer(t, "b.ns.test.", "10.53.0.4:53", decFailure(obs.ReasonDeadline)))
	www := decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonRefused)))
	checks := []struct {
		o    obs.Observation
		seen []Seen
	}{
		{delegation, []Seen{{delegation.Answers[0], "ns1.corp.test. | ns2.corp.test."}, {delegation.Answers[2], "none"}}},
		{ds, []Seen{{ds.Answers[0], "none"}}},
		{www, []Seen{{www.Answers[0], "10.53.0.81"}}},
	}
	for _, file := range files {
		for _, c := range checks {
			t.Run(file.name+"/"+c.o.Key.Kind.String(), func(t *testing.T) {
				want := []decWant{{RuleNotCovered, SeverityMedium, "", c.seen}}
				if file.gone && c.o.Key.Kind == obs.KindDelegation {
					want = append(want, decWant{RuleGone, SeverityCritical, "", []Seen{{c.o.Answers[2], "no such name"}}})
				}
				decCheck(t, Findings(file.f, c.o), c.o.Key, want...)
			})
		}
	}
}

// A check with no line is never compared, whatever its answers: a set whose
// servers all fail is still not covered, with nothing seen.
func TestNotCoveredWhenEveryAnswerFails(t *testing.T) {
	f := decFile(t, "domain corp.test.", "mail.corp.test. A 10.53.0.82")
	o := decObservation(decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), decName(t, "corp.test."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonTimeout)),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonDeadline)))
	decCheck(t, Findings(f, o), o.Key, decWant{RuleNotCovered, SeverityMedium, "", nil})
}

func TestFindsLineIgnoringCase(t *testing.T) {
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.81")
	www := decObservation(decRecordsKey(t, "CORP.Test.", "WWW.Corp.TEST.", dnswire.TypeA), decName(t, "Corp.TEST."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "Www.Corp.Test.", dnswire.TypeA, "10.53.0.81")))
	decCheck(t, Findings(f, www), www.Key)
	del := decObservation(obs.DelegationKey(decName(t, "CORP.TEST.")), decName(t, "test."), nil,
		decAnswer(t, "a.ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "NS1.corp.test.", "ns2.CORP.test.")))
	decCheck(t, Findings(f, del), del.Key)
}

func TestDelegationNameServers(t *testing.T) {
	corp, test := decName(t, "corp.test."), decName(t, "test.")
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.")
	expected := decFormText(t, f, "corp.test.", dnswire.TypeNS)
	// The glue is wrong on purpose: it is not part of the set.
	same := decAnswer(t, "a.ns.test.", "10.53.0.3:53", decAs(t, obs.RecordsResult(obs.Records{
		Set:  []dnswire.Record{decRR(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test."), decRR(t, "corp.test.", dnswire.TypeNS, "ns2.corp.test.")},
		Glue: []dnswire.Record{decRR(t, "ns1.corp.test.", dnswire.TypeA, "10.53.0.99")},
	}), "records"))
	other := decAnswer(t, "b.ns.test.", "10.53.0.4:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.dnshost.test.", "ns2.dnshost.test."))
	failed := decAnswer(t, "c.ns.test.", "10.53.0.5:53", decFailure(obs.ReasonTimeout))
	noName := decAnswer(t, "d.ns.test.", "10.53.0.6:53", decNoName(t, "test."))
	noData := decAnswer(t, "e.ns.test.", "10.53.0.7:53", decNoData(t, "test."))
	key := obs.DelegationKey(corp)

	t.Run("glue is not compared", func(t *testing.T) {
		decCheck(t, Findings(f, decObservation(key, test, nil, same)), key)
	})
	t.Run("a failure is no difference", func(t *testing.T) {
		decCheck(t, Findings(f, decObservation(key, test, nil, same, failed)), key)
	})
	t.Run("each server that differs is seen in order", func(t *testing.T) {
		o := decObservation(key, test, nil, same, other, failed, noName)
		decCheck(t, Findings(f, o), key, decWant{RuleNameServers, SeverityCritical, expected,
			[]Seen{{other, "ns1.dnshost.test. | ns2.dnshost.test."}, {noName, "none"}}},
			decWant{RuleGone, SeverityCritical, "", []Seen{{noName, "no such name"}}})
	})
	t.Run("no data and no such name are an empty set", func(t *testing.T) {
		o := decObservation(key, test, nil, noName, noData)
		gone := decWant{RuleGone, SeverityCritical, "", []Seen{{noName, "no such name"}}}
		decCheck(t, Findings(f, o), key, decWant{RuleNameServers, SeverityCritical, expected,
			[]Seen{{noName, "none"}, {noData, "none"}}}, gone)
		none := decFile(t, "domain corp.test.", "corp.test. NS none")
		decCheck(t, Findings(none, o), key, gone)
	})
}

func TestSerialAndOtherKindsGiveNothing(t *testing.T) {
	corp, www := decName(t, "corp.test."), decName(t, "www.corp.test.")
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.81")
	answer := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99"))
	for _, key := range []obs.Key{
		obs.SerialKey(corp),
		{Kind: 0, Domain: corp, Name: www, Type: dnswire.TypeA},
		obs.CertificatesKey(corp),
		{Kind: 7, Domain: corp, Name: www, Type: dnswire.TypeA},
	} {
		// A zone that is not the expected one, so that no rule has a reason to look.
		o := decObservation(key, www, nil, answer)
		for _, file := range []*expect.File{f, nil} {
			if got := Findings(file, o); len(got) != 0 {
				t.Errorf("%v with file %v: %s", key, file != nil, decShow(got))
			}
		}
	}
}

func TestRecordSetSeenInAnswersOrder(t *testing.T) {
	corp := decName(t, "corp.test.")
	f := decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	a1 := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99"))
	a2 := decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))
	a3 := decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decNoName(t, "corp.test."))
	a4 := decAnswer(t, "ns4.corp.test.", "10.53.0.14:53", decFailure(obs.ReasonServFail))
	a5 := decAnswer(t, "ns5.corp.test.", "10.53.0.15:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99", "10.53.0.81"))
	a6 := decAnswer(t, "ns6.corp.test.", "10.53.0.16:53", decNoData(t, "corp.test."))
	o := decObservation(key, corp, nil, a1, a2, a3, a4, a5, a6)
	decCheck(t, Findings(f, o), key, decWant{RuleRecordSet, SeverityHigh, decFormText(t, f, "www.corp.test.", dnswire.TypeA),
		[]Seen{{a1, "10.53.0.99"}, {a3, "none"}, {a5, "10.53.0.81 | 10.53.0.99"}, {a6, "none"}}})
}

func TestValueIsOneLinePerSeen(t *testing.T) {
	f := decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	o := decObservation(key, decName(t, "corp.test."), nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.99")),
		decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.98")))
	got := Findings(f, o)
	want := "10.53.0.11:53 ns1.corp.test. 10.53.0.99\n10.53.0.12:53 ns2.corp.test. 10.53.0.98"
	if len(got) != 1 || got[0].Value != want {
		t.Errorf("got %s\nwant one finding with value %q", decShow(got), want)
	}
}

func TestRecordsThatMatchGiveNothing(t *testing.T) {
	corp := decName(t, "corp.test.")
	f := decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81 | 10.53.0.82", "nx.corp.test. A none")
	www := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	o := decObservation(www, corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.82", "10.53.0.81")),
		decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "WWW.corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.82", "10.53.0.81")),
		decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonTimeout)))
	decCheck(t, Findings(f, o), www)
	nx := decRecordsKey(t, "corp.test.", "nx.corp.test.", dnswire.TypeA)
	o = decObservation(nx, corp, nil,
		decAnswer(t, "ns1.corp.test.", decNS1, decNoName(t, "corp.test.")),
		decAnswer(t, "ns2.corp.test.", decNS2, decNoData(t, "corp.test.")),
		decAnswer(t, "ns3.corp.test.", "10.53.0.13:53", decFailure(obs.ReasonDeadline)))
	decCheck(t, Findings(f, o), nx)
}

func TestRecordSetSeverityFollowsKeyType(t *testing.T) {
	corp := decName(t, "corp.test.")
	for _, c := range []struct {
		key, seen dnswire.Type
		data      string
		want      Severity
	}{
		{dnswire.TypeA, dnswire.TypeA, "10.53.0.99", SeverityHigh},
		{dnswire.TypeAAAA, dnswire.TypeAAAA, "fd53::99", SeverityHigh},
		{dnswire.TypeCNAME, dnswire.TypeCNAME, "edge.dnshost.test.", SeverityHigh},
		{dnswire.TypeMX, dnswire.TypeMX, "10 mail.dnshost.test.", SeverityHigh},
		{dnswire.TypeNS, dnswire.TypeNS, "ns.dnshost.test.", SeverityHigh},
		{dnswire.TypeTXT, dnswire.TypeTXT, `"v=spf1 +all"`, SeverityMedium},
		{dnswire.TypeCAA, dnswire.TypeCAA, `0 issue "evil.test"`, SeverityMedium},
		{dnswire.TypePTR, dnswire.TypePTR, "host.dnshost.test.", SeverityMedium},
		{dnswire.TypeDNAME, dnswire.TypeDNAME, "dnshost.test.", SeverityMedium},
		{dnswire.TypeSOA, dnswire.TypeSOA, "ns1.corp.test. hostmaster.corp.test. 2 3600 600 604800 300", SeverityMedium},
		// The severity is the one of the set that was asked for, not of the record that came back.
		{dnswire.TypeTXT, dnswire.TypeCNAME, "edge.dnshost.test.", SeverityMedium},
		{dnswire.TypeA, dnswire.TypeCNAME, "edge.dnshost.test.", SeverityHigh},
	} {
		t.Run(c.key.String()+"/"+c.seen.String(), func(t *testing.T) {
			f := decFile(t, "domain corp.test.", "x.corp.test. "+c.key.String()+" none")
			key := decRecordsKey(t, "corp.test.", "x.corp.test.", c.key)
			answer := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "x.corp.test.", c.seen, c.data))
			o := decObservation(key, corp, nil, answer)
			text := expect.SetText(c.key, []dnswire.Record{decRR(t, "x.corp.test.", c.seen, c.data)})
			decCheck(t, Findings(f, o), key, decWant{RuleRecordSet, c.want, "none", []Seen{{answer, text}}})
		})
	}
}

// decCut is the walk of a check whose name was handed to an invented zone:
// the root and the parent refer down as usual, then a server of corp.test.
// refers www.corp.test. to a server of its own choice.
func decCut(t *testing.T) (walk []obs.Answer, cut obs.Answer) {
	cut = decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.CORP.test.", dnswire.TypeNS, "ns.evil.test."))
	// A cached referral: sent before the check started, or not sent at all.
	cut.Sent = time.Time{}
	cut.Received = decT0.Add(-time.Hour)
	return []obs.Answer{
		decAnswer(t, ".", "10.53.0.2:53", decSet(t, "test.", dnswire.TypeNS, "ns.test.")),
		decAnswer(t, "ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")),
		cut,
	}, cut
}

func TestZoneInventedCutWhoseAnswersMatch(t *testing.T) {
	f := decFile(t, "domain Corp.Test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.81")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	walk, cut := decCut(t)
	evil := decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))

	t.Run("the referral into the zone is seen", func(t *testing.T) {
		o := decObservation(key, decName(t, "WWW.Corp.Test."), walk, evil)
		decCheck(t, Findings(f, o), key, decWant{RuleZone, SeverityHigh, "corp.test.", []Seen{{cut, "www.corp.test."}}})
	})
	t.Run("every referral into the zone, in walk order", func(t *testing.T) {
		failed := decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonTimeout))
		cut2 := decAnswer(t, "ns2.corp.test.", decNS2, decSet(t, "www.corp.test.", dnswire.TypeNS, "ns.evil.test."))
		// An address record owned by the zone is no referral.
		address := decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.66"))
		o := decObservation(key, decName(t, "www.corp.test."), append(slices.Clone(walk), failed, cut2, address), evil)
		decCheck(t, Findings(f, o), key, decWant{RuleZone, SeverityHigh, "corp.test.",
			[]Seen{{cut, "www.corp.test."}, {cut2, "www.corp.test."}}})
	})
	t.Run("with no referral into the zone the answers are seen", func(t *testing.T) {
		failed := decAnswer(t, "ns.evil.test.", "10.53.0.67:53", decFailure(obs.ReasonNetwork))
		evil2 := decAnswer(t, "ns.evil.test.", "10.53.0.68:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))
		o := decObservation(key, decName(t, "www.corp.test."), walk[:2], evil, failed, evil2)
		decCheck(t, Findings(f, o), key, decWant{RuleZone, SeverityHigh, "corp.test.",
			[]Seen{{evil, "www.corp.test."}, {evil2, "www.corp.test."}}})
	})
}

func TestZoneThenRecordSet(t *testing.T) {
	f := decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	walk, cut := decCut(t)
	evil := decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.66"))
	o := decObservation(key, decName(t, "www.corp.test."), walk, evil)
	decCheck(t, Findings(f, o), key,
		decWant{RuleZone, SeverityHigh, "corp.test.", []Seen{{cut, "www.corp.test."}}},
		decWant{RuleRecordSet, SeverityHigh, "10.53.0.81", []Seen{{evil, "10.53.0.66"}}})
}

// Both rules hold for a name with no line under an invented cut, in Rule
// order: not-covered before zone.
func TestZoneAndNotCoveredForNameWithoutLine(t *testing.T) {
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	walk, cut := decCut(t)
	evil := decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.66"))
	decCheck(t, Findings(f, decObservation(key, decName(t, "www.corp.test."), walk, evil)), key,
		decWant{RuleNotCovered, SeverityMedium, "", []Seen{{evil, "10.53.0.66"}}},
		decWant{RuleZone, SeverityHigh, "corp.test.", []Seen{{cut, "www.corp.test."}}})
}

func TestZoneDeclaredByNSLines(t *testing.T) {
	f := decFile(t, "domain corp.test.",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"a.corp.test. NS ns.a.corp.test.",
		"b.a.corp.test. NS like *.dnshost.test.",
		"c.corp.test. NS none",
		"a.corp.test. A 10.53.0.81",
		"www.a.corp.test. A 10.53.0.81",
		"x.b.a.corp.test. A 10.53.0.81",
		"www.c.corp.test. A 10.53.0.81",
		"mail.corp.test. A 10.53.0.81")
	for _, c := range []struct {
		name, zone string
		want       string // the expected zone when the rule holds
	}{
		{"www.a.corp.test.", "a.corp.test.", ""},
		{"www.a.corp.test.", "corp.test.", "a.corp.test."},
		{"x.b.a.corp.test.", "b.a.corp.test.", ""},
		{"x.b.a.corp.test.", "a.corp.test.", "b.a.corp.test."},
		{"x.b.a.corp.test.", "corp.test.", "b.a.corp.test."},
		{"a.corp.test.", "a.corp.test.", ""},
		{"a.corp.test.", "corp.test.", "a.corp.test."},
		// An NS line with none declares no zone.
		{"www.c.corp.test.", "corp.test.", ""},
		{"www.c.corp.test.", "c.corp.test.", "corp.test."},
		{"mail.corp.test.", "corp.test.", ""},
		{"mail.corp.test.", "a.corp.test.", "corp.test."},
	} {
		t.Run(c.name+" in "+c.zone, func(t *testing.T) {
			key := decRecordsKey(t, "corp.test.", c.name, dnswire.TypeA)
			answer := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, c.name, dnswire.TypeA, "10.53.0.81"))
			o := decObservation(key, decName(t, c.zone), nil, answer)
			if c.want == "" {
				decCheck(t, Findings(f, o), key)
				return
			}
			decCheck(t, Findings(f, o), key, decWant{RuleZone, SeverityHigh, c.want, []Seen{{answer, c.zone}}})
		})
	}
}

func TestZoneRuleOnlyForRecordsInTheDomain(t *testing.T) {
	corp, test := decName(t, "corp.test."), decName(t, "test.")
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none",
		"www.corp.test. A 10.53.0.81", "edge.dnshost.test. A 10.53.0.83")
	tld := decAnswer(t, "ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test."))

	t.Run("delegation", func(t *testing.T) {
		// The parent zone is never the zone of the domain.
		key := obs.DelegationKey(corp)
		decCheck(t, Findings(f, decObservation(key, test, nil, tld)), key)
	})
	t.Run("ds", func(t *testing.T) {
		key := obs.DSKey(corp)
		decCheck(t, Findings(f, decObservation(key, test, nil, decAnswer(t, "ns.test.", "10.53.0.3:53", decNoData(t, "test.")))), key)
	})
	t.Run("name outside the domain", func(t *testing.T) {
		key := decRecordsKey(t, "corp.test.", "edge.dnshost.test.", dnswire.TypeA)
		answer := decAnswer(t, "ns1.dnshost.test.", decNS1, decSet(t, "edge.dnshost.test.", dnswire.TypeA, "10.53.0.83"))
		decCheck(t, Findings(f, decObservation(key, decName(t, "dnshost.test."), nil, answer)), key)
	})
	walk, _ := decCut(t)
	evil := decAnswer(t, "ns.evil.test.", "10.53.0.66:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))
	t.Run("check of another domain", func(t *testing.T) {
		key := decRecordsKey(t, "shop.test.", "www.corp.test.", dnswire.TypeA)
		o := decObservation(key, decName(t, "www.corp.test."), walk, evil)
		decCheck(t, Findings(f, o), key, decWant{RuleNotCovered, SeverityMedium, "", []Seen{{evil, "10.53.0.81"}}})
	})
	t.Run("no file", func(t *testing.T) {
		key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
		o := decObservation(key, decName(t, "www.corp.test."), walk, evil)
		decCheck(t, Findings(nil, o), key, decWant{RuleNotCovered, SeverityMedium, "", []Seen{{evil, "10.53.0.81"}}})
	})
}

// decOutage is a run of the check of www.corp.test. A in which no query got
// an answer: the walk could not leave the root, so the fan-out asked the
// root servers, and each address gave its own failure.
func decOutage(t *testing.T, key obs.Key) obs.Observation {
	v4 := decAnswer(t, ".", "10.53.0.2:53", decFailure(obs.ReasonNetwork))
	v6 := decAnswer(t, ".", "[fd53::2]:53", decFailure(obs.ReasonNoRoute))
	return decObservation(key, dnswire.Name{}, []obs.Answer{v4, v6}, v4, v6)
}

// A run with no usable answer gives a zone finding only on a referral, from
// servers that answered, into a zone below the expected one: a cut that the
// file does not declare. In an outage of this machine the walk stops at a
// cut learned earlier, above the expected zone or at the root, with no such
// referral, and its Zone tells nothing.
func TestZoneRuleOfARunWithNoUsableAnswer(t *testing.T) {
	f := decFile(t, "domain corp.test.", "lab.corp.test. NS ns.lab.corp.test.",
		"www.corp.test. A 10.53.0.81", "www.lab.corp.test. A 10.53.0.82")
	key := decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
	labKey := decRecordsKey(t, "corp.test.", "www.lab.corp.test.", dnswire.TypeA)
	corp, www := decName(t, "corp.test."), decName(t, "www.corp.test.")
	// walk ends with a referral that a server of corp.test. gave in an
	// earlier run: the walk of this run started from the cut it learned.
	walk, cached := decCut(t)
	live := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeNS, "ns.evil.test."))
	liveWalk := append(slices.Clone(walk[:2]), live)
	evil := func(addr string, r obs.Result) obs.Answer { return decAnswer(t, "ns.evil.test.", addr, r) }
	corpFails := []obs.Answer{decAnswer(t, "ns1.corp.test.", decNS1, decFailure(obs.ReasonNetwork)),
		decAnswer(t, "ns2.corp.test.", decNS2, decFailure(obs.ReasonNetwork))}
	labReferral := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "lab.corp.test.", dnswire.TypeNS, "ns.lab.corp.test."))
	zoneOf := func(seen ...obs.Answer) []decWant {
		var s []Seen
		for _, a := range seen {
			s = append(s, Seen{a, "www.corp.test."})
		}
		return []decWant{{RuleZone, SeverityHigh, "corp.test.", s}}
	}

	for _, c := range []struct {
		name string
		key  obs.Key
		o    obs.Observation
		want []decWant
	}{
		{"failed walk", key, decObservation(key, dnswire.Name{}, walk[:1], decFailedWalk()), nil},
		{"outage: the walk ends at the root", key, decOutage(t, key), nil},
		{"outage: the walk ends at the cut of the domain, learned earlier", key,
			decObservation(key, corp, walk[1:2], corpFails...), nil},
		{"the root answers and the servers of the parent zone fail", key,
			decObservation(key, decName(t, "test."), walk[:1], decAnswer(t, "ns.test.", "10.53.0.3:53", decFailure(obs.ReasonTimeout))), nil},
		{"the servers of the domain fail above a declared subzone", labKey,
			decObservation(labKey, corp, walk[:2], corpFails...), nil},
		{"a zone below the expected one, but no referral into it", key,
			decObservation(key, www, walk[:2], evil("10.53.0.66:53", decFailure(obs.ReasonTimeout))), nil},
		{"a referral of this run, its server times out", key,
			decObservation(key, www, liveWalk, evil("10.53.0.66:53", decFailure(obs.ReasonTimeout))), zoneOf(live)},
		{"a referral of this run, its server refuses", key,
			decObservation(key, www, liveWalk, evil("10.53.0.66:53", decFailure(obs.ReasonRefused))), zoneOf(live)},
		{"a referral of this run, its address may not be asked", key,
			decObservation(key, www, liveWalk, evil("192.0.2.66:53", decFailure(obs.ReasonNotPermitted))), zoneOf(live)},
		{"a referral of this run, its host has no address", key,
			decObservation(key, www, liveWalk, evil("", decFailure(obs.ReasonWalk))), zoneOf(live)},
		{"a referral learned in an earlier run, its servers fail", key,
			decObservation(key, www, walk, evil("10.53.0.66:53", decFailure(obs.ReasonTimeout)),
				evil("10.53.0.67:53", decFailure(obs.ReasonNetwork))), zoneOf(cached)},
		{"a server of the zone answers", key,
			decObservation(key, www, walk, evil("10.53.0.66:53", decFailure(obs.ReasonTimeout)),
				evil("10.53.0.67:53", decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))), zoneOf(cached)},
		{"the servers of a declared subzone fail", labKey,
			decObservation(labKey, decName(t, "lab.corp.test."), append(slices.Clone(walk[:2]), labReferral),
				decAnswer(t, "ns.lab.corp.test.", "10.53.0.70:53", decFailure(obs.ReasonTimeout))), nil},
	} {
		t.Run(c.name, func(t *testing.T) { decCheck(t, Findings(f, c.o), c.key, c.want...) })
	}
}

// An outage neither opens a zone alert nor ends one: the alert ends when a
// server of the expected zone answers again.
func TestDecideOutageKeepsTheZoneAlertAsItIs(t *testing.T) {
	d := decNewDecide(t)
	walk, _ := decCut(t)
	open := d.one(d.f, decObservation(d.key, decName(t, "www.corp.test."), walk, d.at("ns.evil.test.", "10.53.0.66:53", "10.53.0.81")))
	if open.Rule != RuleZone {
		t.Fatalf("want a zone finding:%s", decShow([]Finding{open}))
	}
	outage := decOutage(t, d.key)
	decSameChanges(t, d.decide(nil, outage), nil)
	decSameChanges(t, d.decide([]Finding{open}, outage), nil)
	back := d.observe(d.at("ns1.corp.test.", decNS1, "10.53.0.81"), d.at("ns2.corp.test.", decNS2, "10.53.0.81"))
	decSameChanges(t, d.decide([]Finding{open}, back), []Change{d.change(OpResolve, open)})
}

// A subzone that the file does not declare, whose servers fail: the first run
// that holds the referral opens the alert, a run that starts from the cut it
// learned keeps the alert as it is, and an outage neither adds to it nor ends
// it.
func TestDecideZoneAlertOfASubzoneThatFails(t *testing.T) {
	d := decNewDecide(t)
	www := decName(t, "www.corp.test.")
	walk, _ := decCut(t)
	live := decAnswer(t, "ns1.corp.test.", decNS1, decSet(t, "www.corp.test.", dnswire.TypeNS, "ns.evil.test."))
	first := decObservation(d.key, www, append(slices.Clone(walk[:2]), live), d.failed("ns.evil.test.", "10.53.0.66:53", obs.ReasonTimeout))
	opened := d.one(d.f, first)
	if opened.Rule != RuleZone {
		t.Fatalf("want a zone finding:%s", decShow([]Finding{opened}))
	}
	decSameChanges(t, d.decide(nil, first), []Change{d.change(OpOpen, opened)})
	fromCut := decObservation(d.key, www, walk, d.failed("ns.evil.test.", "10.53.0.66:53", obs.ReasonTimeout))
	decSameChanges(t, d.decide([]Finding{opened}, fromCut), nil)
	decSameChanges(t, d.decide([]Finding{opened}, decOutage(t, d.key)), nil)
}

func TestZoneDomainDirectlyUnderRoot(t *testing.T) {
	f := decFile(t, "domain example.", "www.example. A 10.53.0.81")
	key := decRecordsKey(t, "example.", "www.example.", dnswire.TypeA)
	answer := decAnswer(t, "ns1.example.", decNS1, decSet(t, "www.example.", dnswire.TypeA, "10.53.0.81"))
	decCheck(t, Findings(f, decObservation(key, decName(t, "example."), nil, answer)), key)
	decCheck(t, Findings(f, decObservation(key, decName(t, "www.example."), nil, answer)), key,
		decWant{RuleZone, SeverityHigh, "example.", []Seen{{answer, "www.example."}}})
	// The root as the zone of a walk that did not fail: a root server
	// answered for the name itself.
	root := decAnswer(t, ".", "10.53.0.2:53", decSet(t, "www.example.", dnswire.TypeA, "10.53.0.81"))
	decCheck(t, Findings(f, decObservation(key, dnswire.Name{}, nil, root)), key,
		decWant{RuleZone, SeverityHigh, "example.", []Seen{{root, "."}}})
}

// decDecide is the file and check that the tests of Decide share.
type decDecide struct {
	t   *testing.T
	f   *expect.File
	key obs.Key
	now time.Time
}

func decNewDecide(t *testing.T) decDecide {
	return decDecide{t: t, f: decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81"),
		key: decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA), now: decT0.Add(time.Minute)}
}

// at is an answer of www.corp.test. A: a list of addresses, or a failure.
func (d decDecide) at(host, addr string, data ...string) obs.Answer {
	d.t.Helper()
	return decAnswer(d.t, host, addr, decSet(d.t, "www.corp.test.", dnswire.TypeA, data...))
}

func (d decDecide) failed(host, addr string, reason obs.Reason) obs.Answer {
	d.t.Helper()
	return decAnswer(d.t, host, addr, decFailure(reason))
}

func (d decDecide) observe(answers ...obs.Answer) obs.Observation {
	return decObservation(d.key, decName(d.t, "corp.test."), nil, answers...)
}

// one is the single finding of the observation.
func (d decDecide) one(f *expect.File, o obs.Observation) Finding {
	d.t.Helper()
	got := Findings(f, o)
	if len(got) != 1 {
		d.t.Fatalf("want one finding:%s", decShow(got))
	}
	return got[0]
}

func (d decDecide) decide(open []Finding, o obs.Observation) []Change {
	return Decide(Input{Expect: d.f, Open: open, Observation: o, Now: d.now})
}

func (d decDecide) change(op Op, f Finding) Change {
	return Change{Op: op, Finding: f, At: d.now}
}

func TestDecideOpensEachNewFinding(t *testing.T) {
	d := decNewDecide(t)
	walk, _ := decCut(t)
	o := decObservation(d.key, decName(t, "www.corp.test."), walk, d.at("ns.evil.test.", "10.53.0.66:53", "10.53.0.66"))
	found := Findings(d.f, o)
	if len(found) != 2 {
		t.Fatalf("want two findings:%s", decShow(found))
	}
	decSameChanges(t, d.decide(nil, o), []Change{d.change(OpOpen, found[0]), d.change(OpOpen, found[1])})
}

func TestDecideUpdatesOnlyOnNewText(t *testing.T) {
	d := decNewDecide(t)
	ns1, ns2 := "ns1.corp.test.", "ns2.corp.test."
	both := d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.99"))
	now := d.one(d.f, both)

	// The same servers with the same data, seen at other times.
	earlier := d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.99"))
	for i := range earlier.Answers {
		earlier.Answers[i].Sent = time.Time{}
		earlier.Answers[i].Received = decT0.Add(-time.Hour)
	}
	same := d.one(d.f, earlier)
	onlyNS1 := d.one(d.f, d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.81")))
	nsFails := d.observe(d.failed(ns1, decNS1, obs.ReasonTimeout), d.at(ns2, decNS2, "10.53.0.99"))
	nsChanged := d.observe(d.at(ns1, decNS1, "10.53.0.98"), d.at(ns2, decNS2, "10.53.0.99"))

	with := func(f Finding, change func(*Finding)) Finding {
		change(&f)
		return f
	}
	lines := strings.Split(same.Value, "\n")
	slices.Reverse(lines)
	reordered := with(same, func(f *Finding) { f.Value = strings.Join(lines, "\n") })
	otherExpected := with(same, func(f *Finding) { f.Expected = "10.53.0.80" })
	otherSeverity := with(same, func(f *Finding) { f.Severity = SeverityMedium })
	upper := with(same, func(f *Finding) {
		f.Check = decRecordsKey(t, "CORP.TEST.", "WWW.CORP.TEST.", dnswire.TypeA)
	})
	otherCheck := with(same, func(f *Finding) { f.Check = decRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA) })

	for _, c := range []struct {
		name string
		open []Finding
		o    obs.Observation
		want []Change
	}{
		{"nothing open", nil, both, []Change{d.change(OpOpen, now)}},
		{"same text at other times", []Finding{same}, both, nil},
		{"one more server with the same value", []Finding{onlyNS1}, both, nil},
		{"other expected", []Finding{otherExpected}, both, []Change{d.change(OpUpdate, now)}},
		{"other severity", []Finding{otherSeverity}, both, []Change{d.change(OpUpdate, now)}},
		{"same lines in another order", []Finding{reordered}, both, nil},
		{"a server fails now", []Finding{same}, nsFails, nil},
		{"a server gives other data", []Finding{same}, nsChanged, []Change{d.change(OpUpdate, d.one(d.f, nsChanged))}},
		{"same check in capitals", []Finding{upper}, both, nil},
		{"same rule of another check", []Finding{otherCheck}, both, []Change{d.change(OpOpen, now)}},
		{"the first of two counts", []Finding{otherSeverity, same}, both, []Change{d.change(OpUpdate, now)}},
		{"a later duplicate is ignored", []Finding{same, otherSeverity}, both, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			decSameChanges(t, d.decide(c.open, c.o), c.want)
		})
	}
}

// The addresses of a provider take up a change one after another. One more
// server with a value that the alert shows is no news; a value that the alert
// does not show is.
func TestDecideUpdatesOnlyOnANewValue(t *testing.T) {
	d := decNewDecide(t)
	ns1, ns2 := "ns1.corp.test.", "ns2.corp.test."
	open := d.one(d.f, d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.81")))
	t.Run("the same value at one more server", func(t *testing.T) {
		both := d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.99"))
		decSameChanges(t, d.decide([]Finding{open}, both), nil)
	})
	t.Run("another value at that server", func(t *testing.T) {
		other := d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.98"))
		decSameChanges(t, d.decide([]Finding{open}, other), []Change{d.change(OpUpdate, d.one(d.f, other))})
	})
}

// decValueLine gives a line of a Value without the server of seen that
// starts it: what the line says, whichever server said it.
func decValueLine(line string, seen []Seen) string {
	for _, s := range seen {
		addr, host := "-", "-"
		if s.Answer.Server.Addr.IsValid() {
			addr = s.Answer.Server.Addr.String()
		}
		if s.Answer.Server.Name.LabelCount() > 0 {
			host = s.Answer.Server.Name.Lower().String()
		}
		if rest, ok := strings.CutPrefix(line, addr+" "+host+" "); ok {
			return rest
		}
	}
	return line
}

// decNewValue reports whether a line of the Value of f says what no line of
// the Value of was says, the servers left out.
func decNewValue(was, f Finding) bool {
	old := map[string]bool{}
	for _, l := range strings.Split(was.Value, "\n") {
		old[decValueLine(l, was.Seen)] = true
	}
	for _, l := range strings.Split(f.Value, "\n") {
		if l != "" && !old[decValueLine(l, f.Seen)] {
			return true
		}
	}
	return false
}

func TestDecideResolvesUnlessBlocked(t *testing.T) {
	d := decNewDecide(t)
	ns1, ns2, ns3 := "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."
	const ns2v6 = "[fd53::12]:53"
	// Each open finding saw one server: ns2 at its IPv4 address, ns2 at its
	// IPv6 address, or ns1.
	open := d.one(d.f, d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, decNS2, "10.53.0.99")))
	open6 := d.one(d.f, d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, ns2v6, "10.53.0.99")))
	openNS1 := d.one(d.f, d.observe(d.at(ns1, decNS1, "10.53.0.99"), d.at(ns2, decNS2, "10.53.0.81")))
	noLine := decFile(t, "domain corp.test.", "mail.corp.test. A 10.53.0.82")
	uncovered := d.one(noLine, d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.failed(ns2, decNS2, obs.ReasonTimeout)))
	mail := d.one(d.f, decObservation(decRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA), decName(t, "corp.test."), nil,
		decAnswer(t, ns1, decNS1, decSet(t, "mail.corp.test.", dnswire.TypeA, "10.53.0.99"))))

	fine := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, decNS2, "10.53.0.81"))
	ns1Fails := d.observe(d.failed(ns1, decNS1, obs.ReasonTimeout), d.at(ns2, decNS2, "10.53.0.81"))
	ns2Fails := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.failed(ns2, decNS2, obs.ReasonTimeout))
	ns2Late := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.failed(ns2, decNS2, obs.ReasonDeadline))
	noAddress := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, decNS2, "10.53.0.81"), d.failed(ns3, "", obs.ReasonWalk))
	failedWalk := decObservation(d.key, dnswire.Name{}, nil, decFailedWalk())
	ns2Gone := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns3, "10.53.0.13:53", "10.53.0.81"))
	ns2v6Fails := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, decNS2, "10.53.0.81"), d.failed(ns2, ns2v6, obs.ReasonNetwork))
	walkFails := fine
	walkFails.Walk = []obs.Answer{d.failed(ns2, decNS2, obs.ReasonTimeout), d.failed("ns.test.", "", obs.ReasonWalk)}
	still := d.observe(d.at(ns1, decNS1, "10.53.0.81"), d.at(ns2, decNS2, "10.53.0.99"))
	walk, _ := decCut(t)
	newZone := decObservation(d.key, decName(t, "www.corp.test."), walk, d.at("ns.evil.test.", "10.53.0.66:53", "10.53.0.81"))
	zone := d.one(d.f, newZone)
	invalid := FileChanges(decName(t, "corp.test."), errors.New("line 2: an empty record"), nil, d.now)
	if len(invalid) != 1 {
		t.Fatalf("FileChanges gave %d changes, want 1", len(invalid))
	}
	delegation := decObservation(obs.DelegationKey(decName(t, "corp.test.")), decName(t, "test."), nil,
		decAnswer(t, "ns.test.", "10.53.0.3:53", decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")))

	for _, c := range []struct {
		name string
		open []Finding
		o    obs.Observation
		want []Change
	}{
		{"every server agrees", []Finding{open}, fine, []Change{d.change(OpResolve, open)}},
		{"the server it saw fails", []Finding{open}, ns2Fails, nil},
		{"the server it saw is out of time", []Finding{open}, ns2Late, nil},
		{"another server fails", []Finding{open}, ns1Fails, []Change{d.change(OpResolve, open)}},
		{"a host with no address", []Finding{open}, noAddress, nil},
		{"failed walk", []Finding{open}, failedWalk, nil},
		{"the server it saw is no longer asked", []Finding{open}, ns2Gone, []Change{d.change(OpResolve, open)}},
		{"an IPv6 address it never saw fails", []Finding{open}, ns2v6Fails, []Change{d.change(OpResolve, open)}},
		{"an IPv6 address it saw fails", []Finding{open6}, ns2v6Fails, nil},
		{"failures in the walk only", []Finding{open}, walkFails, []Change{d.change(OpResolve, open)}},
		{"still found", []Finding{open}, still, nil},
		{"each finding has its own servers", []Finding{uncovered, open}, ns2Fails, []Change{d.change(OpResolve, uncovered)}},
		{"in open order", []Finding{open, uncovered}, fine, []Change{d.change(OpResolve, open), d.change(OpResolve, uncovered)}},
		{"in open order, reversed", []Finding{uncovered, open}, fine, []Change{d.change(OpResolve, uncovered), d.change(OpResolve, open)}},
		{"a duplicate resolves once", []Finding{open, open}, fine, []Change{d.change(OpResolve, open)}},
		{"the first of two duplicates decides", []Finding{open, openNS1}, ns1Fails, []Change{d.change(OpResolve, open)}},
		{"a later duplicate does not unblock", []Finding{open, openNS1}, ns2Fails, nil},
		{"opens come before resolves", []Finding{open}, newZone, []Change{d.change(OpOpen, zone), d.change(OpResolve, open)}},
		{"another check", []Finding{mail}, fine, nil},
		// The file has no NS line: the delegation is not covered, and that is all.
		{"the file is no check", []Finding{invalid[0].Finding}, delegation, []Change{d.change(OpOpen, d.one(d.f, delegation))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			decSameChanges(t, d.decide(c.open, c.o), c.want)
		})
	}
}

func TestFileFindingOpensUpdatesAndResolvesForItsDomain(t *testing.T) {
	corp, shop := decName(t, "corp.test."), decName(t, "shop.test.")
	now := decT0.Add(time.Minute)
	bad := errors.New("line 3: an empty record")
	worse := errors.New("line 3: an empty record; line 9: bad prefix \"10.53.0.0/33\"")

	got := FileChanges(corp, bad, nil, now)
	if len(got) != 1 || got[0].Op != OpOpen || !got[0].At.Equal(now) {
		t.Fatalf("FileChanges with an error and nothing open:%s", decShowChanges(got))
	}
	open := got[0].Finding
	if open.Rule != RuleInvalidFile || open.Severity != SeverityMedium || open.Expected != "" || len(open.Seen) != 0 || open.Value != bad.Error() {
		t.Errorf("the finding is%s", decShow([]Finding{open}))
	}
	if c := open.Check; c.Kind != 0 || c.Type != 0 || !c.Domain.Equal(corp) || !c.Name.Equal(corp) {
		t.Errorf("the finding has check %+v, want the domain alone", c)
	}
	scope := open.Check.String()

	changed := FileChanges(corp, worse, nil, now)[0].Finding
	shopOpen := FileChanges(shop, bad, nil, now)[0].Finding
	low := open
	low.Severity = SeverityLow
	upper := open
	upper.Check = obs.Key{Domain: decName(t, "CORP.TEST."), Name: decName(t, "Corp.Test.")}
	apex := decRecordsKey(t, "corp.test.", "corp.test.", dnswire.TypeNS)
	observed := Finding{Rule: RuleRecordSet, Severity: SeverityHigh, Check: apex, Value: "x"}
	delegation := Finding{Rule: RuleNameServers, Severity: SeverityCritical, Check: obs.DelegationKey(corp), Value: "x"}

	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }
	for _, c := range []struct {
		name string
		err  error
		open []Finding
		want []Change
	}{
		{"same text", bad, []Finding{open}, nil},
		{"new text", worse, []Finding{open}, []Change{change(OpUpdate, changed)}},
		{"other severity", bad, []Finding{low}, []Change{change(OpUpdate, open)}},
		{"another domain's file", bad, []Finding{shopOpen}, []Change{change(OpOpen, open)}},
		{"fixed", nil, []Finding{open}, []Change{change(OpResolve, open)}},
		{"fixed, nothing open", nil, nil, nil},
		{"fixed, another domain's file", nil, []Finding{shopOpen}, nil},
		{"fixed, findings of checks", nil, []Finding{observed, delegation}, nil},
		{"fixed, a duplicate resolves once", nil, []Finding{open, open}, []Change{change(OpResolve, open)}},
		{"fixed, the domain in capitals", nil, []Finding{upper}, []Change{change(OpResolve, upper)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := FileChanges(corp, c.err, c.open, now)
			decSameChanges(t, got, c.want)
			for _, g := range got {
				if g.Finding.Check.String() != scope {
					t.Errorf("a change of check %v, want %s", g.Finding.Check, scope)
				}
			}
		})
	}
}

// The property tests draw their inputs from a fixed seed, so a failure can
// be replayed; every message names the seed of its case.
const (
	decSeed  = 20261111
	decCases = 1000
)

type decGen struct {
	t   testing.TB
	rng *rand.Rand
}

func decPick[T any](g *decGen, xs ...T) T { return xs[g.rng.IntN(len(xs))] }

// decLines are the lines a generated file can hold; "@" stands for the
// domain. Each form is one that Parse accepts for the type.
var decLines = []struct {
	owner, typ string
	forms      []string
}{
	{"@", "NS", []string{"ns1.corp.test. | ns2.corp.test.", "ns1.corp.test. | ns2.corp.test. || ns1.dnshost.test. | ns2.dnshost.test.", "like *.corp.test. ns1.dnshost.test.", "none"}},
	{"@", "DS", []string{"none", decDS}},
	{"www.corp.test.", "A", []string{"10.53.0.81", "10.53.0.81 | 10.53.0.82", "10.53.0.81 || 10.53.0.99", "in 10.53.0.0/24", "none"}},
	{"www.corp.test.", "AAAA", []string{"fd53::81", "in fd53::/64", "none"}},
	{"sub.corp.test.", "NS", []string{"ns1.sub.corp.test.", "like *.dnshost.test.", "none"}},
	{"a.sub.corp.test.", "A", []string{"10.53.0.81", "none"}},
	{"mail.corp.test.", "MX", []string{"10 mail.corp.test.", "like mail.corp.test. *.dnshost.test.", "none"}},
	{"corp.test.", "TXT", []string{`"v=spf1 mx -all"`, "none"}},
	{"www.example.", "A", []string{"10.53.0.81", "none"}},
	{"sub.example.", "NS", []string{"ns1.dnshost.test.", "none"}},
}

var decData = map[dnswire.Type][]string{
	dnswire.TypeA:     {"10.53.0.81", "10.53.0.82", "10.53.0.99"},
	dnswire.TypeAAAA:  {"fd53::81", "fd53::99"},
	dnswire.TypeNS:    {"ns1.corp.test.", "ns2.corp.test.", "NS1.Corp.Test.", "ns1.dnshost.test.", "ns2.dnshost.test.", "ns1.sub.corp.test."},
	dnswire.TypeMX:    {"10 mail.corp.test.", "20 mx.dnshost.test."},
	dnswire.TypeTXT:   {`"v=spf1 mx -all"`, `"v=spf1 +all"`},
	dnswire.TypeCNAME: {"edge.dnshost.test.", "www.corp.test."},
	dnswire.TypeDS:    {decDS, "54321 13 2 " + strings.Repeat("AB", 32)},
	dnswire.TypeSOA:   {"ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300"},
}

var (
	decDomains = []string{"corp.test.", "CORP.test.", "example.", "shop.test."}
	decNames   = []string{"corp.test.", "www.corp.test.", "WWW.Corp.Test.", "x.www.corp.test.", "sub.corp.test.",
		"a.sub.corp.test.", "mail.corp.test.", "www.example.", "sub.example.", "edge.dnshost.test."}
	decZones = []string{".", "test.", "corp.test.", "Corp.Test.", "sub.corp.test.", "www.corp.test.", "example.",
		"www.example.", "dnshost.test."}
	decHosts = []string{".", "ns.test.", "ns1.corp.test.", "ns2.corp.test.", "NS1.Corp.Test.", "ns.evil.test."}
	decAddrs = []string{decNS1, decNS2, "10.53.0.3:53", "10.53.0.66:53", "[fd53::12]:53"}
	decTypes = []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeNS, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCNAME}
	decTexts = []string{"none", "10.53.0.81", "10.53.0.99", "www.corp.test.", "corp.test.", "ns1.corp.test. | ns2.corp.test."}
)

func (g *decGen) name(s string) dnswire.Name { return decName(g.t, s) }

func (g *decGen) file() *expect.File {
	if g.rng.IntN(8) == 0 {
		return nil
	}
	domain := decPick(g, "corp.test.", "Corp.Test.", "example.")
	lines := []string{"domain " + domain}
	for _, l := range decLines {
		if g.rng.IntN(2) == 0 {
			continue
		}
		owner := l.owner
		if owner == "@" {
			owner = domain
		}
		lines = append(lines, owner+" "+l.typ+" "+decPick(g, l.forms...))
	}
	g.rng.Shuffle(len(lines)-1, func(i, j int) { lines[i+1], lines[j+1] = lines[j+1], lines[i+1] })
	return decFile(g.t, lines...)
}

var decKindTypes = map[obs.Kind]dnswire.Type{obs.KindDelegation: dnswire.TypeNS, obs.KindDS: dnswire.TypeDS, obs.KindSerial: dnswire.TypeSOA}

func (g *decGen) key() obs.Key {
	domain := decPick(g, decDomains...)
	kind := obs.Kind(decPick(g, 0, 1, 1, 2, 3, 3, 3, 3, 4, 5))
	if typ, ok := decKindTypes[kind]; ok {
		return obs.Key{Kind: kind, Domain: g.name(domain), Name: g.name(domain), Type: typ}
	}
	return obs.Key{Kind: kind, Domain: g.name(domain), Name: g.name(decPick(g, decNames...)), Type: decPick(g, decTypes...)}
}

// recased is the same check with its names in capitals.
func (g *decGen) recased(k obs.Key) obs.Key {
	k.Domain = g.name(strings.ToUpper(k.Domain.String()))
	k.Name = g.name(strings.ToUpper(k.Name.String()))
	return k
}

func (g *decGen) records(owner dnswire.Name, typ dnswire.Type) []dnswire.Record {
	if g.rng.IntN(6) == 0 {
		typ = dnswire.TypeCNAME
	}
	data, ok := decData[typ]
	if !ok {
		typ, data = dnswire.TypeA, decData[dnswire.TypeA]
	}
	var set []dnswire.Record
	for range 1 + g.rng.IntN(3) {
		r := decRR(g.t, owner.String(), typ, decPick(g, data...))
		r.TTL = uint32(g.rng.IntN(4000))
		set = append(set, r)
	}
	return set
}

// result draws one of the four cases, or the zero Result; with failures
// false it draws no failure.
func (g *decGen) result(owner dnswire.Name, typ dnswire.Type, failures bool) obs.Result {
	n := g.rng.IntN(6)
	if !failures {
		n = g.rng.IntN(3)
	}
	soa := decSOA(g.t, decPick(g, decZones[1:]...))
	switch n {
	case 0:
		return obs.NoDataResult(obs.NoData{SOA: soa})
	case 1:
		return obs.NoNameResult(obs.NoName{SOA: soa, Compact: g.rng.IntN(2) == 0})
	case 2:
		var glue []dnswire.Record
		if g.rng.IntN(3) == 0 {
			glue = []dnswire.Record{decRR(g.t, "ns1.corp.test.", dnswire.TypeA, decPick(g, decData[dnswire.TypeA]...))}
		}
		return obs.RecordsResult(obs.Records{Set: g.records(owner, typ), Glue: glue})
	case 3:
		return obs.Result{}
	case 4:
		return decFailure(obs.ReasonDeadline)
	}
	return obs.FailureResult(obs.Failure{Reason: obs.Reason(g.rng.IntN(16)), Detail: "drawn"})
}

func (g *decGen) answer(q dnswire.Question, start time.Time, failures bool) obs.Answer {
	var a obs.Answer
	a.Server.Name = g.name(decPick(g, decHosts...))
	if g.rng.IntN(6) > 0 {
		a.Server.Addr = netip.MustParseAddrPort(decPick(g, decAddrs...))
	}
	a.Question = q
	// A replay has no send time, and a cached referral is older than the check.
	a.Received = start.Add(time.Duration(g.rng.IntN(90)-45) * time.Second)
	if g.rng.IntN(3) > 0 {
		a.Sent = a.Received.Add(-time.Duration(g.rng.IntN(500)) * time.Millisecond)
	}
	if g.rng.IntN(2) == 0 {
		a.Wire = []byte{byte(g.rng.IntN(256)), byte(g.rng.IntN(256))}
	}
	a.TCP = g.rng.IntN(4) == 0
	a.Result = g.result(q.Name, q.Type, failures)
	return a
}

func (g *decGen) observation(key obs.Key, failures bool) obs.Observation {
	start := decT0.Add(time.Duration(g.rng.IntN(1000)) * time.Minute)
	o := obs.Observation{Key: key, Start: start, Deadline: start.Add(45 * time.Second), Zone: g.name(decPick(g, decZones...))}
	for range g.rng.IntN(5) {
		zone := g.name(decPick(g, decZones...))
		w := g.answer(dnswire.Question{Name: zone, Type: dnswire.TypeNS, Class: dnswire.ClassINET}, start, true)
		if g.rng.IntN(2) == 0 {
			w.Result = obs.RecordsResult(obs.Records{Set: g.records(zone, dnswire.TypeNS)})
		}
		o.Walk = append(o.Walk, w)
	}
	q := dnswire.Question{Name: key.Name, Type: key.Type, Class: dnswire.ClassINET}
	if failures && g.rng.IntN(8) == 0 {
		failed := obs.Answer{Result: decFailure(decPick(g, obs.ReasonWalk, obs.ReasonBudget, obs.ReasonDeadline))}
		failed.Question = q
		o.Zone = dnswire.Name{}
		o.Answers = []obs.Answer{failed}
		return o
	}
	for range 1 + g.rng.IntN(4) {
		o.Answers = append(o.Answers, g.answer(q, start, failures))
	}
	return o
}

func (g *decGen) finding(check obs.Key, start time.Time) Finding {
	f := Finding{
		Rule:     Rule(g.rng.IntN(7)),
		Severity: Severity(g.rng.IntN(6)),
		Check:    check,
		Expected: decPick(g, "", "10.53.0.81", "corp.test.", "none", "ns1.corp.test. | ns2.corp.test."),
	}
	var lines []string
	for range g.rng.IntN(4) {
		s := Seen{Answer: g.answer(dnswire.Question{Name: check.Name, Type: check.Type, Class: dnswire.ClassINET}, start, true), Text: decPick(g, decTexts...)}
		f.Seen = append(f.Seen, s)
		line := s.Answer.Server.Addr.String() + " " + s.Answer.Server.Name.Lower().String() + " " + s.Text
		if g.rng.IntN(4) == 0 {
			line = decPick(g, "10.53.0.12:53 ns2.corp.test. 10.53.0.99", "10.53.0.11:53 ns1.corp.test. none", "line 3: an empty record")
		}
		lines = append(lines, line)
	}
	f.Value = strings.Join(lines, "\n")
	return f
}

// other is a check that is not key: another kind, name, type or domain, or
// the file of a domain.
func (g *decGen) other(key obs.Key) obs.Key {
	for {
		k := g.key()
		if g.rng.IntN(4) == 0 {
			k = obs.Key{Domain: k.Domain, Name: k.Domain}
		}
		if k.String() != key.String() {
			return k
		}
	}
}

func (g *decGen) open(key obs.Key, start time.Time) []Finding {
	var open []Finding
	for range g.rng.IntN(6) {
		check := key
		switch g.rng.IntN(6) {
		case 0:
			check = g.recased(key)
		case 1, 2:
			check = g.other(key)
		}
		open = append(open, g.finding(check, start))
	}
	return open
}

// decInput draws one input of Decide from seed: equal seeds give equal
// inputs. A quarter of the cases follow a recipe that forces every kind of
// change, so that a Decide that never changes anything cannot pass.
func decInput(t testing.TB, seed uint64) Input {
	g := &decGen{t: t, rng: rand.New(rand.NewPCG(seed, 4))}
	if seed%4 != 0 {
		in := Input{Expect: g.file(), Observation: g.observation(g.key(), true)}
		in.Open = g.open(in.Observation.Key, in.Observation.Start)
		in.Now = in.Observation.Deadline.Add(time.Duration(g.rng.IntN(60)) * time.Second)
		return in
	}
	// mail.corp.test. A has no line and lies in the expected zone: the one
	// finding is not-covered. No answer fails, so nothing blocks a resolve.
	in := Input{Expect: decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81")}
	in.Observation = g.observation(decRecordsKey(t, "corp.test.", "mail.corp.test.", dnswire.TypeA), false)
	in.Observation.Zone = decName(t, "corp.test.")
	in.Now = in.Observation.Deadline
	for range g.rng.IntN(3) {
		in.Open = append(in.Open, g.finding(g.other(in.Observation.Key), in.Observation.Start))
	}
	if seed%8 == 0 {
		return in
	}
	uncovered := g.finding(in.Observation.Key, in.Observation.Start)
	uncovered.Rule, uncovered.Severity = RuleNotCovered, SeverityLow
	recordSet := g.finding(g.recased(in.Observation.Key), in.Observation.Start)
	recordSet.Rule = RuleRecordSet
	in.Open = append(in.Open, uncovered, recordSet)
	return in
}

// decCount counts the changes by Op, and fails at the end of the test when
// some Op never came up.
type decCount map[Op]int

func (c decCount) add(changes []Change) {
	for _, ch := range changes {
		c[ch.Op]++
	}
}

func (c decCount) check(t *testing.T) {
	t.Helper()
	for _, op := range []Op{OpOpen, OpUpdate, OpResolve} {
		if c[op] == 0 {
			t.Errorf("no case gave %v: the inputs do not test it", op)
		}
	}
}

func TestDecidePureProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", decSeed, decCases)
	count := decCount{}
	for i := range decCases {
		seed := uint64(decSeed + i)
		a, b := decInput(t, seed), decInput(t, seed)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: one seed gave two inputs", seed)
		}
		got := Decide(a)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: Decide changed its input", seed)
		}
		if again := Decide(b); !reflect.DeepEqual(got, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, decShowChanges(got), decShowChanges(again))
		}
		// The goroutines share the slices of one input, so the race
		// detector sees any write to it or to state of the package.
		outs := make([][]Change, 8)
		var wg sync.WaitGroup
		for j := range outs {
			wg.Go(func() { outs[j] = Decide(a) })
		}
		wg.Wait()
		for j, out := range outs {
			if !reflect.DeepEqual(out, got) {
				t.Fatalf("seed %d: goroutine %d gave%s\nwant%s", seed, j, decShowChanges(out), decShowChanges(got))
			}
		}
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: Decide changed its input in a goroutine", seed)
		}
		count.add(got)
	}
	count.check(t)
}

func TestOnlyObservedChecksProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", decSeed, decCases)
	count := decCount{}
	for i := range decCases {
		seed := uint64(decSeed + i)
		in := decInput(t, seed)
		key := in.Observation.Key.String()
		got := Decide(in)
		count.add(got)

		// O with X mixed in at random places, where no x is of the
		// observed check.
		more := decInput(t, seed)
		g := &decGen{t: t, rng: rand.New(rand.NewPCG(seed, 5))}
		for range 1 + g.rng.IntN(4) {
			x := g.finding(g.other(more.Observation.Key), more.Observation.Start)
			more.Open = slices.Insert(more.Open, g.rng.IntN(len(more.Open)+1), x)
		}
		again := Decide(more)
		for _, c := range slices.Concat(got, again) {
			if c.Finding.Check.String() != key {
				t.Fatalf("seed %d: a change of check %v from an observation of %s", seed, c.Finding.Check, key)
			}
		}
		if !reflect.DeepEqual(got, again) {
			t.Fatalf("seed %d: findings of other checks changed the result from%s\nto%s", seed, decShowChanges(got), decShowChanges(again))
		}
	}
	count.check(t)
}
