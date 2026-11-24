package alert

import (
	"fmt"
	"maps"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

var (
	alrT0  = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)
	alrNow = alrT0.Add(10 * time.Minute)
)

// The property tests draw their inputs from a fixed seed, so a failure can
// be replayed; every message names the seed and the case.
const (
	alrSeed  = 20261111
	alrCases = 1000
)

func alrRand(c int) *rand.Rand { return rand.New(rand.NewPCG(alrSeed, uint64(c))) }

func alrPick[T any](rng *rand.Rand, xs ...T) T { return xs[rng.IntN(len(xs))] }

var alrSeverities = []decide.Severity{decide.SeverityLow, decide.SeverityMedium, decide.SeverityHigh, decide.SeverityCritical}

func alrName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// alrKey is the check of the A set of name in the domain corp.test.
func alrKey(t testing.TB, name string) obs.Key {
	t.Helper()
	return obs.RecordsKey(alrName(t, "corp.test."), alrName(t, name), dnswire.TypeA)
}

// alrServer is host at addr; an empty addr is a host with no known address.
func alrServer(t testing.TB, host, addr string) obs.Server {
	t.Helper()
	s := obs.Server{Name: alrName(t, host)}
	if addr != "" {
		s.Addr = netip.MustParseAddrPort(addr)
	}
	return s
}

func alrRR(t testing.TB, owner string, typ dnswire.Type, ttl uint32, data string) dnswire.Record {
	t.Helper()
	d, err := dnswire.ParseRData(typ, data)
	if err != nil {
		t.Fatalf("ParseRData(%v, %q): %v", typ, data, err)
	}
	return dnswire.Record{Name: alrName(t, owner), Class: dnswire.ClassINET, TTL: ttl, Data: d}
}

func alrSOA(t testing.TB, ttl uint32) dnswire.Record {
	t.Helper()
	return alrRR(t, "corp.test.", dnswire.TypeSOA, ttl, "ns1.corp.test. hostmaster.corp.test. 1 3600 600 604800 300")
}

// alrAs fails the test when obs turned a result into another case than
// meant, so that no test of a TTL quietly reads a failure.
func alrAs(t testing.TB, r obs.Result, want string) obs.Result {
	t.Helper()
	got := obs.Match(r,
		func(obs.Records) string { return "records" },
		func(obs.NoData) string { return "nodata" },
		func(obs.NoName) string { return "noname" },
		func(obs.Failure) string { return "failure" })
	if got != want {
		t.Fatalf("built a %s result, want %s", got, want)
	}
	return r
}

func alrAnswer(s obs.Server, r obs.Result, received time.Time) obs.Answer {
	a := obs.Answer{Result: r}
	a.Server = s
	a.Sent = received.Add(-time.Second)
	a.Received = received
	a.Wire = []byte{0x12, 0x34}
	return a
}

// alrProof is three answers that each give their TTL in another way, and
// the lines an alert must keep of them: a set whose records differ in TTL,
// no data and no such name, whose TTL is the smaller of the SOA record's TTL
// and its MINIMUM of 300.
func alrProof(t testing.TB) ([]decide.Seen, []Line) {
	t.Helper()
	ns1 := alrServer(t, "ns1.corp.test.", "10.53.0.11:53")
	ns2 := alrServer(t, "NS2.Corp.Test.", "[fd53::12]:53")
	ns3 := alrServer(t, "ns3.corp.test.", "")
	set := alrAs(t, obs.RecordsResult(obs.Records{Set: []dnswire.Record{
		alrRR(t, "www.corp.test.", dnswire.TypeA, 300, "10.53.0.98"),
		alrRR(t, "www.corp.test.", dnswire.TypeA, 120, "10.53.0.99"),
	}}), "records")
	noData := alrAs(t, obs.NoDataResult(obs.NoData{SOA: alrSOA(t, 900)}), "nodata")
	noName := alrAs(t, obs.NoNameResult(obs.NoName{SOA: alrSOA(t, 60)}), "noname")
	r1, r2, r3 := alrT0.Add(time.Second), alrT0.Add(2*time.Second), alrT0.Add(3*time.Second)
	seen := []decide.Seen{
		{Answer: alrAnswer(ns1, set, r1), Text: "10.53.0.98 | 10.53.0.99"},
		{Answer: alrAnswer(ns2, noData, r2), Text: "none (no data)"},
		{Answer: alrAnswer(ns3, noName, r3), Text: "none (no name)"},
	}
	lines := []Line{
		{Server: ns1, Text: "10.53.0.98 | 10.53.0.99", TTL: 120, Received: r1},
		{Server: ns2, Text: "none (no data)", TTL: 300, Received: r2},
		{Server: ns3, Text: "none (no name)", TTL: 60, Received: r3},
	}
	return seen, lines
}

// alrStored is an open record-set alert of www.corp.test. A as the store
// gives it back, noticed 70 minutes before alrNow.
func alrStored(t testing.TB, sev, peak decide.Severity) Alert {
	t.Helper()
	return Alert{ID: 7, Open: true, Rule: decide.RuleRecordSet, Severity: sev, Peak: peak,
		Check: alrKey(t, "www.corp.test."), Expected: "10.53.0.81", Value: "10.53.0.11:53 ns1.corp.test. 10.53.0.97",
		Lines: []Line{{Server: alrServer(t, "ns1.corp.test.", "10.53.0.11:53"), Text: "10.53.0.97", TTL: 30,
			Received: alrT0.Add(-time.Hour)}},
		Opened: alrT0.Add(-2 * time.Hour), LastClean: alrT0.Add(-3 * time.Hour), Noticed: alrT0.Add(-time.Hour)}
}

// alrNews is a finding of the identity of alrStored with other text.
func alrNews(t testing.TB, sev decide.Severity) decide.Finding {
	t.Helper()
	seen, _ := alrProof(t)
	return decide.Finding{Rule: decide.RuleRecordSet, Severity: sev, Check: alrKey(t, "www.corp.test."),
		Expected: "10.53.0.80", Seen: seen, Value: "three new proof lines"}
}

var alrKindWords = map[EventKind]string{
	EventOpen: "open", EventUpdate: "update", EventEscalate: "escalate", EventReminder: "reminder", EventResolve: "resolve",
	EventRefresh: "refresh",
}

// alrKind names a kind without its String method, so that a wrong word
// there fails one test only.
func alrKind(k EventKind) string {
	if w, ok := alrKindWords[k]; ok {
		return w
	}
	return fmt.Sprintf("event%d", uint8(k))
}

func alrTime(x time.Time) string {
	if x.IsZero() {
		return "zero"
	}
	return x.UTC().Format(time.RFC3339Nano)
}

// alrShow prints every field of the events, so that two lists compare as
// text and a difference shows where it is.
func alrShow(events []Event) string {
	var b strings.Builder
	for _, e := range events {
		a := e.Alert
		fmt.Fprintf(&b, "\n  %s was %v at %s: id %d open %v %v %v peak %v check %q expected %q value %q"+
			" opened %s last-clean %s noticed %s resolved %s",
			alrKind(e.Kind), e.Was, alrTime(e.At), a.ID, a.Open, a.Rule, a.Severity, a.Peak, a.Check.String(),
			a.Expected, a.Value, alrTime(a.Opened), alrTime(a.LastClean), alrTime(a.Noticed), alrTime(a.Resolved))
		for _, l := range a.Lines {
			fmt.Fprintf(&b, "\n    line %s %v %q ttl %d %s", l.Server.Name, l.Server.Addr, l.Text, l.TTL, alrTime(l.Received))
		}
	}
	return b.String()
}

func alrSame(t *testing.T, what string, got, want []Event) {
	t.Helper()
	if g, w := alrShow(got), alrShow(want); g != w {
		t.Errorf("%s: events\n got %s\n want %s", what, g, w)
	}
}

// alrBrief is the kind, row id, rule and value of each event, for tests
// about which alert got which event.
func alrBrief(events []Event) []string {
	var s []string
	for _, e := range events {
		s = append(s, fmt.Sprintf("%s %d %v %s", alrKind(e.Kind), e.Alert.ID, e.Alert.Rule, e.Alert.Value))
	}
	return s
}

func TestEventKindWords(t *testing.T) {
	for _, c := range []struct {
		kind  EventKind
		value uint8
		word  string
	}{
		{EventOpen, 1, "open"},
		{EventUpdate, 2, "update"},
		{EventEscalate, 3, "escalate"},
		{EventReminder, 4, "reminder"},
		{EventResolve, 5, "resolve"},
		{EventRefresh, 6, "refresh"},
		{0, 0, "event0"},
		{7, 7, "event7"},
		{255, 255, "event255"},
	} {
		if uint8(c.kind) != c.value || c.kind.String() != c.word {
			t.Errorf("EventKind %d prints %q; want value %d, %q", uint8(c.kind), c.kind.String(), c.value, c.word)
		}
	}
}

// Two changes with equal identity address one alert, so the identity must
// ignore letter case and keep apart the rules and the kinds of check.
func TestIdentityIsRuleThenCheckText(t *testing.T) {
	corp := alrName(t, "corp.test.")
	www := alrKey(t, "www.corp.test.")
	shouting := obs.RecordsKey(alrName(t, "CORP.TEST."), alrName(t, "WWW.Corp.Test."), dnswire.TypeA)
	for _, c := range []struct {
		rule decide.Rule
		key  obs.Key
		want string
	}{
		{decide.RuleRecordSet, www, "record-set records corp.test. www.corp.test. A"},
		{decide.RuleRecordSet, shouting, "record-set records corp.test. www.corp.test. A"},
		{decide.RuleZone, www, "zone records corp.test. www.corp.test. A"},
		{decide.RuleNotCovered, obs.DelegationKey(corp), "not-covered delegation corp.test. corp.test. NS"},
		{decide.RuleNotCovered, obs.RecordsKey(corp, corp, dnswire.TypeNS), "not-covered records corp.test. corp.test. NS"},
	} {
		if got := Identity(c.rule, c.key); got != c.want {
			t.Errorf("Identity(%v, %v) = %q, want %q", c.rule, c.key, got, c.want)
		}
		a := Alert{Rule: c.rule, Check: c.key, Severity: decide.SeverityHigh, Peak: decide.SeverityCritical, Value: "x"}
		if got := a.Identity(); got != c.want {
			t.Errorf("Alert{%v, %v}.Identity() = %q, want %q", c.rule, c.key, got, c.want)
		}
	}
}

func TestLabelNamesKindSeverityRuleAndCheck(t *testing.T) {
	corp := alrName(t, "corp.test.")
	delegation := Alert{Rule: decide.RuleNameServers, Severity: decide.SeverityCritical, Peak: decide.SeverityCritical,
		Check: obs.DelegationKey(corp)}
	// The peak is above the severity, so the label shows which one it reads.
	www := Alert{Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityCritical,
		Check: obs.RecordsKey(alrName(t, "Corp.Test."), alrName(t, "WWW.Corp.Test."), dnswire.TypeA)}
	raised := www
	raised.Severity = decide.SeverityCritical
	mail := Alert{Rule: decide.RuleNotCovered, Severity: decide.SeverityMedium, Peak: decide.SeverityMedium,
		Check: obs.RecordsKey(corp, alrName(t, "mail.corp.test."), dnswire.TypeMX)}
	// The check of the invalid-file alert has no kind, and its label names
	// only the domain.
	upper := alrName(t, "Corp.Test.")
	file := Alert{Rule: decide.RuleInvalidFile, Severity: decide.SeverityMedium, Peak: decide.SeverityMedium,
		Check: obs.Key{Domain: upper, Name: upper}}
	// The check of the certificates has the domain as its name and no type;
	// its label names the kind and the domain alone.
	issuer := Alert{Rule: decide.RuleIssuer, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh,
		Check: obs.CertificatesKey(upper)}
	hosts := Alert{Rule: decide.RuleHostnames, Severity: decide.SeverityLow, Peak: decide.SeverityLow,
		Check: obs.CertificatesKey(corp)}
	for _, c := range []struct {
		e    Event
		want string
	}{
		{Event{Kind: EventOpen, Alert: issuer, Was: decide.SeverityHigh}, "open high issuer certificates corp.test."},
		{Event{Kind: EventResolve, Alert: issuer, Was: decide.SeverityHigh}, "resolve high issuer certificates corp.test."},
		{Event{Kind: EventUpdate, Alert: hosts, Was: decide.SeverityLow}, "update low hostnames certificates corp.test."},
		{Event{Kind: EventOpen, Alert: delegation, Was: decide.SeverityCritical}, "open critical nameservers delegation corp.test. NS"},
		{Event{Kind: EventResolve, Alert: delegation, Was: decide.SeverityCritical}, "resolve critical nameservers delegation corp.test. NS"},
		{Event{Kind: EventUpdate, Alert: www, Was: decide.SeverityHigh}, "update high record-set records www.corp.test. A"},
		{Event{Kind: EventEscalate, Alert: raised, Was: decide.SeverityHigh}, "escalate critical record-set records www.corp.test. A"},
		{Event{Kind: EventReminder, Alert: mail, Was: decide.SeverityMedium}, "reminder medium not-covered records mail.corp.test. MX"},
		{Event{Kind: EventOpen, Alert: file, Was: decide.SeverityMedium}, "open medium invalid-file corp.test."},
		{Event{Kind: EventResolve, Alert: file, Was: decide.SeverityMedium}, "resolve medium invalid-file corp.test."},
	} {
		if got := c.e.Label(); got != c.want {
			t.Errorf("Label() = %q, want %q", got, c.want)
		}
	}
}

// decide reads of an open finding only its rule, severity, check, expected
// text, value and the server and time of each proof.
func TestFindingGivesBackWhatDecideReads(t *testing.T) {
	_, lines := alrProof(t)
	a := alrStored(t, decide.SeverityHigh, decide.SeverityCritical)
	a.Lines = lines
	f := a.Finding()
	if f.Rule != a.Rule || f.Severity != a.Severity || !reflect.DeepEqual(f.Check, a.Check) ||
		f.Expected != a.Expected || f.Value != a.Value {
		t.Errorf("Finding() is %v %v %v expected %q value %q; want %v %v %v expected %q value %q",
			f.Rule, f.Severity, f.Check, f.Expected, f.Value, a.Rule, a.Severity, a.Check, a.Expected, a.Value)
	}
	if len(f.Seen) != len(lines) {
		t.Fatalf("Finding() has %d seen, want one per line, %d", len(f.Seen), len(lines))
	}
	for i, l := range lines {
		s := f.Seen[i]
		if !reflect.DeepEqual(s.Answer.Server, l.Server) || !s.Answer.Received.Equal(l.Received) || s.Text != l.Text {
			t.Errorf("seen %d is %v %s %q, want %v %s %q", i, s.Answer.Server, alrTime(s.Answer.Received), s.Text,
				l.Server, alrTime(l.Received), l.Text)
		}
		if !reflect.DeepEqual(s.Answer.Result, obs.Result{}) {
			t.Errorf("seen %d has a result; want the zero Result", i)
		}
	}
	a.Lines = nil
	if got := a.Finding().Seen; len(got) != 0 {
		t.Errorf("an alert with no line gives %d seen", len(got))
	}
}

// decide gives the next changes from the open findings; the store keeps
// only what an alert holds, so the findings rebuilt from the alerts must
// lead decide to the same changes as the findings themselves.
func TestFindingRoundTripsThroughDecide(t *testing.T) {
	file := func(lines ...string) *expect.File {
		text := strings.Join(lines, "\n") + "\n"
		f, err := expect.Parse([]byte(text))
		if err != nil {
			t.Fatalf("Parse(%q): %v", text, err)
		}
		return f
	}
	withWWW := file("domain corp.test.", "www.corp.test. A 10.53.0.81")
	withMail := file("domain corp.test.", "www.corp.test. A 10.53.0.81", "mail.corp.test. A 10.53.0.82")
	ns1 := alrServer(t, "ns1.corp.test.", "10.53.0.11:53")
	ns2 := alrServer(t, "ns2.corp.test.", "10.53.0.12:53")
	www, mail := alrKey(t, "www.corp.test."), alrKey(t, "mail.corp.test.")
	at := func(s obs.Server, owner string, data ...string) obs.Answer {
		if len(data) == 0 {
			return alrAnswer(s, alrAs(t, obs.NoDataResult(obs.NoData{SOA: alrSOA(t, 900)}), "nodata"), alrT0.Add(time.Second))
		}
		var set []dnswire.Record
		for _, d := range data {
			set = append(set, alrRR(t, owner, dnswire.TypeA, 300, d))
		}
		return alrAnswer(s, alrAs(t, obs.RecordsResult(obs.Records{Set: set}), "records"), alrT0.Add(time.Second))
	}
	fails := func(s obs.Server) obs.Answer {
		return alrAnswer(s, obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout}), alrT0.Add(time.Second))
	}
	observe := func(k obs.Key, answers ...obs.Answer) obs.Observation {
		return obs.Observation{Key: k, Start: alrT0, Deadline: alrT0.Add(45 * time.Second), Zone: alrName(t, "corp.test."), Answers: answers}
	}
	const w, m = "www.corp.test.", "mail.corp.test."
	wwwFirst := observe(www, at(ns1, w, "10.53.0.81"), at(ns2, w, "10.53.0.99"))
	mailFirst := observe(mail, at(ns1, m), at(ns2, m, "10.53.0.82"))
	for _, c := range []struct {
		name  string
		first obs.Observation // judged with withWWW
		file  *expect.File
		next  obs.Observation
		want  []decide.Op // what decide gives with the original findings
	}{
		{"record-set, nothing new", wwwFirst, withWWW, observe(www, at(ns1, w, "10.53.0.81"), at(ns2, w, "10.53.0.99")), nil},
		{"record-set, new data", wwwFirst, withWWW, observe(www, at(ns1, w, "10.53.0.81"), at(ns2, w, "10.53.0.98")),
			[]decide.Op{decide.OpUpdate}},
		{"record-set, both match", wwwFirst, withWWW, observe(www, at(ns1, w, "10.53.0.81"), at(ns2, w, "10.53.0.81")),
			[]decide.Op{decide.OpResolve}},
		{"record-set, the server that showed it fails", wwwFirst, withWWW, observe(www, at(ns1, w, "10.53.0.81"), fails(ns2)), nil},
		{"record-set, the same value at one more server", wwwFirst, withWWW, observe(www, at(ns1, w, "10.53.0.99"), at(ns2, w, "10.53.0.99")),
			[]decide.Op{decide.OpRefresh}},
		{"record-set, another server fails", wwwFirst, withWWW, observe(www, fails(ns1), at(ns2, w, "10.53.0.81")),
			[]decide.Op{decide.OpResolve}},
		{"not-covered, nothing new", mailFirst, withWWW, mailFirst, nil},
		{"not-covered, a line now", mailFirst, withMail, mailFirst, []decide.Op{decide.OpOpen, decide.OpResolve}},
		{"not-covered, the server that showed it fails", mailFirst, withMail, observe(mail, fails(ns1), at(ns2, m, "10.53.0.82")), nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			changes := decide.Decide(decide.Input{Expect: withWWW, Observation: c.first, Now: alrT0})
			out := Transition(Input{Changes: changes, Now: alrT0})
			if len(changes) == 0 || len(out.Events) != len(changes) {
				t.Fatalf("%d changes gave %d events, want as many and more than none", len(changes), len(out.Events))
			}
			var original, rebuilt []decide.Finding
			for i, e := range out.Events {
				original = append(original, changes[i].Finding)
				rebuilt = append(rebuilt, e.Alert.Finding())
			}
			next := alrNow
			want := decide.Decide(decide.Input{Expect: c.file, Open: original, Observation: c.next, Now: next})
			got := decide.Decide(decide.Input{Expect: c.file, Open: rebuilt, Observation: c.next, Now: next})
			var ops []decide.Op
			for _, ch := range want {
				ops = append(ops, ch.Op)
			}
			if !slices.Equal(ops, c.want) {
				t.Fatalf("the case does not test what it says: decide gives %v, want %v", ops, c.want)
			}
			if g, o := alrShowChanges(got), alrShowChanges(want); g != o {
				t.Errorf("with the rebuilt findings decide gives%s\nwith the original findings%s", g, o)
			}
		})
	}
}

// alrShowChanges prints what decide reads of a finding, so a resolve that
// carries a rebuilt finding compares equal to one that carries the original.
func alrShowChanges(cs []decide.Change) string {
	var b strings.Builder
	for _, c := range cs {
		f := c.Finding
		fmt.Fprintf(&b, "\n  %v at %s: %v %v %v expected %q value %q", c.Op, alrTime(c.At), f.Rule, f.Severity, f.Check, f.Expected, f.Value)
		for _, s := range f.Seen {
			fmt.Fprintf(&b, "\n    seen %s %v %q %s", s.Answer.Server.Name, s.Answer.Server.Addr, s.Text, alrTime(s.Answer.Received))
		}
	}
	return b.String()
}

func TestOpenOrUpdateWithNothingOpenOpensAlert(t *testing.T) {
	seen, lines := alrProof(t)
	k := alrKey(t, "www.corp.test.")
	f := decide.Finding{Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Check: k, Expected: "10.53.0.81",
		Seen: seen, Value: "three proof lines"}
	for _, op := range []decide.Op{decide.OpOpen, decide.OpUpdate} {
		for _, lastClean := range []time.Time{{}, alrT0.Add(-time.Hour)} {
			// The change carries an older time, so every time of the event
			// must come from Now.
			out := Transition(Input{Changes: []decide.Change{{Op: op, Finding: f, At: alrT0}}, LastClean: lastClean, Now: alrNow})
			want := Event{Kind: EventOpen, Was: decide.SeverityHigh, At: alrNow, Alert: Alert{Open: true,
				Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh, Check: k,
				Expected: "10.53.0.81", Value: "three proof lines", Lines: lines, Opened: alrNow, LastClean: lastClean, Noticed: alrNow}}
			what := fmt.Sprintf("%v with last clean %s", op, alrTime(lastClean))
			alrSame(t, what, out.Events, []Event{want})
			if out.Clean {
				t.Errorf("%s: Clean with an alert open", what)
			}
		}
	}
}

func TestChangeOfOpenAlertUpdatesOrEscalates(t *testing.T) {
	const (
		low      = decide.SeverityLow
		medium   = decide.SeverityMedium
		high     = decide.SeverityHigh
		critical = decide.SeverityCritical
	)
	_, lines := alrProof(t)
	for _, c := range []struct {
		name      string
		sev, peak decide.Severity
		op        decide.Op
		now       decide.Severity
		kind      EventKind
		wantPeak  decide.Severity
	}{
		{"same severity, new text", medium, medium, decide.OpUpdate, medium, EventUpdate, medium},
		{"raised", medium, medium, decide.OpUpdate, high, EventEscalate, high},
		{"raised, still below the peak", medium, critical, decide.OpUpdate, high, EventEscalate, critical},
		{"lowered", high, high, decide.OpUpdate, medium, EventUpdate, high},
		{"lowered, below the peak", high, critical, decide.OpUpdate, low, EventUpdate, critical},
		{"open of an open alert", medium, medium, decide.OpOpen, medium, EventUpdate, medium},
		{"open of an open alert, raised", medium, medium, decide.OpOpen, critical, EventEscalate, critical},
	} {
		t.Run(c.name, func(t *testing.T) {
			a := alrStored(t, c.sev, c.peak)
			f := alrNews(t, c.now)
			// The last clean time of the input belongs to alerts that open
			// now, not to this one.
			out := Transition(Input{Open: []Alert{a}, Changes: []decide.Change{{Op: c.op, Finding: f, At: alrT0}},
				LastClean: alrT0.Add(-time.Minute), Now: alrNow})
			b := a
			b.Severity, b.Peak, b.Expected, b.Value, b.Lines, b.Noticed = c.now, c.wantPeak, f.Expected, f.Value, lines, alrNow
			alrSame(t, c.name, out.Events, []Event{{Kind: c.kind, Alert: b, Was: c.sev, At: alrNow}})
			if out.Clean {
				t.Errorf("Clean with an alert open")
			}
		})
	}
}

func TestResolveClosesAlertWithItsOwnFields(t *testing.T) {
	a := alrStored(t, decide.SeverityHigh, decide.SeverityCritical)
	// The finding of the change says other things than the alert; the notice
	// of the end shows what the alert said, but the line now in force.
	f := alrNews(t, decide.SeverityLow)
	out := Transition(Input{Open: []Alert{a}, Changes: []decide.Change{{Op: decide.OpResolve, Finding: f, At: alrT0}},
		LastClean: alrT0.Add(-time.Minute), Now: alrNow})
	b := a
	b.Open, b.Resolved, b.Expected = false, alrNow, f.Expected
	alrSame(t, "resolve", out.Events, []Event{{Kind: EventResolve, Alert: b, Was: decide.SeverityHigh, At: alrNow}})
	if !out.Clean {
		t.Errorf("not Clean after the only alert resolved")
	}
}

func TestResolveOfNothingOpenGivesNothing(t *testing.T) {
	a := alrStored(t, decide.SeverityHigh, decide.SeverityHigh)
	zone := alrNews(t, decide.SeverityHigh)
	zone.Rule = decide.RuleZone
	for _, c := range []struct {
		name  string
		open  []Alert
		f     decide.Finding
		clean bool
	}{
		{"nothing open", nil, alrNews(t, decide.SeverityHigh), true},
		{"another rule of the check is open", []Alert{a}, zone, false},
	} {
		out := Transition(Input{Open: c.open, Changes: []decide.Change{{Op: decide.OpResolve, Finding: c.f, At: alrNow}}, Now: alrNow})
		if len(out.Events) != 0 || out.Clean != c.clean {
			t.Errorf("%s: events %v, Clean %v; want none, Clean %v", c.name, alrBrief(out.Events), out.Clean, c.clean)
		}
	}
}

func TestChangeFindsOpenAlertByIdentity(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
	zone := alrNews(t, decide.SeverityMedium)
	zone.Rule = decide.RuleZone
	shouting := alrNews(t, decide.SeverityMedium)
	shouting.Check = obs.RecordsKey(alrName(t, "CORP.TEST."), alrName(t, "WWW.CORP.TEST."), dnswire.TypeA)
	for _, c := range []struct {
		name string
		ch   decide.Change
		want string
	}{
		{"another rule opens its own alert", decide.Change{Op: decide.OpUpdate, Finding: zone}, "open 0 zone three new proof lines"},
		{"a check in capitals updates the alert", decide.Change{Op: decide.OpUpdate, Finding: shouting}, "update 7 record-set three new proof lines"},
		{"a check in capitals resolves the alert", decide.Change{Op: decide.OpResolve, Finding: shouting},
			"resolve 7 record-set 10.53.0.11:53 ns1.corp.test. 10.53.0.97"},
	} {
		out := Transition(Input{Open: []Alert{a}, Changes: []decide.Change{c.ch}, Now: alrNow})
		if got := alrBrief(out.Events); !slices.Equal(got, []string{c.want}) {
			t.Errorf("%s: events %q, want %q", c.name, got, c.want)
		}
	}
}

// A refresh tells nothing: its event keeps Noticed, so the time to the next
// reminder runs on, and it takes the servers, value and Expected of the
// finding, as an update would store them. A reminder that is due takes them
// in place of a refresh of its own, so the alert still gets one event.
func TestRefreshKeepsNoticedAndGivesWayToAReminder(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityHigh)
	f := alrNews(t, decide.SeverityMedium)
	refreshed := a
	refreshed.Expected, refreshed.Value, refreshed.Lines = f.Expected, f.Value, lines(f.Seen)
	refresh := []decide.Change{{Op: decide.OpRefresh, Finding: f, At: alrNow}}

	out := Transition(Input{Open: []Alert{a}, Changes: refresh, Now: alrNow})
	alrSame(t, "a refresh", out.Events, []Event{{Kind: EventRefresh, Alert: refreshed, Was: decide.SeverityMedium, At: alrNow}})
	if out.Clean {
		t.Error("a refresh leaves the alert open, but the check is Clean")
	}

	reminded := refreshed
	reminded.Noticed = alrNow
	due := Input{Open: []Alert{a}, Changes: refresh, Now: alrNow, Policy: Policy{Remind: time.Hour}}
	alrSame(t, "a refresh and a due reminder", Transition(due).Events,
		[]Event{{Kind: EventReminder, Alert: reminded, Was: decide.SeverityMedium, At: alrNow}})

	due.Policy.Remind = 2 * time.Hour
	alrSame(t, "a refresh before the reminder is due", Transition(due).Events,
		[]Event{{Kind: EventRefresh, Alert: refreshed, Was: decide.SeverityMedium, At: alrNow}})

	if out := Transition(Input{Changes: refresh, Now: alrNow}); len(out.Events) != 0 || !out.Clean {
		t.Errorf("a refresh with nothing open: events %v, Clean %v; want none, Clean", alrBrief(out.Events), out.Clean)
	}
	update := decide.Change{Op: decide.OpUpdate, Finding: alrNews(t, decide.SeverityMedium), At: alrNow}
	if out := Transition(Input{Open: []Alert{a}, Changes: append(refresh, update), Now: alrNow}); len(out.Events) != 1 || out.Events[0].Kind != EventRefresh {
		t.Errorf("a refresh, then an update of the same alert: events %v; want the refresh alone", alrBrief(out.Events))
	}
}

func TestUnknownOpIsIgnored(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
	for _, op := range []decide.Op{0, 5, 255} {
		ch := []decide.Change{{Op: op, Finding: alrNews(t, decide.SeverityHigh), At: alrNow}}
		if out := Transition(Input{Changes: ch, Now: alrNow}); len(out.Events) != 0 || !out.Clean {
			t.Errorf("op %d with nothing open: events %v, Clean %v; want none, Clean", op, alrBrief(out.Events), out.Clean)
		}
		if out := Transition(Input{Open: []Alert{a}, Changes: ch, Now: alrNow}); len(out.Events) != 0 || out.Clean {
			t.Errorf("op %d of an open alert: events %v, Clean %v; want none, not Clean", op, alrBrief(out.Events), out.Clean)
		}
	}
}

// No alert may get two events in one call, and a second row of one
// identity must never be notified.
func TestOnlyFirstAlertAndFirstChangeOfIdentityCount(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
	dup := alrStored(t, decide.SeverityHigh, decide.SeverityCritical)
	dup.ID, dup.Value = 8, "the second row"
	update := decide.Change{Op: decide.OpUpdate, Finding: alrNews(t, decide.SeverityHigh), At: alrNow}
	resolve := decide.Change{Op: decide.OpResolve, Finding: alrNews(t, decide.SeverityHigh), At: alrNow}
	v1 := decide.Finding{Rule: decide.RuleNotCovered, Severity: decide.SeverityMedium, Check: alrKey(t, "mail.corp.test."), Value: "v1"}
	v2 := v1
	v2.Severity, v2.Value = decide.SeverityHigh, "v2"
	for _, c := range []struct {
		name    string
		open    []Alert
		changes []decide.Change
		remind  time.Duration
		want    string
	}{
		{"two rows of one identity, an update", []Alert{a, dup}, []decide.Change{update}, 0, "escalate 7 record-set three new proof lines"},
		{"two rows of one identity, a resolve", []Alert{a, dup}, []decide.Change{resolve}, 0,
			"resolve 7 record-set 10.53.0.11:53 ns1.corp.test. 10.53.0.97"},
		{"two rows of one identity, both due", []Alert{a, dup}, nil, time.Minute,
			"reminder 7 record-set 10.53.0.11:53 ns1.corp.test. 10.53.0.97"},
		{"two opens of one identity", nil, []decide.Change{{Op: decide.OpOpen, Finding: v1}, {Op: decide.OpOpen, Finding: v2}}, 0,
			"open 0 not-covered v1"},
		{"a resolve, then an update", []Alert{a}, []decide.Change{resolve, update}, 0,
			"resolve 7 record-set 10.53.0.11:53 ns1.corp.test. 10.53.0.97"},
		{"an update, then a resolve", []Alert{a}, []decide.Change{update, resolve}, time.Minute, "escalate 7 record-set three new proof lines"},
		{"a resolve of nothing open, then an open", nil, []decide.Change{{Op: decide.OpResolve, Finding: v1}, {Op: decide.OpOpen, Finding: v2}}, 0, ""},
	} {
		out := Transition(Input{Open: c.open, Changes: c.changes, Now: alrNow, Policy: Policy{Remind: c.remind}})
		want := []string{c.want}
		if c.want == "" {
			want = nil
		}
		if got := alrBrief(out.Events); !slices.Equal(got, want) {
			t.Errorf("%s: events %q, want %q", c.name, got, want)
		}
	}
}

func TestEventsFollowChangesThenRemindersInOpenOrder(t *testing.T) {
	k := alrKey(t, "www.corp.test.")
	stored := func(id int64, r decide.Rule) Alert {
		a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
		a.ID, a.Rule, a.Value = id, r, "old"
		return a
	}
	recordSet, zone, notCovered := stored(1, decide.RuleRecordSet), stored(2, decide.RuleZone), stored(3, decide.RuleNotCovered)
	change := func(op decide.Op, r decide.Rule) decide.Change {
		return decide.Change{Op: op, Finding: decide.Finding{Rule: r, Severity: decide.SeverityHigh, Check: k, Value: "new"}, At: alrNow}
	}
	for _, c := range []struct {
		name    string
		open    []Alert
		changes []decide.Change
		want    []string
	}{
		{"changes, then a reminder", []Alert{notCovered, recordSet, zone},
			[]decide.Change{change(decide.OpOpen, decide.RuleNameServers), change(decide.OpUpdate, decide.RuleNotCovered),
				change(decide.OpResolve, decide.RuleRecordSet)},
			[]string{"open 0 nameservers new", "escalate 3 not-covered new", "resolve 1 record-set old", "reminder 2 zone old"}},
		{"reminders only", []Alert{zone, notCovered, recordSet}, nil,
			[]string{"reminder 2 zone old", "reminder 3 not-covered old", "reminder 1 record-set old"}},
	} {
		out := Transition(Input{Open: c.open, Changes: c.changes, Now: alrNow, Policy: Policy{Remind: time.Minute}})
		if got := alrBrief(out.Events); !slices.Equal(got, c.want) {
			t.Errorf("%s: events\n got  %q\n want %q", c.name, got, c.want)
		}
	}
}

func TestReminderOnlyWhenOnAndDue(t *testing.T) {
	a := alrStored(t, decide.SeverityHigh, decide.SeverityCritical)
	since := alrNow.Sub(a.Noticed)
	reminded := a
	reminded.Noticed = alrNow
	reminder := []Event{{Kind: EventReminder, Alert: reminded, Was: decide.SeverityHigh, At: alrNow}}
	for _, c := range []struct {
		name   string
		remind time.Duration
		want   []Event
	}{
		{"off by default", 0, nil},
		{"off when negative", -time.Minute, nil},
		{"exactly at the interval", since, reminder},
		{"one nanosecond before the interval", since + time.Nanosecond, nil},
		{"long after the interval", time.Minute, reminder},
	} {
		out := Transition(Input{Open: []Alert{a}, Now: alrNow, Policy: Policy{Remind: c.remind}})
		alrSame(t, c.name, out.Events, c.want)
		if out.Clean {
			t.Errorf("%s: Clean with an alert open", c.name)
		}
	}
	// An alert that got an event now was just notified.
	for _, op := range []decide.Op{decide.OpUpdate, decide.OpResolve} {
		ch := []decide.Change{{Op: op, Finding: alrNews(t, decide.SeverityHigh), At: alrNow}}
		out := Transition(Input{Open: []Alert{a}, Changes: ch, Now: alrNow, Policy: Policy{Remind: since}})
		if len(out.Events) != 1 || out.Events[0].Kind == EventReminder {
			t.Errorf("%v of a due alert: events %q, want one, not a reminder", op, alrBrief(out.Events))
		}
	}
}

func TestCleanOnlyWhenNoAlertStaysOpenAndNothingFailed(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
	zone := a
	zone.ID, zone.Rule = 8, decide.RuleZone
	resolve := []decide.Change{{Op: decide.OpResolve, Finding: alrNews(t, decide.SeverityMedium), At: alrNow}}
	open := []decide.Change{{Op: decide.OpOpen, Finding: alrNews(t, decide.SeverityMedium), At: alrNow}}
	for _, c := range []struct {
		name    string
		open    []Alert
		changes []decide.Change
		failed  bool
		clean   bool
	}{
		{"nothing open, nothing found", nil, nil, false, true},
		{"nothing open, an answer failed", nil, nil, true, false},
		{"an alert opens", nil, open, false, false},
		{"an alert stays open", []Alert{a}, nil, false, false},
		{"the only alert resolves", []Alert{a}, resolve, false, true},
		{"the only alert resolves, an answer failed", []Alert{a}, resolve, true, false},
		{"one of two alerts resolves", []Alert{a, zone}, resolve, false, false},
	} {
		out := Transition(Input{Open: c.open, Changes: c.changes, Failed: c.failed, Now: alrNow})
		if out.Clean != c.clean {
			t.Errorf("%s: Clean %v, want %v", c.name, out.Clean, c.clean)
		}
	}
}

func TestPeakIsHighestSeveritySoFar(t *testing.T) {
	k := alrKey(t, "www.corp.test.")
	var open []Alert
	now := alrT0
	for i, c := range []struct {
		op   decide.Op // 0: no change, so a reminder is due
		sev  decide.Severity
		kind EventKind
		peak decide.Severity
	}{
		{decide.OpOpen, decide.SeverityMedium, EventOpen, decide.SeverityMedium},
		{decide.OpUpdate, decide.SeverityHigh, EventEscalate, decide.SeverityHigh},
		{decide.OpUpdate, decide.SeverityLow, EventUpdate, decide.SeverityHigh},
		{0, 0, EventReminder, decide.SeverityHigh},
		{decide.OpUpdate, decide.SeverityCritical, EventEscalate, decide.SeverityCritical},
		{decide.OpUpdate, decide.SeverityMedium, EventUpdate, decide.SeverityCritical},
		{decide.OpResolve, decide.SeverityMedium, EventResolve, decide.SeverityCritical},
	} {
		now = now.Add(2 * time.Minute)
		var changes []decide.Change
		if c.op != 0 {
			f := decide.Finding{Rule: decide.RuleRecordSet, Severity: c.sev, Check: k, Value: fmt.Sprintf("v%d", i)}
			changes = []decide.Change{{Op: c.op, Finding: f, At: now}}
		}
		out := Transition(Input{Open: open, Changes: changes, Now: now, Policy: Policy{Remind: time.Minute}})
		if len(out.Events) != 1 || out.Events[0].Kind != c.kind || out.Events[0].Alert.Peak != c.peak {
			t.Fatalf("round %d: events %s; want one %s with peak %v", i, alrShow(out.Events), alrKind(c.kind), c.peak)
		}
		a := out.Events[0].Alert
		if c.kind == EventOpen {
			a.ID = 1
		}
		open = []Alert{a}
	}
}

// alrGen draws inputs of Transition, each from its own case of the fixed
// seed.
type alrGen struct {
	rng   *rand.Rand
	keys  [][]obs.Key
	seen  []decide.Seen
	lines []Line
}

// alrKeys gives three checks, each as a key in lower case and in capitals,
// which have one identity.
func alrKeys(t testing.TB) [][]obs.Key {
	t.Helper()
	corp, shouting := alrName(t, "corp.test."), alrName(t, "CORP.TEST.")
	return [][]obs.Key{
		{alrKey(t, "www.corp.test."), obs.RecordsKey(shouting, alrName(t, "WWW.CORP.TEST."), dnswire.TypeA)},
		{alrKey(t, "mail.corp.test."), obs.RecordsKey(shouting, alrName(t, "Mail.Corp.Test."), dnswire.TypeA)},
		{obs.DelegationKey(corp), obs.DelegationKey(shouting)},
	}
}

func alrNewGen(t testing.TB, c int) *alrGen {
	seen, lines := alrProof(t)
	return &alrGen{rng: alrRand(c), keys: alrKeys(t), seen: seen, lines: lines}
}

func (g *alrGen) alert(k obs.Key) Alert {
	sev := alrPick(g.rng, alrSeverities...)
	return Alert{
		ID:        int64(1 + g.rng.IntN(4)),
		Open:      true,
		Rule:      alrPick(g.rng, decide.RuleNameServers, decide.RuleRecordSet, decide.RuleNotCovered),
		Severity:  sev,
		Peak:      max(sev, alrPick(g.rng, alrSeverities...)),
		Check:     k,
		Expected:  alrPick(g.rng, "", "10.53.0.81"),
		Value:     alrPick(g.rng, "v1", "v2", "v3"),
		Lines:     slices.Clone(g.lines[:g.rng.IntN(len(g.lines)+1)]),
		Opened:    alrT0.Add(-2 * time.Hour),
		LastClean: alrPick(g.rng, time.Time{}, alrT0.Add(-3*time.Hour)),
		Noticed:   alrT0.Add(-time.Duration(g.rng.IntN(120)) * time.Minute),
	}
}

func (g *alrGen) change(k obs.Key, now time.Time) decide.Change {
	return decide.Change{Op: alrPick(g.rng, 0, decide.OpOpen, decide.OpUpdate, decide.OpResolve, decide.OpRefresh, 5), At: now,
		Finding: decide.Finding{Rule: alrPick(g.rng, decide.RuleNameServers, decide.RuleRecordSet, decide.RuleNotCovered),
			Severity: alrPick(g.rng, alrSeverities...), Check: k, Expected: alrPick(g.rng, "", "10.53.0.80"),
			Seen: slices.Clone(g.seen[:g.rng.IntN(len(g.seen)+1)]), Value: alrPick(g.rng, "v1", "v2", "v3")}}
}

// input is any input of one check: duplicate rows and changes of one
// identity, unknown ops, due and fresh alerts all occur.
func (g *alrGen) input() Input {
	keys := alrPick(g.rng, g.keys...)
	in := Input{Failed: g.rng.IntN(2) == 0, LastClean: alrPick(g.rng, time.Time{}, alrT0.Add(-time.Hour)), Now: alrNow,
		Policy: Policy{Remind: alrPick(g.rng, 0, time.Minute, time.Hour)}}
	for range g.rng.IntN(5) {
		in.Open = append(in.Open, g.alert(alrPick(g.rng, keys...)))
	}
	for range g.rng.IntN(5) {
		in.Changes = append(in.Changes, g.change(alrPick(g.rng, keys...), alrNow))
	}
	return in
}

// alrClone copies every slice that Transition could reach.
func alrClone(in Input) Input {
	c := in
	c.Open = slices.Clone(in.Open)
	for i := range c.Open {
		c.Open[i].Lines = slices.Clone(in.Open[i].Lines)
	}
	c.Changes = slices.Clone(in.Changes)
	for i := range c.Changes {
		seen := slices.Clone(in.Changes[i].Finding.Seen)
		for j := range seen {
			seen[j].Answer.Wire = slices.Clone(seen[j].Answer.Wire)
		}
		c.Changes[i].Finding.Seen = seen
	}
	return c
}

// alrExercised fails a property test whose cases gave no event at all: a
// function that does nothing would hold every property.
func alrExercised(t *testing.T, events int) {
	t.Helper()
	if events == 0 {
		t.Fatalf("seed %d: no case gave an event, so the property was not tested", alrSeed)
	}
}

func TestTransitionLeavesItsInputUnchanged(t *testing.T) {
	events := 0
	for c := range alrCases {
		in := alrNewGen(t, c).input()
		before := alrClone(in)
		events += len(Transition(in).Events)
		if !reflect.DeepEqual(in, before) {
			t.Fatalf("seed %d case %d: Transition changed its input", alrSeed, c)
		}
	}
	alrExercised(t, events)
}

func TestTransitionGivesEqualOutputForEqualInput(t *testing.T) {
	events := 0
	for c := range alrCases {
		in, twin := alrNewGen(t, c).input(), alrNewGen(t, c).input()
		first := Transition(in)
		events += len(first.Events)
		if again := Transition(in); !reflect.DeepEqual(first, again) {
			t.Fatalf("seed %d case %d: a second call gave%s\nthe first%s", alrSeed, c, alrShow(again.Events), alrShow(first.Events))
		}
		if other := Transition(twin); !reflect.DeepEqual(first, other) {
			t.Fatalf("seed %d case %d: an equal input gave%s\nthe first%s", alrSeed, c, alrShow(other.Events), alrShow(first.Events))
		}
	}
	alrExercised(t, events)
}

// alrFollowChanges fails unless the events of one call come from distinct
// identities: those of changes first, in the order of their changes, then
// reminders of open alerts.
func alrFollowChanges(t *testing.T, where string, open []Alert, changes []decide.Change, events []Event) {
	t.Helper()
	var order []string
	for _, c := range changes {
		id := Identity(c.Finding.Rule, c.Finding.Check)
		if c.Op >= decide.OpOpen && c.Op <= decide.OpResolve && !slices.Contains(order, id) {
			order = append(order, id)
		}
	}
	var openIDs []string
	for _, a := range open {
		openIDs = append(openIDs, a.Identity())
	}
	had := map[string]bool{}
	next, reminders := 0, false
	for _, e := range events {
		id := e.Alert.Identity()
		if had[id] {
			t.Fatalf("%s: two events of %q:%s", where, id, alrShow(events))
		}
		had[id] = true
		if e.Kind == EventReminder || e.Kind == EventRefresh {
			reminders = true
			if !slices.Contains(openIDs, id) {
				t.Fatalf("%s: a %s of %q, which was not open:%s", where, alrKind(e.Kind), id, alrShow(events))
			}
			continue
		}
		if reminders {
			t.Fatalf("%s: an event of a change after a reminder:%s", where, alrShow(events))
		}
		for next < len(order) && order[next] != id {
			next++
		}
		if next == len(order) {
			t.Fatalf("%s: event of %q is not that of a change, or out of order:%s", where, id, alrShow(events))
		}
	}
}

func TestOneOpenAlertProperty(t *testing.T) {
	keys := alrKeys(t)
	rules := []decide.Rule{decide.RuleNameServers, decide.RuleRecordSet, decide.RuleNotCovered}
	ops := []decide.Op{0, decide.OpOpen, decide.OpUpdate, decide.OpResolve, decide.OpRefresh, 5}
	events := 0
	for c := range alrCases {
		rng := alrRand(c)
		stored := map[int64]Alert{}
		lastID := int64(0)
		now := alrT0
		remind := alrPick(rng, 0, time.Minute)
		for call := range 50 {
			where := fmt.Sprintf("seed %d case %d call %d", alrSeed, c, call)
			now = now.Add(time.Duration(rng.IntN(3)) * 40 * time.Second)
			check := alrPick(rng, keys...)
			var open []Alert
			for _, id := range slices.Sorted(maps.Keys(stored)) {
				if stored[id].Check.String() == check[0].String() {
					open = append(open, stored[id])
				}
			}
			changes := make([]decide.Change, rng.IntN(5))
			for i := range changes {
				changes[i] = decide.Change{Op: alrPick(rng, ops...), At: now, Finding: decide.Finding{
					Rule: alrPick(rng, rules...), Severity: alrPick(rng, alrSeverities...), Check: alrPick(rng, check...),
					Value: alrPick(rng, "v1", "v2", "v3")}}
			}
			out := Transition(Input{Open: open, Changes: changes, Now: now, Policy: Policy{Remind: remind}})
			events += len(out.Events)
			if len(out.Events) > len(changes)+len(open) {
				t.Fatalf("%s: %d events from %d changes and %d open alerts", where, len(out.Events), len(changes), len(open))
			}
			alrFollowChanges(t, where, open, changes, out.Events)
			for _, e := range out.Events {
				if _, ok := alrKindWords[e.Kind]; !ok || (e.Kind == EventOpen) != (e.Alert.ID == 0) || e.Alert.Open != (e.Kind != EventResolve) {
					t.Fatalf("%s: event %s", where, alrShow([]Event{e}))
				}
				if e.Kind == EventOpen {
					lastID++
					e.Alert.ID = lastID
					stored[lastID] = e.Alert
					continue
				}
				if was, ok := stored[e.Alert.ID]; !ok || was.Identity() != e.Alert.Identity() {
					t.Fatalf("%s: event of alert %d, which is not open with identity %q", where, e.Alert.ID, e.Alert.Identity())
				} else if e.Kind == EventRefresh && !e.Alert.Noticed.Equal(was.Noticed) {
					t.Fatalf("%s: a refresh moved Noticed from %v to %v", where, was.Noticed, e.Alert.Noticed)
				}
				if e.Kind == EventResolve {
					delete(stored, e.Alert.ID)
				} else {
					stored[e.Alert.ID] = e.Alert
				}
			}
			count := map[string]int{}
			for _, a := range stored {
				if !a.Open {
					continue
				}
				if count[a.Identity()]++; count[a.Identity()] > 1 {
					t.Fatalf("%s: two open alerts of %q", where, a.Identity())
				}
			}
		}
	}
	alrExercised(t, events)
}

// alrState is what decide finds for one identity (severity 0: nothing),
// or an open alert of the model with its peak.
type alrState struct {
	val       string
	sev, peak decide.Severity
}

// alrModel is a copy of the table of Check in dev/models/alert.tla, with two
// identities: the oracle of TestTransitionMatchesModelProperty.
type alrModel struct {
	remind bool
	world  [2]alrState
	open   [2]*alrState
	due    [2]bool
}

// check is Check(i): the kind of the emitted event ("" for none) and the
// alert as the event shows it.
func (m *alrModel) check(i int) (string, alrState) {
	a, w := m.open[i], m.world[i]
	var kind string
	var b alrState
	switch {
	case a == nil && w.sev == 0:
		return "", alrState{}
	case a == nil:
		kind, b = "open", alrState{w.val, w.sev, w.sev}
		m.open[i] = &b
	case w.sev == 0:
		kind, b = "resolve", *a
		m.open[i] = nil
	case a.val != w.val || a.sev != w.sev:
		kind, b = "update", alrState{w.val, w.sev, max(a.peak, w.sev)}
		if w.sev > a.sev {
			kind = "escalate"
		}
		m.open[i] = &b
	case m.remind && m.due[i]:
		kind, b = "reminder", *a
	default:
		return "", alrState{}
	}
	m.due[i] = false
	return kind, b
}

func (m *alrModel) tick() {
	for i := range m.due {
		m.due[i] = m.due[i] || m.open[i] != nil
	}
}

// alrMinimums are the minimum severities of two channels: one hears every
// alert, the other only alerts that reached high.
var alrMinimums = []decide.Severity{decide.SeverityLow, decide.SeverityHigh}

func alrRows(peak decide.Severity) []int {
	var rows []int
	for c, m := range alrMinimums {
		if m <= peak {
			rows = append(rows, c)
		}
	}
	return rows
}

// alrDecide is the change that decide gives when it finds w for the
// identity of the open alert a: another value is news, as a new line is.
func alrDecide(a *Alert, w alrState, k obs.Key, now time.Time) []decide.Change {
	f := decide.Finding{Rule: decide.RuleRecordSet, Severity: w.sev, Check: k, Value: w.val}
	switch {
	case a == nil && w.sev == 0:
		return nil
	case a == nil:
		return []decide.Change{{Op: decide.OpOpen, Finding: f, At: now}}
	case w.sev == 0:
		return []decide.Change{{Op: decide.OpResolve, Finding: a.Finding(), At: now}}
	case a.Value != w.val || a.Severity != w.sev:
		return []decide.Change{{Op: decide.OpUpdate, Finding: f, At: now}}
	}
	return nil
}

func TestTransitionMatchesModelProperty(t *testing.T) {
	keys := []obs.Key{alrKey(t, "a.corp.test."), alrKey(t, "b.corp.test.")}
	medium, high := decide.SeverityMedium, decide.SeverityHigh
	diffs := []alrState{{}, {"v1", medium, 0}, {"v1", high, 0}, {"v2", medium, 0}, {"v2", high, 0}}
	for c := range alrCases {
		rng := alrRand(c)
		remind := alrPick(rng, 0, time.Minute)
		m := alrModel{remind: remind > 0}
		var stored [2]*Alert
		var heard [2]map[int]bool
		lastID := int64(0)
		now := alrT0
		for act := range 40 {
			where := fmt.Sprintf("seed %d case %d action %d", alrSeed, c, act)
			i := rng.IntN(2)
			switch rng.IntN(6) {
			case 0, 1:
				d := alrPick(rng, diffs...)
				for d == m.world[i] {
					d = alrPick(rng, diffs...)
				}
				m.world[i] = d
				continue
			case 2:
				now = now.Add(remind + time.Second)
				m.tick()
				continue
			}
			changes := alrDecide(stored[i], m.world[i], keys[i], now)
			var open []Alert
			if stored[i] != nil {
				open = []Alert{*stored[i]}
			}
			out := Transition(Input{Open: open, Changes: changes, Now: now, Policy: Policy{Remind: remind}})
			kind, b := m.check(i)
			if kind == "" {
				if len(out.Events) != 0 {
					t.Fatalf("%s: Transition gave%s; the model no event", where, alrShow(out.Events))
				}
			} else {
				if len(out.Events) != 1 {
					t.Fatalf("%s: Transition gave%s; the model %s %v", where, alrShow(out.Events), kind, b)
				}
				e := out.Events[0]
				if alrKind(e.Kind) != kind || e.Alert.Value != b.val || e.Alert.Severity != b.sev || e.Alert.Peak != b.peak {
					t.Fatalf("%s: Transition gave%s; the model %s %v", where, alrShow(out.Events), kind, b)
				}
				rows := alrRows(e.Alert.Peak)
				if !slices.Equal(rows, alrRows(b.peak)) {
					t.Fatalf("%s: channels %v, the model %v", where, rows, alrRows(b.peak))
				}
				if heard[i] == nil {
					heard[i] = map[int]bool{}
				}
				if kind == "resolve" {
					for ch := range heard[i] {
						if !slices.Contains(rows, ch) {
							t.Fatalf("%s: the resolve does not reach channel %d, which heard of the alert", where, ch)
						}
					}
					clear(heard[i])
					stored[i] = nil
				} else {
					for _, ch := range rows {
						heard[i][ch] = true
					}
					a := e.Alert
					if e.Kind == EventOpen {
						lastID++
						a.ID = lastID
					}
					stored[i] = &a
				}
			}
			s, o := stored[i], m.open[i]
			if (s == nil) != (o == nil) || s != nil && (s.Value != o.val || s.Severity != o.sev || s.Peak != o.peak) {
				t.Fatalf("%s: open alert %v, the model %v", where, s, o)
			}
			if out.Clean != (o == nil) {
				t.Fatalf("%s: Clean %v with model alert %v", where, out.Clean, o)
			}
		}
	}
}
