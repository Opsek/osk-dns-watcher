package decide

import (
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// dngServers are the servers of the zone, in the order that the rows name
// them by index.
var dngServers = []struct{ host, addr string }{
	{"ns1.corp.test.", "10.53.0.11:53"},
	{"ns2.corp.test.", "10.53.0.12:53"},
	{"ns3.corp.test.", "10.53.0.13:53"},
	{"ns4.corp.test.", "10.53.0.14:53"},
}

const (
	dngTok1   = `"t0ken1"`
	dngTok2   = `"t0ken2"`
	dngInLine = "in 10.53.0.0/24"
	dngNow    = 60 * time.Minute // after decT0
)

// dngResult builds an answer from a word: "nodata", "noname", "fail", or
// records separated by ";", a record that starts with "CNAME " being a
// CNAME and any other having the type of the check.
func dngResult(t testing.TB, owner string, typ dnswire.Type, spec string) obs.Result {
	t.Helper()
	switch spec {
	case "nodata":
		return decNoData(t, "corp.test.")
	case "noname":
		return decNoName(t, "corp.test.")
	case "fail":
		return decFailure(obs.ReasonTimeout)
	}
	var set []dnswire.Record
	for _, d := range strings.Split(spec, ";") {
		rt := typ
		if rest, ok := strings.CutPrefix(d, "CNAME "); ok {
			rt, d = dnswire.TypeCNAME, rest
		}
		r := decRR(t, owner, rt, d)
		r.TTL = uint32(len(set)+1) * 111
		set = append(set, r)
	}
	return decAs(t, obs.RecordsResult(obs.Records{Set: set}), "records")
}

func dngAnswers(t testing.TB, owner string, typ dnswire.Type, specs ...string) []obs.Answer {
	t.Helper()
	var out []obs.Answer
	for i, s := range specs {
		out = append(out, decAnswer(t, dngServers[i].host, dngServers[i].addr, dngResult(t, owner, typ, s)))
	}
	return out
}

// dngKey is the records check of owner/typ of corp.test.
func dngKey(t testing.TB, owner string, typ dnswire.Type) obs.Key {
	t.Helper()
	return decRecordsKey(t, "corp.test.", owner, typ)
}

// dngObserve is a run in which the check sits in the zone that the file
// expects, so that no zone finding comes up.
func dngObserve(t testing.TB, owner string, typ dnswire.Type, specs ...string) obs.Observation {
	t.Helper()
	return decObservation(dngKey(t, owner, typ), decName(t, "corp.test."), nil, dngAnswers(t, owner, typ, specs...)...)
}

// dngSeenOf builds Seen from "<answer index> <text>".
func dngSeenOf(t testing.TB, answers []obs.Answer, texts ...string) []Seen {
	t.Helper()
	var seen []Seen
	for _, tx := range texts {
		idx, text, _ := strings.Cut(tx, " ")
		i, err := strconv.Atoi(idx)
		if err != nil {
			t.Fatalf("bad seen %q", tx)
		}
		seen = append(seen, Seen{Answer: answers[i], Text: text})
	}
	return seen
}

// ---- Disagree ----

func TestDisagreeFunction(t *testing.T) {
	const www, acme = "www.corp.test.", "_acme-challenge.corp.test."
	rows := []struct {
		name  string
		owner string
		typ   dnswire.Type
		specs []string
		want  bool
	}{
		{"two different sets", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.88"}, true},
		{"two equal sets", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.81"}, false},
		{"one answer", www, dnswire.TypeA, []string{"10.53.0.81"}, false},
		{"the order of a set is no difference", www, dnswire.TypeA, []string{"10.53.0.81;10.53.0.82", "10.53.0.82;10.53.0.81"}, false},
		{"a repeated record is no difference", www, dnswire.TypeA, []string{"10.53.0.81;10.53.0.81", "10.53.0.81"}, false},
		{"one record more", www, dnswire.TypeA, []string{"10.53.0.81;10.53.0.82", "10.53.0.81"}, true},
		{"names in another case are equal", www, dnswire.TypeCNAME, []string{"edge.dnshost.test.", "Edge.Dnshost.Test."}, false},
		{"no data and no such name are both none", www, dnswire.TypeA, []string{"nodata", "noname"}, false},
		{"no data against records", www, dnswire.TypeA, []string{"nodata", "10.53.0.81"}, true},
		{"no such name against records", www, dnswire.TypeA, []string{"10.53.0.81", "noname"}, true},
		{"a failure and one answer", www, dnswire.TypeA, []string{"10.53.0.81", "fail"}, false},
		{"a failure beside two different sets", www, dnswire.TypeA, []string{"10.53.0.81", "fail", "10.53.0.88"}, true},
		{"only failures", www, dnswire.TypeA, []string{"fail", "fail"}, false},
		{"the third answer differs", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.81", "10.53.0.88"}, true},
		{"the last answer differs", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.81", "10.53.0.81", "10.53.0.88"}, true},
		{"a CNAME against a TXT set", acme, dnswire.TypeTXT, []string{dngTok1, "CNAME edge.dnshost.test."}, true},
		{"two TXT sets", acme, dnswire.TypeTXT, []string{dngTok1, dngTok2}, true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := Disagree(dngObserve(t, r.owner, r.typ, r.specs...)); got != r.want {
				t.Errorf("Disagree is %v, want %v", got, r.want)
			}
		})
	}
}

// ---- Sets ----

func TestSets(t *testing.T) {
	const www, acme = "www.corp.test.", "_acme-challenge.corp.test."
	rows := []struct {
		name  string
		owner string
		typ   dnswire.Type
		specs []string
		want  []string // "<answer index> <text>"
	}{
		{"two sets", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.88"}, []string{"0 10.53.0.81", "1 10.53.0.88"}},
		{"the answer order is kept", www, dnswire.TypeA, []string{"10.53.0.88", "10.53.0.81", "10.53.0.89"},
			[]string{"0 10.53.0.88", "1 10.53.0.81", "2 10.53.0.89"}},
		{"equal sets are each listed", www, dnswire.TypeA, []string{"10.53.0.81", "10.53.0.81"}, []string{"0 10.53.0.81", "1 10.53.0.81"}},
		{"a failure is left out", www, dnswire.TypeA, []string{"10.53.0.81", "fail", "10.53.0.88"}, []string{"0 10.53.0.81", "2 10.53.0.88"}},
		{"a failure first", www, dnswire.TypeA, []string{"fail", "10.53.0.81"}, []string{"1 10.53.0.81"}},
		{"a failure last", www, dnswire.TypeA, []string{"10.53.0.81", "fail"}, []string{"0 10.53.0.81"}},
		{"only failures", www, dnswire.TypeA, []string{"fail", "fail"}, nil},
		{"no answer", www, dnswire.TypeA, nil, nil},
		{"no data is none", www, dnswire.TypeA, []string{"nodata", "10.53.0.81"}, []string{"0 none", "1 10.53.0.81"}},
		{"no such name is none", www, dnswire.TypeA, []string{"10.53.0.81", "noname"}, []string{"0 10.53.0.81", "1 none"}},
		{"no data and no such name are alike", www, dnswire.TypeA, []string{"nodata", "noname"}, []string{"0 none", "1 none"}},
		{"a set of several records is one text", www, dnswire.TypeA, []string{"10.53.0.82;10.53.0.81", "10.53.0.81"},
			[]string{"0 10.53.0.81 | 10.53.0.82", "1 10.53.0.81"}},
		{"a repeated record is one", www, dnswire.TypeA, []string{"10.53.0.81;10.53.0.81"}, []string{"0 10.53.0.81"}},
		{"a CNAME beside a TXT set", acme, dnswire.TypeTXT, []string{dngTok1, "CNAME edge.dnshost.test."},
			[]string{"0 " + dngTok1, "1 CNAME edge.dnshost.test."}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			o := dngObserve(t, r.owner, r.typ, r.specs...)
			want := dngSeenOf(t, o.Answers, r.want...)
			if got := Sets(o); !dngSameSeen(got, want) {
				t.Errorf("Sets gave %v, want %v", dngTexts(got), dngTexts(want))
			}
		})
	}
}

// A failed walk is an answer from no server, and it is a failure too.
func TestSetsLeavesOutAFailedWalk(t *testing.T) {
	o := dngObserve(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")
	o.Answers = append(o.Answers, decFailedWalk())
	if got := Sets(o); len(got) != 1 || got[0].Text != "10.53.0.81" {
		t.Errorf("Sets gave %v, want the one answer", dngTexts(got))
	}
}

func dngTexts(seen []Seen) []string {
	var texts []string
	for _, s := range seen {
		texts = append(texts, s.Answer.Server.Name.String()+" "+s.Text)
	}
	return texts
}

func dngSameSeen(a, b []Seen) bool { return (len(a) == 0 && len(b) == 0) || reflect.DeepEqual(a, b) }

func TestDisagreeIsFalseForEveryKindButRecords(t *testing.T) {
	corp := decName(t, "corp.test.")
	for _, key := range []obs.Key{
		obs.DelegationKey(corp), obs.DSKey(corp), obs.SerialKey(corp),
		{Kind: 0, Domain: corp, Name: corp, Type: dnswire.TypeA},
		{Kind: 9, Domain: corp, Name: corp, Type: dnswire.TypeA},
	} {
		o := decObservation(key, corp, nil, dngAnswers(t, "corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.88")...)
		if Disagree(o) {
			t.Errorf("Disagree of two different answers of a %v check is true", key.Kind)
		}
	}
	if !Disagree(dngObserve(t, "corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.88")) {
		t.Error("the same answers of a records check do not disagree")
	}
}

// ---- words, numbers and severities ----

func TestDisagreeRuleWordsNumbersAndSeverities(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		num  Rule
		word string
		sev  Severity
	}{
		{RuleDisagree, 11, "disagree", SeverityMedium},
		{RuleAliasTarget, 12, "alias-target", SeverityHigh},
		{RuleNameServerHost, 13, "nameserver-host", SeverityCritical},
		{RuleMailTarget, 14, "mail-target", SeverityHigh},
		{RuleChallenge, 15, "challenge", SeverityHigh},
		{RuleWildcard, 16, "wildcard", SeverityMedium},
	} {
		if c.rule != c.num {
			t.Errorf("%s is rule number %d, want %d: the store keeps the number", c.word, c.rule, c.num)
		}
		if got := c.num.String(); got != c.word {
			t.Errorf("Rule(%d).String() is %q, want %q", c.num, got, c.word)
		}
		// Only a record-set finding weighs more for the types of highTypes.
		for _, typ := range []dnswire.Type{0, dnswire.TypeA, dnswire.TypeTXT, dnswire.TypeSOA} {
			if got := severity(c.rule, typ); got != c.sev {
				t.Errorf("%s severity for type %v is %v, want %v", c.word, typ, got, c.sev)
			}
		}
	}
	if got := Rule(25).String(); got != "rule25" {
		t.Errorf("Rule(25).String() is %q, want rule25", got)
	}
	if got := Rule(10).String(); got != "gone" {
		t.Errorf("Rule(10).String() is %q, want gone", got)
	}
}

// ---- challenge ----

func dngLine(owner, typ, form string) string { return owner + " " + typ + " " + form }

func dngFind(t *testing.T, lines []string, owner string, typ dnswire.Type, specs ...string) ([]Finding, obs.Key, []obs.Answer) {
	t.Helper()
	f := decFile(t, append([]string{"domain corp.test."}, lines...)...)
	o := dngObserve(t, owner, typ, specs...)
	return Findings(f, o), o.Key, o.Answers
}

func TestChallengeFinding(t *testing.T) {
	const acme = "_acme-challenge.corp.test."
	high := func(r Rule, s Severity, expected string) []decWant {
		return []decWant{{rule: r, severity: s, expected: expected}}
	}
	challenge := high(RuleChallenge, SeverityHigh, "none")
	recordSet := high(RuleRecordSet, SeverityMedium, "none")
	rows := []struct {
		name  string
		lines []string
		owner string
		typ   dnswire.Type
		specs []string
		want  []decWant
		seen  []string // "<answer> <text>" of the one finding
	}{
		{"a token at two servers", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{dngTok1, dngTok1},
			challenge, []string{"0 " + dngTok1, "1 " + dngTok1}},
		{"a token at one server of two", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{"nodata", dngTok1},
			challenge, []string{"1 " + dngTok1}},
		{"two sets", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{dngTok1, dngTok2},
			challenge, []string{"0 " + dngTok1, "1 " + dngTok2}},
		{"a failure beside a token is not seen", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{"fail", dngTok1},
			challenge, []string{"1 " + dngTok1}},
		{"a CNAME hands the challenge on", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{"CNAME edge.dnshost.test.", "nodata"},
			challenge, []string{"0 CNAME edge.dnshost.test."}},
		{"another type of the challenge name", []string{dngLine(acme, "A", "none")}, acme, dnswire.TypeA, []string{"10.53.0.99", "nodata"},
			challenge, []string{"0 10.53.0.99"}},
		{"the name of the line in capitals, below the domain", []string{dngLine("_ACME-Challenge.www.Corp.Test.", "TXT", "none")},
			"_acme-challenge.www.corp.test.", dnswire.TypeTXT, []string{dngTok1, "nodata"}, challenge, []string{"0 " + dngTok1}},
		{"the key in capitals", []string{dngLine(acme, "TXT", "none")}, "_ACME-Challenge.Corp.Test.", dnswire.TypeTXT, []string{dngTok1, "nodata"},
			challenge, []string{"0 " + dngTok1}},
		{"no data everywhere", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{"nodata", "noname"}, nil, nil},
		{"only failures", []string{dngLine(acme, "TXT", "none")}, acme, dnswire.TypeTXT, []string{"fail", "fail"}, nil, nil},
		{"an exact line is a record-set", []string{dngLine(acme, "TXT", dngTok1)}, acme, dnswire.TypeTXT, []string{dngTok1, dngTok2},
			high(RuleRecordSet, SeverityMedium, dngTok1), []string{"1 " + dngTok2}},
		{"first label is another label", []string{dngLine("x."+acme, "TXT", "none")}, "x." + acme, dnswire.TypeTXT, []string{dngTok1, "nodata"},
			recordSet, []string{"0 " + dngTok1}},
		{"the label is longer", []string{dngLine("_acme-challenge-old.corp.test.", "TXT", "none")}, "_acme-challenge-old.corp.test.", dnswire.TypeTXT,
			[]string{dngTok1, "nodata"}, recordSet, []string{"0 " + dngTok1}},
		{"the label is shorter", []string{dngLine("acme-challenge.corp.test.", "TXT", "none")}, "acme-challenge.corp.test.", dnswire.TypeTXT,
			[]string{dngTok1, "nodata"}, recordSet, []string{"0 " + dngTok1}},
		{"the challenge name of another domain", []string{dngLine("_acme-challenge.shop.test.", "TXT", "none")}, "_acme-challenge.shop.test.", dnswire.TypeTXT,
			[]string{dngTok1, "nodata"}, recordSet, []string{"0 " + dngTok1}},
		{"the apex", []string{dngLine("corp.test.", "TXT", "none")}, "corp.test.", dnswire.TypeTXT, []string{dngTok1, "nodata"},
			recordSet, []string{"0 " + dngTok1}},
		{"an address line that is none, not at a challenge name", []string{dngLine("www.corp.test.", "A", "none")}, "www.corp.test.", dnswire.TypeA,
			[]string{"10.53.0.81", "nodata"}, high(RuleRecordSet, SeverityHigh, "none"), []string{"0 10.53.0.81"}},
		{"no line", nil, acme, dnswire.TypeTXT, []string{dngTok1, "nodata"},
			high(RuleNotCovered, SeverityMedium, ""), []string{"0 " + dngTok1, "1 none"}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got, key, answers := dngFind(t, r.lines, r.owner, r.typ, r.specs...)
			for i := range r.want {
				r.want[i].seen = dngSeenOf(t, answers, r.seen...)
			}
			regCheck(t, got, key, r.want...)
		})
	}
}

// The challenge line gives a challenge finding and its neighbours give what
// they gave.
func TestChallengeLineBesideOthers(t *testing.T) {
	f := decFile(t, "domain corp.test.", "_acme-challenge.corp.test. TXT none", "_acme-challenge.corp.test. A none", "www.corp.test. A 10.53.0.81")
	txt := dngObserve(t, "_acme-challenge.corp.test.", dnswire.TypeTXT, dngTok1, dngTok1)
	if got := Findings(f, txt); len(got) != 1 || got[0].Rule != RuleChallenge {
		t.Errorf("the TXT challenge line gave:%s", decShow(got))
	}
	www := dngObserve(t, "www.corp.test.", dnswire.TypeA, "10.53.0.88", "10.53.0.81")
	if got := Findings(f, www); len(got) != 1 || got[0].Rule != RuleRecordSet {
		t.Errorf("the www line gave:%s", decShow(got))
	}
}

func TestChallengeAlertOpensUpdatesAndResolves(t *testing.T) {
	const acme = "_acme-challenge.corp.test."
	f := decFile(t, "domain corp.test.", dngLine(acme, "TXT", "none"))
	now := decT0.Add(time.Minute)
	o := dngObserve(t, acme, dnswire.TypeTXT, dngTok1, "nodata")
	opened := Findings(f, o)
	if len(opened) != 1 || opened[0].Rule != RuleChallenge {
		t.Fatalf("no challenge finding:%s", decShow(opened))
	}
	change := func(op Op, f Finding) Change { return Change{Op: op, Finding: f, At: now} }
	decSameChanges(t, Decide(Input{Expect: f, Observation: o, Now: now}), []Change{change(OpOpen, opened[0])})
	decSameChanges(t, Decide(Input{Expect: f, Observation: o, Now: now, Open: opened}), nil)

	second := dngObserve(t, acme, dnswire.TypeTXT, dngTok1, dngTok2)
	again := Findings(f, second)
	decSameChanges(t, Decide(Input{Expect: f, Observation: second, Now: now, Open: opened}), []Change{change(OpUpdate, again[0])})

	gone := dngObserve(t, acme, dnswire.TypeTXT, "nodata", "noname")
	decSameChanges(t, Decide(Input{Expect: f, Observation: gone, Now: now, Open: opened}), []Change{change(OpResolve, opened[0])})
	// The server that showed the token fails: nothing shows that it is gone.
	blind := dngObserve(t, acme, dnswire.TypeTXT, "fail", "nodata")
	decSameChanges(t, Decide(Input{Expect: f, Observation: blind, Now: now, Open: opened}), nil)
}

// A resolve of a challenge or record-set alert shows the line in force when
// the file has the line, and the stored finding when it has not.
func TestChallengeAndRecordSetResolveShowTheLineInForce(t *testing.T) {
	const acme = "_acme-challenge.corp.test."
	now := decT0.Add(time.Minute)
	gone := dngObserve(t, acme, dnswire.TypeTXT, "nodata", "noname")
	fine := dngObserve(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.81")
	stored := func(r Rule, expected string) []Finding {
		key := gone.Key
		if r == RuleRecordSet {
			key = fine.Key
		}
		return []Finding{{Rule: r, Severity: SeverityHigh, Check: key, Expected: expected, Value: "x"}}
	}
	rows := []struct {
		name  string
		file  *expect.File
		open  []Finding
		wants string // Expected of the resolve
	}{
		{"challenge, the line is unchanged", decFile(t, "domain corp.test.", dngLine(acme, "TXT", "none")), stored(RuleChallenge, "old"), "none"},
		{"challenge, the line was removed", decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81"), stored(RuleChallenge, "old"), "old"},
		{"challenge, no file", nil, stored(RuleChallenge, "old"), "old"},
		{"challenge, the file of another domain", decFile(t, "domain shop.test.", "www.shop.test. A 10.53.0.81"), stored(RuleChallenge, "old"), "old"},
		{"record-set, the line is another", decFile(t, "domain corp.test.", "www.corp.test. A 10.53.0.81"), stored(RuleRecordSet, "old"), "10.53.0.81"},
		{"record-set, the line was removed", decFile(t, "domain corp.test.", "mail.corp.test. A 10.53.0.82"), stored(RuleRecordSet, "old"), "old"},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var resolves []Change
			o := gone
			if r.open[0].Rule == RuleRecordSet {
				o = fine
			}
			for _, c := range Decide(Input{Expect: r.file, Observation: o, Now: now, Open: r.open}) {
				if c.Op == OpResolve && c.Finding.Rule == r.open[0].Rule {
					resolves = append(resolves, c)
				}
			}
			if len(resolves) != 1 || resolves[0].Finding.Expected != r.wants {
				t.Errorf("the resolves are%s, want one with Expected %q", decShowChanges(resolves), r.wants)
			}
		})
	}
}

// ---- disagree in Decide ----

// dngRow is one run of Decide: the file, the answers, whether the split has
// lasted long enough, the open alerts and the changes that must come.
type dngRow struct {
	name    string
	lines   []string // after the domain line; nil: the line "www.corp.test. A in 10.53.0.0/24"
	domain  string   // of the file; default corp.test.
	noFile  bool
	owner   string       // default www.corp.test.
	typ     dnswire.Type // default A
	specs   []string
	long    bool // Input.DisagreeLong
	over    bool // Input.DisagreeOver
	open    []dngOpen
	failing bool // the walk failed too: an answer from no server
	want    []dngChange
}

// dngOpen is an open finding of the check; seen are the servers it saw.
type dngOpen struct {
	rule     Rule
	severity Severity
	expected string
	value    string
	seen     []int
}

// dngChange is a wanted change; seen lists "<answer> <text>". A value "x"
// stands for the usual lines "<addr> <host> <text>" of the seen.
type dngChange struct {
	op       Op
	rule     Rule
	severity Severity
	expected string
	value    string
	seen     []string
	open     int // resolve: the index of the open finding that ends
}

// dngUsual is the Value of a finding of the usual rules.
const dngUsual = "x"

func (r dngRow) value(t *testing.T, w dngChange) string {
	t.Helper()
	if w.value != dngUsual {
		return w.value
	}
	var lines []string
	for _, s := range w.seen {
		idx, text, _ := strings.Cut(s, " ")
		i, err := strconv.Atoi(idx)
		if err != nil {
			t.Fatalf("bad seen %q", s)
		}
		lines = append(lines, dngServers[i].addr+" "+dngServers[i].host+" "+text)
	}
	return strings.Join(lines, "\n")
}

func (r dngRow) run(t *testing.T) {
	t.Helper()
	if r.owner == "" {
		r.owner = "www.corp.test."
	}
	if r.typ == 0 {
		r.typ = dnswire.TypeA
	}
	if r.lines == nil {
		r.lines = []string{"www.corp.test. A " + dngInLine}
	}
	if r.domain == "" {
		r.domain = "corp.test."
	}
	o := dngObserve(t, r.owner, r.typ, r.specs...)
	if r.failing {
		o.Answers = append(o.Answers, decFailedWalk())
	}
	now := decT0.Add(dngNow)
	in := Input{Observation: o, Now: now, DisagreeLong: r.long, DisagreeOver: r.over}
	if !r.noFile {
		in.Expect = decFile(t, append([]string{"domain " + r.domain}, r.lines...)...)
	}
	for _, op := range r.open {
		f := Finding{Rule: op.rule, Severity: op.severity, Check: o.Key, Expected: op.expected, Value: op.value}
		for _, i := range op.seen {
			f.Seen = append(f.Seen, Seen{Answer: decAnswer(t, dngServers[i].host, dngServers[i].addr, decNoData(t, "corp.test.")), Text: "none"})
		}
		in.Open = append(in.Open, f)
	}
	var want []Change
	for _, w := range r.want {
		f := Finding{Rule: w.rule, Severity: w.severity, Check: o.Key, Expected: w.expected, Value: r.value(t, w), Seen: dngSeenOf(t, o.Answers, w.seen...)}
		if w.op == OpResolve {
			f = in.Open[w.open]
		}
		want = append(want, Change{Op: w.op, Finding: f, At: now})
	}
	decSameChanges(t, Decide(in), want)
}

func dngDisagreeOpen(value string, seen ...int) dngOpen {
	return dngOpen{rule: RuleDisagree, severity: SeverityMedium, expected: dngInLine, value: value, seen: seen}
}

func dngOpens(value string, seen ...string) dngChange {
	return dngChange{op: OpOpen, rule: RuleDisagree, severity: SeverityMedium, expected: dngInLine, value: value, seen: seen}
}

func dngUpdates(value string, seen ...string) dngChange {
	c := dngOpens(value, seen...)
	c.op = OpUpdate
	return c
}

func dngNotCovered(seen ...string) dngChange {
	return dngChange{op: OpOpen, rule: RuleNotCovered, severity: SeverityMedium, value: dngUsual, seen: seen}
}

func TestDisagreeOpensOnlyWhenTheSplitHasLastedLongEnough(t *testing.T) {
	two := []string{"10.53.0.81", "10.53.0.88"}
	both := dngOpens("10.53.0.81\n10.53.0.88", "0 10.53.0.81", "1 10.53.0.88")
	rows := []dngRow{
		{name: "long", specs: two, long: true, want: []dngChange{both}},
		{name: "not long", specs: two},
		{name: "not long, an or-line", specs: two, lines: []string{"www.corp.test. A 10.53.0.81 || 10.53.0.88"}},
		{name: "not long, three answers", specs: []string{"10.53.0.81", "10.53.0.88", "10.53.0.89"}},
		{name: "long, three answers", specs: []string{"10.53.0.81", "10.53.0.88", "10.53.0.89"}, long: true,
			want: []dngChange{dngOpens("10.53.0.81\n10.53.0.88\n10.53.0.89", "0 10.53.0.81", "1 10.53.0.88", "2 10.53.0.89")}},
		{name: "long, but the servers agree", specs: []string{"10.53.0.81", "10.53.0.81"}, long: true},
		{name: "long, but one answer", specs: []string{"10.53.0.81"}, long: true},
		{name: "answers in order, a set repeated", specs: []string{"10.53.0.88", "10.53.0.81", "10.53.0.88"}, long: true,
			want: []dngChange{dngOpens("10.53.0.81\n10.53.0.88", "0 10.53.0.88", "1 10.53.0.81", "2 10.53.0.88")}},
		{name: "the value is sorted by octets, not by number", specs: []string{"10.53.0.81", "10.53.0.9"}, long: true,
			want: []dngChange{dngOpens("10.53.0.81\n10.53.0.9", "0 10.53.0.81", "1 10.53.0.9")}},
		{name: "sets of several records", specs: []string{"10.53.0.82;10.53.0.81", "10.53.0.81"}, long: true,
			want: []dngChange{dngOpens("10.53.0.81\n10.53.0.81 | 10.53.0.82", "0 10.53.0.81 | 10.53.0.82", "1 10.53.0.81")}},
		{name: "a set of another order is no difference", specs: []string{"10.53.0.82;10.53.0.81", "10.53.0.81;10.53.0.82"}, long: true},
		{name: "no data and no such name agree", specs: []string{"nodata", "noname"}, lines: []string{"www.corp.test. A none"}, long: true},
		{name: "a failure beside two answers is not seen", specs: []string{"10.53.0.81", "fail", "10.53.0.88"}, long: true,
			want: []dngChange{dngOpens("10.53.0.81\n10.53.0.88", "0 10.53.0.81", "2 10.53.0.88")}},
		{name: "one answer and a failure", specs: []string{"10.53.0.81", "fail"}, long: true},
		{name: "the walk failed too", specs: two, failing: true, long: true, want: []dngChange{both}},
		{name: "an or-line allows both", specs: two, lines: []string{"www.corp.test. A 10.53.0.81 || 10.53.0.88"}, long: true,
			want: []dngChange{{op: OpOpen, rule: RuleDisagree, severity: SeverityMedium, expected: "10.53.0.81 || 10.53.0.88",
				value: "10.53.0.81\n10.53.0.88", seen: []string{"0 10.53.0.81", "1 10.53.0.88"}}}},
		{name: "a like-line allows both", typ: dnswire.TypeCNAME, lines: []string{"www.corp.test. CNAME like *.dnshost.test."},
			specs: []string{"edge.dnshost.test.", "cdn.dnshost.test."}, long: true,
			want: []dngChange{{op: OpOpen, rule: RuleDisagree, severity: SeverityMedium, expected: "like *.dnshost.test.",
				value: "cdn.dnshost.test.\nedge.dnshost.test.", seen: []string{"0 edge.dnshost.test.", "1 cdn.dnshost.test."}}}},
		{name: "an exact line gives the record-set alone", specs: two, lines: []string{"www.corp.test. A 10.53.0.81"}, long: true,
			want: []dngChange{{op: OpOpen, rule: RuleRecordSet, severity: SeverityHigh, expected: "10.53.0.81", value: dngUsual, seen: []string{"1 10.53.0.88"}}}},
		{name: "no line gives not-covered alone", specs: two, lines: []string{"mail.corp.test. A 10.53.0.82"}, long: true,
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.88")}},
		{name: "no file gives not-covered alone", specs: two, noFile: true, long: true,
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.88")}},
		{name: "the file of another domain gives not-covered alone", specs: two, domain: "shop.test.", lines: []string{"www.shop.test. A 10.53.0.81"}, long: true,
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.88")}},
		{name: "a challenge finding keeps it out", owner: "_acme-challenge.corp.test.", typ: dnswire.TypeTXT,
			lines: []string{"_acme-challenge.corp.test. TXT none"}, specs: []string{"nodata", dngTok1}, long: true,
			want: []dngChange{{op: OpOpen, rule: RuleChallenge, severity: SeverityHigh, expected: "none", value: dngUsual, seen: []string{"1 " + dngTok1}}}},
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}

func TestOpenDisagreeAlertKeepsAndResolves(t *testing.T) {
	two := []string{"10.53.0.81", "10.53.0.88"}
	both := "10.53.0.81\n10.53.0.88"
	open := dngDisagreeOpen(both, 0, 1)
	resolve := dngChange{op: OpResolve}
	rows := []dngRow{
		// An alert stays open while the servers differ, however long the split
		// has lasted; a value that changed alone is no news.
		{name: "the servers still disagree", specs: two, open: []dngOpen{open}},
		{name: "the servers still disagree, long", specs: two, long: true, open: []dngOpen{open}},
		{name: "a new distinct answer is no update", specs: []string{"10.53.0.81", "10.53.0.88", "10.53.0.89"}, open: []dngOpen{open}},
		{name: "a new distinct answer is no update, long", specs: []string{"10.53.0.81", "10.53.0.88", "10.53.0.89"}, long: true, open: []dngOpen{open}},
		{name: "another value is no update", specs: two, open: []dngOpen{dngDisagreeOpen("old\nolder", 0, 1)}},
		{name: "an empty value is no update", specs: two, open: []dngOpen{dngDisagreeOpen("", 0, 1)}},
		{name: "a server that fails now is no news", specs: []string{"10.53.0.81", "10.53.0.88", "fail"},
			open: []dngOpen{dngDisagreeOpen("10.53.0.81\n10.53.0.88\n10.53.0.89", 0, 1, 2)}},
		{name: "a server that came back is no news", specs: []string{"10.53.0.81", "10.53.0.88", "10.53.0.88"}, open: []dngOpen{open}},
		{name: "the same answers in another order", specs: []string{"10.53.0.88", "10.53.0.81"}, open: []dngOpen{dngDisagreeOpen("10.53.0.88\n10.53.0.81", 0, 1)}},
		{name: "another expected text", specs: two,
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, expected: "old", value: both, seen: []int{0, 1}}},
			want: []dngChange{dngUpdates(both, "0 10.53.0.81", "1 10.53.0.88")}},
		{name: "another severity", specs: two,
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityLow, expected: dngInLine, value: both, seen: []int{0, 1}}},
			want: []dngChange{dngUpdates(both, "0 10.53.0.81", "1 10.53.0.88")}},
		{name: "the line is gone but the servers still disagree", specs: two, lines: []string{"mail.corp.test. A 10.53.0.82"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, value: both, seen: []int{0, 1}}},
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.88")}},
		{name: "no file but the servers still disagree", specs: two, noFile: true,
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, value: both, seen: []int{0, 1}}},
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.88")}},
		{name: "a record-set finding beside it, the line was another", specs: two, lines: []string{"www.corp.test. A 10.53.0.81"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, expected: dngInLine, value: "10.53.0.81", seen: []int{0}}},
			want: []dngChange{
				{op: OpOpen, rule: RuleRecordSet, severity: SeverityHigh, expected: "10.53.0.81", value: dngUsual, seen: []string{"1 10.53.0.88"}},
				{op: OpUpdate, rule: RuleDisagree, severity: SeverityMedium, expected: "10.53.0.81", value: both, seen: []string{"0 10.53.0.81", "1 10.53.0.88"}},
			}},
		{name: "a record-set finding beside it, the line is the same", specs: two, lines: []string{"www.corp.test. A 10.53.0.81"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, expected: "10.53.0.81", value: "10.53.0.81", seen: []int{0}}},
			want: []dngChange{
				{op: OpOpen, rule: RuleRecordSet, severity: SeverityHigh, expected: "10.53.0.81", value: dngUsual, seen: []string{"1 10.53.0.88"}},
			}},

		// The split is over: an open alert ends by the general rule.
		{name: "the servers agree", specs: []string{"10.53.0.81", "10.53.0.81"}, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "the servers agree, the split was long", specs: []string{"10.53.0.81", "10.53.0.81"}, long: true, over: true,
			open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "both give none", specs: []string{"nodata", "noname"}, lines: []string{"www.corp.test. A none"}, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		// A failure at a server that the alert shows does not keep it open.
		{name: "a server that saw it fails", specs: []string{"10.53.0.81", "fail"}, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "the first server that saw it fails", specs: []string{"fail", "10.53.0.88"}, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "a server that never saw it fails", specs: []string{"10.53.0.81", "fail"}, over: true, open: []dngOpen{dngDisagreeOpen(both, 0, 2)}, want: []dngChange{resolve}},
		{name: "a failure at a server of another address", specs: []string{"10.53.0.81", "10.53.0.81", "fail"}, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "the walk failed", specs: []string{"10.53.0.81", "10.53.0.81"}, failing: true, over: true, open: []dngOpen{open}},
		{name: "every answer fails", specs: []string{"fail", "fail"}, over: true, open: []dngOpen{open}},
		{name: "the open alert saw nothing and a server fails", specs: []string{"10.53.0.81", "10.53.0.81", "fail"}, over: true,
			open: []dngOpen{dngDisagreeOpen("", 3)}, want: []dngChange{resolve}},
		{name: "a duplicate open alert resolves once", specs: []string{"10.53.0.81", "10.53.0.81"}, over: true, open: []dngOpen{open, open}, want: []dngChange{resolve}},
		// The servers differ but the split is over, and it is not long: the
		// formula gives no finding, so the alert ends.
		{name: "the servers differ, the split is over", specs: two, over: true, open: []dngOpen{open}, want: []dngChange{resolve}},
		{name: "the servers differ, the split is over, a server that saw it fails: no block", specs: []string{"10.53.0.81", "10.53.0.88", "fail"}, over: true,
			open: []dngOpen{dngDisagreeOpen(both, 0, 1, 2)}, want: []dngChange{resolve}},
		{name: "the servers differ, the split is over and long", specs: two, over: true, long: true, open: []dngOpen{open}},

		// The split is not over: the alert stays open through runs in which
		// the servers agree, whatever they answer and fail.
		{name: "agree, not over", specs: []string{"10.53.0.81", "10.53.0.81"}, open: []dngOpen{open}},
		{name: "agree, not over, long", specs: []string{"10.53.0.81", "10.53.0.81"}, long: true, open: []dngOpen{open}},
		{name: "none, not over", specs: []string{"nodata", "noname"}, lines: []string{"www.corp.test. A none"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, expected: "none", value: both, seen: []int{0, 1}}}},
		{name: "a server that never saw it fails, not over", specs: []string{"10.53.0.81", "fail"}, open: []dngOpen{dngDisagreeOpen(both, 0, 2)}},
		{name: "a failure at another address, not over", specs: []string{"10.53.0.81", "10.53.0.81", "fail"}, open: []dngOpen{open}},
		{name: "a duplicate open alert, not over", specs: []string{"10.53.0.81", "10.53.0.81"}, open: []dngOpen{open, open}},
		{name: "agree, not over, the line changed", specs: []string{"10.53.0.81", "10.53.0.81"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, expected: "old", value: both, seen: []int{0, 1}}},
			want: []dngChange{dngUpdates("10.53.0.81", "0 10.53.0.81", "1 10.53.0.81")}},
		{name: "agree, not over, the severity changed", specs: []string{"10.53.0.81", "10.53.0.81"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityLow, expected: dngInLine, value: both, seen: []int{0, 1}}},
			want: []dngChange{dngUpdates("10.53.0.81", "0 10.53.0.81", "1 10.53.0.81")}},
		{name: "agree, not over, the line is gone", specs: []string{"10.53.0.81", "10.53.0.81"}, lines: []string{"mail.corp.test. A 10.53.0.82"},
			open: []dngOpen{{rule: RuleDisagree, severity: SeverityMedium, value: both, seen: []int{0, 1}}},
			want: []dngChange{dngNotCovered("0 10.53.0.81", "1 10.53.0.81")}},
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}

// An alert of the same rule on another check, or of another rule on this
// one, neither keeps the disagreement open nor is resolved by its end.
func TestDisagreeOnlyReadsItsOwnAlert(t *testing.T) {
	o := dngObserve(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.88")
	f := decFile(t, "domain corp.test.", "www.corp.test. A "+dngInLine)
	now := decT0.Add(dngNow)
	otherKey := dngKey(t, "mail.corp.test.", dnswire.TypeA)
	elsewhere := Finding{Rule: RuleDisagree, Severity: SeverityMedium, Check: otherKey, Expected: dngInLine, Value: "10.53.0.81\n10.53.0.88"}
	recordSet := Finding{Rule: RuleRecordSet, Severity: SeverityHigh, Check: o.Key, Expected: dngInLine, Value: "x"}
	for name, open := range map[string][]Finding{"another check": {elsewhere}, "another rule": {recordSet}} {
		got := Decide(Input{Expect: f, Observation: o, Now: now, Open: open})
		if slices.ContainsFunc(got, func(c Change) bool { return c.Finding.Rule == RuleDisagree }) {
			t.Errorf("%s: a disagree change without series or own alert:%s", name, decShowChanges(got))
		}
	}
	agree := dngObserve(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.81")
	for _, c := range Decide(Input{Expect: f, Observation: agree, Now: now, Open: []Finding{elsewhere}}) {
		t.Errorf("a change of another check's alert:%s", decShowChanges([]Change{c}))
	}
	// The key of the open alert is compared without regard to case.
	upper := Finding{Rule: RuleDisagree, Severity: SeverityMedium, Expected: dngInLine, Value: "10.53.0.81\n10.53.0.88",
		Check: obs.RecordsKey(decName(t, "CORP.TEST."), decName(t, "WWW.Corp.Test."), dnswire.TypeA)}
	if got := Decide(Input{Expect: f, Observation: agree, Now: now, DisagreeOver: true, Open: []Finding{upper}}); len(got) != 1 || got[0].Op != OpResolve {
		t.Errorf("an alert of the key in capitals:%s", decShowChanges(got))
	}
}

// A new line in the value is news for every rule but disagree.
func TestAnotherRuleUpdatesOnANewValueLine(t *testing.T) {
	line := "www.corp.test. A 10.53.0.81"
	update := dngChange{op: OpUpdate, rule: RuleRecordSet, severity: SeverityHigh, expected: "10.53.0.81", value: dngUsual, seen: []string{"1 10.53.0.88"}}
	same := dngOpen{rule: RuleRecordSet, severity: SeverityHigh, expected: "10.53.0.81", seen: []int{1},
		value: dngServers[1].addr + " " + dngServers[1].host + " 10.53.0.88"}
	other := same
	other.value = dngServers[1].addr + " " + dngServers[1].host + " 10.53.0.99"
	more := same
	more.value = same.value + "\n" + other.value
	less := same
	less.value = ""
	rows := []dngRow{
		{name: "the same value", lines: []string{line}, specs: []string{"10.53.0.81", "10.53.0.88"}, open: []dngOpen{same}},
		{name: "another value", lines: []string{line}, specs: []string{"10.53.0.81", "10.53.0.88"}, open: []dngOpen{other}, want: []dngChange{update}},
		{name: "a value with one line more", lines: []string{line}, specs: []string{"10.53.0.81", "10.53.0.88"}, open: []dngOpen{more}},
		{name: "a value that was empty", lines: []string{line}, specs: []string{"10.53.0.81", "10.53.0.88"}, open: []dngOpen{less}, want: []dngChange{update}},
		{name: "another severity", lines: []string{line}, specs: []string{"10.53.0.81", "10.53.0.88"},
			open: []dngOpen{{rule: RuleRecordSet, severity: SeverityLow, expected: "10.53.0.81", seen: []int{1}, value: same.value}}, want: []dngChange{update}},
	}
	for _, r := range rows {
		t.Run(r.name, r.run)
	}
}

// Disagree is a rule of records checks only.
func TestDisagreeIsGivenForRecordsChecksOnly(t *testing.T) {
	corp := decName(t, "corp.test.")
	f := decFile(t, "domain corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test.")
	now := decT0.Add(dngNow)
	mine := func(cs []Change) []Change { return dngOfRule(cs, RuleDisagree) }
	for _, key := range []obs.Key{obs.DelegationKey(corp), obs.SerialKey(corp)} {
		o := decObservation(key, corp, nil, dngAnswers(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")...)
		open := Finding{Rule: RuleDisagree, Severity: SeverityMedium, Check: key, Value: "x"}
		got := Decide(Input{Expect: f, Observation: o, Now: now, DisagreeLong: true})
		if len(mine(got)) != 0 {
			t.Errorf("%v: a disagree change:%s", key.Kind, decShowChanges(got))
		}
		got = mine(Decide(Input{Expect: f, Observation: o, Now: now, Open: []Finding{open}}))
		if len(got) != 1 || got[0].Op != OpResolve {
			t.Errorf("%v: an open disagree alert of a check that cannot disagree:%s", key.Kind, decShowChanges(got))
		}
	}
}

// ---- the property test ----

const (
	dngSeed  = 20261117
	dngCases = 3000
)

var dngOwners = []string{"www.corp.test.", "_acme-challenge.corp.test.", "_ACME-Challenge.www.Corp.Test.", "x._acme-challenge.corp.test.", "_acme-challenge.shop.test."}

// dngSets are the sets that an answer may hold, by type of the check.
var dngSets = map[dnswire.Type][]string{
	dnswire.TypeA: {"10.53.0.81", "10.53.0.82", "10.53.0.81;10.53.0.82", "10.53.0.82;10.53.0.81", "10.53.0.81;10.53.0.81", "10.53.0.99",
		"CNAME edge.dnshost.test.", "CNAME Edge.Dnshost.Test."},
	dnswire.TypeCNAME: {"CNAME edge.dnshost.test.", "CNAME Edge.Dnshost.Test.", "CNAME cdn.dnshost.test.", "CNAME www.corp.test."},
	dnswire.TypeTXT:   {dngTok1, dngTok2, dngTok1 + ";" + dngTok2, "CNAME edge.dnshost.test."},
}

// dngForms are the forms that a line of the type takes.
var dngForms = map[dnswire.Type][]string{
	dnswire.TypeA:     {"10.53.0.81", "10.53.0.81 | 10.53.0.82", "10.53.0.81 || 10.53.0.82", "10.53.0.81 || 10.53.0.99", dngInLine, dngInLine, dngInLine, "none"},
	dnswire.TypeCNAME: {"edge.dnshost.test.", "like *.dnshost.test.", "like *.dnshost.test.", "like *.dnshost.test.", "none"},
	dnswire.TypeTXT:   {dngTok1, dngTok1 + " | " + dngTok2, dngTok1 + " || " + dngTok2, dngTok1 + " || " + dngTok2, "none"},
}

// dngClean are the sets of a run in which every server answers with data
// that the permissive lines allow.
var dngClean = map[dnswire.Type][]string{
	dnswire.TypeA:     {"10.53.0.81", "10.53.0.82", "10.53.0.81;10.53.0.82", "10.53.0.82;10.53.0.81", "10.53.0.99"},
	dnswire.TypeCNAME: {"CNAME edge.dnshost.test.", "CNAME cdn.dnshost.test."},
	dnswire.TypeTXT:   {dngTok1, dngTok2},
}

type dngGen struct {
	t     testing.TB
	rng   *rand.Rand
	clean bool // the answers are data or failures only
}

func (g *dngGen) pick(xs ...string) string { return xs[g.rng.IntN(len(xs))] }

func (g *dngGen) chance(n int) bool { return g.rng.IntN(n) == 0 }

// result draws a word for dngResult.
func (g *dngGen) result(typ dnswire.Type) string {
	if g.clean {
		if g.chance(6) {
			return "fail"
		}
		return g.pick(dngClean[typ]...)
	}
	switch x := g.rng.IntN(20); {
	case x < 11:
		return g.pick(dngSets[typ]...)
	case x < 13:
		return "nodata"
	case x < 15:
		return "noname"
	}
	return "fail"
}

// dngInput draws one input of Decide from seed: equal seeds give equal inputs.
func dngInput(t testing.TB, seed uint64) Input {
	g := &dngGen{t: t, rng: rand.New(rand.NewPCG(seed, 23))}
	g.clean = g.chance(2)
	owner := g.pick(dngOwners...)
	typ := dnswire.TypeA
	switch {
	case owner != "www.corp.test." && !g.chance(4):
		typ = dnswire.TypeTXT
	case owner == "www.corp.test." && g.chance(3):
		typ = dnswire.TypeCNAME
	}
	domain := g.pick("corp.test.", "corp.test.", "corp.test.", "CORP.Test.")
	key := obs.RecordsKey(decName(t, domain), decName(t, owner), typ)
	if g.chance(12) {
		d := decName(t, domain)
		key = []obs.Key{obs.DelegationKey(d), obs.DSKey(d), obs.SerialKey(d)}[g.rng.IntN(3)]
	}
	// The zone of the observation is the one that the file expects, so that
	// no zone finding comes up.
	o := obs.Observation{Key: key, Start: decT0.Add(time.Duration(g.rng.IntN(1000)) * time.Minute), Zone: decName(t, "corp.test.")}
	o.Deadline = o.Start.Add(45 * time.Second)
	servers := slices.Clone(dngServers)
	g.rng.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
	for _, s := range servers[:1+g.rng.IntN(4)] {
		word := g.result(typ)
		a := decAnswer(t, s.host, s.addr, dngResult(t, owner, typ, word))
		if word == "fail" && g.chance(5) {
			a.Server.Addr = netip.AddrPort{}
		}
		o.Answers = append(o.Answers, a)
	}
	in := Input{Observation: o, Now: o.Deadline.Add(time.Duration(g.rng.IntN(60)) * time.Second)}
	in.Expect = g.file(owner, typ)
	g.series(&in)
	in.Open = g.open(in)
	return in
}

// file gives a file with the line of the check (mostly), the challenge
// lines and a www line; nil, or the file of another domain, now and then.
func (g *dngGen) file(owner string, typ dnswire.Type) *expect.File {
	switch g.rng.IntN(14) {
	case 0:
		return nil
	case 1:
		return decFile(g.t, "domain shop.test.", "www.shop.test. A 10.53.0.81")
	}
	lines := []string{"domain corp.test."}
	seen := map[string]bool{}
	add := func(o string, typ dnswire.Type, form string) {
		k := strings.ToLower(o) + typ.String()
		if !seen[k] {
			seen[k] = true
			lines = append(lines, o+" "+typ.String()+" "+form)
		}
	}
	if !g.chance(6) {
		o := owner
		if g.chance(4) {
			o = strings.ToUpper(o)
		}
		add(o, typ, g.pick(dngForms[typ]...))
	}
	if g.chance(2) {
		add("_acme-challenge.corp.test.", dnswire.TypeTXT, g.pick("none", "none", dngTok1))
	}
	if g.chance(3) {
		add("www.corp.test.", dnswire.TypeA, g.pick(dngForms[dnswire.TypeA]...))
	}
	return decFile(g.t, lines...)
}

// series draws DisagreeLong and DisagreeOver, and FailingSince and FailLimit mostly at the
// edge of the limit.
func (g *dngGen) series(in *Input) {
	edge := func(limit time.Duration) time.Time {
		switch g.rng.IntN(12) {
		case 0, 10:
			return time.Time{}
		case 1, 2:
			return in.Now.Add(-limit + time.Nanosecond)
		case 3, 4, 5:
			return in.Now.Add(-limit)
		case 6, 7:
			return in.Now.Add(-limit - time.Nanosecond)
		case 8:
			return in.Now
		case 9:
			return in.Now.Add(-time.Hour)
		}
		return in.Now.Add(time.Minute)
	}
	limits := []time.Duration{0, -time.Minute, time.Nanosecond, 2 * time.Minute, 10 * time.Minute, 10 * time.Minute, 10 * time.Minute, 10 * time.Minute}
	in.DisagreeLong = g.chance(2)
	in.DisagreeOver = g.chance(3)
	in.FailLimit = limits[g.rng.IntN(len(limits))]
	in.FailingSince = edge(in.FailLimit)
}

// open draws open findings of the check, of its key in capitals and of
// other checks. The values of a disagree alert come from the answers of the
// run, so that every kind of news comes up.
func (g *dngGen) open(in Input) []Finding {
	o := in.Observation
	want := dngDisagreeValue(o)
	var open []Finding
	for range g.rng.IntN(4) {
		rule := []Rule{RuleDisagree, RuleDisagree, RuleDisagree, RuleRecordSet, RuleChallenge, RuleNotCovered, RuleCheckFailing, RuleZone, RuleNameServers}[g.rng.IntN(9)]
		f := Finding{Rule: rule, Severity: []Severity{SeverityMedium, SeverityMedium, SeverityHigh, SeverityLow}[g.rng.IntN(4)], Check: o.Key}
		switch g.rng.IntN(8) {
		case 0:
			f.Check.Domain = decName(g.t, strings.ToUpper(o.Key.Domain.String()))
			f.Check.Name = decName(g.t, strings.ToUpper(o.Key.Name.String()))
		case 1, 2:
			f.Check = dngKey(g.t, "mail.corp.test.", dnswire.TypeA)
		}
		f.Expected = g.pick("", "none", dngInLine, "10.53.0.81", "old")
		if rule == RuleDisagree {
			first, _, _ := strings.Cut(want, "\n")
			f.Value = g.pick(want, want, first, "", "x", want+"\nzzz")
			if g.chance(2) && in.Expect != nil {
				if e, ok := in.Expect.Find(o.Key.Name, o.Key.Type); ok {
					f.Expected = e.FormText()
				}
			}
		} else {
			f.Value = g.pick("", "x", "10.53.0.11:53 ns1.corp.test. none")
		}
		for _, i := range g.rng.Perm(len(dngServers))[:g.rng.IntN(4)] {
			f.Seen = append(f.Seen, Seen{Answer: decAnswer(g.t, dngServers[i].host, dngServers[i].addr, decNoData(g.t, "corp.test.")), Text: "none"})
		}
		open = append(open, f)
	}
	return open
}

// ---- the oracle: the findings and changes of a run, as formulas over its input ----

// dngUsable is the Seen of the answers that are not failures and whose set
// keep accepts, with the text of the set for the type of the check.
func dngUsable(o obs.Observation, keep func(set []dnswire.Record) bool) []Seen {
	var seen []Seen
	for _, a := range o.Answers {
		set, failed := regSetOf(a)
		if !failed && (keep == nil || keep(set)) {
			seen = append(seen, Seen{Answer: a, Text: expect.SetText(o.Key.Type, set)})
		}
	}
	return seen
}

// dngDisagree is two answers that are not failures with different texts.
func dngDisagree(o obs.Observation) bool {
	if o.Key.Kind != obs.KindRecords {
		return false
	}
	seen := dngUsable(o, nil)
	for i := range seen {
		for j := i + 1; j < len(seen); j++ {
			if seen[i].Text != seen[j].Text {
				return true
			}
		}
	}
	return false
}

// dngDisagreeValue is the distinct texts, sorted by octets, one on each line.
func dngDisagreeValue(o obs.Observation) string {
	var texts []string
	for _, s := range dngUsable(o, nil) {
		if !slices.Contains(texts, s.Text) {
			texts = append(texts, s.Text)
		}
	}
	slices.Sort(texts)
	return strings.Join(texts, "\n")
}

// dngChallengeName is C(n): the first label is _acme-challenge in any case,
// and n is at or under the domain.
func dngChallengeName(f *expect.File, n dnswire.Name) bool {
	labels := n.Labels()
	return len(labels) > 0 && strings.EqualFold(labels[0], "_acme-challenge") && n.IsSubdomainOf(f.Domain)
}

func dngSeverity(r Rule, typ dnswire.Type) Severity {
	switch r {
	case RuleChallenge:
		return SeverityHigh
	case RuleRecordSet:
		if slices.Contains([]dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeCNAME, dnswire.TypeMX, dnswire.TypeNS}, typ) {
			return SeverityHigh
		}
	case RuleInvalidFile, RuleNotCovered, RuleZone, RuleNameServers, RuleCheckFailing, RuleZoneChanged, RuleGlue, RuleDS, RuleGone,
		RuleDisagree, RuleAliasTarget, RuleNameServerHost, RuleMailTarget, RuleWildcard, RuleCAA,
		RuleIssuer, RuleCertName, RuleHostnames, RuleSPF, RuleDMARC, RuleDKIM, RuleMTASTS:
		// The oracle gives only the rules of a line; the others weigh medium here.
	}
	return SeverityMedium
}

// dngCovLine says whether the file covers the check and holds its line.
func dngCovLine(f *expect.File, k obs.Key) (cov bool, line *expect.Expectation) {
	cov = f != nil && k.Domain.Equal(f.Domain)
	if cov {
		if e, ok := f.Find(k.Name, k.Type); ok {
			line = &e
		}
	}
	return cov, line
}

// dngFindings are the findings of a records check: the zone is the expected
// one, so only not-covered, record-set and challenge are possible.
func dngFindings(f *expect.File, o obs.Observation) []Finding {
	_, line := dngCovLine(f, o.Key)
	finding := func(r Rule, expected string, seen []Seen) Finding {
		return Finding{Rule: r, Severity: dngSeverity(r, o.Key.Type), Check: o.Key, Expected: expected, Seen: seen, Value: regValue(seen)}
	}
	if line == nil {
		return []Finding{finding(RuleNotCovered, "", dngUsable(o, nil))}
	}
	rule, differs := emlOracleRule(*line), func(set []dnswire.Record) bool { return !line.Match(set) }
	if line.Form == expect.FormNone && dngChallengeName(f, o.Key.Name) {
		rule, differs = RuleChallenge, func(set []dnswire.Record) bool { return len(set) > 0 }
	}
	seen := dngUsable(o, differs)
	if len(seen) == 0 {
		return nil
	}
	found := finding(rule, line.FormText(), seen)
	found.Value = emlOracleValue(rule, *line, seen, found.Value)
	return []Finding{found}
}

func dngFirstOpen(open []Finding, key obs.Key, r Rule) (Finding, bool) {
	for _, f := range open {
		if f.Rule == r && f.Check.String() == key.String() {
			return f, true
		}
	}
	return Finding{}, false
}

func dngHas(found []Finding, r Rule) bool {
	return slices.ContainsFunc(found, func(f Finding) bool { return f.Rule == r })
}

// dngBlocked: every answer failed, or a failure has no address, or, for
// every rule but disagree, a failure is at an address that the open finding
// saw. A failure at a server that a disagree alert shows does not block it:
// the schedule keeps the split through such runs.
func dngBlocked(f Finding, o obs.Observation) bool {
	if len(dngUsable(o, nil)) == 0 {
		return true
	}
	for _, a := range o.Answers {
		if _, failed := regSetOf(a); !failed {
			continue
		}
		shown := f.Rule != RuleDisagree && slices.ContainsFunc(f.Seen, func(s Seen) bool { return s.Answer.Server.Addr == a.Server.Addr })
		if !a.Server.Addr.IsValid() || shown {
			return true
		}
	}
	return false
}

// dngNews: another expected text, another severity, or, for every rule but
// disagree, a value that no line of the open finding showed. A new distinct
// set does not change a disagree alert.
func dngNews(was, f Finding) bool {
	if was.Expected != f.Expected || was.Severity != f.Severity {
		return true
	}
	return f.Rule != RuleDisagree && decNewValue(was, f)
}

// dngWant is what the oracle says about one input.
type dngWant struct {
	findings  []Finding // of Findings (records checks only)
	given     bool      // the disagree finding is given
	cov, line bool
	explained bool // record-set, challenge or not-covered
	late      bool // Input.DisagreeLong
	open      bool // an open disagree alert of the check
	changes   []Change
}

func dngOracle(in Input) dngWant {
	o := in.Observation
	var w dngWant
	records := o.Key.Kind == obs.KindRecords
	if records {
		w.findings = dngFindings(in.Expect, o)
	}
	found := slices.Clone(w.findings)
	if records && len(dngUsable(o, nil)) == 0 && !in.FailingSince.IsZero() && in.FailLimit > 0 && in.Now.Sub(in.FailingSince) >= in.FailLimit {
		found = append(found, Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: o.Key, Value: "no usable answer for " + ShortDuration(in.FailLimit)})
	}
	_, w.open = dngFirstOpen(in.Open, o.Key, RuleDisagree)
	cov, line := dngCovLine(in.Expect, o.Key)
	w.cov, w.line = cov, line != nil
	w.explained = dngHas(w.findings, RuleRecordSet) || dngHas(w.findings, RuleChallenge) || dngHas(w.findings, RuleNotCovered) ||
		dngHas(w.findings, RuleSPF) || dngHas(w.findings, RuleDMARC) || dngHas(w.findings, RuleDKIM) || dngHas(w.findings, RuleMTASTS)
	w.late = in.DisagreeLong
	w.given = records && (dngDisagree(o) && w.line && !w.explained && w.late || w.open && !in.DisagreeOver)
	if w.given {
		expected := ""
		if line != nil {
			expected = line.FormText()
		}
		found = append(found, Finding{Rule: RuleDisagree, Severity: SeverityMedium, Check: o.Key, Expected: expected, Seen: dngUsable(o, nil), Value: dngDisagreeValue(o)})
	}
	// Open and update in the order of found, then the resolves in the order
	// of the open alerts; only the first alert of a rule counts.
	var mine []Finding
	for _, f := range in.Open {
		if f.Check.String() == o.Key.String() && !dngHas(mine, f.Rule) {
			mine = append(mine, f)
		}
	}
	for _, f := range found {
		was, ok := dngFirstOpen(mine, o.Key, f.Rule)
		switch {
		case !ok:
			w.changes = append(w.changes, Change{Op: OpOpen, Finding: f, At: in.Now})
		case dngNews(was, f):
			w.changes = append(w.changes, Change{Op: OpUpdate, Finding: f, At: in.Now})
		case decRefresh(was, f):
			w.changes = append(w.changes, Change{Op: OpRefresh, Finding: f, At: in.Now})
		}
	}
	for _, was := range mine {
		ends := !dngHas(found, was.Rule) && !dngBlocked(was, o)
		if was.Rule == RuleCheckFailing {
			ends = len(dngUsable(o, nil)) > 0
		}
		if ends {
			// A resolve of these rules shows the line in force when the file has it.
			if (was.Rule == RuleRecordSet || was.Rule == RuleChallenge || was.Rule == RuleSPF || was.Rule == RuleDMARC || was.Rule == RuleDKIM ||
				was.Rule == RuleMTASTS || was.Rule == RuleNameServers || was.Rule == RuleDS) && line != nil {
				was.Expected = line.FormText()
			}
			w.changes = append(w.changes, Change{Op: OpResolve, Finding: was, At: in.Now})
		}
	}
	return w
}

// dngOfRule keeps the changes of one rule.
func dngOfRule(cs []Change, r Rule) []Change {
	return slices.DeleteFunc(slices.Clone(cs), func(c Change) bool { return c.Finding.Rule != r })
}

func dngSame(a, b []Change) bool { return (len(a) == 0 && len(b) == 0) || reflect.DeepEqual(a, b) }

func dngSameFindings(a, b []Finding) bool {
	return (len(a) == 0 && len(b) == 0) || reflect.DeepEqual(a, b)
}

func TestDisagreeChallengeProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngSeed, dngCases)
	for i := range dngCases {
		seed := uint64(dngSeed + i)
		in := dngInput(t, seed)
		w := dngOracle(in)
		o := in.Observation
		if got := Disagree(o); got != dngDisagree(o) {
			t.Fatalf("seed %d: Disagree is %v, want %v", seed, got, !got)
		}
		if o.Key.Kind == obs.KindRecords && !dngSameSeen(Sets(o), dngUsable(o, nil)) {
			t.Fatalf("seed %d: Sets gave %v, want %v", seed, dngTexts(Sets(o)), dngTexts(dngUsable(o, nil)))
		}
		got := Decide(in)
		if o.Key.Kind == obs.KindRecords {
			found := Findings(in.Expect, o)
			if !dngSameFindings(found, w.findings) {
				t.Fatalf("seed %d: Findings gave%s\nwant%s", seed, decShow(found), decShow(w.findings))
			}
			if !dngSame(got, w.changes) {
				t.Fatalf("seed %d: Decide gave%s\nwant%s\nfor %v long %v over %v now %v", seed, decShowChanges(got), decShowChanges(w.changes),
					o.Key, in.DisagreeLong, in.DisagreeOver, in.Now)
			}
		}
		if g, want := dngOfRule(got, RuleDisagree), dngOfRule(w.changes, RuleDisagree); !dngSame(g, want) {
			t.Fatalf("seed %d: the disagree changes are%s\nwant%s", seed, decShowChanges(g), decShowChanges(want))
		}
		for _, c := range got {
			if c.Finding.Check.String() != o.Key.String() {
				t.Fatalf("seed %d: a change of check %v", seed, c.Finding.Check)
			}
		}
		// A resolve comes exactly when the alert is open, the finding is not
		// given and nothing blocks it.
		first, isOpen := dngFirstOpen(in.Open, o.Key, RuleDisagree)
		resolved := slices.ContainsFunc(got, func(c Change) bool { return c.Op == OpResolve && c.Finding.Rule == RuleDisagree })
		if want := isOpen && !w.given && !dngBlocked(first, o); resolved != want {
			t.Fatalf("seed %d: disagree resolved %v, want %v", seed, resolved, want)
		}
	}
}

// With a split that has not lasted long and no alert of its own, the rule is
// silent for every input: only an open alert can bring it.
func TestDisagreeIsSilentWhenNotLongProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngSeed, dngCases)
	checked := 0
	for i := range dngCases {
		seed := uint64(dngSeed + i)
		in := dngInput(t, seed)
		in.DisagreeLong = false
		in.Open = slices.DeleteFunc(in.Open, func(f Finding) bool { return f.Rule == RuleDisagree })
		if slices.ContainsFunc(Decide(in), func(c Change) bool { return c.Finding.Rule == RuleDisagree }) {
			t.Fatalf("seed %d: a disagree change with no series and no alert", seed)
		}
		if Disagree(in.Observation) {
			checked++
		}
	}
	if checked < 200 {
		t.Errorf("only %d cases had servers that disagree", checked)
	}
}

// With a long split and no alert of its own, the rule opens exactly when
// the line exists and no other finding explains the run.
func TestDisagreeOpensWhenLongProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngSeed, dngCases)
	spoke, quiet := 0, 0
	for i := range dngCases {
		seed := uint64(dngSeed + i)
		in := dngInput(t, seed)
		in.DisagreeLong = true
		in.Open = slices.DeleteFunc(in.Open, func(f Finding) bool { return f.Rule == RuleDisagree })
		given := slices.ContainsFunc(Decide(in), func(c Change) bool { return c.Finding.Rule == RuleDisagree && c.Op == OpOpen })
		if given {
			spoke++
		} else if Disagree(in.Observation) {
			quiet++
		}
		if want := dngOracle(in).given; given != want {
			t.Fatalf("seed %d: disagree opened %v, want %v", seed, given, want)
		}
	}
	if spoke < 100 || quiet < 100 {
		t.Errorf("spoke %d times, stayed quiet %d times while the servers disagreed", spoke, quiet)
	}
}

// The inputs must reach every outcome, or a rule that never fires would pass.
func TestDisagreeInputsReachEveryOutcome(t *testing.T) {
	tally := map[string]int{}
	for i := range dngCases {
		in := dngInput(t, uint64(dngSeed+i))
		w := dngOracle(in)
		o := in.Observation
		mine := dngOfRule(w.changes, RuleDisagree)
		for _, c := range mine {
			tally["disagree "+c.Op.String()]++
		}
		disagrees := dngDisagree(o)
		eligible := disagrees && !w.open && w.line
		first, _ := dngFirstOpen(in.Open, o.Key, RuleDisagree)
		count := func(ok bool, what string) {
			if ok {
				tally[what]++
			}
		}
		count(w.given && w.open && len(mine) == 0, "disagree kept")
		count(w.given && w.open && !disagrees, "kept through agreeing servers")
		count(w.open && disagrees && in.DisagreeOver && len(mine) == 1 && mine[0].Op == OpResolve, "resolved with differing servers")
		count(!disagrees && len(mine) == 1 && mine[0].Op == OpResolve, "resolved with agreeing servers")
		count(w.given && w.open && !in.DisagreeLong, "kept while not long")
		count(w.given && w.open && in.DisagreeLong, "kept while long")
		count(w.given && w.open && len(mine) == 0 && first.Value != dngDisagreeValue(o), "kept with another value")
		count(eligible && w.explained && dngHas(w.findings, RuleRecordSet), "held back by record-set")
		count(eligible && dngHas(w.findings, RuleChallenge), "held back by challenge")
		count(disagrees && !w.open && dngHas(w.findings, RuleNotCovered), "held back by not-covered")
		count(w.open && !w.given && len(dngUsable(o, nil)) > 0 && len(mine) == 0, "resolve blocked by a failure")
		count(w.given && in.Expect == nil, "disagree with no file")
		count(w.given && w.cov && !w.line, "disagree with no line")
		count(o.Key.Kind != obs.KindRecords && w.open, "open disagree on another kind")
		lower := strings.ToLower(o.Key.Name.String())
		count(eligible && !w.explained && !in.DisagreeLong, "held back: not long")
		count(eligible && !w.explained && in.DisagreeLong, "opens when long")
		count(dngHas(w.findings, RuleChallenge), "challenge")
		count(dngHas(w.findings, RuleChallenge) && lower == "_acme-challenge.corp.test.", "challenge at the apex name")
		count(dngHas(w.findings, RuleChallenge) && lower == "_acme-challenge.www.corp.test.", "challenge below")
		count(dngHas(w.findings, RuleRecordSet) && strings.Contains(lower, "_acme-challenge") && lower != "_acme-challenge.corp.test." && lower != "_acme-challenge.www.corp.test.",
			"record-set at a name that is no challenge")
	}
	for _, want := range []string{
		"disagree open", "disagree update", "disagree resolve", "disagree kept", "kept while not long", "kept while long",
		"kept through agreeing servers", "resolved with differing servers", "resolved with agreeing servers",
		"kept with another value", "held back by record-set", "held back by challenge", "held back by not-covered", "held back: not long",
		"opens when long", "resolve blocked by a failure", "disagree with no file", "disagree with no line", "open disagree on another kind",
		"challenge", "challenge at the apex name", "challenge below", "record-set at a name that is no challenge",
	} {
		if tally[want] < 20 {
			t.Errorf("only %d cases of %q in %d", tally[want], want, dngCases)
		}
	}
}

// Failure is unknown: its reason does not matter, and a failure beside an
// answer that is not one changes nothing.
func TestDisagreeFailuresAreUnknownProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngSeed, dngCases)
	checked := 0
	for i := range dngCases {
		seed := uint64(dngSeed + i)
		in := dngInput(t, seed)
		want := Decide(in)
		wantFound := Findings(in.Expect, in.Observation)

		other := dngInput(t, seed)
		for j, a := range other.Observation.Answers {
			if _, failed := regSetOf(a); failed {
				other.Observation.Answers[j].Result = obs.FailureResult(obs.Failure{Reason: obs.ReasonRefused, Detail: "another reason"})
			}
		}
		if got := Decide(other); !dngSame(got, want) {
			t.Fatalf("seed %d: another reason of failure changed the changes:%s\nto%s", seed, decShowChanges(want), decShowChanges(got))
		}

		more := dngInput(t, seed)
		if len(dngUsable(more.Observation, nil)) == 0 {
			continue
		}
		extra := decAnswer(t, "e.ns.test.", "10.53.0.7:53", decFailure(obs.ReasonTimeout))
		at := int(seed) % (len(more.Observation.Answers) + 1)
		more.Observation.Answers = slices.Insert(more.Observation.Answers, at, extra)
		if got := Decide(more); !dngSame(got, want) {
			t.Fatalf("seed %d: a failure beside a usable answer changed the changes:%s\nto%s", seed, decShowChanges(want), decShowChanges(got))
		}
		if got := Findings(more.Expect, more.Observation); !dngSameFindings(got, wantFound) {
			t.Fatalf("seed %d: a failure beside a usable answer changed the findings:%s\nto%s", seed, decShow(wantFound), decShow(got))
		}
		if Disagree(more.Observation) != Disagree(in.Observation) {
			t.Fatalf("seed %d: a failure beside a usable answer changed Disagree", seed)
		}
		checked++
	}
	if checked < 500 {
		t.Errorf("only %d cases added a failure beside a usable answer", checked)
	}
}

// The same input gives the same changes, and Decide leaves the input alone.
func TestDisagreePureProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngSeed, dngCases)
	for i := range dngCases {
		seed := uint64(dngSeed + i)
		a, b := dngInput(t, seed), dngInput(t, seed)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: one seed gave two inputs", seed)
		}
		got := Decide(a)
		if !reflect.DeepEqual(a, b) {
			t.Fatalf("seed %d: Decide changed its input", seed)
		}
		if again := Decide(b); !dngSame(got, again) {
			t.Fatalf("seed %d: equal inputs gave%s\nand%s", seed, decShowChanges(got), decShowChanges(again))
		}
	}
}

func TestIsChallenge(t *testing.T) {
	rows := []struct {
		name         string
		domain, host string
		want         bool
	}{
		{"the root as name", "corp.test.", ".", false},
		{"the root as name and domain", ".", ".", false},
		{"the root as domain", ".", "_acme-challenge.", true},
		{"at the domain", "corp.test.", "_acme-challenge.corp.test.", true},
		{"below the domain", "corp.test.", "_acme-challenge.www.corp.test.", true},
		{"mixed case", "corp.test.", "_ACME-Challenge.Corp.Test.", true},
		{"the label is not first", "corp.test.", "www._acme-challenge.corp.test.", false},
		{"the label only starts with the word", "corp.test.", "_acme-challenge2.corp.test.", false},
		{"under another domain", "corp.test.", "_acme-challenge.shop.test.", false},
		{"the name is the domain", "corp.test.", "corp.test.", false},
		{"the domain starts with the label", "_acme-challenge.corp.test.", "_acme-challenge.corp.test.", true},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := IsChallenge(decName(t, r.domain), decName(t, r.host)); got != r.want {
				t.Errorf("IsChallenge(%q, %q) is %v, want %v", r.domain, r.host, got, r.want)
			}
		})
	}
}
