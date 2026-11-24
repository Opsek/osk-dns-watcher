package decide

import (
	"fmt"
	"net/netip"
	"reflect"
	"regexp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

var emlServers = []struct{ host, addr string }{
	{"ns1.corp.test.", "10.53.0.11:53"},
	{"ns2.corp.test.", "10.53.0.12:53"},
	{"ns3.corp.test.", "10.53.0.13:53"},
	{"ns4.corp.test.", "10.53.0.14:53"},
}

// emlTXT is the spec of one TXT record of one string.
func emlTXT(s string) string { return `TXT "` + s + `"` }

// emlQ is the presentation of one TXT string.
func emlQ(s string) string { return `"` + s + `"` }

// emlResult builds an answer from a spec: "nodata", "noname", "fail", or
// records separated by a new line, each "<TYPE> <data>".
func emlResult(t testing.TB, owner, spec string) obs.Result {
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
	for _, rec := range strings.Split(spec, "\n") {
		typ, data, _ := strings.Cut(rec, " ")
		var rt dnswire.Type
		switch typ {
		case "TXT":
			rt = dnswire.TypeTXT
		case "CNAME":
			rt = dnswire.TypeCNAME
		case "MX":
			rt = dnswire.TypeMX
		case "A":
			rt = dnswire.TypeA
		default:
			t.Fatalf("bad spec %q", rec)
		}
		set = append(set, decRR(t, owner, rt, data))
	}
	return decAs(t, obs.RecordsResult(obs.Records{Set: set}), "records")
}

func emlObserve(t testing.TB, owner string, typ dnswire.Type, specs ...string) obs.Observation {
	t.Helper()
	var answers []obs.Answer
	for i, s := range specs {
		answers = append(answers, decAnswer(t, emlServers[i].host, emlServers[i].addr, emlResult(t, owner, s)))
	}
	return decObservation(decRecordsKey(t, "corp.test.", owner, typ), decName(t, "corp.test."), nil, answers...)
}

func emlFile(t testing.TB, lines ...string) *expect.File {
	t.Helper()
	return decFile(t, append([]string{"domain corp.test."}, lines...)...)
}

// emlSeen is one answer that a finding shows: the place in the observation
// and the text of its set.
type emlSeen struct {
	at   int
	text string
}

// emlValue is the Value of the finding of a mail rule: the server line of each
// seen answer, then one line "weaker <word>" for each word.
func emlValue(seen []emlSeen, words ...string) string {
	var lines []string
	for _, s := range seen {
		lines = append(lines, emlServers[s.at].addr+" "+emlServers[s.at].host+" "+s.text)
	}
	for _, w := range words {
		lines = append(lines, "weaker "+w)
	}
	return strings.Join(lines, "\n")
}

// emlCheck states one finding, in every field.
func emlCheck(t *testing.T, got Finding, o obs.Observation, rule Rule, expected string, seen []emlSeen, words ...string) {
	t.Helper()
	if got.Rule != rule || got.Severity != SeverityMedium || got.Expected != expected {
		t.Errorf("finding is %v %v expected %q, want %v medium expected %q", got.Rule, got.Severity, got.Expected, rule, expected)
	}
	if got.Check.String() != o.Key.String() {
		t.Errorf("finding has check %v, want %v", got.Check, o.Key)
	}
	if len(got.Seen) != len(seen) {
		t.Errorf("finding shows %d answers, want %d:%s", len(got.Seen), len(seen), decShow([]Finding{got}))
	} else {
		for i, s := range seen {
			if !reflect.DeepEqual(got.Seen[i].Answer, o.Answers[s.at]) || got.Seen[i].Text != s.text {
				t.Errorf("seen %d is %v %q, want answer %d %q", i, got.Seen[i].Answer.Server, got.Seen[i].Text, s.at, s.text)
			}
		}
	}
	if want := emlValue(seen, words...); got.Value != want {
		t.Errorf("value is %q, want %q", got.Value, want)
	}
}

// emlOne is the one finding of a run.
func emlOne(t *testing.T, f *expect.File, o obs.Observation) Finding {
	t.Helper()
	got := Findings(f, o)
	if len(got) != 1 {
		t.Fatalf("want one finding:%s", decShow(got))
	}
	return got[0]
}

// ---- the rule of a line ----

func TestEmlRecordRuleRows(t *testing.T) {
	rows := []struct {
		name string
		part string // the part of the design that gives the row
		line string
		typ  dnswire.Type
		now  string // what one server gives; it differs from the line
		want Rule
		sev  Severity
	}{
		// Row 1: none and a challenge name.
		{"none at a challenge name", "A3 1", `_acme-challenge.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("x"), RuleChallenge, SeverityHigh},
		{"none at a challenge name, a CNAME", "A3 1", `_acme-challenge.corp.test. CNAME none`, dnswire.TypeCNAME, "CNAME x.test.", RuleChallenge, SeverityHigh},
		{"none at a challenge name that holds a domainkey label", "A3 1 before 4", `_acme-challenge.s1._domainkey.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("x"), RuleChallenge, SeverityHigh},
		{"exact at a challenge name", "A3 1 holds for none only", `_acme-challenge.corp.test. TXT "x"`, dnswire.TypeTXT, emlTXT("y"), RuleRecordSet, SeverityMedium},
		{"exact SPF at a challenge name", "A3 5", `_acme-challenge.corp.test. TXT "v=spf1 -all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleSPF, SeverityMedium},

		// Row 2: a type that is not TXT.
		{"MX", "A3 2", `corp.test. MX 10 mail.corp.test.`, dnswire.TypeMX, "MX 10 evil.test.", RuleRecordSet, SeverityHigh},
		{"A", "A3 2", `corp.test. A 192.0.2.1`, dnswire.TypeA, "A 192.0.2.9", RuleRecordSet, SeverityHigh},
		{"A at a DMARC owner", "A3 2 before 4", `_dmarc.corp.test. A 192.0.2.1`, dnswire.TypeA, "A 192.0.2.9", RuleRecordSet, SeverityHigh},
		{"CNAME at a DMARC owner", "A3 2, the provider that hosts the record", `_dmarc.corp.test. CNAME dmarc.provider.test.`, dnswire.TypeCNAME, "CNAME evil.test.", RuleRecordSet, SeverityHigh},
		{"CNAME at an MTA-STS owner", "A3 2", `_mta-sts.corp.test. CNAME sts.provider.test.`, dnswire.TypeCNAME, "CNAME evil.test.", RuleRecordSet, SeverityHigh},
		{"CNAME at a DKIM owner", "A3 2", `s1._domainkey.corp.test. CNAME s1.provider.test.`, dnswire.TypeCNAME, "CNAME evil.test.", RuleRecordSet, SeverityHigh},
		{"CNAME none at a DMARC owner", "A3 2", `_dmarc.corp.test. CNAME none`, dnswire.TypeCNAME, "CNAME evil.test.", RuleRecordSet, SeverityHigh},

		// Row 3: two alternatives.
		{"two alternatives of SPF", "A3 3", `corp.test. TXT "v=spf1 -all" || "v=spf1 ~all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleRecordSet, SeverityMedium},
		{"two alternatives at a DMARC owner", "A3 3 before 4", `_dmarc.corp.test. TXT "v=DMARC1; p=reject" || "v=DMARC1; p=quarantine"`, dnswire.TypeTXT, emlTXT("v=DMARC1; p=none"), RuleRecordSet, SeverityMedium},
		{"two alternatives at a DKIM owner", "A3 3", `s1._domainkey.corp.test. TXT "v=DKIM1; p=QUJDRA==" || "v=DKIM1; p=RUZHSA=="`, dnswire.TypeTXT, emlTXT("v=DKIM1; p=SUpLTA=="), RuleRecordSet, SeverityMedium},
		{"two alternatives at an MTA-STS owner", "A3 3", `_mta-sts.corp.test. TXT "v=STSv1; id=1" || "v=STSv1; id=2"`, dnswire.TypeTXT, emlTXT("v=STSv1; id=3"), RuleRecordSet, SeverityMedium},

		// Row 4: DMARC, DKIM and MTA-STS owners.
		{"DMARC exact", "A3 4", `_dmarc.corp.test. TXT "v=DMARC1; p=reject"`, dnswire.TypeTXT, emlTXT("v=DMARC1; p=none"), RuleDMARC, SeverityMedium},
		{"DMARC none", "A3 4", `_dmarc.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("v=DMARC1; p=none"), RuleDMARC, SeverityMedium},
		{"DMARC owner in capitals", "A3 4, A2 MailDMARC ignores case", `_DMARC.corp.test. TXT "v=DMARC1; p=reject"`, dnswire.TypeTXT, emlTXT("v=DMARC1; p=none"), RuleDMARC, SeverityMedium},
		{"DMARC owner, a record that reads as SPF", "A3 4 before 5", `_dmarc.corp.test. TXT "v=spf1 -all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleDMARC, SeverityMedium},
		{"DMARC owner below another name", "A3 4: first label", `_dmarc.sub.corp.test. TXT "v=DMARC1; p=reject"`, dnswire.TypeTXT, emlTXT("v=DMARC1; p=none"), RuleDMARC, SeverityMedium},
		{"a first label _dmarc wins over a later _domainkey", "decision 5 item 6", `_dmarc._domainkey.corp.test. TXT "x"`, dnswire.TypeTXT, emlTXT("y"), RuleDMARC, SeverityMedium},
		{"DKIM exact", "A3 4", `s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; p=QUJDRA=="`, dnswire.TypeTXT, emlTXT("v=DKIM1; k=rsa; p=RUZHSA=="), RuleDKIM, SeverityMedium},
		{"DKIM none", "A3 4", `s1._domainkey.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("v=DKIM1; k=rsa; p=RUZHSA=="), RuleDKIM, SeverityMedium},
		{"DKIM label in capitals", "A2 MailDKIM ignores case", `s1._DomainKey.corp.test. TXT "v=DKIM1; p=QUJDRA=="`, dnswire.TypeTXT, emlTXT("v=DKIM1; p=RUZHSA=="), RuleDKIM, SeverityMedium},
		{"DKIM, a selector of two labels", "A2 MailDKIM: a label after the first", `a.b._domainkey.corp.test. TXT "x"`, dnswire.TypeTXT, emlTXT("y"), RuleDKIM, SeverityMedium},
		{"the _domainkey name itself", "A2 MailDKIM: a label after the first", `_domainkey.corp.test. TXT "x"`, dnswire.TypeTXT, emlTXT("y"), RuleRecordSet, SeverityMedium},
		{"MTA-STS exact", "A3 4", `_mta-sts.corp.test. TXT "v=STSv1; id=20261117"`, dnswire.TypeTXT, emlTXT("v=STSv1; id=20261118"), RuleMTASTS, SeverityMedium},
		{"MTA-STS none", "A3 4", `_mta-sts.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("v=STSv1; id=1"), RuleMTASTS, SeverityMedium},
		{"MTA-STS owner in capitals", "A2 MailMTASTS ignores case", `_MTA-STS.corp.test. TXT "v=STSv1; id=1"`, dnswire.TypeTXT, emlTXT("v=STSv1; id=2"), RuleMTASTS, SeverityMedium},

		// Row 5: SPF.
		{"SPF at the apex", "A3 5", `corp.test. TXT "v=spf1 mx -all"`, dnswire.TypeTXT, emlTXT("v=spf1 mx ~all"), RuleSPF, SeverityMedium},
		{"SPF at a host", "A3 5", `www.corp.test. TXT "v=spf1 -all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleSPF, SeverityMedium},
		{"SPF at a name with an underscore", "A3 5", `_spf.corp.test. TXT "v=spf1 -all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleSPF, SeverityMedium},
		{"SPF in capitals", "B1 rule 2", `corp.test. TXT "V=SPF1 -ALL"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleSPF, SeverityMedium},
		{"SPF with another record", "A3, the token beside SPF", `corp.test. TXT "google-site-verification=a" | "v=spf1 mx -all"`, dnswire.TypeTXT, emlTXT("google-site-verification=b"), RuleSPF, SeverityMedium},
		{"SPF record of two SPF texts", "A2 HasSPF: two included", `corp.test. TXT "v=spf1 -all" | "v=spf1 ~all"`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleSPF, SeverityMedium},
		{"SPF alone, an SPF line at a host that gets no data", "A3 5", `mail.corp.test. TXT "v=spf1 a -all"`, dnswire.TypeTXT, "nodata", RuleSPF, SeverityMedium},
		{"SPF at the apex, seen as a CNAME", "A3 5: the line decides", `corp.test. TXT "v=spf1 a -all"`, dnswire.TypeTXT, "CNAME evil.test.", RuleSPF, SeverityMedium},

		// Row 6: every other line.
		{"TXT with no SPF at the apex", "A3 6", `corp.test. TXT "google-site-verification=a"`, dnswire.TypeTXT, emlTXT("google-site-verification=b"), RuleRecordSet, SeverityMedium},
		{"TXT with no SPF at a host", "A3 6", `www.corp.test. TXT "hello"`, dnswire.TypeTXT, emlTXT("world"), RuleRecordSet, SeverityMedium},
		{"TXT none at the apex", "A3 6", `corp.test. TXT none`, dnswire.TypeTXT, emlTXT("v=spf1 +all"), RuleRecordSet, SeverityMedium},
		{"TXT none at a host", "A3 6", `www.corp.test. TXT none`, dnswire.TypeTXT, emlTXT("x"), RuleRecordSet, SeverityMedium},
		{"a longer version is no SPF", "B1 rule 2", `corp.test. TXT "v=spf10 -all"`, dnswire.TypeTXT, emlTXT("v=spf10 +all"), RuleRecordSet, SeverityMedium},
		{"a text that starts with SPF text after a space", "B1 rule 2", `corp.test. TXT " v=spf1 -all"`, dnswire.TypeTXT, emlTXT(" v=spf1 +all"), RuleRecordSet, SeverityMedium},
		{"MTA-STS text at the apex", "A3 6", `corp.test. TXT "v=STSv1; id=1"`, dnswire.TypeTXT, emlTXT("v=STSv1; id=2"), RuleRecordSet, SeverityMedium},
	}
	for _, r := range rows {
		t.Run(r.name+" ("+r.part+")", func(t *testing.T) {
			f := emlFile(t, r.line)
			owner, _, _ := strings.Cut(r.line, " ")
			o := emlObserve(t, owner, r.typ, r.now)
			got := Findings(f, o)
			if len(got) != 1 {
				t.Fatalf("want one finding:%s", decShow(got))
			}
			if got[0].Rule != r.want || got[0].Severity != r.sev {
				t.Errorf("finding is %v %v, want %v %v", got[0].Rule, got[0].Severity, r.want, r.sev)
			}
			if (r.want == RuleRecordSet || r.want == RuleChallenge) && strings.Contains(got[0].Value, "weaker ") {
				t.Errorf("a %v finding holds a weaker line: %q", r.want, got[0].Value)
			}
		})
	}
}

// The rule comes from the line and never from the run: what the servers give
// changes the words and never the rule.
func TestEmlRuleDoesNotDependOnTheRun(t *testing.T) {
	lines := []struct {
		line string
		rule Rule
	}{
		{`corp.test. TXT "v=spf1 mx -all"`, RuleSPF},
		{`_dmarc.corp.test. TXT "v=DMARC1; p=reject"`, RuleDMARC},
		{`s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; p=QUJDRA=="`, RuleDKIM},
		{`_mta-sts.corp.test. TXT "v=STSv1; id=20261117"`, RuleMTASTS},
		{`_dmarc.corp.test. TXT none`, RuleDMARC},
		{`corp.test. TXT "google-site-verification=a"`, RuleRecordSet},
		{`corp.test. TXT none`, RuleRecordSet},
	}
	runs := []string{
		"nodata", "noname", emlTXT("v=spf1 +all"), emlTXT("v=DMARC1; p=none"), emlTXT("v=DKIM1; k=rsa; p=RUZHSA=="),
		emlTXT("v=STSv1; id=1"), emlTXT("hello"), "CNAME evil.test.", "MX 10 evil.test.", emlTXT("a") + "\n" + emlTXT("b"),
	}
	for _, l := range lines {
		f := emlFile(t, l.line)
		owner, _, _ := strings.Cut(l.line, " ")
		seen := 0
		for _, run := range runs {
			o := emlObserve(t, owner, dnswire.TypeTXT, run)
			for _, g := range Findings(f, o) {
				seen++
				if g.Rule != l.rule {
					t.Errorf("%s with the run %q gives %v, want %v", l.line, run, g.Rule, l.rule)
				}
			}
		}
		if seen == 0 {
			t.Errorf("%s gave no finding for any run", l.line)
		}
	}
}

// ---- the finding of a rule ----

func TestEmlFindingRows(t *testing.T) {
	const (
		spfLine  = `corp.test. TXT "v=spf1 mx -all"`
		spfWas   = `"v=spf1 mx -all"`
		dmarcLn  = `_dmarc.corp.test. TXT "v=DMARC1; p=reject"`
		dmarcWas = `"v=DMARC1; p=reject"`
		dkimLn   = `s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; p=QUJDRA=="`
		dkimWas  = `"v=DKIM1; k=rsa; p=QUJDRA=="`
		stsLn    = `_mta-sts.corp.test. TXT "v=STSv1; id=20261117"`
		stsWas   = `"v=STSv1; id=20261117"`
		none     = "none"
	)
	// SPF terms for the cap: n distinct terms of one address each.
	terms := func(from, n int) string {
		var s []string
		for i := range n {
			s = append(s, fmt.Sprintf("ip4:192.0.2.%d", from+i))
		}
		return strings.Join(s, " ")
	}
	addrWords := func(from, n int) []string {
		var w []string
		for i := range n {
			w = append(w, fmt.Sprintf("ip4:192.0.2.%d/32 gives pass in place of fail", from+i))
		}
		return w
	}
	rows := []struct {
		name     string
		part     string
		line     string
		owner    string
		answers  []string
		rule     Rule
		expected string
		seen     []emlSeen
		words    []string
	}{
		{"spf, two servers give the same set", "A4, C1, B1 S8", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx ~all"), emlTXT("v=spf1 mx ~all")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 mx ~all")}, {1, emlQ("v=spf1 mx ~all")}}, []string{"all gives softfail in place of fail"}},
		{"spf, a server that matches is not seen", "A4 Seen", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx -all"), emlTXT("v=spf1 mx ~all"), emlTXT("v=spf1 mx -all")}, RuleSPF, spfWas,
			[]emlSeen{{1, emlQ("v=spf1 mx ~all")}}, []string{"all gives softfail in place of fail"}},
		{"spf, a failure is unknown", "A4 Seen", spfLine, "corp.test.",
			[]string{"fail", emlTXT("v=spf1 mx ~all")}, RuleSPF, spfWas,
			[]emlSeen{{1, emlQ("v=spf1 mx ~all")}}, []string{"all gives softfail in place of fail"}},
		{"spf, a difference that permits nothing more", "A4, B1 S7", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx -all foo=bar exp=why.corp.test"), emlTXT("v=spf1 mx -all foo=bar exp=why.corp.test")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 mx -all foo=bar exp=why.corp.test")}, {1, emlQ("v=spf1 mx -all foo=bar exp=why.corp.test")}}, nil},
		{"spf, a stricter record gives the finding with no word", "A0 item 2", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 -all")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 -all")}}, nil},
		{"spf, a token beside the record changed", "A3 row 5", `corp.test. TXT "google-site-verification=a" | "v=spf1 mx -all"`, "corp.test.",
			[]string{emlTXT("v=spf1 mx -all")}, RuleSPF, `"v=spf1 mx -all" | "google-site-verification=a"`,
			[]emlSeen{{0, emlQ("v=spf1 mx -all")}}, nil},
		{"spf, the words of two servers come in the order of the servers", "A4 Words", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx ~all"), emlTXT("v=spf1 mx include:evil.test -all")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 mx ~all")}, {1, emlQ("v=spf1 mx include:evil.test -all")}},
			[]string{"all gives softfail in place of fail", "include:evil.test gives pass in place of fail"}},
		{"spf, the same two servers the other way round", "A4 Words: first appearance, not sorted", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx include:evil.test -all"), emlTXT("v=spf1 mx ~all")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 mx include:evil.test -all")}, {1, emlQ("v=spf1 mx ~all")}},
			[]string{"include:evil.test gives pass in place of fail", "all gives softfail in place of fail"}},
		{"spf, a word that two sets share is kept once", "A4 Words", spfLine, "corp.test.",
			[]string{emlTXT("v=spf1 mx ~all"), emlTXT("v=spf1 mx include:evil.test ~all"), emlTXT("v=spf1 mx ~all")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("v=spf1 mx ~all")}, {1, emlQ("v=spf1 mx include:evil.test ~all")}, {2, emlQ("v=spf1 mx ~all")}},
			[]string{"all gives softfail in place of fail", "include:evil.test gives pass in place of fail"}},
		{"spf, no SPF record where the line has one", "B1 S17", spfLine, "corp.test.",
			[]string{emlTXT("google-site-verification=x")}, RuleSPF, spfWas,
			[]emlSeen{{0, emlQ("google-site-verification=x")}}, []string{"no SPF record: receivers treat every sender as neutral"}},
		{"spf, 12 words of two servers are all shown", "A2 Cap: more than MaxWords", `corp.test. TXT "v=spf1 -all"`, "corp.test.",
			[]string{emlTXT("v=spf1 " + terms(1, 6) + " -all"), emlTXT("v=spf1 " + terms(11, 6) + " -all")}, RuleSPF, `"v=spf1 -all"`,
			[]emlSeen{{0, emlQ("v=spf1 " + terms(1, 6) + " -all")}, {1, emlQ("v=spf1 " + terms(11, 6) + " -all")}},
			append(addrWords(1, 6), addrWords(11, 6)...)},
		{"spf, 13 words of two servers are cut to 11 and a count", "A4 Words: cap", `corp.test. TXT "v=spf1 -all"`, "corp.test.",
			[]string{emlTXT("v=spf1 " + terms(1, 6) + " -all"), emlTXT("v=spf1 " + terms(11, 7) + " -all")}, RuleSPF, `"v=spf1 -all"`,
			[]emlSeen{{0, emlQ("v=spf1 " + terms(1, 6) + " -all")}, {1, emlQ("v=spf1 " + terms(11, 7) + " -all")}},
			append(append(addrWords(1, 6), addrWords(11, 5)...), "and 2 more")},
		{"spf, 14 words of two servers", "A4 Words: cap, k counts the words left out", `corp.test. TXT "v=spf1 -all"`, "corp.test.",
			[]string{emlTXT("v=spf1 " + terms(1, 7) + " -all"), emlTXT("v=spf1 " + terms(11, 7) + " -all")}, RuleSPF, `"v=spf1 -all"`,
			[]emlSeen{{0, emlQ("v=spf1 " + terms(1, 7) + " -all")}, {1, emlQ("v=spf1 " + terms(11, 7) + " -all")}},
			append(append(addrWords(1, 7), addrWords(11, 4)...), "and 3 more")},

		{"dmarc, two words", "A4, C2, B2 D8 style", dmarcLn, "_dmarc.corp.test.",
			[]string{emlTXT("v=DMARC1; p=none; rua=mailto:x@evil.test"), emlTXT("v=DMARC1; p=none; rua=mailto:x@evil.test")}, RuleDMARC, dmarcWas,
			[]emlSeen{{0, emlQ("v=DMARC1; p=none; rua=mailto:x@evil.test")}, {1, emlQ("v=DMARC1; p=none; rua=mailto:x@evil.test")}},
			[]string{"p=none in place of p=reject", "rua also sends reports to mailto:x@evil.test"}},
		{"dmarc, a record written otherwise gives no word", "B2 D1", dmarcLn, "_dmarc.corp.test.",
			[]string{emlTXT("v=DMARC1;p=reject")}, RuleDMARC, dmarcWas, []emlSeen{{0, emlQ("v=DMARC1;p=reject")}}, nil},
		{"dmarc, no record", "B2 D10", dmarcLn, "_dmarc.corp.test.",
			[]string{"nodata"}, RuleDMARC, dmarcWas, []emlSeen{{0, none}}, []string{"no DMARC record: receivers apply no DMARC policy"}},
		{"dmarc, no such name", "B2 D10", dmarcLn, "_dmarc.corp.test.",
			[]string{"noname"}, RuleDMARC, dmarcWas, []emlSeen{{0, none}}, []string{"no DMARC record: receivers apply no DMARC policy"}},
		{"dmarc, the file says none and a record appeared", "B2 D12", `_dmarc.corp.test. TXT none`, "_dmarc.corp.test.",
			[]string{emlTXT("v=DMARC1; p=none; rua=mailto:x@evil.test")}, RuleDMARC, "none",
			[]emlSeen{{0, emlQ("v=DMARC1; p=none; rua=mailto:x@evil.test")}}, nil},
		{"dmarc, the words of two servers in order", "A4 Words", dmarcLn, "_dmarc.corp.test.",
			[]string{emlTXT("v=DMARC1; p=none"), emlTXT("v=DMARC1; p=quarantine")}, RuleDMARC, dmarcWas,
			[]emlSeen{{0, emlQ("v=DMARC1; p=none")}, {1, emlQ("v=DMARC1; p=quarantine")}},
			[]string{"p=none in place of p=reject", "p=quarantine in place of p=reject"}},

		{"dkim, another key", "A4, C3, B3 K2", dkimLn, "s1._domainkey.corp.test.",
			[]string{emlTXT("v=DKIM1; k=rsa; p=RUZHSA=="), emlTXT("v=DKIM1; k=rsa; p=RUZHSA==")}, RuleDKIM, dkimWas,
			[]emlSeen{{0, emlQ("v=DKIM1; k=rsa; p=RUZHSA==")}, {1, emlQ("v=DKIM1; k=rsa; p=RUZHSA==")}},
			[]string{`a key that the file does not list: k=rsa, 8 characters, ending "RUZHSA=="`}},
		{"dkim, a revoked key gives no word", "B3 K3", dkimLn, "s1._domainkey.corp.test.",
			[]string{emlTXT("v=DKIM1; k=rsa; p=")}, RuleDKIM, dkimWas, []emlSeen{{0, emlQ("v=DKIM1; k=rsa; p=")}}, nil},
		{"dkim, the file says none and a key appeared", "B3 K4", `s1._domainkey.corp.test. TXT none`, "s1._domainkey.corp.test.",
			[]string{emlTXT("v=DKIM1; k=rsa; p=QUJDRA==")}, RuleDKIM, "none", []emlSeen{{0, emlQ("v=DKIM1; k=rsa; p=QUJDRA==")}},
			[]string{`a key that the file does not list: k=rsa, 8 characters, ending "QUJDRA=="`}},
		{"dkim, an alias that hands the key to another zone", "B3 K10", dkimLn, "s1._domainkey.corp.test.",
			[]string{"CNAME s1.dkim.evil.test."}, RuleDKIM, dkimWas, []emlSeen{{0, "CNAME s1.dkim.evil.test."}},
			[]string{"a key that the file does not list: CNAME s1.dkim.evil.test."}},
		{"dkim, a key that leaves testing mode", "B3 K6", `s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; t=y; p=QUJDRA=="`, "s1._domainkey.corp.test.",
			[]string{emlTXT("v=DKIM1; k=rsa; p=QUJDRA==")}, RuleDKIM, `"v=DKIM1; k=rsa; t=y; p=QUJDRA=="`, []emlSeen{{0, emlQ("v=DKIM1; k=rsa; p=QUJDRA==")}},
			[]string{`the key k=rsa, 8 characters, ending "QUJDRA==" leaves testing mode: t=y is gone`}},

		{"mta-sts, no record", "A4, C4, B4 M2", stsLn, "_mta-sts.corp.test.",
			[]string{"nodata", "nodata"}, RuleMTASTS, stsWas, []emlSeen{{0, none}, {1, none}},
			[]string{"no MTA-STS record: senders that have not cached the policy send mail without it"}},
		{"mta-sts, a new id alone", "C4, B4 M1", stsLn, "_mta-sts.corp.test.",
			[]string{emlTXT("v=STSv1; id=20261118")}, RuleMTASTS, stsWas, []emlSeen{{0, emlQ("v=STSv1; id=20261118")}}, nil},
		{"mta-sts, a record that cannot be read", "B4 M4", stsLn, "_mta-sts.corp.test.",
			[]string{emlTXT("v=STSv1; id=abc!")}, RuleMTASTS, stsWas, []emlSeen{{0, emlQ("v=STSv1; id=abc!")}},
			[]string{"an MTA-STS record that cannot be read: senders that have not cached the policy send mail without it"}},
		{"mta-sts, the file says none and a record appeared", "B4 M6", `_mta-sts.corp.test. TXT none`, "_mta-sts.corp.test.",
			[]string{emlTXT("v=STSv1; id=1")}, RuleMTASTS, "none", []emlSeen{{0, emlQ("v=STSv1; id=1")}}, nil},
	}
	for _, r := range rows {
		t.Run(r.name+" ("+r.part+")", func(t *testing.T) {
			o := emlObserve(t, r.owner, dnswire.TypeTXT, r.answers...)
			got := emlOne(t, emlFile(t, r.line), o)
			emlCheck(t, got, o, r.rule, r.expected, r.seen, r.words...)
		})
	}
}

// A line is no finding while every server gives what the line says, and a
// failure is no answer.
func TestEmlNoFindingWhenEveryServerMatches(t *testing.T) {
	for _, c := range []struct{ line, owner, same string }{
		{`corp.test. TXT "v=spf1 mx -all"`, "corp.test.", emlTXT("v=spf1 mx -all")},
		{`_dmarc.corp.test. TXT "v=DMARC1; p=reject"`, "_dmarc.corp.test.", emlTXT("v=DMARC1; p=reject")},
		{`s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; p=QUJDRA=="`, "s1._domainkey.corp.test.", emlTXT("v=DKIM1; k=rsa; p=QUJDRA==")},
		{`_mta-sts.corp.test. TXT "v=STSv1; id=1"`, "_mta-sts.corp.test.", emlTXT("v=STSv1; id=1")},
		{`_dmarc.corp.test. TXT none`, "_dmarc.corp.test.", "nodata"},
		{`_mta-sts.corp.test. TXT none`, "_mta-sts.corp.test.", "noname"},
	} {
		f := emlFile(t, c.line)
		for name, specs := range map[string][]string{
			"all match":          {c.same, c.same},
			"one failure":        {"fail", c.same},
			"all fail":           {"fail", "fail"},
			"a failure and none": {c.same, "fail", c.same},
		} {
			if got := Findings(f, emlObserve(t, c.owner, dnswire.TypeTXT, specs...)); len(got) != 0 {
				t.Errorf("%s, %s:%s", c.line, name, decShow(got))
			}
		}
	}
}

// A line that all servers fail on gives no finding of a mail rule, and a
// failure never takes part in the words.
func TestEmlFailureTakesNoPartInTheWords(t *testing.T) {
	f := emlFile(t, `corp.test. TXT "v=spf1 mx -all"`)
	o := emlObserve(t, "corp.test.", dnswire.TypeTXT, "fail", emlTXT("v=spf1 mx ~all"), "fail")
	got := emlOne(t, f, o)
	emlCheck(t, got, o, RuleSPF, `"v=spf1 mx -all"`, []emlSeen{{1, emlQ("v=spf1 mx ~all")}}, "all gives softfail in place of fail")
}

// ---- changed ----

func TestEmlChangedIsNewValueOrNewWord(t *testing.T) {
	const line = `corp.test. TXT "v=spf1 mx -all"`
	f := emlFile(t, line)
	run := func(specs ...string) obs.Observation { return emlObserve(t, "corp.test.", dnswire.TypeTXT, specs...) }
	soft, wide := emlTXT("v=spf1 mx ~all"), emlTXT("v=spf1 mx include:evil.test -all")
	open := emlOne(t, f, run(soft, "fail"))
	decide := func(open Finding, o obs.Observation) []Change {
		return Decide(Input{Expect: f, Open: []Finding{open}, Observation: o, Now: decT0.Add(time.Minute)})
	}
	update := func(o obs.Observation) []Change {
		return []Change{{Op: OpUpdate, Finding: emlOne(t, f, o), At: decT0.Add(time.Minute)}}
	}
	refresh := func(o obs.Observation) []Change {
		return []Change{{Op: OpRefresh, Finding: emlOne(t, f, o), At: decT0.Add(time.Minute)}}
	}
	for _, c := range []struct {
		name string
		o    obs.Observation
		want []Change
	}{
		{"the same run", run(soft, "fail"), nil},
		{"the same set at one more server is no news, and the alert keeps it", run(soft, soft), refresh(run(soft, soft))},
		{"another set at the same server is a new value and a new word", run(wide, "fail"), update(run(wide, "fail"))},
		{"the server that matched now differs", run(soft, wide), update(run(soft, wide))},
	} {
		t.Run(c.name, func(t *testing.T) { decSameChanges(t, decide(open, c.o), c.want) })
	}
	t.Run("a server line that is gone is no news", func(t *testing.T) {
		wide := emlOne(t, f, run(soft, soft))
		decSameChanges(t, decide(wide, run(soft, "fail")), nil)
	})
	t.Run("a server that matches again leaves the finding open", func(t *testing.T) {
		wide := emlOne(t, f, run(soft, soft))
		decSameChanges(t, decide(wide, run(soft, emlTXT("v=spf1 mx -all"))), nil)
	})
	t.Run("a word that the open finding lacks is news", func(t *testing.T) {
		stale := open
		stale.Value = emlValue([]emlSeen{{0, emlQ("v=spf1 mx ~all")}})
		o := run(soft, "fail")
		decSameChanges(t, decide(stale, o), update(o))
	})
	t.Run("a word that is gone is no news", func(t *testing.T) {
		old := open
		old.Value += "\nweaker an old word"
		decSameChanges(t, decide(old, run(soft, "fail")), nil)
	})
	t.Run("a new word line is news also when the server lines are the same", func(t *testing.T) {
		old := open
		old.Value = emlValue([]emlSeen{{0, emlQ("v=spf1 mx ~all")}}, "all gives neutral in place of fail")
		o := run(soft, "fail")
		decSameChanges(t, decide(old, o), update(o))
	})
	t.Run("another line text is news", func(t *testing.T) {
		old := open
		old.Expected = `"v=spf1 a -all"`
		o := run(soft, "fail")
		decSameChanges(t, decide(old, o), update(o))
	})
}

// Every mail rule opens, stays quiet on a repeat, keeps the same set at one
// more server without a message, and updates on a new set.
func TestEmlEachRuleOpensAndUpdates(t *testing.T) {
	for _, k := range emlKinds {
		t.Run(k.word, func(t *testing.T) {
			f := emlFile(t, k.line)
			o := emlObserve(t, k.owner, dnswire.TypeTXT, k.now, k.now)
			found := emlOne(t, f, o)
			in := Input{Expect: f, Observation: o, Now: decT0.Add(time.Minute)}
			decSameChanges(t, Decide(in), []Change{{Op: OpOpen, Finding: found, At: in.Now}})
			in.Open = []Finding{found}
			decSameChanges(t, Decide(in), nil)
			in.Observation = emlObserve(t, k.owner, dnswire.TypeTXT, k.now, k.now, k.now)
			decSameChanges(t, Decide(in), []Change{{Op: OpRefresh, Finding: emlOne(t, f, in.Observation), At: in.Now}})

			in.Observation = emlObserve(t, k.owner, dnswire.TypeTXT, k.now, k.now, "nodata")
			again := emlOne(t, f, in.Observation)
			decSameChanges(t, Decide(in), []Change{{Op: OpUpdate, Finding: again, At: in.Now}})
		})
	}
}

// The resolve of each mail rule shows the line that is in force, as the
// resolve of a record-set alert does.
func TestEmlResolveShowsTheLineInForce(t *testing.T) {
	for _, k := range emlKinds {
		t.Run(k.word, func(t *testing.T) {
			oldFile := emlFile(t, k.line)
			open := emlOne(t, oldFile, emlObserve(t, k.owner, dnswire.TypeTXT, k.now))
			// The operator accepted the set that the servers give.
			e := k.owner + " TXT " + k.nowQuoted
			f := emlFile(t, e)
			o := emlObserve(t, k.owner, dnswire.TypeTXT, k.now)
			if got := Findings(f, o); len(got) != 0 {
				t.Fatalf("the new line still gives%s", decShow(got))
			}
			want := open
			want.Expected = k.nowQuoted
			in := Input{Expect: f, Open: []Finding{open}, Observation: o, Now: decT0.Add(time.Minute)}
			decSameChanges(t, Decide(in), []Change{{Op: OpResolve, Finding: want, At: in.Now}})
		})
	}
}

// ---- LineRule and inForce ----

func TestEmlLineRule(t *testing.T) {
	line := []Rule{RuleRecordSet, RuleChallenge, RuleSPF, RuleDMARC, RuleDKIM, RuleMTASTS}
	for r := Rule(0); r <= RuleMTASTS+3; r++ {
		if got, want := LineRule(r), slices.Contains(line, r); got != want {
			t.Errorf("LineRule(%d %v) is %v, want %v", r, r, got, want)
		}
	}
}

func TestEmlInForceNamesTheLineOfEveryLineRule(t *testing.T) {
	f := emlFile(t, `_dmarc.corp.test. TXT "v=DMARC1; p=reject"`)
	in := Input{Expect: f, Observation: emlObserve(t, "_dmarc.corp.test.", dnswire.TypeTXT, "nodata")}
	for r := RuleInvalidFile; r <= RuleMTASTS; r++ {
		was := Finding{Rule: r, Expected: "old"}
		got := inForce(was, in).Expected
		want := "old"
		if LineRule(r) || r == RuleNameServers || r == RuleDS {
			want = `"v=DMARC1; p=reject"`
		}
		if got != want {
			t.Errorf("inForce of %v gives %q, want %q", r, got, want)
		}
	}
	for _, r := range []Rule{RuleSPF, RuleDMARC, RuleDKIM, RuleMTASTS} {
		in.Expect = nil
		if got := inForce(Finding{Rule: r, Expected: "old"}, in).Expected; got != "old" {
			t.Errorf("with no file, inForce of %v gives %q", r, got)
		}
	}
}

// ---- explained ----

func TestEmlRuleExplainsTheSplit(t *testing.T) {
	for _, k := range emlKinds {
		t.Run(k.word, func(t *testing.T) {
			// One server matches the line and one differs: the split is the
			// difference from the line, and the rule of the line says so.
			f := emlFile(t, k.line)
			o := emlObserve(t, k.owner, dnswire.TypeTXT, emlTXT(k.was), k.now)
			if !Disagree(o) {
				t.Fatal("the servers do not split")
			}
			in := Input{Expect: f, Observation: o, Now: decT0.Add(time.Minute), DisagreeLong: true}
			got := Decide(in)
			if len(got) != 1 || got[0].Finding.Rule != k.rule || got[0].Op != OpOpen {
				t.Errorf("want one open of %v:%s", k.rule, decShowChanges(got))
			}
			// The control: a split that no finding explains opens disagree.
			alts := emlFile(t, k.owner+" TXT "+emlQ(k.was)+" || "+k.nowQuoted)
			in.Expect = alts
			got = Decide(in)
			if len(got) != 1 || got[0].Finding.Rule != RuleDisagree {
				t.Errorf("want one open of disagree:%s", decShowChanges(got))
			}
		})
	}
}

// ---- words, numbers and severities ----

func TestEmlRuleWordsNumbersAndSeverities(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		num  Rule
		word string
	}{
		{RuleSPF, 21, "spf"},
		{RuleDMARC, 22, "dmarc"},
		{RuleDKIM, 23, "dkim"},
		{RuleMTASTS, 24, "mta-sts"},
	} {
		if c.rule != c.num {
			t.Errorf("%s is rule number %d, want %d: the store keeps the number", c.word, c.rule, c.num)
		}
		if got := c.num.String(); got != c.word {
			t.Errorf("Rule(%d).String() is %q, want %q", c.num, got, c.word)
		}
		for _, typ := range []dnswire.Type{0, dnswire.TypeA, dnswire.TypeTXT, dnswire.TypeCNAME, dnswire.TypeMX, dnswire.TypeNS} {
			if got := severity(c.rule, typ); got != SeverityMedium {
				t.Errorf("%s severity for type %v is %v, want medium", c.word, typ, got)
			}
		}
	}
	if got := Rule(25).String(); got != "rule25" {
		t.Errorf("Rule(25).String() is %q, want rule25", got)
	}
}

// ---- the table of the rules ----

type emlKind struct {
	word      string
	rule      Rule
	owner     string
	line      string // the line of the file
	was       string // the text of the line
	now       string // a set that a server gives instead
	nowQuoted string // the form text of a line that holds now, when now is TXT
}

var emlKinds = []emlKind{
	{"spf", RuleSPF, "corp.test.", `corp.test. TXT "v=spf1 mx -all"`, "v=spf1 mx -all", emlTXT("v=spf1 mx ~all"), `"v=spf1 mx ~all"`},
	{"dmarc", RuleDMARC, "_dmarc.corp.test.", `_dmarc.corp.test. TXT "v=DMARC1; p=reject"`, "v=DMARC1; p=reject", emlTXT("v=DMARC1; p=quarantine"), `"v=DMARC1; p=quarantine"`},
	{"dkim", RuleDKIM, "s1._domainkey.corp.test.", `s1._domainkey.corp.test. TXT "v=DKIM1; k=rsa; p=QUJDRA=="`, "v=DKIM1; k=rsa; p=QUJDRA==", emlTXT("v=DKIM1; k=rsa; p=RUZHSA=="), `"v=DKIM1; k=rsa; p=RUZHSA=="`},
	{"mta-sts", RuleMTASTS, "_mta-sts.corp.test.", `_mta-sts.corp.test. TXT "v=STSv1; id=20261117"`, "v=STSv1; id=20261117", emlTXT("v=STSv1; id=20261118"), `"v=STSv1; id=20261118"`},
}

// ---- oracles for the property tests, written again from the table of the rules ----

// emlTexts gives the text of each TXT record of set: its strings joined.
func emlTexts(set []dnswire.RData) []string {
	var texts []string
	for _, d := range set {
		if txt, ok := d.(dnswire.TXT); ok {
			texts = append(texts, strings.Join(txt.Strings, ""))
		}
	}
	return texts
}

// emlIsSPF says whether text is selected as an SPF record: it starts with
// "v=spf1" in any case and ends there or goes on with a space.
func emlIsSPF(text string) bool {
	return len(text) >= 6 && strings.EqualFold(text[:6], "v=spf1") && (len(text) == 6 || text[6] == ' ')
}

// emlOracleRule is the rule that a line gives when a server's set does not
// match it, for a line that is not a challenge line.
func emlOracleRule(line expect.Expectation) Rule {
	if line.Type != dnswire.TypeTXT || (line.Form == expect.FormSets && len(line.Sets) > 1) {
		return RuleRecordSet
	}
	labels := line.Name.Labels()
	switch {
	case len(labels) > 0 && strings.EqualFold(labels[0], "_dmarc"):
		return RuleDMARC
	case len(labels) > 0 && strings.EqualFold(labels[0], "_mta-sts"):
		return RuleMTASTS
	case len(labels) > 1 && slices.ContainsFunc(labels[1:], func(l string) bool { return strings.EqualFold(l, "_domainkey") }):
		return RuleDKIM
	}
	if line.Form == expect.FormSets && slices.ContainsFunc(emlTexts(line.Sets[0]), emlIsSPF) {
		return RuleSPF
	}
	return RuleRecordSet
}

// emlOracleValue is the Value of a finding of rule r: the server lines, then
// the words of the distinct sets in order of first appearance.
func emlOracleValue(r Rule, line expect.Expectation, seen []Seen, serverLines string) string {
	if r != RuleSPF && r != RuleDMARC && r != RuleDKIM && r != RuleMTASTS {
		return serverLines
	}
	var was []dnswire.RData
	if line.Form == expect.FormSets {
		was = line.Sets[0]
	}
	var texts []string
	var lists [][]string
	for _, s := range seen {
		if slices.Contains(texts, s.Text) {
			continue
		}
		texts = append(texts, s.Text)
		set, _ := regSetOf(s.Answer)
		var now []dnswire.RData
		for _, rr := range set {
			now = append(now, rr.Data)
		}
		lists = append(lists, expect.Weaker(expect.MailKindOf(line.Name), line.Name, was, now))
	}
	value := serverLines
	for _, w := range expect.MergeWords(lists...) {
		value += "\nweaker " + w
	}
	return value
}

// emlSPFTarget is a name that an SPF policy makes receivers look up.
type emlSPFTarget struct {
	name     dnswire.Name
	redirect bool
}

// emlSPFTargets reads the SPF policy of set by the rules of RFC 7208 and
// gives the include domains of the terms before the first all, then the
// redirect domain when there is no all. A set with no SPF record or with
// two, a record with any problem, and a domain with a macro give no name.
func emlSPFTargets(set []dnswire.RData) []emlSPFTarget {
	var records []string
	for _, text := range emlTexts(set) {
		if emlIsSPF(text) {
			records = append(records, text)
		}
	}
	if len(records) != 1 || len(records[0]) > 4096 {
		return nil
	}
	type directive struct {
		mech   string
		domain string // as written, for include
	}
	var directives []directive
	var redirect string
	redirected, exp, hasAll := false, false, false
	var fields []string
	for _, f := range strings.Split(records[0][6:], " ") {
		if f != "" {
			fields = append(fields, f)
		}
	}
	if len(fields) > 128 {
		return nil
	}
	for _, f := range fields {
		for i := range len(f) {
			if f[i] < 0x21 || f[i] > 0x7E {
				return nil
			}
		}
		if name, value, ok := emlModifier(f); ok {
			switch strings.ToLower(name) {
			case "redirect", "exp":
				if !emlDomainSpec(value) {
					return nil
				}
				if strings.EqualFold(name, "redirect") {
					if redirected {
						return nil
					}
					redirected, redirect = true, value
				} else {
					if exp {
						return nil
					}
					exp = true
				}
			}
			continue
		}
		mech, domain, ok := emlDirective(f)
		if !ok {
			return nil
		}
		if mech == "all" {
			hasAll = true
		}
		if !hasAll || mech == "all" {
			directives = append(directives, directive{mech, domain})
		}
	}
	lookups := 0
	for _, d := range directives {
		if slices.Contains([]string{"include", "a", "mx", "ptr", "exists"}, d.mech) {
			lookups++
		}
	}
	if redirected && !hasAll {
		lookups++
	}
	if lookups > 10 {
		return nil
	}
	var out []emlSPFTarget
	add := func(d string, redirect bool) {
		if strings.Contains(d, "%") {
			return
		}
		n, err := dnswire.ParseName(strings.ToLower(strings.TrimSuffix(d, ".")) + ".")
		if err == nil {
			out = append(out, emlSPFTarget{n, redirect})
		}
	}
	for _, d := range directives {
		if d.mech == "include" {
			add(d.domain, false)
		}
	}
	if redirected && !hasAll {
		add(redirect, true)
	}
	return out
}

// emlModifier reads "name=value" where name is ALPHA *(ALPHA / DIGIT / "-" / "_" / ".").
func emlModifier(f string) (name, value string, ok bool) {
	isAlpha := func(c byte) bool { return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' }
	if !isAlpha(f[0]) {
		return "", "", false
	}
	i := 1
	for i < len(f) && (isAlpha(f[i]) || f[i] >= '0' && f[i] <= '9' || strings.IndexByte("-_.", f[i]) >= 0) {
		i++
	}
	if i == len(f) || f[i] != '=' {
		return "", "", false
	}
	return f[:i], f[i+1:], true
}

// emlSpecGrammar is the domain-spec of RFC 7208 section 7.1: any octets and
// macros, then a macro, or a dot, a top label and at most one more dot. A
// top label has a letter, or a hyphen inside letters and digits.
var emlSpecGrammar = func() *regexp.Regexp {
	macro := `%(?:[%_-]|\{[slodiphcrtvSLODIPHCRTV][0-9]*[rR]?[-.+,/_=]*\})`
	top := `(?:[0-9A-Za-z]*[A-Za-z][0-9A-Za-z]*|[0-9A-Za-z]+-[0-9A-Za-z-]*[0-9A-Za-z])`
	return regexp.MustCompile(`^(?:[^%]|` + macro + `)*(?:` + macro + `|\.` + top + `\.?)$`)
}()

// emlDomainSpec says whether d is a domain-spec: it fits the grammar, and a
// name with no macro is also a name that the tool can parse.
func emlDomainSpec(d string) bool {
	if !emlSpecGrammar.MatchString(d) {
		return false
	}
	if strings.Contains(d, "%") {
		return true
	}
	_, err := dnswire.ParseName(strings.ToLower(strings.TrimSuffix(d, ".")) + ".")
	return err == nil
}

// emlLength says whether s is a prefix length of at most max: 0, or a digit
// 1 to 9 followed by digits.
func emlLength(s string, max int) bool {
	if s == "" || (len(s) > 1 && s[0] == '0') || len(s) > 3 {
		return false
	}
	n := 0
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
		n = n*10 + int(c-'0')
	}
	return n <= max
}

// emlDirective reads a directive and gives its mechanism, in lower case, and
// its domain-spec as written; ok is false for a term that cannot be read.
func emlDirective(f string) (mech, domain string, ok bool) {
	if strings.ContainsRune("+-~?", rune(f[0])) {
		f = f[1:]
	}
	end := strings.IndexAny(f, ":/")
	if end < 0 {
		end = len(f)
	}
	mech, rest := strings.ToLower(f[:end]), f[end:]
	switch mech {
	case "all":
		return mech, "", rest == ""
	case "include", "exists":
		d, found := strings.CutPrefix(rest, ":")
		return mech, d, found && emlDomainSpec(d)
	case "ptr":
		if rest == "" {
			return mech, "", true
		}
		d, found := strings.CutPrefix(rest, ":")
		return mech, d, found && emlDomainSpec(d)
	case "a", "mx":
		if d, found := strings.CutPrefix(rest, ":"); found {
			d, tail, slash := strings.Cut(d, "/")
			if !emlDomainSpec(d) {
				return mech, "", false
			}
			rest = ""
			if slash {
				rest = "/" + tail
			}
		}
		return mech, "", emlDualLength(rest)
	case "ip4", "ip6":
		a, found := strings.CutPrefix(rest, ":")
		if !found {
			return mech, "", false
		}
		addr, length, hasLen := strings.Cut(a, "/")
		ip, err := netip.ParseAddr(addr)
		if err != nil || (mech == "ip4" && !ip.Is4()) || (mech == "ip6" && !ip.Is6()) {
			return mech, "", false
		}
		max := 32
		if mech == "ip6" {
			max = 128
		}
		return mech, "", !hasLen || emlLength(length, max)
	}
	return mech, "", false
}

// emlDualLength says whether s is empty, "/<n>", "//<m>" or "/<n>//<m>" with
// n at most 32 and m at most 128.
func emlDualLength(s string) bool {
	if s == "" {
		return true
	}
	if v6, ok := strings.CutPrefix(s, "//"); ok {
		return emlLength(v6, 128)
	}
	v4, v6, dual := strings.Cut(strings.TrimPrefix(s, "/"), "//")
	return strings.HasPrefix(s, "/") && emlLength(v4, 32) && (!dual || emlLength(v6, 128))
}
