package decide

import (
	"cmp"
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// ---- helpers ----

var crtStart = time.Date(2026, 11, 17, 12, 34, 22, 0, time.UTC)

func crtMust(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(fmt.Sprintf("ParseName(%q): %v", s, err))
	}
	return n
}

var crtKey = obs.CertificatesKey(crtMust("corp.test."))

const (
	crtApexLine = `corp.test. CAA 0 issue "ca.test"`
	crtApexPart = `corp.test. CAA 0 issue "ca.test"`
	crtWWWLine  = "www.corp.test. A 10.53.0.81"
)

// crtIss is an issuance of the given names; its dates and hash say nothing
// about the names, so that a renewal is another call with another id.
func crtIss(id int, issuer string, caa []string, names ...string) obs.Issuance {
	ns := make([]dnswire.Name, len(names))
	for i, n := range names {
		ns[i] = crtMust(n)
	}
	slices.SortFunc(ns, dnswire.Compare)
	ns = slices.CompactFunc(ns, dnswire.Name.Equal)
	return obs.Issuance{
		ID:        fmt.Sprint(id),
		TBS:       fmt.Sprintf("%064x", id),
		Names:     ns,
		Issuer:    obs.Issuer{Name: issuer, CAA: caa},
		NotBefore: crtStart.Add(-24 * time.Hour),
		NotAfter:  crtStart.Add(90 * 24 * time.Hour),
	}
}

func crtCerts(complete bool, isss ...obs.Issuance) obs.Certificates {
	return obs.Certificates{Key: crtKey, Start: crtStart, Usable: true, Asked: true, Complete: complete, Issuances: isss}
}

// crtF is a finding of the certificates check; texts are given sorted.
func crtF(rule Rule, expected string, texts ...string) Finding {
	sev := SeverityHigh
	if rule == RuleHostnames {
		sev = SeverityLow
	}
	seen := make([]Seen, len(texts))
	for i, tx := range texts {
		seen[i] = Seen{Answer: obs.Answer{Proof: obs.Proof{Received: crtStart}}, Text: tx}
	}
	return Finding{Rule: rule, Severity: sev, Check: crtKey, Expected: expected, Seen: seen, Value: strings.Join(texts, "\n")}
}

func crtShow(fs []Finding) string {
	var b strings.Builder
	for _, f := range fs {
		fmt.Fprintf(&b, "\n  %v %v %v expected %q value %q", f.Rule, f.Severity, f.Check, f.Expected, f.Value)
	}
	return b.String()
}

func crtSameFindings(t *testing.T, what string, got, want []Finding) {
	t.Helper()
	if len(got) == 0 && len(want) == 0 {
		return
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got %s\n want %s", what, crtShow(got), crtShow(want))
	}
}

// ---- the oracle: F2 to F4, written from the text, climbing with File.Find ----

func crtIsWild(n dnswire.Name) bool {
	l := n.Labels()
	return len(l) > 0 && l[0] == "*"
}

func crtText(n dnswire.Name) string { return n.Lower().String() }

func crtOracle(f *expect.File, c obs.Certificates) []Finding {
	if f == nil || !c.Key.Domain.Equal(f.Domain) {
		return nil
	}
	known := map[string]bool{f.Domain.Key(): true}
	for _, e := range f.Expectations {
		if !crtIsWild(e.Name) {
			known[e.Name.Key()] = true
		}
	}
	certNames := map[string]bool{}
	for _, n := range f.CertNames {
		known[n.Key()] = true
		certNames[n.Key()] = true
	}
	var issuerSeen, certSeen, hostSeen, parts []string
	issuerLinesFail := false
	for _, iss := range c.Issuances {
		for _, n := range iss.Names {
			if !n.IsSubdomainOf(f.Domain) {
				continue
			}
			wild := crtIsWild(n)
			base := n
			if wild {
				base = n.Parent()
			}
			caaOK, part := crtClimb(f, base, wild, iss.Issuer.CAA)
			linesOK := len(f.Issuers) == 0
			for _, name := range iss.Issuer.CAA {
				if slices.Contains(f.Issuers, name) {
					linesOK = true
				}
			}
			if !caaOK || !linesOK {
				if len(iss.Issuer.CAA) > 0 {
					issuerSeen = append(issuerSeen, crtText(n)+" from "+strings.Join(iss.Issuer.CAA, ","))
				} else {
					issuerSeen = append(issuerSeen, crtText(n)+" from an authority with no CAA name ("+iss.Issuer.Name+")")
				}
			}
			if !caaOK {
				parts = append(parts, part)
			}
			if !linesOK {
				issuerLinesFail = true
			}
			if wild && !certNames[n.Key()] {
				certSeen = append(certSeen, crtText(n))
			}
			if !wild && !known[n.Key()] {
				hostSeen = append(hostSeen, crtText(n))
			}
		}
	}
	if issuerLinesFail {
		parts = append(parts, "issuer "+strings.Join(f.Issuers, " "))
	}
	var out []Finding
	mk := func(rule Rule, expected string, texts []string) {
		if len(texts) == 0 {
			return
		}
		slices.Sort(texts)
		texts = slices.Compact(texts)
		x := crtF(rule, expected, texts...)
		x.Check = c.Key
		out = append(out, x)
	}
	slices.Sort(parts)
	mk(RuleIssuer, strings.Join(slices.Compact(parts), "; "), issuerSeen)
	mk(RuleCertName, "", certSeen)
	mk(RuleHostnames, "", hostSeen)
	return out
}

// crtClimb is the CAA climb of F2 with File.Find: it gives whether some
// alternative of the governing line names the authority, and the Expected part.
func crtClimb(f *expect.File, base dnswire.Name, wild bool, caa []string) (bool, string) {
	for m := base; ; m = m.Parent() {
		if e, ok := f.Find(m, dnswire.TypeCAA); ok && e.Form == expect.FormSets {
			for _, set := range e.Sets {
				p, _ := PolicyOf(set, PermissiveReading)
				if p.Names(wild, caa) {
					return true, ""
				}
			}
			return false, crtText(e.Name) + " CAA " + e.FormText()
		}
		if m.Equal(f.Domain) {
			return true, ""
		}
	}
}

// ---- words, numbers and severities ----

func TestCertificateRuleWordsNumbersAndSeverities(t *testing.T) {
	for _, c := range []struct {
		rule Rule
		num  Rule
		word string
		sev  Severity
	}{
		{RuleIssuer, 18, "issuer", SeverityHigh},
		{RuleCertName, 19, "certname", SeverityHigh},
		{RuleHostnames, 20, "hostnames", SeverityLow},
	} {
		if c.rule != c.num {
			t.Errorf("%s is rule number %d, want %d: the store keeps the number", c.word, c.rule, c.num)
		}
		if got := c.num.String(); got != c.word {
			t.Errorf("Rule(%d).String() is %q, want %q", c.num, got, c.word)
		}
		for _, typ := range []dnswire.Type{0, dnswire.TypeA, dnswire.TypeCAA} {
			if got := severity(c.rule, typ); got != c.sev {
				t.Errorf("%s severity for type %v is %v, want %v", c.word, typ, got, c.sev)
			}
		}
	}
	if got := Rule(25).String(); got != "rule25" {
		t.Errorf("Rule(25).String() is %q, want rule25", got)
	}
	if RuleCAA != 17 {
		t.Errorf("RuleCAA is %d, want 17", RuleCAA)
	}
}

func TestCertificatesKindGivesNoFindingInFindings(t *testing.T) {
	f := decFile(t, "domain corp.test.", crtApexLine, crtWWWLine)
	o := obs.Observation{Key: crtKey, Start: crtStart}
	if got := Findings(f, o); len(got) != 0 {
		t.Errorf("Findings of kind certificates: %s", decShow(got))
	}
}

// ---- rows of F2 to F4 ----

const (
	crtEvil = "evil.test"
	crtCA   = "ca.test"
)

func crtCAAOf(names ...string) []string { return names }

func TestCertificateFindingsRows(t *testing.T) {
	apex := []string{"domain corp.test.", crtApexLine, crtWWWLine}
	rows := []struct {
		name   string
		lines  []string // default: apex
		domain string   // domain of the run; default corp.test.
		nilF   bool
		certs  []obs.Issuance
		want   []Finding
	}{
		// issuer
		{name: "an expected authority for the names of the file", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "corp.test.", "www.corp.test.")}},
		{name: "another authority", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test")}},
		{name: "the apex itself", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "corp.test. from evil.test")}},
		{name: "two names of one issuance give one expected part and two texts", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.", "corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "corp.test. from evil.test", "www.corp.test. from evil.test")}},
		{name: "several CAA names are joined by a comma", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf("a.test", crtEvil), "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from a.test,evil.test")}},
		{name: "an authority that has one of the CAA names is permitted", certs: []obs.Issuance{crtIss(1, "Multi CA", crtCAAOf("a.test", crtCA), "www.corp.test.")}},
		{name: "the texts are sorted whatever the order of the issuances", certs: []obs.Issuance{
			crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test."), crtIss(2, "Third CA", crtCAAOf("a.test", "b.test"), "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from a.test,b.test", "www.corp.test. from evil.test")}},
		{name: "an authority with no CAA name is named by its short name", certs: []obs.Issuance{crtIss(1, "Other CA", nil, "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from an authority with no CAA name (Other CA)")}},
		{name: "an authority with no CAA name, with a dash", certs: []obs.Issuance{crtIss(1, "-", nil, "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from an authority with no CAA name (-)")}},
		{name: "a name outside the domain is not judged", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.other.test.", "xcorp.test.", "corp.test.example.", "test.")}},
		{name: "a name outside the domain beside a name of it", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.other.test.", "www.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test")}},
		{name: "capitals in a name give the lower case text", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "WWW.Corp.Test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test")}},
		{name: "a name with no line is judged by the CAA policy that covers it", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "new.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "new.corp.test. from evil.test"), crtF(RuleHostnames, "", "new.corp.test.")}},
		{name: "a deeper name climbs to the nearest line", lines: []string{"domain corp.test.", crtApexLine, `www.corp.test. CAA 0 issue "ca2.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "CA 2", crtCAAOf("ca2.test"), "a.b.www.corp.test.")},
			want:  []Finding{crtF(RuleHostnames, "", "a.b.www.corp.test.")}},
		{name: "a none line goes on to the parent", lines: []string{"domain corp.test.", crtApexLine, "www.corp.test. CAA none", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test")}},
		{name: "no CAA line and no issuer line judges nothing", lines: []string{"domain corp.test.", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.")}},
		{name: "a CAA line that forbids all", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue ";"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue ";"`, "www.corp.test. from ca.test")}},
		{name: "the line of two alternatives is satisfied by either", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test" || 0 issue "evil.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "A", crtCAAOf(crtCA), "www.corp.test."), crtIss(2, "B", crtCAAOf(crtEvil), "corp.test.")}},
		{name: "the line of two alternatives fails when no alternative names the authority", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test" || 0 issue "evil.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "C", crtCAAOf("ca3.test"), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test" || 0 issue "evil.test"`, "www.corp.test. from ca3.test")}},
		{name: "an issuance with no names", certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil))}},
		{name: "an issuance with unread names only", certs: []obs.Issuance{func() obs.Issuance {
			i := crtIss(1, "Other CA", crtCAAOf(crtEvil))
			i.Unread = 3
			return i
		}()}},
		{name: "a renewal changes nothing", certs: []obs.Issuance{
			crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.", "*.corp.test.", "dev.corp.test."),
			crtIss(2, "Other CA", crtCAAOf(crtEvil), "www.corp.test.", "*.corp.test.", "dev.corp.test.")},
			want: []Finding{
				crtF(RuleIssuer, crtApexPart, "*.corp.test. from evil.test", "dev.corp.test. from evil.test", "www.corp.test. from evil.test"),
				crtF(RuleCertName, "", "*.corp.test."), crtF(RuleHostnames, "", "dev.corp.test.")}},

		// wildcards
		{name: "a wildcard is judged at its base, by issuewild", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test" | 0 issuewild "evil.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "*.corp.test."), crtIss(2, "C", crtCAAOf(crtCA), "*.corp.test.")},
			want: []Finding{
				crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test" | 0 issuewild "evil.test"`, "*.corp.test. from ca.test"),
				crtF(RuleCertName, "", "*.corp.test.")}},
		{name: "a plain name is judged by issue, not issuewild", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test" | 0 issuewild "evil.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test" | 0 issuewild "evil.test"`, "www.corp.test. from evil.test")}},
		{name: "a wildcard below a name with its own line climbs from that name", lines: []string{"domain corp.test.", crtApexLine, `www.corp.test. CAA 0 issue "ca2.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "C", crtCAAOf(crtCA), "*.www.corp.test.")},
			want: []Finding{
				crtF(RuleIssuer, `www.corp.test. CAA 0 issue "ca2.test"`, "*.www.corp.test. from ca.test"),
				crtF(RuleCertName, "", "*.www.corp.test.")}},
		{name: "a wildcard outside the domain", certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "*.other.test.")}},
		{name: "an unlisted wildcard is certname, high", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "*.corp.test.", "*.www.corp.test.")},
			want: []Finding{crtF(RuleCertName, "", "*.corp.test.", "*.www.corp.test.")}},
		{name: "a certname line lists a wildcard", lines: append(slices.Clone(apex), "certname *.corp.test."),
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "*.corp.test.", "*.www.corp.test.")},
			want:  []Finding{crtF(RuleCertName, "", "*.www.corp.test.")}},
		{name: "a plain certname line does not list the wildcard of that name", lines: append(slices.Clone(apex), "certname dev.corp.test."),
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "*.dev.corp.test.")},
			want:  []Finding{crtF(RuleCertName, "", "*.dev.corp.test.")}},
		{name: "a wildcard line of the file lists nothing", lines: append(slices.Clone(apex), "*.corp.test. A none"),
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "*.corp.test.")},
			want:  []Finding{crtF(RuleCertName, "", "*.corp.test.")}},
		{name: "a wildcard is never a hostname", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "*.corp.test.")},
			want: []Finding{crtF(RuleCertName, "", "*.corp.test.")}},

		// issuer lines
		{name: "an issuer line that the authority has", lines: []string{"domain corp.test.", "issuer ca.test", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf("a.test", crtCA), "www.corp.test.")}},
		{name: "an issuer line that the authority lacks, no CAA line", lines: []string{"domain corp.test.", "issuer ca.test", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, "issuer ca.test", "www.corp.test. from evil.test")}},
		{name: "two issuer lines are joined by a space", lines: []string{"domain corp.test.", "issuer ca2.test", "issuer CA.test", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, "issuer ca.test ca2.test", "www.corp.test. from evil.test")}},
		{name: "an authority with no CAA name fails the issuer lines", lines: []string{"domain corp.test.", "issuer ca.test", crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Other CA", nil, "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, "issuer ca.test", "www.corp.test. from an authority with no CAA name (Other CA)")}},
		{name: "the CAA policy fails and the issuer lines pass", lines: []string{"domain corp.test.", "issuer ca.test", "issuer evil.test", `www.corp.test. CAA 0 issue "ca.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `www.corp.test. CAA 0 issue "ca.test"`, "www.corp.test. from evil.test")}},
		{name: "both fail for one pair: two parts, sorted", lines: []string{"domain corp.test.", "issuer ca.test", crtApexLine, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, crtApexPart+"; issuer ca.test", "www.corp.test. from evil.test")}},
		{name: "each fails alone for another pair: two parts, sorted by octets", lines: []string{"domain corp.test.", "issuer ca.test", "issuer evil.test", `www.corp.test. CAA 0 issue "ca.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test."), crtIss(2, "C2", crtCAAOf("ca2.test"), "dev.corp.test.")},
			want: []Finding{crtF(RuleIssuer, `issuer ca.test evil.test; www.corp.test. CAA 0 issue "ca.test"`,
				"dev.corp.test. from ca2.test", "www.corp.test. from evil.test"), crtF(RuleHostnames, "", "dev.corp.test.")}},
		{name: "two governing lines give two parts, the same line once", lines: []string{"domain corp.test.", crtApexLine, `www.corp.test. CAA 0 issue "ca2.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "corp.test.", "dev.corp.test.", "www.corp.test."), crtIss(2, "E", crtCAAOf(crtEvil), "dev.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart+`; www.corp.test. CAA 0 issue "ca2.test"`,
				"corp.test. from evil.test", "dev.corp.test. from evil.test", "www.corp.test. from evil.test"), crtF(RuleHostnames, "", "dev.corp.test.")}},

		// hostnames
		{name: "an unlisted host is hostnames, low", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "mail.corp.test.", "dev.corp.test.", "www.corp.test.")},
			want: []Finding{crtF(RuleHostnames, "", "dev.corp.test.", "mail.corp.test.")}},
		{name: "the domain and the owner of a line are known", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "corp.test.", "www.corp.test.")}},
		{name: "the owner of any type of line is known", lines: append(slices.Clone(apex), "mail.corp.test. MX 10 mx.corp.test.", `dev.corp.test. CAA 0 issue "ca.test"`),
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "mail.corp.test.", "dev.corp.test.")}},
		{name: "a certname line makes a host known", lines: append(slices.Clone(apex), "certname dev.corp.test."),
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "dev.corp.test.", "mail.corp.test.")},
			want:  []Finding{crtF(RuleHostnames, "", "mail.corp.test.")}},
		{name: "a name below a known name is not known", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "a.www.corp.test.")},
			want: []Finding{crtF(RuleHostnames, "", "a.www.corp.test.")}},
		{name: "a name outside the domain is no hostname", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "www.other.test.", "xcorp.test.")}},
		{name: "a host name in capitals", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "DEV.Corp.test.")},
			want: []Finding{crtF(RuleHostnames, "", "dev.corp.test.")}},
		{name: "the same host in two issuances is one text", certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "dev.corp.test."), crtIss(2, "Lab CA", crtCAAOf(crtCA), "dev.corp.test.")},
			want: []Finding{crtF(RuleHostnames, "", "dev.corp.test.")}},

		// all three, in the order of the rules
		{name: "the three rules in rule order", certs: []obs.Issuance{
			crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test."), crtIss(2, "Lab CA", crtCAAOf(crtCA), "*.corp.test.", "dev.corp.test.")},
			want: []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test"), crtF(RuleCertName, "", "*.corp.test."), crtF(RuleHostnames, "", "dev.corp.test.")}},

		// coverage
		{name: "a file of another domain covers nothing", lines: []string{"domain other.test.", `other.test. CAA 0 issue "ca.test"`},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.", "*.corp.test.")}},
		{name: "a run of another domain than the file's", domain: "other.test.",
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.", "*.corp.test.")}},
		{name: "no file", nilF: true, certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.", "*.corp.test.")}},
		{name: "a run of the domain in capitals", domain: "CORP.TEST.",
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  nil},
		// The two readings of a CAA set differ here; a certificate exists, so it was allowed under the authority's own reading.
		{name: "a repeated validationmethods is read permissively", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "www.corp.test.", "corp.test.")}},
		{name: "a repeated validationmethods, another authority", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`, "www.corp.test. from evil.test")}},
		{name: "a repeated accounturi is read permissively", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/a/1; accounturi=https://ca.test/a/2"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "www.corp.test.")}},
		{name: "a repeated accounturi, another authority", lines: []string{"domain corp.test.", `corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/a/1; accounturi=https://ca.test/a/2"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test; accounturi=https://ca.test/a/1; accounturi=https://ca.test/a/2"`, "www.corp.test. from evil.test")}},
		{name: "a critical unknown tag is ignored by the permissive reading", lines: []string{"domain corp.test.", `corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "Lab CA", crtCAAOf(crtCA), "www.corp.test.")}},
		{name: "a critical unknown tag, another authority", lines: []string{"domain corp.test.", `corp.test. CAA 128 tbs "x" | 0 issue "ca.test"`, crtWWWLine},
			certs: []obs.Issuance{crtIss(1, "E", crtCAAOf(crtEvil), "www.corp.test.")},
			want:  []Finding{crtF(RuleIssuer, `corp.test. CAA 0 issue "ca.test" | 128 tbs "x"`, "www.corp.test. from evil.test")}},
		{name: "no issuance", certs: nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			lines := r.lines
			if lines == nil {
				lines = apex
			}
			f := decFile(t, lines...)
			if r.nilF {
				f = nil
			}
			c := crtCerts(true, r.certs...)
			want := r.want
			if r.domain != "" {
				c.Key = obs.CertificatesKey(crtMust(r.domain))
				if r.domain == "CORP.TEST." {
					// The same domain in capitals is the same domain.
					want = []Finding{crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test")}
					for i := range want {
						want[i].Check = c.Key
					}
				}
			}
			got := CertificateFindings(f, c)
			crtSameFindings(t, "findings", got, want)
			crtSameFindings(t, "oracle", crtOracle(f, c), want)
		})
	}
}

// ---- the property ----

type crtGen struct {
	rng *rand.Rand
	id  int
}

func (g *crtGen) pick(xs ...string) string { return xs[g.rng.IntN(len(xs))] }

func (g *crtGen) subset(max int, xs ...string) []string {
	var out []string
	for _, i := range g.rng.Perm(len(xs))[:g.rng.IntN(max+1)] {
		out = append(out, xs[i])
	}
	return out
}

var (
	crtInside  = []string{"corp.test.", "www.corp.test.", "a.www.corp.test.", "dev.corp.test.", "mail.corp.test.", "*.corp.test.", "*.www.corp.test.", "*.dev.corp.test.", "WWW.corp.test.", "x.dev.corp.test."}
	crtOutside = []string{"other.test.", "www.other.test.", "*.other.test.", "xcorp.test.", "test.", "corp.test.example."}
	crtAuth    = []string{"ca.test", "ca2.test", "evil.test", "other.test"}
	crtPolicy  = []string{
		`0 issue "ca.test"`, `0 issue "ca2.test"`, `0 issue "ca.test" | 0 issuewild "evil.test"`, `0 issuewild "evil.test"`,
		`0 issue ";"`, `0 issue "ca.test" || 0 issue "evil.test"`, "none",
		`0 issue "ca.test; validationmethods=dns-01; validationmethods=dns-01"`, `0 issue "ca2.test; accounturi=a; accounturi=b"`,
		`128 tbs "x" | 0 issue "ca.test"`,
	}
)

func (g *crtGen) file(t testing.TB) *expect.File {
	lines := []string{"domain corp.test."}
	for _, i := range g.subset(2, "ca.test", "ca2.test", "evil.test") {
		lines = append(lines, "issuer "+i)
	}
	for _, n := range g.subset(3, "*.corp.test.", "dev.corp.test.", "*.www.corp.test.", "mail.corp.test.", "*.dev.corp.test.") {
		lines = append(lines, "certname "+n)
	}
	for _, owner := range []string{"corp.test.", "www.corp.test.", "a.www.corp.test.", "dev.corp.test."} {
		if g.rng.IntN(2) == 0 {
			lines = append(lines, owner+" CAA "+g.pick(crtPolicy...))
		}
	}
	for _, owner := range g.subset(3, "www.corp.test.", "mail.corp.test.", "a.www.corp.test.") {
		lines = append(lines, owner+" A 10.53.0.81")
	}
	if g.rng.IntN(4) == 0 {
		lines = append(lines, "*.corp.test. A none")
	}
	return decFile(t, lines...)
}

func (g *crtGen) issuance() obs.Issuance {
	var names []string
	for range 1 + g.rng.IntN(5) {
		if g.rng.IntN(4) == 0 {
			names = append(names, g.pick(crtOutside...))
		} else {
			names = append(names, g.pick(crtInside...))
		}
	}
	caa := g.subset(3, crtAuth...)
	slices.Sort(caa)
	g.id++
	return crtIss(1000+g.id, fmt.Sprintf("CA-%d", g.rng.IntN(5)), caa, names...)
}

func (g *crtGen) certs() obs.Certificates {
	var isss []obs.Issuance
	for range 1 + g.rng.IntN(4) {
		isss = append(isss, g.issuance())
	}
	c := crtCerts(g.rng.IntN(3) > 0, isss...)
	c.Usable = g.rng.IntN(4) > 0
	return c
}

// crtRenewed is the same certificate again with another id, hash and dates.
func crtRenewed(i obs.Issuance, id int) obs.Issuance {
	i.ID = fmt.Sprint(id)
	i.TBS = fmt.Sprintf("%064x", id)
	i.NotBefore = i.NotBefore.Add(48 * time.Hour)
	i.NotAfter = i.NotAfter.Add(48 * time.Hour)
	return i
}

func TestCertificateRulesProperty(t *testing.T) {
	const cases = 1500
	var seenRule [3]int
	for seed := uint64(1); seed <= cases; seed++ {
		g := &crtGen{rng: rand.New(rand.NewPCG(seed, 0xce47))}
		f := g.file(t)
		c := g.certs()
		fail := func(format string, args ...any) {
			t.Helper()
			t.Fatalf("seed %d: %s\n  file %v\n  certs %+v", seed, fmt.Sprintf(format, args...), f, c.Issuances)
		}
		got := CertificateFindings(f, c)
		want := crtOracle(f, c)
		if !(len(got) == 0 && len(want) == 0) && !reflect.DeepEqual(got, want) {
			fail("findings differ:\n got %s\n want %s", crtShow(got), crtShow(want))
		}
		crtShape(t, seed, c, got, fail)
		for _, x := range got {
			seenRule[x.Rule-RuleIssuer]++
		}

		same := func(what string, c2 obs.Certificates) {
			t.Helper()
			got2 := CertificateFindings(f, c2)
			if !(len(got) == 0 && len(got2) == 0) && !reflect.DeepEqual(got, got2) {
				fail("%s changed the findings:\n before %s\n after %s", what, crtShow(got), crtShow(got2))
			}
		}
		shuffled := c
		shuffled.Issuances = slices.Clone(c.Issuances)
		g.rng.Shuffle(len(shuffled.Issuances), func(i, j int) {
			shuffled.Issuances[i], shuffled.Issuances[j] = shuffled.Issuances[j], shuffled.Issuances[i]
		})
		same("reordering the issuances", shuffled)

		renewed := c
		renewed.Issuances = slices.Clone(c.Issuances)
		renewed.Issuances = append(renewed.Issuances, crtRenewed(c.Issuances[g.rng.IntN(len(c.Issuances))], 5000+int(seed)))
		same("a renewal", renewed)

		outside := c
		outside.Issuances = slices.Clone(c.Issuances)
		k := g.rng.IntN(len(outside.Issuances))
		ns := append(slices.Clone(outside.Issuances[k].Names), crtMust(g.pick(crtOutside...)))
		slices.SortFunc(ns, dnswire.Compare)
		outside.Issuances[k].Names = slices.CompactFunc(ns, dnswire.Name.Equal)
		same("a name outside the domain", outside)

		crtDecideCase(t, g, seed, f, c, fail)
	}
	for i, n := range seenRule {
		if n < 100 {
			t.Errorf("the generator gave rule %v only %d times", Rule(int(RuleIssuer)+i), n)
		}
	}
}

// crtShape checks what every finding of the three rules must look like.
func crtShape(t *testing.T, seed uint64, c obs.Certificates, got []Finding, fail func(string, ...any)) {
	t.Helper()
	last := Rule(0)
	for _, x := range got {
		if x.Rule <= last {
			fail("findings are not in rule order: %s", crtShow(got))
		}
		last = x.Rule
		wantSev := SeverityHigh
		if x.Rule == RuleHostnames {
			wantSev = SeverityLow
		}
		if x.Severity != wantSev || !reflect.DeepEqual(x.Check, c.Key) {
			fail("severity or check of %v is wrong", x.Rule)
		}
		if x.Rule != RuleIssuer && x.Expected != "" {
			fail("%v has Expected %q", x.Rule, x.Expected)
		}
		if x.Rule == RuleIssuer && x.Expected == "" {
			fail("issuer has no Expected")
		}
		var texts []string
		for _, s := range x.Seen {
			texts = append(texts, s.Text)
			if !reflect.DeepEqual(s.Answer, obs.Answer{Proof: obs.Proof{Received: c.Start}}) {
				fail("a Seen of %v has an answer: %+v", x.Rule, s.Answer)
			}
		}
		if len(texts) == 0 || !slices.IsSorted(texts) || len(slices.Compact(slices.Clone(texts))) != len(texts) {
			fail("the Seen texts of %v are not sorted and unique: %q", x.Rule, texts)
		}
		if x.Value != strings.Join(texts, "\n") {
			fail("Value of %v is %q, not the texts joined", x.Rule, x.Value)
		}
		for _, i := range c.Issuances {
			for _, bad := range []string{i.ID, i.TBS, i.NotAfter.Format(time.RFC3339), i.NotBefore.Format(time.RFC3339), "2026"} {
				if strings.Contains(x.Value, bad) || strings.Contains(x.Expected, bad) {
					fail("a text of %v holds %q", x.Rule, bad)
				}
			}
		}
	}
}

// ---- F5: DecideCertificates ----

// crtNews is "changed" of F5.5, written again: a new Expected part is news
// for issuer, any other Expected change is news for the rest, and a new
// Value line is news.
func crtNews(was, f Finding) bool {
	if was.Severity != f.Severity {
		return true
	}
	if f.Rule == RuleIssuer {
		old := strings.Split(was.Expected, "; ")
		for _, p := range strings.Split(f.Expected, "; ") {
			if !slices.Contains(old, p) {
				return true
			}
		}
	} else if was.Expected != f.Expected {
		return true
	}
	old := strings.Split(was.Value, "\n")
	for _, l := range strings.Split(f.Value, "\n") {
		if !slices.Contains(old, l) {
			return true
		}
	}
	return false
}

func crtFailing(key obs.Key, limit time.Duration) Finding {
	return Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: key, Value: "no usable answer for " + limit.String()}
}

func crtDecideOracle(in CertInput) []Change {
	c := in.Certificates
	var found []Finding
	if c.Complete {
		found = crtOracle(in.Expect, c)
	}
	if !c.Usable && !in.FailingSince.IsZero() && in.FailLimit > 0 && in.Now.Sub(in.FailingSince) >= in.FailLimit {
		found = append(found, crtFailing(c.Key, in.FailLimit))
	}
	var open []Finding
	for _, o := range in.Open {
		if o.Check.String() == c.Key.String() && !slices.ContainsFunc(open, func(x Finding) bool { return x.Rule == o.Rule }) {
			open = append(open, o)
		}
	}
	var out []Change
	for _, f := range found {
		i := slices.IndexFunc(open, func(o Finding) bool { return o.Rule == f.Rule })
		switch {
		case i < 0:
			out = append(out, Change{Op: OpOpen, Finding: f, At: in.Now})
		case crtNews(open[i], f):
			out = append(out, Change{Op: OpUpdate, Finding: f, At: in.Now})
		}
	}
	for _, was := range open {
		gone := !slices.ContainsFunc(found, func(x Finding) bool { return x.Rule == was.Rule })
		ends := was.Rule == RuleCheckFailing && c.Usable ||
			was.Rule != RuleCheckFailing && c.Complete && gone
		if ends {
			out = append(out, Change{Op: OpResolve, Finding: was, At: in.Now})
		}
	}
	return out
}

func crtSortChanges(cs []Change) []Change {
	cs = slices.Clone(cs)
	slices.SortStableFunc(cs, func(a, b Change) int {
		return cmp.Or(cmp.Compare(a.Op, b.Op), cmp.Compare(a.Finding.Rule, b.Finding.Rule))
	})
	return cs
}

// crtOpenOf makes open findings: some are true findings, changed a little,
// some are of another check, some are a check-failing alert.
func crtOpenOf(g *crtGen, found []Finding, c obs.Certificates) []Finding {
	var open []Finding
	for _, f := range found {
		switch g.rng.IntN(5) {
		case 0:
			continue
		case 1:
			f.Value = f.Value + "\nzz.corp.test."
		case 2:
			f.Value = strings.Split(f.Value, "\n")[0]
			f.Expected += "; extra"
		case 3:
			f.Severity = SeverityMedium
		}
		open = append(open, f)
	}
	for _, r := range []Rule{RuleIssuer, RuleCertName, RuleHostnames, RuleCheckFailing} {
		if g.rng.IntN(4) == 0 {
			open = append(open, Finding{Rule: r, Severity: severity(r, 0), Check: c.Key, Value: "old.corp.test."})
		}
	}
	if g.rng.IntN(3) == 0 {
		open = append(open, Finding{Rule: RuleIssuer, Severity: SeverityHigh, Check: obs.CertificatesKey(crtMust("other.test.")), Value: "x"})
	}
	return open
}

func crtDecideCase(t *testing.T, g *crtGen, seed uint64, f *expect.File, c obs.Certificates, fail func(string, ...any)) {
	t.Helper()
	in := CertInput{Expect: f, Certificates: c, Now: crtStart.Add(time.Duration(g.rng.IntN(100)) * time.Minute)}
	in.FailLimit = []time.Duration{0, 15 * time.Second, time.Minute}[g.rng.IntN(3)]
	if g.rng.IntN(3) > 0 {
		in.FailingSince = in.Now.Add(-time.Duration(g.rng.IntN(120)) * time.Second)
	}
	in.Open = crtOpenOf(g, crtOracle(f, c), c)
	g.rng.Shuffle(len(in.Open), func(i, j int) { in.Open[i], in.Open[j] = in.Open[j], in.Open[i] })
	got := crtSortChanges(DecideCertificates(in))
	want := crtSortChanges(crtDecideOracle(in))
	if !(len(got) == 0 && len(want) == 0) && !reflect.DeepEqual(got, want) {
		fail("changes differ:\n got %s\n want %s", decShowChanges(got), decShowChanges(want))
	}
	if !c.Complete {
		for _, x := range got {
			if x.Finding.Rule != RuleCheckFailing {
				fail("a change of %v while the listing is not complete", x.Finding.Rule)
			}
		}
	}
}

// crtScenario is a file and a complete listing that give the three rules.
func crtScenario(t *testing.T) (*expect.File, obs.Certificates, []Finding) {
	f := decFile(t, "domain corp.test.", crtApexLine, crtWWWLine)
	c := crtCerts(true,
		crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test."),
		crtIss(2, "Lab CA", crtCAAOf(crtCA), "*.corp.test.", "dev.corp.test.", "mail.corp.test."))
	return f, c, []Finding{
		crtF(RuleIssuer, crtApexPart, "www.corp.test. from evil.test"),
		crtF(RuleCertName, "", "*.corp.test."),
		crtF(RuleHostnames, "", "dev.corp.test.", "mail.corp.test."),
	}
}

func crtIn(f *expect.File, c obs.Certificates, open ...Finding) CertInput {
	return CertInput{Expect: f, Open: open, Certificates: c, Now: crtStart.Add(time.Hour)}
}

func crtChange(op Op, f Finding, in CertInput) Change { return Change{Op: op, Finding: f, At: in.Now} }

func TestDecideCertificatesOpensEachRule(t *testing.T) {
	f, c, found := crtScenario(t)
	crtSameFindings(t, "scenario", CertificateFindings(f, c), found)
	in := crtIn(f, c)
	decSameChanges(t, DecideCertificates(in), []Change{
		crtChange(OpOpen, found[0], in), crtChange(OpOpen, found[1], in), crtChange(OpOpen, found[2], in)})
}

func TestDecideCertificatesIsSilentWhileTheListingIsNotComplete(t *testing.T) {
	f, c, found := crtScenario(t)
	c.Complete = false
	cases := map[string][]Finding{
		"no open alert":         nil,
		"the same alerts open":  found,
		"other texts open":      {crtF(RuleIssuer, "x", "a"), crtF(RuleCertName, "", "b"), crtF(RuleHostnames, "", "c")},
		"alerts that would end": {crtF(RuleIssuer, crtApexPart, "gone.corp.test. from evil.test")},
	}
	for name, open := range cases {
		t.Run(name, func(t *testing.T) {
			decSameChanges(t, DecideCertificates(crtIn(f, c, open...)), nil)
		})
	}
	// Nothing to find and open alerts: still no resolve.
	empty := crtCerts(false)
	decSameChanges(t, DecideCertificates(crtIn(f, empty, found...)), nil)
}

func TestDecideCertificatesResolvesWhenCompleteAndTheFindingIsGone(t *testing.T) {
	f, c, found := crtScenario(t)
	// The file now lists everything: no finding.
	clean := decFile(t, "domain corp.test.", `corp.test. CAA 0 issue "ca.test" || 0 issue "evil.test"`, crtWWWLine,
		"certname *.corp.test.", "certname dev.corp.test.", "certname mail.corp.test.")
	in := crtIn(clean, c, found...)
	decSameChanges(t, DecideCertificates(in), []Change{
		crtChange(OpResolve, found[0], in), crtChange(OpResolve, found[1], in), crtChange(OpResolve, found[2], in)})

	// One rule gone, the others stay and say nothing new.
	only := crtCerts(true, crtIss(1, "Other CA", crtCAAOf(crtEvil), "www.corp.test."))
	in = crtIn(f, only, found...)
	decSameChanges(t, DecideCertificates(in), []Change{crtChange(OpResolve, found[1], in), crtChange(OpResolve, found[2], in)})

	// No certificate at all, a complete empty listing: every alert ends.
	in = crtIn(f, crtCerts(true), found...)
	decSameChanges(t, DecideCertificates(in), []Change{
		crtChange(OpResolve, found[0], in), crtChange(OpResolve, found[1], in), crtChange(OpResolve, found[2], in)})

	// A file of another domain, or none, judges nothing: the alerts end.
	in = crtIn(nil, c, found...)
	decSameChanges(t, DecideCertificates(in), []Change{
		crtChange(OpResolve, found[0], in), crtChange(OpResolve, found[1], in), crtChange(OpResolve, found[2], in)})
}

func TestDecideCertificatesSendsNothingForTheSameFindings(t *testing.T) {
	f, c, found := crtScenario(t)
	decSameChanges(t, DecideCertificates(crtIn(f, c, found...)), nil)
	// A renewal of every certificate: a new id, hash and dates, the same names.
	c.Issuances = append(c.Issuances, crtRenewed(c.Issuances[0], 90), crtRenewed(c.Issuances[1], 91))
	decSameChanges(t, DecideCertificates(crtIn(f, c, found...)), nil)
}

func TestDecideCertificatesUsesOnlyTheOpenAlertsOfItsCheck(t *testing.T) {
	f, c, found := crtScenario(t)
	other := found[0]
	other.Check = obs.CertificatesKey(crtMust("other.test."))
	in := crtIn(f, c, other)
	decSameChanges(t, DecideCertificates(in), []Change{
		crtChange(OpOpen, found[0], in), crtChange(OpOpen, found[1], in), crtChange(OpOpen, found[2], in)})

	// The same check written in capitals is the same check.
	caps := found[0]
	caps.Check = obs.CertificatesKey(crtMust("CORP.TEST."))
	decSameChanges(t, DecideCertificates(crtIn(f, c, caps, found[1], found[2])), nil)

	// Of two open alerts of one rule, the first counts.
	stale := found[2]
	stale.Value = "old.corp.test."
	in = crtIn(f, c, found[0], found[1], found[2], stale)
	decSameChanges(t, DecideCertificates(in), nil)
	in = crtIn(f, c, found[0], found[1], stale, found[2])
	decSameChanges(t, DecideCertificates(in), []Change{crtChange(OpUpdate, found[2], in)})
}

func TestDecideCertificatesUpdatesOnNews(t *testing.T) {
	f := decFile(t, "domain corp.test.", crtApexLine, `www.corp.test. CAA 0 issue "ca2.test"`, crtWWWLine)
	c := crtCerts(true,
		crtIss(1, "E", crtCAAOf(crtEvil), "corp.test.", "www.corp.test.", "dev.corp.test.", "mail.corp.test."))
	p1, p2 := crtApexPart, `www.corp.test. CAA 0 issue "ca2.test"`
	now := crtF(RuleIssuer, p1+"; "+p2, "corp.test. from evil.test", "dev.corp.test. from evil.test", "mail.corp.test. from evil.test", "www.corp.test. from evil.test")
	hosts := crtF(RuleHostnames, "", "dev.corp.test.", "mail.corp.test.")
	crtSameFindings(t, "scenario", CertificateFindings(f, c), []Finding{now, hosts})

	with := func(f Finding, mut func(*Finding)) Finding { mut(&f); return f }
	for _, row := range []struct {
		name   string
		open   Finding
		update bool
	}{
		{"the same", now, false},
		{"an Expected part is new", with(now, func(x *Finding) { x.Expected = p1 }), true},
		{"the other Expected part is new", with(now, func(x *Finding) { x.Expected = p2 }), true},
		{"an Expected part is gone", with(now, func(x *Finding) { x.Expected = p1 + "; " + p2 + "; zz.corp.test. CAA none" }), false},
		{"a part is gone and another is new", with(now, func(x *Finding) { x.Expected = p1 + "; zz.corp.test. CAA none" }), true},
		{"a Value line is new", with(now, func(x *Finding) { x.Value = "corp.test. from evil.test" }), true},
		{"a Value line is gone", with(now, func(x *Finding) { x.Value += "\nzz.corp.test. from evil.test" }), false},
		{"the severity differs", with(now, func(x *Finding) { x.Severity = SeverityMedium }), true},
	} {
		t.Run("issuer: "+row.name, func(t *testing.T) {
			in := crtIn(f, c, row.open, hosts)
			var want []Change
			if row.update {
				want = []Change{crtChange(OpUpdate, now, in)}
			}
			decSameChanges(t, DecideCertificates(in), want)
		})
	}
	for _, row := range []struct {
		name   string
		open   Finding
		update bool
	}{
		{"hosts: the same", hosts, false},
		{"hosts: a host is new", with(hosts, func(x *Finding) { x.Value = "dev.corp.test." }), true},
		{"hosts: a host is gone", with(hosts, func(x *Finding) { x.Value += "\nzz.corp.test." }), false},
		{"hosts: another Expected is news", with(hosts, func(x *Finding) { x.Expected = "x" }), true},
		{"hosts: the severity differs", with(hosts, func(x *Finding) { x.Severity = SeverityHigh }), true},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := crtIn(f, c, now, row.open)
			var want []Change
			if row.update {
				want = []Change{crtChange(OpUpdate, hosts, in)}
			}
			decSameChanges(t, DecideCertificates(in), want)
		})
	}
}

func TestDecideCertificatesRestartKeepsQuiet(t *testing.T) {
	f := decFile(t, "domain corp.test.", crtApexLine, crtWWWLine)
	all := crtCerts(true, crtIss(1, "Lab CA", crtCAAOf(crtCA), "a.corp.test.", "b.corp.test.", "c.corp.test."))
	open := crtF(RuleHostnames, "", "a.corp.test.", "b.corp.test.", "c.corp.test.")
	crtSameFindings(t, "listing", CertificateFindings(f, all), []Finding{open})

	// The restarted source knows one certificate and has not seen an empty page.
	partial := crtCerts(false, crtIss(1, "Lab CA", crtCAAOf(crtCA), "a.corp.test."))
	decSameChanges(t, DecideCertificates(crtIn(f, partial, open)), nil)
	// The listing is complete again: the same lines, no change.
	decSameChanges(t, DecideCertificates(crtIn(f, all, open)), nil)
	// A listing that is complete but has lost two hosts: no news either.
	fewer := crtCerts(true, crtIss(1, "Lab CA", crtCAAOf(crtCA), "a.corp.test."))
	decSameChanges(t, DecideCertificates(crtIn(f, fewer, open)), nil)
}

func TestDecideCertificatesCheckFailing(t *testing.T) {
	f, c, found := crtScenario(t)
	c.Usable = false
	c.Failure = "timeout"
	c.Complete = false
	since := crtStart
	limit := 15 * time.Second
	for _, row := range []struct {
		name  string
		now   time.Time
		since time.Time
		limit time.Duration
		opens bool
	}{
		{"1ns before the limit", since.Add(limit - 1), since, limit, false},
		{"at the limit", since.Add(limit), since, limit, true},
		{"1ns after the limit", since.Add(limit + 1), since, limit, true},
		{"long after", since.Add(100 * time.Hour), since, limit, true},
		{"limit 0 never", since.Add(100 * time.Hour), since, 0, false},
		{"a negative limit never", since.Add(100 * time.Hour), since, -limit, false},
		{"no series", since.Add(100 * time.Hour), time.Time{}, limit, false},
		{"a series that starts after now", since.Add(-time.Second), since, limit, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			in := CertInput{Expect: f, Certificates: c, Now: row.now, FailingSince: row.since, FailLimit: row.limit}
			var want []Change
			if row.opens {
				want = []Change{{Op: OpOpen, Finding: crtFailing(crtKey, row.limit), At: row.now}}
			}
			decSameChanges(t, DecideCertificates(in), want)
		})
	}

	t.Run("the finding", func(t *testing.T) {
		in := CertInput{Expect: f, Certificates: c, Now: since.Add(3 * time.Hour), FailingSince: since, FailLimit: 3 * time.Hour}
		got := DecideCertificates(in)
		want := Finding{Rule: RuleCheckFailing, Severity: SeverityMedium, Check: crtKey, Expected: "", Seen: nil, Value: "no usable answer for 3h0m0s"}
		decSameChanges(t, got, []Change{{Op: OpOpen, Finding: want, At: in.Now}})
		if got[0].Finding.Rule.String() != "check-failing" {
			t.Errorf("rule %v", got[0].Finding.Rule)
		}
	})

	t.Run("a usable run never fails", func(t *testing.T) {
		u := c
		u.Usable = true
		in := CertInput{Expect: f, Certificates: u, Now: since.Add(time.Hour), FailingSince: since, FailLimit: limit}
		decSameChanges(t, DecideCertificates(in), nil)
	})

	t.Run("an open alert stays while the runs fail, and says nothing new", func(t *testing.T) {
		in := CertInput{Expect: f, Certificates: c, Now: since.Add(time.Hour), FailingSince: since, FailLimit: limit,
			Open: []Finding{crtFailing(crtKey, limit), found[0], found[2]}}
		decSameChanges(t, DecideCertificates(in), nil)
	})

	t.Run("a usable run ends it, also when the listing is not complete", func(t *testing.T) {
		u := c
		u.Usable = true
		open := crtFailing(crtKey, limit)
		in := CertInput{Expect: f, Certificates: u, Now: since.Add(time.Hour), Open: []Finding{open}}
		decSameChanges(t, DecideCertificates(in), []Change{{Op: OpResolve, Finding: open, At: in.Now}})
	})

	t.Run("it ends with a usable complete run and the rules speak", func(t *testing.T) {
		u := crtCerts(true, c.Issuances...)
		open := crtFailing(crtKey, limit)
		in := CertInput{Expect: f, Certificates: u, Now: since.Add(time.Hour), Open: []Finding{open}}
		decSameChanges(t, DecideCertificates(in), []Change{
			{Op: OpOpen, Finding: found[0], At: in.Now}, {Op: OpOpen, Finding: found[1], At: in.Now}, {Op: OpOpen, Finding: found[2], At: in.Now},
			{Op: OpResolve, Finding: open, At: in.Now}})
	})

	t.Run("a failing run does not end an open rule alert", func(t *testing.T) {
		in := CertInput{Expect: f, Certificates: crtCerts(false), Now: since, Open: found}
		in.Certificates.Usable = false
		decSameChanges(t, DecideCertificates(in), nil)
	})
}
