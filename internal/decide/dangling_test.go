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

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	dngpSeed  = 20261116
	dngpCases = 2000

	dngpAlias  = "alias-target "
	dngpNSHost = "nameserver-host "
	dngpMail   = "mail-target "
)

var dngpRules = []Rule{RuleAliasTarget, RuleNameServerHost, RuleMailTarget}

// ---- the oracles: the text of the rules, written again ----

type dngpTarget struct {
	name dnswire.Name
	refs []Ref
}

// dngpSPFIncludes gives the include domains of a record text, as written.
func dngpSPFIncludes(text string) []string {
	if len(text) < 6 || !strings.EqualFold(text[:6], "v=spf1") || (len(text) > 6 && text[6] != ' ') {
		return nil
	}
	var out []string
	for _, term := range strings.Split(text[6:], " ") {
		if term != "" && strings.ContainsRune("+-~?", rune(term[0])) {
			term = term[1:]
		}
		if len(term) >= 8 && strings.EqualFold(term[:8], "include:") {
			out = append(out, term[8:])
		}
	}
	return out
}

func dngpTargetsOf(f *expect.File) []dngpTarget {
	if f == nil {
		return nil
	}
	var out []dngpTarget
	add := func(e expect.Expectation, rule Rule, n dnswire.Name, middle string) {
		if n.LabelCount() == 0 || (n.IsSubdomainOf(f.Domain) && f.Zone(n).Equal(f.Domain)) {
			return
		}
		ref := Ref{Rule: rule, Text: e.Name.Lower().String() + " " + middle + n.Lower().String()}
		i := slices.IndexFunc(out, func(t dngpTarget) bool { return t.name.Equal(n) })
		if i < 0 {
			out = append(out, dngpTarget{name: n})
			i = len(out) - 1
		}
		if !slices.Contains(out[i].refs, ref) {
			out[i].refs = append(out[i].refs, ref)
		}
	}
	for _, e := range f.Expectations {
		if e.Form != expect.FormSets {
			continue
		}
		for _, alt := range e.Sets {
			for _, d := range alt {
				switch d := d.(type) {
				case dnswire.CNAME:
					add(e, RuleAliasTarget, d.Target, "CNAME ")
				case dnswire.DNAME:
					add(e, RuleAliasTarget, d.Target, "DNAME ")
				case dnswire.NS:
					add(e, RuleNameServerHost, d.Host, "NS ")
				case dnswire.MX:
					add(e, RuleMailTarget, d.Exchange, "MX ")
				case dnswire.TXT:
					for _, dom := range dngpSPFIncludes(strings.Join(d.Strings, "")) {
						dom = strings.TrimSuffix(dom, ".")
						if strings.Contains(dom, "%") {
							continue
						}
						if n, err := dnswire.ParseName(dom + "."); err == nil {
							add(e, RuleMailTarget, n, "TXT include:")
						}
					}
				}
			}
		}
	}
	return out
}

func dngpTargetOf(f *expect.File, name dnswire.Name) *dngpTarget {
	ts := dngpTargetsOf(f)
	i := slices.IndexFunc(ts, func(t dngpTarget) bool { return t.name.Equal(name) })
	if i < 0 {
		return nil
	}
	return &ts[i]
}

func dngpWildcardsOf(f *expect.File) []dnswire.Name {
	if f == nil {
		return nil
	}
	var out []dnswire.Name
	for _, e := range f.Expectations {
		labels := e.Name.Labels()
		if len(labels) == 0 || labels[0] != "*" || e.Type != dnswire.TypeA || e.Form != expect.FormNone {
			continue
		}
		z := e.Name.Parent()
		if _, err := dnswire.NameFromLabels(append([]string{strings.Repeat("a", obs.WildcardLabel)}, z.Labels()...)); err != nil {
			continue
		}
		if !slices.ContainsFunc(out, z.Equal) {
			out = append(out, z)
		}
	}
	return out
}

// dngpSOAOwner is the owner of the SOA record that a NoName answer carries.
func dngpSOAOwner(a obs.Answer) (owner dnswire.Name, ok bool) {
	obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(n obs.NoName) bool { owner, ok = n.SOA.Name, n.SOA.Data != nil; return true },
		func(obs.Failure) bool { return false })
	return owner, ok
}

// dngpMask writes the first label of the question of a as "*" in text,
// ignoring case.
func dngpMask(text string, a obs.Answer) string {
	labels := a.Question.Name.Labels()
	if len(labels) == 0 || labels[0] == "" {
		return text
	}
	l, lower := strings.ToLower(labels[0]), strings.ToLower(text)
	var b strings.Builder
	for {
		i := strings.Index(lower, l)
		if i < 0 {
			return b.String() + text
		}
		b.WriteString(text[:i] + "*")
		text, lower = text[i+len(l):], lower[i+len(l):]
	}
}

// dngpNoNameText is the Text of a Seen of a target probe, for the owner of
// the SOA record of the answer.
func dngpNoNameText(zone, target dnswire.Name) string {
	if !target.IsSubdomainOf(zone) || target.LabelCount() < zone.LabelCount()+2 {
		return "no such name"
	}
	r := target
	for r.LabelCount() > zone.LabelCount()+1 {
		r = r.Parent()
	}
	return "no such name: " + zone.Lower().String() + " does not delegate " + r.Lower().String()
}

func dngpSeverity(r Rule) Severity {
	switch r {
	case RuleNameServerHost:
		return SeverityCritical
	case RuleNotCovered:
		return SeverityMedium
	case RuleWildcard:
		return SeverityMedium
	case RuleInvalidFile, RuleZone, RuleNameServers, RuleRecordSet, RuleCheckFailing, RuleZoneChanged,
		RuleGlue, RuleDS, RuleGone, RuleDisagree, RuleAliasTarget, RuleMailTarget, RuleChallenge:
	}
	return SeverityHigh
}

func dngpAnswerKind(a obs.Answer) string {
	return decCase(a.Result)
}

// dngpFindings is Findings of a records check or a wildcard check; the zone
// of the observation is the expected one, so no zone finding comes up.
func dngpFindings(f *expect.File, o obs.Observation) []Finding {
	cov := f != nil && o.Key.Domain.Equal(f.Domain)
	var found []Finding
	finding := func(r Rule, expected string, seen []Seen) Finding {
		return Finding{Rule: r, Severity: dngpSeverity(r), Check: o.Key, Expected: expected, Seen: seen, Value: regValue(seen)}
	}
	switch o.Key.Kind {
	case obs.KindRecords:
		found = dngFindings(f, o)
		_, line := dngCovLine(f, o.Key)
		tg := dngpTargetOf(f, o.Key.Name)
		if !cov || o.Key.Type != dnswire.TypeA || tg == nil {
			break
		}
		if line == nil {
			found = slices.DeleteFunc(found, func(x Finding) bool { return x.Rule == RuleNotCovered })
		}
		var seen []Seen
		for _, a := range o.Answers {
			if dngpAnswerKind(a) == "noname" {
				text := "no such name"
				if soa, ok := dngpSOAOwner(a); ok {
					text = dngpNoNameText(soa, o.Key.Name)
				}
				seen = append(seen, Seen{Answer: a, Text: text})
			}
		}
		if len(seen) == 0 {
			break
		}
		for _, r := range dngpRules {
			var texts []string
			for _, ref := range tg.refs {
				if ref.Rule == r {
					texts = append(texts, ref.Text)
				}
			}
			if len(texts) > 0 {
				found = append(found, finding(r, strings.Join(texts, "; "), seen))
			}
		}
	case obs.KindWildcard:
		if !cov || !slices.ContainsFunc(dngpWildcardsOf(f), o.Key.Name.Equal) {
			break
		}
		var seen []Seen
		for _, a := range o.Answers {
			if set, failed := regSetOf(a); !failed && dngpAnswerKind(a) == "records" {
				seen = append(seen, Seen{Answer: a, Text: dngpMask(expect.SetText(dnswire.TypeA, set), a)})
			}
		}
		if len(seen) > 0 {
			found = append(found, finding(RuleWildcard, "none", seen))
		}
	case obs.KindDelegation, obs.KindDS, obs.KindSerial:
	}
	slices.SortStableFunc(found, func(a, b Finding) int { return int(a.Rule) - int(b.Rule) })
	return found
}

// dngpChanges is what Decide does with the finding of rule r.
func dngpChanges(in Input, found []Finding, r Rule) []Change {
	o := in.Observation
	i := slices.IndexFunc(found, func(f Finding) bool { return f.Rule == r })
	was, isOpen := dngFirstOpen(in.Open, o.Key, r)
	switch {
	case i >= 0 && !isOpen:
		return []Change{{Op: OpOpen, Finding: found[i], At: in.Now}}
	case i >= 0 && dngNews(was, found[i]):
		return []Change{{Op: OpUpdate, Finding: found[i], At: in.Now}}
	case i < 0 && isOpen && !dngBlocked(was, o):
		return []Change{{Op: OpResolve, Finding: was, At: in.Now}}
	}
	return nil
}

// ---- rendering, for rows ----

func dngpRender(ts []Target) [][]string {
	var out [][]string
	for _, t := range ts {
		row := []string{t.Name.Lower().String()}
		for _, r := range t.Refs {
			row = append(row, r.Rule.String()+" "+r.Text)
		}
		out = append(out, row)
	}
	return out
}

func dngpNames(ns []dnswire.Name) []string {
	var out []string
	for _, n := range ns {
		out = append(out, n.Lower().String())
	}
	return out
}

func dngpFile(t testing.TB, lines ...string) *expect.File {
	return decFile(t, append([]string{"domain corp.test."}, lines...)...)
}

// ---- rows: the targets ----

func TestTargetsRows(t *testing.T) {
	rows := []struct {
		name  string
		lines []string
		want  [][]string
	}{
		{"cname", []string{`cdn.corp.test. CNAME edge.dnshost.test.`},
			[][]string{{"edge.dnshost.test.", dngpAlias + "cdn.corp.test. CNAME edge.dnshost.test."}}},
		{"dname", []string{`old.corp.test. DNAME new.dnshost.test.`},
			[][]string{{"new.dnshost.test.", dngpAlias + "old.corp.test. DNAME new.dnshost.test."}}},
		{"ns host outside the zone only", []string{`corp.test. NS ns1.corp.test. | ns3.dnshost.test.`},
			[][]string{{"ns3.dnshost.test.", dngpNSHost + "corp.test. NS ns3.dnshost.test."}}},
		{"mx exchange", []string{`corp.test. MX 10 mx.dnshost.test.`},
			[][]string{{"mx.dnshost.test.", dngpMail + "corp.test. MX mx.dnshost.test."}}},
		{"null mx", []string{`corp.test. MX 0 .`}, nil},
		{"null mx beside a real one", []string{`corp.test. MX 0 . | 10 mx.dnshost.test.`},
			[][]string{{"mx.dnshost.test.", dngpMail + "corp.test. MX mx.dnshost.test."}}},
		{"root alias target", []string{`cdn.corp.test. CNAME .`}, nil},
		{"spf include", []string{`corp.test. TXT "v=spf1 include:spf.dnshost.test -all"`},
			[][]string{{"spf.dnshost.test.", dngpMail + "corp.test. TXT include:spf.dnshost.test."}}},
		{"other forms give nothing", []string{
			`cdn.corp.test. CNAME like *.dnshost.test.`, `corp.test. NS like *.dnshost.test.`, `old.corp.test. DNAME none`,
			`corp.test. MX none`, `corp.test. TXT none`, `www.corp.test. A in 10.53.0.0/24`, `mail.corp.test. MX like mx.dnshost.test.`,
			`mail.corp.test. TXT "hello"`, `www.corp.test. CNAME none`}, nil},
		{"own zone is left out", []string{
			`cdn.corp.test. CNAME www.corp.test.`, `old.corp.test. DNAME corp.test.`, `corp.test. MX 10 a.b.corp.test.`,
			`corp.test. NS ns1.corp.test. | ns2.corp.test.`, `www.corp.test. TXT "v=spf1 include:spf.corp.test include:corp.test"`}, nil},
		{"a declared subzone is kept", []string{
			`sub.corp.test. NS ns1.sub.corp.test.`, `cdn.corp.test. CNAME sub.corp.test.`, `corp.test. MX 10 mx.sub.corp.test.`},
			[][]string{
				{"mx.sub.corp.test.", dngpMail + "corp.test. MX mx.sub.corp.test."},
				{"sub.corp.test.", dngpAlias + "cdn.corp.test. CNAME sub.corp.test."},
				{"ns1.sub.corp.test.", dngpNSHost + "sub.corp.test. NS ns1.sub.corp.test."}}},
		{"a none NS line declares no subzone", []string{`sub.corp.test. NS none`, `cdn.corp.test. CNAME a.sub.corp.test.`}, nil},
		{"a like NS line declares a subzone", []string{`sub.corp.test. NS like *.x.test.`, `cdn.corp.test. CNAME a.sub.corp.test.`},
			[][]string{{"a.sub.corp.test.", dngpAlias + "cdn.corp.test. CNAME a.sub.corp.test."}}},
		{"a name above the domain is outside it", []string{`cdn.corp.test. CNAME test.`},
			[][]string{{"test.", dngpAlias + "cdn.corp.test. CNAME test."}}},
		{"canonical order of the lines", []string{
			`www.corp.test. CNAME b.dnshost.test.`, `cdn.corp.test. CNAME a.dnshost.test.`, `corp.test. NS ns3.dnshost.test.`},
			[][]string{
				{"ns3.dnshost.test.", dngpNSHost + "corp.test. NS ns3.dnshost.test."},
				{"a.dnshost.test.", dngpAlias + "cdn.corp.test. CNAME a.dnshost.test."},
				{"b.dnshost.test.", dngpAlias + "www.corp.test. CNAME b.dnshost.test."}}},
		{"one target for equal names, refs in order of appearance", []string{
			`www.corp.test. CNAME edge.dnshost.test.`, `cdn.corp.test. CNAME Edge.DnsHost.Test.`,
			`corp.test. MX 10 edge.dnshost.test.`, `corp.test. NS ns1.corp.test. | edge.dnshost.test.`},
			[][]string{{"edge.dnshost.test.",
				dngpNSHost + "corp.test. NS edge.dnshost.test.", dngpMail + "corp.test. MX edge.dnshost.test.",
				dngpAlias + "cdn.corp.test. CNAME edge.dnshost.test.", dngpAlias + "www.corp.test. CNAME edge.dnshost.test."}}},
		{"no repeated ref", []string{
			`corp.test. MX 10 mx.dnshost.test. | 20 mx.dnshost.test.`,
			`corp.test. TXT "v=spf1 include:a.dnshost.test include:A.DnsHost.Test. include:a.dnshost.test"`},
			[][]string{
				{"mx.dnshost.test.", dngpMail + "corp.test. MX mx.dnshost.test."},
				{"a.dnshost.test.", dngpMail + "corp.test. TXT include:a.dnshost.test."}}},
		{"each alternative, then each record", []string{`corp.test. NS ns2.a.test. | ns1.a.test. || ns4.a.test. | ns3.a.test.`},
			[][]string{
				{"ns1.a.test.", dngpNSHost + "corp.test. NS ns1.a.test."}, {"ns2.a.test.", dngpNSHost + "corp.test. NS ns2.a.test."},
				{"ns3.a.test.", dngpNSHost + "corp.test. NS ns3.a.test."}, {"ns4.a.test.", dngpNSHost + "corp.test. NS ns4.a.test."}}},
		{"names are written in lower case", []string{`CDN.Corp.Test. CNAME Edge.DnsHost.Test.`},
			[][]string{{"edge.dnshost.test.", dngpAlias + "cdn.corp.test. CNAME edge.dnshost.test."}}},
		{"a target with a line of its own is still a target", []string{`cdn.corp.test. CNAME edge.dnshost.test.`, `edge.dnshost.test. A 10.53.0.83`},
			[][]string{{"edge.dnshost.test.", dngpAlias + "cdn.corp.test. CNAME edge.dnshost.test."}}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := dngpRender(Targets(dngpFile(t, r.lines...)))
			if !reflect.DeepEqual(got, r.want) {
				t.Errorf("Targets gave %q, want %q", got, r.want)
			}
		})
	}
}

func TestTargetsAndWildcardsOfNilFile(t *testing.T) {
	if got := Targets(nil); got != nil {
		t.Errorf("Targets(nil) = %v", got)
	}
	if got := Wildcards(nil); got != nil {
		t.Errorf("Wildcards(nil) = %v", got)
	}
}

func TestTargetsOfAnotherDomainFile(t *testing.T) {
	f := decFile(t, "domain example.", "cdn.example. CNAME edge.dnshost.test.", "www.example. CNAME www.example.", "example. NS ns1.example.")
	got := dngpRender(Targets(f))
	want := [][]string{{"edge.dnshost.test.", dngpAlias + "cdn.example. CNAME edge.dnshost.test."}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Targets gave %q, want %q", got, want)
	}
}

// ---- rows: the SPF scan ----

func TestSPFScanRows(t *testing.T) {
	a, b := "a.dnshost.test.", "b.dnshost.test."
	long := strings.Repeat("a", 64)
	rows := []struct {
		name string
		data string // the data of a TXT line
		want []string
	}{
		{"plain", `"v=spf1 include:a.dnshost.test -all"`, []string{a}},
		{"case of the version, the term and the name", `"V=SPF1 INCLUDE:A.DnsHost.Test -ALL"`, []string{a}},
		{"every qualifier", `"v=spf1 +include:a.dnshost.test -include:b.dnshost.test ~include:c.dnshost.test ?include:d.dnshost.test"`,
			[]string{a, b, "c.dnshost.test.", "d.dnshost.test."}},
		{"another octet in front", `"v=spf1 *include:a.dnshost.test"`, nil},
		{"two qualifiers", `"v=spf1 ++include:a.dnshost.test"`, nil},
		{"qualifier with a macro", `"v=spf1 -include:%{d}.dnshost.test include:b.dnshost.test"`, []string{b}},
		{"macro in the middle", `"v=spf1 include:a%.dnshost.test"`, nil},
		{"trailing dot", `"v=spf1 include:a.dnshost.test. -all"`, []string{a}},
		{"two trailing dots", `"v=spf1 include:a.dnshost.test.. -all"`, nil},
		{"empty domain", `"v=spf1 include: -all"`, nil},
		{"root domain", `"v=spf1 include:. -all"`, nil},
		{"other terms", `"v=spf1 a mx ip4:10.0.0.0/8 exists:x.dnshost.test redirect=y.dnshost.test -all"`, nil},
		{"not include:", `"v=spf1 include=a.dnshost.test includes:a.dnshost.test xinclude:a.dnshost.test include"`, nil},
		{"a longer version", `"v=spf10 include:a.dnshost.test"`, nil},
		{"no space after the version", `"v=spf1include:a.dnshost.test"`, nil},
		{"a space in front", `" v=spf1 include:a.dnshost.test"`, nil},
		{"another version", `"v=spf2.0/pra include:a.dnshost.test"`, nil},
		{"text before the version", `"hello v=spf1 include:a.dnshost.test"`, nil},
		{"the version alone", `"v=spf1"`, nil},
		{"short text", `"v=spf"`, nil},
		{"qualifier alone", `"v=spf1 +"`, nil},
		{"several spaces", `"v=spf1  include:a.dnshost.test   include:b.dnshost.test "`, []string{a, b}},
		{"two strings, split inside a term", `"v=spf1 include:a" ".dnshost.test -all"`, []string{a}},
		{"two strings, split inside the version", `"v=spf" "1 include:a.dnshost.test"`, []string{a}},
		{"two strings, no space between version and term", `"v=spf1" "include:a.dnshost.test"`, nil},
		{"two strings, space at the end of the first", `"v=spf1 " "include:a.dnshost.test"`, []string{a}},
		{"two strings, space at the start of the second", `"v=spf1" " include:a.dnshost.test"`, []string{a}},
		{"own zone is left out", `"v=spf1 include:spf.corp.test include:corp.test include:a.dnshost.test"`, []string{a}},
		{"order of appearance, no repeat", `"v=spf1 include:b.dnshost.test include:a.dnshost.test include:B.dnshost.test"`, []string{b, a}},
		{"a label that is too long", `"v=spf1 include:` + long + `.dnshost.test include:a.dnshost.test"`, []string{a}},
		{"a record that is not SPF beside one that is", `"hello" | "v=spf1 include:a.dnshost.test"`, []string{a}},
		{"each alternative", `"v=spf1 include:a.dnshost.test" || "v=spf1 include:b.dnshost.test"`, []string{a, b}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			var want [][]string
			for _, n := range r.want {
				want = append(want, []string{n, dngpMail + "corp.test. TXT include:" + n})
			}
			if got := dngpRender(Targets(dngpFile(t, "corp.test. TXT "+r.data))); !reflect.DeepEqual(got, want) {
				t.Errorf("Targets gave %q, want %q", got, want)
			}
		})
	}
}

// ---- rows: the wildcards ----

func TestWildcardsRows(t *testing.T) {
	// 63+63+63+34 octets leave 255 - 27 for the label of 26: the last name that fits.
	zone := func(last int) string {
		l63, l := strings.Repeat("a", 63), strings.Repeat("b", last)
		return l63 + "." + l63 + "." + l63 + "." + l + "."
	}
	rows := []struct {
		name  string
		lines []string
		want  []string
	}{
		{"none", []string{`*.corp.test. A none`}, []string{"corp.test."}},
		{"two none lines give one name", []string{`*.corp.test. A none`, `*.corp.test. AAAA none`}, []string{"corp.test."}},
		{"A none at a second owner", []string{`*.sub.corp.test. MX none`, `*.sub.corp.test. A none`, `*.corp.test. A none`}, []string{"corp.test.", "sub.corp.test."}},
		{"other lines at the owner do not matter: none", []string{`*.corp.test. A none`, `*.corp.test. MX none`}, []string{"corp.test."}},
		{"other lines at the owner do not matter: data", []string{`*.corp.test. A none`, `*.corp.test. TXT "x"`}, []string{"corp.test."}},
		{"only another type, none", []string{`*.corp.test. MX none`}, nil},
		{"only another type, AAAA none", []string{`*.corp.test. AAAA none`}, nil},
		{"only another type, data", []string{`*.corp.test. TXT "x"`}, nil},
		{"data", []string{`*.corp.test. A 10.53.0.66`}, nil},
		{"range", []string{`*.corp.test. A in 10.53.0.0/24`}, nil},
		{"like", []string{`*.corp.test. CNAME like *.dnshost.test.`}, nil},
		{"canonical order", []string{`*.sub.corp.test. A none`, `*.corp.test. A none`}, []string{"corp.test.", "sub.corp.test."}},
		{"one name with data does not hide another", []string{`*.sub.corp.test. A 10.53.0.66`, `*.corp.test. A none`}, []string{"corp.test."}},
		{"first label is not exactly a star", []string{`a*.corp.test. A none`, `x.*.corp.test. A none`, `*x.corp.test. A none`}, nil},
		{"a star under a star", []string{`*.*.corp.test. A none`}, []string{"*.corp.test."}},
		{"case", []string{`*.CORP.test. A none`}, []string{"corp.test."}},
		{"outside the domain", []string{`*.example. A none`}, []string{"example."}},
		{"under the root", []string{`*. A none`}, []string{"."}},
		{"the last name with room", []string{`*.` + zone(34) + ` A none`}, []string{zone(34)}},
		{"no room", []string{`*.` + zone(35) + ` A none`}, nil},
		{"a line with data elsewhere", []string{`www.corp.test. A 10.53.0.81`, `*.corp.test. A none`}, []string{"corp.test."}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			if got := dngpNames(Wildcards(dngpFile(t, r.lines...))); !reflect.DeepEqual(got, r.want) {
				t.Errorf("Wildcards gave %q, want %q", got, r.want)
			}
		})
	}
}

// ---- rows: the findings ----

// dngpObserve builds a run with the given zone. A no such name answer
// carries a SOA record owned by that zone, unless its spec names another
// owner as "noname@<owner>" or "compact@<owner>".
func dngpObserve(t testing.TB, key obs.Key, zone string, specs ...string) obs.Observation {
	t.Helper()
	specs = slices.Clone(specs)
	for i, s := range specs {
		if (s == "noname" || s == "compact") && zone != "" {
			specs[i] = s + "@" + zone
		}
	}
	return decObservation(key, decName(t, zone), nil, dngpAnswers(t, key.Name.String(), key.Type, specs...)...)
}

func dngpAnswers(t testing.TB, owner string, typ dnswire.Type, specs ...string) []obs.Answer {
	t.Helper()
	var out []obs.Answer
	for i, s := range specs {
		out = append(out, dngpAnswer(t, i, owner, typ, s))
	}
	return out
}

func dngpAnswer(t testing.TB, server int, owner string, typ dnswire.Type, spec string) obs.Answer {
	t.Helper()
	kind, soa, _ := strings.Cut(spec, "@")
	var r obs.Result
	if kind != "noname" && kind != "compact" {
		r = dngResult(t, owner, typ, spec)
	} else {
		n := obs.NoName{Compact: kind == "compact"}
		switch soa {
		case "":
			n.SOA = decSOA(t, "corp.test.")
		default:
			n.SOA = decSOA(t, soa)
		}
		r = obs.NoNameResult(n)
	}
	return decAnswer(t, dngServers[server].host, dngServers[server].addr, r)
}

type dngpWant struct {
	rule     Rule
	expected string
	seen     []string // "<answer index> <text>"
}

func TestProbeFindingRows(t *testing.T) {
	alias := []string{"cdn.corp.test. CNAME edge.dnshost.test."}
	rows := []struct {
		name   string
		lines  []string
		domain string
		owner  string
		typ    dnswire.Type
		zone   string
		specs  []string
		want   []dngpWant
	}{
		{"alias, one label below the zone", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname", "noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name", "1 no such name"}}}},
		{"alias, two labels below the zone", alias, "", "edge.dnshost.test.", dnswire.TypeA, "test.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"three labels below the zone", alias, "", "edge.dnshost.test.", dnswire.TypeA, ".", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: . does not delegate test."}}}},
		{"the zone is the name", alias, "", "edge.dnshost.test.", dnswire.TypeA, "edge.dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name"}}}},
		{"the name is not under the zone", alias, "", "edge.dnshost.test.", dnswire.TypeA, "example.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name"}}}},
		{"zone and name in capitals", alias, "", "EDGE.DnsHost.Test.", dnswire.TypeA, "TEST.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"a name two labels under a subzone", []string{"sub.corp.test. NS ns1.sub.corp.test.", "cdn.corp.test. CNAME a.b.sub.corp.test."}, "",
			"a.b.sub.corp.test.", dnswire.TypeA, "sub.corp.test.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, "cdn.corp.test. CNAME a.b.sub.corp.test.", []string{"0 no such name: sub.corp.test. does not delegate b.sub.corp.test."}}}},
		{"nameserver host", []string{"corp.test. NS ns1.corp.test. | ns3.dnshost.test."}, "", "ns3.dnshost.test.", dnswire.TypeA, "test.", []string{"noname", "noname"},
			[]dngpWant{{RuleNameServerHost, "corp.test. NS ns3.dnshost.test.", []string{"0 no such name: test. does not delegate dnshost.test.", "1 no such name: test. does not delegate dnshost.test."}}}},
		{"mx", []string{"corp.test. MX 10 mx.dnshost.test."}, "", "mx.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleMailTarget, "corp.test. MX mx.dnshost.test.", []string{"0 no such name"}}}},
		{"spf include", []string{`corp.test. TXT "v=spf1 include:spf.dnshost.test -all"`}, "", "spf.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleMailTarget, "corp.test. TXT include:spf.dnshost.test.", []string{"0 no such name"}}}},
		{"three rules for one name, each with its own refs", []string{
			"cdn.corp.test. CNAME edge.dnshost.test.", "www.corp.test. CNAME edge.dnshost.test.", "corp.test. MX 10 edge.dnshost.test.",
			"corp.test. NS ns1.corp.test. | edge.dnshost.test.", `corp.test. TXT "v=spf1 include:edge.dnshost.test"`},
			"", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{
				{RuleAliasTarget, "cdn.corp.test. CNAME edge.dnshost.test.; www.corp.test. CNAME edge.dnshost.test.", []string{"0 no such name"}},
				{RuleNameServerHost, "corp.test. NS edge.dnshost.test.", []string{"0 no such name"}},
				{RuleMailTarget, "corp.test. MX edge.dnshost.test.; corp.test. TXT include:edge.dnshost.test.", []string{"0 no such name"}}}},
		{"only the servers that say no such name are seen", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.",
			[]string{"10.53.0.83", "noname", "nodata", "fail", "compact"}[:4],
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"1 no such name"}}}},
		{"the compact form counts", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"nodata", "compact"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"1 no such name"}}}},
		{"the zone of the run is the parent, the SOA is the zone of the target", alias, "", "edge.dnshost.test.", dnswire.TypeA, "test.", []string{"noname@dnshost.test."},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name"}}}},
		{"the zone of the run is the child, the SOA is the parent", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname@test."},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"two answers, two SOA owners", alias, "", "edge.dnshost.test.", dnswire.TypeA, ".", []string{"noname@test.", "noname@dnshost.test.", "compact@."},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: test. does not delegate dnshost.test.", "1 no such name", "2 no such name: . does not delegate test."}}}},
		{"the SOA owner is no ancestor of the name", alias, "", "edge.dnshost.test.", dnswire.TypeA, "test.", []string{"noname@example.", "noname@corp.test.", "noname@mx.dnshost.test."},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name", "1 no such name", "2 no such name"}}}},
		{"the SOA owner in capitals", alias, "", "EDGE.DnsHost.Test.", dnswire.TypeA, "dnshost.test.", []string{"noname@TEST."},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"the SOA owner of a nameserver host", []string{"corp.test. NS ns1.corp.test. | ns3.dnshost.test."}, "", "ns3.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname@test."},
			[]dngpWant{{RuleNameServerHost, "corp.test. NS ns3.dnshost.test.", []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"the SOA owner of a mail target", []string{"corp.test. MX 10 mx.dnshost.test."}, "", "mx.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname@test."},
			[]dngpWant{{RuleMailTarget, "corp.test. MX mx.dnshost.test.", []string{"0 no such name: test. does not delegate dnshost.test."}}}},
		{"records give nothing", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"10.53.0.83", "10.53.0.83"}, nil},
		{"no data gives nothing", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"nodata", "nodata"}, nil},
		{"failures give nothing, not even not-covered", alias, "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"fail", "fail"}, nil},
		{"another type than A is not covered", alias, "", "edge.dnshost.test.", dnswire.TypeAAAA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleNotCovered, "", []string{"0 none"}}}},
		{"a name that no line points at is not covered", alias, "", "other.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleNotCovered, "", []string{"0 none"}}}},
		{"a name in the domain's own zone is not a target", []string{"cdn.corp.test. CNAME www.corp.test."}, "", "www.corp.test.", dnswire.TypeA, "corp.test.", []string{"noname"},
			[]dngpWant{{RuleNotCovered, "", []string{"0 none"}}}},
		{"a file of another domain covers nothing", alias, "shop.test.", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleNotCovered, "", []string{"0 none"}}}},
		{"a line of its own is judged beside the rule", append([]string{"edge.dnshost.test. A 10.53.0.83"}, alias...), "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleRecordSet, "10.53.0.83", []string{"0 none"}}, {RuleAliasTarget, alias[0], []string{"0 no such name"}}}},
		{"a line of its own that matches", append([]string{"edge.dnshost.test. A none"}, alias...), "", "edge.dnshost.test.", dnswire.TypeA, "dnshost.test.", []string{"noname"},
			[]dngpWant{{RuleAliasTarget, alias[0], []string{"0 no such name"}}}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := dngpFile(t, r.lines...)
			if r.domain != "" {
				f = decFile(t, "domain "+r.domain, "www."+r.domain+" A 10.53.0.81")
			}
			key := decRecordsKey(t, "corp.test.", r.owner, r.typ)
			o := dngpObserve(t, key, r.zone, r.specs...)
			var want []decWant
			for _, w := range r.want {
				want = append(want, decWant{rule: w.rule, severity: dngpSeverity(w.rule), expected: w.expected, seen: dngSeenOf(t, o.Answers, w.seen...)})
			}
			if r.want == nil {
				want = nil
			}
			regCheck(t, Findings(f, o), key, want...)
		})
	}
}

func TestProbeRulesNeedAFile(t *testing.T) {
	key := decRecordsKey(t, "corp.test.", "edge.dnshost.test.", dnswire.TypeA)
	o := dngpObserve(t, key, "dnshost.test.", "noname")
	regCheck(t, Findings(nil, o), key, decWant{RuleNotCovered, SeverityMedium, "", dngSeenOf(t, o.Answers, "0 none")})
}

func dngpWildcardKey(t testing.TB, domain, z string) obs.Key {
	return obs.WildcardKey(decName(t, domain), decName(t, z))
}

func dngpWildcardObserve(t testing.TB, key obs.Key, label string, specs ...string) obs.Observation {
	t.Helper()
	owner := label + "." + key.Name.String()
	o := decObservation(key, key.Name, nil, dngpAnswers(t, owner, dnswire.TypeA, specs...)...)
	for i := range o.Answers {
		o.Answers[i].Question = dnswire.Question{Name: decName(t, owner), Type: dnswire.TypeA, Class: dnswire.ClassINET}
	}
	return o
}

func TestWildcardFindingRows(t *testing.T) {
	none := []string{"*.corp.test. A none"}
	rows := []struct {
		name   string
		lines  []string
		domain string
		zone   string
		specs  []string
		want   []dngpWant
	}{
		{"one server answers", none, "corp.test.", "corp.test.", []string{"10.53.0.66", "noname", "nodata", "fail"},
			[]dngpWant{{RuleWildcard, "none", []string{"0 10.53.0.66"}}}},
		{"two sets", none, "corp.test.", "corp.test.", []string{"10.53.0.66", "10.53.0.67;10.53.0.66"},
			[]dngpWant{{RuleWildcard, "none", []string{"0 10.53.0.66", "1 10.53.0.66 | 10.53.0.67"}}}},
		{"a cname shows its target", none, "corp.test.", "corp.test.", []string{"nodata", "CNAME edge.dnshost.test."},
			[]dngpWant{{RuleWildcard, "none", []string{"1 CNAME edge.dnshost.test."}}}},
		{"the label in the data, in capitals", none, "corp.test.", "corp.test.", []string{"CNAME ABCDEFGHIJKLMNOPQRSTUVWXYZ.other.test.", "10.53.0.66"},
			[]dngpWant{{RuleWildcard, "none", []string{"0 CNAME *.other.test.", "1 10.53.0.66"}}}},
		{"the label in the data, twice", none, "corp.test.", "corp.test.", []string{"CNAME abcdefghijklmnopqrstuvwxyz.AbcdefghijklmnopqrstuvwXYZ.test."},
			[]dngpWant{{RuleWildcard, "none", []string{"0 CNAME *.*.test."}}}},
		{"data that does not hold the label", none, "corp.test.", "corp.test.", []string{"CNAME abcdefghijklmnopqrstuvwxy.other.test."},
			[]dngpWant{{RuleWildcard, "none", []string{"0 CNAME abcdefghijklmnopqrstuvwxy.other.test."}}}},
		{"a subzone", []string{"*.sub.corp.test. A none"}, "corp.test.", "sub.corp.test.", []string{"10.53.0.66"},
			[]dngpWant{{RuleWildcard, "none", []string{"0 10.53.0.66"}}}},
		{"no data, no such name and failures are not seen", none, "corp.test.", "corp.test.", []string{"nodata", "noname", "compact", "fail"}, nil},
		{"a name that is not in the list", none, "corp.test.", "sub.corp.test.", []string{"10.53.0.66"}, nil},
		{"a wildcard with data is expected", []string{"*.corp.test. A 10.53.0.66"}, "corp.test.", "corp.test.", []string{"10.53.0.66"}, nil},
		{"a wildcard of another type with data", []string{"*.corp.test. A none", `*.corp.test. TXT "x"`}, "corp.test.", "corp.test.", []string{"10.53.0.66"},
			[]dngpWant{{RuleWildcard, "none", []string{"0 10.53.0.66"}}}},
		{"only a wildcard of another type is none", []string{"*.corp.test. MX none"}, "corp.test.", "corp.test.", []string{"10.53.0.66"}, nil},
		{"a key of another domain", none, "shop.test.", "corp.test.", []string{"10.53.0.66"}, nil},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := dngpFile(t, r.lines...)
			key := dngpWildcardKey(t, r.domain, r.zone)
			o := dngpWildcardObserve(t, key, "abcdefghijklmnopqrstuvwxyz", r.specs...)
			var want []decWant
			for _, w := range r.want {
				want = append(want, decWant{rule: w.rule, severity: SeverityMedium, expected: w.expected, seen: dngSeenOf(t, o.Answers, w.seen...)})
			}
			regCheck(t, Findings(f, o), key, want...)
		})
	}
	t.Run("a nil file", func(t *testing.T) {
		key := dngpWildcardKey(t, "corp.test.", "corp.test.")
		if got := Findings(nil, dngpWildcardObserve(t, key, "abc", "10.53.0.66")); len(got) != 0 {
			t.Errorf("a wildcard check without a file gave%s", decShow(got))
		}
	})
	t.Run("the ordinary check of the same name is not the wildcard check", func(t *testing.T) {
		f := dngpFile(t, none...)
		key := decRecordsKey(t, "corp.test.", "corp.test.", dnswire.TypeA)
		for _, got := range Findings(f, dngpObserve(t, key, "corp.test.", "10.53.0.66")) {
			if got.Rule == RuleWildcard {
				t.Errorf("a records check gave a wildcard finding")
			}
		}
	})
}

func TestWildcardFindingHoldsNoLabel(t *testing.T) {
	const label = "qzqzqzqzqzqzqzqzqzqzqzqzqz"
	f := dngpFile(t, "*.corp.test. A none")
	key := dngpWildcardKey(t, "corp.test.", "corp.test.")
	// The data holds the asked name, as a DNAME or a wildcard CNAME makes it.
	specs := func(data string) []string {
		return []string{"CNAME " + data + ".other.test.", "10.53.0.66", "nodata"}
	}
	o := dngpWildcardObserve(t, key, label, specs(strings.ToUpper(label))...)
	got := Findings(f, o)
	if len(got) != 1 || len(got[0].Seen) != 2 {
		t.Fatalf("got%s", decShow(got))
	}
	for i, want := range []string{"CNAME *.other.test.", "10.53.0.66"} {
		if got[0].Seen[i].Text != want {
			t.Errorf("seen %d is %q, want %q", i, got[0].Seen[i].Text, want)
		}
	}
	for _, s := range []string{got[0].Expected, got[0].Value, got[0].Check.String(), got[0].Seen[0].Text, got[0].Seen[1].Text} {
		if strings.Contains(strings.ToLower(s), label) {
			t.Errorf("%q holds the label", s)
		}
	}
	// A run with another label, in another case, says the same: equal texts,
	// equal Value, and no update for the open alert.
	for _, other := range []struct{ asked, data string }{
		{"mnmnmnmnmnmnmnmnmnmnmnmnmn", "mnmnmnmnmnmnmnmnmnmnmnmnmn"},
		{"MNMNMNMNMNMNMNMNMNMNMNMNMN", "mnmnmnmnmnmnmnmnmnmnmnmnmn"},
		{"mnmnmnmnmnmnmnmnmnmnmnmnmn", "MNMNMNMNMNMNMNMNMNMNMNMNMN"},
	} {
		o2 := dngpWildcardObserve(t, key, other.asked, specs(other.data)...)
		second := Findings(f, o2)
		if len(second) != 1 || second[0].Value != got[0].Value || second[0].Expected != got[0].Expected || !reflect.DeepEqual(dngpTexts(second[0]), dngpTexts(got[0])) {
			t.Errorf("label %q, data %q gave%s\nbut%s", other.asked, other.data, decShow(second), decShow(got))
		}
		in := Input{Expect: f, Open: got, Observation: o2, Now: decT0.Add(time.Hour)}
		if cs := dngOfRule(Decide(in), RuleWildcard); len(cs) != 0 {
			t.Errorf("label %q: another label changed the alert:%s", other.asked, decShowChanges(cs))
		}
	}
}

func dngpTexts(f Finding) []string {
	var out []string
	for _, s := range f.Seen {
		out = append(out, s.Text)
	}
	return out
}

func TestTargetsManyLines(t *testing.T) {
	const n = 2000
	lines := make([]string, 0, 2*n)
	for i := range n {
		lines = append(lines, "o"+strconv.Itoa(i)+".corp.test. CNAME t"+strconv.Itoa(i)+".dnshost.test.")
	}
	for i := range n {
		lines = append(lines, "p"+strconv.Itoa(i)+".corp.test. CNAME T"+strconv.Itoa(i)+".DnsHost.Test.")
	}
	// The file puts the o lines before the p lines, each group by owner in
	// the order of the octets of its first label.
	order := make([]string, n)
	for i := range order {
		order[i] = strconv.Itoa(i)
	}
	slices.SortFunc(order, func(a, b string) int { return strings.Compare("o"+a, "o"+b) })
	var want [][]string
	for _, i := range order {
		want = append(want, []string{"t" + i + ".dnshost.test.",
			dngpAlias + "o" + i + ".corp.test. CNAME t" + i + ".dnshost.test.",
			dngpAlias + "p" + i + ".corp.test. CNAME t" + i + ".dnshost.test."})
	}
	if got := dngpRender(Targets(dngpFile(t, lines...))); !reflect.DeepEqual(got, want) {
		t.Errorf("Targets of %d lines gave %d targets, first %q; want %d, first %q", len(lines), len(got), got[:min(1, len(got))], len(want), want[:1])
	}
}

// ---- rows: the alerts ----

func TestProbeAlertOpensUpdatesAndResolves(t *testing.T) {
	lines := []string{"cdn.corp.test. CNAME edge.dnshost.test."}
	key := decRecordsKey(t, "corp.test.", "edge.dnshost.test.", dnswire.TypeA)
	f := dngpFile(t, lines...)
	now := decT0.Add(time.Hour)
	run := func(f *expect.File, open []Finding, specs ...string) []Change {
		return Decide(Input{Expect: f, Open: open, Observation: dngpObserve(t, key, "dnshost.test.", specs...), Now: now})
	}
	both := Findings(f, dngpObserve(t, key, "dnshost.test.", "noname", "noname"))
	one := Findings(f, dngpObserve(t, key, "dnshost.test.", "noname"))
	if len(both) != 1 || len(one) != 1 {
		t.Fatalf("setup: %s / %s", decShow(both), decShow(one))
	}
	ofRule := func(cs []Change) []Change { return dngOfRule(cs, RuleAliasTarget) }
	rows := []struct {
		name string
		got  []Change
		want []Change
	}{
		{"opens", ofRule(run(f, nil, "noname", "noname")), []Change{{Op: OpOpen, Finding: both[0], At: now}}},
		{"quiet while it lasts", ofRule(run(f, both, "noname", "noname")), nil},
		{"a new server is news", ofRule(run(f, one, "noname", "noname")), []Change{{Op: OpUpdate, Finding: both[0], At: now}}},
		{"a line that is gone is no news", ofRule(run(f, both, "noname", "fail")), nil},
		{"records resolve", ofRule(run(f, both, "10.53.0.83", "10.53.0.83")), []Change{{Op: OpResolve, Finding: both[0], At: now}}},
		{"no data resolves", ofRule(run(f, both, "nodata", "nodata")), []Change{{Op: OpResolve, Finding: both[0], At: now}}},
		{"a failure at a server that saw it blocks", ofRule(run(f, both, "10.53.0.83", "fail")), nil},
		{"a failure at another server does not", ofRule(run(f, one, "10.53.0.83", "fail")), []Change{{Op: OpResolve, Finding: one[0], At: now}}},
		{"every server failing blocks", ofRule(run(f, both, "fail", "fail")), nil},
		{"another Expected is news", ofRule(run(dngpFile(t, append([]string{"www.corp.test. CNAME edge.dnshost.test."}, lines...)...), both, "noname", "noname")),
			[]Change{{Op: OpUpdate, Finding: Findings(dngpFile(t, append([]string{"www.corp.test. CNAME edge.dnshost.test."}, lines...)...), dngpObserve(t, key, "dnshost.test.", "noname", "noname"))[0], At: now}}},
	}
	for _, r := range rows {
		if !dngSame(r.got, r.want) {
			t.Errorf("%s: got%s\nwant%s", r.name, decShowChanges(r.got), decShowChanges(r.want))
		}
	}
}

func TestWildcardAlertOpensUpdatesAndResolves(t *testing.T) {
	f := dngpFile(t, "*.corp.test. A none")
	key := dngpWildcardKey(t, "corp.test.", "corp.test.")
	now := decT0.Add(time.Hour)
	obsOf := func(label string, specs ...string) obs.Observation {
		return dngpWildcardObserve(t, key, label, specs...)
	}
	run := func(open []Finding, o obs.Observation) []Change {
		return dngOfRule(Decide(Input{Expect: f, Open: open, Observation: o, Now: now}), RuleWildcard)
	}
	first := obsOf("aaaaaaaaaaaaaaaaaaaaaaaaaa", "10.53.0.66", "10.53.0.66")
	open := Findings(f, first)
	if len(open) != 1 {
		t.Fatalf("setup: got%s", decShow(open))
	}
	rows := []struct {
		name string
		got  []Change
		want []Change
	}{
		{"opens", run(nil, first), []Change{{Op: OpOpen, Finding: open[0], At: now}}},
		{"another label is no news", run(open, obsOf("bbbbbbbbbbbbbbbbbbbbbbbbbb", "10.53.0.66", "10.53.0.66")), nil},
		{"a new set is news", run(open[:1], obsOf("cccccccccccccccccccccccccc", "10.53.0.66", "10.53.0.77")),
			[]Change{{Op: OpUpdate, Finding: Findings(f, obsOf("cccccccccccccccccccccccccc", "10.53.0.66", "10.53.0.77"))[0], At: now}}},
		{"no data resolves", run(open, obsOf("dddddddddddddddddddddddddd", "nodata", "noname")), []Change{{Op: OpResolve, Finding: open[0], At: now}}},
		{"a failure at a server that saw it blocks", run(open, obsOf("eeeeeeeeeeeeeeeeeeeeeeeeee", "nodata", "fail")), nil},
	}
	for _, r := range rows {
		if !dngSame(r.got, r.want) {
			t.Errorf("%s: got%s\nwant%s", r.name, decShowChanges(r.got), decShowChanges(r.want))
		}
	}
}

// ---- the property tests ----

var dngpLines = []struct {
	owner, typ string
	forms      []string
}{
	{"@", "NS", []string{"ns1.corp.test. | ns2.corp.test.", "ns1.corp.test. | ns3.dnshost.test.", "ns3.dnshost.test. | NS4.DnsHost.Test.", "ns1.corp.test. || ns5.dnshost.test.", "like *.dnshost.test.", "none"}},
	{"corp.test.", "NS", []string{"ns1.corp.test. | ns2.corp.test.", "ns1.dnshost.test."}},
	{"sub.corp.test.", "NS", []string{"ns1.sub.corp.test.", "ns1.sub.corp.test. | ns3.dnshost.test.", "like *.dnshost.test.", "none"}},
	{"cdn.corp.test.", "CNAME", []string{"edge.dnshost.test.", "Edge.DnsHost.Test.", "www.corp.test.", "x.sub.corp.test.", "test.", "like *.dnshost.test.", "none"}},
	{"www.corp.test.", "CNAME", []string{"edge.dnshost.test.", "cdn.example.", "corp.test."}},
	{"old.corp.test.", "DNAME", []string{"new.dnshost.test.", "new.sub.corp.test.", "new.corp.test."}},
	{"@", "MX", []string{"10 mx.dnshost.test.", "10 mx.dnshost.test. | 20 mx2.dnshost.test.", "10 mx.dnshost.test. || 20 mx.dnshost.test.", "0 .", "10 mail.corp.test.", "like mx.dnshost.test.", "none"}},
	{"mail.corp.test.", "MX", []string{"10 edge.dnshost.test.", "10 mx.sub.corp.test."}},
	{"@", "TXT", []string{`"v=spf1 include:spf.dnshost.test -all"`, `"v=spf1 include:spf.dnshost.test include:SPF2.DnsHost.Test. ~all"`,
		`"v=spf1 +include:a.corp.test -include:mx.dnshost.test"`, `"v=spf1 include:%{d}.x.test"`, `"v=spf10 include:spf.dnshost.test"`,
		`"v=spf1 include:spf" ".dnshost.test -all"`, `"hello"`, "none", `"v=spf1 include:edge.dnshost.test"`}},
	{"mail.corp.test.", "TXT", []string{`"v=spf1 include:edge.dnshost.test"`, `"v=spf1 include:x.sub.corp.test"`}},
	{"www.corp.test.", "A", []string{"10.53.0.81", "in 10.53.0.0/24", "none"}},
	{"edge.dnshost.test.", "A", []string{"10.53.0.83", "none", "in 10.53.0.0/24"}},
	{"ns3.dnshost.test.", "A", []string{"10.53.0.12", "none"}},
	{"*.corp.test.", "A", []string{"none", "none", "10.53.0.66"}},
	{"*.corp.test.", "AAAA", []string{"none", "fd53::66"}},
	{"*.corp.test.", "TXT", []string{"none", `"x"`}},
	{"*.sub.corp.test.", "A", []string{"none"}},
	{"*.sub.corp.test.", "MX", []string{"none", "10 mx.dnshost.test."}},
	{"*.corp.test.", "MX", []string{"none"}},
	{"*.example.", "A", []string{"none"}},
	{"*.test.", "A", []string{"none"}},
}

var (
	dngpPool  = []string{"www.corp.test.", "edge.dnshost.test.", "cdn.corp.test.", "sub.corp.test.", "ns3.dnshost.test.", "nope.corp.test.", "*.corp.test.", "corp.test.", "mx.dnshost.test."}
	dngpZones = []string{".", "test.", "dnshost.test.", "com.", "Test.", "example.", "corp.test.", "sub.corp.test."}
	dngpHits  = map[dnswire.Type][]string{
		dnswire.TypeA: {"10.53.0.66", "10.53.0.83", "CNAME edge.dnshost.test."}, dnswire.TypeAAAA: {"fd53::66"},
		dnswire.TypeMX: {"10 mx.dnshost.test."}, dnswire.TypeTXT: {`"x"`}, dnswire.TypeCNAME: {"CNAME edge.dnshost.test."},
	}
)

func dngpMakeFile(g *dngGen) *expect.File {
	switch g.rng.IntN(16) {
	case 0:
		return nil
	case 1:
		return decFile(g.t, "domain shop.test.", "www.shop.test. A 10.53.0.81", "cdn.shop.test. CNAME edge.dnshost.test.")
	}
	domain := g.pick("corp.test.", "corp.test.", "corp.test.", "corp.test.", "corp.test.", "Corp.Test.", "test.", "example.")
	lines := []string{"domain " + domain}
	seen := map[string]bool{}
	for _, l := range dngpLines {
		owner := l.owner
		if owner == "@" {
			owner = domain
		}
		k := strings.ToLower(owner) + l.typ
		if g.chance(2) || seen[k] {
			continue
		}
		seen[k] = true
		lines = append(lines, owner+" "+l.typ+" "+g.pick(l.forms...))
	}
	g.rng.Shuffle(len(lines)-1, func(i, j int) { lines[i+1], lines[j+1] = lines[j+1], lines[i+1] })
	return decFile(g.t, lines...)
}

func dngpRecase(g *dngGen, n dnswire.Name) dnswire.Name {
	if g.chance(4) {
		return decName(g.t, strings.ToUpper(n.String()))
	}
	return n
}

func dngpMakeKey(g *dngGen, f *expect.File) obs.Key {
	domain := "corp.test."
	if f != nil {
		domain = f.Domain.String()
	}
	switch g.rng.IntN(14) {
	case 0:
		domain = "shop.test."
	case 1:
		domain = strings.ToUpper(domain)
	}
	d := decName(g.t, domain)
	targets, wild := dngpTargetsOf(f), dngpWildcardsOf(f)
	switch x := g.rng.IntN(20); {
	case x < 8 && len(targets) > 0:
		typ := dnswire.TypeA
		if g.chance(5) {
			typ = []dnswire.Type{dnswire.TypeAAAA, dnswire.TypeMX}[g.rng.IntN(2)]
		}
		return obs.RecordsKey(d, dngpRecase(g, targets[g.rng.IntN(len(targets))].name), typ)
	case x < 13:
		z := decName(g.t, g.pick("corp.test.", "sub.corp.test.", "example.", "test.", "x.corp.test."))
		if len(wild) > 0 && !g.chance(4) {
			z = wild[g.rng.IntN(len(wild))]
		}
		return obs.WildcardKey(d, dngpRecase(g, z))
	}
	typ := []dnswire.Type{dnswire.TypeA, dnswire.TypeA, dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCNAME}[g.rng.IntN(7)]
	return obs.RecordsKey(d, dngpRecase(g, decName(g.t, g.pick(dngpPool...))), typ)
}

// dngpLabel draws a label as observe does: 26 octets of a to z and 2 to 7.
func dngpLabel(g *dngGen) string {
	const alphabet = "abcdefghijklmnopqrstuvwxyz234567"
	b := make([]byte, 26)
	for i := range b {
		b[i] = alphabet[g.rng.IntN(len(alphabet))]
	}
	return string(b)
}

func dngpMakeObservation(g *dngGen, f *expect.File, key obs.Key, label string) obs.Observation {
	zone := decName(g.t, g.pick(dngpZones...))
	if f != nil && key.Domain.Equal(f.Domain) && key.Name.IsSubdomainOf(f.Domain) {
		zone = f.Zone(key.Name)
	}
	if key.Kind == obs.KindWildcard && f != nil {
		zone = f.Zone(key.Name)
	}
	o := decObservation(key, zone, nil)
	asked := key.Name
	if key.Kind == obs.KindWildcard {
		asked = decName(g.t, dngpCase(g, label)+"."+key.Name.String())
	}
	hits := dngpHits[key.Type]
	if key.Kind == obs.KindWildcard {
		hits = append(slices.Clone(hits), "CNAME "+label+".other.test.", "CNAME "+strings.ToUpper(label)+".other.test.")
	}
	zones := dngpZones
	servers := slices.Clone(dngServers)
	g.rng.Shuffle(len(servers), func(i, j int) { servers[i], servers[j] = servers[j], servers[i] })
	for _, s := range servers[:1+g.rng.IntN(4)] {
		var spec string
		switch x := g.rng.IntN(12); {
		case x < 4 && key.Kind != obs.KindWildcard, x < 7 && key.Kind == obs.KindWildcard:
			spec = g.pick(hits...)
		case x < 7:
			spec = "noname@" + g.pick(zones...)
		case x < 8:
			spec = "compact@" + g.pick(zones...)
		case x < 9:
			spec = "nodata"
		default:
			spec = "fail"
		}
		a := dngpAnswer(g.t, slices.Index(dngServers, s), asked.String(), key.Type, spec)
		if spec == "fail" && g.chance(5) {
			a.Server.Addr = netip.AddrPort{}
		}
		a.Question = dnswire.Question{Name: asked, Type: key.Type, Class: dnswire.ClassINET}
		o.Answers = append(o.Answers, a)
	}
	return o
}

func dngpMakeOpen(g *dngGen, in Input, want []Finding) []Finding {
	o := in.Observation
	var open []Finding
	for range g.rng.IntN(4) {
		r := []Rule{RuleAliasTarget, RuleNameServerHost, RuleMailTarget, RuleWildcard, RuleWildcard, RuleRecordSet, RuleNotCovered}[g.rng.IntN(7)]
		f := Finding{Rule: r, Severity: []Severity{dngpSeverity(r), dngpSeverity(r), SeverityLow}[g.rng.IntN(3)], Check: o.Key}
		if i := slices.IndexFunc(want, func(w Finding) bool { return w.Rule == r }); i >= 0 {
			w := want[i]
			first, _, _ := strings.Cut(w.Value, "\n")
			f.Expected = g.pick(w.Expected, w.Expected, "", "old")
			f.Value = g.pick(w.Value, w.Value, first, "", "x", w.Value+"\nzzz")
		} else {
			f.Expected, f.Value = g.pick("", "none", "old"), g.pick("", "x", "10.53.0.11:53 ns1.corp.test. none")
		}
		switch g.rng.IntN(8) {
		case 0:
			f.Check.Domain = decName(g.t, strings.ToUpper(o.Key.Domain.String()))
			f.Check.Name = decName(g.t, strings.ToUpper(o.Key.Name.String()))
		case 1:
			f.Check = dngKey(g.t, "mail.corp.test.", dnswire.TypeA)
		}
		for _, i := range g.rng.Perm(len(dngServers))[:g.rng.IntN(4)] {
			f.Seen = append(f.Seen, Seen{Answer: decAnswer(g.t, dngServers[i].host, dngServers[i].addr, decNoName(g.t, "corp.test.")), Text: "no such name"})
		}
		open = append(open, f)
	}
	return open
}

func dngpCase(g *dngGen, s string) string {
	if g.chance(4) {
		return strings.ToUpper(s)
	}
	return s
}

func dngpInput(t testing.TB, seed uint64) Input { return dngpInputLabel(t, seed, "") }

// dngpInputLabel is the input of seed, with the label of a wildcard check
// replaced by label when it is not empty; nothing else changes.
func dngpInputLabel(t testing.TB, seed uint64, label string) Input {
	g := &dngGen{t: t, rng: rand.New(rand.NewPCG(seed, 31))}
	f := dngpMakeFile(g)
	in := Input{Expect: f}
	drawn := dngpLabel(g)
	if label == "" {
		label = drawn
	}
	in.Observation = dngpMakeObservation(g, f, dngpMakeKey(g, f), label)
	in.Now = in.Observation.Deadline.Add(time.Duration(g.rng.IntN(60)) * time.Second)
	in.Open = dngpMakeOpen(g, in, dngpFindings(f, in.Observation))
	return in
}

func dngpOnlyMine(cs []Change) []Change {
	return slices.DeleteFunc(slices.Clone(cs), func(c Change) bool {
		return !slices.Contains(append([]Rule{RuleWildcard}, dngpRules...), c.Finding.Rule)
	})
}

func TestProbeRulesProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngpSeed, dngpCases)
	tally := map[string]int{}
	for i := range dngpCases {
		seed := uint64(dngpSeed + i)
		in := dngpInput(t, seed)
		f, o := in.Expect, in.Observation
		if got, want := dngpRender(Targets(f)), dngpRenderOracle(dngpTargetsOf(f)); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: Targets gave %q, want %q", seed, got, want)
		}
		if got, want := dngpNames(Wildcards(f)), dngpNames(dngpWildcardsOf(f)); !reflect.DeepEqual(got, want) {
			t.Fatalf("seed %d: Wildcards gave %q, want %q", seed, got, want)
		}
		want := dngpFindings(f, o)
		got := Findings(f, o)
		if !dngSameFindings(got, want) {
			t.Fatalf("seed %d: Findings of %v gave%s\nwant%s", seed, o.Key, decShow(got), decShow(want))
		}
		changes := Decide(in)
		for _, r := range append([]Rule{RuleWildcard}, dngpRules...) {
			if g, w := dngOfRule(changes, r), dngpChanges(in, want, r); !dngSame(g, w) {
				t.Fatalf("seed %d: the %v changes are%s\nwant%s", seed, r, decShowChanges(g), decShowChanges(w))
			}
		}
		for _, c := range changes {
			if c.Finding.Check.String() != o.Key.String() {
				t.Fatalf("seed %d: a change of check %v", seed, c.Finding.Check)
			}
		}
		dngpTally(tally, in, want, changes)
	}
	for _, k := range []string{"alias-target", "nameserver-host", "mail-target", "wildcard", "open", "update", "resolve", "blocked",
		"exempt", "not-covered kept for a target of another type", "text with the domain", "plain text", "outside zone", "target with a line",
		"target in a subzone", "target key without a finding", "wildcard key without a finding", "no target answered no such name", "label masked"} {
		if tally[k] < 20 {
			t.Errorf("only %d cases reach %q: the inputs do not test it", tally[k], k)
		}
	}
}

func dngpRenderOracle(ts []dngpTarget) [][]string {
	var out [][]string
	for _, t := range ts {
		row := []string{t.name.Lower().String()}
		for _, r := range t.refs {
			row = append(row, r.Rule.String()+" "+r.Text)
		}
		out = append(out, row)
	}
	return out
}

func dngpTally(tally map[string]int, in Input, want []Finding, changes []Change) {
	o, f := in.Observation, in.Expect
	for _, w := range want {
		tally[w.Rule.String()]++
		for _, s := range w.Seen {
			if w.Rule == RuleWildcard && strings.Contains(s.Text, "*") {
				tally["label masked"]++
			}
		}
		for _, s := range w.Seen {
			if strings.Contains(s.Text, "does not delegate") {
				tally["text with the domain"]++
			} else if strings.HasPrefix(s.Text, "no such name") {
				tally["plain text"]++
			}
		}
	}
	for _, c := range dngpOnlyMine(changes) {
		tally[c.Op.String()]++
	}
	for _, r := range append([]Rule{RuleWildcard}, dngpRules...) {
		if was, ok := dngFirstOpen(in.Open, o.Key, r); ok && !slices.ContainsFunc(want, func(w Finding) bool { return w.Rule == r }) && dngBlocked(was, o) {
			tally["blocked"]++
		}
	}
	if o.Key.Kind != obs.KindRecords {
		if !slices.ContainsFunc(want, func(w Finding) bool { return w.Rule == RuleWildcard }) && f != nil && slices.ContainsFunc(dngpWildcardsOf(f), o.Key.Name.Equal) {
			tally["wildcard key without a finding"]++
		}
		return
	}
	cov := f != nil && o.Key.Domain.Equal(f.Domain)
	tg := dngpTargetOf(f, o.Key.Name)
	if !cov || tg == nil {
		return
	}
	_, line := dngCovLine(f, o.Key)
	switch {
	case o.Key.Type != dnswire.TypeA:
		tally["not-covered kept for a target of another type"]++
	case line == nil && !slices.ContainsFunc(dngpOnlyFindings(want), func(Finding) bool { return true }):
		tally["target key without a finding"]++
		if !slices.ContainsFunc(o.Answers, func(a obs.Answer) bool { return dngpAnswerKind(a) == "noname" }) {
			tally["no target answered no such name"]++
		}
		tally["exempt"]++
	case line == nil:
		tally["exempt"]++
	default:
		tally["target with a line"]++
	}
	if !o.Zone.Equal(f.Domain) && o.Key.Name.IsSubdomainOf(f.Domain) {
		tally["target in a subzone"]++
	}
	if !o.Key.Name.IsSubdomainOf(f.Domain) && !o.Zone.Equal(f.Domain) {
		tally["outside zone"]++
	}
}

func dngpOnlyFindings(want []Finding) []Finding {
	return slices.DeleteFunc(slices.Clone(want), func(f Finding) bool { return !slices.Contains(dngpRules, f.Rule) })
}

func TestProbeFindingsIgnoreFailuresAndQuestionsProperty(t *testing.T) {
	t.Logf("seed %d, %d cases", dngpSeed, dngpCases)
	zeroAnswers := func(fs []Finding) []Finding {
		out := slices.Clone(fs)
		for i := range out {
			out[i].Seen = slices.Clone(out[i].Seen)
			for j := range out[i].Seen {
				out[i].Seen[j].Answer = obs.Answer{}
			}
		}
		return out
	}
	zeroQuestions := func(fs []Finding) []Finding {
		out := slices.Clone(fs)
		for i := range out {
			out[i].Seen = slices.Clone(out[i].Seen)
			for j := range out[i].Seen {
				out[i].Seen[j].Answer.Question = dnswire.Question{}
			}
		}
		return out
	}
	for i := range dngpCases {
		seed := uint64(dngpSeed + i)
		in := dngpInput(t, seed)
		f, o := in.Expect, in.Observation
		base := Findings(f, o)
		g := &dngGen{t: t, rng: rand.New(rand.NewPCG(seed, 37))}

		// A failure beside the answers, and another reason for the failures
		// that are there, change nothing.
		more := o
		more.Answers = slices.Clone(o.Answers)
		extra := decAnswer(t, "ns9.corp.test.", "10.53.0.19:53", decFailure(obs.ReasonTimeout))
		extra.Question = more.Answers[0].Question
		more.Answers = slices.Insert(more.Answers, g.rng.IntN(len(more.Answers)+1), extra)
		for j, a := range more.Answers {
			if dngpAnswerKind(a) == "failure timeout" || strings.HasPrefix(dngpAnswerKind(a), "failure") {
				more.Answers[j].Result = decFailure(obs.Reason(1 + g.rng.IntN(14)))
			}
		}
		if got := Findings(f, more); !dngSameFindings(got, base) {
			t.Fatalf("seed %d: a failure changed%s\nto%s", seed, decShow(base), decShow(got))
		}

		if o.Key.Kind == obs.KindWildcard {
			// Another label, asked and held by the data, changes no text, no
			// Value, and so no alert.
			in2 := dngpInputLabel(t, seed, g.pick("mnmnmnmnmnmnmnmnmnmnmnmnmn", "MN2345mnmnmnmnmnmnmnmnmnmnmn", "zyxwvutsrqponmlkjihgfedcba"))
			again := Findings(f, in2.Observation)
			if !dngSameFindings(zeroAnswers(again), zeroAnswers(base)) {
				t.Fatalf("seed %d: another label changed%s\nto%s", seed, decShow(base), decShow(again))
			}
			if i := slices.IndexFunc(base, func(x Finding) bool { return x.Rule == RuleWildcard }); i >= 0 {
				in2.Open = []Finding{base[i]}
				if cs := dngOfRule(Decide(in2), RuleWildcard); len(cs) != 0 {
					t.Fatalf("seed %d: another label changed the alert:%s", seed, decShowChanges(cs))
				}
			}
			continue
		}

		// Other question names change only the questions that the Seen carry.
		q := o
		q.Answers = slices.Clone(o.Answers)
		for j := range q.Answers {
			q.Answers[j].Question = dnswire.Question{Name: decName(t, g.pick("zz.corp.test.", "a.b.c.", "edge.dnshost.test.")), Type: dnswire.Type(1 + g.rng.IntN(30)), Class: dnswire.ClassINET}
		}
		if got := Findings(f, q); !dngSameFindings(zeroQuestions(got), zeroQuestions(base)) {
			t.Fatalf("seed %d: the question names changed%s\nto%s", seed, decShow(base), decShow(got))
		}
	}
}

// ---- fuzz ----

func dngpCheckFile(t *testing.T, f *expect.File) {
	t.Helper()
	before := f.String()
	targets, wild := Targets(f), Wildcards(f)
	if !reflect.DeepEqual(targets, Targets(f)) || !reflect.DeepEqual(wild, Wildcards(f)) {
		t.Fatalf("a second call gave another result")
	}
	if f.String() != before {
		t.Fatalf("the file changed")
	}
	for i, tg := range targets {
		if tg.Name.LabelCount() == 0 {
			t.Fatalf("the root is a target")
		}
		if tg.Name.IsSubdomainOf(f.Domain) && f.Zone(tg.Name).Equal(f.Domain) {
			t.Fatalf("%v lies in the domain's own zone", tg.Name)
		}
		for _, o := range targets[:i] {
			if o.Name.Equal(tg.Name) {
				t.Fatalf("%v is twice a target", tg.Name)
			}
		}
		if len(tg.Refs) == 0 {
			t.Fatalf("%v has no ref", tg.Name)
		}
		for j, r := range tg.Refs {
			if !slices.Contains(dngpRules, r.Rule) || !strings.HasSuffix(r.Text, tg.Name.Lower().String()) {
				t.Fatalf("bad ref %+v of %v", r, tg.Name)
			}
			if slices.Contains(tg.Refs[:j], r) {
				t.Fatalf("ref %+v is twice in %v", r, tg.Name)
			}
		}
	}
	if got, want := dngpRenderOracle(dngpTargetsOf(f)), dngpRender(targets); !reflect.DeepEqual(got, want) {
		t.Fatalf("Targets gave %q, want %q", want, got)
	}
	if got, want := dngpNames(wild), dngpNames(dngpWildcardsOf(f)); !reflect.DeepEqual(got, want) {
		t.Fatalf("Wildcards gave %q, want %q", got, want)
	}
}

func FuzzTargets(f *testing.F) {
	for seed := range uint64(12) {
		g := &dngGen{t: f, rng: rand.New(rand.NewPCG(seed, 41))}
		if file := dngpMakeFile(g); file != nil {
			f.Add(file.String())
		}
	}
	for _, s := range []string{
		"domain corp.test.\ncorp.test. TXT \"v=spf1 include:a.dnshost.test\" \" -all\"\n",
		"domain corp.test.\ncorp.test. TXT \"v=spf1 include:%{d}\" | \"V=SPF1 -INCLUDE:B.test.\"\n",
		"domain corp.test.\ncorp.test. MX 0 .\n*.corp.test. A none\n*.*.corp.test. A none\n*. A none\n",
		"domain .\ncdn. CNAME .\n",
		"domain test.\ncorp.test. NS ns1.corp.test.\nx.corp.test. CNAME corp.test.\n",
		"",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, text string) {
		file, err := expect.Parse([]byte(text))
		if err != nil {
			return
		}
		dngpCheckFile(t, file)
	})
}
