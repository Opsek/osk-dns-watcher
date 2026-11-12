package expect

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// expSeed fixes every generated input, so that a failure can be run again.
const expSeed = 4242

// expHead puts a comment and a blank line before the domain line, so that a
// fault written after it is on line 4 and a parser that counts lines wrongly
// shows it.
const expHead = "# expectations of corp.test.\n\ndomain corp.test.\n"

func expName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("name %q: %v", s, err)
	}
	return n
}

// expRecord builds a record from the text of its data, as a zone file gives it.
func expRecord(t testing.TB, owner string, typ dnswire.Type, data string) dnswire.Record {
	t.Helper()
	d, err := dnswire.ParseRData(typ, data)
	if err != nil {
		t.Fatalf("%s data %q: %v", typ, data, err)
	}
	return dnswire.Record{Name: expName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: d}
}

// expShort keeps failure messages readable when the text is a large file.
func expShort(s string) string {
	if len(s) > 400 {
		return fmt.Sprintf("%q... (%d octets)", s[:400], len(s))
	}
	return fmt.Sprintf("%q", s)
}

func expParse(t testing.TB, text string) *File {
	t.Helper()
	f, err := Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%s): %v", expShort(text), err)
	}
	if f == nil {
		t.Fatalf("Parse(%s) gave neither a file nor an error", expShort(text))
	}
	return f
}

// expProblems returns the problems of a text that must not parse.
func expProblems(t testing.TB, text string) []Problem {
	t.Helper()
	_, err := Parse([]byte(text))
	if err == nil {
		t.Fatalf("Parse(%s) accepted it", expShort(text))
	}
	var e *Error
	if !errors.As(err, &e) || e == nil {
		t.Fatalf("Parse(%s) error %T %v; want a non-nil *Error", expShort(text), err, err)
	}
	return e.Problems
}

// expDataProblem is the problem text for record data that dnswire refuses,
// with the error text that dnswire itself gives.
func expDataProblem(t testing.TB, typ dnswire.Type, text string) string {
	t.Helper()
	_, err := dnswire.ParseRData(typ, text)
	if err == nil {
		t.Fatalf("%s data %q is valid", typ, text)
	}
	return "bad data: " + err.Error()
}

func expNameProblem(t testing.TB, text string) string {
	t.Helper()
	_, err := dnswire.ParseName(text)
	if err == nil {
		t.Fatalf("name %q is valid", text)
	}
	return fmt.Sprintf("bad name %q: %v", text, err)
}

func expLines(n int, line func(i int) string) string {
	var b strings.Builder
	for i := range n {
		b.WriteString(line(i) + "\n")
	}
	return b.String()
}

// expAddr4 is the i-th IPv4 address of 10.0.0.0/8, all distinct.
func expAddr4(i int) string {
	return fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255)
}

func expJoin(n int, sep string, item func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = item(i)
	}
	return strings.Join(parts, sep)
}

func TestFormString(t *testing.T) {
	for _, c := range []struct {
		form  Form
		value uint8
		word  string
	}{
		{FormSets, 1, "sets"},
		{FormRange, 2, "in"},
		{FormNames, 3, "like"},
		{FormNone, 4, "none"},
		{0, 0, "form0"},
		{5, 5, "form5"},
		{255, 255, "form255"},
	} {
		if uint8(c.form) != c.value || c.form.String() != c.word {
			t.Errorf("Form %d prints %q; want value %d, %q", uint8(c.form), c.form.String(), c.value, c.word)
		}
	}
}

func TestPatternMatches(t *testing.T) {
	for _, c := range []struct {
		name   string
		under  bool
		target string
		want   bool
	}{
		{"corp.test.", false, "corp.test.", true},
		{"corp.test.", false, "CORP.Test.", true},
		{"Corp.TEST.", false, "corp.test.", true},
		{"corp.test.", false, "www.corp.test.", false},
		{"corp.test.", false, "test.", false},
		{"corp.test.", false, "xcorp.test.", false},
		{"corp.test.", true, "www.corp.test.", true},
		{"corp.test.", true, "a.b.corp.test.", true},
		{"corp.test.", true, "WWW.CORP.TEST.", true},
		{"corp.test.", true, "corp.test.", false},
		{"corp.test.", true, "xcorp.test.", false},
		{"corp.test.", true, "test.", false},
		{"corp.test.", true, "www.shop.test.", false},
	} {
		p := Pattern{Name: expName(t, c.name), Under: c.under}
		if got := p.Matches(expName(t, c.target)); got != c.want {
			t.Errorf("Pattern{%s, Under %v}.Matches(%s) = %v; want %v", c.name, c.under, c.target, got, c.want)
		}
	}
}

func TestPatternString(t *testing.T) {
	for _, c := range []struct {
		name  string
		under bool
		want  string
	}{
		{"dnshost.test.", true, "*.dnshost.test."},
		{"ns1.corp.test.", false, "ns1.corp.test."},
	} {
		if got := (Pattern{Name: expName(t, c.name), Under: c.under}).String(); got != c.want {
			t.Errorf("Pattern{%s, Under %v}.String() = %q; want %q", c.name, c.under, got, c.want)
		}
	}
}

// expExample is the example file of the format, line for line.
const expExample = `# Lines that start with # (after blanks) are comments. Blank lines are ignored.
domain corp.test.
corp.test. NS ns1.corp.test. | ns2.corp.test.
corp.test. DS none
corp.test. MX 10 mail.corp.test.
corp.test. TXT "v=spf1 mx -all"
www.corp.test. A in 10.53.0.0/24
cdn.corp.test. CNAME like *.dnshost.test.
shop.test. A 10.53.0.84 | 10.53.0.85 || 10.53.0.86
_acme-challenge.corp.test. TXT none
`

// The canonical order is by owner in canonical name order, then by type
// number, so NS (2) comes before MX (15), TXT (16) and DS (43).
const expExampleCanonical = `domain corp.test.
corp.test. NS ns1.corp.test. | ns2.corp.test.
corp.test. MX 10 mail.corp.test.
corp.test. TXT "v=spf1 mx -all"
corp.test. DS none
_acme-challenge.corp.test. TXT none
cdn.corp.test. CNAME like *.dnshost.test.
www.corp.test. A in 10.53.0.0/24
shop.test. A 10.53.0.84 | 10.53.0.85 || 10.53.0.86
`

// expOctets gives the wire octets of each datum, for comparison.
func expOctets(alt []dnswire.RData) []string {
	var s []string
	for _, d := range alt {
		s = append(s, string(dnswire.AppendRData(nil, d)))
	}
	return s
}

func TestParseExampleFile(t *testing.T) {
	f := expParse(t, expExample)
	if !f.Domain.Equal(expName(t, "corp.test.")) {
		t.Errorf("Domain %v; want corp.test.", f.Domain)
	}
	want := []struct {
		line  int
		owner string
		typ   dnswire.Type
		form  Form
	}{
		{3, "corp.test.", dnswire.TypeNS, FormSets},
		{5, "corp.test.", dnswire.TypeMX, FormSets},
		{6, "corp.test.", dnswire.TypeTXT, FormSets},
		{4, "corp.test.", dnswire.TypeDS, FormNone},
		{10, "_acme-challenge.corp.test.", dnswire.TypeTXT, FormNone},
		{8, "cdn.corp.test.", dnswire.TypeCNAME, FormNames},
		{7, "www.corp.test.", dnswire.TypeA, FormRange},
		{9, "shop.test.", dnswire.TypeA, FormSets},
	}
	if len(f.Expectations) != len(want) {
		t.Fatalf("%d expectations; want %d", len(f.Expectations), len(want))
	}
	for i, w := range want {
		e := f.Expectations[i]
		if e.Line != w.line || !e.Name.Equal(expName(t, w.owner)) || e.Type != w.typ || e.Form != w.form {
			t.Errorf("expectation %d: line %d %v %v %v; want line %d %s %v %v", i, e.Line, e.Name, e.Type, e.Form, w.line, w.owner, w.typ, w.form)
		}
	}

	ns := f.Expectations[0]
	wantNS := expOctets([]dnswire.RData{dnswire.NS{Host: expName(t, "ns1.corp.test.")}, dnswire.NS{Host: expName(t, "ns2.corp.test.")}})
	if len(ns.Sets) != 1 || !slices.Equal(expOctets(ns.Sets[0]), wantNS) {
		t.Errorf("NS Sets %v; want one alternative of ns1 and ns2", ns.Sets)
	}
	shop := f.Expectations[7]
	a := func(s string) dnswire.RData { return dnswire.A{Addr: netip.MustParseAddr(s)} }
	if len(shop.Sets) != 2 || !slices.Equal(expOctets(shop.Sets[0]), expOctets([]dnswire.RData{a("10.53.0.84"), a("10.53.0.85")})) ||
		!slices.Equal(expOctets(shop.Sets[1]), expOctets([]dnswire.RData{a("10.53.0.86")})) {
		t.Errorf("shop.test. Sets %v; want [[.84 .85] [.86]]", shop.Sets)
	}
	if www := f.Expectations[6]; !slices.Equal(www.Ranges, []netip.Prefix{netip.MustParsePrefix("10.53.0.0/24")}) {
		t.Errorf("www Ranges %v; want [10.53.0.0/24]", www.Ranges)
	}
	if cdn := f.Expectations[5]; len(cdn.Patterns) != 1 || !cdn.Patterns[0].Under || !cdn.Patterns[0].Name.Equal(expName(t, "dnshost.test.")) {
		t.Errorf("cdn Patterns %v; want [*.dnshost.test.]", cdn.Patterns)
	}
	if got := f.String(); got != expExampleCanonical {
		t.Errorf("String():\n%s\nwant:\n%s", got, expExampleCanonical)
	}
}

func TestCanonicalPrint(t *testing.T) {
	for _, c := range []struct {
		name string
		text string // after the domain line
		want string // after the domain line
	}{
		{"no expectation", "", ""},
		{"comments and blank lines are dropped", "# a\n\n  # b\nwww.corp.test. A 10.0.0.1\n\t\n", "www.corp.test. A 10.0.0.1\n"},
		{"records by wire octets", "www.corp.test. A 10.0.0.10 | 10.0.0.2\n", "www.corp.test. A 10.0.0.2 | 10.0.0.10\n"},
		{"TXT by wire octets, length first", "corp.test. TXT \"aa\" | \"b\"\n", "corp.test. TXT \"b\" | \"aa\"\n"},
		{"MX by wire octets", "corp.test. MX 20 a.corp.test. | 10 b.corp.test.\n", "corp.test. MX 10 b.corp.test. | 20 a.corp.test.\n"},
		{"CAA tags none, or and in", "corp.test. CAA 0 none \"x\" | 0 or \"y\" | 0 in \"z\"\n", "corp.test. CAA 0 in \"z\" | 0 or \"y\" | 0 none \"x\"\n"},
		{"duplicate records dropped", "www.corp.test. A 10.0.0.1 | 10.0.0.1\n", "www.corp.test. A 10.0.0.1\n"},
		{"names in data lowered, then duplicates dropped", "corp.test. NS NS1.Corp.Test. | ns1.corp.test.\n", "corp.test. NS ns1.corp.test.\n"},
		{"SOA names lowered", "corp.test. SOA NS1.Corp.Test. Host.Corp.Test. 1 2 3 4 5\n", "corp.test. SOA ns1.corp.test. host.corp.test. 1 2 3 4 5\n"},
		{"NSEC next name keeps its case", "corp.test. NSEC Next.Corp.Test. A NS\n", "corp.test. NSEC Next.Corp.Test. A NS\n"},
		{"TXT keeps its case", "corp.test. TXT \"ABC\"\n", "corp.test. TXT \"ABC\"\n"},
		{"alternatives sorted", "shop.test. A 10.0.0.3 || 10.0.0.2 | 10.0.0.1\n", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3\n"},
		{"duplicate alternatives dropped", "shop.test. A 10.0.0.2 | 10.0.0.1 || 10.0.0.1 | 10.0.0.2\n", "shop.test. A 10.0.0.1 | 10.0.0.2\n"},
		{"prefixes by address", "www.corp.test. A in 10.0.0.0/8 9.0.0.0/8\n", "www.corp.test. A in 9.0.0.0/8 10.0.0.0/8\n"},
		{"prefixes by length", "www.corp.test. A in 10.0.0.0/16 10.0.0.0/8\n", "www.corp.test. A in 10.0.0.0/8 10.0.0.0/16\n"},
		{"duplicate prefixes dropped", "www.corp.test. A in 10.0.0.0/8 10.0.0.0/8\n", "www.corp.test. A in 10.0.0.0/8\n"},
		{"IPv6 prefixes", "www.corp.test. AAAA in 2001:DB8:1::/48 2001:db8::/32\n", "www.corp.test. AAAA in 2001:db8::/32 2001:db8:1::/48\n"},
		{"patterns by name", "cdn.corp.test. CNAME like b.test. a.test.\n", "cdn.corp.test. CNAME like a.test. b.test.\n"},
		{"exact pattern before the wildcard", "cdn.corp.test. CNAME like *.a.test. a.test.\n", "cdn.corp.test. CNAME like a.test. *.a.test.\n"},
		{"duplicate patterns dropped", "cdn.corp.test. CNAME like A.Test. a.test. *.a.test. *.A.TEST.\n", "cdn.corp.test. CNAME like a.test. *.a.test.\n"},
		{"lines by owner in canonical order", "a.b.test. A none\nb.a.test. A none\n", "b.a.test. A none\na.b.test. A none\n"},
		{"parent before child", "www.corp.test. A none\ncorp.test. A none\n", "corp.test. A none\nwww.corp.test. A none\n"},
		{"lines by type number", "corp.test. CAA none\ncorp.test. AAAA none\ncorp.test. TXT none\ncorp.test. MX none\ncorp.test. A none\n",
			"corp.test. A none\ncorp.test. MX none\ncorp.test. TXT none\ncorp.test. AAAA none\ncorp.test. CAA none\n"},
		{"type in any case or as TYPE<n>", "www.corp.test. type1 10.0.0.1\ncorp.test. mx 10 mail.corp.test.\n", "corp.test. MX 10 mail.corp.test.\nwww.corp.test. A 10.0.0.1\n"},
		{"names lowered", "WWW.Corp.Test. A none\n", "www.corp.test. A none\n"},
		{"bar in an owner", `a\|b.corp.test. A 10.0.0.1` + "\n", `a\|b.corp.test. A 10.0.0.1` + "\n"},
		{"bar in an owner written as a number", `a\124b.corp.test. A 10.0.0.1` + "\n", `a\|b.corp.test. A 10.0.0.1` + "\n"},
		{"bar in a name in data", `corp.test. NS ns\|1.corp.test. | ns2.corp.test.` + "\n", `corp.test. NS ns2.corp.test. | ns\|1.corp.test.` + "\n"},
		{"backslash, then bar, in a name in data", `corp.test. NS a\\\|b.corp.test.` + "\n", `corp.test. NS a\\\|b.corp.test.` + "\n"},
		{"kept backslash, then a separator", `corp.test. NS a\\|b.corp.test.` + "\n", `corp.test. NS b.corp.test. | a\\.` + "\n"},
		{"name in data without its trailing dot", "corp.test. NS ns1.corp.test\n", "corp.test. NS ns1.corp.test.\n"},
		{"bars inside TXT quotes stay as they are", `corp.test. TXT "a|b" | "c||d|||e"` + "\n", `corp.test. TXT "a|b" | "c||d|||e"` + "\n"},
		{"quote and bar inside TXT quotes", `corp.test. TXT "x\"|y" | "#z"` + "\n", `corp.test. TXT "#z" | "x\"|y"` + "\n"},
		{"owner that starts with #", `\#x.corp.test. A 10.0.0.1` + "\n", `\#x.corp.test. A 10.0.0.1` + "\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			text := "domain corp.test.\n" + c.text
			want := "domain corp.test.\n" + c.want
			f := expParse(t, text)
			if got := f.String(); got != want {
				t.Errorf("String() of %q:\n%q\nwant\n%q", text, got, want)
			}
			if g := expParse(t, want); g.String() != want {
				t.Errorf("the canonical text %q prints as %q", want, g.String())
			}
		})
	}
}

// Names print in lower case, the name of the domain line too.
func TestCanonicalDomainLowered(t *testing.T) {
	if got, want := expParse(t, "domain CORP.Test.\n").String(), "domain corp.test.\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

// Alternatives compare as lists of record octets, in order, so a list that
// begins another one comes first.
func TestCanonicalAlternativePrefixFirst(t *testing.T) {
	f := expParse(t, "domain corp.test.\nshop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.1\n")
	if got, want := f.String(), "domain corp.test.\nshop.test. A 10.0.0.1 || 10.0.0.1 | 10.0.0.2\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

// Patterns sort by name in canonical name order, as owners do.
func TestCanonicalPatternsInNameOrder(t *testing.T) {
	f := expParse(t, "domain corp.test.\ncdn.corp.test. CNAME like a.b.test. b.a.test.\n")
	if got, want := f.String(), "domain corp.test.\ncdn.corp.test. CNAME like b.a.test. a.b.test.\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

// A | in any name is written \|: in the domain line and in patterns too.
func TestCanonicalBarInDomainAndPattern(t *testing.T) {
	text := `domain a\|b.test.` + "\n" + `cdn.a\|b.test. CNAME like x\|y.test. *.x\|z.test.` + "\n"
	if got := expParse(t, text).String(); got != text {
		t.Errorf("String() = %q; want %q", got, text)
	}
}

func TestParseBlanks(t *testing.T) {
	const want = "domain corp.test.\nshop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3\n"
	for _, c := range []struct {
		name string
		text string
	}{
		{"tabs and runs of blanks between fields", "domain\t corp.test.\nshop.test.\t\tA  10.0.0.1 | 10.0.0.2 || 10.0.0.3\n"},
		{"no blanks around separators", "domain corp.test.\nshop.test. A 10.0.0.1|10.0.0.2||10.0.0.3\n"},
		{"blanks around separators", "domain corp.test.\nshop.test. A 10.0.0.1 \t|\t 10.0.0.2\t||  10.0.0.3\n"},
		{"blanks at the end of lines", "domain corp.test. \t\nshop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3  \t\n"},
		{"blank lines and indented comments", "\n  \n\t\n  # note\n\t# note\ndomain corp.test.\n \n\t #\nshop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3\n\n"},
		{"blanks before the owner", "domain corp.test.\n  \tshop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := expParse(t, c.text).String(); got != want {
				t.Errorf("String() of %q = %q; want %q", c.text, got, want)
			}
		})
	}
}

func TestParseProblems(t *testing.T) {
	seventeen := expJoin(17, " || ", func(i int) string { return expAddr4(i) })
	recs1001 := expJoin(1001, " | ", expAddr4)
	prefixes65 := expJoin(65, " ", func(i int) string { return fmt.Sprintf("10.%d.0.0/16", i) })
	patterns65 := expJoin(65, " ", func(i int) string { return fmt.Sprintf("h%d.test.", i) })
	long := strings.Repeat("x", 64) + ".corp.test."
	for _, c := range []struct {
		name string
		text string
		want Problem
		// only: the problem is the whole list. Else other problems may
		// follow from the same fault, and the list need only hold it.
		only bool
	}{
		{"empty file", "", Problem{0, "no domain line"}, true},
		{"only comments and blank lines", "# a\n\n  \t\n", Problem{0, "no domain line"}, true},
		{"octet above ASCII in a comment", expHead + "# caf\xe9\n", Problem{4, "octet 0xE9 is not printable ASCII"}, true},
		{"DEL in a comment", expHead + "# del\x7f\n", Problem{4, "octet 0x7F is not printable ASCII"}, true},
		{"control octet in a comment", expHead + "# bell\x07\n", Problem{4, "octet 0x07 is not printable ASCII"}, true},
		{"carriage return", expHead + "www.corp.test. A 10.0.0.1\r\n", Problem{4, "octet 0x0D is not printable ASCII"}, false},
		{"zero octet in the domain line", "# c\n\ndomain corp.test.\x00\n", Problem{3, "octet 0x00 is not printable ASCII"}, false},
		{"domain line without a name", "# c\n\ndomain\n", Problem{3, "a domain line takes one name"}, false},
		{"domain line with two names", "# c\n\ndomain corp.test. shop.test.\n", Problem{3, "a domain line takes one name"}, false},
		{"second domain line", expHead + "domain corp.test.\n", Problem{4, "domain already given on line 3"}, true},
		{"domain without a trailing dot", "# c\n\ndomain corp.test\n", Problem{3, `"corp.test" has no trailing dot`}, false},
		{"domain that is no name", "# c\n\ndomain a..b.\n", Problem{3, expNameProblem(t, "a..b.")}, false},
		{"owner alone", expHead + "www.corp.test.\n", Problem{4, "want <owner> <type> <form>"}, true},
		{"owner and type without a form", expHead + "www.corp.test. A\n", Problem{4, "want <owner> <type> <form>"}, true},
		{"owner without a trailing dot", expHead + "www A 10.0.0.1\n", Problem{4, `"www" has no trailing dot`}, true},
		{"owner with an empty label", expHead + "a..b.corp.test. A 10.0.0.1\n", Problem{4, expNameProblem(t, "a..b.corp.test.")}, true},
		{"owner with a label of 64 octets", expHead + long + " A 10.0.0.1\n", Problem{4, expNameProblem(t, long)}, true},
		{"TTL field", expHead + "www.corp.test. 300 A 10.0.0.1\n", Problem{4, `"300" is not a type; the file has no TTL or class field`}, true},
		{"class field", expHead + "www.corp.test. IN A 10.0.0.1\n", Problem{4, `"IN" is not a type; the file has no TTL or class field`}, true},
		{"type OPT", expHead + "www.corp.test. OPT none\n", Problem{4, "type OPT cannot be checked"}, true},
		{"type TSIG", expHead + "www.corp.test. TSIG none\n", Problem{4, "type TSIG cannot be checked"}, true},
		{"type AXFR", expHead + "www.corp.test. AXFR none\n", Problem{4, "type AXFR cannot be checked"}, true},
		{"type IXFR", expHead + "www.corp.test. IXFR none\n", Problem{4, "type IXFR cannot be checked"}, true},
		{"type ANY in lower case", expHead + "www.corp.test. any none\n", Problem{4, "type ANY cannot be checked"}, true},
		{"type NXNAME", expHead + "www.corp.test. TYPE128 none\n", Problem{4, "type TYPE128 cannot be checked"}, true},
		{"type 0", expHead + "www.corp.test. TYPE0 none\n", Problem{4, "type TYPE0 cannot be checked"}, true},
		{"DS below the domain", expHead + "www.corp.test. DS none\n", Problem{4, "a DS set is checked only at the domain"}, true},
		{"DS outside the domain", expHead + "shop.test. DS none\n", Problem{4, "a DS set is checked only at the domain"}, true},
		{"same set twice", expHead + "www.corp.test. A 10.0.0.1\nwww.corp.test. A 10.0.0.2\n", Problem{5, "www.corp.test. A is already expected on line 4"}, true},
		{"same set twice in other forms", expHead + "www.corp.test. A none\nwww.corp.test. A in 10.0.0.0/8\n", Problem{5, "www.corp.test. A is already expected on line 4"}, true},
		{"field after none", expHead + "www.corp.test. A none 10.0.0.1\n", Problem{4, `"none" takes no more fields`}, true},
		{"in for TXT", expHead + "corp.test. TXT in 10.0.0.0/8\n", Problem{4, "in is for A and AAAA only"}, true},
		{"prefix without a length", expHead + "www.corp.test. A in 10.0.0.0\n", Problem{4, `bad prefix "10.0.0.0"`}, true},
		{"prefix that is no address", expHead + "www.corp.test. A in ten/8\n", Problem{4, `bad prefix "ten/8"`}, true},
		{"prefix length too long", expHead + "www.corp.test. A in 10.0.0.0/33\n", Problem{4, `bad prefix "10.0.0.0/33"`}, true},
		{"IPv4 prefix with bits after its length", expHead + "www.corp.test. A in 10.1.2.3/8\n", Problem{4, "prefix 10.1.2.3/8 has bits after its length; write 10.0.0.0/8"}, true},
		{"IPv6 prefix with bits after its length", expHead + "www.corp.test. AAAA in 2001:db8::1/32\n", Problem{4, "prefix 2001:db8::1/32 has bits after its length; write 2001:db8::/32"}, true},
		{"IPv6 prefix for A", expHead + "www.corp.test. A in 2001:db8::/32\n", Problem{4, "prefix 2001:db8::/32 is not IPv4"}, true},
		{"IPv4 prefix for AAAA", expHead + "www.corp.test. AAAA in 10.0.0.0/8\n", Problem{4, "prefix 10.0.0.0/8 is not IPv6"}, true},
		{"like for A", expHead + "www.corp.test. A like web.corp.test.\n", Problem{4, "like is for NS, CNAME, DNAME and MX only"}, true},
		{"pattern without a trailing dot", expHead + "cdn.corp.test. CNAME like dnshost.test\n", Problem{4, `"dnshost.test" has no trailing dot`}, true},
		{"pattern with an empty label", expHead + "cdn.corp.test. CNAME like a..dnshost.test.\n", Problem{4, expNameProblem(t, "a..dnshost.test.")}, true},
		{"pattern under the root", expHead + "cdn.corp.test. CNAME like *.\n", Problem{4, `bad pattern "*."`}, true},
		{"pattern with a literal star", expHead + `cdn.corp.test. CNAME like \*.dnshost.test.` + "\n", Problem{4, fmt.Sprintf("bad pattern %q", `\*.dnshost.test.`)}, true},
		{"separator at the end", expHead + "www.corp.test. A 10.0.0.1 |\n", Problem{4, "an empty record"}, true},
		{"separator at the end, no blank", expHead + "www.corp.test. A 10.0.0.1|\n", Problem{4, "an empty record"}, true},
		{"separator at the start", expHead + "www.corp.test. A | 10.0.0.1\n", Problem{4, "an empty record"}, true},
		{"two separators", expHead + "www.corp.test. A 10.0.0.1 | | 10.0.0.2\n", Problem{4, "an empty record"}, true},
		{"alternative separator at the end", expHead + "www.corp.test. A 10.0.0.1 ||\n", Problem{4, "an empty record"}, true},
		{"alternative separator at the start", expHead + "www.corp.test. A || 10.0.0.1\n", Problem{4, "an empty record"}, true},
		{"alternative, then record separator", expHead + "www.corp.test. A 10.0.0.1 || | 10.0.0.2\n", Problem{4, "an empty record"}, true},
		{"record, then alternative separator", expHead + "www.corp.test. A 10.0.0.1 | || 10.0.0.2\n", Problem{4, "an empty record"}, true},
		{"bad data", expHead + "www.corp.test. A 10.0.0\n", Problem{4, expDataProblem(t, dnswire.TypeA, "10.0.0")}, true},
		{"bad data in a later alternative", expHead + "www.corp.test. A 10.0.0.1 || 10.0.0.256\n", Problem{4, expDataProblem(t, dnswire.TypeA, "10.0.0.256")}, true},
		{"TXT without quotes", expHead + "corp.test. TXT v=spf1\n", Problem{4, expDataProblem(t, dnswire.TypeTXT, "v=spf1")}, true},
		{"keyword none in upper case is data", expHead + "www.corp.test. A NONE\n", Problem{4, expDataProblem(t, dnswire.TypeA, "NONE")}, true},
		{"keyword in in upper case is data", expHead + "www.corp.test. A IN 10.0.0.0/8\n", Problem{4, expDataProblem(t, dnswire.TypeA, "IN 10.0.0.0/8")}, true},
		{"comment at the end of a line is data", expHead + "www.corp.test. A 10.0.0.1 # web\n", Problem{4, expDataProblem(t, dnswire.TypeA, "10.0.0.1 # web")}, true},
		{"17 alternatives", expHead + "www.corp.test. A " + seventeen + "\n", Problem{4, "more than 16 alternatives"}, true},
		{"1001 records in one set", expHead + "www.corp.test. A " + recs1001 + "\n", Problem{4, "more than 1000 records in one set"}, true},
		{"65 prefixes", expHead + "www.corp.test. A in " + prefixes65 + "\n", Problem{4, "more than 64 prefixes or patterns"}, true},
		{"65 patterns", expHead + "cdn.corp.test. CNAME like " + patterns65 + "\n", Problem{4, "more than 64 prefixes or patterns"}, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := expProblems(t, c.text)
			if c.only && !slices.Equal(got, []Problem{c.want}) {
				t.Errorf("Parse(%s): problems %+v; want only %+v", expShort(c.text), got, c.want)
			}
			if !c.only && !slices.Contains(got, c.want) {
				t.Errorf("Parse(%s): problems %+v; want them to hold %+v", expShort(c.text), got, c.want)
			}
		})
	}
}

// The same set is the same name by Equal, whatever its case. The owner's
// form in the text is not fixed, so only the end of the text is checked.
func TestParseSameSetInOtherCase(t *testing.T) {
	got := expProblems(t, expHead+"www.corp.test. A 10.0.0.1\nWWW.Corp.TEST. A none\n")
	if len(got) != 1 || got[0].Line != 5 || !strings.HasSuffix(got[0].Text, " A is already expected on line 4") {
		t.Errorf("problems %+v; want one on line 5 that ends in \" A is already expected on line 4\"", got)
	}
}

// The same owner with another type is another set.
func TestParseSameOwnerOtherType(t *testing.T) {
	f := expParse(t, expHead+"www.corp.test. A none\nwww.corp.test. AAAA none\ncorp.test. DS none\nCORP.TEST. NS none\n")
	if len(f.Expectations) != 4 {
		t.Errorf("%d expectations; want 4", len(f.Expectations))
	}
}

// The problem stands on the domain line, which is the line out of place.
func TestParseDomainLineAfterExpectation(t *testing.T) {
	got := expProblems(t, "# c\n\nwww.corp.test. A 10.0.0.1\ndomain corp.test.\n")
	if want := (Problem{4, "the domain line must come before the expectations"}); !slices.Contains(got, want) {
		t.Errorf("problems %+v; want them to hold %+v", got, want)
	}
}

// The format gives no text for these faults, so only the line is checked.
func TestParseRefusedWithoutFixedText(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		line int
	}{
		{"root as the domain", "# c\n\ndomain .\n", 3},
		{"run of three bars", expHead + "www.corp.test. A 10.0.0.1 ||| 10.0.0.2\n", 4},
		{"run of four bars", expHead + "www.corp.test. A 10.0.0.1||||10.0.0.2\n", 4},
		{"in without a prefix", expHead + "www.corp.test. A in\n", 4},
		{"like without a pattern", expHead + "cdn.corp.test. CNAME like\n", 4},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := expProblems(t, c.text)
			if !slices.ContainsFunc(got, func(p Problem) bool { return p.Line == c.line }) {
				t.Errorf("problems %+v; want one on line %d", got, c.line)
			}
		})
	}
}

func TestParseGoesOnAfterAProblem(t *testing.T) {
	text := expHead + "www A 10.0.0.1\n# fine\nmail.corp.test. 300 A 10.0.0.2\nok.corp.test. A 10.0.0.3\nweb.corp.test. TXT in 10.0.0.0/8\n"
	want := []Problem{
		{4, `"www" has no trailing dot`},
		{6, `"300" is not a type; the file has no TTL or class field`},
		{8, "in is for A and AAAA only"},
	}
	if got := expProblems(t, text); !slices.Equal(got, want) {
		t.Errorf("problems %+v; want %+v", got, want)
	}
}

func TestParseKeepsTheFirst100Problems(t *testing.T) {
	text := "domain corp.test.\n" + expLines(150, func(i int) string { return fmt.Sprintf("h%d.corp.test. 300 A 10.0.0.1", i) })
	var want []Problem
	for line := 2; line <= 101; line++ {
		want = append(want, Problem{line, `"300" is not a type; the file has no TTL or class field`})
	}
	if got := expProblems(t, text); !slices.Equal(got, want) {
		t.Errorf("%d problems, lines %d to %d; want the 100 of lines 2 to 101", len(got), expFirstLine(got), expLastLine(got))
	}
}

func expFirstLine(ps []Problem) int {
	if len(ps) == 0 {
		return -1
	}
	return ps[0].Line
}

func expLastLine(ps []Problem) int {
	if len(ps) == 0 {
		return -1
	}
	return ps[len(ps)-1].Line
}

// expPadded is a valid file of exactly size octets: a domain line, then
// comment lines.
func expPadded(size int) string {
	var b strings.Builder
	b.WriteString("domain corp.test.\n")
	for b.Len() < size {
		n := min(64, size-b.Len())
		if n == 1 {
			b.WriteString("\n")
		} else {
			b.WriteString("#" + strings.Repeat("x", n-2) + "\n")
		}
	}
	return b.String()
}

func TestParseSizeLimit(t *testing.T) {
	if text := expPadded(4194304); len(text) == 4194304 {
		expParse(t, text)
	} else {
		t.Fatalf("test fault: %d octets", len(text))
	}
	got := expProblems(t, expPadded(4194305))
	if want := []Problem{{0, "the file is larger than 4194304 octets"}}; !slices.Equal(got, want) {
		t.Errorf("problems %+v; want %+v", got, want)
	}
}

func TestParseExpectationLimit(t *testing.T) {
	line := func(i int) string { return fmt.Sprintf("h%d.corp.test. A 10.0.0.1", i) }
	if f := expParse(t, "domain corp.test.\n"+expLines(10000, line)); len(f.Expectations) != 10000 {
		t.Errorf("%d expectations; want 10000", len(f.Expectations))
	}
	got := expProblems(t, "domain corp.test.\n"+expLines(10001, line))
	if want := []Problem{{0, "more than 10000 expectations"}}; !slices.Equal(got, want) {
		t.Errorf("problems %+v; want %+v", got, want)
	}
}

func TestParseLimitsAccepted(t *testing.T) {
	for _, c := range []struct {
		name string
		line string
		form Form
		n    func(e Expectation) int
		want int
	}{
		{"16 alternatives", "www.corp.test. A " + expJoin(16, " || ", expAddr4), FormSets, func(e Expectation) int { return len(e.Sets) }, 16},
		{"1000 records in one set", "www.corp.test. A " + expJoin(1000, " | ", expAddr4), FormSets, func(e Expectation) int { return len(e.Sets[0]) }, 1000},
		{"64 prefixes", "www.corp.test. A in " + expJoin(64, " ", func(i int) string { return fmt.Sprintf("10.%d.0.0/16", i) }), FormRange, func(e Expectation) int { return len(e.Ranges) }, 64},
		{"64 patterns", "cdn.corp.test. CNAME like " + expJoin(64, " ", func(i int) string { return fmt.Sprintf("h%d.test.", i) }), FormNames, func(e Expectation) int { return len(e.Patterns) }, 64},
	} {
		t.Run(c.name, func(t *testing.T) {
			f := expParse(t, "domain corp.test.\n"+c.line+"\n")
			if len(f.Expectations) != 1 || f.Expectations[0].Form != c.form {
				t.Fatalf("expectations %v; want one of form %v", f.Expectations, c.form)
			}
			if got := c.n(f.Expectations[0]); got != c.want {
				t.Errorf("%d; want %d", got, c.want)
			}
		})
	}
}

func TestErrorText(t *testing.T) {
	for _, c := range []struct {
		problems []Problem
		want     string
	}{
		{[]Problem{{3, "an empty record"}}, "line 3: an empty record"},
		{[]Problem{{0, "no domain line"}}, "file: no domain line"},
		{[]Problem{{0, "no domain line"}, {3, "an empty record"}, {9, `"www" has no trailing dot`}},
			`file: no domain line; line 3: an empty record; line 9: "www" has no trailing dot`},
	} {
		if got := (&Error{Problems: c.problems}).Error(); got != c.want {
			t.Errorf("Error() of %+v = %q; want %q", c.problems, got, c.want)
		}
	}
}

func TestFind(t *testing.T) {
	f := expParse(t, expExample)
	for _, c := range []struct {
		name string
		typ  dnswire.Type
		line int // 0: not found
	}{
		{"corp.test.", dnswire.TypeNS, 3},
		{"CORP.Test.", dnswire.TypeNS, 3},
		{"corp.test.", dnswire.TypeDS, 4},
		{"WWW.corp.test.", dnswire.TypeA, 7},
		{"shop.test.", dnswire.TypeA, 9},
		{"www.corp.test.", dnswire.TypeAAAA, 0},
		{"corp.test.", dnswire.TypeA, 0},
		{"nope.corp.test.", dnswire.TypeA, 0},
		{"corp.test.", dnswire.TypeCAA, 0},
	} {
		e, ok := f.Find(expName(t, c.name), c.typ)
		if ok != (c.line != 0) || ok && (e.Line != c.line || e.Type != c.typ || !e.Name.Equal(expName(t, c.name))) {
			t.Errorf("Find(%s, %v) = line %d %v %v, %v; want line %d", c.name, c.typ, e.Line, e.Name, e.Type, ok, c.line)
		}
	}
	if _, ok := expParse(t, "domain corp.test.\n").Find(expName(t, "corp.test."), dnswire.TypeNS); ok {
		t.Error("Find in a file without expectations found one")
	}
}

func TestFileZone(t *testing.T) {
	f := expParse(t, "domain Corp.Test.\n"+
		"corp.test. NS ns1.corp.test. | ns2.corp.test.\n"+
		"a.corp.test. NS ns.a.corp.test.\n"+
		"B.A.CORP.test. NS ns.b.a.corp.test.\n"+
		"n.corp.test. NS none\n"+
		"x.shop.test. NS ns.x.shop.test.\n")
	for _, c := range []struct{ name, want string }{
		{"corp.test.", "corp.test."},
		{"www.corp.test.", "corp.test."},
		{"a.corp.test.", "a.corp.test."},
		{"www.a.corp.test.", "a.corp.test."},
		// Nested NS lines: the deepest that holds the name wins.
		{"b.a.corp.test.", "b.a.corp.test."},
		{"www.b.a.corp.test.", "b.a.corp.test."},
		{"n.corp.test.", "corp.test."},
		{"www.n.corp.test.", "corp.test."},
		// The NS line of x.shop.test. lies outside the domain too.
		{"www.x.shop.test.", "corp.test."},
		{"shop.test.", "corp.test."},
		{"WWW.A.Corp.TEST.", "a.corp.test."},
		{"www.b.A.corp.test.", "b.a.corp.test."},
	} {
		if got := f.Zone(expName(t, c.name)); !got.Equal(expName(t, c.want)) {
			t.Errorf("Zone(%s) = %s; want %s", c.name, got, c.want)
		}
	}
}

func TestFormTextAndString(t *testing.T) {
	for _, c := range []struct {
		line     string
		formText string
		str      string
	}{
		{"corp.test. NS NS2.corp.test. | ns1.corp.test.", "ns1.corp.test. | ns2.corp.test.", "corp.test. NS ns1.corp.test. | ns2.corp.test."},
		{"shop.test. A 10.0.0.3 || 10.0.0.1 | 10.0.0.2", "10.0.0.1 | 10.0.0.2 || 10.0.0.3", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3"},
		{"WWW.corp.test. A in 10.53.0.0/24 10.0.0.0/8", "in 10.0.0.0/8 10.53.0.0/24", "www.corp.test. A in 10.0.0.0/8 10.53.0.0/24"},
		{"cdn.corp.test. CNAME like *.DNSHOST.test. a.test.", "like a.test. *.dnshost.test.", "cdn.corp.test. CNAME like a.test. *.dnshost.test."},
		{"_acme-challenge.corp.test. TXT none", "none", "_acme-challenge.corp.test. TXT none"},
		{`a\|b.corp.test. TXT "x|y"`, `"x|y"`, `a\|b.corp.test. TXT "x|y"`},
		{`\#x.corp.test. A none`, "none", `\#x.corp.test. A none`},
	} {
		f := expParse(t, "domain corp.test.\n"+c.line+"\n")
		if len(f.Expectations) != 1 {
			t.Errorf("%q gives %d expectations", c.line, len(f.Expectations))
			continue
		}
		e := f.Expectations[0]
		if got := e.FormText(); got != c.formText {
			t.Errorf("FormText of %q = %q; want %q", c.line, got, c.formText)
		}
		if got := e.String(); got != c.str {
			t.Errorf("String of %q = %q; want %q", c.line, got, c.str)
		}
	}
}

// An expectation built in code, not read from text, prints the same way.
func TestExpectationBuiltInCode(t *testing.T) {
	e := Expectation{Name: expName(t, "www.corp.test."), Type: dnswire.TypeA, Form: FormSets,
		Sets: [][]dnswire.RData{{dnswire.A{Addr: netip.MustParseAddr("10.0.0.1")}}}}
	if got := e.String(); got != "www.corp.test. A 10.0.0.1" {
		t.Errorf("String() = %q; want %q", got, "www.corp.test. A 10.0.0.1")
	}
	e = Expectation{Name: expName(t, "corp.test."), Type: dnswire.TypeDS, Form: FormNone}
	if got := e.String(); got != "corp.test. DS none" {
		t.Errorf("String() = %q; want %q", got, "corp.test. DS none")
	}
}

const (
	expKeepValid = "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\nwww.corp.test. A 10.53.0.81\n"
	// The change seen is marked as expected, and the edit breaks the file.
	expKeepBroken = "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\nwww.corp.test. A 10.53.0.99 |\n"
	expKeepOther  = "domain corp.test.\nwww.corp.test. A 10.53.0.99\n"
)

// expLast is the file in force before the new data comes.
func expLast(t *testing.T) *File { return expParse(t, expKeepValid) }

func TestKeep(t *testing.T) {
	t.Run("valid data without a last file gives the new file", func(t *testing.T) {
		f, err := Keep(nil, []byte(expKeepValid))
		if err != nil || f == nil {
			t.Fatalf("Keep(nil, valid) = %v, %v; want a file and nil", f, err)
		}
		if got := f.String(); got != expKeepValid {
			t.Errorf("the file prints %q; want %q", got, expKeepValid)
		}
	})
	t.Run("valid data replaces the last file", func(t *testing.T) {
		last := expLast(t)
		f, err := Keep(last, []byte(expKeepOther))
		if err != nil || f == nil || f == last {
			t.Fatalf("Keep(last, other valid) = %p, %v; want a new file and nil", f, err)
		}
		if got := f.String(); got != expKeepOther {
			t.Errorf("the new file prints %q; want %q", got, expKeepOther)
		}
	})
	t.Run("invalid data keeps the last file", func(t *testing.T) {
		last := expLast(t)
		f, err := Keep(last, []byte(expKeepBroken))
		if f != last {
			t.Errorf("Keep(last, broken) gave %p; want last, %p", f, last)
		}
		var e *Error
		if !errors.As(err, &e) || e == nil {
			t.Fatalf("Keep(last, broken) error %T %v; want a non-nil *Error", err, err)
		}
		if want := []Problem{{3, "an empty record"}}; !slices.Equal(e.Problems, want) {
			t.Errorf("problems %+v; want %+v", e.Problems, want)
		}
	})
	t.Run("invalid data without a last file gives no file", func(t *testing.T) {
		f, err := Keep(nil, []byte(expKeepBroken))
		if f != nil {
			t.Errorf("Keep(nil, broken) gave a file %v; want nil", f)
		}
		var e *Error
		if !errors.As(err, &e) || e == nil || len(e.Problems) == 0 {
			t.Errorf("Keep(nil, broken) error %T %v; want a *Error with problems", err, err)
		}
	})
}

// expSet builds records of one type, each with its own owner and TTL, which
// Match must not read.
func expSet(t testing.TB, typ dnswire.Type, data ...string) []dnswire.Record {
	t.Helper()
	var set []dnswire.Record
	for i, d := range data {
		r := expRecord(t, fmt.Sprintf("o%d.elsewhere.test.", i), typ, d)
		r.TTL = uint32(60 * (i + 1))
		set = append(set, r)
	}
	return set
}

func TestMatch(t *testing.T) {
	cname := func(target string) dnswire.Record { return expRecord(t, "x.test.", dnswire.TypeCNAME, target) }
	a := func(addr string) dnswire.Record { return expRecord(t, "x.test.", dnswire.TypeA, addr) }
	for _, c := range []struct {
		name string
		line string
		set  []dnswire.Record
		want bool
	}{
		{"exact: same set in another order", "corp.test. NS ns1.corp.test. | ns2.corp.test.", expSet(t, dnswire.TypeNS, "ns2.corp.test.", "ns1.corp.test."), true},
		{"exact: names in another case", "corp.test. NS ns1.corp.test. | ns2.corp.test.", expSet(t, dnswire.TypeNS, "NS1.CORP.TEST.", "ns2.Corp.Test."), true},
		{"exact: a duplicate", "corp.test. NS ns1.corp.test. | ns2.corp.test.", expSet(t, dnswire.TypeNS, "ns1.corp.test.", "ns1.corp.test.", "ns2.corp.test."), true},
		{"exact: one record missing", "corp.test. NS ns1.corp.test. | ns2.corp.test.", expSet(t, dnswire.TypeNS, "ns1.corp.test."), false},
		{"exact: one record more", "corp.test. NS ns1.corp.test. | ns2.corp.test.", expSet(t, dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test."), false},
		{"exact: empty set", "corp.test. NS ns1.corp.test. | ns2.corp.test.", nil, false},
		{"exact: same name, other type", "corp.test. NS ns1.corp.test.", []dnswire.Record{cname("ns1.corp.test.")}, false},
		{"exact: second alternative", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3", expSet(t, dnswire.TypeA, "10.0.0.3"), true},
		{"exact: first alternative", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3", expSet(t, dnswire.TypeA, "10.0.0.2", "10.0.0.1"), true},
		{"exact: part of an alternative", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3", expSet(t, dnswire.TypeA, "10.0.0.1"), false},
		{"exact: union of alternatives", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3", expSet(t, dnswire.TypeA, "10.0.0.1", "10.0.0.2", "10.0.0.3"), false},
		{"exact: records of two alternatives", "shop.test. A 10.0.0.1 | 10.0.0.2 || 10.0.0.3", expSet(t, dnswire.TypeA, "10.0.0.2", "10.0.0.3"), false},
		{"exact: TXT keeps its case", `corp.test. TXT "v=spf1 mx -all"`, expSet(t, dnswire.TypeTXT, `"V=SPF1 MX -ALL"`), false},
		{"exact: TXT", `corp.test. TXT "v=spf1 mx -all"`, expSet(t, dnswire.TypeTXT, `"v=spf1 mx -all"`), true},
		{"exact: NSEC next name keeps its case", "corp.test. NSEC next.corp.test. A", expSet(t, dnswire.TypeNSEC, "NEXT.corp.test. A"), false},
		{"range: inside", "www.corp.test. A in 10.0.0.0/8 192.168.0.0/16", expSet(t, dnswire.TypeA, "10.1.2.3"), true},
		{"range: each in some prefix", "www.corp.test. A in 10.0.0.0/8 192.168.0.0/16", expSet(t, dnswire.TypeA, "10.1.2.3", "192.168.1.1"), true},
		{"range: last address", "www.corp.test. A in 10.0.0.0/8 192.168.0.0/16", expSet(t, dnswire.TypeA, "10.255.255.255"), true},
		{"range: just before", "www.corp.test. A in 10.0.0.0/8 192.168.0.0/16", expSet(t, dnswire.TypeA, "9.255.255.255"), false},
		{"range: one outside", "www.corp.test. A in 10.0.0.0/8 192.168.0.0/16", expSet(t, dnswire.TypeA, "10.1.2.3", "11.0.0.1"), false},
		{"range: empty set", "www.corp.test. A in 10.0.0.0/8", nil, false},
		{"range: a CNAME", "www.corp.test. A in 10.0.0.0/8", []dnswire.Record{cname("web.corp.test.")}, false},
		{"range: an A record and a CNAME", "www.corp.test. A in 10.0.0.0/8", []dnswire.Record{a("10.0.0.1"), cname("web.corp.test.")}, false},
		{"range: IPv6 inside", "www.corp.test. AAAA in 2001:db8::/32", expSet(t, dnswire.TypeAAAA, "2001:db8::1"), true},
		{"range: IPv6 outside", "www.corp.test. AAAA in 2001:db8::/32", expSet(t, dnswire.TypeAAAA, "2001:db9::1"), false},
		{"range: an A record for AAAA", "www.corp.test. AAAA in ::/0", []dnswire.Record{a("10.0.0.1")}, false},
		{"pattern: under", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeCNAME, "a.dnshost.test."), true},
		{"pattern: deeper under", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeCNAME, "a.b.dnshost.test."), true},
		{"pattern: other case", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeCNAME, "A.DnsHost.TEST."), true},
		{"pattern: the name itself is not under it", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeCNAME, "dnshost.test."), false},
		{"pattern: label boundary", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeCNAME, "xdnshost.test."), false},
		{"pattern: empty set", "cdn.corp.test. CNAME like *.dnshost.test.", nil, false},
		{"pattern: an A record", "cdn.corp.test. CNAME like *.dnshost.test.", []dnswire.Record{a("10.0.0.1")}, false},
		{"pattern: each in some pattern", "corp.test. NS like ns1.corp.test. *.dnshost.test.", expSet(t, dnswire.TypeNS, "ns1.corp.test.", "ns9.dnshost.test."), true},
		{"pattern: one in none", "corp.test. NS like ns1.corp.test. *.dnshost.test.", expSet(t, dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test."), false},
		{"pattern: exact name only", "corp.test. NS like ns1.corp.test.", expSet(t, dnswire.TypeNS, "sub.ns1.corp.test."), false},
		{"pattern: MX exchange", "corp.test. MX like *.corp.test.", expSet(t, dnswire.TypeMX, "10 mail.corp.test."), true},
		{"pattern: MX exchange elsewhere", "corp.test. MX like *.corp.test.", expSet(t, dnswire.TypeMX, "10 mail.other.test."), false},
		{"pattern: an NS record whose host fits an MX pattern", "corp.test. MX like *.corp.test.", expSet(t, dnswire.TypeNS, "mail.corp.test."), false},
		{"pattern: a DNAME whose target fits a CNAME pattern", "cdn.corp.test. CNAME like *.dnshost.test.", expSet(t, dnswire.TypeDNAME, "a.dnshost.test."), false},
		{"range: an A record in an IPv4-mapped AAAA range", "www.corp.test. AAAA in ::ffff:0:0/96", []dnswire.Record{a("10.0.0.1")}, false},
		{"pattern: DNAME target", "old.corp.test. DNAME like new.corp.test.", expSet(t, dnswire.TypeDNAME, "NEW.corp.test."), true},
		{"pattern: DNAME target under", "old.corp.test. DNAME like new.corp.test.", expSet(t, dnswire.TypeDNAME, "x.new.corp.test."), false},
		{"none: empty set", "_acme-challenge.corp.test. TXT none", nil, true},
		{"none: a record", "_acme-challenge.corp.test. TXT none", expSet(t, dnswire.TypeTXT, `"token"`), false},
		{"none: a CNAME", "www.corp.test. A none", []dnswire.Record{cname("web.corp.test.")}, false},
	} {
		f := expParse(t, "domain corp.test.\n"+c.line+"\n")
		if len(f.Expectations) != 1 {
			t.Errorf("%s: %d expectations", c.name, len(f.Expectations))
			continue
		}
		if got := f.Expectations[0].Match(c.set); got != c.want {
			t.Errorf("%s: %q Match(%v) = %v; want %v", c.name, c.line, expRecordTexts(c.set), got, c.want)
		}
	}
}

func expRecordTexts(set []dnswire.Record) []string {
	var s []string
	for _, r := range set {
		s = append(s, r.Type().String()+" "+r.Data.String())
	}
	return s
}

func TestSetText(t *testing.T) {
	for _, c := range []struct {
		name string
		typ  dnswire.Type
		set  []dnswire.Record
		want string
	}{
		{"empty set", dnswire.TypeA, nil, "none"},
		{"sorted by wire octets", dnswire.TypeA, expSet(t, dnswire.TypeA, "10.0.0.10", "10.0.0.2"), "10.0.0.2 | 10.0.0.10"},
		{"names lowered", dnswire.TypeNS, expSet(t, dnswire.TypeNS, "NS2.Corp.Test.", "ns1.corp.test."), "ns1.corp.test. | ns2.corp.test."},
		{"TXT by wire octets", dnswire.TypeTXT, expSet(t, dnswire.TypeTXT, `"aa"`, `"b"`), `"b" | "aa"`},
		{"record of another type", dnswire.TypeA, []dnswire.Record{expRecord(t, "www.corp.test.", dnswire.TypeCNAME, "Web.DnsHost.Test.")}, "CNAME web.dnshost.test."},
		{"bar in a name, as the exact form writes it", dnswire.TypeNS, expSet(t, dnswire.TypeNS, `ns\|1.corp.test.`), `ns\|1.corp.test.`},
		{"bar in TXT quotes", dnswire.TypeTXT, expSet(t, dnswire.TypeTXT, `"a|b"`), `"a|b"`},
	} {
		if got := SetText(c.typ, c.set); got != c.want {
			t.Errorf("%s: SetText(%v, %v) = %q; want %q", c.name, c.typ, expRecordTexts(c.set), got, c.want)
		}
	}
	// Owner, class and TTL are no part of the text.
	x := expRecord(t, "a.test.", dnswire.TypeA, "10.0.0.1")
	y := expRecord(t, "b.other.test.", dnswire.TypeA, "10.0.0.1")
	y.TTL, y.Class = 7, dnswire.ClassCHAOS
	if SetText(dnswire.TypeA, []dnswire.Record{x}) != SetText(dnswire.TypeA, []dnswire.Record{y}) {
		t.Error("SetText depends on owner, class or TTL")
	}
}

// --- generated inputs ---

// expHostileOctets are octets that a careless reader takes for syntax:
// separators, comment and wildcard signs, escapes, quotes, blanks, and
// octets outside printable ASCII, which names print as \DDD.
const expHostileOctets = "|#*,;\\\" \t.()@$-_ABCXYZ019\x00\x7f\x80\xff"

// expLabel is a label of 1 to 6 octets, half of them from octets.
func expLabel(rng *rand.Rand, octets string) string {
	b := make([]byte, 1+rng.IntN(6))
	for i := range b {
		if rng.IntN(2) == 0 {
			b[i] = octets[rng.IntN(len(octets))]
		} else {
			b[i] = byte('a' + rng.IntN(26))
		}
	}
	return string(b)
}

func expNameOf(labels ...string) dnswire.Name {
	n, err := dnswire.NameFromLabels(labels)
	if err != nil {
		panic(fmt.Sprintf("test fault: labels %q: %v", labels, err))
	}
	return n
}

// expHostileName is a name of 1 to 3 hostile labels under test.
func expHostileName(rng *rand.Rand) dnswire.Name {
	var labels []string
	for range 1 + rng.IntN(3) {
		labels = append(labels, expLabel(rng, expHostileOctets))
	}
	return expNameOf(append(labels, "test")...)
}

// expPlainOctets leave out the bar, which a domain and a pattern do not get
// here (see TestCanonicalBarInDomainAndPattern), and keep the rest.
const expPlainOctets = "#*,;\\\" \t.()@$-_ABCXYZ019\x00\x7f\x80\xff"

// expPlainLabel is a hostile label without a bar that does not start with #
// and is not a lone *, so that it can lead a domain or a pattern.
func expPlainLabel(rng *rand.Rand) string {
	l := []byte(expLabel(rng, expPlainOctets))
	if l[0] == '#' {
		l[0] = 'h'
	}
	if string(l) == "*" {
		l[0] = 's'
	}
	return string(l)
}

func expRandomBytes(rng *rand.Rand, lo, hi int) []byte {
	b := make([]byte, lo+rng.IntN(hi-lo+1))
	for i := range b {
		b[i] = byte(rng.Uint32())
	}
	if len(b) == 0 {
		return nil
	}
	return b
}

func expRandom4(rng *rand.Rand) netip.Addr {
	return netip.AddrFrom4([4]byte(expRandomBytes(rng, 4, 4)))
}

func expRandom6(rng *rand.Rand) netip.Addr {
	if rng.IntN(5) == 0 {
		return netip.AddrFrom16(expRandom4(rng).As16())
	}
	return netip.AddrFrom16([16]byte(expRandomBytes(rng, 16, 16)))
}

// expHostileString is TXT or CAA octets with bars, runs of bars, comment
// signs, backslashes, quotes and blanks.
func expHostileString(rng *rand.Rand) string {
	const octets = "|#\\\" \tabcXYZ\x00\x7f\x80\xff"
	var b []byte
	for range rng.IntN(10) {
		if rng.IntN(6) == 0 {
			b = append(b, "|||"[:1+rng.IntN(3)]...)
			continue
		}
		b = append(b, octets[rng.IntN(len(octets))])
	}
	return string(b)
}

func expTypes(rng *rand.Rand) []dnswire.Type {
	pool := []dnswire.Type{1, 2, 5, 6, 15, 16, 28, 46, 47, 50, 128, 257, 65280}
	var ts []dnswire.Type
	for _, t := range pool {
		if rng.IntN(3) == 0 {
			ts = append(ts, t)
		}
	}
	return ts
}

// expSRV is SRV data, a type that dnswire keeps as Unknown although its data
// holds a name, which the canonical form lowers.
func expSRV(rng *rand.Rand) dnswire.RData {
	data := expRandomBytes(rng, 6, 6)
	return dnswire.Unknown{TypeCode: 33, Data: expHostileName(rng).AppendWire(data)}
}

// expDataTypes are the types the generators make: every type that dnswire
// reads as typed data, and three that it keeps as Unknown.
var expDataTypes = []dnswire.Type{
	dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeNS, dnswire.TypeCNAME, dnswire.TypeDNAME, dnswire.TypePTR,
	dnswire.TypeSOA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeSPF, dnswire.TypeCAA, dnswire.TypeDS,
	dnswire.TypeDNSKEY, dnswire.TypeRRSIG, dnswire.TypeNSEC, dnswire.TypeNSEC3, dnswire.TypeNSEC3PARAM,
	13, 33, 65280,
}

var expGenerators = map[dnswire.Type]func(*rand.Rand) dnswire.RData{
	dnswire.TypeA:     func(r *rand.Rand) dnswire.RData { return dnswire.A{Addr: expRandom4(r)} },
	dnswire.TypeAAAA:  func(r *rand.Rand) dnswire.RData { return dnswire.AAAA{Addr: expRandom6(r)} },
	dnswire.TypeNS:    func(r *rand.Rand) dnswire.RData { return dnswire.NS{Host: expHostileName(r)} },
	dnswire.TypeCNAME: func(r *rand.Rand) dnswire.RData { return dnswire.CNAME{Target: expHostileName(r)} },
	dnswire.TypeDNAME: func(r *rand.Rand) dnswire.RData { return dnswire.DNAME{Target: expHostileName(r)} },
	dnswire.TypePTR:   func(r *rand.Rand) dnswire.RData { return dnswire.PTR{Target: expHostileName(r)} },
	dnswire.TypeSOA: func(r *rand.Rand) dnswire.RData {
		return dnswire.SOA{MName: expHostileName(r), RName: expHostileName(r), Serial: r.Uint32(),
			Refresh: r.Uint32(), Retry: r.Uint32(), Expire: r.Uint32(), Minimum: r.Uint32()}
	},
	dnswire.TypeMX: func(r *rand.Rand) dnswire.RData {
		return dnswire.MX{Preference: uint16(r.IntN(50)), Exchange: expHostileName(r)}
	},
	dnswire.TypeTXT: func(r *rand.Rand) dnswire.RData {
		var s []string
		for range 1 + r.IntN(3) {
			s = append(s, expHostileString(r))
		}
		return dnswire.TXT{Strings: s}
	},
	dnswire.TypeSPF: func(r *rand.Rand) dnswire.RData { return dnswire.SPF{Strings: []string{expHostileString(r)}} },
	dnswire.TypeCAA: func(r *rand.Rand) dnswire.RData {
		tags := []string{"issue", "iodef", "or", "in", "none", "like", "Ab9"}
		return dnswire.CAA{Flags: []uint8{0, 128, 7}[r.IntN(3)], Tag: tags[r.IntN(len(tags))], Value: expHostileString(r)}
	},
	dnswire.TypeDS: func(r *rand.Rand) dnswire.RData {
		lengths := map[uint8]int{1: 20, 2: 32, 4: 48, 9: 0}
		dt := []uint8{1, 2, 4, 9}[r.IntN(4)]
		n := lengths[dt]
		if n == 0 {
			n = 1 + r.IntN(12)
		}
		return dnswire.DS{KeyTag: uint16(r.Uint32()), Algorithm: uint8(r.Uint32()), DigestType: dt, Digest: expRandomBytes(r, n, n)}
	},
	dnswire.TypeDNSKEY: func(r *rand.Rand) dnswire.RData {
		return dnswire.DNSKEY{Flags: uint16(r.Uint32()), Protocol: 3, Algorithm: uint8(r.Uint32()), PublicKey: expRandomBytes(r, 1, 24)}
	},
	dnswire.TypeRRSIG: func(r *rand.Rand) dnswire.RData {
		return dnswire.RRSIG{TypeCovered: []dnswire.Type{1, 2, 16, 65280}[r.IntN(4)], Algorithm: uint8(r.Uint32()),
			Labels: uint8(r.IntN(5)), OriginalTTL: r.Uint32(), Expiration: r.Uint32(), Inception: r.Uint32(),
			KeyTag: uint16(r.Uint32()), SignerName: expHostileName(r), Signature: expRandomBytes(r, 1, 24)}
	},
	dnswire.TypeNSEC: func(r *rand.Rand) dnswire.RData {
		return dnswire.NSEC{NextName: expHostileName(r), Types: expTypes(r)}
	},
	dnswire.TypeNSEC3: func(r *rand.Rand) dnswire.RData {
		alg := uint8(1 + r.IntN(2))
		hash := expRandomBytes(r, 1, 24)
		if alg == 1 {
			hash = expRandomBytes(r, 20, 20)
		}
		return dnswire.NSEC3{HashAlgorithm: alg, Flags: uint8(r.IntN(2)), Iterations: uint16(r.IntN(20)),
			Salt: expRandomBytes(r, 0, 8), NextHashed: hash, Types: expTypes(r)}
	},
	dnswire.TypeNSEC3PARAM: func(r *rand.Rand) dnswire.RData {
		return dnswire.NSEC3PARAM{HashAlgorithm: 1, Flags: uint8(r.IntN(2)), Iterations: uint16(r.IntN(20)), Salt: expRandomBytes(r, 0, 8)}
	},
	13: func(r *rand.Rand) dnswire.RData { return dnswire.Unknown{TypeCode: 13, Data: expRandomBytes(r, 0, 10)} },
	33: expSRV,
	65280: func(r *rand.Rand) dnswire.RData {
		return dnswire.Unknown{TypeCode: 65280, Data: expRandomBytes(r, 0, 10)}
	},
}

// expData makes data of type typ and checks that dnswire reads its text
// back, so that a failure later blames the package under test, not the
// generator.
func expData(t testing.TB, rng *rand.Rand, typ dnswire.Type) dnswire.RData {
	t.Helper()
	d := expGenerators[typ](rng)
	p, err := dnswire.ParseRData(typ, d.String())
	if err != nil || !bytes.Equal(dnswire.AppendRData(nil, p), dnswire.AppendRData(nil, d)) {
		t.Fatalf("test fault: %v data %q does not read back: %v", typ, d.String(), err)
	}
	return d
}

func expFlipCase(rng *rand.Rand, n dnswire.Name) dnswire.Name {
	labels := n.Labels()
	for i, l := range labels {
		b := []byte(l)
		for j, c := range b {
			if rng.IntN(2) == 0 && ('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z') {
				b[j] = c ^ 0x20
			}
		}
		labels[i] = string(b)
	}
	return expNameOf(labels...)
}

// expFolders change the case of the names that the canonical form lowers,
// and only those: the next name of NSEC keeps its case.
var expFolders = map[dnswire.Type]func(*rand.Rand, dnswire.RData) dnswire.RData{
	dnswire.TypeNS: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.NS)
		x.Host = expFlipCase(r, x.Host)
		return x
	},
	dnswire.TypeCNAME: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.CNAME)
		x.Target = expFlipCase(r, x.Target)
		return x
	},
	dnswire.TypeDNAME: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.DNAME)
		x.Target = expFlipCase(r, x.Target)
		return x
	},
	dnswire.TypePTR: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.PTR)
		x.Target = expFlipCase(r, x.Target)
		return x
	},
	dnswire.TypeSOA: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.SOA)
		x.MName, x.RName = expFlipCase(r, x.MName), expFlipCase(r, x.RName)
		return x
	},
	dnswire.TypeMX: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.MX)
		x.Exchange = expFlipCase(r, x.Exchange)
		return x
	},
	dnswire.TypeRRSIG: func(r *rand.Rand, d dnswire.RData) dnswire.RData {
		x := d.(dnswire.RRSIG)
		x.SignerName = expFlipCase(r, x.SignerName)
		return x
	},
}

func expFoldCase(rng *rand.Rand, d dnswire.RData) dnswire.RData {
	if f, ok := expFolders[d.Type()]; ok {
		return f(rng, d)
	}
	return d
}

// --- the canonical print, written from the format's rules ---

// expEscapeBars writes each | outside double quotes as \|. A backslash
// keeps the next octet, inside quotes too, as in dnswire.ParseRData.
func expEscapeBars(s string, bar string) string {
	var b strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			b.WriteString(s[i : i+2])
			i++
		case c == '"':
			quoted = !quoted
			b.WriteByte(c)
		case c == '|' && !quoted:
			b.WriteString(bar)
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

func expNameText(n dnswire.Name) string { return expEscapeBars(n.Lower().String(), `\|`) }

func expOwnerText(n dnswire.Name) string {
	s := expNameText(n)
	if strings.HasPrefix(s, "#") {
		return `\` + s
	}
	return s
}

// expDatum is one record of an alternative: its canonical octets and text.
type expDatum struct {
	octets []byte
	text   string
}

func expCanonicalDatum(d dnswire.RData) expDatum {
	c := dnswire.Canonical(dnswire.Record{Data: d}).Data
	return expDatum{dnswire.AppendRData(nil, c), expEscapeBars(c.String(), `\|`)}
}

func expCompareAlts(a, b []expDatum) int {
	return slices.CompareFunc(a, b, func(x, y expDatum) int { return bytes.Compare(x.octets, y.octets) })
}

// expCanonicalAlts sorts records by canonical octets and alternatives by
// their lists of octets, and drops duplicates of both.
func expCanonicalAlts(alts [][]dnswire.RData) [][]expDatum {
	var out [][]expDatum
	for _, alt := range alts {
		var ds []expDatum
		for _, d := range alt {
			ds = append(ds, expCanonicalDatum(d))
		}
		slices.SortFunc(ds, func(a, b expDatum) int { return bytes.Compare(a.octets, b.octets) })
		out = append(out, slices.CompactFunc(ds, func(a, b expDatum) bool { return bytes.Equal(a.octets, b.octets) }))
	}
	slices.SortFunc(out, expCompareAlts)
	return slices.CompactFunc(out, func(a, b []expDatum) bool { return expCompareAlts(a, b) == 0 })
}

func expAltText(alt []expDatum) string {
	var s []string
	for _, d := range alt {
		s = append(s, d.text)
	}
	return strings.Join(s, " | ")
}

func expSortedPrefixes(ps []netip.Prefix) []netip.Prefix {
	ps = slices.Clone(ps)
	slices.SortFunc(ps, func(a, b netip.Prefix) int {
		if c := a.Addr().Compare(b.Addr()); c != 0 {
			return c
		}
		return a.Bits() - b.Bits()
	})
	return slices.Compact(ps)
}

func expSortedPatterns(ps []Pattern) []Pattern {
	ps = slices.Clone(ps)
	under := func(p Pattern) int {
		if p.Under {
			return 1
		}
		return 0
	}
	slices.SortFunc(ps, func(a, b Pattern) int {
		if c := dnswire.Compare(a.Name, b.Name); c != 0 {
			return c
		}
		return under(a) - under(b)
	})
	return slices.CompactFunc(ps, func(a, b Pattern) bool { return a.Name.Equal(b.Name) && a.Under == b.Under })
}

func expPatternText(p Pattern) string {
	if p.Under {
		return "*." + expNameText(p.Name)
	}
	return expNameText(p.Name)
}

// expModel is one expectation as a test means it, before any printing.
type expModel struct {
	owner    dnswire.Name
	typ      dnswire.Type
	form     Form
	alts     [][]dnswire.RData
	prefixes []netip.Prefix
	patterns []Pattern
}

func expCanonicalForm(m expModel) string {
	var parts []string
	if m.form == FormSets {
		for _, alt := range expCanonicalAlts(m.alts) {
			parts = append(parts, expAltText(alt))
		}
		return strings.Join(parts, " || ")
	}
	if m.form == FormRange {
		for _, p := range expSortedPrefixes(m.prefixes) {
			parts = append(parts, p.String())
		}
		return "in " + strings.Join(parts, " ")
	}
	if m.form == FormNames {
		for _, p := range expSortedPatterns(m.patterns) {
			parts = append(parts, expPatternText(p))
		}
		return "like " + strings.Join(parts, " ")
	}
	return "none"
}

func expCanonicalLine(m expModel) string {
	return expOwnerText(m.owner) + " " + m.typ.String() + " " + expCanonicalForm(m)
}

func expCanonicalFile(domain dnswire.Name, models []expModel) string {
	models = slices.Clone(models)
	slices.SortFunc(models, func(a, b expModel) int {
		if c := dnswire.Compare(a.owner, b.owner); c != 0 {
			return c
		}
		return int(a.typ) - int(b.typ)
	})
	var b strings.Builder
	b.WriteString("domain " + expNameText(domain) + "\n")
	for _, m := range models {
		b.WriteString(expCanonicalLine(m) + "\n")
	}
	return b.String()
}

// --- the oracle of Match, written from the format's formulas ---

// expKey is the key of a record: its type and its canonical data octets.
func expKey(r dnswire.Record) string {
	return r.Type().String() + "/" + string(dnswire.AppendRData(nil, dnswire.Canonical(r).Data))
}

func expKeys(set []dnswire.Record) map[string]bool {
	k := map[string]bool{}
	for _, r := range set {
		k[expKey(r)] = true
	}
	return k
}

func expSameKeys(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

func expLowerLabels(n dnswire.Name) []string {
	labels := n.Labels()
	for i, l := range labels {
		b := []byte(l)
		for j, c := range b {
			if 'A' <= c && c <= 'Z' {
				b[j] = c + 'a' - 'A'
			}
		}
		labels[i] = string(b)
	}
	return labels
}

// expPatternOracle: the name itself, or with Under any name strictly below it.
func expPatternOracle(p Pattern, target dnswire.Name) bool {
	pl, tl := expLowerLabels(p.Name), expLowerLabels(target)
	if !p.Under {
		return slices.Equal(pl, tl)
	}
	return len(tl) > len(pl) && slices.Equal(tl[len(tl)-len(pl):], pl)
}

var expTargets = map[dnswire.Type]func(dnswire.RData) dnswire.Name{
	dnswire.TypeNS:    func(d dnswire.RData) dnswire.Name { return d.(dnswire.NS).Host },
	dnswire.TypeCNAME: func(d dnswire.RData) dnswire.Name { return d.(dnswire.CNAME).Target },
	dnswire.TypeDNAME: func(d dnswire.RData) dnswire.Name { return d.(dnswire.DNAME).Target },
	dnswire.TypeMX:    func(d dnswire.RData) dnswire.Name { return d.(dnswire.MX).Exchange },
}

func expAddrOf(d dnswire.RData) netip.Addr {
	if a, ok := d.(dnswire.A); ok {
		return a.Addr
	}
	if a, ok := d.(dnswire.AAAA); ok {
		return a.Addr
	}
	return netip.Addr{}
}

func expOracle(m expModel, set []dnswire.Record) bool {
	if m.form == FormSets {
		k := expKeys(set)
		for _, alt := range m.alts {
			var recs []dnswire.Record
			for _, d := range alt {
				recs = append(recs, dnswire.Record{Data: d})
			}
			if expSameKeys(k, expKeys(recs)) {
				return true
			}
		}
		return false
	}
	if m.form == FormNone {
		return len(set) == 0
	}
	if len(set) == 0 {
		return false
	}
	for _, r := range set {
		if r.Type() != m.typ {
			return false
		}
		in := false
		if m.form == FormRange {
			in = slices.ContainsFunc(m.prefixes, func(p netip.Prefix) bool { return p.Contains(expAddrOf(r.Data)) })
		} else {
			target := expTargets[m.typ](r.Data)
			in = slices.ContainsFunc(m.patterns, func(p Pattern) bool { return expPatternOracle(p, target) })
		}
		if !in {
			return false
		}
	}
	return true
}

// --- TestFormsProperty ---

var (
	expPatternNames = []string{"a.test.", "b.a.test.", "x.b.a.test.", "c.test.", "test.", "dnshost.test."}
	expTargetNames  = []string{"a.test.", "b.a.test.", "q.b.a.test.", "x.b.a.test.", "y.x.b.a.test.", "c.test.", "d.c.test.",
		"e.test.", "test.", "xa.test.", "ba.test.", "ns1.dnshost.test.", "dnshost.test."}
	expNameTypes = []dnswire.Type{dnswire.TypeNS, dnswire.TypeCNAME, dnswire.TypeDNAME, dnswire.TypeMX}
)

func expPick[T any](rng *rand.Rand, s []T) T { return s[rng.IntN(len(s))] }

// expAlt makes 1 to 3 records of typ, distinct by key.
func expAlt(t testing.TB, rng *rand.Rand, typ dnswire.Type) []dnswire.RData {
	var alt []dnswire.RData
	seen := map[string]bool{}
	for range 1 + rng.IntN(3) {
		d := expData(t, rng, typ)
		if k := expKey(dnswire.Record{Data: d}); !seen[k] {
			seen[k] = true
			alt = append(alt, d)
		}
	}
	return alt
}

func expRandomPrefix(rng *rand.Rand, typ dnswire.Type) netip.Prefix {
	if typ == dnswire.TypeA {
		return netip.PrefixFrom(expRandom4(rng), 8+rng.IntN(25)).Masked()
	}
	return netip.PrefixFrom(expRandom6(rng), 16+rng.IntN(113)).Masked()
}

func expFormsModel(t testing.TB, rng *rand.Rand) expModel {
	m := expModel{owner: expName(t, "x.corp.test."), form: Form(1 + rng.IntN(4))}
	if m.form == FormSets || m.form == FormNone {
		m.typ = expPick(rng, expDataTypes)
	}
	if m.form == FormRange {
		m.typ = expPick(rng, []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA})
		for range 1 + rng.IntN(3) {
			m.prefixes = append(m.prefixes, expRandomPrefix(rng, m.typ))
		}
	}
	if m.form == FormNames {
		m.typ = expPick(rng, expNameTypes)
		for range 1 + rng.IntN(3) {
			m.patterns = append(m.patterns, Pattern{Name: expFlipCase(rng, expName(t, expPick(rng, expPatternNames))), Under: rng.IntN(2) == 0})
		}
	}
	if m.form == FormSets {
		for range 1 + rng.IntN(3) {
			m.alts = append(m.alts, expAlt(t, rng, m.typ))
		}
	}
	if m.typ == dnswire.TypeDS {
		m.owner = expName(t, "corp.test.")
	}
	return m
}

func expRec(d dnswire.RData) dnswire.Record {
	return dnswire.Record{Name: expNameOf("o", "test"), Class: dnswire.ClassINET, TTL: 300, Data: d}
}

func expNamed(typ dnswire.Type, target dnswire.Name) dnswire.RData {
	return map[dnswire.Type]dnswire.RData{
		dnswire.TypeNS:    dnswire.NS{Host: target},
		dnswire.TypeCNAME: dnswire.CNAME{Target: target},
		dnswire.TypeDNAME: dnswire.DNAME{Target: target},
		dnswire.TypeMX:    dnswire.MX{Preference: 10, Exchange: target},
	}[typ]
}

// expOtherType is data of another type than typ, so a set that holds it
// matches no form but none.
func expOtherType(t testing.TB, rng *rand.Rand, typ dnswire.Type) dnswire.RData {
	for {
		if o := expPick(rng, expDataTypes); o != typ {
			return expData(t, rng, o)
		}
	}
}

// expDeriveSet makes a set from the model, near enough to it that both
// outcomes of Match come up often.
func expDeriveSet(t testing.TB, rng *rand.Rand, m expModel) []dnswire.Record {
	var set []dnswire.Record
	add := func(d dnswire.RData) { set = append(set, expRec(d)) }
	if m.form == FormSets {
		for _, d := range m.alts[rng.IntN(len(m.alts))] {
			add(d)
		}
		switch rng.IntN(8) {
		case 0:
			set = set[:len(set)-1]
		case 1:
			add(expData(t, rng, m.typ))
		case 2:
			for _, d := range m.alts[rng.IntN(len(m.alts))] {
				add(d)
			}
		case 3:
			// The same octets under another type.
			d := dnswire.AppendRData(nil, set[0].Data)
			set[0].Data = dnswire.Unknown{TypeCode: 65281, Data: d}
		case 4:
			set = nil
		}
		return set
	}
	if m.form == FormNone {
		for range rng.IntN(2) * (1 + rng.IntN(2)) {
			add(expOtherType(t, rng, 0))
		}
		return set
	}
	for range rng.IntN(4) {
		if rng.IntN(7) == 0 {
			add(expOtherType(t, rng, m.typ))
			continue
		}
		if m.form == FormRange {
			p := expPick(rng, m.prefixes)
			var a netip.Addr
			switch rng.IntN(5) {
			case 0:
				a = p.Addr().Prev()
			case 1:
				a = expLastAddr(p).Next()
			case 2:
				if m.typ == dnswire.TypeA {
					a = expRandom4(rng)
				} else {
					a = expRandom6(rng)
				}
			default:
				a = expRandomIn(rng, p)
			}
			if !a.IsValid() {
				a = p.Addr()
			}
			if m.typ == dnswire.TypeA {
				add(dnswire.A{Addr: a})
			} else {
				add(dnswire.AAAA{Addr: a})
			}
			continue
		}
		target := expFlipCase(rng, expName(t, expPick(rng, expTargetNames)))
		if rng.IntN(2) == 0 {
			p := expPick(rng, m.patterns)
			target = p.Name
			if p.Under {
				target = expNameOf(append([]string{expLabel(rng, "abc")}, p.Name.Labels()...)...)
			}
		}
		typ := m.typ
		if rng.IntN(6) == 0 {
			// A target that the patterns allow, in a record of another
			// type that has a target too.
			typ = expPick(rng, expNameTypes)
		}
		add(expNamed(typ, target))
	}
	return set
}

func expRandomIn(rng *rand.Rand, p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := range b {
		keep := min(max(p.Bits()-8*i, 0), 8)
		mask := byte(0xff << (8 - keep))
		b[i] = b[i]&mask | byte(rng.Uint32())&^mask
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func expLastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := range b {
		keep := min(max(p.Bits()-8*i, 0), 8)
		b[i] |= byte(0xff >> keep)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// expVariants are changes that Match must not see: order, duplicates, TTL,
// owner, class, and the case of names that the canonical form lowers.
func expVariants(rng *rand.Rand, set []dnswire.Record) map[string][]dnswire.Record {
	v := map[string][]dnswire.Record{}
	shuffled := slices.Clone(set)
	rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
	v["order"] = shuffled
	if len(set) > 0 {
		v["a duplicate"] = append(slices.Clone(set), set[rng.IntN(len(set))])
	}
	other := slices.Clone(set)
	for i := range other {
		other[i].TTL = rng.Uint32()
		other[i].Name = expHostileName(rng)
		other[i].Class = expPick(rng, []dnswire.Class{dnswire.ClassINET, dnswire.ClassCHAOS, dnswire.ClassANY, 1234})
	}
	v["TTL, owner and class"] = other
	cased := slices.Clone(set)
	for i := range cased {
		cased[i].Data = expFoldCase(rng, cased[i].Data)
	}
	v["case of names"] = cased
	return v
}

// expCheckFields compares what Parse stored with the model: canonical data,
// sorted, without duplicates.
func expCheckFields(m expModel, e Expectation) string {
	if e.Line != 2 || !e.Name.Equal(m.owner) || e.Type != m.typ || e.Form != m.form {
		return fmt.Sprintf("line %d %v %v %v; want line 2 %v %v %v", e.Line, e.Name, e.Type, e.Form, m.owner, m.typ, m.form)
	}
	if m.form == FormSets {
		want := expCanonicalAlts(m.alts)
		if len(e.Sets) != len(want) {
			return fmt.Sprintf("%d alternatives; want %d", len(e.Sets), len(want))
		}
		for i, alt := range e.Sets {
			if len(alt) != len(want[i]) {
				return fmt.Sprintf("alternative %d has %d records; want %d", i, len(alt), len(want[i]))
			}
			for j, d := range alt {
				if d.Type() != m.typ || !bytes.Equal(dnswire.AppendRData(nil, d), want[i][j].octets) {
					return fmt.Sprintf("record %d of alternative %d is %v %q; want %s", j, i, d.Type(), d.String(), want[i][j].text)
				}
			}
		}
	}
	if want := expSortedPrefixes(m.prefixes); m.form == FormRange && !slices.Equal(e.Ranges, want) {
		return fmt.Sprintf("Ranges %v; want %v", e.Ranges, want)
	}
	if m.form == FormNames {
		want := expSortedPatterns(m.patterns)
		if len(e.Patterns) != len(want) {
			return fmt.Sprintf("%d patterns; want %d", len(e.Patterns), len(want))
		}
		for i, p := range e.Patterns {
			if p.Under != want[i].Under || !p.Name.Equal(want[i].Name) {
				return fmt.Sprintf("pattern %d is %v; want %v", i, p, want[i])
			}
		}
	}
	if m.form == FormNone && len(e.Sets)+len(e.Ranges)+len(e.Patterns) > 0 {
		return fmt.Sprintf("none holds data: %v %v %v", e.Sets, e.Ranges, e.Patterns)
	}
	return ""
}

func TestFormsProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(expSeed, 1))
	const cases = 2000
	var outcomes [5][2]int // by form, then false and true
	report := expFailer(t)
	for i := range cases {
		m := expFormsModel(t, rng)
		line := expCanonicalLine(m)
		fail := func(format string, args ...any) {
			t.Helper()
			report(i, "%q: %s", line, fmt.Sprintf(format, args...))
		}
		f, err := Parse([]byte("domain corp.test.\n" + line + "\n"))
		if err != nil || f == nil || len(f.Expectations) != 1 {
			fail("Parse gave %v, %v", f, err)
			continue
		}
		e := f.Expectations[0]
		if msg := expCheckFields(m, e); msg != "" {
			fail("%s", msg)
			continue
		}
		set := expDeriveSet(t, rng, m)
		want := expOracle(m, set)
		if got := e.Match(set); got != want {
			fail("Match(%q) = %v; want %v", expRecordTexts(set), got, want)
			continue
		}
		for what, v := range expVariants(rng, set) {
			if expOracle(m, v) != want {
				t.Fatalf("test fault: seed %d case %d: the oracle changes with %s", expSeed, i, what)
			}
			if got := e.Match(v); got != want {
				fail("Match(%q) = %v after a change of %s; want %v as before", expRecordTexts(v), got, what, want)
			}
		}
		if m.form == FormSets {
			// An observed set equal to an alternative has that
			// alternative's text.
			alt := m.alts[rng.IntN(len(m.alts))]
			var recs []dnswire.Record
			for _, d := range alt {
				recs = append(recs, expRec(expFoldCase(rng, d)))
			}
			if got, want := SetText(m.typ, recs), expAltText(expCanonicalAlts([][]dnswire.RData{alt})[0]); got != want {
				fail("SetText(%q) = %q; want %q", expRecordTexts(recs), got, want)
			}
		}
		if want {
			outcomes[m.form][1]++
		} else {
			outcomes[m.form][0]++
		}
	}
	for form := FormSets; form <= FormNone && !t.Failed(); form++ {
		if n := outcomes[form]; n[0] < cases/80 || n[1] < cases/80 {
			t.Errorf("test fault: form %d had %d non-matching and %d matching cases; both must come up", form, n[0], n[1])
		}
	}
}

// --- TestFormatParseProperty ---

func expBlanks(rng *rand.Rand) string {
	return expPick(rng, []string{" ", " ", "\t", "  ", " \t", "\t\t "})
}

func expTrail(rng *rand.Rand) string {
	return expPick(rng, []string{"", "", "", " ", "\t", "  \t"})
}

// expNoise is 0 to 2 lines that Parse must skip.
func expNoise(rng *rand.Rand) []string {
	pool := []string{"", "   ", "\t", "#", "# note", "  \t# indented | || ||| none in like", `# "open quote \`, "#domain other.test.", "# x.test. A 1.2.3.4"}
	var lines []string
	for range rng.IntN(3) {
		lines = append(lines, expPick(rng, pool))
	}
	return lines
}

// expMessyName writes n with its case changed and each bar escaped in one
// of the two ways that a name may take.
func expMessyName(rng *rand.Rand, n dnswire.Name, owner bool) string {
	s := expEscapeBars(expFlipCase(rng, n).String(), expPick(rng, []string{`\|`, `\124`}))
	if owner && strings.HasPrefix(s, "#") {
		s = `\` + s
	}
	return s
}

func expMessyType(rng *rand.Rand, typ dnswire.Type) string {
	return expPick(rng, []string{typ.String(), strings.ToLower(typ.String()), fmt.Sprintf("TYPE%d", typ), fmt.Sprintf("type%d", typ)})
}

func expShuffled[T any](rng *rand.Rand, s []T) []T {
	s = slices.Clone(s)
	rng.Shuffle(len(s), func(i, j int) { s[i], s[j] = s[j], s[i] })
	return s
}

// expMessyForm writes the form of m in a valid but not canonical way: any
// order, duplicates, other case, other blanks around separators.
func expMessyForm(rng *rand.Rand, m expModel) string {
	var parts []string
	if m.form == FormSets {
		alts := slices.Clone(m.alts)
		if rng.IntN(3) == 0 {
			alts = append(alts, expPick(rng, m.alts))
		}
		for _, alt := range expShuffled(rng, alts) {
			alt = expShuffled(rng, alt)
			if rng.IntN(3) == 0 {
				alt = append(alt, expPick(rng, alt))
			}
			var recs []string
			for _, d := range alt {
				recs = append(recs, expEscapeBars(expFoldCase(rng, d).String(), expPick(rng, []string{`\|`, `\124`})))
			}
			parts = append(parts, strings.Join(recs, expPick(rng, []string{" | ", "|", " |", "| ", "\t|  "})))
		}
		return strings.Join(parts, expPick(rng, []string{" || ", "||", "\t||\t", "  || "}))
	}
	if m.form == FormRange {
		ps := slices.Clone(m.prefixes)
		if rng.IntN(3) == 0 {
			ps = append(ps, expPick(rng, ps))
		}
		for _, p := range expShuffled(rng, ps) {
			parts = append(parts, p.String())
		}
		return "in" + expBlanks(rng) + strings.Join(parts, expBlanks(rng))
	}
	if m.form == FormNames {
		ps := slices.Clone(m.patterns)
		if rng.IntN(3) == 0 {
			ps = append(ps, expPick(rng, ps))
		}
		for _, p := range expShuffled(rng, ps) {
			s := expMessyName(rng, p.Name, false)
			if p.Under {
				s = "*." + s
			}
			parts = append(parts, s)
		}
		return "like" + expBlanks(rng) + strings.Join(parts, expBlanks(rng))
	}
	return "none"
}

func expMessyFile(rng *rand.Rand, domain dnswire.Name, models []expModel) string {
	lines := expNoise(rng)
	lines = append(lines, "domain"+expBlanks(rng)+expMessyName(rng, domain, false)+expTrail(rng))
	for _, m := range expShuffled(rng, models) {
		lines = append(lines, expNoise(rng)...)
		lines = append(lines, expMessyName(rng, m.owner, true)+expBlanks(rng)+expMessyType(rng, m.typ)+expBlanks(rng)+expMessyForm(rng, m)+expTrail(rng))
	}
	lines = append(lines, expNoise(rng)...)
	return strings.Join(lines, "\n") + "\n"
}

func expFileModel(t testing.TB, rng *rand.Rand, owner dnswire.Name, typ dnswire.Type) expModel {
	m := expModel{owner: owner, typ: typ, form: FormSets}
	isRange := typ == dnswire.TypeA || typ == dnswire.TypeAAAA
	_, isNames := expTargets[typ]
	switch r := rng.IntN(10); {
	case r < 2:
		m.form = FormNone
	case r < 5 && isRange:
		m.form = FormRange
		for range 1 + rng.IntN(4) {
			m.prefixes = append(m.prefixes, netip.PrefixFrom(expAddrOfType(rng, typ), rng.IntN(expBits(typ)+1)).Masked())
		}
	case r < 5 && isNames:
		m.form = FormNames
		for range 1 + rng.IntN(4) {
			labels := []string{expPlainLabel(rng)}
			if rng.IntN(2) == 0 {
				labels = append(labels, expLabel(rng, expPlainOctets))
			}
			m.patterns = append(m.patterns, Pattern{Name: expNameOf(append(labels, "test")...), Under: rng.IntN(2) == 0})
		}
	default:
		for range 1 + rng.IntN(3) {
			m.alts = append(m.alts, expAlt(t, rng, typ))
		}
	}
	return m
}

func expAddrOfType(rng *rand.Rand, typ dnswire.Type) netip.Addr {
	if typ == dnswire.TypeA {
		return expRandom4(rng)
	}
	return expRandom6(rng)
}

func expBits(typ dnswire.Type) int {
	if typ == dnswire.TypeA {
		return 32
	}
	return 128
}

func expFileModels(t testing.TB, rng *rand.Rand, domain dnswire.Name) []expModel {
	var models []expModel
	seen := map[string]bool{}
	for range rng.IntN(9) {
		typ := expPick(rng, expDataTypes)
		labels := []string{expLabel(rng, expHostileOctets)}
		if rng.IntN(2) == 0 {
			labels = append(labels, expLabel(rng, expHostileOctets))
		}
		if rng.IntN(3) == 0 {
			labels = append(labels, "other", "test")
		} else {
			labels = append(labels, domain.Labels()...)
		}
		owner := expNameOf(labels...)
		if typ == dnswire.TypeDS || rng.IntN(8) == 0 {
			owner = domain
		}
		if key := owner.Key() + typ.String(); !seen[key] {
			seen[key] = true
			models = append(models, expFileModel(t, rng, owner, typ))
		}
	}
	return models
}

func TestFormatParseProperty(t *testing.T) {
	rng := rand.New(rand.NewPCG(expSeed, 2))
	fail := expFailer(t)
	for i := range 1000 {
		domain := expNameOf(expPlainLabel(rng), "test")
		models := expFileModels(t, rng, domain)
		want := expCanonicalFile(domain, models)
		messy := expMessyFile(rng, domain, models)

		f, err := Parse([]byte(messy))
		if err != nil || f == nil {
			fail(i, "Parse(%q) = %v, %v", messy, f, err)
			continue
		}
		got := f.String()
		if got != want {
			fail(i, "Parse(%q).String():\n%q\nwant\n%q", messy, got, want)
			continue
		}
		g, err := Parse([]byte(got))
		if err != nil || g == nil || g.String() != got {
			fail(i, "the print %q does not parse to itself: %v, %v", got, g, err)
		}
	}
}

// expFailer reports a failing generated case with the seed, and stops the
// test after ten of them, so that one fault does not flood the log.
func expFailer(t *testing.T) func(i int, format string, args ...any) {
	n := 0
	return func(i int, format string, args ...any) {
		t.Helper()
		t.Errorf("seed %d case %d: %s", expSeed, i, fmt.Sprintf(format, args...))
		if n++; n == 10 {
			t.Fatalf("seed %d: stopped after %d failing cases", expSeed, n)
		}
	}
}
