package expect

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

const crtStar = `"*" stands only as the first label`

func crtNameTexts(names []dnswire.Name) []string {
	texts := make([]string, len(names))
	for i, n := range names {
		texts[i] = n.Lower().String()
	}
	return texts
}

func TestCertLinesProblems(t *testing.T) {
	for _, c := range []struct {
		name string
		text string
		want Problem
	}{
		{"issuer without a name", expHead + "issuer\n", Problem{4, "an issuer line takes one name"}},
		{"issuer with two names", expHead + "issuer letsencrypt.org digicert.com\n", Problem{4, "an issuer line takes one name"}},
		{"issuer with a comment after it", expHead + "issuer letsencrypt.org # main\n", Problem{4, "an issuer line takes one name"}},
		{"issuer with a trailing dot", expHead + "issuer letsencrypt.org.\n", Problem{4, `bad issuer "letsencrypt.org.": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with a trailing dot in capitals", expHead + "issuer LetsEncrypt.ORG.\n", Problem{4, `bad issuer "LetsEncrypt.ORG.": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer that is a dot", expHead + "issuer .\n", Problem{4, `bad issuer ".": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with a leading dot", expHead + "issuer .letsencrypt.org\n", Problem{4, `bad issuer ".letsencrypt.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with an empty label", expHead + "issuer lets..encrypt.org\n", Problem{4, `bad issuer "lets..encrypt.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer label that starts with a hyphen", expHead + "issuer -lets.org\n", Problem{4, `bad issuer "-lets.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer label that ends with a hyphen", expHead + "issuer lets-.org\n", Problem{4, `bad issuer "lets-.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with an underscore", expHead + "issuer lets_encrypt.org\n", Problem{4, `bad issuer "lets_encrypt.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with a star", expHead + "issuer *.letsencrypt.org\n", Problem{4, `bad issuer "*.letsencrypt.org": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer with a semicolon", expHead + "issuer letsencrypt.org;\n", Problem{4, `bad issuer "letsencrypt.org;": want a name such as letsencrypt.org, with no trailing dot`}},
		{"issuer given twice", expHead + "issuer letsencrypt.org\nissuer letsencrypt.org\n", Problem{5, "issuer letsencrypt.org is already given on line 4"}},
		{"issuer given twice with lines between", expHead + "issuer ca.test\n# c\nissuer other.test\nwww.corp.test. A none\nissuer ca.test\n", Problem{8, "issuer ca.test is already given on line 4"}},
		{"issuer that is a keyword in capitals", expHead + "Issuer letsencrypt.org\n", Problem{4, "want <owner> <type> <form>"}},
		{"certname that is a keyword in capitals", expHead + "CERTNAME www.corp.test.\n", Problem{4, "want <owner> <type> <form>"}},
		{"certname without a name", expHead + "certname\n", Problem{4, "a certname line takes one name"}},
		{"certname with two names", expHead + "certname www.corp.test. mail.corp.test.\n", Problem{4, "a certname line takes one name"}},
		{"certname without a trailing dot", expHead + "certname www.corp.test\n", Problem{4, `"www.corp.test" has no trailing dot`}},
		{"certname with an empty label", expHead + "certname a..corp.test.\n", Problem{4, expNameProblem(t, "a..corp.test.")}},
		{"certname in another domain", expHead + "certname www.other.test.\n", Problem{4, "certname www.other.test. is not at or under the domain"}},
		{"certname that is the parent of the domain", expHead + "certname test.\n", Problem{4, "certname test. is not at or under the domain"}},
		{"certname that only ends like the domain", expHead + "certname xcorp.test.\n", Problem{4, "certname xcorp.test. is not at or under the domain"}},
		{"certname that holds the domain inside", expHead + "certname corp.test.example.\n", Problem{4, "certname corp.test.example. is not at or under the domain"}},
		{"certname with a star at the end of a label", expHead + "certname a*.corp.test.\n", Problem{4, fmt.Sprintf("bad certname %q: %s", "a*.corp.test.", crtStar)}},
		{"certname with a star at the start of a label", expHead + "certname *a.corp.test.\n", Problem{4, fmt.Sprintf("bad certname %q: %s", "*a.corp.test.", crtStar)}},
		{"certname with a star as the second label", expHead + "certname www.*.corp.test.\n", Problem{4, fmt.Sprintf("bad certname %q: %s", "www.*.corp.test.", crtStar)}},
		{"certname with two stars in a label", expHead + "certname **.corp.test.\n", Problem{4, fmt.Sprintf("bad certname %q: %s", "**.corp.test.", crtStar)}},
		{"certname with two star labels", expHead + "certname *.*.corp.test.\n", Problem{4, fmt.Sprintf("bad certname %q: %s", "*.*.corp.test.", crtStar)}},
		{"certname given twice", expHead + "certname www.corp.test.\ncertname www.corp.test.\n", Problem{5, "certname www.corp.test. is already given on line 4"}},
		{"wildcard certname given twice", expHead + "certname *.corp.test.\ncertname mail.corp.test.\ncertname *.corp.test.\n", Problem{6, "certname *.corp.test. is already given on line 4"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := expProblems(t, c.text); !slices.Equal(got, []Problem{c.want}) {
				t.Errorf("Parse(%s): problems %+v; want only %+v", expShort(c.text), got, c.want)
			}
		})
	}
}

// The same name in another case is the same name; the text of the problem
// names the first line, whatever case it used.
func TestCertLinesGivenTwiceInOtherCase(t *testing.T) {
	for _, c := range []struct {
		name, first, second, prefix string
	}{
		{"issuer", "issuer letsencrypt.org", "issuer LetsEncrypt.ORG", "issuer "},
		{"certname", "certname www.corp.test.", "certname WWW.Corp.TEST.", "certname "},
	} {
		got := expProblems(t, expHead+c.first+"\n"+c.second+"\n")
		if len(got) != 1 || got[0].Line != 5 || !strings.HasPrefix(got[0].Text, c.prefix) ||
			!strings.HasSuffix(got[0].Text, " is already given on line 4") {
			t.Errorf("%s: problems %+v; want one on line 5 that ends in \" is already given on line 4\"", c.name, got)
		}
	}
}

// An issuer and a certname are different kinds of line: the same text in
// both is no repeat.
func TestCertLinesOtherKindIsNoRepeat(t *testing.T) {
	f := expParse(t, expHead+"issuer corp.test\ncertname corp.test.\n")
	if !slices.Equal(f.Issuers, []string{"corp.test"}) || !slices.Equal(crtNameTexts(f.CertNames), []string{"corp.test."}) {
		t.Errorf("issuers %q, certnames %q", f.Issuers, crtNameTexts(f.CertNames))
	}
}

// Both kinds count as expectations for the rule that the domain line comes
// first; the problem stands on the domain line.
func TestCertLinesBeforeTheDomainLine(t *testing.T) {
	want := Problem{4, "the domain line must come before the expectations"}
	for _, c := range []struct{ name, text string }{
		{"issuer", "# c\n\nissuer letsencrypt.org\ndomain corp.test.\n"},
		{"certname", "# c\n\ncertname www.corp.test.\ndomain corp.test.\n"},
	} {
		if got := expProblems(t, c.text); !slices.Contains(got, want) {
			t.Errorf("%s before the domain line: problems %+v; want them to hold %+v", c.name, got, want)
		}
	}
	if got := expProblems(t, "# c\n\nissuer letsencrypt.org\n"); !slices.Contains(got, Problem{0, "no domain line"}) {
		t.Errorf("issuer without a domain line: problems %+v; want them to hold \"no domain line\"", got)
	}
}

func TestCertLinesAfterTheDomainLine(t *testing.T) {
	for _, text := range []string{
		expHead + "issuer letsencrypt.org\n",
		expHead + "certname www.corp.test.\n",
		expHead + "www.corp.test. A 10.0.0.1\nissuer letsencrypt.org\ncertname www.corp.test.\n",
		expHead + "certname www.corp.test.\nissuer letsencrypt.org\nwww.corp.test. A 10.0.0.1\n",
	} {
		expParse(t, text)
	}
}

// Every problem of the file is listed, in line order.
func TestCertLinesProblemsInLineOrder(t *testing.T) {
	text := expHead + "issuer ca.test.\ncertname www.other.test.\nwww.corp.test. A 10.0.0.256\n"
	want := []Problem{
		{4, `bad issuer "ca.test.": want a name such as letsencrypt.org, with no trailing dot`},
		{5, "certname www.other.test. is not at or under the domain"},
		{6, expDataProblem(t, dnswire.TypeA, "10.0.0.256")},
	}
	if got := expProblems(t, text); !slices.Equal(got, want) {
		t.Errorf("problems %+v; want %+v", got, want)
	}
}

// The bound of 10000 counts the issuer and certname lines with the others.
func TestCertLinesCountForTheExpectationLimit(t *testing.T) {
	line := func(i int) string { return fmt.Sprintf("h%d.corp.test. A 10.0.0.1", i) }
	tooMany := []Problem{{0, "more than 10000 expectations"}}
	for _, c := range []struct {
		name  string
		text  string
		lines int // expectations in the file
		ok    bool
	}{
		{"9999 and an issuer", "domain corp.test.\nissuer ca.test\n" + expLines(9999, line), 9999, true},
		{"9999 and a certname", "domain corp.test.\ncertname www.corp.test.\n" + expLines(9999, line), 9999, true},
		{"9998, an issuer and a certname", "domain corp.test.\nissuer ca.test\ncertname www.corp.test.\n" + expLines(9998, line), 9998, true},
		{"9999, an issuer and a certname", "domain corp.test.\nissuer ca.test\ncertname www.corp.test.\n" + expLines(9999, line), 0, false},
		{"10000 and an issuer", "domain corp.test.\nissuer ca.test\n" + expLines(10000, line), 0, false},
		{"10000 and a certname after them", "domain corp.test.\n" + expLines(10000, line) + "certname www.corp.test.\n", 0, false},
		{"10000 and an issuer after them", "domain corp.test.\n" + expLines(10000, line) + "issuer ca.test\n", 0, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			if c.ok {
				if f := expParse(t, c.text); len(f.Expectations) != c.lines {
					t.Errorf("%d expectations; want %d", len(f.Expectations), c.lines)
				}
				return
			}
			if got := expProblems(t, c.text); !slices.Equal(got, tooMany) {
				t.Errorf("problems %+v; want %+v", got, tooMany)
			}
		})
	}
}

func TestCertLinesFields(t *testing.T) {
	f := expParse(t, "# c\n\ndomain Corp.Test.\n"+
		"issuer Sectigo.COM\n"+
		"certname B.corp.test.\n"+
		"issuer letsencrypt.org\n"+
		"\tissuer   digicert.com   \n"+
		"certname a.B.Corp.Test.\n"+
		"www.corp.test. A 10.0.0.1\n"+
		"certname *.corp.test.\n"+
		"certname CORP.test.\n"+
		"certname A.CORP.test.\n"+
		"issuer a-b.c-d.test\n")
	if want := []string{"a-b.c-d.test", "digicert.com", "letsencrypt.org", "sectigo.com"}; !slices.Equal(f.Issuers, want) {
		t.Errorf("Issuers %q; want %q", f.Issuers, want)
	}
	if want := []string{"corp.test.", "*.corp.test.", "a.corp.test.", "b.corp.test.", "a.b.corp.test."}; !slices.Equal(crtNameTexts(f.CertNames), want) {
		t.Errorf("CertNames %q; want %q", crtNameTexts(f.CertNames), want)
	}
	if len(f.Expectations) != 1 || f.Expectations[0].Line != 9 {
		t.Errorf("expectations %+v; want one, on line 9", f.Expectations)
	}
}

func TestCertLinesAbsent(t *testing.T) {
	f := expParse(t, expHead+"www.corp.test. A 10.0.0.1\n")
	if f.Issuers != nil {
		t.Errorf("Issuers %#v; want nil", f.Issuers)
	}
	if len(f.CertNames) != 0 {
		t.Errorf("CertNames %v; want none", f.CertNames)
	}
}

func TestCertLinesUnderTheDomain(t *testing.T) {
	expParse(t, "domain corp.test.\ncertname corp.test.\ncertname WWW.CORP.TEST.\ncertname *.corp.test.\ncertname a.b.c.corp.test.\n")
	expParse(t, "domain Corp.Test.\ncertname www.corp.test.\n")
	got := expProblems(t, "domain www.corp.test.\ncertname corp.test.\n")
	if want := (Problem{2, "certname corp.test. is not at or under the domain"}); !slices.Equal(got, []Problem{want}) {
		t.Errorf("problems %+v; want only %+v", got, want)
	}
}

func TestCertLinesCanonicalPrint(t *testing.T) {
	f := expParse(t, "domain Corp.Test.\n"+
		"www.corp.test. A 10.0.0.1\n"+
		"certname WWW.corp.test.\n"+
		"issuer Sectigo.COM\n"+
		"certname *.corp.test.\n"+
		"issuer letsencrypt.org\n"+
		"certname corp.test.\n"+
		"corp.test. NS none\n")
	want := "domain corp.test.\n" +
		"issuer letsencrypt.org\n" +
		"issuer sectigo.com\n" +
		"certname corp.test.\n" +
		"certname *.corp.test.\n" +
		"certname www.corp.test.\n" +
		"corp.test. NS none\n" +
		"www.corp.test. A 10.0.0.1\n"
	if got := f.String(); got != want {
		t.Fatalf("String() %q; want %q", got, want)
	}
	g := expParse(t, f.String())
	if g.String() != want || !slices.Equal(g.Issuers, f.Issuers) ||
		!slices.Equal(crtNameTexts(g.CertNames), crtNameTexts(f.CertNames)) ||
		len(g.Expectations) != len(f.Expectations) || !g.Domain.Equal(f.Domain) {
		t.Errorf("parse of the print gave %q, issuers %q, certnames %q; want the same file as %q",
			g.String(), g.Issuers, crtNameTexts(g.CertNames), f.String())
	}
}

func TestCertLinesPrintOfABuiltFile(t *testing.T) {
	f := &File{
		Domain:    expName(t, "Corp.Test."),
		Issuers:   []string{"a.test", "b.test"},
		CertNames: []dnswire.Name{expName(t, "Corp.Test."), expName(t, "*.Corp.Test."), expName(t, "WWW.Corp.test.")},
	}
	want := "domain corp.test.\nissuer a.test\nissuer b.test\ncertname corp.test.\ncertname *.corp.test.\ncertname www.corp.test.\n"
	if got := f.String(); got != want {
		t.Errorf("String() %q; want %q", got, want)
	}
	if got := (&File{Domain: expName(t, "corp.test.")}).String(); got != "domain corp.test.\n" {
		t.Errorf("String() of a file without these lines %q; want the domain line alone", got)
	}
}

func TestSetOfCertificatesKeyGivesNoSet(t *testing.T) {
	d := expName(t, "corp.test.")
	name, typ, ok := setOf(obs.CertificatesKey(d))
	if ok || typ != 0 || name.LabelCount() != 0 {
		t.Errorf("setOf of the certificates key gave %v %v %v; want no set", name, typ, ok)
	}
}

// A run of the certificate check shows no record set, so a snapshot leaves it out.
func TestSnapshotLeavesOutCertificates(t *testing.T) {
	f, skips := expSnapshot(t, obs.Observation{Key: obs.CertificatesKey(expName(t, "corp.test."))})
	if want := "domain corp.test.\n"; f.String() != want || len(skips) != 0 {
		t.Errorf("String() %q, skips %q; want %q and no skip", f.String(), skips, want)
	}
}

// The characters at the edge of each allowed range are allowed, and the
// ones just beside the ranges are not, at the start, inside and at the end
// of a label.
func TestCertLinesIssuerCharacterEdges(t *testing.T) {
	shapes := []string{"%s", "%sb.org", "b%sb.org", "b%s.org", "org.%s"}
	for _, ch := range []string{"0", "9", "z", "A", "Z", "a", "Q"} {
		for _, shape := range shapes {
			name := fmt.Sprintf(shape, ch)
			f := expParse(t, expHead+"issuer "+name+"\n")
			if want := []string{strings.ToLower(name)}; !slices.Equal(f.Issuers, want) {
				t.Errorf("issuer %s: Issuers %q; want %q", name, f.Issuers, want)
			}
		}
	}
	for _, name := range []string{"z0.a9.org", "AZ.org"} {
		f := expParse(t, expHead+"issuer "+name+"\n")
		if want := []string{strings.ToLower(name)}; !slices.Equal(f.Issuers, want) {
			t.Errorf("issuer %s: Issuers %q; want %q", name, f.Issuers, want)
		}
	}
	for _, ch := range []string{"/", ":", "@", "[", "`", "{"} {
		for _, shape := range shapes {
			name := fmt.Sprintf(shape, ch)
			want := Problem{4, fmt.Sprintf("bad issuer %q: want a name such as letsencrypt.org, with no trailing dot", name)}
			if got := expProblems(t, expHead+"issuer "+name+"\n"); !slices.Equal(got, []Problem{want}) {
				t.Errorf("issuer %s: problems %+v; want only %+v", name, got, want)
			}
		}
	}
}
