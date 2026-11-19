package start

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

// stfBadChars is the text that asks again for a field with an octet other
// than a letter, a digit, "-", "_" or ".". It never holds the field.
const stfBadChars = `A domain name holds only letters, digits, "-", "_" and ".". ` +
	`Write an international name in its xn-- form, and do not paste a URL here. Try again.` + "\n"

// stfBadFields are fields that the character check refuses. One of them is
// the webhook URL, whose secret must reach nobody.
var stfBadFields = []string{
	iniURL,
	"https://example.com",
	"example.com/",
	"user@example.com",
	"example.com:53",
	"bücher.de",
	"*.example.com",
	"ex*mple.com",
	`exa\mple.com`,
	`exa"mple.com`,
	"exa'mple.com",
	"exa\x01mple.com",
	"exa\x1b[2Jmple.com",
	"exa\x7fmple.com",
	"example.com https://example.com/x example.org",
	"example.com example.org example.net?",
}

// A pasted URL is the dangerous case: init must not ask about it, and nothing
// may print it. A pipe gets each good answer written back by init; a refused
// one is written back as [hidden]. On a terminal the terminal echoes the
// answer and init writes nothing of it. So the field is in no output.
func TestInitAsksAgainForAFieldWithAnOtherOctetWithoutAskingTheServers(t *testing.T) {
	d := "example.com."
	for _, bad := range stfBadFields {
		for _, term := range []bool{false, true} {
			name := "pipe"
			if term {
				name = "terminal"
			}
			t.Run(name+" "+strconv.Quote(bad), func(t *testing.T) {
				s := iniNew(t, bad, "example.com", iniURL, "no")
				s.init.Term, s.in.term = term, term
				code, out := s.run()
				if code != 1 {
					t.Errorf("exit code %d; want 1", code)
				}
				if term {
					if !strings.HasPrefix(out, iniHello+iniDomainsQ+stfBadChars+iniDomainsQ) {
						t.Errorf("the output does not start with the question, the fixed text and the question again:\n%q", out)
					}
				} else {
					want := iniHello + iniDomainsQ + "[hidden]\n" + stfBadChars +
						strings.TrimPrefix(s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))), iniHello) + "no\n" + iniNothing
					iniSame(t, "the dialogue", out, want)
					if n := strings.Count(out, "Try again."); n != 1 {
						t.Errorf("the output asks again %d times; want once", n)
					}
				}
				re := strings.Index(out, stfBadChars)
				if re < 0 {
					t.Fatalf("the output holds no fixed re-ask text:\n%q", out)
				}
				// A line of the good domain may hold text like a refused field, such as
				// the line of a wildcard name: the field must not be in the output up to
				// the re-ask, and its secret in none.
				stfNoField(t, out[:re+len(stfBadChars)], bad)
				if strings.Contains(out, iniMark) {
					t.Errorf("the output holds the secret of the URL:\n%q", out)
				}
				moments := s.in.seen()
				for i, m := range moments[:min(3, len(moments))] {
					if m.checks != 0 {
						t.Errorf("before answer %d, %d checks had run; want none before a good domain answer", i+1, m.checks)
					}
				}
				keys := s.runner.keys()
				slices.Sort(keys)
				if want := iniKeys(d, true); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
					t.Errorf("checks %q; want only those of %s", keys, d)
				}
				for _, r := range s.roots {
					for _, q := range r.asked() {
						if strings.Contains(q.question, "example.org") || strings.Contains(q.question, strings.ToLower(iniMark)) {
							t.Errorf("a root server was asked %q", q.question)
						}
					}
				}
			})
		}
	}
}

// Several bad answers in a row ask again each time, and a good one then goes
// on as before.
func TestInitGoesOnAfterSeveralRefusedDomainAnswers(t *testing.T) {
	s := iniNew(t, iniURL, "example.com/", "bücher.de", "example.com", iniURL, "yes")
	code, out := s.run()
	d := "example.com."
	want := iniHello + iniDomainsQ + "[hidden]\n" + stfBadChars + iniDomainsQ + "[hidden]\n" + stfBadChars +
		iniDomainsQ + "[hidden]\n" + stfBadChars +
		strings.TrimPrefix(s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))), iniHello) + "yes\n" + s.wrote(d)
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	for _, bad := range []string{iniURL, "example.com/", "bücher.de"} {
		stfNoField(t, out, bad)
	}
	iniSame(t, "the dialogue", out, want)
	s.written(d)
}

// The names that osk-dns-watcher watched before stay allowed: both cases, digits, "-",
// "_" and a trailing dot.
func TestInitStillTakesTheCharactersOfADomainName(t *testing.T) {
	s := iniNew(t, "_dmarc.example.com EXAMPLE.com. xn--bcher-kva.de 9-a_b.test", iniURL, "yes")
	code, out := s.run()
	ds := []string{"_dmarc.example.com.", "example.com.", "xn--bcher-kva.de.", "9-a_b.test."}
	var blocks []string
	for _, d := range ds {
		blocks = append(blocks, iniBlock(d, iniLines(d), iniAliasSkip(d)))
	}
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out,
		s.shown("_dmarc.example.com EXAMPLE.com. xn--bcher-kva.de 9-a_b.test", blocks...)+"yes\n"+s.wrote(ds...))
}

// The function that reads the answer, row by row.
func TestParseDomainsRows(t *testing.T) {
	long := strings.Repeat("x", 64) + ".test"
	for _, c := range []struct {
		answer  string
		names   []string
		problem string // "" when the answer is good
	}{
		{"example.com", []string{"example.com."}, ""},
		{"EXAMPLE.com.", []string{"example.com."}, ""},
		{"_dmarc.example.com xn--bcher-kva.de", []string{"_dmarc.example.com.", "xn--bcher-kva.de."}, ""},
		{"a-1.test A-1.TEST.", []string{"a-1.test."}, ""},
		{iniURL, nil, stfBadChars},
		{"https://example.com", nil, stfBadChars},
		{"example.com/", nil, stfBadChars},
		{"user@example.com", nil, stfBadChars},
		{"example.com:53", nil, stfBadChars},
		{"bücher.de", nil, stfBadChars},
		{"ex*mple.com", nil, stfBadChars},
		{`ex\mple.com`, nil, stfBadChars},
		{`ex"mple.com`, nil, stfBadChars},
		{"ex\x01mple.com", nil, stfBadChars},
		{"example.com bad/field example.org", nil, stfBadChars},
		// The older texts stay.
		{"a..b", nil, iniNameProblem(t, "a..b")},
		{long, nil, iniNameProblem(t, long)},
		{".", nil, "osk-dns-watcher does not watch the root. Try again.\n"},
		{"", nil, "Name at least one domain. Try again.\n"},
		{"   ", nil, "Name at least one domain. Try again.\n"},
		{strings.Join(iniDomainsList(101), " "), nil, "osk-dns-watcher watches at most 100 domains. Try again.\n"},
		// The character check comes first.
		{"a..b example.com/", nil, stfBadChars},
		{". example.com/", nil, stfBadChars},
		{long + "* example.com", nil, stfBadChars},
		{strings.Join(iniDomainsList(101), " ") + " a/b", nil, stfBadChars},
	} {
		names, problem := parseDomains(c.answer)
		var got []string
		for _, n := range names {
			got = append(got, n.String())
		}
		if problem != c.problem || !slices.Equal(got, c.names) {
			t.Errorf("parseDomains(%q) = %q, %q; want %q, %q", c.answer, got, problem, c.names, c.problem)
		}
	}
}

// stfNoField checks that no field of the answer that the character rule
// refuses is anywhere in the output, nor the secret of a URL.
func stfNoField(t *testing.T, out, answer string) {
	t.Helper()
	for _, f := range strings.Fields(answer) {
		if strings.ContainsFunc(f, func(r rune) bool {
			return !(r == '-' || r == '_' || r == '.' || r >= '0' && r <= '9' || r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z')
		}) &&
			strings.Contains(out, f) {
			t.Errorf("the output holds the refused field %q:\n%q", f, out)
		}
	}
	if strings.Contains(out, iniMark) {
		t.Errorf("the output holds the secret of the URL:\n%q", out)
	}
}

// A URL can be typed at the trust question too. Without a terminal init
// writes each answer back, but not one that the domain rule refuses; the
// plain answers are written back as before.
func TestInitHidesAnAnswerToTheTrustQuestionThatIsNotAPlainAnswer(t *testing.T) {
	d := "example.com."
	for _, c := range []struct {
		answer string
		echo   string
	}{
		{iniURL, "[hidden]"},
		{"https://example.com", "[hidden]"},
		{"yes example.com/", "[hidden]"},
		{"ye\x1b[2Js", "[hidden]"},
		{"no", "no"},
		{"y", "y"},
		{"", ""},
	} {
		t.Run(strconv.Quote(c.answer), func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, c.answer)
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+c.echo+"\n"+iniNothing)
			if c.echo == "[hidden]" {
				stfNoField(t, out, c.answer)
			}
			s.nothingWritten()
		})
	}
}
