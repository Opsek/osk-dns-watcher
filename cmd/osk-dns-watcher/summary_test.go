package main

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/expect"
)

// svcCanonical gives the canonical print of a file of corp.test. with the
// lines given, as the service stores it.
func svcCanonical(t testing.TB, lines ...string) string {
	t.Helper()
	text := strings.Join(append([]string{"domain corp.test."}, lines...), "\n") + "\n"
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Fatalf("Parse(%q): %v", text, err)
	}
	return f.String()
}

func svcSameLines(t *testing.T, what string, got, want []string) {
	t.Helper()
	if !slices.Equal(got, want) {
		t.Errorf("%s gave:\n%s\nwant:\n%s", what, strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// A line that left the file is told with "- ", a new line with "+ ": the
// removed lines first, in the order of the old file, then the added lines
// in the order of the new one. A changed set is one of each.
func TestSummaryListsRemovedLinesThenAddedLines(t *testing.T) {
	old := svcCanonical(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.81",
		"cdn.corp.test. CNAME edge.dnshost.test.", "_dmarc.corp.test. TXT none")
	changed := svcCanonical(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "www.corp.test. A 10.53.0.99",
		"mail.corp.test. A 10.53.0.82", "_dmarc.corp.test. TXT none", "alpha.corp.test. TXT none")
	svcSameLines(t, "summary of a removed, a changed and two added lines", summary(old, changed), []string{
		"- cdn.corp.test. CNAME edge.dnshost.test.",
		"- www.corp.test. A 10.53.0.81",
		"+ alpha.corp.test. TXT none",
		"+ mail.corp.test. A 10.53.0.82",
		"+ www.corp.test. A 10.53.0.99",
	})
	if got := summary(old, old); len(got) != 0 {
		t.Errorf("summary of a file and itself gave %q, want no line", got)
	}
}

// A domain that left the config has the new text "": every line of its last
// text is told as removed, the domain line too.
func TestSummaryOfADomainThatLeftListsEveryLine(t *testing.T) {
	old := svcCanonical(t, "corp.test. NS ns1.corp.test. | ns2.corp.test.", "corp.test. DS none")
	svcSameLines(t, "summary of a domain that left", summary(old, ""), []string{
		"- domain corp.test.",
		"- corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"- corp.test. DS none",
	})
}

var svcSumOwners = []string{"corp.test.", "www.corp.test.", "mail.corp.test.", "cdn.corp.test.", "_dmarc.corp.test.",
	"_acme-challenge.corp.test.", "a.corp.test.", "b.corp.test.", "deep.www.corp.test.", "edge.dnshost.test."}

var svcSumTypes = []string{"A", "AAAA", "TXT", "MX", "CAA"}

// svcSumLine is a random line: an A set of one or two addresses of a small
// pool, so that two files often hold the same line, or the form none.
func svcSumLine(rng *rand.Rand, owner, typ string) string {
	if typ != "A" || rng.IntN(3) == 0 {
		return owner + " " + typ + " none"
	}
	first := rng.IntN(4)
	if rng.IntN(2) == 0 {
		return fmt.Sprintf("%s A 10.53.0.%d", owner, 80+first)
	}
	return fmt.Sprintf("%s A 10.53.0.%d | 10.53.0.%d", owner, 80+first, 80+(first+1+rng.IntN(3))%4)
}

// svcSumFile picks for each owner and type at most one line from base, a
// new one, or none.
func svcSumFile(rng *rand.Rand, base map[string]string) []string {
	var lines []string
	for _, owner := range svcSumOwners {
		for _, typ := range svcSumTypes {
			key := owner + " " + typ
			switch x := rng.IntN(10); {
			case x < 4 && base[key] != "":
				lines = append(lines, base[key])
			case x < 6:
				lines = append(lines, svcSumLine(rng, owner, typ))
			}
		}
	}
	return lines
}

func svcSumLines(text string) []string {
	if text == "" {
		return nil
	}
	return strings.Split(strings.TrimSuffix(text, "\n"), "\n")
}

// svcIsSubsequence reports whether sub holds lines of all in their order.
func svcIsSubsequence(sub, all []string) bool {
	i := 0
	for _, l := range all {
		if i < len(sub) && sub[i] == l {
			i++
		}
	}
	return i == len(sub)
}

// For random pairs of canonical files: the old lines without the removed
// ones and with the added ones are the new lines; no line is both removed
// and added; each list keeps the order of its file; equal files give no
// line. The files stay small enough that no line is left out.
func TestSummaryProperty(t *testing.T) {
	const seed, cases = 20261116, 1000
	for c := range cases {
		rng := rand.New(rand.NewPCG(seed, uint64(c)))
		base := map[string]string{}
		for _, owner := range svcSumOwners {
			for _, typ := range svcSumTypes {
				base[owner+" "+typ] = svcSumLine(rng, owner, typ)
			}
		}
		old := svcCanonical(t, svcSumFile(rng, base)...)
		cur := svcCanonical(t, svcSumFile(rng, base)...)
		if rng.IntN(10) == 0 {
			cur = old
		}
		got := summary(old, cur)
		where := fmt.Sprintf("seed %d case %d: summary of\n%s\nand\n%s\ngave\n%s\n", seed, c, old, cur, strings.Join(got, "\n"))
		var minus, plus []string
		for i, l := range got {
			switch {
			case strings.HasPrefix(l, "- ") && len(plus) == 0:
				minus = append(minus, strings.TrimPrefix(l, "- "))
			case strings.HasPrefix(l, "+ "):
				plus = append(plus, strings.TrimPrefix(l, "+ "))
			default:
				t.Fatalf("%sline %d is not \"- <line>\" before the added lines or \"+ <line>\"", where, i+1)
			}
		}
		oldLines, newLines := svcSumLines(old), svcSumLines(cur)
		if !svcIsSubsequence(minus, oldLines) || !svcIsSubsequence(plus, newLines) {
			t.Fatalf("%swant the removed lines in the order of the old file and the added ones in the order of the new", where)
		}
		var rebuilt []string
		for _, l := range oldLines {
			if !slices.Contains(minus, l) {
				rebuilt = append(rebuilt, l)
			}
		}
		rebuilt = append(rebuilt, plus...)
		slices.Sort(rebuilt)
		want := slices.Sorted(slices.Values(newLines))
		if !slices.Equal(rebuilt, want) {
			t.Fatalf("%sthe old lines without the removed and with the added ones are not the new lines", where)
		}
		for _, l := range minus {
			if slices.Contains(plus, l) || slices.Contains(newLines, l) {
				t.Fatalf("%sthe line %q is removed although the new file holds it", where, l)
			}
		}
		for _, l := range plus {
			if slices.Contains(oldLines, l) {
				t.Fatalf("%sthe line %q is added although the old file holds it", where, l)
			}
		}
		if old == cur && len(got) != 0 {
			t.Fatalf("%swant no line for equal files", where)
		}
	}
}

// A change of more than 200 lines keeps at most 200 of them, in order, and
// counts the rest in a last line.
func TestSummaryKeepsAtMost200LinesAndCountsTheRest(t *testing.T) {
	var lines, added []string
	for n := range 250 {
		lines = append(lines, fmt.Sprintf("h%03d.corp.test. TXT none", n))
		added = append(added, fmt.Sprintf("+ h%03d.corp.test. TXT none", n))
	}
	got := summary(svcCanonical(t), svcCanonical(t, lines...))
	kept := len(got) - 1
	if kept < 199 || kept > 200 || !slices.Equal(got[:kept], added[:kept]) || got[kept] != fmt.Sprintf("and %d more lines", 250-kept) {
		t.Errorf("summary of 250 added lines gave %d lines, the last %q; want the first 199 or 200 and \"and <the rest> more lines\"",
			len(got), got[max(0, len(got)-1):])
	}
}
