package expect

import (
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// A weaker DMARC tag gives its word wherever it stands in the record.
func TestDMARCReadsEveryTag(t *testing.T) {
	owner := expName(t, emlDMARCOwner)
	was := emlSet("v=DMARC1; p=reject")
	var pad []string
	for i := 1; i <= 31; i++ {
		pad = append(pad, fmt.Sprintf("x%d=1", i))
	}
	for _, tag := range []string{"pct=0", "t=y", "sp=none", "np=none", "rua=mailto:x@evil.test"} {
		t.Run(tag, func(t *testing.T) {
			if Weaker(MailDMARC, owner, was, emlSet("v=DMARC1; p=reject; "+tag)) == nil {
				t.Fatalf("control: %s alone gives no word", tag)
			}
			now := "v=DMARC1; p=reject; " + strings.Join(pad, "; ") + "; " + tag
			if got := Weaker(MailDMARC, owner, was, emlSet(now)); len(got) == 0 {
				t.Errorf("%s after 31 other tags gives no word", tag)
			}
		})
	}
}

// Every key of a set gives its word whatever the order or the number of the
// records.
func TestDKIMReadsEveryRecord(t *testing.T) {
	owner := expName(t, emlDKIMOwner)
	was := emlSet(emlKeyQ)
	for _, n := range []int{16, 17, 20, 100} {
		t.Run(fmt.Sprintf("%d other records", n), func(t *testing.T) {
			var notes []string
			for i := 1; i <= n; i++ {
				notes = append(notes, fmt.Sprintf("note=%d", i))
			}
			keyLast := Weaker(MailDKIM, owner, was, emlSet(append(slices.Clone(notes), emlKeyR)...))
			keyFirst := Weaker(MailDKIM, owner, was, emlSet(append([]string{emlKeyR}, notes...)...))
			if len(keyLast) == 0 {
				t.Errorf("another key after %d other records gives no word", n)
			}
			if !slices.Equal(keyLast, keyFirst) {
				t.Errorf("the words depend on the order of the records: key last %q, key first %q", keyLast, keyFirst)
			}
		})
	}
}

// Another key in a record over 4096 octets still gives a word, as an SPF,
// DMARC or MTA-STS record over the bound does.
func TestDKIMLongRecordGivesAWord(t *testing.T) {
	owner := expName(t, emlDKIMOwner)
	was := emlSet(emlKeyQ)
	head := "v=DKIM1; k=rsa; p=RUZHSA==; n="
	long := head + strings.Repeat("a", 4097-len(head))
	if got := Weaker(MailDKIM, owner, was, emlSet(long)); len(got) == 0 {
		t.Errorf("another key in a record of %d octets gives no word", len(long))
	}
}

// An sp tag that is not valid gives a word: receivers act as if p=none (with a
// rua address) or apply no DMARC policy (RFC 7489 section 6.6.3, item 6).
func TestDMARCInvalidSpGivesAWord(t *testing.T) {
	owner := expName(t, emlDMARCOwner)
	for _, c := range []struct{ name, was, now string }{
		{"no report address", "v=DMARC1; p=reject", "v=DMARC1; p=reject; sp=bogus"},
		{"a report address", "v=DMARC1; p=reject; rua=mailto:a@corp.test", "v=DMARC1; p=reject; sp=bogus; rua=mailto:a@corp.test"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Weaker(MailDMARC, owner, emlSet(c.was), emlSet(c.now)); len(got) == 0 {
				t.Errorf("%q in place of %q gives no word", c.now, c.was)
			}
		})
	}
}

// A DMARC record needs ";" or the end after the version (RFC 7489 section
// 6.4), so "v=DMARC1 p=reject" is no record.
func TestDMARCVersionNeedsSeparator(t *testing.T) {
	owner := expName(t, emlDMARCOwner)
	if got := Weaker(MailDMARC, owner, emlSet("v=DMARC1; p=reject"), emlSet("v=DMARC1 p=reject")); len(got) == 0 {
		t.Errorf(`"v=DMARC1 p=reject" in place of "v=DMARC1; p=reject" gives no word`)
	}
}

// A tag given twice gives a word when the values differ, since a receiver that
// keeps the last value may apply it.
func TestDMARCTagGivenTwice(t *testing.T) {
	owner := expName(t, emlDMARCOwner)
	for _, now := range []string{"v=DMARC1; p=reject; p=none", "v=DMARC1; p=reject; pct=100; pct=0"} {
		t.Run(now, func(t *testing.T) {
			if got := Weaker(MailDMARC, owner, emlSet("v=DMARC1; p=reject"), emlSet(now)); len(got) == 0 {
				t.Errorf("%q gives no word", now)
			}
		})
	}
}

// A term that the grammar of RFC 7208 refuses (a zone in an IPv6 address, a
// domain-spec without a dotted top label, an unknown macro) gives permerror,
// so the record gets the permerror word.
func TestSPFTermsTheGrammarRefuses(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	was := emlSet("v=spf1 mx -all")
	want := []string{emlBadTerm}
	for _, term := range []string{
		"ip6:2001:db8::1%eth0",
		"include:localhost",
		"include:192.0.2.1",
		"exists:%{z}.corp.test",
		"exists:%x.corp.test",
	} {
		t.Run(term, func(t *testing.T) {
			now := "v=spf1 mx -all " + term
			if got := Weaker(MailSPF, owner, was, emlSet(now)); !slices.Equal(got, want) {
				t.Errorf("%q gives %q, want %q", now, got, want)
			}
		})
	}
}

// Removing a fail term that stands before a pass term of another kind gives a
// word, since an a, mx or include term can match the address of an ip4 term
// or of another include; also when the default is fail.
func TestSPFFailTermRemovedBeforeAnotherKind(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	for _, c := range []struct{ name, was, now string }{
		{"ip4 before a", "v=spf1 -ip4:192.0.2.66 a -all", "v=spf1 a -all"},
		{"include before include", "v=spf1 -include:blocked.test include:_spf.provider.test -all", "v=spf1 include:_spf.provider.test -all"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := Weaker(MailSPF, owner, emlSet(c.was), emlSet(c.now)); len(got) == 0 {
				t.Errorf("%q in place of %q gives no word", c.now, c.was)
			}
		})
	}
}

// A CNAME at the owner of a policy is named, and the word does not say that
// there is no record: receivers follow it into another zone.
func TestCNAMEIsNotAMissingRecord(t *testing.T) {
	for _, c := range []struct {
		kind    MailKind
		owner   string
		was     string
		target  string
		missing string
	}{
		{MailSPF, "mail.corp.test.", "v=spf1 a -all", "spf.evil.test.", "no SPF record"},
		{MailDMARC, "_dmarc.corp.test.", "v=DMARC1; p=reject", "dmarc.evil.test.", "no DMARC record"},
		{MailMTASTS, "_mta-sts.corp.test.", "v=STSv1; id=1", "sts.evil.test.", "no MTA-STS record"},
	} {
		t.Run(c.owner, func(t *testing.T) {
			now := []dnswire.RData{emlCNAME(c.target)}
			got := Weaker(c.kind, expName(t, c.owner), emlSet(c.was), now)
			named := false
			for _, w := range got {
				if strings.HasPrefix(w, c.missing) {
					t.Errorf("a CNAME to %s gives %q", c.target, w)
				}
				named = named || strings.Contains(w, c.target)
			}
			if !named {
				t.Errorf("no word names the CNAME target %s: %q", c.target, got)
			}
		})
	}
}

// Weaker joins the words of the sets that it is given, set after set, each
// word once, and caps the whole list once with a true count of the words left
// out.
func TestWeakerSeveralSets(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	was := emlSet("v=spf1 -all")
	record := func(third, from, n int) []dnswire.RData {
		return emlSet("v=spf1 " + mlmTerms(third, from, n) + " -all")
	}
	for _, c := range []struct {
		name string
		now  [][]dnswire.RData
		want []string
	}{
		{"no set", nil, nil},
		{"one set", [][]dnswire.RData{record(0, 1, 3)}, mlmWords(0, 1, 3)},
		{"words of the sets in order", [][]dnswire.RData{record(0, 1, 2), record(1, 1, 2)}, append(mlmWords(0, 1, 2), mlmWords(1, 1, 2)...)},
		{"a word of both sets once", [][]dnswire.RData{record(0, 1, 3), record(0, 2, 3)}, mlmWords(0, 1, 4)},
		{"a set that is not weaker adds nothing", [][]dnswire.RData{record(0, 1, 2), was}, mlmWords(0, 1, 2)},
		{"a first set that is not weaker", [][]dnswire.RData{was, record(0, 1, 2)}, mlmWords(0, 1, 2)},
		{"12 words over two sets stay", [][]dnswire.RData{record(0, 1, 6), record(1, 1, 6)}, append(mlmWords(0, 1, 6), mlmWords(1, 1, 6)...)},
		{"13 words over two sets are capped", [][]dnswire.RData{record(0, 1, 7), record(1, 1, 6)},
			append(append(mlmWords(0, 1, 7), mlmWords(1, 1, 4)...), "and 2 more")},
		{"two sets of 14 words give 11 and a true count", [][]dnswire.RData{record(0, 1, 14), record(1, 1, 14)},
			append(mlmWords(0, 1, 11), "and 17 more")},
		{"words of both sets count once in the cap", [][]dnswire.RData{record(0, 1, 14), emlSet("v=spf1 " + mlmTerms(0, 1, 14) + " -all x=1")},
			append(mlmWords(0, 1, 11), "and 3 more")},
		{"four words of both sets count once in the cap", [][]dnswire.RData{record(0, 1, 14), record(0, 11, 14)},
			append(mlmWords(0, 1, 11), "and 13 more")},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := Weaker(MailSPF, owner, was, c.now...)
			emlWant(t, got, c.want)
			emlCheckWords(t, got)
		})
	}
	t.Run("DMARC, two sets", func(t *testing.T) {
		got := Weaker(MailDMARC, expName(t, emlDMARCOwner), emlSet(emlDMARCBase),
			emlSet("v=DMARC1; p=none"), emlSet("v=DMARC1; p=reject; pct=0"), emlSet("v=DMARC1; p=none; pct=0"))
		emlWant(t, got, []string{"p=none in place of p=reject", "pct=0 in place of pct=100"})
	})
}

// mlmTerms writes n ip4 terms of 10.0.<third>.<from> on.
func mlmTerms(third, from, n int) string {
	return emlTerms(n, func(i int) string { return fmt.Sprintf("ip4:10.0.%d.%d", third, from+i-1) })
}

// mlmWords gives the words for the terms of mlmTerms against a record whose
// default is fail.
func mlmWords(third, from, n int) []string {
	var words []string
	for i := 0; i < n; i++ {
		words = append(words, fmt.Sprintf("ip4:10.0.%d.%d/32 gives pass in place of fail", third, from+i))
	}
	return words
}

// SPFRedirect names the redirect= target of a usable record that has no all
// and a redirect that names one domain.
func TestSPFRedirect(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	tens := emlTerms(10, func(i int) string { return fmt.Sprintf("include:i%d.test", i) })
	for _, c := range []struct {
		name string
		set  []dnswire.RData
		want string // "" when there is none
	}{
		{"redirect alone", emlSet("v=spf1 redirect=r.test"), "r.test."},
		{"redirect after a term", emlSet("v=spf1 mx redirect=r.test"), "r.test."},
		{"redirect before a term", emlSet("v=spf1 redirect=r.test mx"), "r.test."},
		{"redirect after includes", emlSet("v=spf1 include:a.test include:b.test redirect=r.test"), "r.test."},
		{"case and a trailing dot", emlSet("v=SPF1 REDIRECT=R.Test."), "r.test."},
		{"strings joined", []dnswire.RData{emlTXT("v=spf1 redirect=r", ".test")}, "r.test."},
		{"beside another text", emlSet("google-site-verification=x", "v=spf1 redirect=r.test"), "r.test."},
		{"nine lookups and a redirect", emlSet("v=spf1 " + emlTerms(9, func(i int) string { return fmt.Sprintf("include:i%d.test", i) }) + " redirect=r.test"), "r.test."},
		{"all before the redirect", emlSet("v=spf1 -all redirect=r.test"), ""},
		{"all after the redirect", emlSet("v=spf1 redirect=r.test -all"), ""},
		{"a pass all beside the redirect", emlSet("v=spf1 redirect=r.test +all"), ""},
		{"no redirect", emlSet("v=spf1 mx include:a.test"), ""},
		{"exp is no redirect", emlSet("v=spf1 exp=r.test"), ""},
		{"redirect with a macro", emlSet("v=spf1 redirect=_spf.%{d}"), ""},
		{"redirect with a macro in the middle", emlSet("v=spf1 redirect=%{d}.r.test"), ""},
		{"redirect to the root", emlSet("v=spf1 redirect=."), ""},
		{"redirect to a name with no dot", emlSet("v=spf1 redirect=localhost"), ""},
		{"redirect to an empty name", emlSet("v=spf1 redirect="), ""},
		{"an invalid term", emlSet("v=spf1 foo:bar redirect=r.test"), ""},
		{"an invalid term after the redirect", emlSet("v=spf1 redirect=r.test foo:bar"), ""},
		{"redirect given twice", emlSet("v=spf1 redirect=a.test redirect=b.test"), ""},
		{"ten lookups and a redirect", emlSet("v=spf1 " + tens + " redirect=r.test"), ""},
		{"more than 128 terms", emlSet("v=spf1 redirect=r.test " + emlTerms(128, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) })), ""},
		{"a record over 4096 octets", emlSet(emlPad("v=spf1 redirect=r.test x=", 4097)), ""},
		{"two SPF records", emlSet("v=spf1 redirect=r.test", "v=spf1 redirect=s.test"), ""},
		{"two SPF records, one with an all", emlSet("v=spf1 redirect=r.test", "v=spf1 -all"), ""},
		{"no SPF record", emlSet("google-site-verification=x"), ""},
		{"no record", nil, ""},
		{"a longer version", emlSet("v=spf10 redirect=r.test"), ""},
		{"SPF type only", []dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 redirect=r.test"}}}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, ok := SPFRedirect(owner, c.set)
			switch {
			case c.want == "" && ok:
				t.Errorf("SPFRedirect = %q; want none", got.String())
			case c.want != "" && (!ok || got.String() != c.want):
				t.Errorf("SPFRedirect = %q, %v; want %q", got.String(), ok, c.want)
			}
		})
	}
}

// SPFRedirect gives the name that SPFTargets gives last when a redirect is
// the last target.
func TestSPFRedirectIsTheLastTarget(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	set := emlSet("v=spf1 include:a.test redirect=r.test")
	targets := SPFTargets(owner, set)
	got, ok := SPFRedirect(owner, set)
	if !ok || len(targets) == 0 || !targets[len(targets)-1].Equal(got) {
		t.Errorf("SPFRedirect = %q, %v; last of SPFTargets = %q", got.String(), ok, emlNames(targets))
	}
}
