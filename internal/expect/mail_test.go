package expect

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

const emlSeed = 20261117

const (
	emlSPFOwner   = "corp.test."
	emlDMARCOwner = "_dmarc.corp.test."
	emlDKIMOwner  = "s1._domainkey.corp.test."
	emlSTSOwner   = "_mta-sts.corp.test."
)

const (
	emlTailNeutral = ": receivers treat every sender as neutral"
	emlTailPerm    = ": receivers give permerror, so no sender fails"
	emlTailOsk     = ": osk-dns-watcher does not read it and counts every sender as neutral"
	emlNoSPF       = "no SPF record" + emlTailNeutral
	emlBadTerm     = "an SPF term that cannot be read" + emlTailPerm
	emlNoDMARC     = "no DMARC record: receivers apply no DMARC policy"
	emlSTSTail     = ": senders that have not cached the policy send mail without it"
	emlNoSTS       = "no MTA-STS record" + emlSTSTail
	emlBadSTS      = "an MTA-STS record that cannot be read" + emlSTSTail
)

// emlRec builds one TXT record from a text, cut into strings of at most 255
// octets as a zone does.
func emlRec(text string) dnswire.RData {
	var pieces []string
	for len(text) > 255 {
		pieces = append(pieces, text[:255])
		text = text[255:]
	}
	return dnswire.TXT{Strings: append(pieces, text)}
}

// emlTXT builds one TXT record from the given strings as they are.
func emlTXT(pieces ...string) dnswire.RData { return dnswire.TXT{Strings: pieces} }

// emlSet builds a set of TXT records, one for each text.
func emlSet(texts ...string) []dnswire.RData {
	var set []dnswire.RData
	for _, s := range texts {
		set = append(set, emlRec(s))
	}
	return set
}

// emlPad extends prefix with letters to exactly size octets.
func emlPad(prefix string, size int) string {
	return prefix + strings.Repeat("a", size-len(prefix))
}

// emlCheckWords holds the promises of Weaker about every list it gives.
func emlCheckWords(t testing.TB, words []string) {
	t.Helper()
	if len(words) > MaxWords {
		t.Errorf("%d words; want at most %d", len(words), MaxWords)
	}
	seen := map[string]bool{}
	for _, w := range words {
		if len(w) > 240 {
			t.Errorf("word of %d octets: %q", len(w), w)
		}
		for i := 0; i < len(w); i++ {
			if w[i] < 0x20 || w[i] > 0x7E {
				t.Errorf("word %q holds octet 0x%02X", w, w[i])
				break
			}
		}
		if seen[w] {
			t.Errorf("word %q twice in %q", w, words)
		}
		seen[w] = true
	}
}

// emlWant compares a list of words; nil is a different answer from a list.
func emlWant(t testing.TB, got, want []string) {
	t.Helper()
	if want == nil {
		if got != nil {
			t.Errorf("words = %q; want nil", got)
		}
		return
	}
	if !slices.Equal(got, want) {
		t.Errorf("words = %q; want %q", got, want)
	}
}

type emlRow struct {
	name  string
	kind  MailKind
	owner string
	was   []dnswire.RData
	now   []dnswire.RData
	want  []string
	back  bool // the other way gives no words
}

func (r emlRow) rev() emlRow { r.back = true; return r }

func emlS(name string, was, now []dnswire.RData, want ...string) emlRow {
	return emlRow{name: name, kind: MailSPF, owner: emlSPFOwner, was: was, now: now, want: want}
}

func emlD(name string, was, now []dnswire.RData, want ...string) emlRow {
	return emlRow{name: name, kind: MailDMARC, owner: emlDMARCOwner, was: was, now: now, want: want}
}

func emlK(name string, was, now []dnswire.RData, want ...string) emlRow {
	return emlRow{name: name, kind: MailDKIM, owner: emlDKIMOwner, was: was, now: now, want: want}
}

func emlM(name string, was, now []dnswire.RData, want ...string) emlRow {
	return emlRow{name: name, kind: MailMTASTS, owner: emlSTSOwner, was: was, now: now, want: want}
}

// emlTerms writes n terms, one for each call of f, joined by spaces.
func emlTerms(n int, f func(i int) string) string {
	parts := make([]string, n)
	for i := range parts {
		parts[i] = f(i + 1)
	}
	return strings.Join(parts, " ")
}

func emlIP4Words(n int) []string {
	var w []string
	for i := 1; i <= n; i++ {
		w = append(w, fmt.Sprintf("ip4:10.0.0.%d/32 gives pass in place of fail", i))
	}
	return w
}

func emlSPFRows() []emlRow {
	base := emlSet("v=spf1 mx -all")
	rows := []emlRow{
		emlS("RFC 7208 3.3 strings joined with nothing", base, []dnswire.RData{emlTXT("v=spf1 mx", " -all")}).rev(),
		emlS("RFC 7208 3.3 version cut inside", base, []dnswire.RData{emlTXT("v=sp", "f1 mx -", "all")}).rev(),
		emlS("RFC 7208 4.6.1 case", base, emlSet("V=SPF1 MX -ALL")).rev(),
		emlS("RFC 7208 4.6.1 extra spaces", base, emlSet("v=spf1  mx   -all ")).rev(),
		emlS("RFC 7208 4.5 leading space is no record", base, emlSet(" v=spf1 mx -all"), emlNoSPF),
		emlS("RFC 7208 4.6.2 plus written", base, emlSet("v=spf1 +mx -all")).rev(),
		emlS("RFC 7208 5.3 domain-spec of the owner", emlSet("v=spf1 a -all"), emlSet("v=spf1 a:Corp.Test. -all")).rev(),
		emlS("RFC 7208 5.6 host bits and /32", emlSet("v=spf1 ip4:192.0.2.0/24 ip4:192.0.2.1 -all"),
			emlSet("v=spf1 ip4:192.0.2.77/24 ip4:192.0.2.1/32 -all")).rev(),
		emlS("RFC 7208 5.1 include after all", base, emlSet("v=spf1 mx -all include:evil.test")).rev(),
		emlS("RFC 7208 6.2 unknown modifier and exp", base, emlSet("v=spf1 mx -all foo=bar exp=why.corp.test")).rev(),
		emlS("RFC 7208 5.1 softfail all", base, emlSet("v=spf1 mx ~all"), "all gives softfail in place of fail"),
		emlS("RFC 7208 5.1 stricter all", emlSet("v=spf1 mx ~all"), base),
		emlS("RFC 7208 4.7 neutral default", base, emlSet("v=spf1 mx"), "all gives neutral in place of fail"),
		emlS("RFC 7208 5.2 include passes", base, emlSet("v=spf1 mx include:evil.test -all"),
			"include:evil.test gives pass in place of fail"),
		emlS("RFC 7208 5.6 wider prefix", emlSet("v=spf1 ip4:192.0.2.0/25 -all"), emlSet("v=spf1 ip4:192.0.2.0/24 -all"),
			"ip4:192.0.2.0/24 gives pass in place of fail"),
		emlS("RFC 7208 5.6 narrower prefix", emlSet("v=spf1 ip4:192.0.2.0/24 -all"), emlSet("v=spf1 ip4:192.0.2.0/25 -all")),
		emlS("RFC 7208 5.3 a with IPv4 length", emlSet("v=spf1 a -all"), emlSet("v=spf1 a/24 -all"),
			"a:corp.test/24 gives pass in place of fail"),
		emlS("RFC 7208 5.6 a with IPv6 length", emlSet("v=spf1 a -all"), emlSet("v=spf1 a//64 -all"),
			"a:corp.test//64 gives pass in place of fail"),
		emlS("RFC 7208 4.6.2 first match wins", emlSet("v=spf1 -ip4:192.0.2.1 ip4:192.0.2.0/24 -all"),
			emlSet("v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.1 -all"), "ip4:192.0.2.1/32 gives pass in place of fail"),
		emlS("RFC 7208 4.6.2 first match wins, other way", emlSet("v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.1 -all"),
			emlSet("v=spf1 -ip4:192.0.2.1 ip4:192.0.2.0/24 -all")),
		emlS("RFC 7208 4.6.2 fail term removed", emlSet("v=spf1 -include:bad.test mx ~all"), emlSet("v=spf1 mx ~all"),
			"include:bad.test gives softfail in place of fail"),
		emlS("RFC 7208 6.1 redirect in place of all", base, emlSet("v=spf1 mx redirect=evil.test"),
			"all gives the result of redirect=evil.test in place of fail"),
		emlS("RFC 7208 6.1 redirect replaced by all", emlSet("v=spf1 mx redirect=evil.test"), base),
		emlS("RFC 7208 5.1 redirect beside all", base, emlSet("v=spf1 mx -all redirect=evil.test")).rev(),
		emlS("RFC 7208 6.1 redirect before all", emlSet("v=spf1 -all"), emlSet("v=spf1 redirect=evil.test -all")).rev(),
		emlS("RFC 7208 4.5 no record", base, nil, emlNoSPF),
		emlS("RFC 7208 4.5 only another text", base, emlSet("google-site-verification=x"), emlNoSPF),
		emlS("RFC 7208 4.5 SPF type is not read", base, []dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 mx -all"}}}, emlNoSPF),
		emlS("RFC 7208 4.5 other data is not read", base, []dnswire.RData{dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")}}, emlNoSPF),
		emlS("a CNAME is named in place of the word for no record", base, []dnswire.RData{emlCNAME("spf.evil.test.")},
			emlCNAMEWord("spf.evil.test.")),
		emlS("RFC 7208 4.5 two records", base, emlSet("v=spf1 mx -all", "v=spf1 +all"),
			"two or more SPF records"+emlTailPerm),
		emlS("RFC 7208 4.6 first problem in field order: term first", base, emlSet("v=spf1 mx foo:bar redirect=a.test redirect=b.test"), emlBadTerm),
		emlS("RFC 7208 4.6 first problem in field order: redirect twice first", base, emlSet("v=spf1 mx redirect=a.test redirect=b.test foo:bar"),
			"redirect= or exp= given twice"+emlTailPerm),
		emlS("osk-dns-watcher bound 129 terms before the fields are read", base,
			emlSet("v=spf1 foo:bar "+emlTerms(127, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) })+" -all"), "more than 128 SPF terms"+emlTailOsk),
		emlS("osk-dns-watcher bound 4097 octets with two records", base, emlSet(emlPad("v=spf1 mx -all x=", 4097), "v=spf1 +all"),
			"two or more SPF records"+emlTailPerm),
		emlS("osk-dns-watcher bound a text of 5000 octets that is no record", base, emlSet(emlPad("x=", 5000), "v=spf1 mx -all")).rev(),
		emlS("RFC 7208 6 redirect twice", base, emlSet("v=spf1 mx redirect=a.test redirect=b.test"),
			"redirect= or exp= given twice"+emlTailPerm),
		emlS("RFC 7208 6 redirect twice in other case", base, emlSet("v=spf1 mx redirect=a.test REDIRECT=b.test"),
			"redirect= or exp= given twice"+emlTailPerm),
		emlS("RFC 7208 6.2 exp twice", base, emlSet("v=spf1 mx exp=a.test exp=b.test"),
			"redirect= or exp= given twice"+emlTailPerm),
		emlS("RFC 7208 4.5 version with more digits", base, emlSet("v=spf10 +all"), emlNoSPF),
		emlS("RFC 7208 4.5 tab after version", base, emlSet("v=spf1\t+all"), emlNoSPF),
		emlS("RFC 7208 4.5 short version", base, emlSet("v=spf +all"), emlNoSPF),
		emlS("RFC 7208 7 macro as written", emlSet("v=spf1 include:%{d}.spf.corp.test -all"),
			emlSet("v=spf1 include:%{d}.spf.corp.test -all")).rev(),
		emlS("RFC 7208 7 macro letter case", emlSet("v=spf1 include:%{d}.spf.corp.test -all"),
			emlSet("v=spf1 include:%{D}.spf.corp.test -all"), "include:%{D}.spf.corp.test gives pass in place of fail"),
		emlS("RFC 7208 5.1 nothing to lose", emlSet("v=spf1 +all"), emlSet("v=spf1 include:any.test -all")),
		emlS("RFC 7208 7.1 domain of Z and A folds to lower case", emlSet("v=spf1 include:za.test include:az.test -all"),
			emlSet("v=spf1 include:ZA.TEST include:AZ.Test. -all")).rev(),
		emlS("RFC 7208 7.1 domain of Z folded in a word", emlSet("v=spf1 -all"), emlSet("v=spf1 include:ZAZ.TEST -all"),
			"include:zaz.test gives pass in place of fail"),
		emlS("RFC 7208 7.1 domain of A folded in a word", emlSet("v=spf1 -all"), emlSet("v=spf1 include:AZA.Test. -all"),
			"include:aza.test gives pass in place of fail"),
		emlS("RFC 7208 7.1 a and mx domain of Z", emlSet("v=spf1 -all"), emlSet("v=spf1 a:ZZ.Test/24 -all"),
			"a:zz.test/24 gives pass in place of fail", "a:zz.test//128 gives pass in place of fail"),
		emlS("RFC 7208 7.1 redirect domain of Z", emlSet("v=spf1 redirect=zz.test"), emlSet("v=spf1 redirect=ZZ.TEST")).rev(),
		emlS("RFC 7208 7 printable 0x21 in a macro piece", emlSet("v=spf1 -all"), emlSet("v=spf1 include:%{d}!x.test -all"),
			"include:%{d}!x.test gives pass in place of fail"),
		emlS("RFC 7208 7 printable 0x7E in a macro piece", emlSet("v=spf1 -all"), emlSet("v=spf1 include:%{d}~x.test -all"),
			"include:%{d}~x.test gives pass in place of fail"),
		emlS("RFC 7208 6 modifier value of 0x21", base, emlSet("v=spf1 mx -all foo=!")).rev(),
		emlS("RFC 7208 6 modifier value of 0x7E", base, emlSet("v=spf1 mx -all foo=~")).rev(),
		emlS("RFC 7208 4.6.1 modifier value with a control octet", base, emlSet("v=spf1 mx -all foo=a\x01"), emlBadTerm),
		emlS("RFC 7208 4.6.1 modifier value with a DEL octet", base, emlSet("v=spf1 mx -all foo=a\x7f"), emlBadTerm),
		emlS("RFC 7208 5.1 something to lose", emlSet("v=spf1 include:any.test -all"), emlSet("v=spf1 +all"), "all gives pass in place of fail"),
		emlS("RFC 7208 4.7 from no record to pass all", nil, emlSet("v=spf1 +all"), "all gives pass in place of neutral"),
		emlS("RFC 7208 4.7 from no record to fail all", nil, emlSet("v=spf1 -all")),
		emlS("osk-dns-watcher bound 4096 octets accepted", base, emlSet(emlPad("v=spf1 mx -all x=", 4096))).rev(),
		emlS("osk-dns-watcher bound 4097 octets", base, emlSet(emlPad("v=spf1 mx -all x=", 4097)),
			"an SPF record longer than 4096 octets"+emlTailOsk),

		// Qualifiers and results (RFC 7208 4.6.2, 4.7).
		emlS("RFC 7208 4.6.2 fail to neutral", emlSet("v=spf1 -all"), emlSet("v=spf1 ?all"), "all gives neutral in place of fail"),
		emlS("RFC 7208 4.6.2 softfail to neutral", emlSet("v=spf1 ~all"), emlSet("v=spf1 ?all"), "all gives neutral in place of softfail"),
		emlS("RFC 7208 4.6.2 neutral to softfail", emlSet("v=spf1 ?all"), emlSet("v=spf1 ~all")),
		emlS("RFC 7208 4.6.2 pass all to softfail", emlSet("v=spf1 +all"), emlSet("v=spf1 ~all")),
		emlS("RFC 7208 4.6.2 neutral to pass all", emlSet("v=spf1 ?all"), emlSet("v=spf1 +all"), "all gives pass in place of neutral"),
		emlS("RFC 7208 4.6.2 pass term to neutral term", emlSet("v=spf1 ip4:192.0.2.1 -all"), emlSet("v=spf1 ?ip4:192.0.2.1 -all")),
		emlS("RFC 7208 4.6.2 softfail term to pass term", emlSet("v=spf1 ~ip4:192.0.2.1 -all"), emlSet("v=spf1 ip4:192.0.2.1 -all"),
			"ip4:192.0.2.1/32 gives pass in place of softfail"),

		// The order of the words and the atoms (RFC 7208 5.1 to 5.7).
		emlS("RFC 7208 5.1 all, then atoms of now in term order", emlSet("v=spf1 -all"),
			emlSet("v=spf1 ip4:192.0.2.1 include:evil.test ~all"),
			"all gives softfail in place of fail",
			"ip4:192.0.2.1/32 gives pass in place of fail",
			"include:evil.test gives pass in place of fail"),
		emlS("RFC 7208 5.1 an atom of was gives a word", emlSet("v=spf1 -ip4:192.0.2.1 +all"), emlSet("v=spf1 ~all"),
			"ip4:192.0.2.1/32 gives softfail in place of fail"),
		emlS("RFC 7208 5.1 a term lost from was", emlSet("v=spf1 ip4:192.0.2.1 -all"), emlSet("v=spf1 -all")),
		emlS("RFC 7208 5.6 same atom twice gives one word", emlSet("v=spf1 -all"),
			emlSet("v=spf1 ip4:192.0.2.1 ip4:192.0.2.1/32 -all"), "ip4:192.0.2.1/32 gives pass in place of fail"),
		emlS("RFC 7208 5.2 include only in was", emlSet("v=spf1 include:a.test -all"), emlSet("v=spf1 include:b.test -all"),
			"include:b.test gives pass in place of fail"),
		emlS("RFC 7208 5.6 prefix pass over a narrower fail", emlSet("v=spf1 -ip4:192.0.2.0/25 ip4:192.0.2.0/24 -all"),
			emlSet("v=spf1 ip4:192.0.2.0/24 -all"), "ip4:192.0.2.0/25 gives pass in place of fail"),
		emlS("RFC 7208 5.6 narrow fail before wide pass", emlSet("v=spf1 ip4:192.0.2.0/24 -all"),
			emlSet("v=spf1 -ip4:192.0.2.0/25 ip4:192.0.2.0/24 -all")),

		// Atoms of ip4, ip6, a, mx, ptr and exists.
		emlS("RFC 7208 5.6 prefix is masked", emlSet("v=spf1 -all"), emlSet("v=spf1 ip4:192.0.2.77/24 -all"),
			"ip4:192.0.2.0/24 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip4 /0 contains all", emlSet("v=spf1 ip4:192.0.2.0/24 -all"), emlSet("v=spf1 ip4:0.0.0.0/0 -all"),
			"ip4:0.0.0.0/0 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip4 /0 masks every host bit", emlSet("v=spf1 -all"), emlSet("v=spf1 ip4:192.0.2.1/0 -all"),
			"ip4:0.0.0.0/0 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip6 masked", emlSet("v=spf1 -all"), emlSet("v=spf1 ip6:2001:DB8::1/64 -all"),
			"ip6:2001:db8::/64 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip6 without length", emlSet("v=spf1 -all"), emlSet("v=spf1 ip6:2001:db8::1 -all"),
			"ip6:2001:db8::1/128 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip6 wider prefix", emlSet("v=spf1 ip6:2001:db8:1::/48 -all"), emlSet("v=spf1 ip6:2001:db8::/32 -all"),
			"ip6:2001:db8::/32 gives pass in place of fail"),
		emlS("RFC 7208 5.6 ip6 narrower prefix", emlSet("v=spf1 ip6:2001:db8::/32 -all"), emlSet("v=spf1 ip6:2001:db8:1::/48 -all")),
		emlS("RFC 7208 5.6 ip4 does not contain ip6", emlSet("v=spf1 ip4:0.0.0.0/0 -all"), emlSet("v=spf1 ip6:::/0 -all"),
			"ip6:::/0 gives pass in place of fail"),
		emlS("RFC 7208 5.4 mx with length", emlSet("v=spf1 -all"), emlSet("v=spf1 mx/24 -all"),
			"mx:corp.test/24 gives pass in place of fail", "mx:corp.test//128 gives pass in place of fail"),
		emlS("RFC 7208 5.4 mx with both lengths", emlSet("v=spf1 -all"), emlSet("v=spf1 mx:Mail.Corp.Test./24//64 -all"),
			"mx:mail.corp.test/24 gives pass in place of fail", "mx:mail.corp.test//64 gives pass in place of fail"),
		emlS("RFC 7208 5.3 a with no length", emlSet("v=spf1 -all"), emlSet("v=spf1 a -all"),
			"a:corp.test/32 gives pass in place of fail", "a:corp.test//128 gives pass in place of fail"),
		emlS("RFC 7208 5.3 a narrower", emlSet("v=spf1 a/24 -all"), emlSet("v=spf1 a -all")),
		emlS("RFC 7208 5.3 a IPv6 wider", emlSet("v=spf1 a//96 -all"), emlSet("v=spf1 a//64 -all"),
			"a:corp.test//64 gives pass in place of fail"),
		emlS("RFC 7208 5.3 a of another domain", emlSet("v=spf1 a:other.test -all"), emlSet("v=spf1 a:third.test -all"),
			"a:third.test/32 gives pass in place of fail", "a:third.test//128 gives pass in place of fail"),
		emlS("RFC 7208 5.3 a does not contain mx", emlSet("v=spf1 a -all"), emlSet("v=spf1 mx -all"),
			"mx:corp.test/32 gives pass in place of fail", "mx:corp.test//128 gives pass in place of fail"),
		emlS("RFC 7208 5.3 default domain is the owner", emlRowsOwnerWas(), emlRowsOwnerNow(),
			"a:corp.test/32 gives pass in place of fail", "a:corp.test//128 gives pass in place of fail"),
		emlS("RFC 7208 5.5 ptr", emlSet("v=spf1 -all"), emlSet("v=spf1 ptr -all"), "ptr:corp.test gives pass in place of fail"),
		emlS("RFC 7208 5.5 ptr with domain", emlSet("v=spf1 -all"), emlSet("v=spf1 ptr:Other.Test. -all"),
			"ptr:other.test gives pass in place of fail"),
		emlS("RFC 7208 5.7 exists with macro", emlSet("v=spf1 -all"), emlSet("v=spf1 exists:%{i}._spf.corp.test -all"),
			"exists:%{i}._spf.corp.test gives pass in place of fail"),
		emlS("RFC 7208 7.1 include lowercased, no trailing dot", emlSet("v=spf1 -all"), emlSet("v=spf1 include:Evil.TEST. -all"),
			"include:evil.test gives pass in place of fail"),

		// Redirect against the other results (RFC 7208 6.1).
		emlS("RFC 7208 6.1 redirect against softfail", emlSet("v=spf1 ~all"), emlSet("v=spf1 redirect=r.test"),
			"all gives the result of redirect=r.test in place of softfail"),
		emlS("RFC 7208 6.1 softfail against redirect", emlSet("v=spf1 redirect=r.test"), emlSet("v=spf1 ~all"),
			"all gives softfail in place of the result of redirect=r.test"),
		emlS("RFC 7208 6.1 redirect against neutral", emlSet("v=spf1 mx"), emlSet("v=spf1 mx redirect=r.test"),
			"all gives the result of redirect=r.test in place of neutral"),
		emlS("RFC 7208 6.1 neutral against redirect", emlSet("v=spf1 mx redirect=r.test"), emlSet("v=spf1 mx"),
			"all gives neutral in place of the result of redirect=r.test"),
		emlS("RFC 7208 6.1 redirect above pass", emlSet("v=spf1 +all"), emlSet("v=spf1 redirect=r.test")),
		emlS("RFC 7208 6.1 pass below redirect", emlSet("v=spf1 redirect=r.test"), emlSet("v=spf1 +all"),
			"all gives pass in place of the result of redirect=r.test"),
		emlS("RFC 7208 6.1 same redirect", emlSet("v=spf1 redirect=r.test"), emlSet("v=spf1 REDIRECT=R.Test.")).rev(),
		emlS("RFC 7208 6.1 another redirect", emlSet("v=spf1 redirect=a.test"), emlSet("v=spf1 redirect=b.test"),
			"all gives the result of redirect=b.test in place of the result of redirect=a.test"),
		emlS("RFC 7208 7 redirect with macro", emlSet("v=spf1 -all"), emlSet("v=spf1 redirect=_spf.%{d}"),
			"all gives the result of redirect=_spf.%{d} in place of fail"),
		emlS("RFC 7208 6.1 term against redirect default", emlSet("v=spf1 redirect=a.test"), emlSet("v=spf1 ip4:192.0.2.1 redirect=a.test"),
			"ip4:192.0.2.1/32 gives pass in place of the result of redirect=a.test"),

		// A record with a problem is read as no terms and neutral (RFC 7208 4.6, 4.7).
		emlS("RFC 7208 4.6 problem in was", emlSet("v=spf1 foo:bar"), base,
			"mx:corp.test/32 gives pass in place of neutral", "mx:corp.test//128 gives pass in place of neutral"),
		emlS("RFC 7208 4.6 problem in now, nothing weaker", emlSet("v=spf1 +all"), emlSet("v=spf1 foo:bar")),
		emlS("RFC 7208 4.6 problem in now, neutral was", emlSet("v=spf1 mx"), emlSet("v=spf1 foo:bar")),
		emlS("RFC 7208 4.6 problem in now, softfail was", emlSet("v=spf1 ~all"), emlSet("v=spf1 foo:bar"),
			"an SPF term that cannot be read"+emlTailPerm),
		emlS("RFC 7208 4.5 no record on both sides", nil, emlSet("google-site-verification=x")),
		emlS("RFC 7208 4.5 empty set both sides", nil, nil),

		// Bounds: terms and lookups (RFC 7208 4.6.4 and osk-dns-watcher bounds).
		emlS("RFC 7208 4.6.4 ten lookups", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(10, func(i int) string { return fmt.Sprintf("-include:i%d.test", i) })+" -all")),
		emlS("RFC 7208 4.6.4 ten lookups, words", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(10, func(i int) string { return fmt.Sprintf("include:i%d.test", i) })+" -all"),
			func() []string {
				var w []string
				for i := 1; i <= 10; i++ {
					w = append(w, fmt.Sprintf("include:i%d.test gives pass in place of fail", i))
				}
				return w
			}()...),
		emlS("RFC 7208 4.6.4 eleven lookups", base,
			emlSet("v=spf1 "+emlTerms(11, func(i int) string { return fmt.Sprintf("include:a%d.test", i) })+" -all"),
			"more than 10 SPF terms that need a DNS lookup"+emlTailPerm),
		emlS("RFC 7208 4.6.4 ten lookups of five kinds", emlSet("v=spf1 -all"),
			emlSet("v=spf1 -a:a1.test -a:a2.test -mx:m1.test -mx:m2.test -ptr:p1.test -ptr:p2.test -exists:e1.test -exists:e2.test -include:i1.test -include:i2.test -all")),
		emlS("RFC 7208 4.6.4 eleven lookups of five kinds", emlSet("v=spf1 -all"),
			emlSet("v=spf1 -a:a1.test -a:a2.test -mx:m1.test -mx:m2.test -ptr:p1.test -ptr:p2.test -exists:e1.test -exists:e2.test -include:i1.test -include:i2.test -a:a3.test -all"),
			"more than 10 SPF terms that need a DNS lookup"+emlTailPerm),
		emlS("RFC 7208 4.6.4 ip and all are no lookups", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(10, func(i int) string { return fmt.Sprintf("-include:i%d.test", i) })+
				" -ip4:192.0.2.1 -ip6:2001:db8::1 -all -all")),
		emlS("RFC 7208 4.6.4 includes after all are no lookups", emlSet("v=spf1 -all"),
			emlSet("v=spf1 -all "+emlTerms(11, func(i int) string { return fmt.Sprintf("include:i%d.test", i) }))),
		emlS("RFC 7208 4.6.4 nine lookups and a redirect", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(9, func(i int) string { return fmt.Sprintf("-include:i%d.test", i) })+" redirect=r.test"),
			"all gives the result of redirect=r.test in place of fail"),
		emlS("RFC 7208 4.6.4 ten lookups and a redirect", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(10, func(i int) string { return fmt.Sprintf("-include:i%d.test", i) })+" redirect=r.test"),
			"more than 10 SPF terms that need a DNS lookup"+emlTailPerm),
		emlS("RFC 7208 4.6.4 ten lookups and a redirect beside all", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(10, func(i int) string { return fmt.Sprintf("-include:i%d.test", i) })+" redirect=r.test -all")),
		emlS("osk-dns-watcher bound 128 terms", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(127, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) })+" -all"),
			append(func() []string {
				var w []string
				for i := 1; i <= 11; i++ {
					w = append(w, fmt.Sprintf("ip4:10.1.%d.1/32 gives pass in place of fail", i))
				}
				return w
			}(), "and 116 more")...),
		emlS("osk-dns-watcher bound 129 terms", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(128, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) })+" -all"),
			"more than 128 SPF terms"+emlTailOsk),
		emlS("osk-dns-watcher bound 128 terms with blanks", emlSet("v=spf1 -all"),
			emlSet("v=spf1   "+emlTerms(128, func(int) string { return "-all   " })+" -all"), "more than 128 SPF terms"+emlTailOsk)}
	// The cap on the words: 12 words stay, 13 give 11 and a count.
	rows = append(rows,
		emlS("cap: 12 words stay", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(12, func(i int) string { return fmt.Sprintf("ip4:10.0.0.%d", i) })+" -all"), emlIP4Words(12)...),
		emlS("cap: 13 words give 11 and a count", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(13, func(i int) string { return fmt.Sprintf("ip4:10.0.0.%d", i) })+" -all"),
			append(emlIP4Words(11), "and 2 more")...),
		emlS("cap: duplicates count once", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(13, func(i int) string { return fmt.Sprintf("ip4:10.0.0.%d ip4:10.0.0.%d/32", i, i) })+" -all"),
			append(emlIP4Words(11), "and 2 more")...),
		emlS("cap: 12 distinct after duplicates", emlSet("v=spf1 -all"),
			emlSet("v=spf1 "+emlTerms(12, func(i int) string { return fmt.Sprintf("ip4:10.0.0.%d ip4:10.0.0.%d/32", i, i) })+" -all"),
			emlIP4Words(12)...),
	)
	rows = append(rows, emlSPFWordCutRows()...)
	rows = append(rows, emlSPFFieldRows()...)
	rows = append(rows, emlSPFKeptRows()...)
	rows = append(rows, emlSPFCNAMERows()...)
	return rows
}

// emlCNAMEWord is the word for a CNAME at the owner of a policy that is not
// DKIM.
func emlCNAMEWord(target string) string {
	return "a CNAME to " + target + ": another zone holds the record, and osk-dns-watcher does not read it"
}

// emlSPFCNAMERows: a CNAME hands the record to another zone.
func emlSPFCNAMERows() []emlRow {
	base := emlSet("v=spf1 mx -all")
	cname := []dnswire.RData{emlCNAME("spf.evil.test.")}
	return []emlRow{
		emlS("CNAME in place of a record names the CNAME", base, cname, emlCNAMEWord("spf.evil.test.")),
		emlS("CNAME in place of a record that gives no weaker word gives none", emlSet("v=spf1 +all"), cname),
		emlS("CNAME in place of a record: the target is in lower case", base, []dnswire.RData{emlCNAME("SPF.Evil.TEST.")},
			emlCNAMEWord("spf.evil.test.")),
		emlS("CNAME in place of a CNAME gives no word", cname, cname).rev(),
		emlS("a CNAME changed to another CNAME gives no word", cname, []dnswire.RData{emlCNAME("other.evil.test.")}),
		emlS("the same CNAME in other case gives no word", cname, []dnswire.RData{emlCNAME("SPF.EVIL.test.")}).rev(),
		emlS("a CNAME beside a record: only the CNAME counts", base, append(emlSet("v=spf1 +all"), cname...),
			emlCNAMEWord("spf.evil.test.")),
		emlS("CNAME as was reads as no record", cname, emlSet("v=spf1 +all"), "all gives pass in place of neutral"),
		emlS("two CNAME targets: in octet order", base,
			[]dnswire.RData{emlCNAME("b.evil.test."), emlCNAME("a.evil.test.")},
			emlCNAMEWord("a.evil.test."), emlCNAMEWord("b.evil.test.")),
		emlS("two CNAME targets: each once", base,
			[]dnswire.RData{emlCNAME("b.evil.test."), emlCNAME("A.evil.test."), emlCNAME("B.EVIL.test.")},
			emlCNAMEWord("a.evil.test."), emlCNAMEWord("b.evil.test.")),
	}
}

// emlSPFKeptRows: a term of another kind can match the senders of an atom
// before the term that holds it (an a, mx or include term may meet an ip4
// address), so removing a term that is neither pass nor all gives a word.
func emlSPFKeptRows() []emlRow {
	const kept = " no longer always gets "
	const tail = ": another term may let it pass"
	return []emlRow{
		emlS("kept: a fail term removed with nothing else gives no word", emlSet("v=spf1 -ip4:192.0.2.66 -all"), emlSet("v=spf1 -all")).rev(),
		emlS("kept: a fail term removed before an a term", emlSet("v=spf1 -ip4:192.0.2.66 a -all"), emlSet("v=spf1 a -all"),
			"ip4:192.0.2.66/32"+kept+"fail"+tail),
		emlS("kept: a softfail term removed before an a term", emlSet("v=spf1 ~ip4:192.0.2.66 -all"), emlSet("v=spf1 a -all"),
			"a:corp.test/32 gives pass in place of fail", "a:corp.test//128 gives pass in place of fail",
			"ip4:192.0.2.66/32"+kept+"softfail"+tail),
		emlS("kept: a neutral term removed before an a term", emlSet("v=spf1 ?ip4:192.0.2.66 -all"), emlSet("v=spf1 a -all"),
			"a:corp.test/32 gives pass in place of fail", "a:corp.test//128 gives pass in place of fail",
			"ip4:192.0.2.66/32"+kept+"neutral"+tail),
		emlS("kept: a fail term removed before an include term",
			emlSet("v=spf1 -include:blocked.test include:_spf.provider.test -all"), emlSet("v=spf1 include:_spf.provider.test -all"),
			"include:blocked.test"+kept+"fail"+tail),
		emlS("kept: all to softfail gives the words of all and of the atom, no third",
			emlSet("v=spf1 -ip4:192.0.2.66 -all"), emlSet("v=spf1 ~all"),
			"all gives softfail in place of fail", "ip4:192.0.2.66/32 gives softfail in place of fail"),
		emlS("kept: the other pass term has an address of its own",
			emlSet("v=spf1 -ip4:192.0.2.66 ip4:198.51.100.0/24 -all"), emlSet("v=spf1 ip4:198.51.100.0/24 -all"),
			"ip4:192.0.2.66/32"+kept+"fail"+tail),
		emlS("kept: the term that stays is a pass term of the same atom",
			emlSet("v=spf1 -ip4:192.0.2.66 ip4:192.0.2.0/24 -all"), emlSet("v=spf1 ip4:192.0.2.0/24 -all"),
			"ip4:192.0.2.66/32 gives pass in place of fail"),
		emlS("kept: a record against itself, a fail address inside a pass prefix",
			emlSet("v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.1 -all"), emlSet("v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.1 -all")).rev(),
		emlS("kept: all gets its word when no other word came",
			emlSet("v=spf1 -all"), emlSet("v=spf1 -ip4:10.0.0.0/8 ?ip4:10.1.1.1 -all"),
			"all"+kept+"fail"+tail),
		emlS("kept: all gets no word when another came",
			emlSet("v=spf1 -all"), emlSet("v=spf1 ?ip4:10.1.1.1 -all"),
			"ip4:10.1.1.1/32 gives neutral in place of fail"),
		emlS("kept: all gets no word when the least result stays",
			emlSet("v=spf1 -all"), emlSet("v=spf1 -ip4:10.0.0.0/8 -ip4:10.1.1.1 -all")).rev(),
		emlS("kept: a redirect default in now gives the word of all and none of the atom",
			emlSet("v=spf1 -ip4:192.0.2.66 -all"), emlSet("v=spf1 -ip4:192.0.2.66 redirect=r.test"),
			"all gives the result of redirect=r.test in place of fail"),
		emlS("kept: a redirect default in both, another fail term added",
			emlSet("v=spf1 -ip4:192.0.2.66 redirect=r.test"), emlSet("v=spf1 -ip4:192.0.2.66 -ip4:192.0.2.67 redirect=r.test")),
	}
}

func emlRowsOwnerWas() []dnswire.RData { return emlSet("v=spf1 a:other.test -all") }
func emlRowsOwnerNow() []dnswire.RData { return emlSet("v=spf1 a -all") }

// emlSPFWordCutRows: a word of 240 octets stays, one of 241 is cut to 237 and "...".
func emlSPFWordCutRows() []emlRow {
	const tail = " gives pass in place of fail"
	// A domain-spec with a macro is not a name, so it can be as long as the
	// record allows.
	mk := func(n int) (string, string) {
		d := "%{d}" + strings.Repeat("a", n-len("include:%{d}.test")-len(tail)) + ".test"
		return "include:" + d, "include:" + d + tail
	}
	atom240, word240 := mk(240)
	atom241, word241 := mk(241)
	atom300, word300 := mk(300)
	// A name of 204 octets in labels of 60: the word is 240 octets.
	name := strings.Repeat(strings.Repeat("a", 60)+".", 3) + strings.Repeat("b", 21)
	return []emlRow{
		emlS("word of 240 octets from a long name is whole", emlSet("v=spf1 -all"), emlSet("v=spf1 include:"+name+" -all"),
			"include:"+name+tail),
		emlS("word of 240 octets is whole", emlSet("v=spf1 -all"), emlSet("v=spf1 "+atom240+" -all"), word240),
		emlS("word of 241 octets is cut", emlSet("v=spf1 -all"), emlSet("v=spf1 "+atom241+" -all"), word241[:237]+"..."),
		emlS("word of 300 octets is cut", emlSet("v=spf1 -all"), emlSet("v=spf1 "+atom300+" -all"), word300[:237]+"..."),
	}
}

// emlSPFFieldRows: every field is checked, also after all (RFC 7208 4.6).
func emlSPFFieldRows() []emlRow {
	var rows []emlRow
	base := emlSet("v=spf1 mx -all")
	valid := []string{"foo=bar", "foo=", "x-y_z.1=v", "ip4=1", "FOO=Bar", "ip4:0.0.0.0/0", "ip4:192.0.2.1/32", "ip6:::1/128", "ip6:2001:db8::1",
		"a/0", "a//0", "a/32//128", "mx:x.test/24//64", "ptr", "ptr:x.test.", "exists:%{i}.x.test", "include:%{d}", "?all", "-a", "~mx",
		"redirect=x.test", "exp=%{d}.x.test", "ip6:::/0", "a:x.test//128", "+ip4:192.0.2.0/24"}
	// The domain-spec grammar (RFC 7208 7.1): each macro form; a macro or a
	// toplabel at the end; an IPv6 address without a zone.
	valid = append(valid, "include:a%%b.test", "include:a%_b.test", "include:a%-b.test", "include:%{d}.x.test", "include:%{d}}.x.test",
		"include:%{d1}.x.test", "include:%{d0}.x.test", "include:%{d12}.x.test", "include:%{dr}.x.test", "include:%{dR}.x.test",
		"include:%{d2r}.x.test", "include:%{d2r.-}.x.test",
		"include:%{d.}.x.test", "include:%{d-}.x.test", "include:%{d+}.x.test", "include:%{d,}.x.test", "include:%{d/}.x.test",
		"include:%{d_}.x.test", "include:%{d=}.x.test", "include:%{d.-+,/_=}.x.test",
		"include:%{s}.x.test", "include:%{l}.x.test", "include:%{o}.x.test", "include:%{i}.x.test", "include:%{p}.x.test",
		"include:%{h}.x.test", "include:%{c}.x.test", "include:%{r}.x.test", "include:%{t}.x.test", "include:%{v}.x.test",
		"include:%{S}.x.test", "include:%{L}.x.test", "include:%{O}.x.test", "include:%{D}.x.test", "include:%{I}.x.test",
		"include:%{P}.x.test", "include:%{H}.x.test", "include:%{C}.x.test", "include:%{R}.x.test", "include:%{T}.x.test",
		"include:%{V}.x.test",
		"include:%{d}%{d}.x.test", "include:%{l}%%%{d2r.}.x.test", "include:x.%{d}", "include:x%%", "include:x.%_", "include:x.%-",
		"include:x.%{d2}", "exists:%{l1r+-}.%{d}",
		"include:x.com", "include:x.c0m", "include:x.a-b", "include:x.a--b", "include:x.1a", "include:x.a1", "include:x.1-1",
		"include:x.com.", "include:x.Com", "redirect=x.com", "mx:x.com", "a:x.a-b/24", "ptr:x.com.",
		"ip6:::ffff:192.0.2.1", "ip6:fe80::1", "ip6:fe80::/10")
	for _, f := range valid {
		rows = append(rows, emlS("RFC 7208 4.6 valid field "+f, base, emlSet("v=spf1 mx -all "+f)).rev())
	}
	bad := []string{"foo:bar", "ip4:300.0.0.1", "ip4:192.0.2.0/33", "a/024", "ip4:192.0.2.1/024", "ip6:2001:db8::/129", "ip6:192.0.2.1",
		"ip4:2001:db8::1", "ip4:::ffff:192.0.2.1", "ip4", "ip4:", "ip6:", "all:x", "all/24", "-", "+", "include", "include:", "exists", "exists:",
		"a:", "a/33", "a//129", "a//64/24", "ptr/24", "mx:bad..name", "include:bad..name", "redirect=", "exp=", "exp=a..b", "redirect=bad..name",
		"1foo=bar", "\x7f", "\x01", "caf\xc3\xa9", "ip4:192.0.2.1/-1", "a/x", "?", "~~all", "*all"}
	bad = append(bad, "ip6:2001:db8::1%eth0", "ip6:fe80::1%eth0/64", "ip6:fe80::1%1", "ip6:fe80::1%", "ip4:192.0.2.1%eth0",
		// A macro that is not a macro-expand.
		"include:%", "include:x%", "include:%.x.test", "include:%x.x.test", "include:%{z}.x.test", "include:%{d.x.test", "include:%{}.x.test",
		"include:%{d!}.x.test", "include:%{d1x}.x.test", "include:%{dr1}.x.test", "include:%{rd}.x.test",
		"include:%{d}%.x.test", "include:%{d}%x", "include:%{%d}.x.test", "include:%{{d}}.x.test",
		"include:%{D!}.x.test", "include:%{d~}.x.test", "include:%{d:}.x.test", "include:%{d*}.x.test", "include:%{1d}.x.test",
		"exists:%{z}.corp.test", "exists:%x.corp.test", "exp=%{z}.x.test", "redirect=%x", "a:%{z}.x.test",
		// A domain-spec that does not end in a macro-expand or in a dot and a toplabel.
		"include:localhost", "include:192.0.2.1", "include:com", "include:x.123", "include:x.-ab", "include:x.ab-", "include:x.-",
		"include:x.1--", "include:x.a_b", "include:x.com..", "include:x.", "include:.", "include:.com", "include:x..com",
		"include:%{d}.", "include:%{d}x", "include:x.%{d}x", "include:%{d}.123", "include:%{d}.-ab",
		"exists:localhost", "redirect=localhost", "exp=localhost", "a:localhost", "mx:localhost", "ptr:localhost", "redirect=.", "a:x.123/24")
	for _, f := range bad {
		rows = append(rows, emlS("RFC 7208 4.6 invalid field "+strings.ToValidUTF8(fmt.Sprintf("%q", f), "?"), base, emlSet("v=spf1 mx -all "+f), emlBadTerm))
	}
	rows = append(rows, emlS("RFC 7208 4.6 tab between terms", base, emlSet("v=spf1 mx\t-all"), emlBadTerm))
	rows = append(rows, emlS("RFC 7208 4.6 invalid field before all", base, emlSet("v=spf1 foo:bar mx -all"), emlBadTerm))
	return rows
}

func TestMailPolicyConformance(t *testing.T) {
	var rows []emlRow
	rows = append(rows, emlSPFRows()...)
	rows = append(rows, emlDMARCRows()...)
	rows = append(rows, emlDKIMRows()...)
	rows = append(rows, emlSTSRows()...)
	names := map[string]bool{}
	for _, r := range rows {
		key := fmt.Sprintf("%d %s", r.kind, r.name)
		if names[key] {
			t.Fatalf("two rows named %q", r.name)
		}
		names[key] = true
		t.Run(r.name, func(t *testing.T) {
			owner := expName(t, r.owner)
			got := Weaker(r.kind, owner, r.was, r.now)
			emlWant(t, got, r.want)
			emlCheckWords(t, got)
			emlWant(t, Weaker(r.kind, owner, r.was, r.now), got)
			if r.back {
				if back := Weaker(r.kind, owner, r.now, r.was); back != nil {
					t.Errorf("the other way: words = %q; want nil", back)
				}
			}
			if self := Weaker(r.kind, owner, r.now, r.now); self != nil {
				t.Errorf("now against itself: words = %q; want nil", self)
			}
		})
	}
}

const emlDMARCBase = "v=DMARC1; p=reject"

func emlDMARCRows() []emlRow {
	was := emlSet(emlDMARCBase)
	off := "receivers apply no DMARC policy"
	rows := []emlRow{
		emlD("RFC 7489 6.4 no spaces", was, emlSet("v=DMARC1;p=reject")).rev(),
		emlD("RFC 7489 6.3 spaces and case", was, emlSet("v = DMARC1 ; P = Reject ;")).rev(),
		emlD("RFC 7489 6.3 strings joined", was, []dnswire.RData{emlTXT("v=DMARC1; ", "p=reject")}).rev(),
		emlD("RFC 7489 6.3 defaults and unknown tags", was, emlSet("v=DMARC1; p=reject; adkim=r; aspf=r; pct=100; fo=1; foo=bar")).rev(),
		emlD("RFC 7489 6.3 defaults, psd, t and np", was, emlSet("v=DMARC1; p=reject; psd=u; t=n; ri=86400; rf=afrf")).rev(),
		emlD("RFC 7489 6.4 version then a space and a tag is no record", was, emlSet("v=DMARC1 p=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 version then spaces and a semicolon", was, emlSet("v=DMARC1   ; p=reject")).rev(),
		emlD("RFC 7489 6.4 version then a tab and a semicolon", was, emlSet("v=DMARC1\t;p=reject")).rev(),
		emlD("RFC 7489 6.4 version then spaces and the end", was, emlSet("v=DMARC1   "), "no valid p= and no report address: "+off),
		emlD("RFC 7489 6.4 version then a tab and a tag is no record", was, emlSet("v=DMARC1\tp=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 version with blanks around the equal sign then a tag is no record", was, emlSet("v = DMARC1 p=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 version then a tab and the end", was, emlSet("v=DMARC1\t"), "no valid p= and no report address: "+off),
		emlD("RFC 7489 6.3 part without equal sign", was, emlSet("v=DMARC1; p=reject; garbage; ;")).rev(),
		emlD("RFC 7489 6.3 quarantine", was, emlSet("v=DMARC1; p=quarantine"), "p=quarantine in place of p=reject"),
		emlD("RFC 7489 6.3 none in capitals", was, emlSet("v=DMARC1; p=NONE"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.3 stricter p", emlSet("v=DMARC1; p=none"), was),
		emlD("RFC 7489 6.3 quarantine to reject", emlSet("v=DMARC1; p=quarantine"), was),
		emlD("RFC 7489 6.3 reject to none", was, emlSet("v=DMARC1; p=none"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.3 quarantine to none", emlSet("v=DMARC1; p=quarantine"), emlSet("v=DMARC1; p=none"), "p=none in place of p=quarantine"),
		emlD("RFC 7489 6.3 p given twice: the first value applies and a word says the other may", was, emlSet("v=DMARC1; p=none; p=reject"),
			"p=none in place of p=reject", emlTwice("p")),
		emlD("RFC 7489 6.3 p given twice with a stricter first value still gets the word", emlSet("v=DMARC1; p=none"), emlSet("v=DMARC1; p=reject; p=none"),
			emlTwice("p")),
		emlD("RFC 7489 6.3 sp", was, emlSet("v=DMARC1; p=reject; sp=none"), "sp=none in place of sp=reject"),
		emlD("RFC 7489 6.3 sp quarantine", was, emlSet("v=DMARC1; p=reject; sp=quarantine"), "sp=quarantine in place of sp=reject"),
		emlD("RFC 7489 6.3 sp stricter", emlSet("v=DMARC1; p=reject; sp=none"), was),
		emlD("RFC 7489 6.6.3 sp that is not valid and no report address turns the record off", emlSet("v=DMARC1; p=reject; sp=reject"),
			emlSet("v=DMARC1; p=reject; sp=bogus"), emlBadSP),
		emlD("RFC 7489 6.6.3 sp that is not valid with a mailto address reads as p=none", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"),
			emlSet(emlDMARCBase+"; sp=bogus; rua=mailto:a@corp.test"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.6.3 sp that is not valid with a mailto address, sp written before", emlSet(emlDMARCBase+"; sp=reject; rua=mailto:a@corp.test"),
			emlSet(emlDMARCBase+"; sp=bogus; rua=mailto:a@corp.test"), "p=none in place of p=reject", "sp=none in place of sp=reject"),
		emlD("RFC 7489 6.6.3 sp that is not valid with a mailto address in capitals", emlSet(emlDMARCBase+"; rua=MAILTO:a@corp.test"),
			emlSet(emlDMARCBase+"; sp=bogus; rua=MAILTO:a@corp.test"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.6.3 sp that is not valid with a report address that is not mailto", was,
			emlSet(emlDMARCBase+"; sp=bogus; rua=https://r.test/x"), emlBadSP),
		emlD("RFC 7489 6.6.3 sp that is not valid with a mailto address only in ruf", was,
			emlSet(emlDMARCBase+"; sp=bogus; ruf=mailto:a@corp.test"), emlBadSP),
		emlD("RFC 7489 6.6.3 sp that is empty is not valid", was, emlSet(emlDMARCBase+"; sp="), emlBadSP),
		emlD("RFC 7489 6.6.3 sp in capitals that is not valid", was, emlSet(emlDMARCBase+"; SP=bogus"), emlBadSP),
		emlD("RFC 7489 6.6.3 p and sp that are not valid give the reason of p", was, emlSet("v=DMARC1; p=bogus; sp=bogus"),
			"no valid p= and no report address: "+off),
		emlD("RFC 7489 6.6.3 sp that is not valid after a record that was off", emlSet("v=DMARC1; p=bogus"), emlSet(emlDMARCBase+"; sp=bogus")),
		emlD("RFC 9989 4.7 np that is not valid is absent", emlSet(emlDMARCBase+"; np=reject"), emlSet(emlDMARCBase+"; np=bogus")),
		emlD("RFC 7489 6.3 p lower, sp written in both", emlSet("v=DMARC1; p=reject; sp=reject"), emlSet("v=DMARC1; p=none; sp=reject"),
			"p=none in place of p=reject"),
		emlD("RFC 9989 4.7 np", was, emlSet("v=DMARC1; p=reject; np=none"), "np=none in place of np=reject"),
		emlD("RFC 9989 4.7 np stricter", emlSet("v=DMARC1; p=reject; np=none"), was),
		emlD("RFC 9989 4.7 np falls back to sp", emlSet("v=DMARC1; p=reject; sp=reject; np=reject"), emlSet("v=DMARC1; p=reject; sp=reject")),
		emlD("RFC 9989 4.7 np and sp together", was, emlSet("v=DMARC1; p=reject; sp=none; np=quarantine"),
			"sp=none in place of sp=reject", "np=quarantine in place of np=reject"),
		emlD("RFC 7489 6.3 pct", was, emlSet("v=DMARC1; p=reject; pct=10"), "pct=10 in place of pct=100"),
		emlD("RFC 7489 6.3 pct 0", was, emlSet("v=DMARC1; p=reject; pct=0"), "pct=0 in place of pct=100"),
		emlD("RFC 7489 6.3 pct not digits", was, emlSet("v=DMARC1; p=reject; pct=abc")),
		emlD("RFC 7489 6.3 pct over 100 is the default", emlSet("v=DMARC1; p=reject; pct=50"), emlSet("v=DMARC1; p=reject; pct=101")),
		emlD("RFC 7489 6.3 pct signed is the default", emlSet("v=DMARC1; p=reject; pct=50"), emlSet("v=DMARC1; p=reject; pct=+60")),
		emlD("RFC 7489 6.3 pct empty is the default", emlSet("v=DMARC1; p=reject; pct=50"), emlSet("v=DMARC1; p=reject; pct=")),
		emlD("RFC 7489 6.3 pct higher", emlSet("v=DMARC1; p=reject; pct=10"), emlSet("v=DMARC1; p=reject; pct=11")),
		emlD("RFC 7489 6.3 pct one lower", emlSet("v=DMARC1; p=reject; pct=11"), emlSet("v=DMARC1; p=reject; pct=10"),
			"pct=10 in place of pct=11"),
		emlD("RFC 7489 6.3 pct 100 written", emlSet("v=DMARC1; p=reject; pct=99"), emlSet("v=DMARC1; p=reject; pct=100")),
		emlD("RFC 9989 4.7 t=y", was, emlSet("v=DMARC1; p=reject; t=y"), "t=y in place of t=n"),
		emlD("RFC 9989 4.7 t=y gone", emlSet("v=DMARC1; p=reject; t=y"), was),
		emlD("RFC 9989 4.7 t invalid is n", emlSet("v=DMARC1; p=reject; t=y"), emlSet("v=DMARC1; p=reject; t=maybe")),
		emlD("RFC 7489 6.3 adkim", emlSet("v=DMARC1; p=reject; adkim=s"), was, "adkim=r in place of adkim=s"),
		emlD("RFC 7489 6.3 aspf", emlSet("v=DMARC1; p=reject; aspf=s"), was, "aspf=r in place of aspf=s"),
		emlD("RFC 7489 6.3 adkim stricter", was, emlSet("v=DMARC1; p=reject; adkim=s; aspf=S")),
		emlD("RFC 7489 6.3 adkim invalid is r", emlSet("v=DMARC1; p=reject; adkim=s"), emlSet("v=DMARC1; p=reject; adkim=x"), "adkim=r in place of adkim=s"),
		emlD("RFC 7489 6.4 added report address", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"),
			emlSet(emlDMARCBase+"; rua=mailto:a@corp.test!10m,mailto:x@evil.test"), "rua also sends reports to mailto:x@evil.test"),
		emlD("RFC 7489 6.4 size is not part of the address", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"),
			emlSet(emlDMARCBase+"; rua=mailto:a@corp.test!10m")).rev(),
		emlD("RFC 7489 6.4 address given twice", was, emlSet(emlDMARCBase+"; rua=mailto:x@evil.test, mailto:x@evil.test!1k"),
			"rua also sends reports to mailto:x@evil.test"),
		emlD("RFC 7489 6.4 address with a control octet is dropped", was, emlSet(emlDMARCBase+"; rua=mailto:x\x01y@evil.test")),
		emlD("RFC 7489 6.4 address with a DEL octet is dropped", was, emlSet(emlDMARCBase+"; rua=mailto:x\x7fy@evil.test")),
		emlD("RFC 7489 6.4 address with a tilde is kept", was, emlSet(emlDMARCBase+"; rua=mailto:x~y@evil.test"),
			"rua also sends reports to mailto:x~y@evil.test"),
		emlD("RFC 7489 6.4 address cut at the first bang", was, emlSet(emlDMARCBase+"; rua=mailto:x!y@evil.test"),
			"rua also sends reports to mailto:x"),
		emlD("RFC 7489 6.4 address of a bang only is dropped", was, emlSet(emlDMARCBase+"; rua=!10m")),
		emlD("RFC 7489 6.4 address with a space is dropped", was, emlSet(emlDMARCBase+"; rua=mailto:x y@evil.test")),
		emlD("RFC 7489 6.3 added failure report address", was, emlSet(emlDMARCBase+"; ruf=mailto:x@evil.test"),
			"ruf also sends failure reports to mailto:x@evil.test"),
		emlD("RFC 7489 6.3 rua of another case is another address", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"),
			emlSet(emlDMARCBase+"; rua=mailto:A@corp.test"), "rua also sends reports to mailto:A@corp.test",
			"rua no longer sends reports to mailto:a@corp.test"),
		emlD("RFC 7489 6.3 removed report address", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"), was,
			"rua no longer sends reports to mailto:a@corp.test"),
		emlD("RFC 7489 6.3 removed failure report address", emlSet(emlDMARCBase+"; ruf=mailto:a@corp.test"), was,
			"ruf no longer sends failure reports to mailto:a@corp.test"),
		emlD("RFC 7489 6.3 added and removed, octet order", emlSet(emlDMARCBase+"; rua=mailto:a@x.test,mailto:b@x.test,mailto:q@x.test"),
			emlSet(emlDMARCBase+"; rua=mailto:z@x.test,mailto:b@x.test,mailto:m@x.test"),
			"rua also sends reports to mailto:m@x.test", "rua also sends reports to mailto:z@x.test",
			"rua no longer sends reports to mailto:a@x.test", "rua no longer sends reports to mailto:q@x.test"),
		emlD("RFC 7489 6.6.3 no record", was, nil, emlNoDMARC),
		emlD("RFC 7489 6.6.3 only another text", was, emlSet("v=spf1 -all"), emlNoDMARC),
		emlD("RFC 7489 6.6.3 two records", was, emlSet(emlDMARCBase, emlDMARCBase), "two or more DMARC records: "+off),
		emlD("RFC 7489 6.6.3 no valid p", was, emlSet("v=DMARC1; p=bogus"), "no valid p= and no report address: "+off),
		emlD("RFC 7489 6.6.3 no p at all", was, emlSet("v=DMARC1"), "no valid p= and no report address: "+off),
		emlD("RFC 7489 6.6.3 version with a semicolon only", was, emlSet("v=DMARC1;"), "no valid p= and no report address: "+off),
		emlD("RFC 7489 6.6.3 report address without mailto", was, emlSet("v=DMARC1; rua=https://r.test/x"),
			"no valid p= and no report address: "+off),
		emlD("RFC 7489 6.4 version in lower case", was, emlSet("v=dmarc1; p=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 version not first", was, emlSet("p=reject; v=DMARC1"), emlNoDMARC),
		emlD("RFC 7489 6.4 leading space", was, emlSet(" v=DMARC1; p=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 longer version", was, emlSet("v=DMARC10; p=reject"), emlNoDMARC),
		emlD("RFC 7489 6.4 V in capitals is a record", was, emlSet("V=DMARC1; p=reject")).rev(),
		emlD("RFC 7489 6.6.3 off to off", emlSet("v=DMARC1; p=bogus"), nil),
		emlD("RFC 7489 6.6.3 off to off, other reason", nil, emlSet(emlDMARCBase, emlDMARCBase)),
		emlD("RFC 7489 6.6.3 off to on", nil, was),
		emlD("RFC 7489 6.6.3 none is above off", emlSet("v=DMARC1; p=none"), nil, emlNoDMARC),
		emlD("RFC 7489 6.6.3 other types are not read", was, []dnswire.RData{dnswire.SPF{Strings: []string{emlDMARCBase}}}, emlNoDMARC),
		emlD("RFC 7489 6.6.3 p missing with a report address", emlSet(emlDMARCBase+"; rua=mailto:a@corp.test"),
			emlSet("v=DMARC1; rua=mailto:a@corp.test"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.6.3 p invalid with a report address", emlSet(emlDMARCBase+"; rua=MAILTO:a@corp.test"),
			emlSet("v=DMARC1; p=bogus; rua=MAILTO:a@corp.test"), "p=none in place of p=reject"),
		emlD("RFC 7489 6.6.3 p missing with a report address, none was", emlSet("v=DMARC1; p=none; rua=mailto:a@corp.test"),
			emlSet("v=DMARC1; rua=mailto:a@corp.test")),
		emlD("design: from no record", nil, emlSet("v=DMARC1; p=none; rua=mailto:x@evil.test")),
		emlD("RFC 9989 4.7 psd", was, emlSet("v=DMARC1; p=reject; psd=y"), "psd=y in place of psd=u"),
		emlD("RFC 9989 4.7 psd n", was, emlSet("v=DMARC1; p=reject; psd=n"), "psd=n in place of psd=u"),
		emlD("RFC 9989 4.7 any change of psd", emlSet("v=DMARC1; p=reject; psd=n"), emlSet("v=DMARC1; p=reject; psd=y"), "psd=y in place of psd=n"),
		emlD("RFC 9989 4.7 psd back to the default", emlSet("v=DMARC1; p=reject; psd=y"), was, "psd=u in place of psd=y"),
		emlD("words in order", emlSet("v=DMARC1; p=reject; sp=reject"),
			emlSet("v=DMARC1; p=none; sp=none; pct=50; t=y; rua=mailto:x@evil.test"),
			"p=none in place of p=reject", "sp=none in place of sp=reject", "pct=50 in place of pct=100", "t=y in place of t=n",
			"rua also sends reports to mailto:x@evil.test"),
		emlD("words in order, all of them", emlSet("v=DMARC1; p=reject; adkim=s; aspf=s; psd=n; rua=mailto:a@x.test; ruf=mailto:a@x.test"),
			emlSet("v=DMARC1; p=none; sp=none; np=none; pct=0; t=y; psd=y; rua=mailto:b@x.test; ruf=mailto:b@x.test"),
			"p=none in place of p=reject", "sp=none in place of sp=reject", "np=none in place of np=reject", "pct=0 in place of pct=100",
			"t=y in place of t=n", "adkim=r in place of adkim=s", "aspf=r in place of aspf=s", "psd=y in place of psd=n",
			"rua also sends reports to mailto:b@x.test", "rua no longer sends reports to mailto:a@x.test",
			"ruf also sends failure reports to mailto:b@x.test", "ruf no longer sends failure reports to mailto:a@x.test"),
	}
	// Bounds: 4096 octets, 32 tags, 16 report addresses.
	rows = append(rows,
		emlD("osk-dns-watcher bound 4096 octets accepted", was, emlSet(emlPad("v=DMARC1; p=quarantine; x=", 4096)), "p=quarantine in place of p=reject"),
		emlD("osk-dns-watcher bound 4097 octets with two records", was, emlSet(emlPad("v=DMARC1; p=quarantine; x=", 4097), emlDMARCBase),
			"two or more DMARC records: "+off),
		emlD("osk-dns-watcher bound a text of 5000 octets that is no record", was, emlSet(emlPad("x=", 5000), emlDMARCBase)).rev(),
		emlD("osk-dns-watcher bound 4097 octets", was, emlSet(emlPad("v=DMARC1; p=quarantine; x=", 4097)), "a DMARC record longer than 4096 octets: "+off),
		emlD("osk-dns-watcher bound 32 tags", was, emlSet(emlDMARCBase+"; "+emlTerms(30, func(i int) string { return fmt.Sprintf("x%d=1;", i) })+" pct=10"),
			"pct=10 in place of pct=100"),
		emlD("no bound on tags: the 33rd is read", was, emlSet(emlDMARCBase+"; "+emlTerms(31, func(i int) string { return fmt.Sprintf("x%d=1;", i) })+" pct=10"),
			"pct=10 in place of pct=100"),
		emlD("no bound on tags: the 40th is read", was, emlSet(emlDMARCBase+"; "+emlTerms(38, func(i int) string { return fmt.Sprintf("x%d=1;", i) })+" pct=10"),
			"pct=10 in place of pct=100"),
		emlD("no bound on tags: a tag given twice after 38 others", was,
			emlSet(emlDMARCBase+"; "+emlTerms(38, func(i int) string { return fmt.Sprintf("x%d=1;", i) })+" p=none"), emlTwice("p")),
		emlD("osk-dns-watcher bound 16 report addresses", was, emlSet(emlDMARCBase+"; rua="+emlAddrs(16)),
			append(emlRuaWords(11), "and 5 more")...),
		emlD("osk-dns-watcher bound 17 report addresses", was, emlSet(emlDMARCBase+"; rua="+emlAddrs(17)),
			append(emlRuaWords(11), "and 5 more")...),
		emlD("osk-dns-watcher bound 12 report addresses", was, emlSet(emlDMARCBase+"; rua="+emlAddrs(12)), emlRuaWords(12)...),
		emlD("osk-dns-watcher bound 17 failure report addresses", was, emlSet(emlDMARCBase+"; ruf="+emlAddrs(17)),
			append(emlRufWords(11), "and 5 more")...),
		emlD("osk-dns-watcher bound 16 addresses lost", emlSet(emlDMARCBase+"; rua="+emlAddrs(16)), was,
			append(emlRuaGoneWords(11), "and 5 more")...),
	)
	// A word of 240 octets stays, one of 241 is cut to 237 and "...".
	const head = "rua also sends reports to mailto:"
	for _, n := range []int{240, 241, 300} {
		w := head + strings.Repeat("a", n-len(head))
		want := w
		if n > 240 {
			want = w[:237] + "..."
		}
		rows = append(rows, emlD(fmt.Sprintf("word of %d octets", n), was, emlSet(emlDMARCBase+"; rua="+w[len("rua also sends reports to "):]), want))
	}
	rows = append(rows, emlDMARCTwiceRows()...)
	rows = append(rows, emlDMARCCNAMERows()...)
	return rows
}

const emlBadSP = "an sp= that is not valid and no report address: receivers apply no DMARC policy"

// emlTwice is the word for a tag that a record gives twice with two values.
func emlTwice(tag string) string {
	return tag + "= given twice with different values: receivers may apply either one"
}

// emlDMARCTwiceRows: osk-dns-watcher reads the first value of a tag, and a receiver that
// keeps the last may read another policy, so a tag that is given twice with
// different values gets a word, unless the line holds the same duplicate.
func emlDMARCTwiceRows() []emlRow {
	was := emlSet(emlDMARCBase)
	return []emlRow{
		emlD("a tag given twice with the same value gives no word", was, emlSet("v=DMARC1; p=reject; p=reject")).rev(),
		emlD("a tag given twice with the same value after blanks gives no word", was, emlSet("v=DMARC1; p=reject; p= reject ; P=reject")).rev(),
		emlD("a tag given twice with different values gives a word", was, emlSet("v=DMARC1; p=reject; p=none"), emlTwice("p")),
		emlD("pct given twice with different values", was, emlSet("v=DMARC1; p=reject; pct=100; pct=0"), emlTwice("pct")),
		emlD("a tag in capitals given twice is one tag", was, emlSet("v=DMARC1; p=reject; P=none"), emlTwice("p")),
		emlD("sp given twice", was, emlSet("v=DMARC1; p=reject; sp=reject; sp=none"), emlTwice("sp")),
		emlD("np given twice", was, emlSet("v=DMARC1; p=reject; np=reject; np=none"), emlTwice("np")),
		emlD("t given twice", was, emlSet("v=DMARC1; p=reject; t=n; t=y"), emlTwice("t")),
		emlD("adkim given twice", was, emlSet("v=DMARC1; p=reject; adkim=s; adkim=r"), emlTwice("adkim")),
		emlD("aspf given twice", was, emlSet("v=DMARC1; p=reject; aspf=s; aspf=r"), emlTwice("aspf")),
		emlD("psd given twice", was, emlSet("v=DMARC1; p=reject; psd=u; psd=y"), emlTwice("psd")),
		emlD("rua given twice", was, emlSet("v=DMARC1; p=reject; rua=mailto:a@corp.test; rua=mailto:b@corp.test"),
			emlTwice("rua"), "rua also sends reports to mailto:a@corp.test"),
		emlD("ruf given twice", was, emlSet("v=DMARC1; p=reject; ruf=mailto:a@corp.test; ruf=mailto:b@corp.test"),
			emlTwice("ruf"), "ruf also sends failure reports to mailto:a@corp.test"),
		emlD("a tag that osk-dns-watcher does not read given twice gives no word", was, emlSet("v=DMARC1; p=reject; fo=0; fo=1")).rev(),
		emlD("an unknown tag given twice gives no word", was, emlSet("v=DMARC1; p=reject; foo=a; foo=b")).rev(),
		emlD("a part without an equal sign is not a tag given twice", was, emlSet("v=DMARC1; p=reject; p; p")).rev(),
		emlD("a tag given twice three times is one word", was, emlSet("v=DMARC1; p=reject; p=none; p=quarantine"), emlTwice("p")),
		emlD("two tags given twice: words in the order of the tags", was, emlSet("v=DMARC1; p=reject; t=n; pct=100; t=y; pct=0"),
			emlTwice("pct"), emlTwice("t")),
		emlD("the word comes before the words for addresses", was, emlSet("v=DMARC1; p=reject; rua=mailto:x@evil.test; p=none"),
			emlTwice("p"), "rua also sends reports to mailto:x@evil.test"),
		emlD("the word comes after the words for the tags", emlSet("v=DMARC1; p=reject; pct=100"),
			emlSet("v=DMARC1; p=quarantine; pct=50; p=none"), "p=quarantine in place of p=reject", "pct=50 in place of pct=100", emlTwice("p")),
		emlD("the line holds the same duplicate: no word", emlSet("v=DMARC1; p=reject; pct=100; pct=0"),
			emlSet("v=DMARC1; p=reject; pct=100; pct=50")),
		emlD("the line holds the same duplicate with the same values: no word", emlSet("v=DMARC1; p=reject; p=none"),
			emlSet("v=DMARC1; p=reject; p=none")).rev(),
		emlD("the line holds another duplicate: a word", emlSet("v=DMARC1; p=reject; pct=100; pct=0"),
			emlSet("v=DMARC1; p=reject; pct=100; pct=0; p=none"), emlTwice("p")),
		emlD("a duplicate that now has one value gives no word", emlSet("v=DMARC1; p=reject; p=none"), was),
		emlD("a duplicate in a record that was off gives no word", emlSet("v=DMARC1; p=bogus"), emlSet("v=DMARC1; p=reject; p=none")),
		emlD("a duplicate in a record that is now off gives the off word only", was, emlSet("v=DMARC1; p=bogus; p=none"),
			"no valid p= and no report address: receivers apply no DMARC policy"),
	}
}

func emlDMARCCNAMERows() []emlRow {
	was := emlSet(emlDMARCBase)
	cname := []dnswire.RData{emlCNAME("dmarc.evil.test.")}
	return []emlRow{
		emlD("CNAME in place of a record names the CNAME", was, cname, emlCNAMEWord("dmarc.evil.test.")),
		emlD("CNAME in place of a CNAME gives no word", cname, cname).rev(),
		emlD("a CNAME changed to another CNAME gives no word", cname, []dnswire.RData{emlCNAME("other.evil.test.")}),
		emlD("CNAME as was reads as no record", cname, was),
		emlD("a CNAME beside a record: only the CNAME counts", was, append(emlSet(emlDMARCBase), cname...), emlCNAMEWord("dmarc.evil.test.")),
		emlD("two CNAME targets: in octet order, each once", was,
			[]dnswire.RData{emlCNAME("b.evil.test."), emlCNAME("a.evil.test."), emlCNAME("B.evil.test.")},
			emlCNAMEWord("a.evil.test."), emlCNAMEWord("b.evil.test.")),
	}
}

func emlAddrs(n int) string {
	return strings.ReplaceAll(emlTerms(n, func(i int) string { return fmt.Sprintf("mailto:a%02d@x.test", i) }), " ", ",")
}

func emlRuaWords(n int) []string {
	var w []string
	for i := 1; i <= n; i++ {
		w = append(w, fmt.Sprintf("rua also sends reports to mailto:a%02d@x.test", i))
	}
	return w
}

func emlRufWords(n int) []string {
	var w []string
	for i := 1; i <= n; i++ {
		w = append(w, fmt.Sprintf("ruf also sends failure reports to mailto:a%02d@x.test", i))
	}
	return w
}

func emlRuaGoneWords(n int) []string {
	var w []string
	for i := 1; i <= n; i++ {
		w = append(w, fmt.Sprintf("rua no longer sends reports to mailto:a%02d@x.test", i))
	}
	return w
}

const (
	emlKeyQ = "v=DKIM1; k=rsa; p=QUJDRA=="
	emlKeyR = "v=DKIM1; k=rsa; p=RUZHSA=="
	emlIDQ  = `k=rsa, 8 characters, ending "QUJDRA=="`
	emlIDR  = `k=rsa, 8 characters, ending "RUZHSA=="`
)

func emlNewKey(id string) string { return "a key that the file does not list: " + id }

func emlCNAME(target string) dnswire.RData {
	n, err := dnswire.ParseName(target)
	if err != nil {
		panic(err)
	}
	return dnswire.CNAME{Target: n}
}

func emlDKIMRows() []emlRow {
	was := emlSet(emlKeyQ)
	rows := []emlRow{
		emlK("RFC 6376 3.6.2.2 strings joined", was, []dnswire.RData{emlTXT("v=DKIM1; k=rsa; ", "p=QUJDRA==")}).rev(),
		emlK("RFC 6376 3.6.1 whitespace inside p", was, emlSet("v=DKIM1;k=rsa;p=QUJD RA==")).rev(),
		emlK("RFC 6376 3.6.1 tab and line break inside p", was, emlSet("v=DKIM1; k=rsa; p=QU\tJD\r\n RA==")).rev(),
		emlK("RFC 6376 3.2 line breaks between tags", was, emlSet("v=DKIM1;\r\n k=rsa;\r\n p=QUJDRA==\r\n")).rev(),
		emlK("RFC 6376 3.6.1 no version", was, emlSet("k=rsa; p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 no k", was, emlSet("v=DKIM1; p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 neither version nor k", was, emlSet("p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 ignored tags", was, emlSet("v=DKIM1; k=rsa; p=QUJDRA==; n=x; h=sha256")).rev(),
		emlK("RFC 6376 3.2 trailing semicolons", was, emlSet("v=DKIM1; k=rsa; p=QUJDRA==;;")).rev(),
		emlK("RFC 6376 3.6.1 tags in another order", was, emlSet("v=DKIM1; p=QUJDRA==; k=rsa")).rev(),
		emlK("RFC 6376 3.6.1 testing flag in was and now", emlSet("v=DKIM1; t=y; p=QUJDRA=="), emlSet("p=QUJDRA==; t=y")).rev(),
		emlK("RFC 6376 3.6.1 another key", was, emlSet(emlKeyR), emlNewKey(emlIDR)),
		emlK("whole key text: same length and ending is another key", emlSet("v=DKIM1; p=AAAAQUJDRElGR0hJ"), emlSet("v=DKIM1; p=BBBBQUJDRElGR0hJ"),
			emlNewKey(`k=rsa, 16 characters, ending "QUJDRElGR0hJ"`)),
		emlK("whole key text: the same key written with white space", emlSet("v=DKIM1; p=AAAAQUJDRElGR0hJ"), emlSet("v=DKIM1; p=AAAA QUJD\tRElG R0hJ")).rev(),
		emlK("whole key text: two other keys with one tail give one word", emlSet("v=DKIM1; p=AAAAQUJDRElGR0hJ"),
			emlSet("v=DKIM1; p=AAAAQUJDRElGR0hJ", "v=DKIM1; p=BBBBQUJDRElGR0hJ", "v=DKIM1; p=CCCCQUJDRElGR0hJ"),
			emlNewKey(`k=rsa, 16 characters, ending "QUJDRElGR0hJ"`)),
		emlK("whole key text: testing flag is kept per key", emlSet("v=DKIM1; t=y; p=AAAAQUJDRElGR0hJ"), emlSet("v=DKIM1; t=y; p=BBBBQUJDRElGR0hJ"),
			emlNewKey(`k=rsa, 16 characters, ending "QUJDRElGR0hJ"`)),
		emlK("case of k is kept", was, emlSet("v=DKIM1; k=RSA; p=QUJDRA=="), emlNewKey(`k=RSA, 8 characters, ending "QUJDRA=="`)),
		emlK("case of t is kept: t=Y is no testing flag", emlSet("v=DKIM1; t=y; p=QUJDRA=="), emlSet("v=DKIM1; t=Y; p=QUJDRA=="),
			"the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("case of t is kept: t=S is no strict flag", emlSet("v=DKIM1; t=s; p=QUJDRA=="), emlSet("v=DKIM1; t=S; p=QUJDRA=="),
			"the key "+emlIDQ+" no longer has t=s"),
		emlK("case of s is kept: s=EMAIL signs no mail", was, emlSet("v=DKIM1; s=EMAIL; p=RUZHSA==")),
		emlK("case of s is kept: s=Email signs no mail", was, emlSet("v=DKIM1; s=Email; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 another length", emlSet("v=DKIM1; p=AAAAQUJDRElGR0hJ"), emlSet("v=DKIM1; p=AAAAAQUJDRElGR0hJ"),
			emlNewKey(`k=rsa, 17 characters, ending "QUJDRElGR0hJ"`)),
		emlK("RFC 6376 3.6.1 p of 12 characters", nil, emlSet("v=DKIM1; p=QUJDRElGR0hJ"), emlNewKey(`k=rsa, 12 characters, ending "QUJDRElGR0hJ"`)),
		emlK("RFC 6376 3.6.1 p of 13 characters", nil, emlSet("v=DKIM1; p=XQUJDRElGR0hJ"), emlNewKey(`k=rsa, 13 characters, ending "QUJDRElGR0hJ"`)),
		emlK("RFC 6376 3.6.1 p of 16 characters", nil, emlSet("v=DKIM1; p=QUJDRElGR0hJSg=="), emlNewKey(`k=rsa, 16 characters, ending "RElGR0hJSg=="`)),
		emlK("RFC 6376 3.6.1 p length counts no white space", nil, emlSet("v=DKIM1; p=QUJD RElG R0hJ"), emlNewKey(`k=rsa, 12 characters, ending "QUJDRElGR0hJ"`)),
		emlK("RFC 6376 3.6.1 k is part of the key", was, emlSet("v=DKIM1; k=rsa2; p=QUJDRA=="), emlNewKey(`k=rsa2, 8 characters, ending "QUJDRA=="`)),
		emlK("RFC 6376 3.6.1 revoked", was, emlSet("v=DKIM1; k=rsa; p=")),
		emlK("RFC 6376 3.6.1 revoked with white space", was, emlSet("v=DKIM1; k=rsa; p=  ")),
		emlK("RFC 6376 3.6.1 revoked, no version", was, emlSet("p=")),
		emlK("RFC 6376 3.6.1 key gone", was, nil),
		emlK("RFC 6376 3.6.1 no record before", nil, was, emlNewKey(emlIDQ)),
		emlK("RFC 6376 3.6.1 revoked before", emlSet("v=DKIM1; p="), was, emlNewKey(emlIDQ)),
		emlK("RFC 6376 3.6.2.2 two records", was, emlSet(emlKeyQ, emlKeyR), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.2.2 two records, one a text", was, emlSet(emlKeyQ, "google-site-verification=x")),
		emlK("RFC 6376 3.6.2.2 a key lost, another stays", emlSet(emlKeyQ, emlKeyR), was),
		emlK("RFC 6376 3.6.1 testing mode ends", emlSet("v=DKIM1; k=rsa; t=y; p=QUJDRA=="), was,
			"the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("RFC 6376 3.6.1 testing mode begins", was, emlSet("v=DKIM1; k=rsa; t=y; p=QUJDRA==")),
		emlK("RFC 6376 3.6.1 t with other flags", emlSet("v=DKIM1; t=x:y; p=QUJDRA=="), was,
			"the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("RFC 6376 3.6.1 other flag only", emlSet("v=DKIM1; t=y; p=QUJDRA=="), emlSet("v=DKIM1; t=x; p=QUJDRA=="),
			"the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("RFC 6376 3.6.1 flags trimmed", emlSet("v=DKIM1; t= y : s ; p=QUJDRA=="), emlSet("v=DKIM1; t=y:s; p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 strict stays, testing goes", emlSet("v=DKIM1; t=y:s; p=QUJDRA=="), emlSet("v=DKIM1; t=s; p=QUJDRA=="),
			"the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("RFC 6376 3.6.1 testing, two copies, one without", emlSet("v=DKIM1; t=y; p=QUJDRA=="),
			emlSet("v=DKIM1; t=y; p=QUJDRA==", emlKeyQ), "the key "+emlIDQ+" leaves testing mode: t=y is gone"),
		emlK("RFC 6376 3.6.1 testing, two copies, both", emlSet("v=DKIM1; t=y; p=QUJDRA=="),
			emlSet("v=DKIM1; t=y; p=QUJDRA==", "t=y; p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 strict flag gone", emlSet("v=DKIM1; k=rsa; t=s; p=QUJDRA=="), was,
			"the key "+emlIDQ+" no longer has t=s"),
		emlK("RFC 6376 3.6.1 strict flag added", was, emlSet("v=DKIM1; k=rsa; t=s; p=QUJDRA==")),
		emlK("RFC 6376 3.6.1 strict, two copies, one without", emlSet("v=DKIM1; t=s; p=QUJDRA=="),
			emlSet("v=DKIM1; t=s; p=QUJDRA==", emlKeyQ), "the key "+emlIDQ+" no longer has t=s"),
		emlK("RFC 6376 3.6.1 strict, two copies, both", emlSet("v=DKIM1; t=s; p=QUJDRA=="),
			emlSet("v=DKIM1; t=s; p=QUJDRA==", "t=s; p=QUJDRA==")).rev(),
		emlK("RFC 6376 3.6.1 version not first", was, emlSet("p=RUZHSA==; v=DKIM1")),
		emlK("RFC 6376 3.6.1 other version", was, emlSet("v=DKIM2; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 version in lower case", was, emlSet("v=dkim1; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 not base64", was, emlSet("v=DKIM1; p=RUZH$A==")),
		emlK("RFC 6376 3.6.1 hyphen in p", was, emlSet("v=DKIM1; p=RUZH-A==")),
		emlK("RFC 6376 3.2 p twice", was, emlSet("v=DKIM1; p=QUJDRA==; p=RUZHSA==")),
		emlK("RFC 6376 3.2 part without equal sign", was, emlSet("v=DKIM1; p=RUZHSA==; garbage")),
		emlK("RFC 6376 3.2 tag name starts with a digit", was, emlSet("v=DKIM1; p=RUZHSA==; 1x=1")),
		emlK("RFC 6376 3.2 tag name with a hyphen", was, emlSet("v=DKIM1; p=RUZHSA==; x-y=1")),
		emlK("RFC 6376 3.2 tag name in capitals is another tag", was, emlSet("v=DKIM1; P=RUZHSA==")),
		emlK("RFC 6376 3.6.1 no p", was, emlSet("v=DKIM1; k=rsa")),
		emlK("RFC 6376 3.6.1 k with a hyphen", was, emlSet("v=DKIM1; k=rsa-1; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 k empty", was, emlSet("v=DKIM1; k=; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 k starts with a digit", was, emlSet("v=DKIM1; k=1rsa; p=RUZHSA==")),
		emlK("RFC 6376 3.6.2.2 other types are not read", was, []dnswire.RData{dnswire.SPF{Strings: []string{emlKeyR}}}),
		emlK("RFC 6376 3.6.1 s names another service", was, emlSet("v=DKIM1; s=other; p=RUZHSA==")),
		emlK("RFC 6376 3.6.1 s=email", was, emlSet("v=DKIM1; s=email; p=RUZHSA=="), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.1 s=*", was, emlSet("v=DKIM1; s=*; p=RUZHSA=="), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.1 s list with email", was, emlSet("v=DKIM1; s=other : email; p=RUZHSA=="), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.1 s list with *", was, emlSet("v=DKIM1; s=other:*; p=RUZHSA=="), emlNewKey(emlIDR)),
		emlK("design: a CNAME", was, []dnswire.RData{emlCNAME("s1.dkim.evil.test.")}, emlNewKey("CNAME s1.dkim.evil.test.")),
		emlK("design: a CNAME in lower case", was, []dnswire.RData{emlCNAME("S1.DKIM.Evil.Test.")}, emlNewKey("CNAME s1.dkim.evil.test.")),
		emlK("design: the same CNAME", []dnswire.RData{emlCNAME("s1.dkim.evil.test.")}, []dnswire.RData{emlCNAME("S1.dkim.EVIL.test.")}).rev(),
		emlK("design: another CNAME", []dnswire.RData{emlCNAME("s1.dkim.evil.test.")}, []dnswire.RData{emlCNAME("s1.dkim.other.test.")},
			emlNewKey("CNAME s1.dkim.other.test.")),
		emlK("design: a CNAME gone", []dnswire.RData{emlCNAME("s1.dkim.evil.test.")}, nil),
		emlK("design: a CNAME beside a key", was, append(emlSet(emlKeyQ), emlCNAME("s1.dkim.evil.test.")), emlNewKey("CNAME s1.dkim.evil.test.")),
		emlK("design: a CNAME sorts before a key", nil, append(emlSet(emlKeyR), emlCNAME("s1.dkim.evil.test.")),
			emlNewKey("CNAME s1.dkim.evil.test."), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.1 another type of key", was, emlSet("v=DKIM1; k=ed25519; p=QUJDRA=="),
			emlNewKey(`k=ed25519, 8 characters, ending "QUJDRA=="`)),
		emlK("RFC 6376 3.6.1 words in octet order of the identities", nil, emlSet(emlKeyR, "v=DKIM1; k=ed25519; p=QUJDRA==", emlKeyQ),
			emlNewKey(`k=ed25519, 8 characters, ending "QUJDRA=="`), emlNewKey(emlIDQ), emlNewKey(emlIDR)),
		emlK("RFC 6376 3.6.1 a flag word and a key word in octet order", emlSet("v=DKIM1; k=rsa; t=y; p=QUJDRA=="),
			emlSet(emlKeyQ, emlKeyR), "the key "+emlIDQ+" leaves testing mode: t=y is gone", emlNewKey(emlIDR)),
	}
	// Records of a set: no bound on their number; one over 4096 octets.
	junk := func(n int) []string {
		var s []string
		for i := 0; i < n; i++ {
			s = append(s, "x=1")
		}
		return s
	}
	cname := emlCNAME("s1.dkim.evil.test.")
	big := emlPad("x=", 4097)
	rows = append(rows,
		emlK("a key in record 16 is read", was, emlSet(append(junk(15), emlKeyR)...), emlNewKey(emlIDR)),
		emlK("a key in record 17 is read", was, emlSet(append(junk(16), emlKeyR)...), emlNewKey(emlIDR)),
		emlK("a key in record 21 is read", was, emlSet(append(junk(20), emlKeyR)...), emlNewKey(emlIDR)),
		emlK("a CNAME as record 16 is read", was, append(emlSet(junk(15)...), cname), emlNewKey("CNAME s1.dkim.evil.test.")),
		emlK("a CNAME as record 17 is read", was, append(emlSet(junk(16)...), cname), emlNewKey("CNAME s1.dkim.evil.test.")),
		emlK("records of any type are read: a key after 15 SPF-type records", was, append(emlSPFJunk(15), emlSet(emlKeyR)...), emlNewKey(emlIDR)),
		emlK("records of any type are read: a key after 16 SPF-type records", was, append(emlSPFJunk(16), emlSet(emlKeyR)...), emlNewKey(emlIDR)),
		emlK("20 records with the new key first", was, emlSet(append([]string{emlKeyR}, junk(19)...)...), emlNewKey(emlIDR)),
		emlK("20 records that hold only the key of the file give no word", was, emlSet(append(junk(19), emlKeyQ)...)).rev(),
		emlK("16 records with the new key last", nil, emlSet(append(junk(15), emlKeyR)...), emlNewKey(emlIDR)),
		emlK("4096 octets is read as a key", was, emlSet(emlPad("v=DKIM1; k=rsa; p=RUZHSA==; n=", 4096)), emlNewKey(emlIDR)),
		emlK("4096 octets that the file holds give no word", emlSet(emlPad("v=DKIM1; k=rsa; p=RUZHSA==; n=", 4096)),
			emlSet(emlPad("v=DKIM1; k=rsa; p=RUZHSA==; n=", 4096))).rev(),
		emlK("4097 octets count as a key that the file does not list", was, emlSet(emlPad("v=DKIM1; k=rsa; p=RUZHSA==; n=", 4097)), emlDKIMLong),
		emlK("4097 octets that are no key count too", was, emlSet(big), emlDKIMLong),
		emlK("4097 octets of the key of the file count too", was, emlSet(emlPad("v=DKIM1; k=rsa; p=QUJDRA==; n=", 4097)), emlDKIMLong),
		emlK("4097 octets with a key after it", was, emlSet(big, emlKeyR), emlDKIMLong, emlNewKey(emlIDR)),
		emlK("4097 octets with a key before it", was, emlSet(emlKeyR, big), emlDKIMLong, emlNewKey(emlIDR)),
		emlK("4097 octets and a CNAME: words in octet order", was, append(emlSet(big), cname),
			emlNewKey("CNAME s1.dkim.evil.test."), emlDKIMLong),
		emlK("the file holds the same text of 4097 octets: no word", emlSet(big), emlSet(big)).rev(),
		emlK("the file holds the same text of 4097 octets among other records: no word", emlSet(big, emlKeyQ), emlSet(emlKeyQ, big)).rev(),
		emlK("the file holds another text of 4097 octets: a word", emlSet(big), emlSet(emlPad("y=", 4097)), emlDKIMLong),
		emlK("the file holds a text of 4098 octets: a word", emlSet(emlPad("x=", 4098)), emlSet(big), emlDKIMLong),
		emlK("the same text of 4097 octets twice gives one word", was, emlSet(big, big), emlDKIMLong),
		emlK("the file holds the text of 4097 octets and now it is there twice", emlSet(big), emlSet(big, big)).rev(),
		emlK("a text of 4097 octets that is gone gives no word", emlSet(big), nil),
	)
	return rows
}

// emlDKIMLong is the word for a record over 4096 octets that the file does
// not hold.
const emlDKIMLong = "a DKIM record longer than 4096 octets: osk-dns-watcher does not read it and counts it as a key that the file does not list"

func emlSTSRows() []emlRow {
	was := emlSet("v=STSv1; id=20261117")
	rows := []emlRow{
		emlM("RFC 8461 3.1 no space", was, emlSet("v=STSv1;id=20261117")).rev(),
		emlM("RFC 8461 3.1 trailing semicolon", was, emlSet("v=STSv1; id=20261117;")).rev(),
		emlM("RFC 8461 3.1 another id", was, emlSet("v=STSv1; id=20261118")).rev(),
		emlM("RFC 8461 3.1 extension field", was, emlSet("v=STSv1; id=1; foo=bar")).rev(),
		emlM("RFC 8461 3.1 extension field with odd name", was, emlSet("v=STSv1; id=1; x_y-z.1=v; 1a=b")).rev(),
		emlM("RFC 8461 3.1 blanks around semicolons", was, emlSet("v=STSv1 ; id=1 ;")).rev(),
		emlM("RFC 8461 3.1 tabs", was, emlSet("v=STSv1\t;\tid=1\t;")).rev(),
		emlM("RFC 8461 3.1 strings joined", was, []dnswire.RData{emlTXT("v=STSv1; ", "id=1")}).rev(),
		emlM("RFC 8461 3.1 id of 32 octets", was, emlSet("v=STSv1; id="+strings.Repeat("aB1", 10)+"xy")).rev(),
		emlM("RFC 8461 3.1 id of 1 octet", was, emlSet("v=STSv1; id=Z")).rev(),
		emlM("RFC 8461 3.1 name of 32 octets", was, emlSet("v=STSv1; id=1; a"+strings.Repeat("b", 31)+"=v")).rev(),
		emlM("RFC 8461 3.1 value of 0x21", was, emlSet("v=STSv1; id=1; foo=!")).rev(),
		emlM("RFC 8461 3.1 value of 0x7E", was, emlSet("v=STSv1; id=1; foo=~")).rev(),
		emlM("RFC 8461 3.1 extra text record", was, emlSet("v=STSv1; id=1", "something else")).rev(),
		emlM("RFC 8461 10.2 no record", was, nil, emlNoSTS),
		emlM("RFC 8461 3.1 only another text", was, emlSet("v=spf1 -all"), emlNoSTS),
		emlM("RFC 8461 3.1 other types are not read", was, []dnswire.RData{dnswire.SPF{Strings: []string{"v=STSv1; id=1"}}}, emlNoSTS),
		emlM("RFC 8461 3.1 two records", was, emlSet("v=STSv1; id=1", "v=STSv1; id=2"),
			"two or more MTA-STS records"+emlSTSTail),
		emlM("RFC 8461 3.1 id with a bang", was, emlSet("v=STSv1; id=abc!"), emlBadSTS),
		emlM("RFC 8461 3.1 id of 33 octets", was, emlSet("v=STSv1; id="+strings.Repeat("a", 33)), emlBadSTS),
		emlM("RFC 8461 3.1 empty id", was, emlSet("v=STSv1; id="), emlBadSTS),
		emlM("RFC 8461 3.1 id with a hyphen", was, emlSet("v=STSv1; id=a-b"), emlBadSTS),
		emlM("RFC 8461 3.1 empty field inside", was, emlSet("v=STSv1; ; id=1"), emlBadSTS),
		emlM("RFC 8461 3.1 two empty fields at the end", was, emlSet("v=STSv1; id=1;;"), emlBadSTS),
		emlM("RFC 8461 3.1 no fields", was, emlSet("v=STSv1;"), emlBadSTS),
		emlM("RFC 8461 3.1 no id", was, emlSet("v=STSv1; foo=bar"), emlBadSTS),
		emlM("RFC 8461 3.1 field without value", was, emlSet("v=STSv1; id=1; junk"), emlBadSTS),
		emlM("RFC 8461 3.1 empty value", was, emlSet("v=STSv1; id=1; foo="), emlBadSTS),
		emlM("RFC 8461 3.1 equal sign in a value", was, emlSet("v=STSv1; id=1; foo=a=b"), emlBadSTS),
		emlM("RFC 8461 3.1 blank in a value", was, emlSet("v=STSv1; id=1; foo=a b"), emlBadSTS),
		emlM("RFC 8461 3.1 name of 33 octets", was, emlSet("v=STSv1; id=1; a"+strings.Repeat("b", 32)+"=v"), emlBadSTS),
		emlM("RFC 8461 3.1 name starts with a hyphen", was, emlSet("v=STSv1; id=1; -a=v"), emlBadSTS),
		emlM("RFC 8461 3.1 name starts with a dot", was, emlSet("v=STSv1; id=1; .a=v"), emlBadSTS),
		emlM("RFC 8461 3.1 control octet in a value", was, emlSet("v=STSv1; id=1; foo=a\x01"), emlBadSTS),
		emlM("RFC 8461 3.1 version in lower case", was, emlSet("v=stsv1; id=1"), emlNoSTS),
		emlM("RFC 8461 3.1 version in capitals", was, emlSet("V=STSV1; id=1"), emlNoSTS),
		emlM("RFC 8461 3.1 leading space", was, emlSet(" v=STSv1; id=1"), emlNoSTS),
		emlM("RFC 8461 3.1 another version", was, emlSet("v=STSv2; id=1"), emlNoSTS),
		emlM("RFC 8461 3.1 version followed by a letter", was, emlSet("v=STSv1x; id=1"), emlNoSTS),
		emlM("RFC 8461 3.1 version alone", was, emlSet("v=STSv1"), emlBadSTS),
		emlM("RFC 8461 3.1 version and a space, no semicolon", was, emlSet("v=STSv1 id=1"), emlBadSTS),
		emlM("RFC 8461 3.1 version and a tab, no semicolon", was, emlSet("v=STSv1\tid=1"), emlBadSTS),
		emlM("RFC 8461 3.1 every id must be valid", was, emlSet("v=STSv1; id=1; id=abc!"), emlBadSTS),
		emlM("RFC 8461 3.1 every id must be valid, bad one first", was, emlSet("v=STSv1; id=abc!; id=1"), emlBadSTS),
		emlM("osk-dns-watcher bound 4097 octets with two records", was, emlSet(emlPad("v=STSv1; id=1; x=", 4097), "v=STSv1; id=1"),
			"two or more MTA-STS records"+emlSTSTail),
		emlM("osk-dns-watcher bound: a text of 5000 octets that is no record", was, emlSet(emlPad("x=", 5000), "v=STSv1; id=1")).rev(),
		emlM("RFC 8461 3.1 from no record", nil, emlSet("v=STSv1; id=1")),
		emlM("RFC 8461 3.1 off to off", nil, nil),
		emlM("RFC 8461 3.1 off to another off", emlSet("v=STSv1; id=!"), emlSet("v=STSv1; id=1", "v=STSv1; id=2")),
		emlM("RFC 8461 3.1 off with a problem to on", emlSet("v=STSv1; id=!"), was),
		emlM("osk-dns-watcher bound 4096 octets", was, emlSet(emlPad("v=STSv1; id=1; x=", 4096))).rev(),
		emlM("osk-dns-watcher bound 4097 octets", was, emlSet(emlPad("v=STSv1; id=1; x=", 4097)),
			"an MTA-STS record longer than 4096 octets"+emlSTSTail),
	}
	cname := []dnswire.RData{emlCNAME("sts.evil.test.")}
	rows = append(rows,
		emlM("CNAME in place of a record names the CNAME", was, cname, emlCNAMEWord("sts.evil.test.")),
		emlM("CNAME in place of a CNAME gives no word", cname, cname).rev(),
		emlM("a CNAME changed to another CNAME gives no word", cname, []dnswire.RData{emlCNAME("other.evil.test.")}),
		emlM("CNAME as was reads as no record", cname, was),
		emlM("a CNAME beside a record: only the CNAME counts", was, append(emlSet("v=STSv1; id=1"), cname...), emlCNAMEWord("sts.evil.test.")),
		emlM("two CNAME targets: in octet order, each once", was,
			[]dnswire.RData{emlCNAME("b.evil.test."), emlCNAME("a.evil.test."), emlCNAME("B.evil.test.")},
			emlCNAMEWord("a.evil.test."), emlCNAMEWord("b.evil.test.")),
	)
	return rows
}

func TestMailKindOf(t *testing.T) {
	for _, c := range []struct {
		owner string
		want  MailKind
	}{
		{"corp.test.", MailSPF},
		{"www.corp.test.", MailSPF},
		{".", MailSPF},
		{"test.", MailSPF},
		{"_dmarc.corp.test.", MailDMARC},
		{"_DMARC.corp.test.", MailDMARC},
		{"_DmArC.corp.test.", MailDMARC},
		{"_dmarc.", MailDMARC},
		{"_dmarc.a.b.corp.test.", MailDMARC},
		{"a._dmarc.corp.test.", MailSPF},
		{"_dmarcx.corp.test.", MailSPF},
		{"dmarc.corp.test.", MailSPF},
		{"s1._domainkey.corp.test.", MailDKIM},
		{"a.b._domainkey.corp.test.", MailDKIM},
		{"S1._DomainKey.corp.test.", MailDKIM},
		{"s1._DOMAINKEY.", MailDKIM},
		{"_domainkey._domainkey.corp.test.", MailDKIM},
		{"_domainkey.corp.test.", MailSPF},
		{"_dmarc._domainkey.corp.test.", MailDMARC},
		{"_DMARC._DOMAINKEY.corp.test.", MailDMARC},
		{"_mta-sts._domainkey.corp.test.", MailMTASTS},
		{"_MTA-STS._DomainKey.corp.test.", MailMTASTS},
		{"_domainkey.", MailSPF},
		{"s1._domainkeyx.corp.test.", MailSPF},
		{"s1.domainkey.corp.test.", MailSPF},
		{"_mta-sts.corp.test.", MailMTASTS},
		{"_MTA-STS.corp.test.", MailMTASTS},
		{"_mta-sts.x.corp.test.", MailMTASTS},
		{"_mta-sts.", MailMTASTS},
		{"x._mta-sts.corp.test.", MailSPF},
		{"mta-sts.corp.test.", MailSPF},
		{"_mta-sts2.corp.test.", MailSPF},
	} {
		if got := MailKindOf(expName(t, c.owner)); got != c.want {
			t.Errorf("MailKindOf(%s) = %d; want %d", c.owner, got, c.want)
		}
	}
	for i, k := range []MailKind{MailSPF, MailDMARC, MailDKIM, MailMTASTS} {
		if int(k) != i+1 {
			t.Errorf("kind %d has the value %d; want %d", i, k, i+1)
		}
	}
	if MaxWords != 12 {
		t.Errorf("MaxWords = %d; want 12", MaxWords)
	}
}

func TestHasSPF(t *testing.T) {
	long := emlPad("v=spf1 mx -all x=", 4097)
	for _, c := range []struct {
		name string
		set  []dnswire.RData
		want bool
	}{
		{"empty set", nil, false},
		{"one record", emlSet("v=spf1 mx -all"), true},
		{"version only", emlSet("v=spf1"), true},
		{"version and a space", emlSet("v=spf1 "), true},
		{"capitals", emlSet("V=SPF1 -all"), true},
		{"mixed case", emlSet("v=SpF1 -all"), true},
		{"two records", emlSet("v=spf1 mx -all", "v=spf1 +all"), true},
		{"one among other texts", emlSet("google-site-verification=x", "v=spf1 -all", "other"), true},
		{"strings cut inside the version", []dnswire.RData{emlTXT("v=sp", "f1 -all")}, true},
		{"empty string first", []dnswire.RData{emlTXT("", "v=spf1 -all")}, true},
		{"4097 octets", emlSet(long), true},
		{"other texts", emlSet("google-site-verification=x"), false},
		{"longer version", emlSet("v=spf10 +all"), false},
		{"five octets", emlSet("v=spf"), false},
		{"tab after the version", emlSet("v=spf1\t-all"), false},
		{"leading space", emlSet(" v=spf1 -all"), false},
		{"other version", emlSet("v=spf2 -all"), false},
		{"empty text", emlSet(""), false},
		{"text that holds the record later", emlSet("x v=spf1 -all"), false},
		{"SPF type", []dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 -all"}}}, false},
		{"a CNAME", []dnswire.RData{emlCNAME("spf.evil.test.")}, false},
		{"SPF type beside a TXT", append([]dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 -all"}}}, emlSet("v=spf1 -all")...), true},
	} {
		if got := HasSPF(c.set); got != c.want {
			t.Errorf("HasSPF(%s) = %v; want %v", c.name, got, c.want)
		}
	}
}

func emlNames(names []dnswire.Name) []string {
	var s []string
	for _, n := range names {
		s = append(s, n.String())
	}
	return s
}

func TestSPFTargets(t *testing.T) {
	owner := expName(t, emlSPFOwner)
	two := emlSet("v=spf1 include:a.test -all", "v=spf1 include:b.test -all")
	for _, c := range []struct {
		name string
		set  []dnswire.RData
		want []string // nil: the set has no usable record
	}{
		{"includes in order", emlSet("v=spf1 include:a.test include:b.test -all"), []string{"a.test.", "b.test."}},
		{"order is the order of terms", emlSet("v=spf1 include:b.test mx include:a.test -all"), []string{"b.test.", "a.test."}},
		{"include after all", emlSet("v=spf1 include:a.test -all include:b.test"), []string{"a.test."}},
		{"include after a softfail all", emlSet("v=spf1 include:a.test ~all include:b.test"), []string{"a.test."}},
		{"include after a pass all", emlSet("v=spf1 include:a.test +all include:b.test"), []string{"a.test."}},
		{"all first", emlSet("v=spf1 all include:a.test"), []string{}},
		// The root has no top label: the record is a permerror and gives no targets.
		{"include of the root is a problem", emlSet("v=spf1 include:. -all"), nil},
		{"include of the root beside another is a problem", emlSet("v=spf1 include:. include:a.test -all"), nil},
		{"redirect to the root is a problem", emlSet("v=spf1 mx redirect=."), nil},
		{"redirect to the root beside an include is a problem", emlSet("v=spf1 include:a.test redirect=."), nil},
		{"include of a name with no dot is a problem", emlSet("v=spf1 include:localhost -all"), nil},
		{"include of an address is a problem", emlSet("v=spf1 include:192.0.2.1 -all"), nil},
		{"include with a bad macro is a problem", emlSet("v=spf1 include:%{z}.x.test include:a.test -all"), nil},
		{"include with a trailing dot", emlSet("v=spf1 include:a.test. -all"), []string{"a.test."}},
		{"two records, one over 4096 octets", emlSet(emlPad("v=spf1 include:a.test x=", 4097), "v=spf1 include:b.test"), nil},
		{"a text over 4096 octets that is no record", emlSet(emlPad("x=", 5000), "v=spf1 include:a.test -all"), []string{"a.test."}},
		{"redirect without all", emlSet("v=spf1 include:a.test redirect=r.test"), []string{"a.test.", "r.test."}},
		{"redirect first, without all", emlSet("v=spf1 redirect=r.test include:a.test"), []string{"a.test.", "r.test."}},
		{"redirect alone", emlSet("v=spf1 redirect=r.test"), []string{"r.test."}},
		{"redirect with all after it", emlSet("v=spf1 redirect=r.test -all"), []string{}},
		{"redirect with all before it", emlSet("v=spf1 -all redirect=r.test"), []string{}},
		{"redirect with all and an include", emlSet("v=spf1 include:a.test redirect=r.test ?all"), []string{"a.test."}},
		{"macro include left out", emlSet("v=spf1 include:%{d}.x.test include:a.test -all"), []string{"a.test."}},
		{"macro redirect left out", emlSet("v=spf1 include:a.test redirect=%{d}.x.test"), []string{"a.test."}},
		{"macro in the middle of a name", emlSet("v=spf1 include:_spf.%{d2}.test -all"), []string{}},
		{"qualifiers", emlSet("v=spf1 -include:a.test ~include:b.test ?include:c.test +include:d.test -all"), []string{"a.test.", "b.test.", "c.test.", "d.test."}},
		{"case and trailing dot", emlSet("v=SPF1 INCLUDE:Evil.TEST. REDIRECT=R.Test."), []string{"evil.test.", "r.test."}},
		{"other mechanisms are no targets", emlSet("v=spf1 a:a.test mx:m.test ptr:p.test exists:e.test ip4:192.0.2.1 -all"), []string{}},
		{"strings joined", []dnswire.RData{emlTXT("v=spf1 include:a", ".test -all")}, []string{"a.test."}},
		{"beside another text", emlSet("google-site-verification=x", "v=spf1 include:a.test -all"), []string{"a.test."}},
		{"beside an SPF type", append([]dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 include:z.test -all"}}}, emlSet("v=spf1 include:a.test -all")...), []string{"a.test."}},
		{"term after all is not read but is checked", emlSet("v=spf1 include:a.test -all foo:bar"), nil},
		{"two records", two, nil},
		{"two records, one a modifier", emlSet("v=spf1 include:a.test", "v=spf1 redirect=r.test"), nil},
		{"problem", emlSet("v=spf1 include:a.test foo:bar"), nil},
		{"problem: bad name", emlSet("v=spf1 include:a..test -all"), nil},
		{"problem: redirect twice", emlSet("v=spf1 include:a.test redirect=r.test redirect=s.test"), nil},
		{"problem: eleven lookups", emlSet("v=spf1 " + emlTerms(11, func(i int) string { return fmt.Sprintf("include:i%d.test", i) })), nil},
		{"ten lookups", emlSet("v=spf1 " + emlTerms(10, func(i int) string { return fmt.Sprintf("include:i%d.test", i) })),
			func() []string {
				var w []string
				for i := 1; i <= 10; i++ {
					w = append(w, fmt.Sprintf("i%d.test.", i))
				}
				return w
			}()},
		{"ten lookups and a redirect", emlSet("v=spf1 " + emlTerms(10, func(i int) string { return fmt.Sprintf("include:i%d.test", i) }) + " redirect=r.test"), nil},
		{"eleven lookups after all", emlSet("v=spf1 -all " + emlTerms(11, func(i int) string { return fmt.Sprintf("include:i%d.test", i) })), []string{}},
		{"4097 octets", emlSet(emlPad("v=spf1 include:a.test -all x=", 4097)), nil},
		{"4096 octets", emlSet(emlPad("v=spf1 include:a.test -all x=", 4096)), []string{"a.test."}},
		{"129 terms", emlSet("v=spf1 include:a.test " + emlTerms(127, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) }) + " -all"), nil},
		{"128 terms", emlSet("v=spf1 include:a.test " + emlTerms(126, func(i int) string { return fmt.Sprintf("ip4:10.1.%d.1", i) }) + " -all"), []string{"a.test."}},
		{"no record", emlSet("google-site-verification=x"), nil},
		{"empty set", nil, nil},
		{"longer version", emlSet("v=spf10 include:a.test"), nil},
		{"SPF type only", []dnswire.RData{dnswire.SPF{Strings: []string{"v=spf1 include:a.test -all"}}}, nil},
	} {
		got := SPFTargets(owner, c.set)
		if c.want == nil {
			if got != nil {
				t.Errorf("%s: targets = %q; want nil", c.name, emlNames(got))
			}
			continue
		}
		if names := emlNames(got); len(names) != len(c.want) || (len(names) > 0 && !slices.Equal(names, c.want)) {
			t.Errorf("%s: targets = %q; want %q", c.name, names, c.want)
		}
	}
}

// An emlKind drives the order property for one policy: a generator of
// models, a plain writing of a model, random edits that make a policy
// stricter or weaker, and rewrites that write the same policy otherwise.
type emlKind struct {
	kind     MailKind
	owner    string
	cases    int
	gen      func(r *rand.Rand) any
	render   func(m any) []dnswire.RData
	edit     func(r *rand.Rand, m any) any
	rewrites []func(r *rand.Rand, m any) []dnswire.RData
}

func emlShow(set []dnswire.RData) string {
	var b strings.Builder
	for _, d := range set {
		fmt.Fprintf(&b, "%q ", d.String())
	}
	return b.String()
}

func TestMailPolicyOrderProperty(t *testing.T) {
	kinds := []emlKind{emlSPFKind(), emlDMARCKind(), emlDKIMKind(), emlSTSKind()}
	for _, k := range kinds {
		t.Run(fmt.Sprintf("kind %d", k.kind), func(t *testing.T) { emlRunProperty(t, k) })
	}
	t.Run("weakening edits give words", emlWeakeningEdits)
}

func emlRunProperty(t *testing.T, k emlKind) {
	r := rand.New(rand.NewPCG(emlSeed, uint64(k.kind)))
	owner := expName(t, k.owner)
	weaker := func(was, now []dnswire.RData) []string { return Weaker(k.kind, owner, was, now) }
	premises := 0
	for i := 0; i < k.cases; i++ {
		fail := func(format string, args ...any) {
			t.Helper()
			t.Fatalf("seed %d case %d: %s", emlSeed, i, fmt.Sprintf(format, args...))
		}
		xm, ym := k.gen(r), k.gen(r)
		x, y := k.render(xm), k.render(ym)

		if w := weaker(x, x); w != nil {
			fail("reflexive: Weaker(x, x) = %q for %s", w, emlShow(x))
		}
		w := weaker(x, y)
		emlCheckWords(t, w)
		if !slices.Equal(w, weaker(x, y)) {
			fail("Weaker is not deterministic for %s -> %s", emlShow(x), emlShow(y))
		}

		for ri, rewrite := range k.rewrites {
			rx := rewrite(r, xm)
			if w := weaker(x, rx); w != nil {
				fail("rewrite %d: Weaker(x, r(x)) = %q; x = %s r(x) = %s", ri, w, emlShow(x), emlShow(rx))
			}
			if w := weaker(rx, x); w != nil {
				fail("rewrite %d: Weaker(r(x), x) = %q; x = %s r(x) = %s", ri, w, emlShow(x), emlShow(rx))
			}
			if a, b := weaker(rx, y), weaker(x, y); !slices.Equal(a, b) {
				fail("rewrite %d: Weaker(r(x), y) = %q but Weaker(x, y) = %q; x = %s r(x) = %s y = %s", ri, a, b, emlShow(x), emlShow(rx), emlShow(y))
			}
			if a, b := weaker(y, rx), weaker(y, x); !slices.Equal(a, b) {
				fail("rewrite %d: Weaker(y, r(x)) = %q but Weaker(y, x) = %q; x = %s r(x) = %s y = %s", ri, a, b, emlShow(x), emlShow(rx), emlShow(y))
			}
		}

		bm, cm := xm, xm
		for n := r.IntN(4); n > 0; n-- {
			bm = k.edit(r, bm)
		}
		cm = bm
		for n := r.IntN(4); n > 0; n-- {
			cm = k.edit(r, cm)
		}
		a, b, c := x, k.render(bm), k.render(cm)
		if weaker(a, b) == nil && weaker(b, c) == nil {
			premises++
			if w := weaker(a, c); w != nil {
				fail("transitive: Weaker(a, c) = %q; a = %s b = %s c = %s", w, emlShow(a), emlShow(b), emlShow(c))
			}
		}
	}
	if premises < 200 {
		t.Errorf("the premises of transitivity held in %d of %d cases; want at least 200", premises, k.cases)
	}
}

// emlSPF: fields of a record after the version.

type emlSPFM struct{ fields []string }

var (
	emlIP4Pool = []string{"192.0.2.0/24", "192.0.2.0/25", "192.0.2.64/26", "192.0.2.1", "192.0.2.1/32", "198.51.100.0/24", "10.0.0.0/8", "0.0.0.0/0"}
	emlIP6Pool = []string{"2001:db8::/32", "2001:db8:1::/48", "2001:db8:1::5", "::/0"}
	emlDomains = []string{"corp.test", "other.test", "spf.partner.test", "%{d}.spf.corp.test"}
	emlLengths = []string{"", "/24", "/28", "//64", "//96", "/24//64"}
	emlQuals   = []string{"", "+", "-", "~", "?"}
)

func emlPick(r *rand.Rand, s []string) string { return s[r.IntN(len(s))] }

func emlSPFTerm(r *rand.Rand) string {
	q := emlPick(r, emlQuals)
	switch r.IntN(7) {
	case 0:
		return q + "ip4:" + emlPick(r, emlIP4Pool)
	case 1:
		return q + "ip6:" + emlPick(r, emlIP6Pool)
	case 2, 3:
		name := []string{"a", "mx"}[r.IntN(2)]
		if r.IntN(2) == 0 {
			name += ":" + emlPick(r, emlDomains)
		}
		return q + name + emlPick(r, emlLengths)
	case 4:
		return q + "include:" + emlPick(r, emlDomains)
	case 5:
		return q + "exists:" + emlPick(r, emlDomains)
	}
	if r.IntN(2) == 0 {
		return q + "ptr:" + emlPick(r, emlDomains)
	}
	return q + "ptr"
}

// emlSPFSplit gives the qualifier, the name and the rest of a field, and
// whether it is a modifier.
func emlSPFSplit(f string) (q, name, rest string, mod bool) {
	if f != "" && strings.ContainsRune("+-~?", rune(f[0])) {
		q, f = f[:1], f[1:]
	}
	i := strings.IndexAny(f, ":/=")
	if i < 0 {
		return q, f, "", false
	}
	return q, f[:i], f[i:], f[i] == '='
}

func emlSPFLookups(fields []string) int {
	n := 0
	for _, f := range fields {
		_, name, _, mod := emlSPFSplit(f)
		name = strings.ToLower(name)
		if (!mod && (name == "a" || name == "mx" || name == "include" || name == "exists" || name == "ptr")) || (mod && name == "redirect") {
			n++
		}
	}
	return n
}

func emlSPFInsert(fields []string, i int, f string) []string {
	return slices.Insert(slices.Clone(fields), i, f)
}

func emlSPFGen(r *rand.Rand) any {
	var f []string
	for n := r.IntN(8); n > 0; n-- {
		if t := emlSPFTerm(r); emlSPFLookups(append(slices.Clone(f), t)) <= 6 {
			f = append(f, t)
		}
	}
	if r.IntN(10) < 7 {
		at := len(f)
		if r.IntN(10) >= 7 {
			at = r.IntN(len(f) + 1)
		}
		f = emlSPFInsert(f, at, emlPick(r, emlQuals)+"all")
	}
	if r.IntN(4) == 0 {
		f = emlSPFInsert(f, r.IntN(len(f)+1), "redirect="+emlPick(r, emlDomains))
	}
	if r.IntN(5) == 0 {
		f = emlSPFInsert(f, r.IntN(len(f)+1), "exp="+emlPick(r, emlDomains))
	}
	if r.IntN(5) == 0 {
		f = emlSPFInsert(f, r.IntN(len(f)+1), "foo=bar")
	}
	if r.IntN(12) == 0 {
		f = emlSPFInsert(f, r.IntN(len(f)+1), "foo:bar")
	}
	return emlSPFM{f}
}

// emlSPFWrite writes a record; split cuts the text into short strings.
func emlSPFWrite(ver string, fields []string, sep string, split *rand.Rand) []dnswire.RData {
	text := ver
	if len(fields) > 0 {
		text += sep + strings.Join(fields, sep)
	}
	if sep != " " {
		text += sep
	}
	if split == nil {
		return emlSet(text)
	}
	var pieces []string
	for len(text) > 0 {
		n := min(1+split.IntN(20), len(text))
		pieces = append(pieces, text[:n])
		text = text[n:]
	}
	return []dnswire.RData{emlTXT(pieces...)}
}

func emlSPFRender(m any) []dnswire.RData { return emlSPFWrite("v=spf1", m.(emlSPFM).fields, " ", nil) }

func emlSPFMap(fields []string, f func(string) string) []string {
	out := make([]string, len(fields))
	for i, x := range fields {
		out[i] = f(x)
	}
	return out
}

func emlSPFRewrites() []func(r *rand.Rand, m any) []dnswire.RData {
	fields := func(m any) []string { return m.(emlSPFM).fields }
	return []func(r *rand.Rand, m any) []dnswire.RData{
		func(r *rand.Rand, m any) []dnswire.RData { return emlSPFWrite("v=spf1", fields(m), " ", r) },
		func(r *rand.Rand, m any) []dnswire.RData {
			up := emlSPFMap(fields(m), func(f string) string {
				q, name, rest, _ := emlSPFSplit(f)
				return q + strings.ToUpper(name) + rest
			})
			return emlSPFWrite("V=SPF1", up, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData { return emlSPFWrite("v=spf1", fields(m), "   ", nil) },
		func(r *rand.Rand, m any) []dnswire.RData {
			plus := emlSPFMap(fields(m), func(f string) string {
				if q, _, _, mod := emlSPFSplit(f); q == "" && !mod {
					return "+" + f
				}
				return f
			})
			return emlSPFWrite("v=spf1", plus, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			own := emlSPFMap(fields(m), func(f string) string {
				if q, name, rest, mod := emlSPFSplit(f); !mod && name == "a" && !strings.HasPrefix(rest, ":") {
					return q + "a:corp.test." + rest
				}
				return f
			})
			return emlSPFWrite("v=spf1", own, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			bits := emlSPFMap(fields(m), func(f string) string {
				q, name, rest, _ := emlSPFSplit(f)
				p, err := netip.ParsePrefix(strings.TrimPrefix(rest, ":"))
				if name != "ip4" || err != nil || p.Bits() == 32 {
					return f
				}
				u := uint64(p.Addr().As4()[0])<<24 | uint64(p.Addr().As4()[1])<<16 | uint64(p.Addr().As4()[2])<<8 | uint64(p.Addr().As4()[3])
				u |= r.Uint64() & (1<<(32-p.Bits()) - 1)
				return fmt.Sprintf("%sip4:%d.%d.%d.%d/%d", q, u>>24&255, u>>16&255, u>>8&255, u&255, p.Bits())
			})
			return emlSPFWrite("v=spf1", bits, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			s32 := emlSPFMap(fields(m), func(f string) string {
				if _, name, rest, _ := emlSPFSplit(f); name == "ip4" && !strings.Contains(rest, "/") {
					return f + "/32"
				}
				return f
			})
			return emlSPFWrite("v=spf1", s32, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			f := slices.Clone(fields(m))
			for _, x := range f {
				if _, name, _, mod := emlSPFSplit(x); !mod && name == "all" {
					f = append(f, "include:z.test", "ip4:10.9.9.9", "mx", "foo=baz")
					break
				}
			}
			return emlSPFWrite("v=spf1", f, " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			f := fields(m)
			return emlSPFWrite("v=spf1", emlSPFInsert(f, r.IntN(len(f)+1), "foo=bar"), " ", nil)
		},
		func(r *rand.Rand, m any) []dnswire.RData {
			f := fields(m)
			for _, x := range f {
				if _, name, _, mod := emlSPFSplit(x); mod && name == "exp" {
					return emlSPFWrite("v=spf1", f, " ", nil)
				}
			}
			return emlSPFWrite("v=spf1", emlSPFInsert(f, r.IntN(len(f)+1), "exp=why.corp.test"), " ", nil)
		},
	}
}

func emlSPFEdit(r *rand.Rand, m any) any {
	f := slices.Clone(m.(emlSPFM).fields)
	pickIdx := func(pred func(q, name string, mod bool) bool) int {
		var idx []int
		for i, x := range f {
			if q, name, _, mod := emlSPFSplit(x); pred(q, strings.ToLower(name), mod) {
				idx = append(idx, i)
			}
		}
		if len(idx) == 0 {
			return -1
		}
		return idx[r.IntN(len(idx))]
	}
	directive := func(string, string, bool) bool { return true }
	switch r.IntN(8) {
	case 0: // a stricter or a weaker all
		if i := pickIdx(func(q, name string, mod bool) bool { return !mod && name == "all" }); i >= 0 {
			order := []string{"+", "?", "~", "-"}
			q, _, _, _ := emlSPFSplit(f[i])
			if q == "" {
				q = "+"
			}
			j := slices.Index(order, q) + []int{-1, 1}[r.IntN(2)]
			if j >= 0 && j < len(order) {
				f[i] = order[j] + "all"
			}
		}
	case 1:
		if i := pickIdx(directive); i >= 0 {
			f = slices.Delete(f, i, i+1)
		}
	case 2:
		if t := emlSPFTerm(r); emlSPFLookups(append(slices.Clone(f), t)) <= 8 {
			f = slices.Insert(f, r.IntN(len(f)+1), t)
		}
	case 3: // a prefix wider or narrower
		if i := pickIdx(func(q, name string, mod bool) bool { return name == "ip4" && !mod }); i >= 0 {
			q, _, rest, _ := emlSPFSplit(f[i])
			if p, err := netip.ParsePrefix(strings.TrimPrefix(rest, ":")); err == nil || !strings.Contains(rest, "/") {
				addr, bits := strings.TrimPrefix(rest, ":"), 32
				if err == nil {
					addr, bits = p.Addr().String(), p.Bits()
				}
				if nb := bits + []int{-1, 1}[r.IntN(2)]; nb >= 0 && nb <= 32 {
					f[i] = fmt.Sprintf("%sip4:%s/%d", q, addr, nb)
				}
			}
		}
	case 4:
		if i := pickIdx(func(q, name string, mod bool) bool { return !mod && name != "all" }); i >= 0 {
			_, name, rest, _ := emlSPFSplit(f[i])
			f[i] = emlPick(r, emlQuals) + name + rest
		}
	case 5:
		if len(f) > 1 {
			i := r.IntN(len(f) - 1)
			f[i], f[i+1] = f[i+1], f[i]
		}
	case 6:
		if t := emlSPFTerm(r); strings.HasPrefix(t, "-") || r.IntN(2) == 0 {
			if emlSPFLookups(append(slices.Clone(f), t)) <= 8 {
				f = slices.Insert(f, 0, "-"+strings.TrimLeft(t, "+-~?"))
			}
		}
	case 7:
		if i := pickIdx(func(q, name string, mod bool) bool { return mod && name == "redirect" }); i >= 0 {
			f = slices.Delete(f, i, i+1)
		} else if emlSPFLookups(f) <= 8 {
			f = slices.Insert(f, r.IntN(len(f)+1), "redirect="+emlPick(r, emlDomains))
		}
	}
	return emlSPFM{f}
}

// emlOracleTargets is the reading of SPF targets written over the fields of a model;
// usable is false for a record with a problem.
func emlOracleTargets(fields []string) (targets []string, usable bool) {
	hasAll, allAt := false, len(fields)
	for i, f := range fields {
		_, name, rest, mod := emlSPFSplit(f)
		name = strings.ToLower(name)
		if name == "foo" && !mod && rest != "" {
			return nil, false
		}
		if !mod && name == "all" && !hasAll {
			hasAll, allAt = true, i
		}
	}
	for _, f := range fields[:allAt] {
		if _, name, rest, mod := emlSPFSplit(f); !mod && strings.ToLower(name) == "include" && !strings.Contains(rest, "%") {
			targets = append(targets, strings.ToLower(rest[1:])+".")
		}
	}
	if !hasAll {
		for _, f := range fields {
			if _, name, rest, mod := emlSPFSplit(f); mod && strings.ToLower(name) == "redirect" && !strings.Contains(rest, "%") {
				targets = append(targets, strings.ToLower(rest[1:])+".")
			}
		}
	}
	return targets, true
}

func emlSPFKind() emlKind {
	return emlKind{kind: MailSPF, owner: emlSPFOwner, cases: 1500, gen: emlSPFGen, render: emlSPFRender, edit: emlSPFEdit, rewrites: emlSPFRewrites()}
}

// emlOracleHasSPF is the selection of an SPF record.
func emlOracleHasSPF(texts []string) bool {
	for _, s := range texts {
		if len(s) >= 6 && strings.EqualFold(s[:6], "v=spf1") && (len(s) == 6 || s[6] == ' ') {
			return true
		}
	}
	return false
}

func emlJoined(set []dnswire.RData) []string {
	var texts []string
	for _, d := range set {
		texts = append(texts, strings.Join(d.(dnswire.TXT).Strings, ""))
	}
	return texts
}

func TestMailPolicySPFOracles(t *testing.T) {
	r := rand.New(rand.NewPCG(emlSeed, 99))
	owner := expName(t, emlSPFOwner)
	rewrites := emlSPFRewrites()
	for i := 0; i < 1500; i++ {
		m := emlSPFGen(r)
		sets := [][]dnswire.RData{emlSPFRender(m)}
		for _, rw := range rewrites {
			sets = append(sets, rw(r, m))
		}
		want, usable := emlOracleTargets(m.(emlSPFM).fields)
		for _, set := range sets {
			if !HasSPF(set) {
				t.Fatalf("seed %d case %d: HasSPF is false for %s", emlSeed, i, emlShow(set))
			}
			got := SPFTargets(owner, set)
			if !usable {
				if got != nil {
					t.Fatalf("seed %d case %d: SPFTargets = %q; want nil for %s", emlSeed, i, emlNames(got), emlShow(set))
				}
				continue
			}
			if names := emlNames(got); len(names) != len(want) || (len(want) > 0 && !slices.Equal(names, want)) {
				t.Fatalf("seed %d case %d: SPFTargets = %q; want %q for %s", emlSeed, i, names, want, emlShow(set))
			}
		}
	}
	// HasSPF over texts that start in nearly the same way.
	heads := []string{"v=spf1", "V=SPF1", "v=Spf1", "v=spf", "v=spf10", "v=spf1 ", "v=spf1\t", " v=spf1", "x", "", "v=spf2", "v=spf1;"}
	tails := []string{"", " -all", "\t", "x", " v=spf1", "-all"}
	for i := 0; i < 1000; i++ {
		var set []dnswire.RData
		for n := r.IntN(3); n >= 0; n-- {
			set = append(set, emlRec(emlPick(r, heads)+emlPick(r, tails)))
		}
		if got, want := HasSPF(set), emlOracleHasSPF(emlJoined(set)); got != want {
			t.Fatalf("seed %d case %d: HasSPF = %v; want %v for %s", emlSeed, i, got, want, emlShow(set))
		}
	}
}

// emlDMARC: a model of the tags.

type emlDM struct {
	off                                 bool
	p, sp, np, pct, t, adkim, aspf, psd string
	rua, ruf                            []string
}

var emlAddrPool = []string{"mailto:a@corp.test", "mailto:b@corp.test", "mailto:x@evil.test"}

func emlSubset(r *rand.Rand, pool []string) []string {
	var s []string
	for _, a := range pool {
		if r.IntN(2) == 0 {
			s = append(s, a)
		}
	}
	return s
}

func emlDMARCGen(r *rand.Rand) any {
	kw := []string{"", "none", "quarantine", "reject"}
	return emlDM{
		off:   r.IntN(12) == 0,
		p:     emlPick(r, []string{"none", "quarantine", "reject", "reject", "bogus", ""}),
		sp:    emlPick(r, kw),
		np:    emlPick(r, kw),
		pct:   emlPick(r, []string{"", "0", "10", "50", "100"}),
		t:     emlPick(r, []string{"", "y", "n"}),
		adkim: emlPick(r, []string{"", "r", "s"}),
		aspf:  emlPick(r, []string{"", "r", "s"}),
		psd:   emlPick(r, []string{"", "y", "n", "u"}),
		rua:   emlSubset(r, emlAddrPool),
		ruf:   emlSubset(r, emlAddrPool),
	}
}

type emlDStyle struct{ spaces, upName, upVal, defaults, extras, bang, dup, shuffle, trail, split bool }

func emlDMARCWrite(m emlDM, s emlDStyle, r *rand.Rand) []dnswire.RData {
	if m.off {
		return nil
	}
	var tags [][2]string
	add := func(name, v string) {
		if v != "" {
			tags = append(tags, [2]string{name, v})
		}
	}
	dflt := func(v, d string) string {
		if v == "" && s.defaults {
			return d
		}
		return v
	}
	addrs := func(l []string) string {
		var out []string
		for _, a := range l {
			if s.bang {
				a += "!10m"
			}
			out = append(out, a)
		}
		if s.dup && len(l) > 0 {
			out = append(out, l[0])
		}
		return strings.Join(out, ",")
	}
	add("p", m.p)
	add("sp", m.sp)
	add("np", m.np)
	add("pct", dflt(m.pct, "100"))
	add("t", dflt(m.t, "n"))
	add("adkim", dflt(m.adkim, "r"))
	add("aspf", dflt(m.aspf, "r"))
	add("psd", dflt(m.psd, "u"))
	add("rua", addrs(m.rua))
	add("ruf", addrs(m.ruf))
	if s.extras {
		add("fo", "1")
		add("rf", "afrf")
		add("ri", "86400")
		add("foo", "bar")
	}
	if s.shuffle {
		r.Shuffle(len(tags), func(i, j int) { tags[i], tags[j] = tags[j], tags[i] })
	}
	eq, delim, head := "=", "; ", "v=DMARC1"
	if s.spaces {
		eq, delim, head = " = ", " ; ", "v = DMARC1"
	}
	keyword := "p sp np t adkim aspf psd"
	var parts []string
	for _, tg := range tags {
		name, v := tg[0], tg[1]
		if s.upVal && emlHasWord(keyword, name) {
			v = strings.ToUpper(v)
		}
		if s.upName {
			name = strings.ToUpper(name)
		}
		parts = append(parts, name+eq+v)
	}
	text := head
	if len(parts) > 0 {
		text += delim + strings.Join(parts, delim)
	}
	if s.trail {
		text += ";"
	}
	if !s.split {
		return emlSet(text)
	}
	var pieces []string
	for len(text) > 0 {
		n := min(1+r.IntN(15), len(text))
		pieces = append(pieces, text[:n])
		text = text[n:]
	}
	return []dnswire.RData{emlTXT(pieces...)}
}

func emlHasWord(list, w string) bool { return slices.Contains(strings.Fields(list), w) }

func emlDMARCEdit(r *rand.Rand, a any) any {
	m := a.(emlDM)
	m.rua, m.ruf = slices.Clone(m.rua), slices.Clone(m.ruf)
	kw := []string{"", "none", "quarantine", "reject"}
	toggle := func(l []string) []string {
		a := emlPick(r, emlAddrPool)
		if i := slices.Index(l, a); i >= 0 {
			return slices.Delete(l, i, i+1)
		}
		return append(l, a)
	}
	switch r.IntN(10) {
	case 0:
		m.p = emlPick(r, kw[1:])
	case 1:
		m.sp = emlPick(r, kw)
	case 2:
		m.np = emlPick(r, kw)
	case 3:
		m.pct = emlPick(r, []string{"", "0", "10", "50", "100"})
	case 4:
		m.t = emlPick(r, []string{"", "y", "n"})
	case 5:
		m.adkim = emlPick(r, []string{"", "r", "s"})
	case 6:
		m.aspf = emlPick(r, []string{"", "r", "s"})
	case 7:
		m.psd = emlPick(r, []string{"", "y", "n", "u"})
	case 8:
		m.rua = toggle(m.rua)
		m.ruf = toggle(m.ruf)
	case 9:
		m.off = r.IntN(6) == 0
	}
	return m
}

func emlDMARCKind() emlKind {
	style := func(f func(*emlDStyle)) func(r *rand.Rand, m any) []dnswire.RData {
		return func(r *rand.Rand, m any) []dnswire.RData {
			var s emlDStyle
			f(&s)
			return emlDMARCWrite(m.(emlDM), s, r)
		}
	}
	return emlKind{
		kind: MailDMARC, owner: emlDMARCOwner, cases: 1500, gen: emlDMARCGen, edit: emlDMARCEdit,
		render: func(m any) []dnswire.RData { return emlDMARCWrite(m.(emlDM), emlDStyle{}, nil) },
		rewrites: []func(r *rand.Rand, m any) []dnswire.RData{
			style(func(s *emlDStyle) { s.spaces = true }),
			style(func(s *emlDStyle) { s.upName = true }),
			style(func(s *emlDStyle) { s.upVal = true }),
			style(func(s *emlDStyle) { s.defaults = true }),
			style(func(s *emlDStyle) { s.extras = true }),
			style(func(s *emlDStyle) { s.bang = true }),
			style(func(s *emlDStyle) { s.dup = true }),
			style(func(s *emlDStyle) { s.shuffle = true }),
			style(func(s *emlDStyle) { s.trail = true }),
			style(func(s *emlDStyle) { s.split = true }),
			style(func(s *emlDStyle) {
				s.spaces, s.upName, s.upVal, s.defaults, s.extras, s.bang, s.dup, s.shuffle, s.trail, s.split = true, true, true, true, true, true, true, true, true, true
			}),
		},
	}
}

// emlDKIM: keys and CNAMEs.

type emlDKKey struct {
	k, p, t string
	revoked bool
}

type emlDK struct {
	keys   []emlDKKey
	cnames []string
}

var (
	emlDKPool   = []string{"QUJDRA==", "RUZHSA==", "QUJDRElGR0hJSg=="}
	emlCNAMEs   = []string{"s1.dkim.evil.test.", "s1.dkim.other.test."}
	emlDKFlags  = []string{"", "y", "s", "y:s"}
	emlDKStyles = []string{"split", "ws", "noV", "noK", "extras", "shuffle", "records"}
)

func emlDKGen(r *rand.Rand) any {
	var m emlDK
	for n := r.IntN(4); n > 0; n-- {
		m.keys = append(m.keys, emlDKKey{k: emlPick(r, []string{"rsa", "rsa", "ed25519"}), p: emlPick(r, emlDKPool), t: emlPick(r, emlDKFlags), revoked: r.IntN(8) == 0})
	}
	if r.IntN(5) == 0 {
		m.cnames = []string{emlPick(r, emlCNAMEs)}
	}
	return m
}

func emlDKWrite(m emlDK, style string, r *rand.Rand) []dnswire.RData {
	var texts []string
	for _, k := range m.keys {
		p := k.p
		if k.revoked {
			p = ""
		}
		if style == "ws" && p != "" {
			ws := []string{" ", "\t", "\r\n "}
			i := r.IntN(len(p) + 1)
			p = p[:i] + emlPick(r, ws) + p[i:]
		}
		rest := []string{"p=" + p}
		if k.k != "rsa" || style != "noK" {
			rest = append(rest, "k="+k.k)
		}
		if k.t != "" {
			rest = append(rest, "t="+k.t)
		}
		if style == "extras" {
			rest = append(rest, "h=sha256", "n=note", "foo=bar")
		}
		if style == "shuffle" {
			r.Shuffle(len(rest), func(i, j int) { rest[i], rest[j] = rest[j], rest[i] })
		}
		if style != "noV" {
			rest = append([]string{"v=DKIM1"}, rest...)
		}
		texts = append(texts, strings.Join(rest, "; "))
	}
	if style == "records" {
		r.Shuffle(len(texts), func(i, j int) { texts[i], texts[j] = texts[j], texts[i] })
	}
	var set []dnswire.RData
	for _, s := range texts {
		if style != "split" {
			set = append(set, emlRec(s))
			continue
		}
		var pieces []string
		for len(s) > 0 {
			n := min(1+r.IntN(9), len(s))
			pieces = append(pieces, s[:n])
			s = s[n:]
		}
		set = append(set, emlTXT(pieces...))
	}
	for _, c := range m.cnames {
		set = append(set, emlCNAME(c))
	}
	return set
}

func emlDKEdit(r *rand.Rand, a any) any {
	m := a.(emlDK)
	m.keys, m.cnames = slices.Clone(m.keys), slices.Clone(m.cnames)
	switch n := r.IntN(7); {
	case n == 0 && len(m.keys) > 0:
		i := r.IntN(len(m.keys))
		m.keys = slices.Delete(m.keys, i, i+1)
	case n == 1 && len(m.keys) > 0:
		m.keys[r.IntN(len(m.keys))].revoked = true
	case n == 2 && len(m.keys) > 0:
		m.keys[r.IntN(len(m.keys))].t = emlPick(r, emlDKFlags)
	case n == 3:
		m.keys = append(m.keys, emlDKKey{k: "rsa", p: emlPick(r, emlDKPool), t: emlPick(r, emlDKFlags)})
	case n == 4 && len(m.keys) > 0:
		m.keys[r.IntN(len(m.keys))].p = emlPick(r, emlDKPool)
	case n == 5:
		if len(m.cnames) > 0 {
			m.cnames = nil
		} else {
			m.cnames = []string{emlPick(r, emlCNAMEs)}
		}
	case n == 6 && len(m.keys) > 0:
		m.keys[r.IntN(len(m.keys))].revoked = false
	}
	return m
}

func emlDKIMKind() emlKind {
	var rewrites []func(r *rand.Rand, m any) []dnswire.RData
	for _, s := range emlDKStyles {
		rewrites = append(rewrites, func(r *rand.Rand, m any) []dnswire.RData { return emlDKWrite(m.(emlDK), s, r) })
	}
	return emlKind{
		kind: MailDKIM, owner: emlDKIMOwner, cases: 1500, gen: emlDKGen, edit: emlDKEdit, rewrites: rewrites,
		render: func(m any) []dnswire.RData { return emlDKWrite(m.(emlDK), "", nil) },
	}
}

// emlSTS: the record is on or off, and has an id.

type emlSM struct {
	on bool
	id string
}

func emlSTSWrite(m emlSM, id, head, delim string, trail bool) []dnswire.RData {
	if !m.on {
		return nil
	}
	text := head + delim + "id=" + id
	if trail {
		text += ";"
	}
	return emlSet(text)
}

func emlSTSKind() emlKind {
	ids := []string{"1", "20261117", "abc", "Z9"}
	plain := func(m any) []dnswire.RData { return emlSTSWrite(m.(emlSM), m.(emlSM).id, "v=STSv1", "; ", false) }
	return emlKind{
		kind: MailMTASTS, owner: emlSTSOwner, cases: 1000, render: plain,
		gen: func(r *rand.Rand) any { return emlSM{on: r.IntN(10) < 7, id: emlPick(r, ids)} },
		edit: func(r *rand.Rand, a any) any {
			m := a.(emlSM)
			if r.IntN(2) == 0 {
				m.on = !m.on
			} else {
				m.id = emlPick(r, ids)
			}
			return m
		},
		rewrites: []func(r *rand.Rand, m any) []dnswire.RData{
			func(r *rand.Rand, m any) []dnswire.RData {
				return emlSTSWrite(m.(emlSM), emlPick(r, ids), "v=STSv1", "; ", false)
			},
			func(r *rand.Rand, m any) []dnswire.RData {
				if s := m.(emlSM); s.on {
					return emlSet("v=STSv1; id=" + s.id + "; foo=bar; x_y=1")
				}
				return nil
			},
			func(r *rand.Rand, m any) []dnswire.RData {
				return emlSTSWrite(m.(emlSM), m.(emlSM).id, "v=STSv1 ", " ; ", false)
			},
			func(r *rand.Rand, m any) []dnswire.RData {
				return emlSTSWrite(m.(emlSM), m.(emlSM).id, "v=STSv1", ";", true)
			},
		},
	}
}

// emlWeakeningEdits: each listed edit of a strict base gives a word of the
// named form.
func emlWeakeningEdits(t *testing.T) {
	for _, c := range []struct {
		name       string
		kind       MailKind
		owner      string
		base, edit []dnswire.RData
		word       string
	}{
		{"SPF lower all", MailSPF, emlSPFOwner, emlSet("v=spf1 mx -all"), emlSet("v=spf1 mx ~all"), "all gives softfail in place of fail"},
		{"SPF new pass term", MailSPF, emlSPFOwner, emlSet("v=spf1 mx -all"), emlSet("v=spf1 mx ip4:203.0.113.5 -all"), "ip4:203.0.113.5/32 gives pass in place of fail"},
		{"SPF wider prefix", MailSPF, emlSPFOwner, emlSet("v=spf1 ip4:192.0.2.0/25 -all"), emlSet("v=spf1 ip4:192.0.2.0/24 -all"), "ip4:192.0.2.0/24 gives pass in place of fail"},
		{"SPF fail term moved after a pass term", MailSPF, emlSPFOwner, emlSet("v=spf1 -ip4:192.0.2.1 ip4:192.0.2.0/24 -all"),
			emlSet("v=spf1 ip4:192.0.2.0/24 -ip4:192.0.2.1 -all"), "ip4:192.0.2.1/32 gives pass in place of fail"},
		{"SPF fail term removed above a weaker default", MailSPF, emlSPFOwner, emlSet("v=spf1 -ip4:192.0.2.1 ~all"), emlSet("v=spf1 ~all"),
			"ip4:192.0.2.1/32 gives softfail in place of fail"},
		{"SPF redirect in place of all", MailSPF, emlSPFOwner, emlSet("v=spf1 mx -all"), emlSet("v=spf1 mx redirect=evil.test"),
			"all gives the result of redirect=evil.test in place of fail"},
		{"DMARC lower p", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject"), emlSet("v=DMARC1; p=none"), "p=none in place of p=reject"},
		{"DMARC lower sp", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject; sp=reject"), emlSet("v=DMARC1; p=reject; sp=none"), "sp=none in place of sp=reject"},
		{"DMARC lower np", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject; np=reject"), emlSet("v=DMARC1; p=reject; np=none"), "np=none in place of np=reject"},
		{"DMARC lower pct", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject"), emlSet("v=DMARC1; p=reject; pct=50"), "pct=50 in place of pct=100"},
		{"DMARC t=y", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject"), emlSet("v=DMARC1; p=reject; t=y"), "t=y in place of t=n"},
		{"DMARC s to r", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject; aspf=s"), emlSet("v=DMARC1; p=reject"), "aspf=r in place of aspf=s"},
		{"DMARC address added", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject"), emlSet("v=DMARC1; p=reject; rua=mailto:x@evil.test"), "rua also sends reports to mailto:x@evil.test"},
		{"DMARC address removed", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject; rua=mailto:a@corp.test"), emlSet("v=DMARC1; p=reject"), "rua no longer sends reports to mailto:a@corp.test"},
		{"DMARC record removed", MailDMARC, emlDMARCOwner, emlSet("v=DMARC1; p=reject"), nil, emlNoDMARC},
		{"DKIM another key", MailDKIM, emlDKIMOwner, emlSet(emlKeyQ), emlSet(emlKeyR), emlNewKey(emlIDR)},
		{"DKIM a second key", MailDKIM, emlDKIMOwner, emlSet(emlKeyQ), emlSet(emlKeyQ, emlKeyR), emlNewKey(emlIDR)},
		{"DKIM t=y removed", MailDKIM, emlDKIMOwner, emlSet("v=DKIM1; k=rsa; t=y; p=QUJDRA=="), emlSet(emlKeyQ), "the key " + emlIDQ + " leaves testing mode: t=y is gone"},
		{"MTA-STS record removed", MailMTASTS, emlSTSOwner, emlSet("v=STSv1; id=1"), nil, emlNoSTS},
	} {
		got := Weaker(c.kind, expName(t, c.owner), c.base, c.edit)
		if !slices.Contains(got, c.word) {
			t.Errorf("%s: words = %q; want one of them to be %q", c.name, got, c.word)
		}
		emlCheckWords(t, got)
	}
}

func emlSPFJunk(n int) []dnswire.RData {
	var set []dnswire.RData
	for i := 0; i < n; i++ {
		set = append(set, dnswire.SPF{Strings: []string{"x=1"}})
	}
	return set
}

func emlWords(prefix string, from, to int) []string {
	var w []string
	for i := from; i <= to; i++ {
		w = append(w, fmt.Sprintf("%s%d", prefix, i))
	}
	return w
}

func TestMergeWords(t *testing.T) {
	long := func(n int, tail string) string { return strings.Repeat("a", n-len(tail)) + tail }
	cut := func(s string) string { return s[:237] + "..." }
	for _, c := range []struct {
		name  string
		lists [][]string
		want  []string
	}{
		{"no list", nil, nil},
		{"one empty list", [][]string{nil}, nil},
		{"empty lists", [][]string{nil, {}, nil}, nil},
		{"one list", [][]string{{"b", "a"}}, []string{"b", "a"}},
		{"list after list", [][]string{{"b", "a"}, {"d", "c"}}, []string{"b", "a", "d", "c"}},
		{"empty list between", [][]string{{"b"}, nil, {"a"}}, []string{"b", "a"}},
		{"duplicate across two lists", [][]string{{"a", "b"}, {"c", "a"}}, []string{"a", "b", "c"}},
		{"duplicate in one list", [][]string{{"a", "a", "b", "a"}}, []string{"a", "b"}},
		{"word of 239 octets", [][]string{{long(239, "x")}}, []string{long(239, "x")}},
		{"word of 240 octets", [][]string{{long(240, "x")}}, []string{long(240, "x")}},
		{"word of 241 octets", [][]string{{long(241, "x")}}, []string{cut(long(241, "x"))}},
		{"word of 1000 octets", [][]string{{long(1000, "x")}}, []string{cut(long(1000, "x"))}},
		{"duplicate made by the cut", [][]string{{long(300, "p")}, {long(301, "q")}}, []string{cut(long(300, "p"))}},
		{"cut word then its cut form", [][]string{{long(300, "p")}, {cut(long(300, "p"))}}, []string{cut(long(300, "p"))}},
		{"words differing before the cut point stay", [][]string{{long(300, "p")}, {"b" + long(300, "q")}}, []string{cut(long(300, "p")), cut("b" + long(300, "q"))}},
		{"11 words", [][]string{emlWords("w", 1, 11)}, emlWords("w", 1, 11)},
		{"12 words stay", [][]string{emlWords("w", 1, 12)}, emlWords("w", 1, 12)},
		{"12 words over two lists", [][]string{emlWords("w", 1, 5), emlWords("w", 6, 12)}, emlWords("w", 1, 12)},
		{"13 words are capped", [][]string{emlWords("w", 1, 13)}, append(emlWords("w", 1, 11), "and 2 more")},
		{"13 words over two lists", [][]string{emlWords("w", 1, 7), emlWords("w", 8, 13)}, append(emlWords("w", 1, 11), "and 2 more")},
		{"30 words", [][]string{emlWords("w", 1, 30)}, append(emlWords("w", 1, 11), "and 19 more")},
		{"13 words with duplicates are 12", [][]string{emlWords("w", 1, 12), emlWords("w", 3, 8)}, emlWords("w", 1, 12)},
		{"14 words with duplicates are 13", [][]string{emlWords("w", 1, 13), emlWords("w", 1, 13)}, append(emlWords("w", 1, 11), "and 2 more")},
		{"cut words are counted once", [][]string{{long(300, "p"), long(301, "q")}, emlWords("w", 1, 11)}, append([]string{cut(long(300, "p"))}, emlWords("w", 1, 11)...)},
	} {
		got := MergeWords(c.lists...)
		if len(got) != len(c.want) || (len(got) > 0 && !slices.Equal(got, c.want)) {
			t.Errorf("%s: MergeWords = %q; want %q", c.name, got, c.want)
		}
	}
}
