package expect

import (
	"errors"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

const stpSeed = 20261118

// The problem texts of the policy file (RFC 8461 section 3.2).
const (
	stpNoVersion  = "no version line"
	stpBadVersion = "the version is not STSv1"
	stpNoMode     = "no mode line"
	stpBadMode    = "the mode is not enforce, testing or none"
	stpNoAge      = "no max_age line"
	stpBadAge     = "max_age is not a whole number from 0 to 31557600"
	stpNoMX       = "no mx line"
	stpBadMX      = "an mx line that cannot be read"
	stpManyMX     = "more than 64 mx lines"
	stpTooLong    = "longer than 65536 octets"
	stpNotASCII   = "a line that is not printable ASCII"
	stpNoColon    = "a line without a colon"
)

var stpProblems = []string{stpNoVersion, stpBadVersion, stpNoMode, stpBadMode, stpNoAge, stpBadAge, stpNoMX, stpBadMX, stpManyMX, stpTooLong, stpNotASCII, stpNoColon}

// The words of the order (RFC 8461 sections 4.1 and 5).
const (
	stpTesting = "mode testing in place of enforce: senders deliver mail even when the TLS check fails"
	stpMXTail  = " is not allowed by the file"
)

func stpNoneIn(was string) string {
	return "mode none in place of " + was + ": senders act as if there were no policy"
}

func stpAgeWord(now, was int) string {
	return "max_age " + strconv.Itoa(now) + " in place of " + strconv.Itoa(was) + ": senders keep the policy for less time"
}

func stpBody(lines ...string) string { return strings.Join(lines, "\n") + "\n" }

// stpWasBody is the file of the rows of RFC 8461 section 3.2 and 5.
var stpWasBody = stpBody("version: STSv1", "mode: enforce", "mx: mail.corp.test", "max_age: 604800")

func stpRead(t testing.TB, body string) STSPolicy {
	t.Helper()
	p, problem := ParseSTSPolicy([]byte(body))
	if problem != "" {
		t.Fatalf("ParseSTSPolicy(%s): problem %q; want it to read", expShort(body), problem)
	}
	return p
}

func stpProblemOf(body string) string {
	p, problem := ParseSTSPolicy([]byte(body))
	if problem != "" && (p.Mode != 0 || p.MaxAge != 0 || p.MX != nil || p.Line != 0) {
		return "a policy with a problem: " + problem
	}
	return problem
}

func stpNames(t testing.TB, texts ...string) []dnswire.Name {
	t.Helper()
	var out []dnswire.Name
	for _, s := range texts {
		out = append(out, expName(t, s))
	}
	return out
}

func stpMXText(p STSPolicy) []string {
	out := []string{}
	for _, n := range p.MX {
		out = append(out, n.String())
	}
	return out
}

// stpGoodChars are the first and the last character of each class that a
// host name label allows; stpBadChars are the characters just outside.
const (
	stpGoodChars = "09azAZ"
	stpBadChars  = "/:@[`{"
)

// ---------------------------------------------------------------------
// The policy file: the P rows (RFC 8461 sections 3.2, 4.1 and 5).

type stpRow struct {
	name  string
	was   string
	now   string
	text  string // the canonical text of now
	words []string
	back  bool // the other way gives no words
}

func stpRows() []stpRow {
	crlf := strings.ReplaceAll(stpWasBody, "\n", "\r\n")
	const same = "mta-sts enforce 604800 mail.corp.test."
	f := func(mode, age string, mx ...string) string {
		lines := []string{"version: STSv1", "mode: " + mode, "max_age: " + age}
		for _, m := range mx {
			lines = append(lines, "mx: "+m)
		}
		return stpBody(lines...)
	}
	wild := f("enforce", "604800", "*.corp.test")
	rows := []stpRow{
		{name: "P1 RFC 8461 3.2 CRLF", now: crlf, text: same},
		{name: "P1 RFC 8461 3.2 CRLF and no last line end", now: strings.TrimSuffix(crlf, "\r\n"), text: same},
		{name: "P1 RFC 8461 3.2 a CR on the last line without LF", now: strings.TrimSuffix(stpWasBody, "\n") + "\r", text: same},
		{name: "P1 RFC 8461 3.2 another line order", now: stpBody("max_age: 604800", "mx: mail.corp.test", "mode: enforce", "version: STSv1"), text: same},
		{name: "P1 RFC 8461 3.2 an unknown key", now: stpWasBody + "foo: bar\n", text: same},
		{name: "P1 RFC 8461 3.2 unknown keys of odd shapes", now: stpBody("x y: z", "Foo-Bar: a:b:c", "foo:", "version: STSv1", "mode: enforce", "mx: mail.corp.test", "max_age: 604800", "foo:\t~ \tbar"), text: same},
		{name: "P1 RFC 8461 3.2 mx in capitals and with a dot", now: f("enforce", "604800", "Mail.Corp.Test."), text: same},
		{name: "P1 RFC 8461 3.2 mx without a dot", now: f("enforce", "604800", "mail.corp.test"), text: same},
		{name: "P1 RFC 8461 3.2 mx given twice", now: f("enforce", "604800", "mail.corp.test", "MAIL.corp.test."), text: same},
		{name: "P1 RFC 8461 3.2 empty lines", now: "\n\r\n" + stpWasBody + "\n\r\n\n", text: same},
		{name: "P1 RFC 8461 3.2 blanks around the values", now: stpBody("version:STSv1  ", "mode:\tenforce\t", "mx:   mail.corp.test \t", "max_age:604800"), text: same},
		{name: "P1 RFC 8461 3.2 keys are case sensitive, so MX and Mode are unknown", now: stpWasBody + "MX: evil.test\nMode: none\nMax_age: 1\nVersion: STSv9\n", text: same},
		{name: "P1 RFC 8461 3.2 a printable octet at each end of the range", now: stpWasBody + "x: ~ \t!\n", text: same},
		{name: "P1 RFC 8461 3.2 mode none keeps its mx", now: f("none", "604800", "mail.corp.test"), text: "mta-sts none 604800 mail.corp.test.", words: []string{stpNoneIn("enforce")}},
		{name: "P2 RFC 8461 5 testing in place of enforce", now: f("testing", "604800", "mail.corp.test"), text: "mta-sts testing 604800 mail.corp.test.", words: []string{stpTesting}},
		{name: "P3 RFC 8461 5 none in place of enforce", now: f("none", "604800"), text: "mta-sts none 604800", words: []string{stpNoneIn("enforce")}},
		{name: "P3 RFC 8461 5 none in place of testing", was: f("testing", "604800", "mail.corp.test"), now: f("none", "604800"), text: "mta-sts none 604800", words: []string{stpNoneIn("testing")}},
		{name: "P3 RFC 8461 5 enforce in place of testing", was: f("testing", "604800", "mail.corp.test"), now: stpWasBody, text: same, back: false, words: nil},
		{name: "P3 RFC 8461 5 testing in place of none", was: f("none", "604800"), now: f("testing", "604800", "mail.corp.test"), text: "mta-sts testing 604800 mail.corp.test.", words: []string{"mx mail.corp.test." + stpMXTail}},
		{name: "P4 RFC 8461 3.2 a lower max_age", now: f("enforce", "86400", "mail.corp.test"), text: "mta-sts enforce 86400 mail.corp.test.", words: []string{stpAgeWord(86400, 604800)}},
		{name: "P4 RFC 8461 3.2 a max_age of 0", now: f("enforce", "0", "mail.corp.test"), text: "mta-sts enforce 0 mail.corp.test.", words: []string{stpAgeWord(0, 604800)}},
		{name: "P4 RFC 8461 3.2 one second less", now: f("enforce", "604799", "mail.corp.test"), text: "mta-sts enforce 604799 mail.corp.test.", words: []string{stpAgeWord(604799, 604800)}},
		{name: "P4 RFC 8461 3.2 a higher max_age", now: f("enforce", "604801", "mail.corp.test"), text: "mta-sts enforce 604801 mail.corp.test.", back: false},
		{name: "P4 RFC 8461 3.2 the largest max_age", now: f("enforce", "31557600", "mail.corp.test"), text: "mta-sts enforce 31557600 mail.corp.test."},
		{name: "P4 RFC 8461 3.2 max_age padded with zeros to 10 digits", now: f("enforce", "0000604800", "mail.corp.test"), text: same},
		{name: "P4 RFC 8461 3.2 max_age of ten zeros", now: f("enforce", "0000000000", "mail.corp.test"), text: "mta-sts enforce 0 mail.corp.test.", words: []string{stpAgeWord(0, 604800)}},
		{name: "P5 RFC 8461 4.1 a name where a wildcard was", was: wild, now: stpWasBody, text: same},
		{name: "P5 RFC 8461 4.1 a wildcard where a name was", now: wild, text: "mta-sts enforce 604800 *.corp.test.", words: []string{"mx *.corp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 another name beside", now: f("enforce", "604800", "mail.corp.test", "evil.test"), text: "mta-sts enforce 604800 mail.corp.test. evil.test.", words: []string{"mx evil.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 two labels under a wildcard", was: wild, now: f("enforce", "604800", "a.b.corp.test"), text: "mta-sts enforce 604800 a.b.corp.test.", words: []string{"mx a.b.corp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 the name of the wildcard itself", was: wild, now: f("enforce", "604800", "corp.test"), text: "mta-sts enforce 604800 corp.test.", words: []string{"mx corp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 a wildcard under a wildcard", was: wild, now: f("enforce", "604800", "*.a.corp.test"), text: "mta-sts enforce 604800 *.a.corp.test.", words: []string{"mx *.a.corp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 the same wildcard in capitals", was: wild, now: f("enforce", "604800", "*.CORP.test."), text: "mta-sts enforce 604800 *.corp.test."},
		{name: "P5 RFC 8461 4.1 a wildcard above", was: wild, now: f("enforce", "604800", "*.test"), text: "mta-sts enforce 604800 *.test.", words: []string{"mx *.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 a name under a wildcard above, one label", was: f("enforce", "604800", "*.test"), now: f("enforce", "604800", "corp.test"), text: "mta-sts enforce 604800 corp.test."},
		{name: "P5 RFC 8461 4.1 a name that only ends like the wildcard", was: wild, now: f("enforce", "604800", "xcorp.test"), text: "mta-sts enforce 604800 xcorp.test.", words: []string{"mx xcorp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 one of several names is not covered", was: f("enforce", "604800", "a.corp.test", "*.b.test"), now: f("enforce", "604800", "a.corp.test", "x.b.test", "y.corp.test"),
			text: "mta-sts enforce 604800 x.b.test. a.corp.test. y.corp.test.", words: []string{"mx y.corp.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 every uncovered name in the order of now", now: f("enforce", "604800", "mail.corp.test", "z.test", "a.test", "m.test"),
			text: "mta-sts enforce 604800 a.test. mail.corp.test. m.test. z.test.", words: []string{"mx a.test." + stpMXTail, "mx m.test." + stpMXTail, "mx z.test." + stpMXTail}},
		{name: "P5 RFC 8461 4.1 fewer names", was: f("enforce", "604800", "mail.corp.test", "b.corp.test"), now: stpWasBody, text: same},
		{name: "words of mode, max_age and names, in this order", now: f("none", "0", "evil.test", "mail.corp.test"), text: "mta-sts none 0 mail.corp.test. evil.test.",
			words: []string{stpNoneIn("enforce"), stpAgeWord(0, 604800), "mx evil.test." + stpMXTail}},
		{name: "words of testing, max_age and names, in this order", now: f("testing", "1", "evil.test"), text: "mta-sts testing 1 evil.test.",
			words: []string{stpTesting, stpAgeWord(1, 604800), "mx evil.test." + stpMXTail}},
		{name: "P7 RFC 8461 3.2 the first mode counts", now: stpBody("version: STSv1", "mode: testing", "mode: enforce", "mx: mail.corp.test", "max_age: 604800"), text: "mta-sts testing 604800 mail.corp.test.", words: []string{stpTesting}},
		{name: "P7 RFC 8461 3.2 the first mode counts, enforce first", now: stpBody("version: STSv1", "mode: enforce", "mode: none", "mx: mail.corp.test", "max_age: 604800"), text: same},
		{name: "P7 RFC 8461 3.2 the first max_age counts", now: stpBody("version: STSv1", "max_age: 86400", "max_age: 604800", "mode: enforce", "mx: mail.corp.test"), text: "mta-sts enforce 86400 mail.corp.test.", words: []string{stpAgeWord(86400, 604800)}},
		{name: "P7 RFC 8461 3.2 the first max_age counts, a bad one later", now: stpWasBody + "max_age: bogus\nmode: bogus\nversion: STSv2\n", text: same},
		{name: "P7 RFC 8461 3.2 every mx line counts", now: stpBody("version: STSv1", "mode: enforce", "mx: mail.corp.test", "max_age: 604800", "mx: b.corp.test", "mx: a.corp.test"),
			text: "mta-sts enforce 604800 a.corp.test. b.corp.test. mail.corp.test.", words: []string{"mx a.corp.test." + stpMXTail, "mx b.corp.test." + stpMXTail}},
	}
	for i := range rows {
		if rows[i].was == "" {
			rows[i].was = stpWasBody
		}
	}
	return rows
}

func TestSTSPolicyConformance(t *testing.T) {
	names := map[string]bool{}
	for _, r := range stpRows() {
		if names[r.name] {
			t.Fatalf("two rows named %q", r.name)
		}
		names[r.name] = true
		t.Run(r.name, func(t *testing.T) {
			was, now := stpRead(t, r.was), stpRead(t, r.now)
			if now.Line != 0 {
				t.Errorf("Line = %d for a policy file; want 0", now.Line)
			}
			if got := now.String(); got != r.text {
				t.Errorf("String() = %q; want %q", got, r.text)
			}
			got := STSPolicyWeaker(was, now)
			emlWant(t, got, r.words)
			emlCheckWords(t, got)
			emlWant(t, STSPolicyWeaker(was, now), got)
			if self := STSPolicyWeaker(now, now); self != nil {
				t.Errorf("now against itself: words = %q; want nil", self)
			}
			if self := STSPolicyWeaker(was, was); self != nil {
				t.Errorf("was against itself: words = %q; want nil", self)
			}
			if r.words == nil && r.was == stpWasBody && r.text == "mta-sts enforce 604800 mail.corp.test." {
				if back := STSPolicyWeaker(now, was); back != nil {
					t.Errorf("the other way: words = %q; want nil", back)
				}
			}
		})
	}
}

// A written change of the mode, max_age or mx patterns that makes the policy
// stricter gives no word (RFC 8461 section 5).
func TestSTSPolicyStricterGivesNoWords(t *testing.T) {
	f := func(mode, age string, mx ...string) STSPolicy {
		lines := []string{"version: STSv1", "mode: " + mode, "max_age: " + age}
		for _, m := range mx {
			lines = append(lines, "mx: "+m)
		}
		return stpRead(t, stpBody(lines...))
	}
	weak := f("testing", "100", "*.corp.test", "evil.test")
	for _, now := range []STSPolicy{
		f("enforce", "100", "*.corp.test", "evil.test"),
		f("testing", "101", "*.corp.test", "evil.test"),
		f("testing", "100", "*.corp.test"),
		f("testing", "100", "evil.test"),
		f("testing", "100", "a.corp.test"),
		f("enforce", "31557600", "a.corp.test"),
	} {
		if got := STSPolicyWeaker(weak, now); got != nil {
			t.Errorf("Weaker(%s, %s) = %q; want nil", weak, now, got)
		}
	}
}

func TestSTSPolicyWordsAreCapped(t *testing.T) {
	var mx []string
	for i := range 15 {
		mx = append(mx, fmt.Sprintf("h%02d.evil.test", i))
	}
	body := func(n int) string {
		lines := []string{"version: STSv1", "mode: enforce", "max_age: 1"}
		for _, m := range mx[:n] {
			lines = append(lines, "mx: "+m)
		}
		return stpBody(lines...)
	}
	was := stpRead(t, stpWasBody)
	// The max_age word comes before the names: 12 words in all stay whole,
	// 13 are cut to 11 and a count.
	for _, n := range []int{1, 10, 11} {
		if got := STSPolicyWeaker(was, stpRead(t, body(n))); len(got) != 1+n || strings.HasPrefix(got[len(got)-1], "and ") {
			t.Errorf("%d names: %d words %q; want %d", n, len(got), got, 1+n)
		}
	}
	if got := STSPolicyWeaker(was, stpRead(t, body(12))); len(got) != MaxWords || got[MaxWords-1] != "and 2 more" {
		t.Errorf("12 names: words %q; want 11 and \"and 2 more\"", got)
	}
	got := STSPolicyWeaker(was, stpRead(t, body(15)))
	if len(got) != MaxWords {
		t.Fatalf("15 names: %d words; want %d: %q", len(got), MaxWords, got)
	}
	want := []string{stpAgeWord(1, 604800)}
	for _, m := range mx[:10] {
		want = append(want, "mx "+m+"."+stpMXTail)
	}
	want = append(want, "and 5 more")
	// 16 words in all: the max_age word, 15 names.
	if !slices.Equal(got, want) {
		t.Errorf("words = %q; want %q", got, want)
	}
	emlCheckWords(t, got)
}

func TestSTSPolicyLongWordIsBounded(t *testing.T) {
	l := strings.Repeat("a", 63)
	long := l + "." + l + "." + l + "." + strings.Repeat("b", 61)
	now := stpRead(t, stpBody("version: STSv1", "mode: enforce", "max_age: 604800", "mx: "+long))
	got := STSPolicyWeaker(stpRead(t, stpWasBody), now)
	if len(got) != 1 || !strings.HasPrefix(got[0], "mx "+l+".") {
		t.Fatalf("words = %q", got)
	}
	emlCheckWords(t, got)
}

// ---------------------------------------------------------------------
// The policy file: every problem text, exactly (RFC 8461 section 3.2).

func stpPadded(n int, tail string) string {
	head := stpBody("version: STSv1", "mode: testing", "max_age: 1", "mx: a.test")
	pad := n - len(head) - len("x:")
	return head + "x:" + strings.Repeat("a", pad) + tail
}

func stpMXLines(n int, distinct bool) string {
	lines := []string{"version: STSv1", "mode: enforce", "max_age: 1"}
	for i := range n {
		if distinct {
			lines = append(lines, fmt.Sprintf("mx: h%d.corp.test", i))
		} else {
			lines = append(lines, "mx: h.corp.test")
		}
	}
	return stpBody(lines...)
}

func TestSTSPolicyProblems(t *testing.T) {
	okTail := []string{"version: STSv1", "mode: enforce", "max_age: 1", "mx: a.test"}
	with := func(drop string, extra ...string) string {
		var lines []string
		for _, l := range okTail {
			if !strings.HasPrefix(l, drop+":") {
				lines = append(lines, l)
			}
		}
		return stpBody(append(lines, extra...)...)
	}
	l63, l64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	for _, c := range []struct{ name, body, want string }{
		// P6, RFC 8461 3.2: what a file must hold.
		{"P6 RFC 8461 3.2 an empty body", "", stpNoVersion},
		{"P6 RFC 8461 3.2 only empty lines", "\n\r\n\n", stpNoVersion},
		{"P6 RFC 8461 3.2 no version line", with("version"), stpNoVersion},
		{"P6 RFC 8461 3.2 version in another case of the key", with("version", "Version: STSv1"), stpNoVersion},
		{"P6 RFC 8461 3.2 a blank before the colon is part of the key", with("version", "version : STSv1"), stpNoVersion},
		{"P6 RFC 8461 3.2 a blank before the key is part of the key", with("version", " version: STSv1"), stpNoVersion},
		{"P6 RFC 8461 3.2 version STSv2", with("version", "version: STSv2"), stpBadVersion},
		{"P6 RFC 8461 3.2 version in lower case", with("version", "version: stsv1"), stpBadVersion},
		{"P6 RFC 8461 3.2 an empty version", with("version", "version:"), stpBadVersion},
		{"P6 RFC 8461 3.2 version and more", with("version", "version: STSv1 x"), stpBadVersion},
		{"P6 RFC 8461 3.2 the first version counts, a bad one first", with("version", "version: STSv2", "version: STSv1"), stpBadVersion},
		{"P6 RFC 8461 3.2 no mode", with("mode"), stpNoMode},
		{"P6 RFC 8461 3.2 Mode: enforce and no other mode", with("mode", "Mode: enforce"), stpNoMode},
		{"P6 RFC 8461 3.2 mode bogus", with("mode", "mode: bogus"), stpBadMode},
		{"P6 RFC 8461 3.2 mode in capitals", with("mode", "mode: ENFORCE"), stpBadMode},
		{"P6 RFC 8461 3.2 mode with a capital", with("mode", "mode: Testing"), stpBadMode},
		{"P6 RFC 8461 3.2 an empty mode", with("mode", "mode:"), stpBadMode},
		{"P6 RFC 8461 3.2 mode and more", with("mode", "mode: enforce now"), stpBadMode},
		{"P6 RFC 8461 3.2 the first mode counts, a bad one first", with("mode", "mode: bogus", "mode: enforce"), stpBadMode},
		{"P6 RFC 8461 3.2 no max_age", with("max_age"), stpNoAge},
		{"P6 RFC 8461 3.2 max_age one over the largest", with("max_age", "max_age: 31557601"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 11 digits", with("max_age", "max_age: 12345678901"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 11 digits that are zeros", with("max_age", "max_age: 00000000000"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 11 digits, padded", with("max_age", "max_age: 00031557600"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 10 digits, one over", with("max_age", "max_age: 0031557601"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 10 digits, the largest that fits 32 bits", with("max_age", "max_age: 4294967295"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 10 digits, past 32 bits", with("max_age", "max_age: 4294967296"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 10 nines", with("max_age", "max_age: 9999999999"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age of 20 digits", with("max_age", "max_age: 99999999999999999999"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age with a sign", with("max_age", "max_age: +1"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age negative", with("max_age", "max_age: -1"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age with a fraction", with("max_age", "max_age: 1.5"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age with an exponent", with("max_age", "max_age: 1e3"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age in hex", with("max_age", "max_age: 0x10"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age with an underscore", with("max_age", "max_age: 1_0"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age with a blank inside", with("max_age", "max_age: 1 0"), stpBadAge},
		{"P6 RFC 8461 3.2 max_age a word", with("max_age", "max_age: abc"), stpBadAge},
		{"P6 RFC 8461 3.2 an empty max_age", with("max_age", "max_age:"), stpBadAge},
		{"P6 RFC 8461 3.2 the first max_age counts, a bad one first", with("max_age", "max_age: abc", "max_age: 1"), stpBadAge},
		{"P6 RFC 8461 3.2 enforce with no mx", with("mx"), stpNoMX},
		{"P6 RFC 8461 3.2 testing with no mx", stpBody("version: STSv1", "mode: testing", "max_age: 1"), stpNoMX},
		{"P6 RFC 8461 3.2 MX in capitals is no mx line", with("mx", "MX: a.test"), stpNoMX},
		// The order of the checks: version, mode, max_age, mx.
		{"order: version before mode", stpBody("mode: bogus", "max_age: x"), stpNoVersion},
		{"order: mode before max_age", stpBody("version: STSv1", "mode: bogus", "max_age: x"), stpBadMode},
		{"order: no mode before no max_age", stpBody("version: STSv1"), stpNoMode},
		{"order: max_age before mx", stpBody("version: STSv1", "mode: enforce", "max_age: x"), stpBadAge},
		// mx lines, RFC 8461 3.2 and RFC 5321 4.1.2.
		{"P6 RFC 8461 3.2 mx star dot", with("mx", "mx: *."), stpBadMX},
		{"P6 RFC 8461 3.2 mx empty", with("mx", "mx:"), stpBadMX},
		{"P6 RFC 8461 3.2 mx dot", with("mx", "mx: ."), stpBadMX},
		{"P6 RFC 8461 3.2 mx star", with("mx", "mx: *"), stpBadMX},
		{"P6 RFC 8461 3.2 mx two dots at the end", with("mx", "mx: a.test.."), stpBadMX},
		{"P6 RFC 8461 3.2 mx an empty label", with("mx", "mx: a..test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a leading dot", with("mx", "mx: .a.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a label that starts with a hyphen", with("mx", "mx: -a.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a label that ends with a hyphen", with("mx", "mx: a-.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a hyphen alone", with("mx", "mx: -.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx an underscore", with("mx", "mx: a_b.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx two wildcards", with("mx", "mx: *.*.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a wildcard inside", with("mx", "mx: a.*.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a star in a label", with("mx", "mx: a*.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx two stars", with("mx", "mx: **.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a blank inside", with("mx", "mx: a b.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a backslash", with("mx", `mx: a\.b.test`), stpBadMX},
		{"P6 RFC 8461 3.2 mx an escape", with("mx", `mx: a\046b.test`), stpBadMX},
		{"P6 RFC 8461 3.2 mx a port", with("mx", "mx: a.test:25"), stpBadMX},
		{"P6 RFC 8461 3.2 mx an address", with("mx", "mx: u@a.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx one good and one bad line", with("mx", "mx: a.test", "mx: b_.test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a label of 64 octets", with("mx", "mx: "+l64+".test"), stpBadMX},
		{"P6 RFC 8461 3.2 mx a name of 256 octets", with("mx", "mx: "+l63+"."+l63+"."+l63+"."+strings.Repeat("b", 62)), stpBadMX},
		{"P6 RFC 8461 3.2 mx a name of 256 octets under a wildcard", with("mx", "mx: *."+l63+"."+l63+"."+l63+"."+strings.Repeat("b", 60)), stpBadMX},
		{"P6 RFC 8461 3.2 mode none, a bad mx", stpBody("version: STSv1", "mode: none", "max_age: 1", "mx: a_b.test"), stpBadMX},
		// Lines, RFC 8461 3.2.
		{"P6 RFC 8461 3.2 a line without a colon", "garbage\n", stpNoColon},
		{"P6 RFC 8461 3.2 a line without a colon, before the other problems", stpBody("garbage", "version: STSv2"), stpNoColon},
		{"P6 RFC 8461 3.2 a line without a colon after a good file", stpWasBody + "garbage\n", stpNoColon},
		{"P6 RFC 8461 3.2 a line of blanks", stpWasBody + "   \n", stpNoColon},
		{"P6 RFC 8461 3.2 a line of a tab", stpWasBody + "\t\n", stpNoColon},
		{"P6 RFC 8461 3.2 a line of a CR and a blank", stpWasBody + " \r\n", stpNoColon},
		{"P6 RFC 8461 3.2 the first bad line decides, no colon first", stpWasBody + "garbage\n\x01: a\n", stpNoColon},
		{"P6 RFC 8461 3.2 the first bad line decides, an octet first", stpWasBody + "\x01: a\ngarbage\n", stpNotASCII},
		{"P6 RFC 8461 3.2 an octet before a missing colon in one line", stpWasBody + "\x01garbage\n", stpNotASCII},
		{"P6 RFC 8461 3.2 NUL", stpWasBody + "x: a\x00\n", stpNotASCII},
		{"P6 RFC 8461 3.2 0x1F", stpWasBody + "x: a\x1f\n", stpNotASCII},
		{"P6 RFC 8461 3.2 0x7F", stpWasBody + "x: a\x7f\n", stpNotASCII},
		{"P6 RFC 8461 3.2 0x80", stpWasBody + "x: a\x80\n", stpNotASCII},
		// An unknown key whose line is valid UTF-8 is skipped whole (see
		// TestSTSPolicySkipsTheLineOfAnUnknownKey); these lines are refused.
		{"P6 RFC 8461 3.2 a control character after a letter with an accent", stpWasBody + "x: \u00e9\x01\n", stpNotASCII},
		{"P6 RFC 8461 3.2 DEL after a letter with an accent", stpWasBody + "x: caf\u00e9\x7f\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a next-line character", stpWasBody + "x: a\u0085b\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a CR inside a value with an accent", stpWasBody + "x: \u00e9\rb\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a line separator", stpWasBody + "x: a\u2028b\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a paragraph separator", stpWasBody + "x: a\u2029b\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a line separator after a key that looks like mx", stpWasBody + "x: a\u2028mx: evil.test\n", stpNotASCII},
		{"P6 RFC 8461 3.2 U+009F", stpWasBody + "x: a\u009fb\n", stpNotASCII},
		{"P6 RFC 8461 3.2 an octet 0xFF, invalid UTF-8", stpWasBody + "x: a\xffb\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a written U+FFFD", stpWasBody + "x: a\ufffdb\n", stpNotASCII},
		{"P6 RFC 8461 3.2 invalid UTF-8, a lone continuation octet", stpWasBody + "x: \x80\n", stpNotASCII},
		{"P6 RFC 8461 3.2 invalid UTF-8, a letter with an accent in Latin-1", stpWasBody + "x: caf\xe9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 invalid UTF-8, a cut sequence", stpWasBody + "x: \xc3\n", stpNotASCII},
		{"P6 RFC 8461 3.2 invalid UTF-8, an overlong form", stpWasBody + "x: \xc0\xaf\n", stpNotASCII},
		{"P6 RFC 8461 3.2 invalid UTF-8, a surrogate", stpWasBody + "x: \xed\xa0\x80\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a letter with an accent", stpWasBody + "x\u00e9: a\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a blank inside, and a letter with an accent in the value", stpWasBody + "x y: \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a blank before it, and a letter with an accent in the value", stpWasBody + " x: \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a blank after it, and a letter with an accent in the value", stpWasBody + "x : \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a tab after it, and a letter with an accent in the value", stpWasBody + "x\t: \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 an empty key, and a letter with an accent in the value", stpWasBody + ": \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key of 33 octets, and a letter with an accent in the value", stpWasBody + strings.Repeat("a", 33) + ": \u00e9\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a key with a character outside the key form, and a letter with an accent in the value", stpWasBody + "x+y: \u00e9\n", stpNotASCII},
		// A known key keeps the strict ASCII rule.
		{"P6 RFC 8461 3.2 version with a letter with an accent", with("version", "version: STSv1\u00e9"), stpNotASCII},
		{"P6 RFC 8461 3.2 mode with a letter with an accent", with("mode", "mode: enforc\u00e9"), stpNotASCII},
		{"P6 RFC 8461 3.2 max_age with a letter with an accent", with("max_age", "max_age: 1\u00e9"), stpNotASCII},
		{"P6 RFC 8461 3.2 mx with a letter with an accent", with("mx", "mx: \u00e9.test"), stpNotASCII},
		{"P6 RFC 8461 3.2 mx with a letter with an accent after the name", with("mx", "mx: a.test\u00e9"), stpNotASCII},
		{"P6 RFC 8461 3.2 mx with a line separator", with("mx", "mx: a.test\u2028"), stpNotASCII},
		{"P6 RFC 8461 3.2 a letter with an accent in a known key given twice, the second line", with("mode", "mode: enforce", "mode: \u00e9"), stpNotASCII},
		// Odd octets before a known key on the same line make it no known key, and the line is refused.
		{"P6 RFC 8461 3.2 a letter with an accent before mode", stpWasBody + "\u00e9mode: enforce\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a letter with an accent and a blank before version", with("version", "\u00e9 version: STSv1"), stpNotASCII},
		{"P6 RFC 8461 3.2 a control character before mx", with("mx", "\x01mx: a.test"), stpNotASCII},
		{"P6 RFC 8461 3.2 a line separator before max_age", with("max_age", "\u2028max_age: 1"), stpNotASCII},
		{"P6 RFC 8461 3.2 a byte order mark before version", with("version", "\ufeffversion: STSv1"), stpNotASCII},
		{"P6 RFC 8461 3.2 a vertical tab", stpWasBody + "x: a\x0b\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a form feed", stpWasBody + "x: a\x0c\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a CR inside a line", stpWasBody + "x: a\rb\n", stpNotASCII},
		{"P6 RFC 8461 3.2 two CRs at the end of a line", stpWasBody + "x: a\r\r\n", stpNotASCII},
		{"P6 RFC 8461 3.2 a non printable octet in the version line", stpBody("version: STSv1\x01", "mode: enforce", "max_age: 1", "mx: a.test"), stpNotASCII},
		{"P6 RFC 8461 3.2 a non printable octet in an mx line", with("mx", "mx: a.test\x7f"), stpNotASCII},
		// Size, RFC 8461 3.3.
		{"RFC 8461 3.3 65537 octets", stpPadded(65537, ""), stpTooLong},
		{"RFC 8461 3.3 65537 octets of line feeds", strings.Repeat("\n", 65537), stpTooLong},
		{"RFC 8461 3.3 65537 octets that are no ASCII", strings.Repeat("\x01", 65537), stpTooLong},
		{"RFC 8461 3.3 65536 octets of line feeds", strings.Repeat("\n", 65536), stpNoVersion},
		{"RFC 8461 3.3 65536 octets of a bad octet", strings.Repeat("\x01", 65536), stpNotASCII},
		// More than 64 mx lines.
		{"RFC 8461 3.2 65 mx lines", stpMXLines(65, true), stpManyMX},
		{"RFC 8461 3.2 65 mx lines that are the same name", stpMXLines(65, false), stpManyMX},
		{"RFC 8461 3.2 65 mx lines, mode none", strings.Replace(stpMXLines(65, true), "mode: enforce", "mode: none", 1), stpManyMX},
		{"RFC 8461 3.2 65 mx lines, no version", strings.Replace(stpMXLines(65, true), "version: STSv1", "", 1), stpNoVersion},
		{"RFC 8461 3.2 200 mx lines", stpMXLines(200, true), stpManyMX},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := stpProblemOf(c.body); got != c.want {
				t.Errorf("ParseSTSPolicy(%s): problem %q; want %q", expShort(c.body), got, c.want)
			}
			p, _ := ParseSTSPolicy([]byte(c.body))
			if p.Mode != 0 || p.MX != nil {
				t.Errorf("a policy with a problem is not zero: %+v", p)
			}
		})
	}
}

// The line of an unknown key whose key has the form of a key is skipped whole
// when its value is valid UTF-8 with no control character other than tab and
// no line or paragraph separator (RFC 8461 section 3.2: a sender ignores such
// a field). The policy that the file gives does not change.
func TestSTSPolicySkipsTheLineOfAnUnknownKey(t *testing.T) {
	const want = "mta-sts enforce 604800 mail.corp.test."
	for _, c := range []struct{ name, body string }{
		{"a letter with an accent", stpWasBody + "x: \u00e9\n"},
		{"several letters with accents", stpWasBody + "x: caf\u00e9 \u00fc\n"},
		{"two octets of a character", stpWasBody + "x: \u65e5\u672c\n"},
		{"four octets of a character", stpWasBody + "x: \U0001F600\n"},
		{"tabs around the value", stpWasBody + "x:\t\u00e9\t\n"},
		{"a no-break space", stpWasBody + "x: a\u00a0b\n"},
		{"a zero width space", stpWasBody + "x: a\u200bb\n"},
		{"a byte order mark inside the value", stpWasBody + "x: a\ufeffb\n"},
		{"CRLF", stpWasBody + "x: \u00e9\r\n"},
		{"the last line with no line end", stpWasBody + "x: \u00e9"},
		{"before the known keys", "x: \u00e9\n" + stpWasBody},
		{"between the known keys", stpBody("version: STSv1", "x: \u00e9", "mode: enforce", "mx: mail.corp.test", "max_age: 604800")},
		{"a key with a dash, a dot and an underscore", stpWasBody + "x-y.z_1: \u00e9\n"},
		{"a key of 32 octets", stpWasBody + strings.Repeat("a", 32) + ": \u00e9\n"},
		{"a key in capitals", stpWasBody + "X: \u00e9\n"},
		{"a known key in capitals", stpWasBody + "MX: \u00e9\nMode: \u00e9\n"},
		{"a key that starts as a known one", stpWasBody + "version2: \u00e9\nmx2: \u00e9\n"},
		{"a value that looks like a known key", stpWasBody + "x: \u00e9 mode: none\n"},
		{"a value that looks like a whole line", stpWasBody + "x: \u00e9 mx: evil.test max_age: 1\n"},
		{"two such lines", stpWasBody + "x: \u00e9\ny: \u00fc\n"},
		{"a colon in the value", stpWasBody + "x: \u00e9: mx: evil.test\n"},
		{"a space inside the value", stpWasBody + "x: a b\n"},
		{"a tab inside the value", stpWasBody + "x: a\tb\n"},
		{"0x7E", stpWasBody + "x: a~b\n"},
		{"U+00A0, just above the controls", stpWasBody + "x: a\u00a0b\n"},
		{"U+2027, just below the line separator", stpWasBody + "x: a\u2027b\n"},
		{"U+202A, just above the paragraph separator", stpWasBody + "x: a\u202ab\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := stpRead(t, c.body)
			if p.String() != want || p.Line != 0 {
				t.Errorf("ParseSTSPolicy(%s) = %q on line %d; want %q", expShort(c.body), p.String(), p.Line, want)
			}
		})
	}
}

func TestSTSPolicyLimits(t *testing.T) {
	// 65536 octets are not too long; 65537 are (RFC 8461 section 3.3).
	for _, n := range []int{65535, 65536} {
		p, problem := ParseSTSPolicy([]byte(stpPadded(n, "")))
		if problem != "" || p.Mode != STSTesting {
			t.Errorf("a body of %d octets: %+v %q; want it to read", n, p, problem)
		}
	}
	if len(stpPadded(65536, "")) != 65536 || len(stpPadded(65537, "")) != 65537 {
		t.Fatal("test fault: wrong padding")
	}
	// The 64 mx lines of RFC 8461 section 3.2 as limited here.
	for _, n := range []int{1, 63, 64} {
		p := stpRead(t, stpMXLines(n, true))
		if len(p.MX) != n {
			t.Errorf("%d mx lines gave %d patterns", n, len(p.MX))
		}
	}
	if p := stpRead(t, stpMXLines(64, false)); len(p.MX) != 1 {
		t.Errorf("64 mx lines of one name gave %d patterns; want 1", len(p.MX))
	}
	// max_age.
	for _, c := range []struct {
		text string
		want uint32
	}{
		{"0", 0}, {"1", 1}, {"31557599", 31557599}, {"31557600", 31557600},
		{"0000000000", 0}, {"0000000001", 1}, {"0031557600", 31557600}, {"0000604800", 604800},
	} {
		p := stpRead(t, stpBody("version: STSv1", "mode: none", "max_age: "+c.text))
		if p.MaxAge != c.want {
			t.Errorf("max_age %s read as %d; want %d", c.text, p.MaxAge, c.want)
		}
	}
	// A name of the longest length, with and without a wildcard.
	l63 := strings.Repeat("a", 63)
	longest := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61)
	for _, mx := range []string{longest, longest + ".", "*." + l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 59),
		l63 + ".test", "A" + l63[1:] + ".TEST."} {
		p := stpRead(t, stpBody("version: STSv1", "mode: none", "max_age: 1", "mx: "+mx))
		if len(p.MX) != 1 || p.MX[0].String() != strings.ToLower(strings.TrimSuffix(mx, ".")+".") {
			t.Errorf("mx %q read as %v", mx, stpMXText(p))
		}
	}
}

// Each character class of a host name: the first and the last character of
// each, and the one just outside (RFC 5321 section 4.1.2).
func TestSTSPolicyMXCharacters(t *testing.T) {
	read := func(mx string) (STSPolicy, string) {
		return ParseSTSPolicy([]byte(stpBody("version: STSv1", "mode: none", "max_age: 1", "mx: "+mx)))
	}
	for _, c := range []byte(stpGoodChars) {
		for _, mx := range []string{string(c) + ".test", "a" + string(c) + ".test", string(c) + "a.test", "*." + string(c) + "x.test."} {
			p, problem := read(mx)
			want := strings.ToLower(strings.TrimSuffix(mx, ".")) + "."
			if problem != "" || len(p.MX) != 1 || p.MX[0].String() != want {
				t.Errorf("mx %q: %v %q; want %q", mx, stpMXText(p), problem, want)
			}
		}
	}
	for _, mx := range []string{"a-b.test", "a--b.test", "0-0.test", "a-b.c-d.test"} {
		if p, problem := read(mx); problem != "" || len(p.MX) != 1 {
			t.Errorf("mx %q: %q; want it to read", mx, problem)
		}
	}
	for _, mx := range []string{"-.test", "-a.test", "a-.test", "a.-b.test", "a.b-.test", "*.-a.test", "*.a-.test"} {
		if _, problem := read(mx); problem != stpBadMX {
			t.Errorf("mx %q: problem %q; want %q", mx, problem, stpBadMX)
		}
	}
	for _, c := range []byte(stpBadChars + "_\\!#$%&'()+,;<=>?^|}~\"*") {
		for _, mx := range []string{"a" + string(c) + "b.test", string(c) + "a.test", "a" + string(c) + ".test", "*.a" + string(c) + "b.test."} {
			if _, problem := read(mx); problem != stpBadMX {
				t.Errorf("mx %q: problem %q; want %q", mx, problem, stpBadMX)
			}
		}
	}
	for _, mx := range []string{"*.a.test", "*.a.test.", "*.a", "*.a-b.c.test"} {
		if p, problem := read(mx); problem != "" || len(p.MX) != 1 || !strings.HasPrefix(p.MX[0].String(), "*.") {
			t.Errorf("mx %q: %v %q; want a wildcard", mx, stpMXText(p), problem)
		}
	}
}

func TestSTSPolicyReadsStringsJoined(t *testing.T) {
	body := stpWasBody
	for _, n := range []int{1, 2, 255} {
		var pieces []string
		for s := body; s != ""; {
			k := min(n, len(s))
			pieces = append(pieces, s[:k])
			s = s[k:]
		}
		if got := stpRead(t, strings.Join(pieces, "")).String(); got != "mta-sts enforce 604800 mail.corp.test." {
			t.Errorf("pieces of %d: %q", n, got)
		}
	}
}

// ---------------------------------------------------------------------
// The text of a policy and its round trip.

func TestSTSPolicyString(t *testing.T) {
	mx := func(s ...string) []dnswire.Name { return stpNames(t, s...) }
	for _, c := range []struct {
		p    STSPolicy
		want string
	}{
		{STSPolicy{Mode: STSEnforce, MaxAge: 604800, MX: mx("mail.corp.test.")}, "mta-sts enforce 604800 mail.corp.test."},
		{STSPolicy{Mode: STSTesting, MaxAge: 1, MX: mx("a.test.", "*.b.test.")}, "mta-sts testing 1 a.test. *.b.test."},
		{STSPolicy{Mode: STSNone, MaxAge: 0}, "mta-sts none 0"},
		{STSPolicy{Mode: STSNone, MaxAge: 31557600, MX: mx("a.test.")}, "mta-sts none 31557600 a.test."},
		{STSPolicy{Line: 9, Mode: STSEnforce, MaxAge: 1, MX: mx("a.test.")}, "mta-sts enforce 1 a.test."},
	} {
		if got := c.p.String(); got != c.want {
			t.Errorf("String() = %q; want %q", got, c.want)
		}
	}
	if STSNone >= STSTesting || STSTesting >= STSEnforce || STSNone != 1 {
		t.Errorf("modes: none %d, testing %d, enforce %d; want 1 < 2 < 3 in the order of RFC 8461 section 5", STSNone, STSTesting, STSEnforce)
	}
	// A mode of no word never panics.
	_ = STSPolicy{}.String()
	_ = STSPolicy{Mode: 200}.String()
}

func TestSTSPolicyRoundTrip(t *testing.T) {
	for _, body := range []string{
		stpWasBody,
		stpBody("version: STSv1", "mode: none", "max_age: 0"),
		stpBody("version: STSv1", "mode: testing", "max_age: 31557600", "mx: *.corp.test", "mx: mail.corp.test", "mx: a.b.corp.test.", "mx: Z.test"),
		stpBody("version: STSv1", "mode: none", "max_age: 5", "mx: x.test"),
	} {
		p := stpRead(t, body)
		// The text is a valid line, and reads to the same text.
		f := expParse(t, expHead+p.String()+"\n")
		if f.Policy == nil || f.Policy.String() != p.String() || f.Policy.Mode != p.Mode || f.Policy.MaxAge != p.MaxAge || !slices.EqualFunc(f.Policy.MX, p.MX, dnswire.Name.Equal) {
			t.Errorf("the line %q reads as %+v", p.String(), f.Policy)
		}
		// The words of the line are a policy file again.
		file := []string{"version: STSv1", "mode: " + stpModeWord(p.Mode), "max_age: " + strconv.Itoa(int(p.MaxAge))}
		for _, n := range p.MX {
			file = append(file, "mx: "+n.String())
		}
		if again := stpRead(t, stpBody(file...)); again.String() != p.String() {
			t.Errorf("round trip through a file: %q then %q", p.String(), again.String())
		}
	}
}

func stpModeWord(m STSMode) string {
	return map[STSMode]string{STSNone: "none", STSTesting: "testing", STSEnforce: "enforce"}[m]
}

// ---------------------------------------------------------------------
// The line mta-sts (RFC 8461 section 3.2).

func stpDomain(last int) string {
	a := strings.Repeat("a", 62)
	return a + "." + a + "." + a + "." + strings.Repeat("b", last) + "."
}

func TestSTSLineProblems(t *testing.T) {
	l63, l64 := strings.Repeat("a", 63), strings.Repeat("a", 64)
	fields := func(n int) string {
		var s []string
		for i := range n {
			s = append(s, fmt.Sprintf("h%d.corp.test.", i))
		}
		return strings.Join(s, " ")
	}
	badFields := strings.TrimSpace(strings.Repeat("bad ", 65))
	const want = "want mta-sts <mode> <max_age> <mx>..."
	for _, c := range []struct {
		name string
		text string
		want Problem
	}{
		{"given twice", expHead + "mta-sts enforce 1 a.test.\nmta-sts testing 1 b.test.\n", Problem{5, "mta-sts already given on line 4"}},
		{"given twice, with lines between", expHead + "mta-sts enforce 1 a.test.\n# c\nwww.corp.test. A none\nmta-sts enforce 1 a.test.\n", Problem{7, "mta-sts already given on line 4"}},
		{"no fields", expHead + "mta-sts\n", Problem{4, want}},
		{"one field", expHead + "mta-sts enforce\n", Problem{4, want}},
		{"one field, bad mode", expHead + "mta-sts bogus\n", Problem{4, want}},
		{"mode in capitals", expHead + "mta-sts ENFORCE 1 a.test.\n", Problem{4, "mode must be enforce, testing or none"}},
		{"mode with a capital", expHead + "mta-sts Testing 1 a.test.\n", Problem{4, "mode must be enforce, testing or none"}},
		{"mode bogus", expHead + "mta-sts bogus 1 a.test.\n", Problem{4, "mode must be enforce, testing or none"}},
		{"mode of another word", expHead + "mta-sts report 1 a.test.\n", Problem{4, "mode must be enforce, testing or none"}},
		{"max_age one over", expHead + "mta-sts enforce 31557601 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age of 11 digits", expHead + "mta-sts enforce 12345678901 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age of 11 digits, zeros", expHead + "mta-sts enforce 00000000000 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age of 11 digits, padded", expHead + "mta-sts enforce 00031557600 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age of 10 digits, one over", expHead + "mta-sts enforce 0031557601 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age past 32 bits", expHead + "mta-sts enforce 4294967296 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age with a sign", expHead + "mta-sts enforce +1 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age negative", expHead + "mta-sts enforce -1 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age with a fraction", expHead + "mta-sts enforce 1.5 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age with an underscore", expHead + "mta-sts enforce 1_0 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age in hex", expHead + "mta-sts enforce 0x10 a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"max_age a word", expHead + "mta-sts enforce soon a.test.\n", Problem{4, "max_age must be a whole number from 0 to 31557600"}},
		{"no mx with enforce", expHead + "mta-sts enforce 1\n", Problem{4, "mode enforce needs at least one mx pattern"}},
		{"no mx with testing", expHead + "mta-sts testing 1\n", Problem{4, "mode testing needs at least one mx pattern"}},
		{"mx without a trailing dot", expHead + "mta-sts enforce 1 mail.corp.test\n", Problem{4, `"mail.corp.test" has no trailing dot`}},
		{"the second mx without a trailing dot", expHead + "mta-sts enforce 1 a.test. b.test\n", Problem{4, `"b.test" has no trailing dot`}},
		{"a wildcard without a trailing dot", expHead + "mta-sts enforce 1 *.corp.test\n", Problem{4, `"*.corp.test" has no trailing dot`}},
		{"a star alone", expHead + "mta-sts enforce 1 *\n", Problem{4, `"*" has no trailing dot`}},
		{"a comment after the patterns", expHead + "mta-sts enforce 1 a.test. # main\n", Problem{4, `"#" has no trailing dot`}},
		{"the root", expHead + "mta-sts enforce 1 .\n", Problem{4, `bad mx pattern "."`}},
		{"a star and a dot", expHead + "mta-sts enforce 1 *.\n", Problem{4, `bad mx pattern "*."`}},
		{"two stars", expHead + "mta-sts enforce 1 *.*.corp.test.\n", Problem{4, `bad mx pattern "*.*.corp.test."`}},
		{"a star inside", expHead + "mta-sts enforce 1 a.*.test.\n", Problem{4, `bad mx pattern "a.*.test."`}},
		{"a star in a label", expHead + "mta-sts enforce 1 a*.test.\n", Problem{4, `bad mx pattern "a*.test."`}},
		{"an empty label", expHead + "mta-sts enforce 1 a..test.\n", Problem{4, `bad mx pattern "a..test."`}},
		{"two trailing dots", expHead + "mta-sts enforce 1 a.test..\n", Problem{4, `bad mx pattern "a.test.."`}},
		{"a leading dot", expHead + "mta-sts enforce 1 .a.test.\n", Problem{4, `bad mx pattern ".a.test."`}},
		{"an underscore", expHead + "mta-sts enforce 1 a_b.test.\n", Problem{4, `bad mx pattern "a_b.test."`}},
		{"a label that starts with a hyphen", expHead + "mta-sts enforce 1 -a.test.\n", Problem{4, `bad mx pattern "-a.test."`}},
		{"a label that ends with a hyphen", expHead + "mta-sts enforce 1 a-.test.\n", Problem{4, `bad mx pattern "a-.test."`}},
		{"an escape", expHead + `mta-sts enforce 1 a\046b.test.` + "\n", Problem{4, fmt.Sprintf("bad mx pattern %q", `a\046b.test.`)}},
		{"a label of 64 octets", expHead + "mta-sts enforce 1 " + l64 + ".test.\n", Problem{4, fmt.Sprintf("bad mx pattern %q", l64+".test.")}},
		{"a name of 256 octets", expHead + "mta-sts enforce 1 " + l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 62) + ".\n",
			Problem{4, fmt.Sprintf("bad mx pattern %q", l63+"."+l63+"."+l63+"."+strings.Repeat("b", 62)+".")}},
		{"mode none, a bad pattern", expHead + "mta-sts none 1 a_b.test.\n", Problem{4, `bad mx pattern "a_b.test."`}},
		{"65 patterns", expHead + "mta-sts enforce 1 " + fields(65) + "\n", Problem{4, "more than 64 prefixes or patterns"}},
		{"65 patterns of one name", expHead + "mta-sts enforce 1 " + strings.TrimSpace(strings.Repeat("a.test. ", 65)) + "\n", Problem{4, "more than 64 prefixes or patterns"}},
		{"65 patterns, mode none", expHead + "mta-sts none 1 " + fields(65) + "\n", Problem{4, "more than 64 prefixes or patterns"}},
		{"65 patterns that are bad: the count comes first", expHead + "mta-sts enforce 1 " + badFields + "\n", Problem{4, "more than 64 prefixes or patterns"}},
		{"the name of the policy host is too long", "domain " + stpDomain(57) + "\nmta-sts enforce 1 a.test.\n", Problem{2, "the name mta-sts." + stpDomain(57) + " is too long"}},
		{"the name of the policy host is too long, in capitals", "domain " + strings.ToUpper(stpDomain(57)) + "\nmta-sts enforce 1 a.test.\n", Problem{2, "the name mta-sts." + stpDomain(57) + " is too long"}},
		{"the name of the policy host is too long, mode none", "domain " + stpDomain(57) + "\nmta-sts none 1\n", Problem{2, "the name mta-sts." + stpDomain(57) + " is too long"}},
		{"the line before the domain line", "mta-sts enforce 1 a.test.\ndomain corp.test.\n", Problem{2, "the domain line must come before the expectations"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := expProblems(t, c.text); !slices.Equal(got, []Problem{c.want}) {
				t.Errorf("Parse(%s): problems %+v; want only %+v", expShort(c.text), got, c.want)
			}
		})
	}
	t.Run("no domain line", func(t *testing.T) {
		got := expProblems(t, "mta-sts enforce 1 a.test.\n")
		if want := []Problem{{0, "no domain line"}}; !slices.Equal(got, want) {
			t.Errorf("problems %+v; want %+v", got, want)
		}
	})
	t.Run("two faults give both problems in line order", func(t *testing.T) {
		got := expProblems(t, expHead+"mta-sts bogus 1 a.test.\nwww.corp.test. A bad\n")
		if len(got) != 2 || got[0] != (Problem{4, "mode must be enforce, testing or none"}) || got[1].Line != 5 {
			t.Errorf("problems %+v", got)
		}
	})
}

// The keyword is read in lower case only; in another case it is an owner.
func TestSTSLineKeywordIsLowerCase(t *testing.T) {
	for _, w := range []string{"MTA-STS", "Mta-Sts", "mta-sts."} {
		_, err := Parse([]byte(expHead + w + " enforce 1 a.test.\n"))
		if err == nil {
			t.Errorf("%q accepted as the keyword", w)
		}
	}
}

func TestSTSLineLimits(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	line := func(s string) *STSPolicy { return expParse(t, expHead+s+"\n").Policy }
	// 64 patterns and 64 patterns of one name pass.
	var s []string
	for i := range 64 {
		s = append(s, fmt.Sprintf("h%d.corp.test.", i))
	}
	if p := line("mta-sts enforce 1 " + strings.Join(s, " ")); len(p.MX) != 64 {
		t.Errorf("64 patterns gave %d", len(p.MX))
	}
	if p := line("mta-sts enforce 1 " + strings.TrimSpace(strings.Repeat("a.test. ", 64))); len(p.MX) != 1 {
		t.Errorf("64 patterns of one name gave %d", len(p.MX))
	}
	if p := line("mta-sts enforce 1 " + strings.Join(s[:63], " ")); len(p.MX) != 63 {
		t.Errorf("63 patterns gave %d", len(p.MX))
	}
	// max_age.
	for _, c := range []struct {
		text string
		want uint32
	}{{"0", 0}, {"1", 1}, {"31557599", 31557599}, {"31557600", 31557600}, {"0000000000", 0}, {"0031557600", 31557600}, {"0000000001", 1}} {
		if p := line("mta-sts none " + c.text); p.MaxAge != c.want || p.Mode != STSNone {
			t.Errorf("max_age %s read as %+v", c.text, p)
		}
	}
	// The longest name of a pattern, and the longest domain whose policy host fits.
	longest := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61) + "."
	if p := line("mta-sts none 1 " + longest); len(p.MX) != 1 || p.MX[0].String() != longest {
		t.Errorf("the longest name read as %v", p.MX)
	}
	wild := "*." + l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 59) + "."
	if p := line("mta-sts none 1 " + wild); len(p.MX) != 1 || p.MX[0].String() != wild {
		t.Errorf("the longest wildcard read as %v", p.MX)
	}
	f := expParse(t, "domain "+stpDomain(56)+"\nmta-sts enforce 1 a.test.\n")
	if f.Policy == nil {
		t.Errorf("the longest domain whose policy host fits is refused")
	}
}

// The characters of a host name on the line: the first and the last of each
// class, and the one just outside.
func TestSTSLineMXCharacters(t *testing.T) {
	for _, c := range []byte(stpGoodChars) {
		for _, mx := range []string{string(c) + ".test.", "a" + string(c) + ".test.", string(c) + "a.test.", "*." + string(c) + "x.test."} {
			f := expParse(t, expHead+"mta-sts none 1 "+mx+"\n")
			if want := strings.ToLower(mx); len(f.Policy.MX) != 1 || f.Policy.MX[0].String() != want {
				t.Errorf("mx %q read as %v; want %q", mx, stpMXText(*f.Policy), want)
			}
		}
	}
	for _, mx := range []string{"a-b.test.", "0-0.test.", "a--b.c-d.test."} {
		expParse(t, expHead+"mta-sts none 1 "+mx+"\n")
	}
	for _, c := range []byte(stpBadChars + "_!$%&'()+,<=>?^|}~") {
		for _, mx := range []string{"a" + string(c) + "b.test.", string(c) + "a.test.", "a" + string(c) + ".test."} {
			want := Problem{4, fmt.Sprintf("bad mx pattern %q", mx)}
			if got := expProblems(t, expHead+"mta-sts none 1 "+mx+"\n"); !slices.Equal(got, []Problem{want}) {
				t.Errorf("mx %q: problems %+v; want %+v", mx, got, want)
			}
		}
	}
}

func TestSTSLineReadsAndPrints(t *testing.T) {
	f := expParse(t, expHead+"mta-sts testing 0031557600 B.test. *.corp.test. a.corp.test. corp.test. A.TEST. b.test.\n")
	p := f.Policy
	if p == nil {
		t.Fatal("no policy")
	}
	if p.Line != 4 || p.Mode != STSTesting || p.MaxAge != 31557600 {
		t.Errorf("policy %+v; want line 4, testing, 31557600", p)
	}
	// dnswire.Compare order: from the right, a shorter name first.
	want := []string{"a.test.", "b.test.", "corp.test.", "*.corp.test.", "a.corp.test."}
	if got := stpMXText(*p); !slices.Equal(got, want) {
		t.Errorf("patterns %q; want %q", got, want)
	}
	if got, want := p.String(), "mta-sts testing 31557600 a.test. b.test. corp.test. *.corp.test. a.corp.test."; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	// Blanks and tabs between the fields, and leading blanks before the word.
	f = expParse(t, expHead+" \t mta-sts\tnone \t 7\n")
	if f.Policy == nil || f.Policy.String() != "mta-sts none 7" || f.Policy.Line != 4 {
		t.Errorf("policy %+v", f.Policy)
	}
	// No line, no policy, no word in the text.
	f = expParse(t, expHead)
	if f.Policy != nil || strings.Contains(f.String(), "mta-sts") {
		t.Errorf("a file without the line: policy %+v, text %q", f.Policy, f.String())
	}
}

func TestSTSLinePrintPosition(t *testing.T) {
	text := "# a file\nissuer ca.test\nwww.corp.test. A none\ndomain corp.test.\ncertname mail.corp.test.\nmta-sts enforce 604800 b.test. a.test.\nissuer ab.test\n"
	_, err := Parse([]byte(text))
	if err == nil {
		t.Fatal("a domain line after an expectation is accepted")
	}
	text = "domain corp.test.\nwww.corp.test. A none\ncertname mail.corp.test.\nmta-sts enforce 604800 b.test. a.test.\nissuer ca.test\n"
	f := expParse(t, text)
	want := "domain corp.test.\nmta-sts enforce 604800 a.test. b.test.\nissuer ca.test\ncertname mail.corp.test.\nwww.corp.test. A none\n"
	if got := f.String(); got != want {
		t.Errorf("String() =\n%s\nwant\n%s", got, want)
	}
	if f.Policy.Line != 4 {
		t.Errorf("Line = %d; want 4", f.Policy.Line)
	}
	g := expParse(t, f.String())
	if g.String() != want || g.Policy.Line != 2 {
		t.Errorf("round trip: %q, line %d", g.String(), g.Policy.Line)
	}
	// The line is first, directly after the domain line, with and without issuers.
	f = expParse(t, "domain corp.test.\nissuer ca.test\nmta-sts none 5\n")
	if got, want := f.String(), "domain corp.test.\nmta-sts none 5\nissuer ca.test\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
	f = expParse(t, "domain corp.test.\ncertname a.corp.test.\nmta-sts none 5\n")
	if got, want := f.String(), "domain corp.test.\nmta-sts none 5\ncertname a.corp.test.\n"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

func TestSTSLineRoundTripOfAWholeFile(t *testing.T) {
	for _, text := range []string{
		"domain corp.test.\n",
		"domain corp.test.\nmta-sts none 0\n",
		"domain corp.test.\nmta-sts enforce 604800 mail.corp.test.\n",
		"domain corp.test.\nissuer ca.test\ncertname *.corp.test.\n_mta-sts.corp.test. TXT \"v=STSv1; id=1\"\nwww.corp.test. A 192.0.2.1\n",
		"domain corp.test.\nmta-sts enforce 31557600 a.test.\ncorp.test. NS like *.dnshost.test.\n",
	} {
		f := expParse(t, text)
		if got := f.String(); got != text {
			t.Errorf("Parse(%q).String() = %q", text, got)
		}
		g := expParse(t, f.String())
		if g.String() != text {
			t.Errorf("second round: %q; want %q", g.String(), text)
		}
		if (f.Policy == nil) != (g.Policy == nil) {
			t.Errorf("policy lost in %q", text)
		}
	}
}

// The line counts as an expectation of the bound of 10000 (RFC 8461 section 3.2).
func TestSTSLineCountsTowardTheBound(t *testing.T) {
	others := func(n int) string {
		return expLines(n, func(i int) string { return fmt.Sprintf("h%d.corp.test. A none", i) })
	}
	expParse(t, expHead+others(10000))
	expParse(t, expHead+"mta-sts none 1\n"+others(9999))
	expParse(t, expHead+others(9999)+"mta-sts none 1\n")
	for _, text := range []string{expHead + "mta-sts none 1\n" + others(10000), expHead + others(10000) + "mta-sts none 1\n"} {
		got := expProblems(t, text)
		if len(got) != 1 || got[0] != (Problem{0, "more than 10000 expectations"}) {
			t.Errorf("problems %+v; want the bound", got)
		}
	}
	// A faulty line counts too.
	got := expProblems(t, expHead+"mta-sts bogus 1\n"+others(10000))
	if len(got) != 2 || got[0] != (Problem{0, "more than 10000 expectations"}) {
		t.Errorf("problems %+v; want the bound first", got)
	}
}

// A faulty first line counts as given, so that the second line is reported
// too (RFC 8461 section 3.2: one policy).
func TestSTSLineFaultyFirstCountsAsGiven(t *testing.T) {
	got := expProblems(t, expHead+"mta-sts bogus 1 a.test.\nmta-sts enforce 1 a.test.\nmta-sts enforce 1 a.test.\n")
	want := []Problem{{4, "mode must be enforce, testing or none"}, {5, "mta-sts already given on line 4"}, {6, "mta-sts already given on line 4"}}
	if !slices.Equal(got, want) {
		t.Errorf("problems %+v; want %+v", got, want)
	}
}

// ---------------------------------------------------------------------
// Snapshot (RFC 8461 sections 3.1, 3.3 and 8.2).

const (
	stpPolicyHost = "mta-sts.corp.test."
	stpAddr1      = "192.0.2.1:443"
	stpAddr2      = "192.0.2.2:443"
	stpSrv1       = stpAddr1 + " " + stpPolicyHost
	stpSrv2       = stpAddr2 + " " + stpPolicyHost
	stpLine       = "mta-sts enforce 604800 mail.corp.test."
)

func stpTXTResult(t testing.TB, owner string, texts ...string) obs.Result {
	t.Helper()
	var set []dnswire.Record
	for _, text := range texts {
		set = append(set, dnswire.Record{Name: expName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: emlRec(text)})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

// stpPolicyAnswer is one fetch of the policy file that gave body.
func stpPolicyAnswer(t testing.TB, addr, body string) obs.Answer {
	return expAnswer(t, stpPolicyHost, addr, stpTXTResult(t, stpPolicyHost, body))
}

func stpPolicyObs(t testing.TB, answers ...obs.Answer) obs.Observation {
	t.Helper()
	key, ok := obs.PolicyKey(expName(t, "corp.test."))
	if !ok {
		t.Fatal("no policy key")
	}
	return expObs(t, key, "corp.test.", answers...)
}

// stpRecordObs is the records check of _mta-sts.corp.test. TXT, answered by
// two servers with the same texts.
func stpRecordObs(t testing.TB, texts ...string) obs.Observation {
	t.Helper()
	r := stpTXTResult(t, "_mta-sts.corp.test.", texts...)
	return expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, r), expAnswer(t, "ns2.corp.test.", expNS2Addr, r))
}

const stpGoodRecord = "v=STSv1; id=20261117"

// stpPolicySkips gives the skips of the policy host.
func stpPolicySkips(skips []string) []string {
	var out []string
	for _, s := range skips {
		if strings.HasPrefix(s, stpPolicyHost+" TXT") {
			out = append(out, s)
		}
	}
	return out
}

func stpWantLine(t *testing.T, f *File, skips []string, line string) {
	t.Helper()
	if f.Policy == nil {
		t.Fatalf("no mta-sts line; skips %q", skips)
	}
	if got := f.Policy.String(); got != line {
		t.Errorf("line %q; want %q", got, line)
	}
	if got := stpPolicySkips(skips); got != nil {
		t.Errorf("skips of the policy host %q; want none", got)
	}
	if !strings.Contains(f.String(), "\n"+line+"\n") {
		t.Errorf("the text of the file holds no line %q: %q", line, f.String())
	}
}

func stpWantNone(t *testing.T, f *File, skips []string) {
	t.Helper()
	if f.Policy != nil {
		t.Errorf("line %q; want none", f.Policy.String())
	}
	if got := stpPolicySkips(skips); got != nil {
		t.Errorf("skips of the policy host %q; want none", got)
	}
	if strings.Contains(f.String(), "mta-sts ") {
		t.Errorf("the text of the file holds a line: %q", f.String())
	}
}

func TestSTSSnapshotWritesTheLine(t *testing.T) {
	good := stpPolicyAnswer(t, stpAddr1, stpWasBody)
	for _, c := range []struct {
		name string
		obs  []obs.Observation
		line string
	}{
		{"a record and a policy", []obs.Observation{stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, good)}, stpLine},
		{"the policy first, the record after", []obs.Observation{stpPolicyObs(t, good), stpRecordObs(t, stpGoodRecord)}, stpLine},
		{"two servers that give one policy", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, good, stpPolicyAnswer(t, stpAddr2, stpWasBody))}, stpLine},
		{"two servers that give one policy written in two ways", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, good, stpPolicyAnswer(t, stpAddr2, stpBody("mx: MAIL.corp.test.", "max_age: 604800", "version: STSv1", "foo: x", "mode: enforce")))}, stpLine},
		{"two checks that give one policy", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, good), stpPolicyObs(t, stpPolicyAnswer(t, stpAddr2, stpWasBody))}, stpLine},
		{"the line is the canonical text", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, stpPolicyAnswer(t, stpAddr1, "version: STSv1\r\nmode: enforce\r\nmax_age: 604800\r\nmx: Mail.Corp.Test.\r\nmx: b.corp.test\r\nmx: mail.corp.test\r\nfoo: bar\r\n"))},
			"mta-sts enforce 604800 b.corp.test. mail.corp.test."},
		{"a body of several strings", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, expAnswer(t, stpPolicyHost, stpAddr1, stpTXTResult(t, stpPolicyHost, strings.Repeat("foo: "+strings.Repeat("x", 100)+"\n", 12)+stpWasBody)))}, stpLine},
		{"mode none", []obs.Observation{stpRecordObs(t, stpGoodRecord),
			stpPolicyObs(t, stpPolicyAnswer(t, stpAddr1, stpBody("version: STSv1", "mode: none", "max_age: 0")))}, "mta-sts none 0"},
		{"the record beside another text", []obs.Observation{stpRecordObs(t, stpGoodRecord, "something else"), stpPolicyObs(t, good)}, stpLine},
		{"another TXT set ahead of _mta-sts", []obs.Observation{
			expObs(t, expRecordsKey(t, "corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "corp.test.", "v=spf1 -all"))),
			expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "www.corp.test.", "hello"))),
			expObs(t, expRecordsKey(t, "_dmarc.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_dmarc.corp.test.", "v=DMARC1; p=reject"))),
			stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, good)}, stpLine},
		{"an A set at the name of the record, ahead of it", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeA), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, expNoData(t, "corp.test."))),
			stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, good)}, stpLine},
		{"an MTA-STS text at another name, ahead of the record", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.x.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, expNoData(t, "corp.test."))),
			stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, good)}, stpLine},
		{"an IPv6 server with no route, for the record", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.corp.test.", stpGoodRecord)),
				expAnswer(t, "ns6.corp.test.", "[2001:db8::1]:53", expFailure(obs.ReasonNoRoute))),
			stpPolicyObs(t, good)}, stpLine},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, c.obs...)
			stpWantLine(t, f, skips, c.line)
			// The invariant: the line reads back, and the next fetch of the same file gives it again.
			g := expParse(t, f.String())
			if g.Policy == nil || g.Policy.String() != c.line {
				t.Errorf("the file read back gives %+v; want %q", g.Policy, c.line)
			}
			if again, _ := expSnapshot(t, c.obs...); again.String() != f.String() {
				t.Errorf("Snapshot is not deterministic")
			}
		})
	}
}

func TestSTSSnapshotWritesTheLineForAProviderCNAME(t *testing.T) {
	cname := obs.RecordsResult(obs.Records{Set: []dnswire.Record{expRecord(t, "_mta-sts.corp.test.", dnswire.TypeCNAME, "_mta-sts.provider.test.")}})
	recs := expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
		expAnswer(t, "ns1.corp.test.", expNS1Addr, cname), expAnswer(t, "ns2.corp.test.", expNS2Addr, cname))
	f, skips := expSnapshot(t, recs, stpPolicyObs(t, stpPolicyAnswer(t, stpAddr1, stpWasBody)))
	if f.Policy == nil || f.Policy.String() != stpLine {
		t.Fatalf("line %+v; want %q (RFC 8461 section 8.2)", f.Policy, stpLine)
	}
	if got := stpPolicySkips(skips); got != nil {
		t.Errorf("skips of the policy host %q", got)
	}
}

// The record is not on, or not known: no line and no skip for the policy.
func TestSTSSnapshotWritesNothingWhenTheRecordIsNotOn(t *testing.T) {
	good := stpPolicyAnswer(t, stpAddr1, stpWasBody)
	txt := func(r obs.Result) obs.Observation {
		return expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
			expAnswer(t, "ns1.corp.test.", expNS1Addr, r), expAnswer(t, "ns2.corp.test.", expNS2Addr, r))
	}
	for _, c := range []struct {
		name string
		obs  []obs.Observation
	}{
		{"no record observation", []obs.Observation{stpPolicyObs(t, good)}},
		{"only observations of other names", []obs.Observation{
			expObs(t, expRecordsKey(t, "www.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "www.corp.test.", stpGoodRecord))),
			expObs(t, expRecordsKey(t, "_dmarc.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_dmarc.corp.test.", stpGoodRecord))),
			stpPolicyObs(t, good)}},
		{"a record under another name", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.x.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.x.corp.test.", stpGoodRecord))),
			stpPolicyObs(t, good)}},
		{"no data at the record", []obs.Observation{txt(expNoData(t, "corp.test.")), stpPolicyObs(t, good)}},
		{"no such name at the record", []obs.Observation{txt(expNoName(t, "corp.test.")), stpPolicyObs(t, good)}},
		{"a text that is not an MTA-STS record", []obs.Observation{stpRecordObs(t, "v=spf1 -all"), stpPolicyObs(t, good)}},
		{"two records", []obs.Observation{stpRecordObs(t, "v=STSv1; id=1", "v=STSv1; id=2"), stpPolicyObs(t, good)}},
		{"a record that cannot be read", []obs.Observation{stpRecordObs(t, "v=STSv1; id=abc!"), stpPolicyObs(t, good)}},
		{"a record without an id", []obs.Observation{stpRecordObs(t, "v=STSv1;"), stpPolicyObs(t, good)}},
		{"a record in lower case", []obs.Observation{stpRecordObs(t, "v=stsv1; id=1"), stpPolicyObs(t, good)}},
		{"a record of 4097 octets", []obs.Observation{stpRecordObs(t, emlPad("v=STSv1; id=1; x=", 4097)), stpPolicyObs(t, good)}},
		{"the record failed at both servers", []obs.Observation{txt(expFailure(obs.ReasonTimeout)), stpPolicyObs(t, good)}},
		{"the record failed at one server", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.corp.test.", stpGoodRecord)),
				expAnswer(t, "ns2.corp.test.", expNS2Addr, expFailure(obs.ReasonTimeout))),
			stpPolicyObs(t, good)}},
		{"the record of an IPv6 server with no route is the only answer", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns6.corp.test.", "[2001:db8::1]:53", expFailure(obs.ReasonNoRoute))),
			stpPolicyObs(t, good)}},
		{"the servers disagree on the record", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.corp.test.", "v=STSv1; id=1")),
				expAnswer(t, "ns2.corp.test.", expNS2Addr, stpTXTResult(t, "_mta-sts.corp.test.", "v=STSv1; id=2"))),
			stpPolicyObs(t, good)}},
		{"one server has the record and the other has none", []obs.Observation{
			expObs(t, expRecordsKey(t, "_mta-sts.corp.test.", dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.corp.test.", stpGoodRecord)),
				expAnswer(t, "ns2.corp.test.", expNS2Addr, expNoData(t, "corp.test."))),
			stpPolicyObs(t, good)}},
		{"the record check of another domain", []obs.Observation{
			expObs(t, obs.RecordsKey(expName(t, "other.test."), expName(t, "_mta-sts.corp.test."), dnswire.TypeTXT), "corp.test.",
				expAnswer(t, "ns1.corp.test.", expNS1Addr, stpTXTResult(t, "_mta-sts.corp.test.", stpGoodRecord))),
			stpPolicyObs(t, good)}},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, c.obs...)
			stpWantNone(t, f, skips)
		})
	}
	// A bad policy under an off record gives no skip either.
	f, skips := expSnapshot(t, stpRecordObs(t, "v=STSv1; id=abc!"),
		stpPolicyObs(t, stpPolicyAnswer(t, stpAddr1, "garbage\n")),
		stpPolicyObs(t, expAnswer(t, stpPolicyHost, "", expFailure(obs.ReasonTimeout))))
	stpWantNone(t, f, skips)
}

func TestSTSSnapshotSkips(t *testing.T) {
	good := func(addr string) obs.Answer { return stpPolicyAnswer(t, addr, stpWasBody) }
	testing_ := stpBody("version: STSv1", "mode: testing", "max_age: 604800", "mx: mail.corp.test")
	failed := func(addr string, r obs.Reason) obs.Answer {
		return expAnswer(t, stpPolicyHost, addr, expFailure(r))
	}
	read := func(why string) string { return "the policy file cannot be read: " + why }
	for _, c := range []struct {
		name    string
		answers []obs.Answer
		want    string
	}{
		{"a fetch that timed out", []obs.Answer{failed("", obs.ReasonTimeout)}, "- " + stpPolicyHost + " gave no answer: timeout"},
		{"a fetch that gave a bad answer", []obs.Answer{failed(stpAddr1, obs.ReasonBadAnswer)}, stpSrv1 + " gave no answer: bad-answer"},
		{"a fetch that was not permitted", []obs.Answer{failed(stpAddr1, obs.ReasonNotPermitted)}, stpSrv1 + " gave no answer: not-permitted"},
		{"a fetch that failed on the network", []obs.Answer{failed("", obs.ReasonNetwork)}, "- " + stpPolicyHost + " gave no answer: network"},
		{"a good answer followed by a failed one", []obs.Answer{good(stpAddr1), failed(stpAddr2, obs.ReasonTimeout)}, stpSrv2 + " gave no answer: timeout"},
		{"a failed answer followed by a good one", []obs.Answer{failed(stpAddr2, obs.ReasonTimeout), good(stpAddr1)}, stpSrv2 + " gave no answer: timeout"},
		{"two failed answers: the first", []obs.Answer{failed(stpAddr1, obs.ReasonTimeout), failed(stpAddr2, obs.ReasonBadAnswer)}, stpSrv1 + " gave no answer: timeout"},
		{"a failure without an answer", []obs.Answer{{}}, "- - gave no answer: none"},
		{"no data", []obs.Answer{expAnswer(t, stpPolicyHost, stpAddr1, expNoData(t, "corp.test."))}, read(stpNoVersion)},
		{"no such name", []obs.Answer{expAnswer(t, stpPolicyHost, stpAddr1, expNoName(t, "corp.test."))}, read(stpNoVersion)},
		{"an empty body", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "")}, read(stpNoVersion)},
		{"a good answer followed by an unreadable one", []obs.Answer{good(stpAddr1), stpPolicyAnswer(t, stpAddr2, "version: STSv2\n")}, read(stpBadVersion)},
		{"an unreadable answer followed by a good one", []obs.Answer{stpPolicyAnswer(t, stpAddr2, "version: STSv2\n"), good(stpAddr1)}, read(stpBadVersion)},
		{"an unreadable answer followed by a failed one", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "garbage"), failed(stpAddr2, obs.ReasonTimeout)}, read(stpNoColon)},
		{"a failed answer followed by an unreadable one", []obs.Answer{failed(stpAddr2, obs.ReasonTimeout), stpPolicyAnswer(t, stpAddr1, "garbage")}, stpSrv2 + " gave no answer: timeout"},
		{"no mode", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmax_age: 1\nmx: a.test\n")}, read(stpNoMode)},
		{"a bad mode", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmode: x\nmax_age: 1\nmx: a.test\n")}, read(stpBadMode)},
		{"no max_age", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmode: testing\nmx: a.test\n")}, read(stpNoAge)},
		{"a bad max_age", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmode: testing\nmax_age: 31557601\nmx: a.test\n")}, read(stpBadAge)},
		{"no mx", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmode: testing\nmax_age: 1\n")}, read(stpNoMX)},
		{"a bad mx", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\nmode: testing\nmax_age: 1\nmx: a_b.test\n")}, read(stpBadMX)},
		{"too many mx", []obs.Answer{stpPolicyAnswer(t, stpAddr1, stpMXLines(65, true))}, read(stpManyMX)},
		{"too long", []obs.Answer{stpPolicyAnswer(t, stpAddr1, stpPadded(65537, ""))}, read(stpTooLong)},
		{"a non printable octet", []obs.Answer{stpPolicyAnswer(t, stpAddr1, "version: STSv1\x00\n")}, read(stpNotASCII)},
		{"two policies that differ in the mode", []obs.Answer{good(stpAddr1), stpPolicyAnswer(t, stpAddr2, testing_)},
			"servers disagree: " + stpSrv1 + " gives " + stpLine + "; " + stpSrv2 + " gives mta-sts testing 604800 mail.corp.test."},
		{"two policies that differ in the mode, the other way round", []obs.Answer{stpPolicyAnswer(t, stpAddr2, testing_), good(stpAddr1)},
			"servers disagree: " + stpSrv2 + " gives mta-sts testing 604800 mail.corp.test.; " + stpSrv1 + " gives " + stpLine},
		{"two policies that differ in max_age", []obs.Answer{good(stpAddr1), stpPolicyAnswer(t, stpAddr2, strings.Replace(stpWasBody, "604800", "604801", 1))},
			"servers disagree: " + stpSrv1 + " gives " + stpLine + "; " + stpSrv2 + " gives mta-sts enforce 604801 mail.corp.test."},
		{"two policies that differ in the names", []obs.Answer{good(stpAddr1), stpPolicyAnswer(t, stpAddr2, strings.Replace(stpWasBody, "mail", "evil", 1))},
			"servers disagree: " + stpSrv1 + " gives " + stpLine + "; " + stpSrv2 + " gives mta-sts enforce 604800 evil.corp.test."},
		{"two policies that differ in one name more", []obs.Answer{good(stpAddr1), stpPolicyAnswer(t, stpAddr2, stpWasBody+"mx: b.test\n")},
			"servers disagree: " + stpSrv1 + " gives " + stpLine + "; " + stpSrv2 + " gives mta-sts enforce 604800 b.test. mail.corp.test."},
		{"the third answer differs", []obs.Answer{good(stpAddr1), good(stpAddr1), stpPolicyAnswer(t, stpAddr2, testing_)},
			"servers disagree: " + stpSrv1 + " gives " + stpLine + "; " + stpSrv2 + " gives mta-sts testing 604800 mail.corp.test."},
	} {
		t.Run(c.name, func(t *testing.T) {
			f, skips := expSnapshot(t, stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, c.answers...))
			if f.Policy != nil {
				t.Errorf("line %q; want none", f.Policy.String())
			}
			want := stpPolicyHost + " TXT: " + c.want
			if got := stpPolicySkips(skips); !slices.Equal(got, []string{want}) {
				t.Errorf("skips %q; want [%q]", got, want)
			}
		})
	}
}

// Two checks of the policy file, each with its answer: the skips and the
// line follow the same rules as the answers of one check.
func TestSTSSnapshotTwoChecks(t *testing.T) {
	good := stpPolicyAnswer(t, stpAddr1, stpWasBody)
	bad := expAnswer(t, stpPolicyHost, stpAddr2, expFailure(obs.ReasonTimeout))
	f, skips := expSnapshot(t, stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, good), stpPolicyObs(t, bad))
	if f.Policy != nil || !slices.Equal(stpPolicySkips(skips), []string{stpPolicyHost + " TXT: " + stpSrv2 + " gave no answer: timeout"}) {
		t.Errorf("policy %+v, skips %q", f.Policy, skips)
	}
	f, skips = expSnapshot(t, stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, bad), stpPolicyObs(t, good))
	if f.Policy != nil || len(stpPolicySkips(skips)) != 1 {
		t.Errorf("policy %+v, skips %q", f.Policy, skips)
	}
}

// The line is the canonical text of what the fetch read, so a policy that
// reads to the same policy gives the same line, whatever its writing.
func TestSTSSnapshotLineEqualsTheReading(t *testing.T) {
	for _, body := range []string{
		stpWasBody,
		strings.ReplaceAll(stpWasBody, "\n", "\r\n"),
		stpBody("version: STSv1", "mode: testing", "max_age: 0031557600", "mx: *.corp.test", "mx: B.test.", "mx: a.test"),
		stpBody("version: STSv1", "mode: none", "max_age: 0", "mx: z.test"),
		stpBody("version: STSv1", "mode: none", "max_age: 0"),
	} {
		want := stpRead(t, body).String()
		f, skips := expSnapshot(t, stpRecordObs(t, stpGoodRecord), stpPolicyObs(t, stpPolicyAnswer(t, stpAddr1, body)))
		stpWantLine(t, f, skips, want)
		g := expParse(t, f.String())
		if g.Policy == nil || g.Policy.String() != want {
			t.Errorf("read back: %+v; want %q", g.Policy, want)
		}
	}
}

// Other domains' observations do not count.
func TestSTSSnapshotIgnoresAnotherDomain(t *testing.T) {
	key, _ := obs.PolicyKey(expName(t, "other.test."))
	other := expObs(t, key, "other.test.", expAnswer(t, "mta-sts.other.test.", stpAddr1, stpTXTResult(t, "mta-sts.other.test.", stpWasBody)))
	f, skips := expSnapshot(t, stpRecordObs(t, stpGoodRecord), other)
	stpWantNone(t, f, skips)
}

// ---------------------------------------------------------------------
// The order as a property (RFC 8461 sections 4.1 and 5).

type stpModel struct {
	mode int // 1 none, 2 testing, 3 enforce
	age  int
	mx   []string // lower case, with the trailing dot
}

var stpPool = []string{"mail.corp.test.", "*.corp.test.", "a.corp.test.", "b.corp.test.", "*.a.corp.test.", "x.a.corp.test.", "evil.test.", "*.test.", "corp.test.", "*.evil.test."}
var stpAges = []int{0, 1, 86400, 604800, 604801, 31557600}
var stpModes = []string{"", "none", "testing", "enforce"}

func (m stpModel) clone() stpModel { m.mx = slices.Clone(m.mx); return m }

func stpGen(r *rand.Rand) stpModel {
	m := stpModel{mode: 1 + r.IntN(3), age: stpAges[r.IntN(len(stpAges))]}
	for _, p := range stpPool {
		if r.IntN(3) == 0 {
			m.mx = append(m.mx, p)
		}
	}
	if len(m.mx) == 0 && m.mode != 1 {
		m.mx = []string{stpPool[r.IntN(len(stpPool))]}
	}
	return m
}

// stpWrite writes the model as a policy file, in a random way that does not
// change what it says.
func stpWrite(r *rand.Rand, m stpModel) string {
	lines := []string{"version: STSv1", "mode: " + stpModes[m.mode], "max_age: " + strconv.Itoa(m.age)}
	for _, p := range m.mx {
		for range 1 + r.IntN(2) {
			text := p
			if r.IntN(2) == 0 {
				text = strings.TrimSuffix(text, ".")
			}
			if r.IntN(2) == 0 {
				text = strings.ToUpper(text)
			}
			lines = append(lines, "mx:"+strings.Repeat(" ", r.IntN(3))+text+strings.Repeat("\t", r.IntN(2)))
		}
	}
	extra := []string{"foo: bar", "x-y: a:b", "MX: evil.test", "Mode: none", "Version: x", "", "version :x"}
	for range r.IntN(4) {
		lines = append(lines, extra[r.IntN(len(extra))])
	}
	r.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	nl := "\n"
	if r.IntN(2) == 0 {
		nl = "\r\n"
	}
	text := strings.Join(lines, nl)
	if r.IntN(2) == 0 {
		text += nl
	}
	return text
}

func stpCovers(p, q string) bool {
	if p == q {
		return true
	}
	rest, ok := strings.CutPrefix(p, "*.")
	if !ok {
		return false
	}
	label, tail, ok := strings.Cut(q, ".")
	return ok && label != "" && tail == rest
}

func stpLess(a, b string) int {
	la, lb := strings.Split(strings.TrimSuffix(a, "."), "."), strings.Split(strings.TrimSuffix(b, "."), ".")
	for i, j := len(la)-1, len(lb)-1; i >= 0 && j >= 0; i, j = i-1, j-1 {
		if c := strings.Compare(la[i], lb[j]); c != 0 {
			return c
		}
	}
	return len(la) - len(lb)
}

// stpOracle gives the words of the design for two models.
func stpOracle(was, now stpModel) []string {
	var words []string
	if now.mode < was.mode {
		if now.mode == 2 {
			words = append(words, stpTesting)
		} else {
			words = append(words, stpNoneIn(stpModes[was.mode]))
		}
	}
	if now.age < was.age {
		words = append(words, stpAgeWord(now.age, was.age))
	}
	mx := slices.Clone(now.mx)
	slices.SortFunc(mx, stpLess)
	for _, q := range slices.Compact(mx) {
		if !slices.ContainsFunc(was.mx, func(p string) bool { return stpCovers(p, q) }) {
			words = append(words, "mx "+q+stpMXTail)
		}
	}
	if len(words) > MaxWords {
		words = append(words[:MaxWords-1], "and "+strconv.Itoa(len(words)-(MaxWords-1))+" more")
	}
	return words
}

// stpEdit changes the model by one edit: stricter when up, else weaker.
func stpEdit(r *rand.Rand, m stpModel, up bool) stpModel {
	m = m.clone()
	switch r.IntN(3) {
	case 0:
		// A policy with no pattern that asks for a mode that needs one has
		// a new pattern, which the order rightly reports.
		if up && m.mode < 3 && len(m.mx) > 0 {
			m.mode++
		} else if !up && m.mode > 1 {
			m.mode--
		}
	case 1:
		if up {
			m.age = min(31557600, m.age+1+r.IntN(1000))
		} else {
			m.age = r.IntN(m.age + 1)
		}
	default:
		if up {
			if len(m.mx) > 1 {
				m.mx = slices.Delete(m.mx, 0, 1)
			} else if len(m.mx) == 1 && m.mx[0] == "*.corp.test." {
				m.mx[0] = "a.corp.test."
			}
		} else {
			m.mx = append(m.mx, stpPool[r.IntN(len(stpPool))])
		}
	}
	if m.mode != 1 && len(m.mx) == 0 {
		m.mx = []string{"mail.corp.test."}
	}
	return m
}

func TestSTSPolicyOrderProperty(t *testing.T) {
	r := rand.New(rand.NewPCG(stpSeed, 1))
	const cases = 1500
	premises := 0
	for i := range cases {
		fail := func(format string, args ...any) {
			t.Helper()
			t.Fatalf("seed %d case %d: %s", stpSeed, i, fmt.Sprintf(format, args...))
		}
		xm, ym := stpGen(r), stpGen(r)
		x, y := stpRead(t, stpWrite(r, xm)), stpRead(t, stpWrite(r, ym))
		// Written otherwise: the same text, and the order does not see it.
		x2 := stpRead(t, stpWrite(r, xm))
		if x.String() != x2.String() {
			fail("two writings of one model read as %q and %q", x.String(), x2.String())
		}
		// Reflexive.
		if w := STSPolicyWeaker(x, x); w != nil {
			fail("Weaker(x, x) = %q for %s", w, x)
		}
		if w := STSPolicyWeaker(x, x2); w != nil {
			fail("Weaker(x, r(x)) = %q for %s", w, x)
		}
		if w := STSPolicyWeaker(x2, x); w != nil {
			fail("Weaker(r(x), x) = %q for %s", w, x)
		}
		// The words are those of the design, bounded, and the same twice.
		got := STSPolicyWeaker(x, y)
		emlCheckWords(t, got)
		if want := stpOracle(xm, ym); !slices.Equal(got, want) || (got == nil) != (want == nil) {
			fail("Weaker(%s, %s) = %q; want %q", x, y, got, want)
		}
		if again := STSPolicyWeaker(x, y); !emlSameWords(got, again) {
			fail("not deterministic: %q then %q", got, again)
		}
		if a, b := STSPolicyWeaker(x2, y), got; !emlSameWords(a, b) {
			fail("Weaker(r(x), y) = %q but Weaker(x, y) = %q", a, b)
		}
		if a, b := STSPolicyWeaker(y, x2), STSPolicyWeaker(y, x); !emlSameWords(a, b) {
			fail("Weaker(y, r(x)) = %q but Weaker(y, x) = %q", a, b)
		}
		// A stricter edit gives no word.
		strict := stpEdit(r, xm, true)
		if w := STSPolicyWeaker(x, stpRead(t, stpWrite(r, strict))); w != nil {
			fail("a stricter edit gives %q: %v -> %v", w, xm, strict)
		}
		// A weakening edit gives a word, in the words of the design.
		weak := stpEdit(r, xm, false)
		if want := stpOracle(xm, weak); len(want) > 0 {
			if w := STSPolicyWeaker(x, stpRead(t, stpWrite(r, weak))); !slices.Equal(w, want) {
				fail("a weakening edit gives %q; want %q: %v -> %v", w, want, xm, weak)
			}
		}
		// Transitive.
		bm := xm
		for n := r.IntN(4); n > 0; n-- {
			bm = stpEdit(r, bm, r.IntN(4) != 0)
		}
		cm := bm
		for n := r.IntN(4); n > 0; n-- {
			cm = stpEdit(r, cm, r.IntN(4) != 0)
		}
		a, b, c := x, stpRead(t, stpWrite(r, bm)), stpRead(t, stpWrite(r, cm))
		if STSPolicyWeaker(a, b) == nil && STSPolicyWeaker(b, c) == nil {
			premises++
			if w := STSPolicyWeaker(a, c); w != nil {
				fail("transitive: Weaker(a, c) = %q; a = %s b = %s c = %s", w, a, b, c)
			}
		}
	}
	if premises < 200 {
		t.Errorf("the premises of transitivity held in %d of %d cases; want at least 200", premises, cases)
	}
}

func TestSTSPolicyWeakeningEditsGiveWords(t *testing.T) {
	f := func(mode, age string, mx ...string) STSPolicy {
		lines := []string{"version: STSv1", "mode: " + mode, "max_age: " + age}
		for _, m := range mx {
			lines = append(lines, "mx: "+m)
		}
		return stpRead(t, stpBody(lines...))
	}
	for _, c := range []struct {
		name     string
		was, now STSPolicy
		word     string
	}{
		{"a lower mode", f("enforce", "1", "a.test"), f("testing", "1", "a.test"), stpTesting},
		{"a lower max_age", f("enforce", "100", "a.test"), f("enforce", "99", "a.test"), stpAgeWord(99, 100)},
		{"a pattern that no pattern covers", f("enforce", "1", "a.test"), f("enforce", "1", "a.test", "b.test"), "mx b.test." + stpMXTail},
		{"a pattern widened to a wildcard", f("enforce", "1", "a.corp.test"), f("enforce", "1", "*.corp.test"), "mx *.corp.test." + stpMXTail},
		{"none in place of testing", f("testing", "1", "a.test"), f("none", "1", "a.test"), stpNoneIn("testing")},
	} {
		got := STSPolicyWeaker(c.was, c.now)
		if !slices.Equal(got, []string{c.word}) {
			t.Errorf("%s: words %q; want [%q]", c.name, got, c.word)
		}
		emlCheckWords(t, got)
	}
}

// ---------------------------------------------------------------------
// Fuzz tests.

func FuzzSTSPolicy(f *testing.F) {
	seeds := []string{
		stpWasBody,
		strings.ReplaceAll(stpWasBody, "\n", "\r\n"),
		stpBody("version: STSv1", "mode: none", "max_age: 0"),
		stpBody("version: STSv1", "mode: testing", "max_age: 0031557600", "mx: *.corp.test", "mx: A.b.test.", "foo: bar"),
		stpBody("version: STSv1", "mode: enforce", "max_age: 99999999999", "mx: a.test"),
		stpBody("version: STSv1", "mode: enforce", "max_age: 1", "mx: *."),
		"garbage", "\x00", "version: STSv1\x7f\n", "", "\r\n\r\n",
		stpBody("mode: testing", "mode: enforce", "version: STSv1", "version: x", "max_age: 1", "max_age: x", "mx: a.test"),
		stpMXLines(64, true), stpMXLines(65, true), stpPadded(65536, ""), stpPadded(65537, ""),
	}
	for _, a := range seeds {
		for _, b := range seeds[:5] {
			f.Add([]byte(a), []byte(b), []byte(seeds[0]))
		}
	}
	f.Fuzz(func(t *testing.T, was, now, third []byte) {
		p, problem := ParseSTSPolicy(now)
		stpCheckReading(t, now, p, problem)
		if q, again := ParseSTSPolicy(now); again != problem || q.String() != p.String() {
			t.Fatalf("ParseSTSPolicy is not deterministic: %q %q", problem, again)
		}
		w, wp := ParseSTSPolicy(was)
		stpCheckReading(t, was, w, wp)
		c, cp := ParseSTSPolicy(third)
		if wp == "" && problem == "" {
			if got := STSPolicyWeaker(p, p); got != nil {
				t.Fatalf("Weaker(x, x) = %q for %s", got, p)
			}
			got := STSPolicyWeaker(w, p)
			emlCheckWords(t, got)
			if again := STSPolicyWeaker(w, p); !emlSameWords(got, again) {
				t.Fatalf("Weaker is not deterministic: %q then %q", got, again)
			}
			for _, word := range got {
				if strings.ContainsAny(word, "\r\n\t") {
					t.Fatalf("word %q holds a line break or tab", word)
				}
			}
			if cp == "" && STSPolicyWeaker(w, p) == nil && STSPolicyWeaker(p, c) == nil {
				if got := STSPolicyWeaker(w, c); got != nil {
					t.Fatalf("not transitive: %q for %s, %s, %s", got, w, p, c)
				}
			}
		}
	})
}

func stpCheckReading(t *testing.T, body []byte, p STSPolicy, problem string) {
	t.Helper()
	if problem != "" {
		if !slices.Contains(stpProblems, problem) {
			t.Fatalf("problem %q is not one of the fixed texts", problem)
		}
		if p.Mode != 0 || p.MaxAge != 0 || p.MX != nil || p.Line != 0 {
			t.Fatalf("a policy with a problem %q is not zero: %+v", problem, p)
		}
		return
	}
	if len(body) > 65536 {
		t.Fatalf("a body of %d octets reads", len(body))
	}
	if p.Line != 0 || p.Mode < STSNone || p.Mode > STSEnforce || p.MaxAge > 31557600 || len(p.MX) > 64 {
		t.Fatalf("policy out of bounds: %+v", p)
	}
	if p.Mode != STSNone && len(p.MX) == 0 {
		t.Fatalf("mode %d with no mx", p.Mode)
	}
	for i, n := range p.MX {
		if !n.Equal(n.Lower()) || n.String() != strings.ToLower(n.String()) {
			t.Fatalf("pattern %q is not in lower case", n)
		}
		if i > 0 && dnswire.Compare(p.MX[i-1], n) >= 0 {
			t.Fatalf("patterns %q and %q are out of order or equal", p.MX[i-1], n)
		}
		s := n.String()
		if s == "." || strings.Trim(s, "abcdefghijklmnopqrstuvwxyz0123456789-.*") != "" || strings.Contains(s, "..") || strings.LastIndex(s, "*") > 0 {
			t.Fatalf("pattern %q is outside the grammar", s)
		}
	}
	text := p.String()
	for i := 0; i < len(text); i++ {
		if text[i] < 0x20 || text[i] > 0x7E {
			t.Fatalf("String() holds octet 0x%02X", text[i])
		}
	}
	if got := len(strings.Fields(text)); got != 3+len(p.MX) {
		t.Fatalf("String() %q has %d fields; want %d", text, got, 3+len(p.MX))
	}
	// The text is a line of the file that reads back to itself.
	file, err := Parse([]byte("domain corp.test.\n" + text + "\n"))
	if err != nil || file.Policy == nil || file.Policy.String() != text {
		t.Fatalf("the line %q reads as %+v, %v", text, file, err)
	}
	// And its words are a policy file that reads to the same text.
	lines := []string{"version: STSv1", "mode: " + stpModeWord(p.Mode), "max_age: " + strconv.Itoa(int(p.MaxAge))}
	for _, n := range p.MX {
		lines = append(lines, "mx: "+n.String())
	}
	if q, problem := ParseSTSPolicy([]byte(stpBody(lines...))); problem != "" || q.String() != text {
		t.Fatalf("the words of %q read as %q, %q", text, q.String(), problem)
	}
	// A file with CRLF reads the same, when it holds no CR.
	if len(body) < 60000 && !strings.Contains(string(body), "\r") {
		crlf := strings.ReplaceAll(string(body), "\n", "\r\n")
		if q, problem := ParseSTSPolicy([]byte(crlf)); problem != "" || q.String() != text {
			t.Fatalf("with CRLF: %q, %q; want %q", q.String(), problem, text)
		}
	}
}

// FuzzParseFile covers the whole file parser, with the mta-sts line in its
// seeds: no panic, and a file that parses prints and parses again to the
// same file.
func FuzzParseFile(f *testing.F) {
	for _, s := range []string{
		"",
		expHead,
		"domain corp.test.\nmta-sts enforce 604800 mail.corp.test.\n",
		"domain corp.test.\nmta-sts none 0\n",
		"domain corp.test.\nmta-sts testing 31557600 *.corp.test. a.test. A.TEST.\nissuer ca.test\ncertname *.corp.test.\nwww.corp.test. A 192.0.2.1\n",
		"mta-sts enforce 1 a.test.\ndomain corp.test.\n",
		"domain corp.test.\nmta-sts enforce 1 a.test.\nmta-sts enforce 1 a.test.\n",
		"domain corp.test.\nmta-sts enforce 1 a_b.test. *.\n",
		"domain corp.test.\nmta-sts enforce 99999999999 a.test.\n",
		"domain corp.test.\nmta-sts bogus\n",
		"domain " + stpDomain(57) + "\nmta-sts none 1\n",
		"domain " + stpDomain(56) + "\nmta-sts none 1\n",
		"domain corp.test.\n_mta-sts.corp.test. TXT \"v=STSv1; id=1\"\nmta-sts enforce 1 mail.corp.test.\r\n",
		"domain corp.test.\nmta-sts enforce 1 " + strings.TrimSpace(strings.Repeat("a.test. ", 65)) + "\n",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		file, err := Parse(data)
		if err != nil {
			var e *Error
			if !errors.As(err, &e) || len(e.Problems) == 0 || len(e.Problems) > 100 || file != nil {
				t.Fatalf("Parse gave %v, %v", file, err)
			}
			for _, p := range e.Problems {
				if p.Line < 0 || p.Text == "" {
					t.Fatalf("problem %+v", p)
				}
			}
			return
		}
		text := file.String()
		again, err := Parse([]byte(text))
		if err != nil {
			t.Fatalf("the text %q of a file does not parse: %v", text, err)
		}
		if got := again.String(); got != text {
			t.Fatalf("round trip: %q then %q", text, got)
		}
		if (file.Policy == nil) != (again.Policy == nil) {
			t.Fatalf("the mta-sts line is lost in %q", text)
		}
		if file.Policy != nil {
			if file.Policy.Line < 2 || !strings.Contains(text, "\n"+file.Policy.String()+"\n") {
				t.Fatalf("policy %+v not in %q", file.Policy, text)
			}
			if !strings.HasPrefix(text[strings.Index(text, "\n")+1:], file.Policy.String()+"\n") {
				t.Fatalf("the mta-sts line is not right after the domain line: %q", text)
			}
			if len(file.Policy.MX) > 64 || file.Policy.MaxAge > 31557600 {
				t.Fatalf("policy out of bounds: %+v", file.Policy)
			}
		}
	})
}
