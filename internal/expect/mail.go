package expect

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// MailKind is the mail policy that the TXT records at an owner hold.
type MailKind uint8

const (
	MailSPF    MailKind = iota + 1 // any owner that none of the three below names (RFC 7208)
	MailDMARC                      // first label "_dmarc", ignoring case (RFC 7489 section 6.1)
	MailDKIM                       // a label "_domainkey" after the first, ignoring case (RFC 6376 section 3.6.2.1)
	MailMTASTS                     // first label "_mta-sts", ignoring case (RFC 8461 section 3.1)
)

// MaxWords bounds the words of one comparison.
const MaxWords = 12

const (
	// maxText is the longest record text that osk-dns-watcher reads. Each reader says
	// what a longer one means.
	maxText = 4096
	// maxWordLen bounds a word: a domain-spec, a report address or a key
	// type can be almost as long as a record.
	maxWordLen = 240
)

const (
	alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
	alnum = alpha + "0123456789"
)

// MailKindOf gives the policy that the records at owner hold. A first label
// decides before a later "_domainkey".
func MailKindOf(owner dnswire.Name) MailKind {
	labels := owner.Labels()
	switch {
	case len(labels) == 0:
		return MailSPF
	case lowerASCII(labels[0]) == "_dmarc":
		return MailDMARC
	case lowerASCII(labels[0]) == "_mta-sts":
		return MailMTASTS
	case slices.ContainsFunc(labels[1:], func(l string) bool { return lowerASCII(l) == "_domainkey" }):
		return MailDKIM
	}
	return MailSPF
}

// HasSPF reports whether set holds one or more records that RFC 7208
// section 4.5 selects as SPF, two included.
func HasSPF(set []dnswire.RData) bool {
	return len(policyRecords(set, spfVersion)) > 0
}

// Weaker gives each way in which the policy of a set of now permits more
// than the policy of was, in words: those of each set after those of the
// sets before it, merged by MergeWords; nil when no set permits more. owner
// is the owner of the line; only SPF reads it. Total on any input,
// deterministic, at most MaxWords words, each of printable ASCII (0x20 to
// 0x7E) and at most 240 octets.
func Weaker(k MailKind, owner dnswire.Name, was []dnswire.RData, now ...[]dnswire.RData) []string {
	var lists [][]string
	for _, set := range now {
		lists = append(lists, weaker(k, owner, was, set))
	}
	return MergeWords(lists...)
}

func weaker(k MailKind, owner dnswire.Name, was, now []dnswire.RData) []string {
	var compare func(was, now []dnswire.RData) []string
	switch k {
	case MailDKIM:
		return dkimWeaker(readDKIM(was), readDKIM(now))
	case MailSPF:
		compare = func(was, now []dnswire.RData) []string {
			return spfWeaker(readSPF(owner, was), readSPF(owner, now))
		}
	case MailDMARC:
		compare = func(was, now []dnswire.RData) []string {
			return dmarcWeaker(readDMARC(was), readDMARC(now))
		}
	case MailMTASTS:
		compare = func(was, now []dnswire.RData) []string {
			return stsWeaker(readSTS(was), readSTS(now))
		}
	default:
		return nil
	}
	// A CNAME hands the record to another zone, which osk-dns-watcher does not follow:
	// the set reads as no record, and the words name the CNAME in place of
	// the word for no record.
	if len(cnameTargets(was)) > 0 {
		was = nil
	}
	targets := cnameTargets(now)
	if len(targets) > 0 {
		now = nil
	}
	words := compare(was, now)
	if len(words) == 0 || len(targets) == 0 {
		return words
	}
	named := make([]string, len(targets))
	for i, t := range targets {
		named[i] = "a CNAME to " + t + ": another zone holds the record, and osk-dns-watcher does not read it"
	}
	return named
}

// cnameTargets gives the targets of the CNAME records of set, in lower case,
// in octet order, each once.
func cnameTargets(set []dnswire.RData) []string {
	var targets []string
	for _, d := range set {
		if c, ok := d.(dnswire.CNAME); ok {
			targets = append(targets, c.Target.Lower().String())
		}
	}
	slices.Sort(targets)
	return slices.Compact(targets)
}

// SPFTargets gives the names that the SPF policy of set makes receivers look
// up: the include domains of the terms before the first all, in order, then
// the redirect domain when there is no all. A domain with a macro is left
// out: it names no single name. nil when set has no usable SPF record.
func SPFTargets(owner dnswire.Name, set []dnswire.RData) []dnswire.Name {
	p := readSPF(owner, set)
	var names []dnswire.Name
	for _, t := range p.terms {
		if n, ok := specName(t.spec); ok && t.mech == "include" {
			names = append(names, n)
		}
	}
	if n, ok := p.redirect(); ok {
		names = append(names, n)
	}
	return names
}

// SPFRedirect gives the redirect target that SPFTargets gives as its last
// name, when there is one: a record with no all and a redirect= that names
// one domain. false otherwise.
func SPFRedirect(owner dnswire.Name, set []dnswire.RData) (dnswire.Name, bool) {
	return readSPF(owner, set).redirect()
}

// MergeWords joins lists of words, list after list, each in its order. A
// word longer than 240 octets is cut to its first 237 octets and "...".
// Each word is kept once, at its first place. When more than MaxWords
// words are left, the first MaxWords - 1 are kept and then "and <k> more".
// nil when there are no words.
func MergeWords(lists ...[]string) []string {
	var out []string
	kept := map[string]bool{}
	for _, words := range lists {
		for _, w := range words {
			if len(w) > maxWordLen {
				w = w[:maxWordLen-3] + "..."
			}
			if !kept[w] {
				kept[w] = true
				out = append(out, w)
			}
		}
	}
	if len(out) > MaxWords {
		out = append(out[:MaxWords-1], "and "+strconv.Itoa(len(out)-(MaxWords-1))+" more")
	}
	return out
}

// recordProblems are the texts of the three ways in which a set has no
// record of a policy that receivers can use.
type recordProblems struct{ none, many, long string }

// oneRecord picks the record of a policy from set: the one TXT record whose
// text version accepts. It gives the text after the version, or the
// problem.
func oneRecord(set []dnswire.RData, version func(string) (string, bool), p recordProblems) (rest, problem string) {
	records := policyRecords(set, version)
	switch {
	case len(records) == 0:
		return "", p.none
	case len(records) > 1:
		return "", p.many
	case len(records[0]) > maxText:
		return "", p.long
	}
	rest, _ = version(records[0])
	return rest, ""
}

// policyRecords gives the texts of the TXT records of set that version
// accepts.
func policyRecords(set []dnswire.RData, version func(string) (string, bool)) []string {
	var records []string
	for _, text := range texts(set) {
		if _, ok := version(text); ok {
			records = append(records, text)
		}
	}
	return records
}

// texts gives the text of each TXT record of set: its strings joined with
// nothing between them (RFC 7208 section 3.3, RFC 6376 section 3.6.2.2).
// Records of other types hold no policy.
func texts(set []dnswire.RData) []string {
	var out []string
	for _, d := range set {
		if t, ok := d.(dnswire.TXT); ok {
			out = append(out, strings.Join(t.Strings, ""))
		}
	}
	return out
}

// lowerASCII folds A to Z only. The mail records compare their names and
// keywords in ASCII, and Unicode folding would read the Kelvin sign as k.
func lowerASCII(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 'a' - 'A'
		}
	}
	return string(b)
}

// cutPrefixFold is strings.CutPrefix with the ASCII case of s ignored;
// prefix is in lower case.
func cutPrefixFold(s, prefix string) (string, bool) {
	if len(s) < len(prefix) || lowerASCII(s[:len(prefix)]) != prefix {
		return s, false
	}
	return s[len(prefix):], true
}

// visible reports whether s is not empty and holds only printable ASCII
// other than the space.
func visible(s string) bool {
	return s != "" && !strings.ContainsFunc(s, func(r rune) bool { return r < 0x21 || r > 0x7E })
}

// onlyOf reports whether every octet of s is one of set.
func onlyOf(s, set string) bool {
	return !strings.ContainsFunc(s, func(r rune) bool { return !strings.ContainsRune(set, r) })
}

// isWord reports whether s starts with an octet of first and holds only
// octets of rest.
func isWord(s, first, rest string) bool {
	return strings.IndexAny(s, first) == 0 && onlyOf(s, rest)
}
