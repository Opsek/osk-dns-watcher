package expect

import (
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

const maxDMARCAddresses = 16 // for each of rua and ruf

// wsp is the white space that may stand around the parts of a record.
const wsp = " \t"

var dmarcPick = recordProblems{
	none: "no DMARC record",
	many: "two or more DMARC records",
	long: "a DMARC record longer than 4096 octets",
}

// dmarcActions are the values of p, sp and np, from the least strict.
var dmarcActions = []string{"none", "quarantine", "reject"}

// dmarcRead are the tags that osk reads; no other tag changes who passes or
// who hears.
var dmarcRead = []string{"p", "sp", "np", "pct", "t", "adkim", "aspf", "psd", "rua", "ruf"}

// dmarcPolicy is a DMARC record as both RFC 7489 and RFC 9989 read it:
// receivers follow either one.
type dmarcPolicy struct {
	off          string // why receivers apply no policy; "" when they apply this one
	p, sp, np    int    // in effect, as an index of dmarcActions
	spSet, npSet bool   // the record gives a valid sp, np
	pct          int
	testing      bool // t=y
	adkim, aspf  bool // strict: s
	psd          string
	rua, ruf     []string // in octet order
	twice        []string // the tags of dmarcRead given twice with different values
}

// dmarcWeaker names each tag of now that asks less of receivers than was.
// An added report address counts too: it sends data about the domain's
// mail to another party. A record that applies no policy is below every
// other.
func dmarcWeaker(was, now dmarcPolicy) []string {
	if was.off != "" {
		return nil
	}
	if now.off != "" {
		return []string{now.off + ": receivers apply no DMARC policy"}
	}
	var words []string
	if now.p < was.p {
		words = append(words, change("p", dmarcActions[now.p], dmarcActions[was.p]))
	}
	// An sp or np that neither record gives follows p, whose word says it.
	if (now.spSet || was.spSet) && now.sp < was.sp {
		words = append(words, change("sp", dmarcActions[now.sp], dmarcActions[was.sp]))
	}
	if (now.npSet || was.npSet) && now.np < was.np {
		words = append(words, change("np", dmarcActions[now.np], dmarcActions[was.np]))
	}
	if now.pct < was.pct {
		words = append(words, change("pct", strconv.Itoa(now.pct), strconv.Itoa(was.pct)))
	}
	if now.testing && !was.testing {
		words = append(words, change("t", "y", "n"))
	}
	if !now.adkim && was.adkim {
		words = append(words, change("adkim", "r", "s"))
	}
	if !now.aspf && was.aspf {
		words = append(words, change("aspf", "r", "s"))
	}
	if now.psd != was.psd {
		words = append(words, change("psd", now.psd, was.psd))
	}
	// osk reads the first value; a receiver that keeps the last one may read
	// a weaker policy.
	for _, tag := range dmarcRead {
		if slices.Contains(now.twice, tag) && !slices.Contains(was.twice, tag) {
			words = append(words, tag+"= given twice with different values: receivers may apply either one")
		}
	}
	words = append(words, addressWords(was.rua, now.rua, "rua also sends reports to ", "rua no longer sends reports to ")...)
	return append(words, addressWords(was.ruf, now.ruf, "ruf also sends failure reports to ", "ruf no longer sends failure reports to ")...)
}

func change(tag, now, was string) string {
	return tag + "=" + now + " in place of " + tag + "=" + was
}

// addressWords names the addresses of now that was lacks, then those of was
// that now lacks.
func addressWords(was, now []string, added, removed string) []string {
	var words []string
	for _, a := range now {
		if !slices.Contains(was, a) {
			words = append(words, added+a)
		}
	}
	for _, a := range was {
		if !slices.Contains(now, a) {
			words = append(words, removed+a)
		}
	}
	return words
}

func readDMARC(set []dnswire.RData) dmarcPolicy {
	rest, problem := oneRecord(set, dmarcVersion, dmarcPick)
	if problem != "" {
		return dmarcPolicy{off: problem}
	}
	tags, twice := dmarcTags(rest)
	d := dmarcPolicy{
		p:       dmarcAction(tags["p"]),
		sp:      dmarcAction(tags["sp"]),
		np:      dmarcAction(tags["np"]),
		pct:     100,
		testing: lowerASCII(tags["t"]) == "y",
		adkim:   lowerASCII(tags["adkim"]) == "s",
		aspf:    lowerASCII(tags["aspf"]) == "s",
		psd:     lowerASCII(tags["psd"]),
		rua:     dmarcAddresses(tags["rua"]),
		ruf:     dmarcAddresses(tags["ruf"]),
		twice:   twice,
	}
	// RFC 7489 section 6.6.3, item 6 (and RFC 9989 section 4.10.1 for p): a
	// record without a valid p, or with an sp that is not valid, applies
	// p=none when rua names a mailto: address, and no policy otherwise.
	_, hasSP := tags["sp"]
	reason := ""
	switch {
	case d.p < 0:
		reason = "no valid p= and no report address"
	case hasSP && d.sp < 0:
		reason = "an sp= that is not valid and no report address"
	}
	if reason != "" {
		if !slices.ContainsFunc(d.rua, isMailto) {
			return dmarcPolicy{off: reason}
		}
		d.p = 0 // none
	}
	// RFC 9989 section 4.7: np falls back to sp, and sp to p.
	d.spSet, d.npSet = d.sp >= 0, d.np >= 0
	if !d.spSet {
		d.sp = d.p
	}
	if !d.npSet {
		d.np = d.sp
	}
	// A pct above 100 is invalid, which gives the default 100 too.
	if n, err := strconv.ParseUint(tags["pct"], 10, 64); err == nil {
		d.pct = int(min(n, 100))
	}
	if d.psd != "y" && d.psd != "n" {
		d.psd = "u"
	}
	return d
}

// dmarcVersion accepts the text of a DMARC record and gives the text after
// the version: "v" in either case, "=" and "DMARC1" in this case, with
// spaces or tabs around "=", then the end or ";" after spaces or tabs (RFC
// 7489 section 6.4).
func dmarcVersion(text string) (string, bool) {
	rest, v := cutPrefixFold(text, "v")
	rest, eq := strings.CutPrefix(strings.TrimLeft(rest, wsp), "=")
	rest, version := strings.CutPrefix(strings.TrimLeft(rest, wsp), "DMARC1")
	sep := strings.TrimLeft(rest, wsp)
	return rest, v && eq && version && (sep == "" || sep[0] == ';')
}

// dmarcTags reads the tags after the version (RFC 7489 section 6.3), by name
// in lower case. A part without "=" is a syntax error, which leaves a tag at
// its default. Of a name given twice the first counts; twice gives each tag
// of dmarcRead that is given again with another value.
func dmarcTags(rest string) (tags map[string]string, twice []string) {
	tags = map[string]string{}
	for _, part := range strings.Split(rest, ";") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			continue
		}
		name, value = lowerASCII(strings.Trim(name, wsp)), strings.Trim(value, wsp)
		first, given := tags[name]
		switch {
		case !given:
			tags[name] = value
		case first != value && slices.Contains(dmarcRead, name) && !slices.Contains(twice, name):
			twice = append(twice, name)
		}
	}
	return tags, twice
}

// dmarcAction gives the index in dmarcActions of a value of p, sp or np;
// -1 when it is none of them.
func dmarcAction(v string) int {
	return slices.Index(dmarcActions, lowerASCII(v))
}

// dmarcAddresses reads a list of report addresses (RFC 7489 section 6.4):
// each without its size limit, each once, at most 16, in octet order.
func dmarcAddresses(list string) []string {
	var out []string
	for _, a := range strings.Split(list, ",") {
		a, _, _ = strings.Cut(strings.Trim(a, wsp), "!")
		if !visible(a) || slices.Contains(out, a) {
			continue
		}
		if len(out) == maxDMARCAddresses {
			break
		}
		out = append(out, a)
	}
	slices.Sort(out)
	return out
}

func isMailto(address string) bool {
	_, ok := cutPrefixFold(address, "mailto:")
	return ok
}
