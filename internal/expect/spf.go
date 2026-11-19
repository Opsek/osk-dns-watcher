package expect

import (
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

const (
	maxSPFTerms   = 128 // bounds the work of one comparison
	maxSPFLookups = 10  // RFC 7208 section 4.6.4
)

// The ends of the word for a record that receivers cannot use.
const (
	spfPermerror = ": receivers give permerror, so no sender fails"
	spfNotRead   = ": osk-dns-watcher does not read it and counts every sender as neutral"
)

const spfUnreadable = "an SPF term that cannot be read" + spfPermerror

var spfPick = recordProblems{
	none: "no SPF record: receivers treat every sender as neutral",
	many: "two or more SPF records" + spfPermerror,
	long: "an SPF record longer than 4096 octets" + spfNotRead,
}

// spfLookups are the mechanisms that make a receiver query the DNS.
var spfLookups = []string{"include", "a", "mx", "ptr", "exists"}

// spfRank is a result of RFC 7208 section 2.6, from the least strict.
type spfRank uint8

const (
	spfPass spfRank = iota
	spfNeutral
	spfSoftfail
	spfFail
	spfRedirect // the result of the record that redirect= names
)

// spfQualifiers are the qualifiers in the order of spfRank.
const spfQualifiers = "+?~-"

var spfRankWords = []string{"pass", "neutral", "softfail", "fail"}

// spfResult is what a policy gives a sender.
type spfResult struct {
	rank   spfRank
	domain string // spfRedirect: the domain-spec of redirect=
}

func (r spfResult) String() string {
	if r.rank == spfRedirect {
		return "the result of redirect=" + r.domain
	}
	return spfRankWords[r.rank]
}

// atLeast reports whether r is at least as strict as s. The result of a
// redirect can be anything that the other record gives, so it is above
// pass and below fail only.
func (r spfResult) atLeast(s spfResult) bool {
	if r.rank == spfRedirect || s.rank == spfRedirect {
		return r == s || s.rank == spfPass || r.rank == spfFail
	}
	return r.rank >= s.rank
}

// spfAtom is a set of senders that one term matches: an IPv4 or IPv6
// prefix; the addresses of a or mx for one domain and family, within a
// length; or what include, exists or ptr matches for one domain-spec.
type spfAtom struct {
	text  string       // as a word prints it
	scope string       // the atom without its length: only atoms of one scope contain one another
	net   netip.Prefix // ip4 and ip6
	bits  int          // ip4, ip6, a and mx: the length
}

// contains reports whether every sender of m is a sender of c.
func (c spfAtom) contains(m spfAtom) bool {
	return c.scope == m.scope && c.bits <= m.bits && (!c.net.IsValid() || c.net.Contains(m.net.Addr()))
}

func namedAtom(mech, spec string) spfAtom {
	text := mech + ":" + spec
	return spfAtom{text: text, scope: text}
}

func lengthAtom(scope string, bits int) spfAtom {
	return spfAtom{text: scope + strconv.Itoa(bits), scope: scope, bits: bits}
}

type spfTerm struct {
	mech   string    // the mechanism name, in lower case
	spec   string    // include, exists, ptr, a and mx: the domain-spec
	result spfResult // given by the qualifier
	atoms  []spfAtom
}

type spfPolicy struct {
	problem string    // the word for a record that receivers cannot use; "" when it reads
	terms   []spfTerm // the directives before the first all, in order
	def     spfResult // what a sender that no term matches gets
}

// result gives what p gives the senders of m: the result of the first term
// that matches all of them.
func (p spfPolicy) result(m spfAtom) spfResult {
	for _, t := range p.terms {
		if slices.ContainsFunc(t.atoms, func(c spfAtom) bool { return c.contains(m) }) {
			return t.result
		}
	}
	return p.def
}

// kept gives the least result that the senders of m can get from p: the
// least result of the terms up to the first one that contains m, since a
// term of another kind before it may match some of them; with no such term,
// of all terms and the default. A redirect can give anything, so pass.
func (p spfPolicy) kept(m spfAtom) spfRank {
	least := spfFail
	for _, t := range p.terms {
		least = min(least, t.result.rank)
		if slices.ContainsFunc(t.atoms, func(c spfAtom) bool { return c.contains(m) }) {
			return least
		}
	}
	if p.def.rank == spfRedirect {
		return spfPass
	}
	return min(least, p.def.rank)
}

// spfWeaker names each candidate whose result in now is not at least as
// strict as in was. The candidates are all senders, then the atoms of now
// and of was, each once. Then it names each atom of was whose kept result
// is lower in now, and all senders only when nothing else gave a word.
func spfWeaker(was, now spfPolicy) []string {
	candidates := []spfAtom{{text: "all", scope: "all"}}
	for _, p := range []spfPolicy{now, was} {
		for _, t := range p.terms {
			for _, a := range t.atoms {
				if !slices.Contains(candidates, a) {
					candidates = append(candidates, a)
				}
			}
		}
	}
	var words []string
	for _, m := range candidates {
		w, n := was.result(m), now.result(m)
		if !n.atLeast(w) {
			words = append(words, m.text+" gives "+n.String()+" in place of "+w.String())
		}
	}
	// Atoms of two kinds never contain one another, so the results above
	// cannot show a term of another kind that now meets the senders of an
	// atom first. Comparing kept results for each atom of was, and for all
	// senders, keeps the order transitive. An atom that already has a word
	// gets no second one.
	for _, t := range was.terms {
		for _, m := range t.atoms {
			if now.result(m).atLeast(was.result(m)) && now.kept(m) < was.kept(m) {
				words = append(words, keptWord(m, was.kept(m)))
			}
		}
	}
	if all := candidates[0]; len(words) == 0 && now.kept(all) < was.kept(all) {
		words = append(words, keptWord(all, was.kept(all)))
	}
	if now.problem != "" && len(words) > 0 {
		return []string{now.problem}
	}
	return words
}

func keptWord(m spfAtom, was spfRank) string {
	return m.text + " no longer always gets " + spfRankWords[was] + ": another term may let it pass"
}

// readSPF reads the SPF policy of set, whose owner is owner. A record that
// receivers cannot use gives neutral to every sender: RFC 7208 section 8.2
// treats neutral as no policy, and osk-dns-watcher treats permerror the same way.
func readSPF(owner dnswire.Name, set []dnswire.RData) spfPolicy {
	rest, problem := oneRecord(set, spfVersion, spfPick)
	if problem != "" {
		return spfFailed(problem)
	}
	return parseSPF(strings.TrimSuffix(owner.Lower().String(), "."), rest)
}

func spfFailed(problem string) spfPolicy {
	return spfPolicy{problem: problem, def: spfResult{rank: spfNeutral}}
}

// spfVersion accepts the text of an SPF record (RFC 7208 section 4.5) and
// gives the text after the version.
func spfVersion(text string) (string, bool) {
	rest, ok := cutPrefixFold(text, "v=spf1")
	return rest, ok && (rest == "" || rest[0] == ' ')
}

// parseSPF reads the terms of an SPF record (RFC 7208 sections 4.6 to 6).
// owner is the domain-spec of a, mx and ptr when they name none.
func parseSPF(owner, terms string) spfPolicy {
	fields := strings.FieldsFunc(terms, func(r rune) bool { return r == ' ' })
	if len(fields) > maxSPFTerms {
		return spfFailed("more than 128 SPF terms" + spfNotRead)
	}
	p := spfPolicy{def: spfResult{rank: spfNeutral}}
	modifiers := map[string]string{} // redirect and exp: the domain-spec
	all := false
	for _, f := range fields {
		if !visible(f) {
			return spfFailed(spfUnreadable)
		}
		if name, value, ok := spfModifier(f); ok {
			if name != "redirect" && name != "exp" {
				continue // RFC 7208 section 6: other modifiers are ignored
			}
			if _, twice := modifiers[name]; twice {
				return spfFailed("redirect= or exp= given twice" + spfPermerror)
			}
			spec, ok := domainSpec(value)
			if !ok {
				return spfFailed(spfUnreadable)
			}
			modifiers[name] = spec
			continue
		}
		t, ok := spfDirective(owner, f)
		switch {
		case !ok:
			return spfFailed(spfUnreadable)
		case all:
			// RFC 7208 section 5.1: no term after the first all is tested.
		case t.mech == "all":
			all = true
			p.def = t.result
		default:
			p.terms = append(p.terms, t)
		}
	}
	lookups := 0
	for _, t := range p.terms {
		if slices.Contains(spfLookups, t.mech) {
			lookups++
		}
	}
	if redirect, ok := modifiers["redirect"]; ok && !all {
		p.def = spfResult{rank: spfRedirect, domain: redirect}
		lookups++
	}
	if lookups > maxSPFLookups {
		return spfFailed("more than 10 SPF terms that need a DNS lookup" + spfPermerror)
	}
	return p
}

// spfModifier splits a modifier (RFC 7208 section 6): a name, ALPHA
// *(ALPHA / DIGIT / "-" / "_" / "."), then "=". The name is in lower case.
func spfModifier(f string) (name, value string, ok bool) {
	name, value, ok = strings.Cut(f, "=")
	return lowerASCII(name), value, ok && isWord(name, alpha, alnum+"-_.")
}

// spfDirective reads a directive (RFC 7208 sections 4.6.2 and 5): an
// optional qualifier, then a mechanism. Without a qualifier the result is
// pass.
func spfDirective(owner, f string) (t spfTerm, ok bool) {
	if q := strings.IndexByte(spfQualifiers, f[0]); q >= 0 {
		t.result.rank = spfRank(q)
		f = f[1:]
	}
	head, _, _ := strings.Cut(f, ":")
	name, _, _ := strings.Cut(head, "/")
	t.mech = lowerASCII(name)
	t.spec, t.atoms, ok = spfMechanism(owner, t.mech, f[len(name):])
	return t, ok
}

// spfMechanism reads a mechanism (RFC 7208 section 5) from its name and the
// text after the name: its domain-spec and the atoms that it matches.
func spfMechanism(owner, mech, rest string) (string, []spfAtom, bool) {
	switch mech {
	case "all":
		return "", nil, rest == ""
	case "include", "exists":
		text, found := strings.CutPrefix(rest, ":")
		spec, ok := domainSpec(text)
		return spec, []spfAtom{namedAtom(mech, spec)}, found && ok
	case "ptr":
		spec, ok := optionalSpec(owner, rest)
		return spec, []spfAtom{namedAtom(mech, spec)}, ok
	case "a", "mx":
		return hostAtoms(owner, mech, rest)
	case "ip4", "ip6":
		atom, ok := ipAtom(mech, rest)
		return "", []spfAtom{atom}, ok
	}
	return "", nil, false
}

// hostAtoms reads the rest of a or mx: an optional ":" and domain-spec, then
// a dual-cidr-length (RFC 7208 sections 5.3, 5.4 and 5.6). The domain-spec
// ends at the first "/", since a host name holds none. The IPv4 atom comes
// first.
func hostAtoms(owner, mech, rest string) (string, []spfAtom, bool) {
	head, lengths := rest, ""
	if i := strings.IndexByte(rest, '/'); i >= 0 {
		head, lengths = rest[:i], rest[i:]
	}
	spec, okSpec := optionalSpec(owner, head)
	v4, v6, okLengths := spfLengths(lengths)
	scope := mech + ":" + spec + "/"
	return spec, []spfAtom{lengthAtom(scope, v4), lengthAtom(scope+"/", v6)}, okSpec && okLengths
}

// spfLengths reads a dual-cidr-length (RFC 7208 section 5.6): an optional
// "/" and IPv4 length, then an optional "//" and IPv6 length. Absent
// lengths are 32 and 128.
func spfLengths(s string) (v4, v6 int, ok bool) {
	s4, s6, dual := strings.Cut(s, "//")
	v4, v6 = 32, 128
	ok4, ok6 := true, true
	if s4 != "" {
		v4, ok4 = cidrLength(s4[1:], 32)
	}
	if dual {
		v6, ok6 = cidrLength(s6, 128)
	}
	return v4, v6, ok4 && ok6
}

// ipAtom reads the rest of ip4 or ip6 (RFC 7208 section 5.6): ":", an
// address of the family, then an optional length. The atom holds the
// masked prefix.
func ipAtom(mech, rest string) (spfAtom, bool) {
	text, found := strings.CutPrefix(rest, ":")
	text, length, hasLength := strings.Cut(text, "/")
	// A text that does not parse gives the zero Addr, which is of neither
	// family.
	addr, _ := netip.ParseAddr(text)
	// RFC 7208 section 5.6 takes the address forms of RFC 4291 section 2.2,
	// which have no zone.
	family := addr.Is6() && addr.Zone() == ""
	if mech == "ip4" {
		family = addr.Is4()
	}
	bits, okLength := addr.BitLen(), true
	if hasLength {
		bits, okLength = cidrLength(length, addr.BitLen())
	}
	prefix := netip.PrefixFrom(addr, bits).Masked()
	return spfAtom{text: mech + ":" + prefix.String(), scope: mech + ":", net: prefix, bits: bits}, found && family && okLength
}

// cidrLength reads a prefix length: "0", or a digit 1 to 9 and more digits,
// at most limit (RFC 7208 section 5.6).
func cidrLength(s string, limit int) (int, bool) {
	n, err := strconv.ParseUint(s, 10, 8)
	return int(n), err == nil && int(n) <= limit && strconv.FormatUint(n, 10) == s
}

// optionalSpec reads an optional ":" and domain-spec; without them the
// domain-spec is owner (RFC 7208 sections 5.3 to 5.5).
func optionalSpec(owner, s string) (string, bool) {
	if s == "" {
		return owner, true
	}
	text, found := strings.CutPrefix(s, ":")
	spec, ok := domainSpec(text)
	return spec, found && ok
}

// domainSpec reads a domain-spec (RFC 7208 section 7.1). One with a macro is
// kept as written: it is expanded for each message. Another is a name, kept
// in lower case and without one trailing dot.
func domainSpec(s string) (string, bool) {
	if !specGrammar(s) {
		return "", false
	}
	if strings.Contains(s, "%") {
		return s, true
	}
	d := lowerASCII(strings.TrimSuffix(s, "."))
	_, err := dnswire.ParseName(d + ".")
	return d, err == nil
}

// spfMacroLetters are the macro letters of RFC 7208 section 7.1, in either
// case.
const spfMacroLetters = "slodiphcrtvSLODIPHCRTV"

// specGrammar reports whether s is a macro-string and then a domain-end (RFC
// 7208 section 7.1): each "%" starts a macro-expand, and s ends with a
// macro-expand or with "." and a toplabel, then at most one ".". The other
// octets of a field are printable already.
func specGrammar(s string) bool {
	endsInMacro := false
	for i := 0; i < len(s); {
		n := 1
		if s[i] == '%' {
			if n = macroExpand(s[i:]); n == 0 {
				return false
			}
		}
		endsInMacro = s[i] == '%'
		i += n
	}
	if endsInMacro {
		return true
	}
	name := strings.TrimSuffix(s, ".")
	dot := strings.LastIndexByte(name, '.')
	return dot >= 0 && toplabel(name[dot+1:])
}

// macroExpand gives the length of the macro-expand at the start of s, which
// starts with "%": "%%", "%_", "%-", or "%{", a macro letter, digits, an
// optional "r", delimiters and "}" (RFC 7208 section 7.1). 0 when there is
// none.
func macroExpand(s string) int {
	if len(s) >= 2 && strings.IndexByte("%_-", s[1]) >= 0 {
		return 2
	}
	body, open := strings.CutPrefix(s, "%{")
	end := strings.IndexByte(body, '}')
	if !open || end < 1 || strings.IndexByte(spfMacroLetters, body[0]) < 0 {
		return 0
	}
	rest, _ := cutPrefixFold(strings.TrimLeft(body[1:end], "0123456789"), "r")
	if !onlyOf(rest, ".-+,/_=") {
		return 0
	}
	return len("%{") + end + 1
}

// toplabel reports whether s is a toplabel (RFC 7208 section 7.1): letters
// and digits with a letter among them, or letters, digits and hyphens with a
// hyphen inside and a letter or digit at each end. A name of digits alone
// would read as an address.
func toplabel(s string) bool {
	if s == "" || !onlyOf(s, alnum+"-") || s[0] == '-' || s[len(s)-1] == '-' {
		return false
	}
	return strings.ContainsAny(s, alpha+"-")
}

// redirect gives the name that the kept redirect= of p names, when it names
// one domain.
func (p spfPolicy) redirect() (dnswire.Name, bool) {
	if p.def.rank != spfRedirect {
		return dnswire.Name{}, false
	}
	return specName(p.def.domain)
}

// specName gives the name of spec, unless spec holds a macro: it names no one
// domain to look up.
func specName(spec string) (dnswire.Name, bool) {
	n, err := dnswire.ParseName(spec + ".")
	return n, err == nil && !strings.Contains(spec, "%")
}
