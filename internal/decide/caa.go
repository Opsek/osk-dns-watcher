package decide

import (
	"cmp"
	"slices"
	"strings"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Bounds on the work that one CAA set can ask for when two policies are
// compared. Past them a class reads as allowing any request, and a grant as
// allowing any method. In a set that a server gives, that is the side that
// alerts. In a line of the file it is the other side: a class of more than 64
// different grants reads as no policy for that class, so nothing under it
// can read as weaker there, and a method list of more than 16 labels reads as
// any method for its grant.
const (
	maxGrants  = 64 // grants of one class
	maxMethods = 16 // labels of one validationmethods list
)

// Reading is how an authority reads the three parts of a CAA set that
// authorities read in different ways. Each is read strictly (the authority
// refuses what it can refuse) or permissively (it allows what it can allow),
// and one authority may read each part its own way, so a reading is a set of
// the parts that it reads permissively. A weakening can hide in any reading,
// so a set is judged under each, both sides read the same way. Making a part
// permissive never permits less.
type Reading uint8

const (
	// knownTag: a critical flag on a tag other than issue, issuewild and iodef
	// does not stop the authority, which knows the tag.
	knownTag Reading = 1 << iota
	// anyAccount: accounturi that cannot hold as written, given twice or
	// empty, allows any account.
	anyAccount
	// anyMethod: validationmethods that cannot hold as written, given twice
	// or with an empty label or a bad octet, allows any method.
	anyMethod

	StrictReading     Reading = 0                                 // every part read strictly
	PermissiveReading         = knownTag | anyAccount | anyMethod // every part read permissively

	// Readings is the number of readings. They are walked in the fixed order
	// Reading(0) to Readings-1: StrictReading first, PermissiveReading last.
	Readings = PermissiveReading + 1
)

// Request is one certificate that an authority could be asked for: a plain
// name or a wildcard, by one authority, for one account, by one validation
// method, with the other parameters that the authority reads. An empty
// Account or Method is one that no parameter names.
type Request struct {
	Wildcard                       bool
	Issuer, Account, Method, Extra string
}

// Grant is what one issue or issuewild property allows.
type Grant struct {
	Issuer  string   // lower case; never empty
	Account string   // the accounturi value; "" for any account
	Methods []string // validationmethods labels, lower case, sorted, unique; nil for any method
	Extra   string   // the other parameters, "tag=value" as written, sorted, joined by ";"; "" for none
}

// Class is the policy for plain names or for wildcards.
type Class struct {
	Any    bool    // every request is allowed
	Grants []Grant // when !Any; empty: no request is allowed
}

// Policy is what a CAA set allows, for plain names and for wildcards.
type Policy struct{ Name, Wild Class }

// OpenPolicy is no CAA set at all.
var OpenPolicy = Policy{Name: Class{Any: true}, Wild: Class{Any: true}}

func (p Policy) class(wildcard bool) Class {
	if wildcard {
		return p.Wild
	}
	return p.Name
}

func isOpen(p Policy) bool { return p.Name.Any && p.Wild.Any }

// Permits reports whether p allows the request r. Parameters that are not
// accounturi or validationmethods must be equal as written: some narrow a
// grant and some may widen it, so any change of them counts as permitting
// more, the side that cannot hide a weakening.
func (p Policy) Permits(r Request) bool {
	c := p.class(r.Wildcard)
	return c.Any || slices.ContainsFunc(c.Grants, func(g Grant) bool { return g.permits(r) })
}

func (g Grant) permits(r Request) bool {
	return g.Issuer == r.Issuer && (g.Account == "" || g.Account == r.Account) &&
		(g.Methods == nil || slices.Contains(g.Methods, r.Method)) && g.Extra == r.Extra
}

// Weaker gives a request that now permits and want does not, plain names
// first. ok is false when every request that now permits, want permits too.
func Weaker(now, want Policy) (Request, bool) {
	for _, wildcard := range []bool{false, true} {
		if r, ok := weakerIn(wildcard, now.class(wildcard), want); ok {
			return r, true
		}
	}
	return Request{}, false
}

// weakerIn looks for the request in one class. The requests of one grant
// differ only in account and method. An empty account matches only a grant
// for any account, and an empty method only a grant for any method, so the
// grant's own account with each of its methods ("" for any) are the hardest
// requests of the grant: want permits them all exactly when it permits every
// request of the grant.
func weakerIn(wildcard bool, now Class, want Policy) (Request, bool) {
	if want.class(wildcard).Any {
		return Request{}, false
	}
	if now.Any {
		// No grant has an empty issuer, so want cannot permit this one.
		return Request{Wildcard: wildcard}, true
	}
	for _, g := range now.Grants {
		methods := g.Methods
		if methods == nil {
			methods = []string{""}
		}
		for _, m := range methods {
			r := Request{Wildcard: wildcard, Issuer: g.Issuer, Account: g.Account, Method: m, Extra: g.Extra}
			if !want.Permits(r) {
				return r, true
			}
		}
	}
	return Request{}, false
}

// Names reports whether the class of wildcard could have allowed a
// certificate from an authority that CAA records call by one of issuers. A
// certificate shows neither the account nor the method, so any grant that
// names the authority could have allowed it.
func (p Policy) Names(wildcard bool, issuers []string) bool {
	c := p.class(wildcard)
	return c.Any || slices.ContainsFunc(c.Grants, func(g Grant) bool { return slices.Contains(issuers, g.Issuer) })
}

// PolicyOf reads a CAA set under the reading r (RFC 8659 section 4, RFC
// 8657). ok is false when set is empty or holds data that is not CAA, such as
// an alias.
func PolicyOf(set []dnswire.RData, r Reading) (p Policy, ok bool) {
	if len(set) == 0 {
		return Policy{}, false
	}
	var issues, wilds []string
	critical := false
	for _, d := range set {
		c, isCAA := d.(dnswire.CAA)
		if !isCAA {
			return Policy{}, false
		}
		switch {
		case tagIs(c.Tag, "issue"):
			issues = append(issues, c.Value)
		case tagIs(c.Tag, "issuewild"):
			wilds = append(wilds, c.Value)
		case tagIs(c.Tag, "iodef"):
			// A place for reports; it allows and forbids nothing.
		default:
			critical = critical || c.Flags&128 != 0
		}
	}
	// An authority must not issue when it does not know a tag that is marked
	// critical; one that knows the tag is not stopped by the flag.
	if critical && r&knownTag == 0 {
		return Policy{}, true
	}
	p = Policy{Name: classOf(issues, r), Wild: classOf(wilds, r)}
	// Without issuewild, the issue properties also rule wildcards.
	if len(wilds) == 0 {
		p.Wild = p.Name
	}
	return p, true
}

// tagIs reports whether tag is the lower-case word want in any ASCII case.
// The equal length keeps out non-ASCII letters that fold to ASCII ones, such
// as the long s.
func tagIs(tag, want string) bool {
	return len(tag) == len(want) && strings.EqualFold(tag, want)
}

// classOf gives the class of the values of the issue or issuewild properties
// of one set; no property restricts nothing.
func classOf(values []string, r Reading) Class {
	if len(values) == 0 {
		return Class{Any: true}
	}
	var grants []Grant
	for _, v := range values {
		if g, ok := grantOf(v, r); ok {
			grants = append(grants, g)
		}
	}
	slices.SortFunc(grants, compareGrants)
	grants = slices.CompactFunc(grants, func(a, b Grant) bool { return compareGrants(a, b) == 0 })
	if len(grants) > maxGrants {
		return Class{Any: true}
	}
	return Class{Grants: grants}
}

func compareGrants(a, b Grant) int {
	return cmp.Or(strings.Compare(a.Issuer, b.Issuer), strings.Compare(a.Account, b.Account),
		strings.Compare(strings.Join(a.Methods, ","), strings.Join(b.Methods, ",")), strings.Compare(a.Extra, b.Extra))
}

const (
	blanks       = " \t"
	issuerOctets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-."
	methodOctets = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-"
)

// grantOf reads one value leniently. RFC 8659 reads a value outside its
// grammar as granting nothing, so an edit from "ca.test" to "evil.test x"
// would rank as stricter, although an authority that reads leniently could
// issue. Here the leading name is the issuer and the rest are parameters;
// every value inside the grammar reads as the grammar says. An account or a
// method list that cannot hold as written gives no grant when r reads it
// strictly, and a grant for any account or method when r reads it
// permissively.
func grantOf(value string, r Reading) (Grant, bool) {
	s := strings.Trim(value, blanks)
	rest := strings.TrimLeft(s, issuerOctets)
	g := Grant{Issuer: strings.ToLower(s[:len(s)-len(rest)])}
	params := strings.TrimPrefix(strings.TrimLeft(rest, blanks), ";")
	var accounts, lists, extra []string
	for _, piece := range strings.Split(params, ";") {
		piece = strings.Trim(piece, blanks)
		if piece == "" {
			continue
		}
		tag, v, hasValue := strings.Cut(piece, "=")
		tag, v = strings.Trim(tag, blanks), strings.Trim(v, blanks)
		// The tags are matched in exact case: an authority that reads them
		// with case could take "AccountURI=x" as no account binding.
		switch {
		case hasValue && tag == "accounturi":
			accounts = append(accounts, v)
		case hasValue && tag == "validationmethods":
			lists = append(lists, v)
		case hasValue:
			extra = append(extra, tag+"="+v)
		default:
			extra = append(extra, piece)
		}
	}
	if g.Issuer == "" {
		return Grant{}, false
	}
	// Two accounts, or an empty one, never hold (RFC 8657).
	switch {
	case len(accounts) == 1 && accounts[0] != "":
		g.Account = accounts[0]
	case len(accounts) > 0 && r&anyAccount == 0:
		return Grant{}, false
	}
	methods, ok := methodList(lists)
	if !ok && r&anyMethod == 0 {
		return Grant{}, false
	}
	g.Methods = methods
	slices.Sort(extra)
	g.Extra = strings.Join(extra, ";")
	return g, true
}

// methodList reads the validationmethods parameters of one value: nil for
// any method. ok is false when they are not one list of labels; RFC 8657
// does not say what two lists mean.
func methodList(lists []string) (methods []string, ok bool) {
	if len(lists) == 0 {
		return nil, true
	}
	if len(lists) > 1 {
		return nil, false
	}
	methods = strings.Split(lists[0], ",")
	for i, m := range methods {
		if m == "" || strings.TrimLeft(m, methodOctets) != "" {
			return nil, false
		}
		methods[i] = strings.ToLower(m)
	}
	if len(methods) > maxMethods {
		return nil, true
	}
	slices.Sort(methods)
	return slices.Compact(methods), true
}

// CAAPolicy is the policy that the file expects for name: the CAA line of the
// nearest name at or above name, up to the domain, whose form is exact. A
// "none" line, or no line, goes on to the parent. ok is false when no such
// line exists: the file states no policy, which reads as OpenPolicy.
//
// alts[r] holds one Policy for each alternative of the line under the
// reading r, for each of the Readings; line is the CAA line that governs. A wildcard *.X uses the climb
// of X (RFC 8659 section 3). Above the domain the file states nothing, and
// the levels there belong to the registry, so they read as no policy.
func CAAPolicy(f *expect.File, name dnswire.Name) (alts [Readings][]Policy, line expect.Expectation, ok bool) {
	if f == nil {
		return alts, line, false
	}
	if IsWildcardOwner(name) {
		name = name.Parent()
	}
	l, ok := newCAALines(f, StrictReading, PermissiveReading).at(name)
	return l.alts, l.line, ok
}

// caaLine is an exact CAA line and the policy of each of its alternatives
// under the readings that were asked for; alts[r] is nil for the others.
type caaLine struct {
	line expect.Expectation
	alts [Readings][]Policy
}

// caaLines finds the exact CAA line that governs a name. It belongs to one
// call: each line is read at most once, under the readings first to last, the
// ones that the call needs, and only when a climb reaches it.
type caaLines struct {
	domain      dnswire.Name
	exact       map[string]expect.Expectation // by Name.Key()
	read        map[string]caaLine
	first, last Reading
}

func newCAALines(f *expect.File, first, last Reading) *caaLines {
	c := &caaLines{domain: f.Domain, exact: map[string]expect.Expectation{}, read: map[string]caaLine{}, first: first, last: last}
	for _, e := range f.Expectations {
		if e.Type == dnswire.TypeCAA && e.Form == expect.FormSets {
			c.exact[e.Name.Key()] = e
		}
	}
	return c
}

// at is the climb of CAAPolicy from name itself.
func (c *caaLines) at(name dnswire.Name) (caaLine, bool) {
	if !name.IsSubdomainOf(c.domain) {
		return caaLine{}, false
	}
	for m := name; ; m = m.Parent() {
		if l, ok := c.line(m.Key()); ok {
			return l, true
		}
		if m.Equal(c.domain) {
			return caaLine{}, false
		}
	}
}

// line gives the exact CAA line of the name whose Name.Key() is k.
func (c *caaLines) line(k string) (caaLine, bool) {
	if l, ok := c.read[k]; ok {
		return l, true
	}
	e, ok := c.exact[k]
	if !ok {
		return caaLine{}, false
	}
	l := caaLine{line: e}
	for r := c.first; r <= c.last; r++ {
		l.alts[r] = make([]Policy, len(e.Sets))
		for i, set := range e.Sets {
			// The data of a CAA line is CAA data, so the policy is always read.
			l.alts[r][i], _ = PolicyOf(set, r)
		}
	}
	c.read[k] = l
	return l, true
}

// guarded reports whether the file states a policy that something can permit
// more than: none of the alternatives of the line is open, for nothing
// permits more than an open policy. The strict reading decides it. A reading
// that is permissive in some part never permits less, so an alternative that
// is open under the strict reading is open under every reading: a line that
// is guarded under some reading is guarded under the strict one.
func guarded(l caaLine, ok bool) bool {
	return ok && !slices.ContainsFunc(l.alts[StrictReading], isOpen)
}

// caaJudged reports whether the caa rule judges the CAA set of name, which is
// then a name at or under the domain that a certificate can hold, under a
// guarded policy; l is the line that governs it. The checks of CAANames, the
// probes and the rule all use this one test.
func caaJudged(lines *caaLines, name dnswire.Name) (l caaLine, ok bool) {
	l, ok = lines.at(name)
	return l, guarded(l, ok) && certifiable(lines.domain, name)
}

// CAANames gives the names whose CAA set a check must see, in canonical
// order: every name from the owner of a line up to the domain that the caa
// rule judges. The domain is among them only when it has an exact CAA line,
// the one line that states its policy. With these, a weaker policy anywhere
// on the climb of a name of the file is seen at some level, each level judged
// against the file.
func CAANames(f *expect.File) []dnswire.Name {
	if f == nil {
		return nil
	}
	lines := newCAALines(f, StrictReading, StrictReading)
	visited := map[string]bool{}
	var names []dnswire.Name
	for _, e := range f.Expectations {
		for m := e.Name; m.IsSubdomainOf(f.Domain) && !visited[m.Key()]; m = m.Parent() {
			visited[m.Key()] = true
			if _, ok := caaJudged(lines, m); ok {
				names = append(names, m)
			}
		}
	}
	slices.SortFunc(names, dnswire.Compare)
	return names
}

// certifiable reports whether a certificate can hold name, which is at or
// under domain: no label below the domain starts with "_" or is "*". The caa
// rule leaves every other name to the ordinary set comparison: a CAA set at a
// name with a "_" label is no policy for a certificate, and the policy of *.X
// is the one of X, so on a zone that equals the file the set at the owner
// *.X, or a climb that passes it, could still read as weaker.
func certifiable(domain, name dnswire.Name) bool {
	labels := name.Labels()
	for _, l := range labels[:len(labels)-domain.LabelCount()] {
		if l == "*" || strings.HasPrefix(l, "_") {
			return false
		}
	}
	return true
}

// caa judges the check of o by the caa rule. judged is false when the rule
// does not judge it; a CAA check with no CAA line of its own is a probe
// exactly when judged is true. found holds a finding when a server gives a
// CAA set that, under some reading, permits more than every alternative of
// the line that governs the name, read the same way. An answer with no CAA
// set (no data or no such name) takes the policy that the file states above
// the name, as the climb of an authority does. An alias takes it too: an
// authority would follow the alias and read the set of its target, which
// osk-dns-watcher does not read.
func caa(f *expect.File, o obs.Observation) (judged bool, found []Finding) {
	if o.Key.Type != dnswire.TypeCAA || !covers(f, o) {
		return false, nil
	}
	lines := newCAALines(f, StrictReading, PermissiveReading)
	want, judged := caaJudged(lines, o.Key.Name)
	if !judged {
		return false, nil
	}
	up, upOK := lines.at(o.Key.Name.Parent())
	weaker := func(set []dnswire.Record) bool {
		data := rdataOf(set)
		for r := range Readings {
			eff := []Policy{OpenPolicy}
			if upOK {
				eff = up.alts[r]
			}
			if p, ok := PolicyOf(data, r); ok {
				eff = []Policy{p}
			}
			if slices.ContainsFunc(eff, func(p Policy) bool { return weakerThanEach(p, want.alts[r]) }) {
				return true
			}
		}
		return false
	}
	seen := seenIf(o.Answers, weaker, setText(dnswire.TypeCAA))
	if len(seen) == 0 {
		return true, nil
	}
	return true, []Finding{newFinding(RuleCAA, o, want.line.FormText(), seen)}
}

// weakerThanEach reports whether p permits more than each alternative of
// want: the servers may hold any one of them.
func weakerThanEach(p Policy, want []Policy) bool {
	for _, w := range want {
		if _, weaker := Weaker(p, w); !weaker {
			return false
		}
	}
	return true
}

func rdataOf(set []dnswire.Record) []dnswire.RData {
	data := make([]dnswire.RData, len(set))
	for i, r := range set {
		data[i] = r.Data
	}
	return data
}
