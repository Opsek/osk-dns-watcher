// Package expect reads the file in which an operator writes what the record
// sets of one domain must hold, prints it in one canonical form, and judges
// an observed record set against it. It reads no clock, network or file, so
// the same file and the same answers always give the same judgement.
package expect

import (
	"bytes"
	"cmp"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Form is how an expectation states the set it allows.
type Form uint8

const (
	FormSets  Form = iota + 1 // exact data: one of several sets
	FormRange                 // addresses inside some prefixes
	FormNames                 // targets that match some name patterns
	FormNone                  // no data, or no such name
)

var formWords = map[Form]string{
	FormSets:  "sets",
	FormRange: "in",
	FormNames: "like",
	FormNone:  "none",
}

func (f Form) String() string {
	if w, ok := formWords[f]; ok {
		return w
	}
	return "form" + strconv.Itoa(int(f))
}

// Pattern is one name that a target may be, or, with Under, the names
// strictly under it.
type Pattern struct {
	Name  dnswire.Name
	Under bool
}

func (p Pattern) Matches(n dnswire.Name) bool {
	if p.Under {
		return n.IsSubdomainOf(p.Name) && !n.Equal(p.Name)
	}
	return n.Equal(p.Name)
}

func (p Pattern) String() string {
	if p.Under {
		return "*." + nameText(p.Name)
	}
	return nameText(p.Name)
}

// Expectation is what one record set must hold. Only the field of its Form
// is used.
type Expectation struct {
	Line     int // where Parse read it; 0 when not read from text
	Name     dnswire.Name
	Type     dnswire.Type
	Form     Form
	Sets     [][]dnswire.RData // FormSets: alternatives, canonical, sorted, no duplicates; 1 to 16, each 1 to 1000
	Ranges   []netip.Prefix    // FormRange: masked, sorted; 1 to 64
	Patterns []Pattern         // FormNames: sorted; 1 to 64
}

// Match reports whether an observed set is allowed. An empty set stands for
// no data and for no such name. Owner, class and TTL are not compared: a
// TTL change is no hijack.
func (e Expectation) Match(set []dnswire.Record) bool {
	switch e.Form {
	case FormSets:
		seen := canonicalData(recordData(set))
		return slices.ContainsFunc(e.Sets, func(alt []dnswire.RData) bool {
			return slices.EqualFunc(seen, canonicalData(alt), sameData)
		})
	case FormRange:
		return e.each(set, func(d dnswire.RData) bool {
			addr, ok := address(d)
			return ok && slices.ContainsFunc(e.Ranges, func(p netip.Prefix) bool { return p.Contains(addr) })
		})
	case FormNames:
		return e.each(set, func(d dnswire.RData) bool {
			name, ok := target(d)
			return ok && slices.ContainsFunc(e.Patterns, func(p Pattern) bool { return p.Matches(name) })
		})
	case FormNone:
		return len(set) == 0
	}
	return false
}

// each reports whether set is not empty and every record has the type of e
// and passes ok.
func (e Expectation) each(set []dnswire.Record, ok func(dnswire.RData) bool) bool {
	if len(set) == 0 {
		return false
	}
	for _, r := range set {
		if r.Type() != e.Type || !ok(r.Data) {
			return false
		}
	}
	return true
}

func address(d dnswire.RData) (netip.Addr, bool) {
	switch d := d.(type) {
	case dnswire.A:
		return d.Addr, true
	case dnswire.AAAA:
		return d.Addr, true
	}
	return netip.Addr{}, false
}

func target(d dnswire.RData) (dnswire.Name, bool) {
	switch d := d.(type) {
	case dnswire.NS:
		return d.Host, true
	case dnswire.CNAME:
		return d.Target, true
	case dnswire.DNAME:
		return d.Target, true
	case dnswire.MX:
		return d.Exchange, true
	}
	return dnswire.Name{}, false
}

// FormText is the text after the type, as the file prints it. It sorts
// copies, so that a value built by hand prints the same as after a parse.
func (e Expectation) FormText() string {
	switch e.Form {
	case FormSets:
		alts := make([]string, 0, len(e.Sets))
		for _, alt := range canonicalSets(e.Sets) {
			alts = append(alts, dataListText(e.Type, alt))
		}
		return strings.Join(alts, " || ")
	case FormRange:
		words := []string{"in"}
		for _, p := range sortedPrefixes(e.Ranges) {
			words = append(words, p.String())
		}
		return strings.Join(words, " ")
	case FormNames:
		words := []string{"like"}
		for _, p := range sortedPatterns(e.Patterns) {
			words = append(words, p.String())
		}
		return strings.Join(words, " ")
	case FormNone:
		return "none"
	}
	return ""
}

func (e Expectation) String() string {
	return ownerText(e.Name) + " " + e.Type.String() + " " + e.FormText()
}

// File is the expectations of one domain.
type File struct {
	Domain       dnswire.Name
	Issuers      []string       // the names that CAA records use for the authorities to expect: lower case, sorted, unique; nil when there is none
	CertNames    []dnswire.Name // names that certificates may hold besides the owners of the lines: dnswire.Compare order, unique by Key
	Expectations []Expectation  // canonical order; at most one for each (Name, Type)
}

func (f *File) Find(name dnswire.Name, t dnswire.Type) (Expectation, bool) {
	for _, e := range f.Expectations {
		if e.Type == t && e.Name.Equal(name) {
			return e, true
		}
	}
	return Expectation{}, false
}

// Zone is the zone that the file expects to hold name: the deepest of the
// domain and the owners of NS lines under it that hold name. A none line
// declares no zone. A name outside the domain gets the domain, because no
// line there declares a zone.
func (f *File) Zone(name dnswire.Name) dnswire.Name {
	zone := f.Domain
	for _, e := range f.Expectations {
		if e.Type == dnswire.TypeNS && e.Form != FormNone && name.IsSubdomainOf(e.Name) &&
			e.Name.IsSubdomainOf(f.Domain) && e.Name.LabelCount() > zone.LabelCount() {
			zone = e.Name
		}
	}
	return zone
}

// SetText is the text of an observed set in the exact form: canonical data,
// sorted, joined by " | ", each record of another type than t prefixed by
// "<TYPE> "; "none" for an empty set. Duplicates are dropped, as Match
// ignores them.
func SetText(t dnswire.Type, set []dnswire.Record) string {
	if len(set) == 0 {
		return "none"
	}
	return dataListText(t, canonicalData(recordData(set)))
}

func recordData(set []dnswire.Record) []dnswire.RData {
	data := make([]dnswire.RData, len(set))
	for i, r := range set {
		data[i] = r.Data
	}
	return data
}

// canonicalData gives a new slice: the data in canonical form (names in
// lower case where RFC 4034 wants it), sorted by type and then by wire form,
// without duplicates.
func canonicalData(data []dnswire.RData) []dnswire.RData {
	out := make([]dnswire.RData, len(data))
	for i, d := range data {
		out[i] = dnswire.Canonical(dnswire.Record{Data: d}).Data
	}
	slices.SortFunc(out, compareData)
	return slices.CompactFunc(out, sameData)
}

func compareData(a, b dnswire.RData) int {
	return cmp.Or(cmp.Compare(a.Type(), b.Type()),
		bytes.Compare(dnswire.AppendRData(nil, a), dnswire.AppendRData(nil, b)))
}

func sameData(a, b dnswire.RData) bool { return compareData(a, b) == 0 }

// canonicalSets gives new slices: each alternative canonical, the
// alternatives sorted by their data in order, without duplicates.
func canonicalSets(sets [][]dnswire.RData) [][]dnswire.RData {
	out := make([][]dnswire.RData, len(sets))
	for i, alt := range sets {
		out[i] = canonicalData(alt)
	}
	slices.SortFunc(out, func(a, b []dnswire.RData) int { return slices.CompareFunc(a, b, compareData) })
	return slices.CompactFunc(out, func(a, b []dnswire.RData) bool { return slices.EqualFunc(a, b, sameData) })
}

func sortedPrefixes(prefixes []netip.Prefix) []netip.Prefix {
	out := slices.Clone(prefixes)
	slices.SortFunc(out, func(a, b netip.Prefix) int {
		return cmp.Or(a.Addr().Compare(b.Addr()), cmp.Compare(a.Bits(), b.Bits()))
	})
	return slices.Compact(out)
}

func sortedPatterns(patterns []Pattern) []Pattern {
	out := slices.Clone(patterns)
	slices.SortFunc(out, comparePatterns)
	return slices.CompactFunc(out, func(a, b Pattern) bool { return comparePatterns(a, b) == 0 })
}

// comparePatterns puts a name before the names under it.
func comparePatterns(a, b Pattern) int {
	if c := dnswire.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	switch {
	case a.Under == b.Under:
		return 0
	case b.Under:
		return -1
	}
	return 1
}

// dataListText writes data of another type than t after its type, so that
// such data never reads as data of type t.
func dataListText(t dnswire.Type, data []dnswire.RData) string {
	texts := make([]string, len(data))
	for i, d := range data {
		texts[i] = dataText(d)
		if d.Type() != t {
			texts[i] = d.Type().String() + " " + texts[i]
		}
	}
	return strings.Join(texts, " | ")
}

func dataText(d dnswire.RData) string { return escapeBars(d.String()) }

func nameText(n dnswire.Name) string { return escapeBars(n.Lower().String()) }

// ownerText keeps a line from reading as a comment.
func ownerText(n dnswire.Name) string {
	s := nameText(n)
	if strings.HasPrefix(s, "#") {
		return `\` + s
	}
	return s
}

// escapeBars puts a backslash before each "|" outside double quotes, so that
// the scanner of the exact form keeps it in the data. Printed data quotes
// only text, and names never print a bare quote, so the quote and backslash
// rule here is the one of the scanner.
func escapeBars(s string) string {
	if !strings.Contains(s, "|") {
		return s
	}
	var b strings.Builder
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+1 < len(s):
			b.WriteByte(c)
			i++
			c = s[i]
		case c == '"':
			quoted = !quoted
		case c == '|' && !quoted:
			b.WriteByte('\\')
		}
		b.WriteByte(c)
	}
	return b.String()
}
