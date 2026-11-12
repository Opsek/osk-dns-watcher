package expect

import (
	"cmp"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// Bounds on the work and memory that one file can ask for.
const (
	maxFileSize     = 4194304
	maxExpectations = 10000
	maxProblems     = 100
	maxAlternatives = 16
	maxRecords      = 1000
	maxTerms        = 64 // prefixes of an "in" form, or patterns of a "like" form
)

// uncheckable are the types that no check can ask for as a record set.
var uncheckable = []dnswire.Type{0, dnswire.TypeOPT, dnswire.TypeTSIG, dnswire.TypeAXFR,
	dnswire.TypeIXFR, dnswire.TypeANY, dnswire.TypeNXNAME}

var patternTypes = []dnswire.Type{dnswire.TypeNS, dnswire.TypeCNAME, dnswire.TypeDNAME, dnswire.TypeMX}

type Problem struct {
	Line int // 0: the file as a whole
	Text string
}

type Error struct {
	Problems []Problem // in line order, at most 100
}

func (e *Error) Error() string {
	texts := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		where := fmt.Sprintf("line %d", p.Line)
		if p.Line == 0 {
			where = "file"
		}
		texts[i] = where + ": " + p.Text
	}
	return strings.Join(texts, "; ")
}

// Keep gives the file to judge with: the new file and nil when data is
// valid, else last (which may be nil) and the *Error. A broken edit must not
// leave the domain without expectations.
func Keep(last *File, data []byte) (*File, error) {
	f, err := Parse(data)
	if err != nil {
		return last, err
	}
	return f, nil
}

// Parse reads a file of expectations. The error is an *Error that lists
// every problem found, so that one pass of edits can fix them all.
func Parse(data []byte) (*File, error) {
	if len(data) > maxFileSize {
		return nil, &Error{Problems: []Problem{{Text: fmt.Sprintf("the file is larger than %d octets", maxFileSize)}}}
	}
	p := parser{seen: map[setKey]int{}}
	n := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		n++
		if text := p.readLine(n, line); text != "" && len(p.problems) < maxProblems {
			p.problems = append(p.problems, Problem{Line: n, Text: text})
		}
	}
	var problems []Problem
	if p.domainLine == 0 {
		problems = append(problems, Problem{Text: "no domain line"})
	}
	if p.count > maxExpectations {
		problems = append(problems, Problem{Text: fmt.Sprintf("more than %d expectations", maxExpectations)})
	}
	problems = append(problems, p.problems...)
	if len(problems) > 0 {
		return nil, &Error{Problems: problems[:min(len(problems), maxProblems)]}
	}
	slices.SortFunc(p.file.Expectations, compareExpectations)
	return &p.file, nil
}

// setKey names one record set; the name is its Key, so case does not count.
type setKey struct {
	name string
	t    dnswire.Type
}

type parser struct {
	file       File
	hasDomain  bool
	domainLine int // the first domain line, valid or not
	count      int // expectation lines
	seen       map[setKey]int
	problems   []Problem
}

// readLine reads one line and gives its problem, or "" when it has none.
func (p *parser) readLine(n int, line string) string {
	first, rest := cutField(line)
	if first == "domain" {
		return p.readDomain(n, line, rest)
	}
	if text := checkOctets(line); text != "" {
		return text
	}
	if first == "" || first[0] == '#' {
		return ""
	}
	p.count++
	e, text := p.readExpectation(n, first, rest)
	if text == "" {
		p.file.Expectations = append(p.file.Expectations, e)
	}
	return text
}

// readDomain counts a faulty domain line as given, so that one fault does
// not also report a missing domain line.
func (p *parser) readDomain(n int, line, rest string) string {
	if p.domainLine != 0 {
		return fmt.Sprintf("domain already given on line %d", p.domainLine)
	}
	p.domainLine = n
	if text := checkOctets(line); text != "" {
		return text
	}
	fields := splitFields(rest)
	if len(fields) != 1 {
		return "a domain line takes one name"
	}
	name, text := parseName(fields[0])
	if text != "" {
		return text
	}
	if name.LabelCount() == 0 {
		return fmt.Sprintf("bad name %q: the domain cannot be the root", fields[0])
	}
	p.file.Domain, p.hasDomain = name, true
	if p.count > 0 {
		return "the domain line must come before the expectations"
	}
	return ""
}

func (p *parser) readExpectation(n int, ownerField, rest string) (Expectation, string) {
	typeField, form := cutField(rest)
	if form == "" {
		return Expectation{}, "want <owner> <type> <form>"
	}
	owner, text := parseName(ownerField)
	if text != "" {
		return Expectation{}, text
	}
	t, err := dnswire.ParseType(typeField)
	if err != nil {
		return Expectation{}, fmt.Sprintf("%q is not a type; the file has no TTL or class field", typeField)
	}
	if slices.Contains(uncheckable, t) {
		return Expectation{}, fmt.Sprintf("type %s cannot be checked", t)
	}
	// The DS set lives at the parent and is checked for the domain alone.
	if t == dnswire.TypeDS && p.hasDomain && !owner.Equal(p.file.Domain) {
		return Expectation{}, "a DS set is checked only at the domain"
	}
	key := setKey{name: owner.Key(), t: t}
	if line, ok := p.seen[key]; ok {
		return Expectation{}, fmt.Sprintf("%s %s is already expected on line %d", owner.Lower(), t, line)
	}
	p.seen[key] = n
	e := Expectation{Line: n, Name: owner, Type: t}
	text = readForm(&e, form)
	return e, text
}

// readForm fills the form of e from the text after the type. A keyword
// counts only as the first field, in lower case, so that data such as a
// CAA tag "none" stays data.
func readForm(e *Expectation, text string) string {
	keyword, rest := cutField(text)
	switch keyword {
	case "none":
		e.Form = FormNone
		if rest != "" {
			return fmt.Sprintf("%q takes no more fields", keyword)
		}
		return ""
	case "in":
		e.Form = FormRange
		return readRanges(e, splitFields(rest))
	case "like":
		e.Form = FormNames
		return readPatterns(e, splitFields(rest))
	}
	e.Form = FormSets
	return readSets(e, text)
}

func readRanges(e *Expectation, fields []string) string {
	if e.Type != dnswire.TypeA && e.Type != dnswire.TypeAAAA {
		return "in is for A and AAAA only"
	}
	if len(fields) > maxTerms {
		return fmt.Sprintf("more than %d prefixes or patterns", maxTerms)
	}
	if len(fields) == 0 {
		return `bad prefix ""`
	}
	for _, f := range fields {
		p, err := netip.ParsePrefix(f)
		switch {
		case err != nil:
			return fmt.Sprintf("bad prefix %q", f)
		case e.Type == dnswire.TypeA && !p.Addr().Is4():
			return fmt.Sprintf("prefix %s is not IPv4", p)
		case e.Type == dnswire.TypeAAAA && !p.Addr().Is6():
			return fmt.Sprintf("prefix %s is not IPv6", p)
		case p != p.Masked():
			return fmt.Sprintf("prefix %s has bits after its length; write %s", p, p.Masked())
		}
		e.Ranges = append(e.Ranges, p)
	}
	e.Ranges = sortedPrefixes(e.Ranges)
	return ""
}

func readPatterns(e *Expectation, fields []string) string {
	if !slices.Contains(patternTypes, e.Type) {
		return "like is for NS, CNAME, DNAME and MX only"
	}
	if len(fields) > maxTerms {
		return fmt.Sprintf("more than %d prefixes or patterns", maxTerms)
	}
	if len(fields) == 0 {
		return `bad pattern ""`
	}
	for _, f := range fields {
		pattern, text := parsePattern(f)
		if text != "" {
			return text
		}
		e.Patterns = append(e.Patterns, pattern)
	}
	e.Patterns = sortedPatterns(e.Patterns)
	return ""
}

func parsePattern(field string) (Pattern, string) {
	if !hasTrailingDot(field) {
		return Pattern{}, fmt.Sprintf("%q has no trailing dot", field)
	}
	text, under := strings.CutPrefix(field, "*.")
	if under && (text == "" || text == ".") {
		// Every name lies under the root, so this would allow any target.
		return Pattern{}, fmt.Sprintf("bad pattern %q", field)
	}
	name, err := dnswire.ParseName(text)
	if err != nil {
		return Pattern{}, fmt.Sprintf("bad name %q: %v", field, err)
	}
	if labels := name.Labels(); len(labels) > 0 && labels[0] == "*" {
		// It would print as "*.<name>", the other kind of pattern.
		return Pattern{}, fmt.Sprintf("bad pattern %q", field)
	}
	return Pattern{Name: name, Under: under}, ""
}

func readSets(e *Expectation, text string) string {
	alts, ok := splitSets(text)
	if !ok {
		return "an empty record"
	}
	if len(alts) > maxAlternatives {
		return fmt.Sprintf("more than %d alternatives", maxAlternatives)
	}
	for _, alt := range alts {
		if len(alt) > maxRecords {
			return fmt.Sprintf("more than %d records in one set", maxRecords)
		}
		var set []dnswire.RData
		for _, s := range alt {
			d, err := dnswire.ParseRData(e.Type, s)
			if err != nil {
				return "bad data: " + err.Error()
			}
			set = append(set, d)
		}
		e.Sets = append(e.Sets, set)
	}
	e.Sets = canonicalSets(e.Sets)
	return ""
}

// splitSets reads the exact form: records apart at "|", alternatives at
// "||". Quotes and backslashes follow the rule of record data, so a "|"
// inside quotes or after a backslash stays in its record. ok is false when a
// record is empty, which also covers a run of three or more "|".
func splitSets(s string) (alts [][]string, ok bool) {
	var records []string
	start, end := -1, 0 // the record being read is s[start:end], without blanks at either end
	quoted := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if !quoted && (c == ' ' || c == '\t') {
			continue
		}
		if !quoted && c == '|' {
			run := len(s[i:]) - len(strings.TrimLeft(s[i:], "|"))
			if start < 0 || run > 2 {
				return nil, false
			}
			records = append(records, s[start:end])
			start = -1
			if run == 2 {
				alts = append(alts, records)
				records = nil
			}
			i += run - 1
			continue
		}
		if start < 0 {
			start = i
		}
		switch c {
		case '\\':
			i++
		case '"':
			quoted = !quoted
		}
		end = min(i+1, len(s))
	}
	if start < 0 {
		return nil, false
	}
	return append(alts, append(records, s[start:end])), true
}

// cutField gives the first field of s and the text after it, both without
// blanks in front. A field ends at a blank outside double quotes, and a
// backslash keeps the next octet in the field, as in record data.
func cutField(s string) (field, rest string) {
	s = strings.TrimLeft(s, " \t")
	quoted := false
	for i := 0; i < len(s); i++ {
		switch c := s[i]; {
		case c == '\\':
			i++
		case c == '"':
			quoted = !quoted
		case !quoted && (c == ' ' || c == '\t'):
			return s[:i], strings.TrimLeft(s[i:], " \t")
		}
	}
	return s, ""
}

func splitFields(s string) []string {
	var fields []string
	for field, rest := cutField(s); field != ""; field, rest = cutField(rest) {
		fields = append(fields, field)
	}
	return fields
}

// checkOctets keeps out control octets and look-alike characters, so that a
// person who reviews a change of the file sees every octet of it.
func checkOctets(line string) string {
	for i := 0; i < len(line); i++ {
		if c := line[i]; c != '\t' && (c < 0x20 || c > 0x7E) {
			return fmt.Sprintf("octet 0x%02X is not printable ASCII", c)
		}
	}
	return ""
}

// parseName reads an owner or the domain. The file has no origin, so a name
// without its trailing dot is a mistake, such as "www" meant as
// "www.corp.test.".
func parseName(field string) (dnswire.Name, string) {
	if !hasTrailingDot(field) {
		return dnswire.Name{}, fmt.Sprintf("%q has no trailing dot", field)
	}
	n, err := dnswire.ParseName(field)
	if err != nil {
		return dnswire.Name{}, fmt.Sprintf("bad name %q: %v", field, err)
	}
	return n, ""
}

// hasTrailingDot reports whether s ends with a dot that no backslash keeps
// in its label.
func hasTrailingDot(s string) bool {
	body, ok := strings.CutSuffix(s, ".")
	return ok && (len(body)-len(strings.TrimRight(body, `\`)))%2 == 0
}

// String prints the file in its canonical form: one line for each set, so
// that a change of one set is a one-line change of the text.
func (f *File) String() string {
	var b strings.Builder
	b.WriteString("domain " + nameText(f.Domain) + "\n")
	for _, e := range slices.SortedFunc(slices.Values(f.Expectations), compareExpectations) {
		b.WriteString(e.String() + "\n")
	}
	return b.String()
}

func compareExpectations(a, b Expectation) int {
	return cmp.Or(dnswire.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type))
}
