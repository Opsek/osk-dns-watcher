// Package decide judges one observation against the expectations of its
// domain and turns what it finds into changes of the open alerts. It reads
// no clock, network, file or store, and never depends on map order, so the
// same input always gives the same changes in the same order.
package decide

import (
	"cmp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Rule is what a finding says is wrong. The store keeps the number of a
// rule, so a new rule is only ever appended.
type Rule uint8

const (
	RuleInvalidFile  Rule = iota + 1 // the expectations file is not valid
	RuleNotCovered                   // no expectation covers the check
	RuleZone                         // the set was served by another zone than the file declares
	RuleNameServers                  // the parent delegates the domain to other name servers
	RuleRecordSet                    // a server gives another record set than expected
	RuleCheckFailing                 // the check has had no usable answer for too long
	RuleZoneChanged                  // the serial of the zone moved and no watched record differs
)

var ruleWords = map[Rule]string{
	RuleInvalidFile:  "invalid-file",
	RuleNotCovered:   "not-covered",
	RuleZone:         "zone",
	RuleNameServers:  "nameservers",
	RuleRecordSet:    "record-set",
	RuleCheckFailing: "check-failing",
	RuleZoneChanged:  "zone-changed",
}

func (r Rule) String() string { return word(ruleWords, r, "rule") }

type Severity uint8

const (
	SeverityLow Severity = iota + 1
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

var severityWords = map[Severity]string{
	SeverityLow:      "low",
	SeverityMedium:   "medium",
	SeverityHigh:     "high",
	SeverityCritical: "critical",
}

func (s Severity) String() string { return word(severityWords, s, "severity") }

// Op is what a change does to an alert.
type Op uint8

const (
	OpOpen Op = iota + 1
	OpUpdate
	OpResolve
)

var opWords = map[Op]string{
	OpOpen:    "open",
	OpUpdate:  "update",
	OpResolve: "resolve",
}

func (o Op) String() string { return word(opWords, o, "op") }

func word[T ~uint8](words map[T]string, v T, prefix string) string {
	if w, ok := words[v]; ok {
		return w
	}
	return prefix + strconv.Itoa(int(v))
}

// severities is the weight of each rule. A record-set finding about one of
// highTypes weighs high instead: those sets steer traffic and mail.
var severities = map[Rule]Severity{
	RuleInvalidFile:  SeverityMedium,
	RuleNotCovered:   SeverityMedium,
	RuleZone:         SeverityHigh,
	RuleNameServers:  SeverityCritical,
	RuleRecordSet:    SeverityMedium,
	RuleCheckFailing: SeverityMedium,
	RuleZoneChanged:  SeverityLow,
}

var highTypes = map[dnswire.Type]bool{
	dnswire.TypeA:     true,
	dnswire.TypeAAAA:  true,
	dnswire.TypeCNAME: true,
	dnswire.TypeMX:    true,
	dnswire.TypeNS:    true,
}

func severity(r Rule, t dnswire.Type) Severity {
	if r == RuleRecordSet && highTypes[t] {
		return SeverityHigh
	}
	return severities[r]
}

type Seen struct {
	Answer obs.Answer // the proof as observe gave it, times included
	Text   string     // SetText of its Set ("none" for no data or no such name); for RuleZone the zone name
}

type Finding struct {
	Rule     Rule
	Severity Severity
	Check    obs.Key // the check that shows it; RuleInvalidFile, RuleZoneChanged: Kind 0, Domain = Name = the domain, Type 0
	Expected string  // FormText of the expectation; "" when there is none
	Seen     []Seen
	Value    string // the Seen lines "<addr> <host> <Text>" joined by "\n"; RuleInvalidFile: the error text; RuleCheckFailing: the limit; RuleZoneChanged: a line for each move
}

type Change struct {
	Op      Op
	Finding Finding   // open, update: the finding now; resolve: the open finding that ends
	At      time.Time // the time given to Decide, FileChanges or ZoneChanges
}

type Input struct {
	Expect       *expect.File // the file in force (expect.Keep); nil when no file was ever valid
	Open         []Finding    // open alerts: the finding that opened or last updated each
	Observation  obs.Observation
	Now          time.Time
	FailingSince time.Time     // start of the unbroken series of runs of this check with no usable answer, this one included; zero when this run had one
	FailLimit    time.Duration // how long such a series may last before check-failing; 0: never
}

// Findings judges o against f, in Rule order. A failed answer is unknown: it
// is never read as no records, never counts as a difference and is never
// seen. Open alerts play no part, so they cannot change the judgement.
func Findings(f *expect.File, o obs.Observation) []Finding {
	e, ok := expectation(f, o.Key)
	var found []Finding
	switch o.Key.Kind {
	case obs.KindDelegation:
		found = judge(o, e, ok, RuleNameServers)
	case obs.KindDS:
		// A DS line covers the check, but the DS data is not compared.
		if !ok {
			found = []Finding{notCovered(o)}
		}
	case obs.KindRecords:
		found = append(zone(f, o), judge(o, e, ok, RuleRecordSet)...)
	case obs.KindSerial:
		// No line of the file is about the serial.
	}
	slices.SortStableFunc(found, func(a, b Finding) int { return cmp.Compare(a.Rule, b.Rule) })
	return found
}

// expectation is the line for the check. A file of another domain covers
// nothing.
func expectation(f *expect.File, k obs.Key) (expect.Expectation, bool) {
	if f == nil || !k.Domain.Equal(f.Domain) {
		return expect.Expectation{}, false
	}
	return f.Find(k.Name, k.Type)
}

// judge gives not-covered when there is no expectation, else a finding of
// rule r when some server gives a set that does not match.
func judge(o obs.Observation, e expect.Expectation, ok bool, r Rule) []Finding {
	if !ok {
		return []Finding{notCovered(o)}
	}
	differs := func(set []dnswire.Record) bool { return !e.Match(set) }
	seen := seenIf(o.Answers, differs, setText(o.Key.Type))
	if len(seen) == 0 {
		return nil
	}
	return []Finding{newFinding(r, o, e.FormText(), seen)}
}

// notCovered is given even when every answer failed: an unwatched set is
// never reported as fine.
func notCovered(o obs.Observation) Finding {
	return newFinding(RuleNotCovered, o, "", seenIf(o.Answers, anySet, setText(o.Key.Type)))
}

// zone gives a finding when a name of the domain was served by another zone
// than the deepest cut that the file declares above it. One child server can
// refer the walk to a cut that it invents, and the servers it names can then
// answer with matching data, so this needs no record difference. Outside the
// domain nothing tells which zone is right.
func zone(f *expect.File, o obs.Observation) []Finding {
	if f == nil || !o.Key.Domain.Equal(f.Domain) || !o.Key.Name.IsSubdomainOf(f.Domain) || walkFailed(o) {
		return nil
	}
	want := f.Zone(o.Key.Name)
	if o.Zone.Equal(want) {
		return nil
	}
	text := func([]dnswire.Record) string { return o.Zone.Lower().String() }
	seen := seenIf(o.Walk, ownsNS(o.Zone), text)
	if len(seen) == 0 {
		seen = seenIf(o.Answers, anySet, text)
	}
	return []Finding{newFinding(RuleZone, o, want.Lower().String(), seen)}
}

// walkFailed reports the one answer that observe gives when the walk from
// the root failed: it comes from no server at all.
func walkFailed(o obs.Observation) bool {
	if len(o.Answers) != 1 {
		return false
	}
	s := o.Answers[0].Server
	return s.Name.LabelCount() == 0 && !s.Addr.IsValid()
}

// ownsNS accepts a referral into zone.
func ownsNS(zone dnswire.Name) func([]dnswire.Record) bool {
	return func(set []dnswire.Record) bool {
		return slices.ContainsFunc(set, func(r dnswire.Record) bool {
			return r.Type() == dnswire.TypeNS && r.Name.Equal(zone)
		})
	}
}

func anySet([]dnswire.Record) bool { return true }

func setText(t dnswire.Type) func([]dnswire.Record) string {
	return func(set []dnswire.Record) string { return expect.SetText(t, set) }
}

// seenIf gives a Seen for each answer that is not a failure and whose set
// keep accepts, in order, with the Text that text gives for that set.
func seenIf(answers []obs.Answer, keep func([]dnswire.Record) bool, text func([]dnswire.Record) string) []Seen {
	var seen []Seen
	for _, a := range answers {
		if set, ok := answerSet(a); ok && keep(set) {
			seen = append(seen, Seen{Answer: a, Text: text(set)})
		}
	}
	return seen
}

// answerSet gives the record set of an answer, empty for no data and for no
// such name; ok is false for a failure.
func answerSet(a obs.Answer) (set []dnswire.Record, ok bool) {
	ok = obs.Match(a.Result,
		func(r obs.Records) bool { set = r.Set; return true },
		func(obs.NoData) bool { return true },
		func(obs.NoName) bool { return true },
		func(obs.Failure) bool { return false })
	return set, ok
}

func newFinding(r Rule, o obs.Observation, expected string, seen []Seen) Finding {
	return Finding{Rule: r, Severity: severity(r, o.Key.Type), Check: o.Key, Expected: expected, Seen: seen, Value: value(seen)}
}

func value(seen []Seen) string {
	lines := make([]string, len(seen))
	for i, s := range seen {
		lines[i] = serverText(s.Answer.Server) + " " + s.Text
	}
	return strings.Join(lines, "\n")
}

// serverText writes "-" for a server with no address, and for a server whose
// name is not known, which observe gives as the root.
func serverText(s obs.Server) string {
	addr, host := "-", "-"
	if s.Addr.IsValid() {
		addr = s.Addr.String()
	}
	if s.Name.LabelCount() > 0 {
		host = s.Name.Lower().String()
	}
	return addr + " " + host
}

// Decide gives the changes of the open alerts of the observed check. Open
// findings of other checks are never read.
func Decide(in Input) []Change {
	o := in.Observation
	found := Findings(in.Expect, o)
	if f, ok := checkFailing(in); ok {
		found = append(found, f)
	}
	open := firstOpen(in.Open, o.Key.String())
	changes := openOrUpdate(found, open, in.Now)
	for _, was := range open {
		ends := !hasRule(found, was.Rule) && !blocked(was, o)
		if was.Rule == RuleCheckFailing {
			// A restart forgets the series, so a failed run may not reach
			// the limit again; only a usable answer shows that the check
			// sees the zone again.
			ends = !Failed(o)
		}
		if ends {
			changes = append(changes, Change{Op: OpResolve, Finding: was, At: in.Now})
		}
	}
	return changes
}

// FileChanges opens or updates the invalid-file alert of the domain while
// the file is not valid, and resolves it once it is.
func FileChanges(domain dnswire.Name, err error, open []Finding, now time.Time) []Change {
	scope := domainScope(domain)
	mine := firstOpen(open, scope.String())
	if err != nil {
		f := Finding{Rule: RuleInvalidFile, Severity: severity(RuleInvalidFile, 0), Check: scope, Value: err.Error()}
		return openOrUpdate([]Finding{f}, mine, now)
	}
	return resolveRule(mine, RuleInvalidFile, now)
}

// domainScope is the check of an alert about the whole domain. No
// observation has a key of kind 0, so no check can open, update or resolve
// such an alert.
func domainScope(domain dnswire.Name) obs.Key {
	return obs.Key{Domain: domain, Name: domain}
}

// resolveRule resolves the open finding of rule r in mine, if there is one.
func resolveRule(mine []Finding, r Rule, now time.Time) []Change {
	i := slices.IndexFunc(mine, func(f Finding) bool { return f.Rule == r })
	if i < 0 {
		return nil
	}
	return []Change{{Op: OpResolve, Finding: mine[i], At: now}}
}

// firstOpen gives the open findings of check k, in order. Only the first
// of each rule counts.
func firstOpen(open []Finding, k string) []Finding {
	var mine []Finding
	for _, f := range open {
		if f.Check.String() == k && !hasRule(mine, f.Rule) {
			mine = append(mine, f)
		}
	}
	return mine
}

func hasRule(findings []Finding, r Rule) bool {
	return slices.ContainsFunc(findings, func(f Finding) bool { return f.Rule == r })
}

func openOrUpdate(found, open []Finding, now time.Time) []Change {
	var changes []Change
	for _, f := range found {
		i := slices.IndexFunc(open, func(o Finding) bool { return o.Rule == f.Rule })
		switch {
		case i < 0:
			changes = append(changes, Change{Op: OpOpen, Finding: f, At: now})
		case changed(open[i], f):
			changes = append(changes, Change{Op: OpUpdate, Finding: f, At: now})
		}
	}
	return changes
}

// changed reports whether f tells more than was. A line that is gone is no
// news: a server that fails now and then drops out of Seen and comes back.
func changed(was, f Finding) bool {
	if was.Expected != f.Expected || was.Severity != f.Severity {
		return true
	}
	old := lines(was.Value)
	return slices.ContainsFunc(lines(f.Value), func(l string) bool { return !slices.Contains(old, l) })
}

func lines(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// blocked reports whether a failure now could hide the problem that f shows:
// every answer failed, so the run saw nothing; a failure with no address
// (the walk or a host lookup failed); or a failure at a server that showed
// the problem. Any other failure does not block, so an address that this
// machine cannot reach does not keep an alert open for good.
func blocked(f Finding, o obs.Observation) bool {
	if Failed(o) {
		return true
	}
	for _, a := range o.Answers {
		if _, ok := answerSet(a); ok {
			continue
		}
		showed := func(s Seen) bool { return s.Answer.Server.Addr == a.Server.Addr }
		if !a.Server.Addr.IsValid() || slices.ContainsFunc(f.Seen, showed) {
			return true
		}
	}
	return false
}
