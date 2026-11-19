package expect

import (
	"cmp"
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Skip is a set that Snapshot wrote no line for, and why.
type Skip struct {
	Name dnswire.Name
	Type dnswire.Type
	Why  string
}

// Snapshot turns observations of one domain into a file. A set gets a line
// only when every server answered and all agree, because the file is what
// later answers are judged against. The exceptions: an IPv6 address that
// this machine cannot reach (see reachable), and the NS set of the domain
// (see nsAlternatives). Skips are sorted by Name, then Type.
func Snapshot(domain dnswire.Name, observations []obs.Observation) (*File, []Skip) {
	file := &File{Domain: domain}
	var skips []Skip
	mine := ofDomain(domain, observations)
	groups := groupSets(mine)
	for _, g := range groups {
		e, _, why := g.line()
		if why == "" {
			why = unreadable(domain, e.String())
		}
		if why != "" {
			skips = append(skips, Skip{Name: g.name, Type: g.t, Why: why})
			continue
		}
		file.Expectations = append(file.Expectations, e)
	}
	var policySkips []Skip
	file.Policy, policySkips = snapshotPolicy(domain, groups, mine)
	skips = append(skips, policySkips...)
	skips = append(skips, dropForeignZones(file, observations)...)
	skips = append(skips, dropDifferentGlue(file, mine)...)
	slices.SortFunc(file.Expectations, compareExpectations)
	slices.SortFunc(skips, func(a, b Skip) int {
		return cmp.Or(dnswire.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type))
	})
	return file, skips
}

// unreadable gives the first problem that Parse finds in a file of domain
// whose one line is line, or "" when it finds none. Parse is the one source
// of what a line may hold: a record can print in a form that it refuses, and
// a line can break a rule on its owner, such as a DS set below the domain.
// One such line makes the whole file invalid.
func unreadable(domain dnswire.Name, line string) string {
	_, err := Parse([]byte("domain " + nameText(domain) + "\n" + line + "\n"))
	var e *Error
	if !errors.As(err, &e) || len(e.Problems) == 0 {
		return ""
	}
	return "the file cannot hold this line: " + e.Problems[0].Text
}

// Unreached gives the servers that a snapshot of these observations leaves
// out of a set that gets a line: IPv6 addresses that this machine could not
// reach. Each address is given once, sorted.
func Unreached(observations []obs.Observation) []obs.Server {
	var servers []obs.Server
	for _, g := range groupSets(observations) {
		if _, left, why := g.line(); why == "" {
			servers = append(servers, left...)
		}
	}
	slices.SortFunc(servers, func(a, b obs.Server) int { return a.Addr.Compare(b.Addr) })
	return slices.CompactFunc(servers, func(a, b obs.Server) bool { return a.Addr == b.Addr })
}

// ofDomain gives the observations of the checks of domain.
func ofDomain(domain dnswire.Name, observations []obs.Observation) []obs.Observation {
	return slices.DeleteFunc(slices.Clone(observations), func(o obs.Observation) bool {
		return !o.Key.Domain.Equal(domain)
	})
}

// setGroup is every answer about one record set, in the order of the
// observations and of their answers.
type setGroup struct {
	name    dnswire.Name
	t       dnswire.Type
	answers []obs.Answer
	parent  []bool // for each answer: it came from the parent zone, through the delegation check
}

func groupSets(observations []obs.Observation) []*setGroup {
	var groups []*setGroup
	byKey := map[setKey]*setGroup{}
	for _, o := range observations {
		name, t, ok := setOf(o.Key)
		if !ok {
			continue
		}
		key := setKey{name: name.Key(), t: t}
		g := byKey[key]
		if g == nil {
			g = &setGroup{name: name, t: t}
			byKey[key] = g
			groups = append(groups, g)
		}
		answers := o.Answers
		if len(answers) == 0 {
			// The zero Answer reads as a failure: no answer proves nothing.
			answers = []obs.Answer{{}}
		}
		g.answers = append(g.answers, answers...)
		for range answers {
			g.parent = append(g.parent, o.Key.Kind == obs.KindDelegation)
		}
	}
	return groups
}

// setOf gives the record set that an observation shows. The delegation and
// the apex records share the NS line of the domain.
func setOf(k obs.Key) (dnswire.Name, dnswire.Type, bool) {
	switch k.Kind {
	case obs.KindDelegation:
		return k.Domain, dnswire.TypeNS, true
	case obs.KindDS:
		return k.Domain, dnswire.TypeDS, true
	case obs.KindRecords:
		return k.Name, k.Type, true
	case obs.KindSerial:
		// The serial changes with every edit of the zone; no line holds it.
	case obs.KindWildcard:
		// A random name is no set of the file.
	case obs.KindCertificates:
		// A certificate log is no record set.
	case obs.KindPolicy:
		// A policy file gives the mta-sts line, not a set: see snapshotPolicy.
	}
	return dnswire.Name{}, 0, false
}

// snapshotPolicy gives the mta-sts line that the fetches of the policy file
// show, or a Skip that says why they give none. A domain whose MTA-STS
// record is off gets neither: it has no policy to watch. As for a set, every
// fetch must have read the file, and all must read one policy.
func snapshotPolicy(domain dnswire.Name, groups []*setGroup, observations []obs.Observation) (*STSPolicy, []Skip) {
	if !stsRecordOn(domain, groups) {
		return nil, nil
	}
	var line *STSPolicy
	var from obs.Server // the last server that gave line
	for _, o := range observations {
		if o.Key.Kind != obs.KindPolicy {
			continue
		}
		for _, a := range o.Answers {
			p, why := fetchedPolicy(a)
			if why == "" {
				why = unreadable(domain, p.String())
			}
			if why == "" && line != nil && p.String() != line.String() {
				why = fmt.Sprintf("servers disagree: %s gives %s; %s gives %s",
					serverText(from), line.String(), serverText(a.Server), p.String())
			}
			if why != "" {
				return nil, []Skip{{Name: o.Key.Name, Type: dnswire.TypeTXT, Why: why}}
			}
			line, from = &p, a.Server
		}
	}
	return line, nil
}

// stsRecordOn reports whether the records check of _mta-sts.<domain> TXT
// shows one MTA-STS record that reads, or a CNAME: a provider that hosts the
// record (RFC 8461 section 8.2). Every server that judges the set must have
// answered, and all must agree.
func stsRecordOn(domain dnswire.Name, groups []*setGroup) bool {
	for _, g := range groups {
		if g.t != dnswire.TypeTXT || MailKindOf(g.name) != MailMTASTS || !g.name.Parent().Equal(domain) {
			continue
		}
		set := g.agreed()
		return STSOn(recordData(set)) ||
			slices.ContainsFunc(set, func(r dnswire.Record) bool { return r.Type() == dnswire.TypeCNAME })
	}
	return false
}

// agreed gives the set that every answer that judges g gives; nil when one
// of them failed or two differ.
func (g *setGroup) agreed() []dnswire.Record {
	answers, _ := g.reachable()
	seen := map[string]struct{}{}
	var set []dnswire.Record
	for _, a := range answers {
		s, _, failed := readAnswer(a)
		if failed {
			return nil
		}
		set = s
		seen[SetText(g.t, s)] = struct{}{}
	}
	if len(seen) != 1 {
		return nil
	}
	return set
}

// fetchedPolicy reads the policy file of one fetch: the TXT strings of its
// records, joined. A negative answer reads as an empty file, which is no
// policy.
func fetchedPolicy(a obs.Answer) (STSPolicy, string) {
	set, failure, failed := readAnswer(a)
	if failed {
		return STSPolicy{}, fmt.Sprintf("%s gave no answer: %s", serverText(a.Server), failure.Reason)
	}
	p, problem := ParseSTSPolicy([]byte(strings.Join(texts(recordData(set)), "")))
	if problem != "" {
		return STSPolicy{}, "the policy file cannot be read: " + problem
	}
	return p, ""
}

// line gives the line of the set and the servers that it leaves out, or why
// it gets none. The NS set of the domain gets a line with each set that its
// servers gave when they do not agree; the reason then stays only when that
// line cannot be written either.
func (g *setGroup) line() (Expectation, []obs.Server, string) {
	e, left, why := g.agreedLine()
	if why == "" || !slices.Contains(g.parent, true) {
		return e, left, why
	}
	if ns, ok := g.nsAlternatives(); ok {
		return ns.line, ns.left, ""
	}
	return e, left, why
}

// agreedLine gives the line of a set on which every server agrees, or why
// there is none: the first reason of this order that applies, at the first
// answer that shows it.
func (g *setGroup) agreedLine() (Expectation, []obs.Server, string) {
	answers, left := g.reachable()
	sets := make([][]dnswire.Record, len(answers))
	for i, a := range answers {
		set, failure, failed := readAnswer(a)
		if failed {
			return Expectation{}, nil, fmt.Sprintf("%s gave no answer: %s", serverText(a.Server), failure.Reason)
		}
		sets[i] = set
	}
	for i, set := range sets {
		for _, r := range set {
			if r.Type() != g.t {
				return Expectation{}, nil, fmt.Sprintf("%s answers with a %s record; snapshot %s %s instead",
					serverText(answers[i].Server), r.Type(), g.name.Lower(), r.Type())
			}
		}
	}
	first := SetText(g.t, sets[0])
	for i, set := range sets {
		if text := SetText(g.t, set); text != first {
			return Expectation{}, nil, fmt.Sprintf("servers disagree: %s gives %s; %s gives %s",
				serverText(answers[0].Server), first, serverText(answers[i].Server), text)
		}
	}
	if len(sets[0]) == 0 {
		return Expectation{Name: g.name, Type: g.t, Form: FormNone}, left, ""
	}
	if IsChallengeName(g.name) {
		return Expectation{}, nil, "a certificate-challenge record is there now; write none once it is gone, or no line if you use DNS challenges"
	}
	data := canonicalData(recordData(sets[0]))
	if len(data) > maxRecords {
		return Expectation{}, nil, fmt.Sprintf("more than %d records", maxRecords)
	}
	return Expectation{Name: g.name, Type: g.t, Form: FormSets, Sets: [][]dnswire.RData{data}}, left, ""
}

// maxNSSets bounds the sets that one NS line accepts. Each set is trust given
// on one look; servers that give more sets than this are in the middle of a
// change, or several of them lie, and must be put right first.
const maxNSSets = 4

// NSSource is one set of an NS line that accepts several, and the servers
// that gave it, each as "<addr> <host>".
type NSSource struct {
	Text   string   // the set as the line writes it
	Parent []string // servers of the parent zone, in the order of their answers
	Zone   []string // servers of the domain
}

// NSSources gives the sets of the NS line that Snapshot writes for domain,
// in the order of the line, when the line accepts more than one; else nil.
func NSSources(domain dnswire.Name, observations []obs.Observation) []NSSource {
	if ns, ok := nsOf(domain, observations); ok && len(ns.sources) > 1 {
		return ns.sources
	}
	return nil
}

// NoPath stands in NSNoAnswer for the servers of the domain when the walk
// from the root found no path to them.
const NoPath = "no path from the root to the servers of the domain"

// NSNoAnswer gives the servers that gave no answer about the NS set of
// domain, each as "<addr> <host> (<reason>)", or NoPath, when the NS line
// that Snapshot writes rests on the others. An IPv6 address that this
// machine cannot reach is not among them: Unreached gives it.
func NSNoAnswer(domain dnswire.Name, observations []obs.Observation) []string {
	ns, _ := nsOf(domain, observations)
	return ns.noAnswer
}

func nsOf(domain dnswire.Name, observations []obs.Observation) (nsLine, bool) {
	for _, g := range groupSets(ofDomain(domain, observations)) {
		if slices.Contains(g.parent, true) {
			return g.nsAlternatives()
		}
	}
	return nsLine{}, false
}

// nsLine is the NS line of the domain with each set that a server gave.
type nsLine struct {
	line     Expectation
	sources  []NSSource
	left     []obs.Server // IPv6 addresses that this machine cannot reach
	noAnswer []string     // every other server that gave no answer
}

// nsAlternatives gives the NS line of the domain with each set that a server
// gave as one alternative. The parent zone and the domain's own servers
// often disagree in small ways, and a domain without an NS line has no alarm
// for a change of its nameservers. A failed answer says nothing and is left
// out. ok is false when the parent zone gave no set, which is the one that
// resolvers follow; when an answer is no data, no such name or a record of
// another type, which no alternative can state; and when there are more than
// maxNSSets sets.
func (g *setGroup) nsAlternatives() (nsLine, bool) {
	type alt struct {
		data   []dnswire.RData
		source NSSource
	}
	var alts []alt
	var ns nsLine
	fromParent := false
	for i, a := range g.answers {
		set, failure, failed := readAnswer(a)
		switch {
		case failed && failure.Reason == obs.ReasonNetwork && a.Server.Addr.Addr().Is6():
			ns.left = append(ns.left, a.Server)
			continue
		case failed && !g.parent[i] && a.Server.Name.LabelCount() == 0 && !a.Server.Addr.IsValid():
			// The walk to the servers of the domain failed, so no server can be named.
			if !slices.Contains(ns.noAnswer, NoPath) {
				ns.noAnswer = append(ns.noAnswer, NoPath)
			}
			continue
		case failed:
			ns.noAnswer = append(ns.noAnswer, serverText(a.Server)+" ("+failure.Reason.String()+")")
			continue
		}
		if len(set) == 0 || slices.ContainsFunc(set, func(r dnswire.Record) bool { return r.Type() != g.t }) {
			return nsLine{}, false
		}
		fromParent = fromParent || g.parent[i]
		text := SetText(g.t, set)
		j := slices.IndexFunc(alts, func(x alt) bool { return x.source.Text == text })
		if j < 0 {
			alts = append(alts, alt{data: canonicalData(recordData(set)), source: NSSource{Text: text}})
			j = len(alts) - 1
		}
		if g.parent[i] {
			alts[j].source.Parent = append(alts[j].source.Parent, serverText(a.Server))
		} else {
			alts[j].source.Zone = append(alts[j].source.Zone, serverText(a.Server))
		}
	}
	if !fromParent || len(alts) > maxNSSets {
		return nsLine{}, false
	}
	// The order of the line, so that the same answers give the same file.
	slices.SortFunc(alts, func(a, b alt) int { return slices.CompareFunc(a.data, b.data, compareData) })
	ns.line = Expectation{Name: g.name, Type: g.t, Form: FormSets}
	for _, x := range alts {
		ns.line.Sets = append(ns.line.Sets, x.data)
		ns.sources = append(ns.sources, x.source)
	}
	return ns, true
}

// IsChallengeName reports whether name is an ACME challenge name. The record
// at such a name, or an alias that hands it to another zone, lets whoever
// controls it obtain a certificate. Its token changes with each request, so a
// line for it would report the next one.
func IsChallengeName(name dnswire.Name) bool {
	labels := name.Labels()
	return len(labels) > 0 && strings.EqualFold(labels[0], "_acme-challenge")
}

// reachable gives the answers that judge the set, and the servers left out.
// On a machine without IPv6, every IPv6 address fails with network, and
// almost no set would get a line. So such an answer is left out when another
// answer is usable: the line then rests on the servers that answered.
func (g *setGroup) reachable() ([]obs.Answer, []obs.Server) {
	var kept []obs.Answer
	var left []obs.Server
	usable := false
	for _, a := range g.answers {
		_, failure, failed := readAnswer(a)
		if failed && failure.Reason == obs.ReasonNetwork && a.Server.Addr.Addr().Is6() {
			left = append(left, a.Server)
			continue
		}
		kept = append(kept, a)
		usable = usable || !failed
	}
	if !usable {
		return g.answers, nil
	}
	return kept, left
}

// readAnswer gives the records of an answer: none for no data and for no
// such name, and failed for a failure.
func readAnswer(a obs.Answer) (set []dnswire.Record, failure obs.Failure, failed bool) {
	failed = obs.Match(a.Result,
		func(r obs.Records) bool { set = r.Set; return false },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(f obs.Failure) bool { failure = f; return true })
	return set, failure, failed
}

// serverText gives "<addr> <host>", each "-" when not known.
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

// dropForeignZones removes the line of each name under the domain whose
// records check found it in another zone than the file expects: else the
// first check of a name in a subzone that the file does not declare would
// report a changed zone. A removed NS line moves the expected zone of the
// names under it, so this repeats until nothing changes; each round judges
// every check against the same file, so that the order of the observations
// does not change which lines go. A failed walk found no zone, so it says
// nothing about a cut, and the zone rule skips it too; the line of its set
// may rest on other answers, such as the parent's.
func dropForeignZones(file *File, observations []obs.Observation) []Skip {
	var skips []Skip
	for {
		var foreign []Skip
		for _, o := range observations {
			k := o.Key
			if k.Kind != obs.KindRecords || !k.Domain.Equal(file.Domain) || !k.Name.IsSubdomainOf(file.Domain) ||
				walkFailed(o) || o.Zone.Equal(file.Zone(k.Name)) {
				continue
			}
			if _, ok := file.Find(k.Name, k.Type); !ok || slices.ContainsFunc(foreign, sameSet(k.Name, k.Type)) {
				continue
			}
			zone := o.Zone.Lower().String()
			foreign = append(foreign, Skip{Name: k.Name, Type: k.Type, Why: fmt.Sprintf("lies in zone %s; add the pair %s NS", zone, zone)})
		}
		if len(foreign) == 0 {
			return skips
		}
		file.Expectations = slices.DeleteFunc(file.Expectations, func(e Expectation) bool {
			return slices.ContainsFunc(foreign, sameSet(e.Name, e.Type))
		})
		skips = append(skips, foreign...)
	}
}

func sameSet(name dnswire.Name, t dnswire.Type) func(Skip) bool {
	return func(s Skip) bool { return s.Type == t && s.Name.Equal(name) }
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

// dropDifferentGlue removes the address lines of each nameserver host whose
// glue at the parent zone those lines do not allow. The glue of a host with
// an address line is judged against its lines, so the new file would report
// it at its first check. Both lines of the host go, because glue of a type
// with no line differs too.
func dropDifferentGlue(file *File, observations []obs.Observation) []Skip {
	var skips []Skip
	for _, o := range observations {
		if o.Key.Kind != obs.KindDelegation {
			continue
		}
		for _, a := range o.Answers {
			glue := glueOf(a)
			for _, r := range glue {
				host, t := r.Name, r.Type()
				group := slices.DeleteFunc(slices.Clone(glue), func(x dnswire.Record) bool {
					return x.Type() != t || !x.Name.Equal(host)
				})
				line, ok := file.Find(host, t)
				if !hasAddressLine(file, host) || ok && line.Match(group) {
					continue
				}
				why := fmt.Sprintf("the parent zone gives other glue: %s gives %s %s", serverText(a.Server), t, SetText(t, group))
				if !ok {
					why = fmt.Sprintf("the %s address of the host could not be read, so its glue at the parent zone cannot be compared", t)
				}
				for _, at := range []dnswire.Type{dnswire.TypeA, dnswire.TypeAAAA} {
					i := slices.IndexFunc(file.Expectations, func(e Expectation) bool { return e.Type == at && e.Name.Equal(host) })
					if i >= 0 {
						file.Expectations = slices.Delete(file.Expectations, i, i+1)
						skips = append(skips, Skip{Name: host, Type: at, Why: why})
					}
				}
			}
		}
	}
	return skips
}

func hasAddressLine(file *File, host dnswire.Name) bool {
	_, a := file.Find(host, dnswire.TypeA)
	_, aaaa := file.Find(host, dnswire.TypeAAAA)
	return a || aaaa
}

// glueOf gives the glue of an answer; only an answer of records holds any.
func glueOf(a obs.Answer) []dnswire.Record {
	return obs.Match(a.Result,
		func(r obs.Records) []dnswire.Record { return r.Glue },
		func(obs.NoData) []dnswire.Record { return nil },
		func(obs.NoName) []dnswire.Record { return nil },
		func(obs.Failure) []dnswire.Record { return nil })
}
