package expect

import (
	"cmp"
	"fmt"
	"slices"

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
// later answers are judged against; the one exception is an IPv6 address
// that this machine cannot reach (see reachable). Skips are sorted by Name,
// then Type.
func Snapshot(domain dnswire.Name, observations []obs.Observation) (*File, []Skip) {
	file := &File{Domain: domain}
	var skips []Skip
	for _, g := range groupSets(ofDomain(domain, observations)) {
		e, _, why := g.line()
		if why != "" {
			skips = append(skips, Skip{Name: g.name, Type: g.t, Why: why})
			continue
		}
		file.Expectations = append(file.Expectations, e)
	}
	skips = append(skips, dropForeignZones(file, observations)...)
	slices.SortFunc(file.Expectations, compareExpectations)
	slices.SortFunc(skips, func(a, b Skip) int {
		return cmp.Or(dnswire.Compare(a.Name, b.Name), cmp.Compare(a.Type, b.Type))
	})
	return file, skips
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
	}
	return dnswire.Name{}, 0, false
}

// line gives the line of the set and the servers that it leaves out, or why
// it gets none: the first reason of this order that applies, at the first
// answer that shows it.
func (g *setGroup) line() (Expectation, []obs.Server, string) {
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
	data := canonicalData(recordData(sets[0]))
	if len(data) > maxRecords {
		return Expectation{}, nil, fmt.Sprintf("more than %d records", maxRecords)
	}
	return Expectation{Name: g.name, Type: g.t, Form: FormSets, Sets: [][]dnswire.RData{data}}, left, ""
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
// names under it, so this repeats until nothing changes. A failed walk gives
// failures, and its set has no line to lose.
func dropForeignZones(file *File, observations []obs.Observation) []Skip {
	var skips []Skip
	for removed := true; removed; {
		removed = false
		for _, o := range observations {
			k := o.Key
			if k.Kind != obs.KindRecords || !k.Domain.Equal(file.Domain) || !k.Name.IsSubdomainOf(file.Domain) ||
				o.Zone.Equal(file.Zone(k.Name)) {
				continue
			}
			i := slices.IndexFunc(file.Expectations, func(e Expectation) bool {
				return e.Type == k.Type && e.Name.Equal(k.Name)
			})
			if i < 0 {
				continue
			}
			file.Expectations = slices.Delete(file.Expectations, i, i+1)
			zone := o.Zone.Lower().String()
			skips = append(skips, Skip{Name: k.Name, Type: k.Type, Why: fmt.Sprintf("lies in zone %s; add the pair %s NS", zone, zone)})
			removed = true
		}
	}
	return skips
}
