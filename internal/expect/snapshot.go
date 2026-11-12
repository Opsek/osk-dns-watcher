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
// later answers are judged against. Skips are sorted by Name, then Type.
func Snapshot(domain dnswire.Name, observations []obs.Observation) (*File, []Skip) {
	file := &File{Domain: domain}
	var skips []Skip
	for _, g := range groupSets(domain, observations) {
		e, why := g.line()
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

// setGroup is every answer about one record set, in the order of the
// observations and of their answers.
type setGroup struct {
	name    dnswire.Name
	t       dnswire.Type
	answers []obs.Answer
}

func groupSets(domain dnswire.Name, observations []obs.Observation) []*setGroup {
	var groups []*setGroup
	byKey := map[setKey]*setGroup{}
	for _, o := range observations {
		name, t, ok := setOf(domain, o.Key)
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

// setOf gives the record set that an observation of the domain shows. The
// delegation and the apex records share the NS line of the domain.
func setOf(domain dnswire.Name, k obs.Key) (dnswire.Name, dnswire.Type, bool) {
	if !k.Domain.Equal(domain) {
		return dnswire.Name{}, 0, false
	}
	switch k.Kind {
	case obs.KindDelegation:
		return domain, dnswire.TypeNS, true
	case obs.KindDS:
		return domain, dnswire.TypeDS, true
	case obs.KindRecords:
		return k.Name, k.Type, true
	case obs.KindSerial:
		// The serial changes with every edit of the zone; no line holds it.
	}
	return dnswire.Name{}, 0, false
}

// line gives the line of the set, or why it gets none: the first reason of
// this order that applies, at the first answer that shows it.
func (g *setGroup) line() (Expectation, string) {
	sets := make([][]dnswire.Record, len(g.answers))
	for i, a := range g.answers {
		set, failure, failed := readAnswer(a)
		if failed {
			return Expectation{}, fmt.Sprintf("%s gave no answer: %s", serverText(a.Server), failure.Reason)
		}
		sets[i] = set
	}
	for i, set := range sets {
		for _, r := range set {
			if r.Type() != g.t {
				return Expectation{}, fmt.Sprintf("%s answers with a %s record; snapshot %s %s instead",
					serverText(g.answers[i].Server), r.Type(), g.name.Lower(), r.Type())
			}
		}
	}
	first := SetText(g.t, sets[0])
	for i, set := range sets {
		if text := SetText(g.t, set); text != first {
			return Expectation{}, fmt.Sprintf("servers disagree: %s gives %s; %s gives %s",
				serverText(g.answers[0].Server), first, serverText(g.answers[i].Server), text)
		}
	}
	if len(sets[0]) == 0 {
		return Expectation{Name: g.name, Type: g.t, Form: FormNone}, ""
	}
	data := canonicalData(recordData(sets[0]))
	if len(data) > maxRecords {
		return Expectation{}, fmt.Sprintf("more than %d records", maxRecords)
	}
	return Expectation{Name: g.name, Type: g.t, Form: FormSets, Sets: [][]dnswire.RData{data}}, ""
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
