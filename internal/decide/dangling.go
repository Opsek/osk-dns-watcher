package decide

import (
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Ref is one line of the file that points at a target.
type Ref struct {
	Rule Rule   // RuleAliasTarget, RuleNameServerHost or RuleMailTarget
	Text string // "<owner> <TYPE> <target>"; for an SPF include "<owner> TXT include:<target>"
}

// Target is a name that lines of the file point at, and the lines that do.
type Target struct {
	Name dnswire.Name
	Refs []Ref // in the order of the file, without duplicates
}

// Targets gives the names that the exact lines of f point at: alias targets,
// name server hosts, mail exchanges and SPF includes. Names in the zone of
// the domain itself are left out: such a name changes only through the zone,
// so it has a check only when a line of its own says what it holds.
func Targets(f *expect.File) []Target {
	if f == nil {
		return nil
	}
	var targets []Target
	index := map[string]int{} // Name.Key() to the place in targets
	add := func(name dnswire.Name, ref Ref) {
		if name.LabelCount() == 0 || (name.IsSubdomainOf(f.Domain) && f.Zone(name).Equal(f.Domain)) {
			return
		}
		i, seen := index[name.Key()]
		if !seen {
			targets = append(targets, Target{Name: name})
			i = len(targets) - 1
			index[name.Key()] = i
		}
		if !slices.Contains(targets[i].Refs, ref) {
			targets[i].Refs = append(targets[i].Refs, ref)
		}
	}
	for _, e := range f.Expectations {
		if e.Form != expect.FormSets {
			continue
		}
		owner := e.Name.Lower().String()
		line := func(r Rule, target dnswire.Name) Ref {
			return Ref{r, owner + " " + e.Type.String() + " " + target.Lower().String()}
		}
		for _, alt := range e.Sets {
			for _, d := range alt {
				switch d := d.(type) {
				case dnswire.CNAME:
					add(d.Target, line(RuleAliasTarget, d.Target))
				case dnswire.DNAME:
					add(d.Target, line(RuleAliasTarget, d.Target))
				case dnswire.NS:
					add(d.Host, line(RuleNameServerHost, d.Host))
				case dnswire.MX:
					add(d.Exchange, line(RuleMailTarget, d.Exchange))
				case dnswire.TXT:
					for _, n := range spfIncludes(d.Strings) {
						add(n, Ref{RuleMailTarget, owner + " TXT include:" + n.Lower().String()})
					}
				}
			}
		}
	}
	return targets
}

// spfIncludes gives the domains of the include terms of a TXT record, if the
// record is SPF. The text comes from DNS, so every term that is odd is skipped.
func spfIncludes(strs []string) []dnswire.Name {
	text := strings.Join(strs, "")
	const version = "v=spf1"
	if len(text) < len(version) || !strings.EqualFold(text[:len(version)], version) {
		return nil
	}
	text = text[len(version):]
	if text != "" && text[0] != ' ' {
		return nil
	}
	var names []dnswire.Name
	for _, term := range strings.Split(text, " ") {
		if term != "" && strings.ContainsRune("+-~?", rune(term[0])) {
			term = term[1:]
		}
		const include = "include:"
		if len(term) < len(include) || !strings.EqualFold(term[:len(include)], include) {
			continue
		}
		domain := strings.TrimSuffix(term[len(include):], ".")
		if domain == "" || strings.Contains(domain, "%") {
			continue
		}
		if n, err := dnswire.ParseName(domain + "."); err == nil {
			names = append(names, n)
		}
	}
	return names
}

// IsWildcardOwner reports whether name is a wildcard owner. Only a "*" that is
// the whole first label makes a wildcard (RFC 4592), so "a*.example" is an
// ordinary name. The root has no label and is not one.
func IsWildcardOwner(name dnswire.Name) bool {
	labels := name.Labels()
	return len(labels) > 0 && labels[0] == "*"
}

// Wildcards gives the zones under which the file says that no wildcard
// answers: it has the line "*.<zone> A none", and the check asks for A. A
// zone with no room for the random label of the check is left out.
func Wildcards(f *expect.File) []dnswire.Name {
	if f == nil {
		return nil
	}
	var zones []dnswire.Name
	for _, e := range f.Expectations {
		if !IsWildcardOwner(e.Name) || e.Type != dnswire.TypeA || e.Form != expect.FormNone {
			continue
		}
		zone := e.Name.Parent()
		if slices.ContainsFunc(zones, zone.Equal) || !hasRoomForLabel(zone) {
			continue
		}
		zones = append(zones, zone)
	}
	return zones
}

func hasRoomForLabel(zone dnswire.Name) bool {
	label := strings.Repeat("a", obs.WildcardLabel)
	_, err := dnswire.NameFromLabels(append([]string{label}, zone.Labels()...))
	return err == nil
}

// target gives the target that the check is the probe of, if f covers the
// check and the check asks for its address.
func target(f *expect.File, o obs.Observation) (Target, bool) {
	if !covers(f, o) || o.Key.Type != dnswire.TypeA {
		return Target{}, false
	}
	for _, t := range Targets(f) {
		if t.Name.Equal(o.Key.Name) {
			return t, true
		}
	}
	return Target{}, false
}

// targetFindings gives a finding for each of the three target rules that has
// a line pointing at t, the probed name, when a server says the name does not
// exist.
func targetFindings(o obs.Observation, t Target) []Finding {
	var seen []Seen
	for _, a := range o.Answers {
		if zone, ok := denial(a); ok {
			seen = append(seen, Seen{Answer: a, Text: noNameText(zone, t.Name)})
		}
	}
	if len(seen) == 0 {
		return nil
	}
	var found []Finding
	for _, r := range []Rule{RuleAliasTarget, RuleNameServerHost, RuleMailTarget} {
		var refs []string
		for _, ref := range t.Refs {
			if ref.Rule == r {
				refs = append(refs, ref.Text)
			}
		}
		if len(refs) > 0 {
			found = append(found, newFinding(r, o, strings.Join(refs, "; "), seen))
		}
	}
	return found
}

// denial says whether the answer is "no such name" and which zone says so:
// the owner of its SOA record. It is not always the zone whose servers were
// asked, so two answers of one run can name different zones.
func denial(a obs.Answer) (zone dnswire.Name, ok bool) {
	ok = obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(n obs.NoName) bool { zone = n.SOA.Name; return true },
		func(obs.Failure) bool { return false })
	return zone, ok
}

// noNameText says why the name does not exist. A zone that answers "no such
// name" for a name two or more labels below it holds no delegation above that
// name, so the domain just under the zone is not delegated: for a registry
// zone, not registered.
func noNameText(zone, name dnswire.Name) string {
	if !name.IsSubdomainOf(zone) || name.LabelCount() < zone.LabelCount()+2 {
		return "no such name"
	}
	labels := name.Labels()
	registered := labels[len(labels)-zone.LabelCount()-1:]
	// The labels came from a valid name, so they make one again.
	r, err := dnswire.NameFromLabels(registered)
	if err != nil {
		return "no such name"
	}
	return "no such name: " + zone.Lower().String() + " does not delegate " + r.Lower().String()
}

// wildcard gives a finding when a random name under a zone without a
// wildcard got records. The random name is not in the finding, so the finding
// does not change from one run to the next.
func wildcard(f *expect.File, o obs.Observation) []Finding {
	if !covers(f, o) || !slices.ContainsFunc(Wildcards(f), o.Key.Name.Equal) {
		return nil
	}
	var seen []Seen
	for _, a := range o.Answers {
		if set, ok := recordsOf(a); ok {
			seen = append(seen, Seen{Answer: a, Text: hideLabel(expect.SetText(dnswire.TypeA, set), a.Question)})
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return []Finding{newFinding(RuleWildcard, o, "none", seen)}
}

// hideLabel writes the first label of the question as "*" in text. A DNAME or
// a wildcard CNAME builds its answer from the name that was asked, so the
// random label can come back in the records; the text must be the same at
// every run, or each run would update the alert.
func hideLabel(text string, q dnswire.Question) string {
	labels := q.Name.Labels()
	if len(labels) == 0 {
		return text
	}
	label := labels[0]
	// The text is DNS presentation text, so ASCII: lower-casing keeps every
	// length, and an index in the copy is an index in the original.
	lowText, lowLabel := strings.ToLower(text), strings.ToLower(label)
	var b strings.Builder
	for {
		before, after, found := strings.Cut(lowText, lowLabel)
		if !found {
			break
		}
		b.WriteString(text[:len(before)] + "*")
		text, lowText = text[len(before)+len(label):], after
	}
	return b.String() + text
}

// recordsOf gives the set of an answer that holds records; no data, no such
// name and a failure are not records.
func recordsOf(a obs.Answer) (set []dnswire.Record, ok bool) {
	ok = obs.Match(a.Result,
		func(r obs.Records) bool { set = r.Set; return true },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(obs.Failure) bool { return false })
	return set, ok
}
