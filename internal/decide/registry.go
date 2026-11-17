package decide

import (
	"cmp"
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// covers reports whether the file is about the domain of the check. Without
// a line to compare, the rules below have nothing to say.
func covers(f *expect.File, o obs.Observation) bool {
	return f != nil && o.Key.Domain.Equal(f.Domain)
}

// glue gives a finding when a parent gives, for a nameserver host that the
// file gives address lines for, glue that those lines do not allow. A host
// with no address line is not compared, and absent glue is not compared:
// there is no address to swap. Glue of a type with no line differs, because
// added AAAA glue sends traffic to a new place.
func glue(f *expect.File, o obs.Observation) []Finding {
	if !covers(f, o) {
		return nil
	}
	var seen []Seen
	type part struct {
		host dnswire.Name
		t    dnswire.Type
		text string
	}
	var expected []part
	for _, a := range o.Answers {
		for _, g := range glueGroups(glueOf(a)) {
			host, t := g[0].Name, g[0].Type()
			if !watched(f, host) {
				continue
			}
			line, has := f.Find(host, t)
			if has && line.Match(g) {
				continue
			}
			text := host.Lower().String() + " " + t.String()
			seen = append(seen, Seen{Answer: a, Text: text + " " + expect.SetText(t, g)})
			if has {
				text = line.String()
			} else {
				text += " (no line)"
			}
			if !slices.ContainsFunc(expected, func(p part) bool { return p.text == text }) {
				expected = append(expected, part{host, t, text})
			}
		}
	}
	if len(seen) == 0 {
		return nil
	}
	// Sorted, so that the order of the answers does not make the text change.
	slices.SortFunc(expected, func(a, b part) int {
		return cmp.Or(dnswire.Compare(a.host, b.host), cmp.Compare(a.t, b.t))
	})
	texts := make([]string, len(expected))
	for i, p := range expected {
		texts[i] = p.text
	}
	return []Finding{newFinding(RuleGlue, o, strings.Join(texts, "; "), seen)}
}

// glueOf is the glue of an answer; a failure and a negative answer have none.
func glueOf(a obs.Answer) []dnswire.Record {
	return obs.Match(a.Result,
		func(r obs.Records) []dnswire.Record { return r.Glue },
		func(obs.NoData) []dnswire.Record { return nil },
		func(obs.NoName) []dnswire.Record { return nil },
		func(obs.Failure) []dnswire.Record { return nil })
}

// glueGroups splits glue into one group for each owner and type, ordered by
// owner and then type, so that the order does not depend on the message.
func glueGroups(glue []dnswire.Record) [][]dnswire.Record {
	sorted := slices.Clone(glue)
	slices.SortStableFunc(sorted, func(a, b dnswire.Record) int {
		return cmp.Or(dnswire.Compare(a.Name, b.Name), cmp.Compare(a.Type(), b.Type()))
	})
	var groups [][]dnswire.Record
	for _, r := range sorted {
		if n := len(groups); n > 0 {
			last := groups[n-1][0]
			if last.Name.Equal(r.Name) && last.Type() == r.Type() {
				groups[n-1] = append(groups[n-1], r)
				continue
			}
		}
		groups = append(groups, []dnswire.Record{r})
	}
	return groups
}

// watched reports whether the file has an address line for host.
func watched(f *expect.File, host dnswire.Name) bool {
	_, a := f.Find(host, dnswire.TypeA)
	_, aaaa := f.Find(host, dnswire.TypeAAAA)
	return a || aaaa
}

// gone gives a finding when the parent says that the domain does not exist.
// The domain line is the expectation, so none is needed.
func gone(f *expect.File, o obs.Observation) []Finding {
	if !covers(f, o) {
		return nil
	}
	var seen []Seen
	for _, a := range o.Answers {
		if noName(a) {
			seen = append(seen, Seen{Answer: a, Text: "no such name"})
		}
	}
	if len(seen) == 0 {
		return nil
	}
	return []Finding{newFinding(RuleGone, o, "", seen)}
}

func noName(a obs.Answer) bool {
	return obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return true },
		func(obs.Failure) bool { return false })
}

// raiseDS makes the ds findings critical when the name servers alert is open:
// a new DS next to new name servers is a takeover. It never lowers an alert
// that is open, because the DS is still wrong and a lower severity would send
// a notice when nothing changed.
func raiseDS(found, open []Finding, nameServersOpen bool) {
	i := slices.IndexFunc(open, func(f Finding) bool { return f.Rule == RuleDS })
	if !nameServersOpen && (i < 0 || open[i].Severity != SeverityCritical) {
		return
	}
	for i := range found {
		if found[i].Rule == RuleDS {
			found[i].Severity = SeverityCritical
		}
	}
}
