package decide

import (
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// recordFindings judges a records check against its line. A line of a mail
// policy gets the ways in which the observed record permits more than the
// line, as lines of Value after the server lines.
func recordFindings(f *expect.File, o obs.Observation, e expect.Expectation, ok bool) []Finding {
	r := recordRule(f, e, ok)
	differs := func(set []dnswire.Record) bool { return !e.Match(set) }
	if r == RuleMTASTS && f.Policy != nil && e.Form == expect.FormSets && expect.STSOn(e.Sets[0]) {
		// The policy check reads the policy itself, and the id changes with
		// every update of it, so the record here is judged only on or off.
		differs = func(set []dnswire.Record) bool { return !e.Match(set) && !expect.STSOn(rdataOf(set)) }
	}
	found := judgeIf(o, e, ok, r, differs)
	if len(found) > 0 && r != RuleRecordSet && r != RuleChallenge {
		found[0].Value = withWords(found[0], e)
	}
	return found
}

// withWords adds one "weaker <word>" line for each word of the sets that the
// servers gave, each set once. A server line starts with an address or "-",
// so no server line reads as a word line.
func withWords(f Finding, e expect.Expectation) string {
	var was []dnswire.RData
	if e.Form == expect.FormSets {
		was = e.Sets[0]
	}
	var texts []string
	var sets [][]dnswire.RData
	for _, s := range f.Seen {
		if slices.Contains(texts, s.Text) {
			continue
		}
		texts = append(texts, s.Text)
		set, _ := answerSet(s.Answer)
		sets = append(sets, rdataOf(set))
	}
	return wordLines(f.Value, expect.Weaker(expect.MailKindOf(e.Name), e.Name, was, sets...))
}

func wordLines(value string, words []string) string {
	for _, w := range words {
		value += "\nweaker " + w
	}
	return value
}

// policyLine is the mta-sts line of f when k is the policy check that it
// asks for.
func policyLine(f *expect.File, k obs.Key) *expect.STSPolicy {
	if f == nil || f.Policy == nil || k.Kind != obs.KindPolicy || !k.Domain.Equal(f.Domain) {
		return nil
	}
	if want, ok := obs.PolicyKey(f.Domain); !ok || !k.Name.Equal(want.Name) {
		return nil
	}
	return f.Policy
}

// policyFindings judges the policy file that a check fetched against the
// mta-sts line. Only the canonical text of the policy, or a fixed phrase, is
// ever shown: the body of the file is the host's to write.
func policyFindings(f *expect.File, o obs.Observation) []Finding {
	line := policyLine(f, o.Key)
	if line == nil {
		return nil
	}
	expected := line.String()
	var seen []Seen
	var lists [][]string
	for _, a := range o.Answers {
		set, ok := policyRecords(a)
		if !ok {
			continue
		}
		p, problem := expect.ParseSTSPolicy([]byte(policyBody(set)))
		text, words := p.String(), expect.STSPolicyWeaker(*line, p)
		if problem != "" {
			text = "mta-sts policy cannot be read: " + problem
			words = []string{"the policy file cannot be read: senders act as if there were no policy"}
		}
		if text != expected {
			seen = append(seen, Seen{Answer: a, Text: text})
			lists = append(lists, words)
		}
	}
	if len(seen) == 0 {
		return nil
	}
	found := newFinding(RuleMTASTS, o, expected, seen)
	found.Value = wordLines(found.Value, expect.MergeWords(lists...))
	return []Finding{found}
}

// policyRecords gives the records of an answer that holds some; a failure is
// unknown, and a negative answer is no policy file.
func policyRecords(a obs.Answer) (set []dnswire.Record, ok bool) {
	return set, obs.Match(a.Result,
		func(r obs.Records) bool { set = r.Set; return true },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(obs.Failure) bool { return false })
}

// policyBody joins the TXT strings of set: the fetch cuts the file into
// strings of 255 octets.
func policyBody(set []dnswire.Record) string {
	var b strings.Builder
	for _, r := range set {
		if t, ok := r.Data.(dnswire.TXT); ok {
			b.WriteString(strings.Join(t.Strings, ""))
		}
	}
	return b.String()
}
