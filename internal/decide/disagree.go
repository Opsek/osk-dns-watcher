package decide

import (
	"slices"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// IsChallenge reports whether name is a name of the ACME DNS challenge at or
// under domain (RFC 8555 section 8.4). Its record, or an alias that hands it
// to another zone, lets whoever controls it obtain a certificate, so the
// challenge rule and the fast tier of the schedule must agree on the names.
func IsChallenge(domain, name dnswire.Name) bool {
	return expect.IsChallengeName(name) && name.IsSubdomainOf(domain)
}

// Disagree reports whether o is a records check in which two answers that
// are not failures give different sets. A failure is unknown, so it never
// counts as a difference.
func Disagree(o obs.Observation) bool {
	return o.Key.Kind == obs.KindRecords && len(distinctTexts(Sets(o))) > 1
}

// Sets gives every answer of o that is not a failure, in answer order, with
// its set as text ("none" for no data and for no such name). The schedule
// compares these texts between runs, so both sides must read an answer the
// same way.
func Sets(o obs.Observation) []Seen {
	return seenIf(o.Answers, anySet, setText(o.Key.Type))
}

// distinctTexts gives the texts of seen once each, sorted by octets.
func distinctTexts(seen []Seen) []string {
	texts := make([]string, len(seen))
	for i, s := range seen {
		texts[i] = s.Text
	}
	slices.Sort(texts)
	return slices.Compact(texts)
}

// disagree gives a finding when the servers have given different sets,
// each one steadily, for long enough (in.DisagreeLong). It stays out while a
// finding about the line already explains the run, because then some server
// differs from the file. Once it is open it lasts through runs in which the
// servers agree, until the schedule says the split is over (in.DisagreeOver):
// a split that comes and goes must not open and resolve again and again. A
// restart that forgets the series neither opens it twice nor ends it early.
// found holds the other findings of the run and open the open ones of the
// check.
func disagree(in Input, found, open []Finding) (Finding, bool) {
	o := in.Observation
	if o.Key.Kind != obs.KindRecords {
		return Finding{}, false
	}
	e, line := expectation(in.Expect, o.Key)
	explained := hasLineRule(found) || hasRule(found, RuleNotCovered) || hasRule(found, RuleCAA)
	opens := Disagree(o) && line && !explained && in.DisagreeLong
	stays := hasRule(open, RuleDisagree) && !in.DisagreeOver
	if !opens && !stays {
		return Finding{}, false
	}
	seen := Sets(o)
	expected := ""
	if line {
		expected = e.FormText()
	}
	// The value lists each distinct set once. Nothing in it is news for an
	// update: the answers of servers that rotate would change it at every run.
	return Finding{Rule: RuleDisagree, Severity: severity(RuleDisagree, o.Key.Type), Check: o.Key,
		Expected: expected, Seen: seen, Value: strings.Join(distinctTexts(seen), "\n")}, true
}
