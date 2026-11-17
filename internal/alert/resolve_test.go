package alert

import (
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
)

// rsvChange is a finding of the identity of a with another Expected, and
// with other text in every field that the alert must not take. Its check is
// the same one in capitals.
func rsvChange(t testing.TB, a Alert, op decide.Op, expected string) decide.Change {
	f := alrNews(t, decide.SeverityLow)
	f.Rule, f.Expected = a.Rule, expected
	f.Check = alrKeys(t)[0][1]
	return decide.Change{Op: op, Finding: f, At: alrT0}
}

// The resolve shows the line that the servers match now, and nothing else of
// the alert changes.
func TestResolveTakesTheExpectedOfTheChange(t *testing.T) {
	for _, rule := range []decide.Rule{decide.RuleNameServers, decide.RuleRecordSet, decide.RuleDS, decide.RuleGlue} {
		t.Run(rule.String(), func(t *testing.T) {
			a := alrStored(t, decide.SeverityHigh, decide.SeverityCritical)
			a.Rule = rule
			c := rsvChange(t, a, decide.OpResolve, "10.53.0.99")
			in := Input{Open: []Alert{a}, Changes: []decide.Change{c}, LastClean: alrT0.Add(-time.Minute), Now: alrNow}
			out := Transition(in)
			b := a
			b.Open, b.Resolved, b.Expected = false, alrNow, "10.53.0.99"
			alrSame(t, "resolve", out.Events, []Event{{Kind: EventResolve, Alert: b, Was: decide.SeverityHigh, At: alrNow}})
			if !out.Clean {
				t.Errorf("not Clean after the only alert resolved")
			}
			if len(out.Events) == 1 && out.Events[0].Alert.Finding().Expected != "10.53.0.99" {
				t.Errorf("the alert for the store gives back Expected %q", out.Events[0].Alert.Finding().Expected)
			}
			if a.Expected != "10.53.0.81" || in.Open[0].Expected != "10.53.0.81" {
				t.Errorf("Transition changed the alert that it was given: %q", in.Open[0].Expected)
			}
		})
	}
}

func TestResolveWithTheSameExpectedChangesNothing(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityHigh)
	c := rsvChange(t, a, decide.OpResolve, a.Expected)
	out := Transition(Input{Open: []Alert{a}, Changes: []decide.Change{c}, Now: alrNow})
	b := a
	b.Open, b.Resolved = false, alrNow
	alrSame(t, "resolve", out.Events, []Event{{Kind: EventResolve, Alert: b, Was: decide.SeverityMedium, At: alrNow}})
}

// Each alert takes the Expected of its own change.
func TestResolvesOfTwoRulesTakeTheirOwnExpected(t *testing.T) {
	ns := alrStored(t, decide.SeverityCritical, decide.SeverityCritical)
	ns.Rule, ns.ID, ns.Expected = decide.RuleNameServers, 1, "ns-old"
	ds := alrStored(t, decide.SeverityHigh, decide.SeverityHigh)
	ds.Rule, ds.ID, ds.Expected = decide.RuleDS, 2, "ds-old"
	out := Transition(Input{Open: []Alert{ns, ds}, Now: alrNow, Changes: []decide.Change{
		rsvChange(t, ns, decide.OpResolve, "ns-new"), rsvChange(t, ds, decide.OpResolve, "ds-new")}})
	bn, bd := ns, ds
	bn.Open, bn.Resolved, bn.Expected = false, alrNow, "ns-new"
	bd.Open, bd.Resolved, bd.Expected = false, alrNow, "ds-new"
	alrSame(t, "resolves", out.Events, []Event{
		{Kind: EventResolve, Alert: bn, Was: decide.SeverityCritical, At: alrNow},
		{Kind: EventResolve, Alert: bd, Was: decide.SeverityHigh, At: alrNow}})
}

// The rule is about a resolve only: open and update take the finding as they
// always did.
func TestOpenAndUpdateStillTakeTheExpectedOfTheFinding(t *testing.T) {
	a := alrStored(t, decide.SeverityMedium, decide.SeverityMedium)
	_, lines := alrProof(t)
	for _, op := range []decide.Op{decide.OpUpdate, decide.OpOpen} {
		c := rsvChange(t, a, op, "10.53.0.99")
		out := Transition(Input{Open: []Alert{a}, Changes: []decide.Change{c}, Now: alrNow})
		b := a
		b.Severity, b.Expected, b.Value, b.Lines, b.Noticed = decide.SeverityLow, "10.53.0.99", c.Finding.Value, lines, alrNow
		alrSame(t, op.String(), out.Events, []Event{{Kind: EventUpdate, Alert: b, Was: decide.SeverityMedium, At: alrNow}})
	}
	c := rsvChange(t, a, decide.OpOpen, "10.53.0.99")
	out := Transition(Input{Changes: []decide.Change{c}, LastClean: alrT0, Now: alrNow})
	if len(out.Events) != 1 || out.Events[0].Kind != EventOpen || out.Events[0].Alert.Expected != "10.53.0.99" {
		t.Errorf("open of a new alert:%s", alrShow(out.Events))
	}
}
