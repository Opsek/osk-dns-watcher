package decide

import (
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// rsvOld is the text that an open finding carries after its line changed.
const rsvOld = "10.53.0.5 | a line that is gone"

var rsvNow = decT0.Add(time.Minute)

// The lines of the file for the three keys; a case replaces the one of its
// own key and leaves the others, so a resolve that read the wrong line shows.
const (
	rsvNSOther = "corp.test. NS ns1.dnshost.test."
	rsvAOther  = "www.corp.test. A 10.53.7.7"
)

var rsvDSOther = "corp.test. DS 99 13 2 " + strings.Repeat("CD", 32)

// rsvKeys: the parent checks of corp.test. and the A set of www.
func rsvKeys(t testing.TB) (ns, ds, a obs.Key) {
	return obs.DelegationKey(decName(t, "corp.test.")), obs.DSKey(decName(t, "corp.test.")),
		decRecordsKey(t, "corp.test.", "www.corp.test.", dnswire.TypeA)
}

// rsvFile is the file of corp.test. with the line of one key replaced; an
// empty line leaves that key without a line.
func rsvFile(t testing.TB, rule Rule, line string) *expect.File {
	lines := map[Rule]string{RuleNameServers: rsvNSOther, RuleDS: rsvDSOther, RuleRecordSet: rsvAOther}
	lines[rule] = line
	out := []string{"domain corp.test."}
	for _, r := range []Rule{RuleNameServers, RuleDS, RuleRecordSet} {
		if lines[r] != "" {
			out = append(out, lines[r])
		}
	}
	return decFile(t, out...)
}

// rsvObserve is one clean answer for the key of rule: the parent zone for
// nameservers and ds, a name server of the zone for the A set.
func rsvObserve(t testing.TB, key obs.Key, r obs.Result) obs.Observation {
	if key.Kind == obs.KindRecords {
		return decObservation(key, decName(t, "corp.test."), nil, decAnswer(t, "ns1.corp.test.", "10.53.0.11:53", r))
	}
	return decObservation(key, decName(t, "test."), nil, decAnswer(t, "a.ns.test.", "10.53.0.3:53", r))
}

// rsvStored is an open finding of rule with every field filled, so that a
// copy of the wrong field shows.
func rsvStored(t testing.TB, rule Rule, key obs.Key, expected string) Finding {
	old := decAnswer(t, "old.ns.test.", "10.53.9.9:53", decNoData(t, "test."))
	return Finding{Rule: rule, Severity: SeverityCritical, Check: key, Expected: expected,
		Seen: []Seen{{Answer: old, Text: "old seen"}}, Value: "10.53.9.9:53 old.ns.test. old seen"}
}

// rsvResolves are the resolve changes of changes.
func rsvResolves(changes []Change) []Change {
	var out []Change
	for _, c := range changes {
		if c.Op == OpResolve {
			out = append(out, c)
		}
	}
	return out
}

// rsvLineInForce is the finding as a resolve must carry it: Expected is the
// text of the line of the key in f, when f covers the domain and has one.
func rsvLineInForce(f *expect.File, key obs.Key, was Finding) Finding {
	if was.Rule != RuleNameServers && was.Rule != RuleRecordSet && was.Rule != RuleDS {
		return was
	}
	if f == nil || !key.Domain.Equal(f.Domain) {
		return was
	}
	if e, ok := f.Find(key.Name, key.Type); ok {
		was.Expected = e.FormText()
	}
	return was
}

type rsvCase struct {
	name string
	rule Rule
	key  obs.Key
	line string     // the line of the key in the file
	set  obs.Result // an answer that the line accepts
	text string     // the FormText that the resolve must carry
}

func rsvCases(t testing.TB) []rsvCase {
	ns, ds, a := rsvKeys(t)
	dsAnswer := decSet(t, "corp.test.", dnswire.TypeDS, regDS2)
	nsAnswer := decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test.")
	aAnswer := decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81", "10.53.0.82")
	none := decNoData(t, "corp.test.")
	return []rsvCase{
		{"nameservers exact", RuleNameServers, ns, "corp.test. NS ns2.corp.test. | ns1.corp.test.", nsAnswer, "ns1.corp.test. | ns2.corp.test."},
		{"nameservers like", RuleNameServers, ns, "corp.test. NS like *.corp.test.", nsAnswer, "like *.corp.test."},
		{"nameservers none", RuleNameServers, ns, "corp.test. NS none", none, "none"},
		{"nameservers alternatives", RuleNameServers, ns, "corp.test. NS ns1.other.test. || ns2.corp.test. | ns1.corp.test.", nsAnswer,
			"ns1.corp.test. | ns2.corp.test. || ns1.other.test."},
		{"record-set exact", RuleRecordSet, a, "www.corp.test. A 10.53.0.82 | 10.53.0.81", aAnswer, "10.53.0.81 | 10.53.0.82"},
		{"record-set in", RuleRecordSet, a, "www.corp.test. A in 10.53.0.0/24", aAnswer, "in 10.53.0.0/24"},
		{"record-set none", RuleRecordSet, a, "www.corp.test. A none", none, "none"},
		{"record-set alternatives", RuleRecordSet, a, "www.corp.test. A 10.53.0.99 || 10.53.0.82 | 10.53.0.81", aAnswer,
			"10.53.0.81 | 10.53.0.82 || 10.53.0.99"},
		{"ds exact", RuleDS, ds, "corp.test. DS " + regDS2, dsAnswer, regDS2},
		{"ds none", RuleDS, ds, "corp.test. DS none", none, "none"},
		{"ds alternatives", RuleDS, ds, "corp.test. DS " + regDS2 + " || " + decDS, dsAnswer, decDS + " || " + regDS2},
	}
}

func TestResolveCarriesTheLineInForce(t *testing.T) {
	for _, c := range rsvCases(t) {
		t.Run(c.name, func(t *testing.T) {
			f := rsvFile(t, c.rule, c.line)
			if got := decFormText(t, f, c.key.Name.String(), c.key.Type); got != c.text {
				t.Fatalf("the case is wrong: FormText of the line is %q, not %q", got, c.text)
			}
			o := rsvObserve(t, c.key, c.set)
			if g := Findings(f, o); len(g) != 0 {
				t.Fatalf("the case is wrong: the observation still differs:%s", decShow(g))
			}
			for _, stored := range []string{rsvOld, c.text} {
				was := rsvStored(t, c.rule, c.key, stored)
				want := was
				want.Expected = c.text
				got := Decide(Input{Expect: f, Open: []Finding{was}, Observation: o, Now: rsvNow})
				decSameChanges(t, got, []Change{{Op: OpResolve, Finding: want, At: rsvNow}})
			}
		})
	}
}

// Each rule of one check takes the line of the key for itself; glue and gone
// beside it keep what they carry.
func TestResolveOfSeveralRulesOfOneCheck(t *testing.T) {
	ns, _, _ := rsvKeys(t)
	f := rsvFile(t, RuleNameServers, "corp.test. NS ns1.corp.test. | ns2.corp.test.")
	o := rsvObserve(t, ns, decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test."))
	nsF := rsvStored(t, RuleNameServers, ns, rsvOld)
	glueF := rsvStored(t, RuleGlue, ns, "ns1.corp.test. A 10.53.0.11")
	goneF := rsvStored(t, RuleGone, ns, "")
	wantNS := nsF
	wantNS.Expected = "ns1.corp.test. | ns2.corp.test."
	got := Decide(Input{Expect: f, Open: []Finding{glueF, nsF, goneF}, Observation: o, Now: rsvNow})
	decSameChanges(t, got, []Change{{Op: OpResolve, Finding: glueF, At: rsvNow}, {Op: OpResolve, Finding: wantNS, At: rsvNow},
		{Op: OpResolve, Finding: goneF, At: rsvNow}})
}

// With no line of the key in force there is nothing newer to show.
func TestResolveKeepsTheTextWithoutALine(t *testing.T) {
	ns, ds, a := rsvKeys(t)
	other := decFile(t, "domain www.corp.test.", "www.corp.test. A 10.53.0.81")
	otherNS := decFile(t, "domain corp.test.", "sub.corp.test. NS ns1.sub.corp.test.")
	subNS := obs.DelegationKey(decName(t, "sub.corp.test."))
	any := decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81")
	for _, c := range []struct {
		name    string
		rule    Rule
		key     obs.Key
		f       *expect.File
		notCov  bool // the file covers the domain, so not-covered opens
		observe obs.Result
	}{
		{"nameservers, no line", RuleNameServers, ns, rsvFile(t, RuleNameServers, ""), true, any},
		{"ds, no line", RuleDS, ds, rsvFile(t, RuleDS, ""), true, any},
		{"record-set, no line", RuleRecordSet, a, rsvFile(t, RuleRecordSet, ""), true, any},
		{"nameservers, no file", RuleNameServers, ns, nil, false, any},
		{"ds, no file", RuleDS, ds, nil, false, any},
		{"record-set, no file", RuleRecordSet, a, nil, false, any},
		{"record-set, a file of another domain with a line for the name", RuleRecordSet, a, other, false, any},
		{"nameservers, a file of another domain with a line for the name", RuleNameServers, subNS, otherNS, false, any},
	} {
		t.Run(c.name, func(t *testing.T) {
			was := rsvStored(t, c.rule, c.key, rsvOld)
			o := rsvObserve(t, c.key, c.observe)
			changes := Decide(Input{Expect: c.f, Open: []Finding{was}, Observation: o, Now: rsvNow})
			decSameChanges(t, rsvResolves(changes), []Change{{Op: OpResolve, Finding: was, At: rsvNow}})
			if c.notCov && (len(changes) != 2 || changes[0].Op != OpOpen || changes[0].Finding.Rule != RuleNotCovered) {
				t.Errorf("want not-covered to open beside the resolve:%s", decShowChanges(changes))
			}
		})
	}
}

// Only nameservers, record-set and ds follow the line: the other rules carry
// what the open finding says, though the file has a line for the key.
func TestResolveOfOtherRulesIsUnchanged(t *testing.T) {
	ns, _, a := rsvKeys(t)
	fns := rsvFile(t, RuleNameServers, "corp.test. NS ns1.corp.test. | ns2.corp.test.")
	fa := rsvFile(t, RuleRecordSet, "www.corp.test. A 10.53.0.81")
	nsO := rsvObserve(t, ns, decSet(t, "corp.test.", dnswire.TypeNS, "ns1.corp.test.", "ns2.corp.test."))
	aO := rsvObserve(t, a, decSet(t, "www.corp.test.", dnswire.TypeA, "10.53.0.81"))
	for _, rule := range []Rule{RuleGlue, RuleGone, RuleZone, RuleNotCovered, RuleCheckFailing, RuleInvalidFile, RuleZoneChanged} {
		for _, k := range []struct {
			key obs.Key
			f   *expect.File
			o   obs.Observation
		}{{ns, fns, nsO}, {a, fa, aO}} {
			t.Run(rule.String()+" on "+k.key.Kind.String(), func(t *testing.T) {
				for _, stored := range []string{rsvOld, ""} {
					was := rsvStored(t, rule, k.key, stored)
					got := Decide(Input{Expect: k.f, Open: []Finding{was}, Observation: k.o, Now: rsvNow})
					decSameChanges(t, got, []Change{{Op: OpResolve, Finding: was, At: rsvNow}})
				}
			})
		}
	}
}

// The oracle that the other tests share must agree with the cases above.
func TestResolveOracleAgreesWithTheCases(t *testing.T) {
	for _, c := range rsvCases(t) {
		f := rsvFile(t, c.rule, c.line)
		was := rsvStored(t, c.rule, c.key, rsvOld)
		if got := rsvLineInForce(f, c.key, was); got.Expected != c.text {
			t.Errorf("%s: the oracle gives %q, want %q", c.name, got.Expected, c.text)
		}
	}
}
