package decide

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// emmRecordSetAlert is the open record-set alert of the finding that a mail
// rule gives for the same line and servers.
func emmRecordSetAlert(found Finding) Finding {
	found.Rule = RuleRecordSet
	found.Value = value(found.Seen)
	return found
}

// emmKinds are the lines of every mail rule, and the lines of a policy that
// the file says has no record.
func emmKinds() []emlKind {
	return append(slices.Clone(emlKinds),
		emlKind{word: "dmarc none", rule: RuleDMARC, owner: "_dmarc.corp.test.", line: `_dmarc.corp.test. TXT none`, now: emlTXT("v=DMARC1; p=none")},
		emlKind{word: "mta-sts none", rule: RuleMTASTS, owner: "_mta-sts.corp.test.", line: `_mta-sts.corp.test. TXT none`, now: emlTXT("v=STSv1; id=1")},
	)
}

// While the servers still give a set that differs from the line, an open
// record-set alert of a TXT line that gets a mail rule is neither resolved
// nor updated: the rule of the line opens its own alert.
func TestOpenRecordSetAlertOfAMailLineStays(t *testing.T) {
	for _, k := range emmKinds() {
		t.Run(k.word, func(t *testing.T) {
			f := emlFile(t, k.line)
			o := emlObserve(t, k.owner, dnswire.TypeTXT, k.now, k.now)
			found := emlOne(t, f, o)
			if found.Rule != k.rule {
				t.Fatalf("the line gives the rule %v, want %v", found.Rule, k.rule)
			}
			in := Input{Expect: f, Open: []Finding{emmRecordSetAlert(found)}, Observation: o, Now: decT0.Add(time.Minute)}
			decSameChanges(t, Decide(in), []Change{{Op: OpOpen, Finding: found, At: in.Now}})
		})
	}
}

// The record-set alert of a mail line is resolved once the servers give the
// set of the line again.
func TestOpenRecordSetAlertOfAMailLineResolves(t *testing.T) {
	for _, k := range emlKinds {
		t.Run(k.word, func(t *testing.T) {
			f := emlFile(t, k.line)
			old := emmRecordSetAlert(emlOne(t, f, emlObserve(t, k.owner, dnswire.TypeTXT, k.now)))
			o := emlObserve(t, k.owner, dnswire.TypeTXT, emlTXT(k.was), emlTXT(k.was))
			if got := Findings(f, o); len(got) != 0 {
				t.Fatalf("the servers match the line, yet:%s", decShow(got))
			}
			in := Input{Expect: f, Open: []Finding{old}, Observation: o, Now: decT0.Add(time.Minute)}
			decSameChanges(t, Decide(in), []Change{{Op: OpResolve, Finding: old, At: in.Now}})
		})
	}
}

// emmRecord is an SPF record with n ip4 terms, 10.0.<third>.<from> on.
func emmRecord(third, from, n int) string {
	var terms []string
	for i := 0; i < n; i++ {
		terms = append(terms, fmt.Sprintf("ip4:10.0.%d.%d", third, from+i))
	}
	return "v=spf1 " + strings.Join(terms, " ") + " -all"
}

func emmWords(third, from, n int) []string {
	var words []string
	for i := 0; i < n; i++ {
		words = append(words, fmt.Sprintf("ip4:10.0.%d.%d/32 gives pass in place of fail", third, from+i))
	}
	return words
}

// emmWordLines gives the words of the lines "weaker <word>" of a value.
func emmWordLines(value string) []string {
	var words []string
	for _, line := range strings.Split(value, "\n") {
		if w, ok := strings.CutPrefix(line, "weaker "); ok {
			words = append(words, w)
		}
	}
	return words
}

// The words of the sets that the servers gave are merged and capped once:
// "and <k> more" counts every word left out, also the words that the list of
// one answer alone would have held back.
func TestMergedWordsCountEveryWordLeftOut(t *testing.T) {
	f := emlFile(t, `corp.test. TXT "v=spf1 -all"`)
	for _, c := range []struct {
		name string
		sets []string
		want []string
	}{
		{"two answers of 14 words", []string{emmRecord(0, 1, 14), emmRecord(1, 1, 14)}, append(emmWords(0, 1, 11), "and 17 more")},
		{"words of two answers once", []string{emmRecord(0, 1, 14), emmRecord(0, 1, 14) + " x=1"}, append(emmWords(0, 1, 11), "and 3 more")},
		{"one answer of 14 words", []string{emmRecord(0, 1, 14)}, append(emmWords(0, 1, 11), "and 3 more")},
		{"12 words over two answers", []string{emmRecord(0, 1, 6), emmRecord(1, 1, 6)}, append(emmWords(0, 1, 6), emmWords(1, 1, 6)...)},
		{"13 words over two answers", []string{emmRecord(0, 1, 7), emmRecord(1, 1, 6)}, append(append(emmWords(0, 1, 7), emmWords(1, 1, 4)...), "and 2 more")},
	} {
		t.Run(c.name, func(t *testing.T) {
			var specs []string
			for _, s := range c.sets {
				specs = append(specs, emlTXT(s))
			}
			got := emlOne(t, f, emlObserve(t, "corp.test.", dnswire.TypeTXT, specs...))
			if words := emmWordLines(got.Value); !slices.Equal(words, c.want) {
				t.Errorf("words of the value are %q, want %q", words, c.want)
			}
		})
	}
}
