package decide

import (
	"encoding/binary"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// caatAnswer is what a server sends for "corp.test. CAA": a message built with
// the encoder of dnswire and read again with Parse, as the code that reads a
// real answer does.
func caatAnswer(t *testing.T, set ...dnswire.CAA) obs.Result {
	t.Helper()
	owner := decName(t, "corp.test.")
	b := []byte{0x12, 0x34, 0x84, 0x00, 0, 1, 0, byte(len(set)), 0, 0, 0, 0}
	b = owner.AppendWire(b)
	b = binary.BigEndian.AppendUint16(b, uint16(dnswire.TypeCAA))
	b = binary.BigEndian.AppendUint16(b, uint16(dnswire.ClassINET))
	for _, d := range set {
		b = dnswire.AppendRecord(b, dnswire.Record{Name: owner, Class: dnswire.ClassINET, TTL: 300, Data: d})
	}
	m, err := dnswire.Parse(b)
	if err != nil {
		t.Fatalf("an answer with the set %v does not read: %v", set, err)
	}
	if len(m.Answer) != len(set) {
		t.Fatalf("the answer holds %d records, want %d", len(m.Answer), len(set))
	}
	return decAs(t, obs.RecordsResult(obs.Records{Set: m.Answer}), "records")
}

func caatObserve(t *testing.T, sets ...[]dnswire.CAA) obs.Observation {
	t.Helper()
	var answers []obs.Answer
	for i, s := range sets {
		answers = append(answers, decAnswer(t, caaServers[i].host, caaServers[i].addr, caatAnswer(t, s...)))
	}
	return decObservation(decRecordsKey(t, "corp.test.", "corp.test.", dnswire.TypeCAA), decName(t, "corp.test."), nil, answers...)
}

func TestCAAOddTagThroughTheCodec(t *testing.T) {
	file := decFile(t, "domain corp.test.", caaApex)
	fileSet := []dnswire.CAA{caaIssue("ca.test")}
	evil := caaIssue("evil.test")
	odd := func(flags uint8) dnswire.CAA { return caaC(flags, "bad-tag", "x") }
	const (
		evilText = `0 issue "evil.test"`
		fileText = `0 issue "ca.test"`
	)
	rows := []struct {
		name   string
		sets   [][]dnswire.CAA
		rule   Rule
		sev    Severity
		seen   []string // index of the answer, then its text
		values []string // the Value of the finding
	}{
		{
			name: "a new authority beside an odd tag at one server",
			sets: [][]dnswire.CAA{{evil, odd(0)}, fileSet},
			rule: RuleCAA, sev: SeverityHigh,
			seen:   []string{`0 ` + evilText + ` | 0 bad\045tag "x"`},
			values: []string{`10.53.0.11:53 ns1.corp.test. ` + evilText + ` | 0 bad\045tag "x"`},
		},
		{
			name: "the same with the critical flag on the odd record",
			sets: [][]dnswire.CAA{{evil, odd(128)}, fileSet},
			rule: RuleCAA, sev: SeverityHigh,
			seen:   []string{`0 ` + evilText + ` | 128 bad\045tag "x"`},
			values: []string{`10.53.0.11:53 ns1.corp.test. ` + evilText + ` | 128 bad\045tag "x"`},
		},
		{
			name: "an odd tag beside the file's set at both servers",
			sets: [][]dnswire.CAA{{caaIssue("ca.test"), odd(0)}, {caaIssue("ca.test"), odd(0)}},
			rule: RuleRecordSet, sev: SeverityMedium,
			seen: []string{`0 ` + fileText + ` | 0 bad\045tag "x"`, `1 ` + fileText + ` | 0 bad\045tag "x"`},
			values: []string{
				`10.53.0.11:53 ns1.corp.test. ` + fileText + ` | 0 bad\045tag "x"`,
				`10.53.0.12:53 ns2.corp.test. ` + fileText + ` | 0 bad\045tag "x"`,
			},
		},
		{
			name: "an odd critical tag beside the file's set at both servers",
			sets: [][]dnswire.CAA{{caaIssue("ca.test"), odd(128)}, {caaIssue("ca.test"), odd(128)}},
			rule: RuleRecordSet, sev: SeverityMedium,
			seen: []string{`0 ` + fileText + ` | 128 bad\045tag "x"`, `1 ` + fileText + ` | 128 bad\045tag "x"`},
			values: []string{
				`10.53.0.11:53 ns1.corp.test. ` + fileText + ` | 128 bad\045tag "x"`,
				`10.53.0.12:53 ns2.corp.test. ` + fileText + ` | 128 bad\045tag "x"`,
			},
		},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			o := caatObserve(t, r.sets...)
			got := Findings(file, o)
			want := decWant{r.rule, r.sev, decFormText(t, file, "corp.test.", dnswire.TypeCAA), dngSeenOf(t, o.Answers, r.seen...)}
			regCheck(t, got, o.Key, want)
			if len(got) != 1 {
				return
			}
			wantValue := ""
			for i, v := range r.values {
				if i > 0 {
					wantValue += "\n"
				}
				wantValue += v
			}
			if got[0].Value != wantValue {
				t.Errorf("Value = %q, want %q", got[0].Value, wantValue)
			}
		})
	}
}
