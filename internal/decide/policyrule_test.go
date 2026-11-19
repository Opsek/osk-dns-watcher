package decide

import (
	"fmt"
	"math/rand/v2"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

const (
	plrHost = "mta-sts.corp.test."
	plrLine = "mta-sts enforce 604800 mail.corp.test."
	// plrNoRead is the one word of a policy file that does not read.
	plrNoRead = "the policy file cannot be read: senders act as if there were no policy"
)

// plrAddrs are the addresses that a fetch can come from.
var plrAddrs = []string{"192.0.2.10:443", "192.0.2.11:443", "192.0.2.12:443", "192.0.2.13:443"}

// plrDoc is a policy file that reads, with LF line ends.
func plrDoc(mode, maxAge string, mx ...string) string {
	body := "version: STSv1\nmode: " + mode + "\nmax_age: " + maxAge + "\n"
	for _, m := range mx {
		body += "mx: " + m + "\n"
	}
	return body
}

// plrResult is what a fetch gives for a body: one TXT record whose strings
// cut the body every 255 octets, one empty string for an empty body.
func plrResult(t testing.TB, body string) obs.Result {
	t.Helper()
	var strs []string
	for len(body) > 255 {
		strs = append(strs, body[:255])
		body = body[255:]
	}
	strs = append(strs, body)
	rec := dnswire.Record{Name: decName(t, plrHost), Class: dnswire.ClassINET, Data: dnswire.TXT{Strings: strs}}
	return decAs(t, obs.RecordsResult(obs.Records{Set: []dnswire.Record{rec}}), "records")
}

// plrAnswer is the answer at plrAddrs[i]: the body, or a failure when the
// spec starts with "fail ".
func plrAnswer(t testing.TB, i int, spec string) obs.Answer {
	t.Helper()
	if reason, ok := strings.CutPrefix(spec, "fail "); ok {
		return decAnswer(t, plrHost, plrAddrs[i], decFailure(plrReason(t, reason)))
	}
	return decAnswer(t, plrHost, plrAddrs[i], plrResult(t, spec))
}

func plrReason(t testing.TB, word string) obs.Reason {
	t.Helper()
	for _, r := range []obs.Reason{obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonBadAnswer, obs.ReasonNotPermitted} {
		if r.String() == word {
			return r
		}
	}
	t.Fatalf("no reason %q", word)
	return 0
}

// plrObserve is a run of the policy check of corp.test. with one answer for
// each spec.
func plrObserve(t testing.TB, specs ...string) obs.Observation {
	t.Helper()
	var answers []obs.Answer
	for i, s := range specs {
		answers = append(answers, plrAnswer(t, i, s))
	}
	return plrWith(t, answers...)
}

func plrWith(t testing.TB, answers ...obs.Answer) obs.Observation {
	t.Helper()
	d := decName(t, "corp.test.")
	key, ok := obs.PolicyKey(d)
	if !ok {
		t.Fatal("no policy key for corp.test.")
	}
	return decObservation(key, d, nil, answers...)
}

func plrFile(t testing.TB, lines ...string) *expect.File {
	t.Helper()
	return emlFile(t, lines...)
}

// plrSeen is one answer that a finding shows: its place in the observation
// and its text.
type plrSeen struct {
	at   int
	text string
}

// plrValue is the Value of a policy finding: a server line for each seen
// answer, then a "weaker" line for each word.
func plrValue(o obs.Observation, seen []plrSeen, words ...string) string {
	var lines []string
	for _, s := range seen {
		lines = append(lines, o.Answers[s.at].Server.Addr.String()+" "+plrHost+" "+s.text)
	}
	for _, w := range words {
		lines = append(lines, "weaker "+w)
	}
	return strings.Join(lines, "\n")
}

// plrCheck states one policy finding in every field.
func plrCheck(t *testing.T, got Finding, o obs.Observation, expected string, seen []plrSeen, words []string) {
	t.Helper()
	if got.Rule != RuleMTASTS || got.Severity != SeverityMedium || got.Expected != expected {
		t.Errorf("finding is %v %v expected %q, want mta-sts medium expected %q", got.Rule, got.Severity, got.Expected, expected)
	}
	if got.Check.String() != o.Key.String() {
		t.Errorf("finding has check %v, want %v", got.Check, o.Key)
	}
	if len(got.Seen) != len(seen) {
		t.Errorf("finding shows %d answers, want %d:%s", len(got.Seen), len(seen), decShow([]Finding{got}))
	} else {
		for i, s := range seen {
			if !reflect.DeepEqual(got.Seen[i].Answer, o.Answers[s.at]) || got.Seen[i].Text != s.text {
				t.Errorf("seen %d is %v %q, want answer %d %q", i, got.Seen[i].Answer.Server, got.Seen[i].Text, s.at, s.text)
			}
		}
	}
	if want := plrValue(o, seen, words...); got.Value != want {
		t.Errorf("value is %q, want %q", got.Value, want)
	}
}

// plrMany is the words of a policy that lets in twelve new hosts on top of a
// lower mode and a lower max_age.
func plrMany() (body, text string, words []string) {
	var mx, names []string
	words = []string{
		"mode testing in place of enforce: senders deliver mail even when the TLS check fails",
		"max_age 86400 in place of 604800: senders keep the policy for less time",
	}
	for i := 1; i <= 12; i++ {
		h := fmt.Sprintf("m%02d.evil.test", i)
		mx = append(mx, h)
		names = append(names, h+".")
		if i <= 9 {
			words = append(words, "mx "+h+". is not allowed by the file")
		}
	}
	words = append(words, "and 3 more")
	return plrDoc("testing", "86400", append([]string{"mail.corp.test"}, mx...)...),
		"mta-sts testing 86400 mail.corp.test. " + strings.Join(names, " "), words
}

// Each row: a policy line, what the servers fetched and what is right.
func TestPlrPolicyFindingRows(t *testing.T) {
	manyBody, manyText, manyWords := plrMany()
	const modeTesting = "mode testing in place of enforce: senders deliver mail even when the TLS check fails"
	const modeNone = "mode none in place of enforce: senders act as if there were no policy"
	const wasEnforce = "mta-sts enforce 604800 mail.corp.test."
	rows := []struct {
		name  string
		right string // the correct behaviour
		line  string
		specs []string
		seen  []plrSeen // nil: no finding
		words []string
	}{
		{"equal", "a policy equal to the line gives no finding", plrLine,
			[]string{plrDoc("enforce", "604800", "mail.corp.test.")}, nil, nil},
		{"equal written otherwise", "CRLF, another line order, an unknown key and another case and dot of mx read as the same policy: no finding", plrLine,
			[]string{"max_age: 604800\r\nfoo: bar\r\nmode: enforce\r\nmx: Mail.Corp.Test.\r\nversion: STSv1\r\n"}, nil, nil},
		{"equal on two servers", "two policies equal to the line give no finding", plrLine,
			[]string{plrDoc("enforce", "604800", "mail.corp.test"), plrDoc("enforce", "604800", "mail.corp.test")}, nil, nil},

		{"stricter mode", "a policy that differs but permits no more is shown with its text and no weaker line", "mta-sts testing 604800 mail.corp.test.",
			[]string{plrDoc("enforce", "604800", "mail.corp.test")}, []plrSeen{{0, wasEnforce}}, nil},
		{"fewer mx", "fewer hosts permit less: shown, no weaker line", "mta-sts enforce 604800 mail.corp.test. other.corp.test.",
			[]string{plrDoc("enforce", "604800", "mail.corp.test")}, []plrSeen{{0, wasEnforce}}, nil},
		{"longer max_age", "a longer max_age permits no more: shown, no weaker line", plrLine,
			[]string{plrDoc("enforce", "1209600", "mail.corp.test")}, []plrSeen{{0, "mta-sts enforce 1209600 mail.corp.test."}}, nil},

		{"enforce to testing", "one word for the lower mode", plrLine,
			[]string{plrDoc("testing", "604800", "mail.corp.test")},
			[]plrSeen{{0, "mta-sts testing 604800 mail.corp.test."}}, []string{modeTesting}},
		{"enforce to none", "one word for mode none, naming enforce", plrLine,
			[]string{plrDoc("none", "604800")},
			[]plrSeen{{0, "mta-sts none 604800"}}, []string{modeNone}},
		{"enforce to none keeping mx", "mode none with a listed host is still mode none", plrLine,
			[]string{plrDoc("none", "604800", "mail.corp.test")},
			[]plrSeen{{0, "mta-sts none 604800 mail.corp.test."}}, []string{modeNone}},
		{"testing to none", "mode none names testing as the old mode", "mta-sts testing 604800 mail.corp.test.",
			[]string{plrDoc("none", "604800")},
			[]plrSeen{{0, "mta-sts none 604800"}}, []string{"mode none in place of testing: senders act as if there were no policy"}},
		{"new mx", "one word for the host that the line does not list", plrLine,
			[]string{plrDoc("enforce", "604800", "mail.corp.test", "evil.test")},
			[]plrSeen{{0, "mta-sts enforce 604800 mail.corp.test. evil.test."}}, []string{"mx evil.test. is not allowed by the file"}},
		{"wider mx", "a wildcard covers more than a name: one word", plrLine,
			[]string{plrDoc("enforce", "604800", "*.corp.test")},
			[]plrSeen{{0, "mta-sts enforce 604800 *.corp.test."}}, []string{"mx *.corp.test. is not allowed by the file"}},
		{"deeper than the wildcard", "a wildcard matches one label: a deeper name is new", "mta-sts enforce 604800 *.corp.test.",
			[]string{plrDoc("enforce", "604800", "a.b.corp.test")},
			[]plrSeen{{0, "mta-sts enforce 604800 a.b.corp.test."}}, []string{"mx a.b.corp.test. is not allowed by the file"}},
		{"shorter max_age", "one word with both values", plrLine,
			[]string{plrDoc("enforce", "86400", "mail.corp.test")},
			[]plrSeen{{0, "mta-sts enforce 86400 mail.corp.test."}}, []string{"max_age 86400 in place of 604800: senders keep the policy for less time"}},
		{"max_age zero", "zero is the shortest max_age", plrLine,
			[]string{plrDoc("enforce", "0", "mail.corp.test")},
			[]plrSeen{{0, "mta-sts enforce 0 mail.corp.test."}}, []string{"max_age 0 in place of 604800: senders keep the policy for less time"}},

		{"no colon", "a policy that does not parse shows the fixed text and the one word", plrLine,
			[]string{"garbage\n"}, []plrSeen{{0, "mta-sts policy cannot be read: a line without a colon"}}, []string{plrNoRead}},
		{"empty body", "an empty file does not parse", plrLine,
			[]string{""}, []plrSeen{{0, "mta-sts policy cannot be read: no version line"}}, []string{plrNoRead}},
		{"wrong version", "a wrong version does not parse", plrLine,
			[]string{"version: STSv2\nmode: enforce\nmax_age: 604800\nmx: mail.corp.test\n"},
			[]plrSeen{{0, "mta-sts policy cannot be read: the version is not STSv1"}}, []string{plrNoRead}},
		{"control octet", "a line that is not printable does not parse", plrLine,
			[]string{"version: STSv1\x01\n"},
			[]plrSeen{{0, "mta-sts policy cannot be read: a line that is not printable ASCII"}}, []string{plrNoRead}},

		{"several weakenings", "the words come in the order mode, max_age, then each new host in the order of the policy", plrLine,
			[]string{plrDoc("testing", "86400", "mail.corp.test", "a.evil.test", "b.evil.test")},
			[]plrSeen{{0, "mta-sts testing 86400 mail.corp.test. a.evil.test. b.evil.test."}},
			[]string{modeTesting, "max_age 86400 in place of 604800: senders keep the policy for less time",
				"mx a.evil.test. is not allowed by the file", "mx b.evil.test. is not allowed by the file"}},
		{"more words than the cap", "twelve words at most: the first eleven, then the count of the rest", plrLine,
			[]string{manyBody}, []plrSeen{{0, manyText}}, manyWords},

		{"two different weaker policies", "one Seen for each answer, the words of both in the order of the answers", plrLine,
			[]string{plrDoc("testing", "604800", "mail.corp.test"), plrDoc("none", "604800")},
			[]plrSeen{{0, "mta-sts testing 604800 mail.corp.test."}, {1, "mta-sts none 604800"}}, []string{modeTesting, modeNone}},
		{"two equal weaker policies", "both answers are seen and each word is given once", plrLine,
			[]string{plrDoc("testing", "604800", "mail.corp.test"), plrDoc("testing", "604800", "mail.corp.test")},
			[]plrSeen{{0, "mta-sts testing 604800 mail.corp.test."}, {1, "mta-sts testing 604800 mail.corp.test."}}, []string{modeTesting}},
		{"one equal, one weaker", "only the weaker answer is seen", plrLine,
			[]string{plrDoc("enforce", "604800", "mail.corp.test"), plrDoc("testing", "604800", "mail.corp.test")},
			[]plrSeen{{1, "mta-sts testing 604800 mail.corp.test."}}, []string{modeTesting}},
		{"one failed, one weaker", "a failed fetch is unknown and is not seen", plrLine,
			[]string{"fail timeout", plrDoc("testing", "604800", "mail.corp.test")},
			[]plrSeen{{1, "mta-sts testing 604800 mail.corp.test."}}, []string{modeTesting}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			f := plrFile(t, r.line)
			o := plrObserve(t, r.specs...)
			got := Findings(f, o)
			if r.seen == nil {
				if len(got) != 0 {
					t.Fatalf("%s, but got%s", r.right, decShow(got))
				}
				return
			}
			if len(got) != 1 {
				t.Fatalf("%s, but got%s", r.right, decShow(got))
			}
			plrCheck(t, got[0], o, f.Policy.String(), r.seen, r.words)
		})
	}
}

// A fetch that fails is unknown: no finding, never seen, and it does not end
// an open alert. A later fetch equal to the line ends it.
func TestPlrFailedFetchIsUnknown(t *testing.T) {
	f := plrFile(t, plrLine)
	weak := plrObserve(t, plrDoc("testing", "604800", "mail.corp.test"))
	now := decT0.Add(time.Minute)
	open := emlOne(t, f, weak)
	for _, reason := range []obs.Reason{obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonBadAnswer, obs.ReasonNotPermitted} {
		for _, addr := range []string{"", plrAddrs[0]} {
			name := fmt.Sprintf("%s, address %q", reason, addr)
			t.Run(name, func(t *testing.T) {
				o := plrWith(t, decAnswer(t, plrHost, addr, decFailure(reason)))
				if got := Findings(f, o); len(got) != 0 {
					t.Fatalf("a failed fetch gives no finding, but got%s", decShow(got))
				}
				if got := Decide(Input{Expect: f, Open: []Finding{open}, Observation: o, Now: now}); len(got) != 0 {
					t.Fatalf("a failed fetch leaves the open alert as it is, but got%s", decShowChanges(got))
				}
				if got := Decide(Input{Expect: f, Observation: o, Now: now}); len(got) != 0 {
					t.Fatalf("a failed fetch opens nothing, but got%s", decShowChanges(got))
				}
			})
		}
	}
	good := plrObserve(t, plrDoc("enforce", "604800", "mail.corp.test"))
	want := open
	want.Expected = plrLine
	decSameChanges(t, Decide(Input{Expect: f, Open: []Finding{open}, Observation: good, Now: now}),
		[]Change{{Op: OpResolve, Finding: want, At: now}})
}

// An open policy alert updates when the policy text changes to another weaker
// text, and not when only the address that answered differs.
func TestPlrOpenAlertUpdates(t *testing.T) {
	f := plrFile(t, plrLine)
	now := decT0.Add(time.Minute)
	testing1 := plrDoc("testing", "604800", "mail.corp.test")
	first := plrObserve(t, testing1)
	open := emlOne(t, f, first)
	at := func(i int, spec string) obs.Observation { return plrWith(t, plrAnswer(t, i, spec)) }
	rows := []struct {
		name  string
		right string
		o     obs.Observation
		op    Op // 0: no change
	}{
		{"same text, same address", "nothing new: no change", first, 0},
		{"same text, another address", "the address is not part of the comparison: no change", at(1, testing1), 0},
		{"other weaker text", "a new text and new words: update", at(0, plrDoc("none", "604800")), OpUpdate},
		{"other weaker text, another address", "a new text: update", at(1, plrDoc("enforce", "86400", "mail.corp.test")), OpUpdate},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			got := Decide(Input{Expect: f, Open: []Finding{open}, Observation: r.o, Now: now})
			if r.op == 0 {
				if len(got) != 0 {
					t.Fatalf("%s, but got%s", r.right, decShowChanges(got))
				}
				return
			}
			if len(got) != 1 || got[0].Op != r.op || got[0].Finding.Rule != RuleMTASTS {
				t.Fatalf("%s, but got%s", r.right, decShowChanges(got))
			}
			if want := Findings(f, r.o); len(want) != 1 || !reflect.DeepEqual(got[0].Finding, want[0]) {
				t.Fatalf("the update carries the finding of the run, got%s", decShowChanges(got))
			}
		})
	}
}

// The policy alert opens once, and resolves with the line that is in force.
func TestPlrOpenAndResolve(t *testing.T) {
	f := plrFile(t, plrLine)
	now := decT0.Add(time.Minute)
	weak := plrObserve(t, plrDoc("testing", "604800", "mail.corp.test"))
	got := Decide(Input{Expect: f, Observation: weak, Now: now})
	if len(got) != 1 || got[0].Op != OpOpen || got[0].Finding.Rule != RuleMTASTS {
		t.Fatalf("a weaker policy opens one mta-sts alert, got%s", decShowChanges(got))
	}
	open := got[0].Finding

	t.Run("the file now holds the weaker policy", func(t *testing.T) {
		g := plrFile(t, "mta-sts testing 604800 mail.corp.test.")
		want := open
		want.Expected = "mta-sts testing 604800 mail.corp.test."
		decSameChanges(t, Decide(Input{Expect: g, Open: []Finding{open}, Observation: weak, Now: now}),
			[]Change{{Op: OpResolve, Finding: want, At: now}})
	})
	t.Run("the file lost the line", func(t *testing.T) {
		g := plrFile(t)
		decSameChanges(t, Decide(Input{Expect: g, Open: []Finding{open}, Observation: weak, Now: now}),
			[]Change{{Op: OpResolve, Finding: open, At: now}})
	})
	t.Run("an alert of another check is not read", func(t *testing.T) {
		other := open
		other.Check = decRecordsKey(t, "corp.test.", "_mta-sts.corp.test.", dnswire.TypeTXT)
		if got := Decide(Input{Expect: f, Open: []Finding{other}, Observation: weak, Now: now}); len(got) != 1 || got[0].Op != OpOpen {
			t.Fatalf("want one open, got%s", decShowChanges(got))
		}
	})
}

// A policy check of another domain or name gives nothing.
func TestPlrOnlyTheKeyOfTheLineIsJudged(t *testing.T) {
	f := plrFile(t, plrLine)
	good := plrObserve(t, plrDoc("none", "1"))
	d := decName(t, "corp.test.")
	for name, key := range map[string]obs.Key{
		"another name":   {Kind: obs.KindPolicy, Domain: d, Name: decName(t, "www.corp.test."), Type: dnswire.TypeTXT},
		"another domain": {Kind: obs.KindPolicy, Domain: decName(t, "other.test."), Name: decName(t, "mta-sts.other.test."), Type: dnswire.TypeTXT},
	} {
		o := good
		o.Key = key
		if got := Findings(f, o); len(got) != 0 {
			t.Errorf("%s: want no finding, got%s", name, decShow(got))
		}
	}
	if got := Findings(plrFile(t), good); len(got) != 0 {
		t.Errorf("a file with no mta-sts line: want no finding, got%s", decShow(got))
	}
}

// ---- the record at _mta-sts ----

const plrTXTLine = `_mta-sts.corp.test. TXT "v=STSv1; id=1"`

func plrSame(t *testing.T, what string, got, want []Finding) {
	t.Helper()
	if !reflect.DeepEqual(got, want) {
		t.Errorf("%s:\n got%s\nwant%s", what, decShow(got), decShow(want))
	}
}

// With an mta-sts line, the record at _mta-sts is judged on or off. A set
// that reads as on never differs, whatever its id; a set that reads as off
// gives the finding that it gives with no mta-sts line.
func TestPlrRecordIsJudgedOnOrOff(t *testing.T) {
	const owner = "_mta-sts.corp.test."
	rows := []struct {
		name  string
		right string
		specs []string
		on    bool
	}{
		{"another id", "an id change is no finding", []string{emlTXT("v=STSv1; id=2")}, true},
		{"extension field", "extension fields are not compared", []string{emlTXT("v=STSv1; id=2; foo=bar")}, true},
		{"another TXT record in the set", "other records of the set are not compared", []string{emlTXT("v=STSv1; id=2") + "\n" + emlTXT("hello")}, true},
		{"two servers, ids differ", "each server's id is free", []string{emlTXT("v=STSv1; id=2"), emlTXT("v=STSv1; id=3")}, true},
		{"the same record", "the record of the line", []string{emlTXT("v=STSv1; id=1")}, true},

		{"no data", "the record is gone: the finding of the record line", []string{"nodata"}, false},
		{"no such name", "the record is gone: the finding of the record line", []string{"noname"}, false},
		{"two MTA-STS records", "two records do not read as on", []string{emlTXT("v=STSv1; id=2") + "\n" + emlTXT("v=STSv1; id=3")}, false},
		{"bad id", "an id that does not read is off", []string{emlTXT("v=STSv1; id=abc!")}, false},
		{"no id", "a record with no id is off", []string{emlTXT("v=STSv1")}, false},
		{"other text", "another text at the name is off", []string{emlTXT("hello")}, false},
		{"a CNAME", "a CNAME is not a record that reads", []string{"CNAME mta-sts.hosting.test."}, false},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			with := emlFile(t, plrLine, plrTXTLine)
			without := emlFile(t, plrTXTLine)
			o := emlObserve(t, owner, dnswire.TypeTXT, r.specs...)
			got := Findings(with, o)
			if r.on {
				if len(got) != 0 {
					t.Fatalf("%s, but got%s", r.right, decShow(got))
				}
				// Without the line the id change is the alert of the record.
				if base := Findings(without, o); len(base) == 0 && r.specs[0] != emlTXT("v=STSv1; id=1") {
					t.Fatalf("a file with no mta-sts line shows the id change, but got nothing")
				}
				return
			}
			if len(got) != 1 || got[0].Rule != RuleMTASTS {
				t.Fatalf("%s, but got%s", r.right, decShow(got))
			}
			plrSame(t, r.right, got, Findings(without, o))
		})
	}
}

// The relaxation needs a line that is exact and reads as on.
func TestPlrRelaxationNeedsTheLineToReadAsOn(t *testing.T) {
	const owner = "_mta-sts.corp.test."
	on := emlTXT("v=STSv1; id=2")
	rows := []struct {
		name, txtLine string
	}{
		{"the line says none", `_mta-sts.corp.test. TXT none`},
		{"the line has no id", `_mta-sts.corp.test. TXT "v=STSv1"`},
		{"the line holds other text", `_mta-sts.corp.test. TXT "hello"`},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			with, without := emlFile(t, plrLine, r.txtLine), emlFile(t, r.txtLine)
			o := emlObserve(t, owner, dnswire.TypeTXT, on)
			got := Findings(with, o)
			if len(got) != 1 || got[0].Rule != RuleMTASTS {
				t.Fatalf("a line that does not read as on keeps its finding, but got%s", decShow(got))
			}
			plrSame(t, "the finding of the line alone", got, Findings(without, o))
		})
	}
}

// One cause, one alert.
func TestPlrOneCauseOneAlert(t *testing.T) {
	f := emlFile(t, plrLine, plrTXTLine)
	now := decT0.Add(time.Minute)
	record := func(spec string) obs.Observation {
		return emlObserve(t, "_mta-sts.corp.test.", dnswire.TypeTXT, spec, spec)
	}
	t.Run("weaker file, same record", func(t *testing.T) {
		if got := Decide(Input{Expect: f, Observation: record(emlTXT("v=STSv1; id=1")), Now: now}); len(got) != 0 {
			t.Errorf("the record check gives nothing, got%s", decShowChanges(got))
		}
		weak := plrObserve(t, plrDoc("testing", "604800", "mail.corp.test"))
		got := Decide(Input{Expect: f, Observation: weak, Now: now})
		if len(got) != 1 || got[0].Op != OpOpen || got[0].Finding.Rule != RuleMTASTS || got[0].Finding.Check.Kind != obs.KindPolicy {
			t.Errorf("the policy check opens the one alert, got%s", decShowChanges(got))
		}
	})
	t.Run("new id, same policy", func(t *testing.T) {
		if got := Decide(Input{Expect: f, Observation: record(emlTXT("v=STSv1; id=2")), Now: now}); len(got) != 0 {
			t.Errorf("the record check gives nothing, got%s", decShowChanges(got))
		}
		same := plrObserve(t, plrDoc("enforce", "604800", "mail.corp.test"))
		if got := Decide(Input{Expect: f, Observation: same, Now: now}); len(got) != 0 {
			t.Errorf("the policy check gives nothing, got%s", decShowChanges(got))
		}
	})
	t.Run("both change", func(t *testing.T) {
		weak := plrObserve(t, plrDoc("testing", "604800", "mail.corp.test"))
		var all []Finding
		all = append(all, Findings(f, record(emlTXT("v=STSv1; id=2")))...)
		all = append(all, Findings(f, weak)...)
		if len(all) != 1 || all[0].Check.Kind != obs.KindPolicy {
			t.Errorf("one alert from the policy check, got%s", decShow(all))
		}
	})
}

// ---- property ----

const (
	plrSeed  = 20261118
	plrCases = 1500
)

var (
	plrModes = []string{"enforce", "testing", "none"}
	plrAges  = []string{"0", "1", "86400", "604800", "1209600", "31557600"}
	plrNames = []string{"mail.corp.test.", "*.corp.test.", "a.corp.test.", "b.a.corp.test.", "*.a.corp.test.", "mx.evil.test.", "*.evil.test.", "x.evil.test."}
)

// plrPolicy is a random policy: its mode, max_age and hosts. A mode other
// than none has at least one host.
func plrPolicy(rng *rand.Rand) (mode, age string, mx []string) {
	mode, age = plrModes[rng.IntN(3)], plrAges[rng.IntN(len(plrAges))]
	n := rng.IntN(5)
	if mode != "none" && n == 0 {
		n = 1
	}
	for _, i := range rng.Perm(len(plrNames))[:n] {
		mx = append(mx, plrNames[i])
	}
	return mode, age, mx
}

// plrWritten writes a policy file in a random way: line ends, the order of
// the lines, the case of hosts, the dot at the end and an unknown key.
func plrWritten(rng *rand.Rand, mode, age string, mx []string) string {
	lines := []string{"version: STSv1", "mode: " + mode, "max_age: " + age}
	for _, m := range mx {
		if rng.IntN(2) == 0 {
			m = strings.TrimSuffix(m, ".")
		}
		if rng.IntN(2) == 0 {
			m = strings.ToUpper(m)
		}
		lines = append(lines, "mx: "+m)
	}
	if rng.IntN(2) == 0 {
		lines = append(lines, "x-extra: 1")
	}
	rng.Shuffle(len(lines), func(i, j int) { lines[i], lines[j] = lines[j], lines[i] })
	end := "\n"
	if rng.IntN(2) == 0 {
		end = "\r\n"
	}
	return strings.Join(lines, end) + end
}

// For random pairs of valid policies, policyFindings gives words exactly
// when expect.STSPolicyWeaker gives words, and each word once, in order.
func TestPlrPolicyFindingsFollowWeakerProperty(t *testing.T) {
	var weaker, stricter, same int
	for c := 0; c < plrCases; c++ {
		rng := rand.New(rand.NewPCG(plrSeed, uint64(c)))
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("seed %d case %d: panic %v", plrSeed, c, r)
				}
			}()
			wm, wa, wx := plrPolicy(rng)
			line := strings.Join(append([]string{"mta-sts", wm, wa}, wx...), " ")
			f := plrFile(t, line)
			fm, fa, fx := plrPolicy2(rng, wm, wa, wx)
			body := plrWritten(rng, fm, fa, fx)
			p, problem := expect.ParseSTSPolicy([]byte(body))
			if problem != "" {
				t.Fatalf("seed %d case %d: the generated policy %q does not read: %s", plrSeed, c, body, problem)
			}
			words := expect.STSPolicyWeaker(*f.Policy, p)
			got := policyFindings(f, plrObserve(t, body))
			switch {
			case p.String() == f.Policy.String():
				same++
				if len(got) != 0 {
					t.Fatalf("seed %d case %d: equal texts %q gave%s", plrSeed, c, p.String(), decShow(got))
				}
				return
			case len(got) != 1:
				t.Fatalf("seed %d case %d: line %q file %q gave%s", plrSeed, c, line, body, decShow(got))
			}
			var lines []string
			for _, l := range strings.Split(got[0].Value, "\n") {
				if w, ok := strings.CutPrefix(l, "weaker "); ok {
					lines = append(lines, w)
				}
			}
			if !slices.Equal(lines, words) {
				t.Fatalf("seed %d case %d: line %q file %q\n words %q\nwant  %q", plrSeed, c, line, body, lines, words)
			}
			if got[0].Rule != RuleMTASTS || got[0].Severity != SeverityMedium || got[0].Expected != f.Policy.String() ||
				len(got[0].Seen) != 1 || got[0].Seen[0].Text != p.String() {
				t.Fatalf("seed %d case %d: finding is wrong:%s", plrSeed, c, decShow(got))
			}
			if len(words) > 0 {
				weaker++
			} else {
				stricter++
			}
		}()
	}
	if weaker < 200 || stricter < 50 || same < 20 {
		t.Errorf("seed %d: %d weaker, %d stricter, %d same; the generator is too narrow", plrSeed, weaker, stricter, same)
	}
}

// plrPolicy2 gives the policy of a file: often a small edit of the line, so
// that equal, stricter and weaker pairs all come up.
func plrPolicy2(rng *rand.Rand, mode, age string, mx []string) (string, string, []string) {
	if rng.IntN(3) == 0 {
		return plrPolicy(rng)
	}
	switch rng.IntN(4) {
	case 0:
		mode = plrModes[rng.IntN(3)]
	case 1:
		age = plrAges[rng.IntN(len(plrAges))]
	case 2:
		mx = slices.Clone(mx)
		mx = append(mx, plrNames[rng.IntN(len(plrNames))])
	}
	mx = slices.Compact(slices.Sorted(slices.Values(mx)))
	if mode != "none" && len(mx) == 0 {
		mx = []string{plrNames[0]}
	}
	return mode, age, mx
}

// A server that shows an on record is not shown; the one with no record is.
func TestPlrOnlyTheServerWithNoRecordIsShown(t *testing.T) {
	f := emlFile(t, plrLine, plrTXTLine)
	o := emlObserve(t, "_mta-sts.corp.test.", dnswire.TypeTXT, emlTXT("v=STSv1; id=2"), "nodata")
	got := Findings(f, o)
	if len(got) != 1 || got[0].Rule != RuleMTASTS || len(got[0].Seen) != 1 || !reflect.DeepEqual(got[0].Seen[0].Answer, o.Answers[1]) {
		t.Fatalf("want one mta-sts finding that shows server 2 only, got%s", decShow(got))
	}
}

// A key that is not the policy check of the line, or a missing file or line,
// gives no finding and no panic, even when the answer would read as weaker.
func TestPlrKeysThatAreNotTheCheckOfTheLine(t *testing.T) {
	f := plrFile(t, plrLine)
	weak := plrObserve(t, plrDoc("none", "1"))
	d := decName(t, "corp.test.")
	rows := []struct {
		name string
		file *expect.File
		key  obs.Key
	}{
		{"no file", nil, weak.Key},
		{"no mta-sts line", plrFile(t), weak.Key},
		{"records check of the same name", f,
			obs.Key{Kind: obs.KindRecords, Domain: d, Name: weak.Key.Name, Type: dnswire.TypeTXT}},
		{"policy check of another domain, same name", f,
			obs.Key{Kind: obs.KindPolicy, Domain: decName(t, "other.test."), Name: weak.Key.Name, Type: dnswire.TypeTXT}},
	}
	for _, r := range rows {
		t.Run(r.name, func(t *testing.T) {
			o := weak
			o.Key = r.key
			if got := policyFindings(r.file, o); len(got) != 0 {
				t.Fatalf("want no finding, got%s", decShow(got))
			}
		})
	}
}

// A name that does not exist or holds no data is no policy file seen: it is
// not read as an empty file, which would show as a policy that cannot be read
// and keep an open alert alive. With no policy file seen the alert resolves.
func TestPlrNegativeAnswerIsNoPolicyFile(t *testing.T) {
	f := plrFile(t, plrLine)
	now := decT0.Add(time.Minute)
	open := emlOne(t, f, plrObserve(t, plrDoc("testing", "604800", "mail.corp.test")))
	results := map[string]obs.Result{
		"no data": decNoData(t, "corp.test."),
		"no name": decNoName(t, "corp.test."),
	}
	for name, res := range results {
		t.Run(name, func(t *testing.T) {
			if set, ok := policyRecords(decAnswer(t, plrHost, plrAddrs[0], res)); ok || set != nil {
				t.Fatalf("a negative answer holds no records, got ok %v set %v", ok, set)
			}
			o := plrWith(t, decAnswer(t, plrHost, plrAddrs[0], res))
			if got := Findings(f, o); len(got) != 0 {
				t.Fatalf("a negative answer gives no finding, got%s", decShow(got))
			}
			mixed := plrWith(t, plrAnswer(t, 0, plrDoc("enforce", "604800", "mail.corp.test")), decAnswer(t, plrHost, plrAddrs[1], res))
			if got := Findings(f, mixed); len(got) != 0 {
				t.Fatalf("a negative answer is not seen beside an equal policy, got%s", decShow(got))
			}
			decSameChanges(t, Decide(Input{Expect: f, Open: []Finding{open}, Observation: o, Now: now}),
				[]Change{{Op: OpResolve, Finding: open, At: now}})
			if got := Decide(Input{Expect: f, Observation: o, Now: now}); len(got) != 0 {
				t.Fatalf("a negative answer opens nothing, got%s", decShowChanges(got))
			}
		})
	}
}
