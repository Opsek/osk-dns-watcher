package main

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
)

// The commands reach the policy host through the system resolver and the
// system trust store, and the fake DNS server of these tests lies in the
// root zone, so no test here can serve a policy file. What a policy file
// does to a finding is tested through the functions that the commands call
// after the fetch.

const (
	pccPolicyLine = "mta-sts enforce 604800 mail.corp.test."
	pccFile       = "domain corp.test.\n" + pccPolicyLine + "\ncorp.test. DS none\n"
	pccServer     = "10.53.0.30:443"
	pccHost       = "mta-sts.corp.test."
)

var pccNow = time.Date(2026, 11, 18, 10, 0, 0, 0, time.UTC)

func pccPolicyKey(t testing.TB) obs.Key {
	k, ok := obs.PolicyKey(cliName("corp.test."))
	if !ok {
		t.Fatal("no policy key for corp.test.")
	}
	return k
}

func pccAnswer(k obs.Key, r obs.Result) obs.Answer {
	return obs.Answer{
		Proof: obs.Proof{
			Server:   obs.Server{Name: k.Name, Addr: netip.MustParseAddrPort(pccServer)},
			Question: dnswire.Question{Name: k.Name, Type: dnswire.TypeTXT, Class: dnswire.ClassINET},
			Sent:     pccNow, Received: pccNow, TCP: true,
		},
		Result: r,
	}
}

// pccFetched is the observation of a fetch that read body.
func pccFetched(t testing.TB, body string) obs.Observation {
	k := pccPolicyKey(t)
	set := []dnswire.Record{{Name: k.Name, Class: dnswire.ClassINET, Data: dnswire.TXT{Strings: []string{body}}}}
	return obs.Observation{Key: k, Start: pccNow, Zone: k.Domain, Answers: []obs.Answer{pccAnswer(k, obs.RecordsResult(obs.Records{Set: set}))}}
}

func pccFailed(t testing.TB, reason obs.Reason, detail string) obs.Observation {
	k := pccPolicyKey(t)
	f := obs.FailureResult(obs.Failure{Reason: reason, Detail: detail})
	return obs.Observation{Key: k, Start: pccNow, Zone: k.Domain, Answers: []obs.Answer{pccAnswer(k, f)}}
}

func pccFormat(t *testing.T, asJSON bool, observations ...obs.Observation) (out string, clean bool) {
	t.Helper()
	f, err := expect.Parse([]byte(pccFile))
	if err != nil {
		t.Fatal(err)
	}
	l := &lines{json: asJSON}
	clean = formatFindings(l, f, observations, pccNow)
	return l.String(), clean
}

const pccWas = "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmax_age: 604800\n"

var pccWeakerRows = []struct {
	name, body, seen string
	words            []string
}{
	{"a lower mode", "version: STSv1\nmode: testing\nmx: mail.corp.test\nmax_age: 604800\n", "mta-sts testing 604800 mail.corp.test.",
		[]string{"mode testing in place of enforce: senders deliver mail even when the TLS check fails"}},
	{"mode none", "version: STSv1\nmode: none\nmax_age: 604800\n", "mta-sts none 604800",
		[]string{"mode none in place of enforce: senders act as if there were no policy"}},
	{"a lower max_age", "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmax_age: 86400\n", "mta-sts enforce 86400 mail.corp.test.",
		[]string{"max_age 86400 in place of 604800: senders keep the policy for less time"}},
	{"another host", "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmx: *.evil.test\nmax_age: 604800\n", "mta-sts enforce 604800 mail.corp.test. *.evil.test.",
		[]string{"mx *.evil.test. is not allowed by the file"}},
	{"all three", "version: STSv1\nmode: testing\nmx: mail.corp.test\nmx: *.evil.test\nmax_age: 86400\n", "mta-sts testing 86400 mail.corp.test. *.evil.test.",
		[]string{
			"mode testing in place of enforce: senders deliver mail even when the TLS check fails",
			"max_age 86400 in place of 604800: senders keep the policy for less time",
			"mx *.evil.test. is not allowed by the file"}},
	{"a file that does not read", "<html>not found</html>\n", "mta-sts policy cannot be read: a line without a colon",
		[]string{"the policy file cannot be read: senders act as if there were no policy"}},
}

// The words of a weaker policy print as "weaker" lines after the line that
// the host gave, and nothing of the file but its canonical text is shown.
func TestPccCheckPrintsTheWordsOfAWeakerPolicy(t *testing.T) {
	for _, c := range pccWeakerRows {
		t.Run(c.name, func(t *testing.T) {
			out, clean := pccFormat(t, false, pccFetched(t, c.body))
			want := []string{
				"finding medium mta-sts policy mta-sts.corp.test. TXT",
				"  expected " + pccPolicyLine,
				"  seen " + pccServer + " " + pccHost + " " + c.seen,
			}
			for _, w := range c.words {
				want = append(want, "  weaker "+w)
			}
			want = append(want, "checked corp.test. 1 sets: 1 findings, 0 unknown answers")
			if got := strings.Split(strings.TrimSuffix(out, "\n"), "\n"); !slices.Equal(got, want) {
				t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
			if clean {
				t.Error("the check is clean although it found a policy that differs")
			}
		})
	}
}

// With --json the words are the list "weaker", after "seen".
func TestPccCheckJSONHasTheWordsOfAWeakerPolicy(t *testing.T) {
	for _, c := range pccWeakerRows {
		t.Run(c.name, func(t *testing.T) {
			out, _ := pccFormat(t, true, pccFetched(t, c.body))
			var found int
			for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
				var f struct {
					Type, Severity, Rule, Kind, Name, RType, Expected string
					Seen                                              []struct{ Address, Host, Text string }
					Weaker                                            []string
				}
				if err := json.Unmarshal([]byte(line), &f); err != nil {
					t.Fatalf("line %q: %v", line, err)
				}
				if f.Type != "finding" {
					continue
				}
				found++
				if f.Severity != "medium" || f.Rule != "mta-sts" || f.Kind != "policy" || f.Name != pccHost || f.RType != "TXT" ||
					f.Expected != pccPolicyLine || len(f.Seen) != 1 || f.Seen[0].Address != pccServer || f.Seen[0].Host != pccHost ||
					f.Seen[0].Text != c.seen || !slices.Equal(f.Weaker, c.words) {
					t.Errorf("finding %+v; want a medium mta-sts finding of the policy check, seen %q, words %q", f, c.seen, c.words)
				}
				if i, j := strings.Index(line, `"seen":`), strings.Index(line, `"weaker":[`); i < 0 || j < i {
					t.Errorf("line %s: the key weaker does not follow seen", line)
				}
			}
			if found != 1 {
				t.Errorf("%d findings in:\n%s\nwant 1", found, out)
			}
		})
	}
}

// A policy that says what the line says gives no finding, with no word and no
// "weaker" key, however the file is written.
func TestPccCheckFindsNothingInThePolicyThatTheLineSays(t *testing.T) {
	for _, c := range []struct{ name, body string }{
		{"the same file", pccWas},
		{"CRLF", strings.ReplaceAll(pccWas, "\n", "\r\n")},
		{"another order", "max_age: 604800\nmx: Mail.Corp.Test.\nmode: enforce\nversion: STSv1\n"},
		{"an extra key", pccWas + "foo: bar\n"},
		{"an extra mx", "version: STSv1\nmode: enforce\nmx: mail.corp.test\nmx: mail.corp.test\nmax_age: 604800\n"},
		{"UTF-8 in the value of an unknown key", pccWas + "x: café\n"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				out, clean := pccFormat(t, asJSON, pccFetched(t, c.body))
				if !clean || strings.Contains(out, "finding ") || strings.Contains(out, `"type":"finding"`) || strings.Contains(out, "weaker") {
					t.Errorf("json %t: clean %t, output:\n%s\nwant a clean check", asJSON, clean, out)
				}
			}
		})
	}
}

// A fetch that failed is unknown, never a finding.
func TestPccCheckPrintsAFailedPolicyFetchAsUnknown(t *testing.T) {
	out, clean := pccFormat(t, false, pccFailed(t, obs.ReasonBadAnswer, "HTTP status 404"))
	got := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	if len(got) != 2 || clean {
		t.Fatalf("output:\n%s\nwant one unknown line and the count, and no clean check", out)
	}
	if head := "unknown policy mta-sts.corp.test. TXT " + pccServer + " " + pccHost + " "; !strings.HasPrefix(got[0], head) ||
		!strings.HasSuffix(got[0], ` - failure bad-answer "HTTP status 404"`) {
		t.Errorf("line %q; want it to start with %q and end with the failure", got[0], head)
	}
	if got[1] != "checked corp.test. 1 sets: 0 findings, 1 unknown answers" {
		t.Errorf("last line %q", got[1])
	}
}

// pccFailedLine splits a checked line of a failed check into what comes
// before " failed " and what follows. runParse takes one word of reasons, so
// it cannot read the line of a failed policy check, which adds the cause.
func pccFailedLine(text string) (head, reasons string, ok bool) {
	return strings.Cut(text, " failed ")
}

// A failed policy check names the cause in parentheses after its reason; a
// failed DNS check names the reason only, and a check that gave a usable
// answer is ok.
func TestPccCheckedLineOfAPolicyCheck(t *testing.T) {
	k := pccPolicyKey(t)
	dns := obs.RecordsKey(cliName("corp.test."), cliName("www.corp.test."), dnswire.TypeA)
	fail := func(key obs.Key, reason obs.Reason, detail string) obs.Observation {
		return obs.Observation{Key: key, Start: pccNow, Answers: []obs.Answer{pccAnswer(key, obs.FailureResult(obs.Failure{Reason: reason, Detail: detail}))}}
	}
	head := func(key obs.Key) string {
		return "checked other " + key.String() + " " + pccNow.Format(receivedLayout)
	}
	for _, c := range []struct {
		name string
		o    obs.Observation
		want string
	}{
		{"policy, HTTP status", fail(k, obs.ReasonBadAnswer, "HTTP status 404"), head(k) + " failed bad-answer (HTTP status 404)"},
		{"policy, timeout", fail(k, obs.ReasonTimeout, "timeout"), head(k) + " failed timeout (timeout)"},
		{"policy, too large", fail(k, obs.ReasonBadAnswer, "the policy file is larger than 65536 octets"),
			head(k) + " failed bad-answer (the policy file is larger than 65536 octets)"},
		{"policy, network", fail(k, obs.ReasonNetwork, "network: the host does not answer"),
			head(k) + " failed network (network: the host does not answer)"},
		{"policy, ok", pccFetched(t, pccWas), head(k) + " ok"},
		{"dns, network", fail(dns, obs.ReasonNetwork, "read udp 10.53.0.2:53: i/o timeout"), head(dns) + " failed network"},
		{"dns, refused", fail(dns, obs.ReasonRefused, "REFUSED"), head(dns) + " failed refused"},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := checkedLine(schedule.TierOther, c.o); got != c.want {
				t.Errorf("line %q; want %q", got, c.want)
			}
			if _, reasons, failed := pccFailedLine(c.want); failed {
				if want := c.o.Key.Kind == obs.KindPolicy; strings.Contains(reasons, "(") != want {
					t.Errorf("reasons %q: parentheses %t; want %t", reasons, !want, want)
				}
			}
		})
	}
}

// snapshot of a domain with no record at _mta-sts writes no mta-sts line and
// says nothing of the policy file: it never asked for it. (The fake server
// lies in the root zone, so a snapshot with the record on cannot be played
// here: the record is left out as lying in the wrong zone.)
func TestPccSnapshotWritesNoMTASTSLineWithoutTheRecord(t *testing.T) {
	s := transportStart(t, cliWorld)
	_, lines, errOut := expRun(t, "snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.", "_mta-sts.corp.test.", "TXT")
	if errOut != "" {
		t.Errorf("errors %q; want none", errOut)
	}
	for _, l := range lines {
		if strings.HasPrefix(l, "mta-sts ") || strings.HasPrefix(l, "# not written: "+pccHost) || strings.Contains(l, "policy") {
			t.Errorf("the snapshot says something of the policy file: %q", l)
		}
	}
}
