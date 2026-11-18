package start

import (
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

const (
	pcsRecord   = `"v=STSv1; id=20261117"`
	pcsPolicyAt = "192.0.2.80:443"
)

// pcsBody is a policy file written in a way that the file of init must not
// copy: CRLF, an unknown key, an upper-case pattern, another line order.
const pcsBody = "version: STSv1\r\nmx: Mail.Example.COM.\r\nmode: enforce\r\nfoo: bar\r\nmax_age: 604800\r\n"

const pcsLine = "mta-sts enforce 604800 mail.example.com."

// pcsPolicy is the answer of the policy host of domain d to a fetch that
// read body.
func pcsPolicy(d, body string) []obs.Answer {
	var strs []string
	for len(body) > 255 {
		strs, body = append(strs, body[:255]), body[255:]
	}
	set := []dnswire.Record{{Name: iniName("mta-sts." + d), Class: dnswire.ClassINET, Data: dnswire.TXT{Strings: append(strs, body)}}}
	return []obs.Answer{iniAt("mta-sts."+d, pcsPolicyAt, obs.RecordsResult(obs.Records{Set: set}))}
}

func pcsPolicyFails(d string, why obs.Reason) []obs.Answer {
	return []obs.Answer{iniAt("mta-sts."+d, pcsPolicyAt, iniFail(why))}
}

func pcsPolicyKey(d string) string {
	k, _ := obs.PolicyKey(iniName(d))
	return k.String()
}

func pcsRecordKey(d string) string { return iniKey(d, "_mta-sts."+d, dnswire.TypeTXT) }

// pcsOn is what the servers of d give for the _mta-sts name when the record
// is on.
func pcsOn(d string) []obs.Answer {
	return iniBoth(iniRecords("_mta-sts."+d, dnswire.TypeTXT, pcsRecord))
}

// pcsLines are the lines of the fake world with the MTA-STS record on and,
// when policy is not empty, the mta-sts line.
func pcsLines(d, policy string) []string {
	lines := slices.Clone(iniLines(d))
	i := slices.Index(lines, "_mta-sts."+d+" TXT none")
	lines[i] = "_mta-sts." + d + " TXT " + pcsRecord
	if policy != "" {
		lines = slices.Insert(lines, 1, policy)
	}
	return lines
}

func pcsObservation(d string, answers []obs.Answer) []obs.Observation {
	return []obs.Observation{{Key: obs.RecordsKey(iniName(d), iniName("_mta-sts."+d), dnswire.TypeTXT), Zone: iniName(d), Answers: answers}}
}

func TestPcsWantsPolicy(t *testing.T) {
	const d = "example.com."
	name := "_mta-sts." + d
	record := func(texts ...string) []obs.Answer {
		return iniBoth(iniRecords(name, dnswire.TypeTXT, texts...))
	}
	for _, c := range []struct {
		name    string
		answers []obs.Answer
		want    bool
	}{
		{"one record that reads", record(pcsRecord), true},
		{"one record with a trailing semicolon and more fields", record(`"v=STSv1; id=1; x=y;"`), true},
		{"one record in two strings", record(`"v=STSv1; " "id=20261117"`), true},
		{"no record: no data", iniBoth(iniNoData(d)), false},
		{"no record: no such name", iniBoth(iniNoName(d)), false},
		{"two MTA-STS records", record(pcsRecord, `"v=STSv1; id=20261118"`), false},
		{"one MTA-STS record and another text", record(pcsRecord, `"v=spf1 -all"`), true},
		{"a record with no id", record(`"v=STSv1"`), false},
		{"a record with no semicolon after the version", record(`"v=STSv1 id=1"`), false},
		{"a record of another version", record(`"v=STSv2; id=1"`), false},
		{"a text that is no MTA-STS record", record(`"v=spf1 -all"`), false},
		{"a CNAME set: a provider hosts the record", iniBoth(iniRecords(name, dnswire.TypeCNAME, "hosted.provider.example.")), false},
		{"every server failed", iniBoth(iniFail(obs.ReasonTimeout)), false},
		{"no answer at all", nil, false},
		{"one server gave the record and the other failed", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords(name, dnswire.TypeTXT, pcsRecord)),
			iniAt("ns2.example.net.", iniNS2Addr, iniFail(obs.ReasonTimeout))}, false},
		{"the servers give different records", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords(name, dnswire.TypeTXT, pcsRecord)),
			iniAt("ns2.example.net.", iniNS2Addr, iniRecords(name, dnswire.TypeTXT, `"v=STSv1; id=20261118"`))}, false},
		{"one server gave the record and the other none", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords(name, dnswire.TypeTXT, pcsRecord)),
			iniAt("ns2.example.net.", iniNS2Addr, iniNoData(d))}, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			key, ok := WantsPolicy(iniName(d), pcsObservation(d, c.answers))
			if ok != c.want {
				t.Errorf("WantsPolicy = %t; want %t", ok, c.want)
			}
			if want, _ := obs.PolicyKey(iniName(d)); ok && key.String() != want.String() {
				t.Errorf("the key is %s; want %s", key, want)
			}
		})
	}
}

// Observations of other names do not make a policy check, and the check of
// another domain's record does not either.
func TestPcsWantsPolicyReadsTheRecordOfItsOwnDomain(t *testing.T) {
	const d = "example.com."
	other := pcsObservation("example.org.", iniBoth(iniRecords("_mta-sts.example.org.", dnswire.TypeTXT, pcsRecord)))
	at := func(name string) []obs.Observation {
		return []obs.Observation{{Key: obs.RecordsKey(iniName(d), iniName(name), dnswire.TypeTXT), Zone: iniName(d),
			Answers: iniBoth(iniRecords(name, dnswire.TypeTXT, pcsRecord))}}
	}
	for _, c := range []struct {
		name         string
		observations []obs.Observation
	}{
		{"none", nil},
		{"another domain", other},
		{"the apex TXT only", at(d)},
		{"a name under it", at("_mta-sts.www." + d)},
	} {
		if _, ok := WantsPolicy(iniName(d), c.observations); ok {
			t.Errorf("%s: WantsPolicy is true; want false", c.name)
		}
	}
}

// The look asks for the policy file exactly once, and only for a domain
// whose _mta-sts record is on.
func TestPcsInitFetchesThePolicyOnlyWhenTheRecordIsOn(t *testing.T) {
	const d = "example.com."
	for _, c := range []struct {
		name    string
		record  []obs.Answer // nil: the fake world, which has no record
		fetches int
	}{
		{"record on", pcsOn(d), 1},
		{"no record", nil, 0},
		{"two records", iniBoth(iniRecords("_mta-sts."+d, dnswire.TypeTXT, pcsRecord, `"v=STSv1; id=2"`)), 0},
		{"a record that does not read", iniBoth(iniRecords("_mta-sts."+d, dnswire.TypeTXT, `"v=STSv1"`)), 0},
		{"the servers disagree", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords("_mta-sts."+d, dnswire.TypeTXT, pcsRecord)),
			iniAt("ns2.example.net.", iniNS2Addr, iniNoData(d))}, 0},
		{"a failure answer", iniBoth(iniFail(obs.ReasonTimeout)), 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			seq := map[string][][]obs.Answer{pcsPolicyKey(d): {pcsPolicy(d, pcsBody)}}
			if c.record != nil {
				seq[pcsRecordKey(d)] = [][]obs.Answer{c.record}
			}
			s, r := stfNew(t, seq, "example.com", iniURL, "yes")
			code, _ := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if got := r.runs(pcsPolicyKey(d)); got != c.fetches {
				t.Errorf("the policy file was fetched %d times; want %d", got, c.fetches)
			}
			file := s.written(d)["example.com.expect"]
			if has := strings.Contains(file, "\nmta-sts "); has != (c.fetches == 1) {
				t.Errorf("the file has an mta-sts line: %t; want %t\n%s", has, c.fetches == 1, file)
			}
		})
	}
}

// A policy fetch that failed is not asked again, whatever the reason. A DNS
// check with a failure answer in the same look still runs once more.
func TestPcsInitDoesNotAskForAFailedPolicyFetchAgain(t *testing.T) {
	const d = "example.com."
	apexA := iniKey(d, d, dnswire.TypeA)
	for _, why := range []obs.Reason{obs.ReasonTimeout, obs.ReasonNetwork, obs.ReasonBadAnswer, obs.ReasonNotPermitted} {
		t.Run(why.String(), func(t *testing.T) {
			s, r := stfNew(t, map[string][][]obs.Answer{
				pcsRecordKey(d): {pcsOn(d)},
				pcsPolicyKey(d): {pcsPolicyFails(d, why)},
				apexA:           {stfOneDead(d, dnswire.TypeA, obs.ReasonTimeout, "192.0.2.10"), nil},
			}, "example.com", iniURL, "yes")
			code, _ := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if got := r.runs(pcsPolicyKey(d)); got != 1 {
				t.Errorf("the failed policy fetch ran %d times; want 1", got)
			}
			if got := r.runs(apexA); got != 2 {
				t.Errorf("the DNS check with a failure answer ran %d times; want 2", got)
			}
			if got := r.runs(pcsRecordKey(d)); got != 1 {
				t.Errorf("the check of the MTA-STS record ran %d times; want 1", got)
			}
			// The 14 DNS checks, then the policy fetch, and the one retry.
			if got := r.all(); got != 14+1+1 {
				t.Errorf("%d checks ran; want 16", got)
			}
		})
	}
}

// The snapshot holds the mta-sts line with the canonical text of the policy
// that the fetch read, however the file wrote it, and the file that init
// writes reads back to the same policy.
func TestPcsInitWritesTheMTASTSLineOfTheFetchedPolicy(t *testing.T) {
	const d = "example.com."
	s, _ := stfNew(t, map[string][][]obs.Answer{
		pcsRecordKey(d): {pcsOn(d)},
		pcsPolicyKey(d): {pcsPolicy(d, pcsBody)},
	}, "example.com", iniURL, "yes")
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	lines := pcsLines(d, pcsLine)
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	text := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", text, iniStamp+strings.Join(lines, "\n")+"\n")
	f, err := expect.Parse([]byte(text))
	if err != nil {
		t.Fatalf("the file that init wrote does not parse: %v", err)
	}
	if f.Policy == nil || f.Policy.String() != pcsLine || f.Policy.Line != 3 {
		t.Errorf("the policy of the file: %+v; want %q on line 3", f.Policy, pcsLine)
	}
}

// With the record on and no policy that reads, the file gets no mta-sts line
// and the snapshot says why under the sets that it leaves out.
func TestPcsInitLeavesOutTheMTASTSLineOfAPolicyItCannotRead(t *testing.T) {
	const d = "example.com."
	const host = "mta-sts." + d
	for _, c := range []struct {
		name   string
		answer []obs.Answer
		skip   string
	}{
		{"a failed fetch", pcsPolicyFails(d, obs.ReasonTimeout), host + " TXT: " + pcsPolicyAt + " " + host + " gave no answer: timeout"},
		{"a file with no mx line", pcsPolicy(d, "version: STSv1\nmode: enforce\nmax_age: 1\n"), host + " TXT: the policy file cannot be read: no mx line"},
		{"a file that is no policy", pcsPolicy(d, "<html>not found</html>\n"), host + " TXT: the policy file cannot be read: a line without a colon"},
		{"an empty file", pcsPolicy(d, ""), host + " TXT: the policy file cannot be read: no version line"},
		{"no data", []obs.Answer{iniAt(host, pcsPolicyAt, iniNoData(d))}, host + " TXT: the policy file cannot be read: no version line"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, _ := stfNew(t, map[string][][]obs.Answer{
				pcsRecordKey(d): {pcsOn(d)},
				pcsPolicyKey(d): {c.answer},
			}, "example.com", iniURL, "yes")
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			lines := pcsLines(d, "")
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, c.skip, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
			iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
		})
	}
}

// Two fetches that read different policies give no line either.
func TestPcsInitLeavesOutTheMTASTSLineWhenTheFetchesDisagree(t *testing.T) {
	const d = "example.com."
	one := pcsPolicy(d, pcsBody)
	other := pcsPolicy(d, "version: STSv1\nmode: testing\nmx: mail.example.com\nmax_age: 60\n")
	other[0].Server.Addr = netip.MustParseAddrPort("192.0.2.81:443")
	s, _ := stfNew(t, map[string][][]obs.Answer{
		pcsRecordKey(d): {pcsOn(d)},
		pcsPolicyKey(d): {slices.Concat(one, other)},
	}, "example.com", iniURL, "yes")
	if code, _ := s.run(); code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	file := s.written(d)["example.com.expect"]
	if strings.Contains(file, "\nmta-sts ") {
		t.Errorf("the file has an mta-sts line although two fetches read different policies:\n%s", file)
	}
}
