package decide

import (
	"net/netip"
	"os"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// TestUnregisteredDomainFixture reads an answer that a .com server gave for a
// name under a domain nobody registered. The note testdata/unregistered-com.txt
// says where it came from.
func TestUnregisteredDomainFixture(t *testing.T) {
	wire, err := os.ReadFile("testdata/unregistered-com.answer")
	if err != nil {
		t.Fatal(err)
	}
	m, err := dnswire.Parse(wire)
	if err != nil {
		t.Fatal(err)
	}

	// Check the recording first: a wrong file must fail here, not in the rule.
	if len(m.Question) != 1 || m.Question[0].Type != dnswire.TypeA || m.Question[0].Class != dnswire.ClassINET {
		t.Fatalf("question is %v, want one A IN question", m.Question)
	}
	q := m.Question[0]
	if m.Rcode != dnswire.Rcode(3) {
		t.Errorf("response code is %v, want NXDOMAIN", m.Rcode)
	}
	if !m.Authoritative {
		t.Error("the answer is not authoritative")
	}
	if m.RecursionAvailable {
		t.Error("the answer says recursion is available")
	}
	var soas []dnswire.Record
	for _, r := range m.Authority {
		if r.Type() == dnswire.TypeSOA {
			soas = append(soas, r)
		}
	}
	if len(soas) != 1 || soas[0].Name.String() != "com." {
		t.Fatalf("authority section holds SOA records %v, want exactly one, owned by com.", soas)
	}

	// The name is ns1.<label>.com.; the label is random, so it is read, not typed.
	labels := q.Name.Labels()
	if len(labels) != 3 || labels[0] != "ns1" || labels[2] != "com" {
		t.Fatalf("question name is %v, want ns1.<label>.com.", q.Name)
	}
	host := labels[1] + ".com."
	nsHost := q.Name.String()

	key := decRecordsKey(t, "corp.test.", nsHost, dnswire.TypeA)
	answer := obs.Answer{
		Proof: obs.Proof{
			Server:   obs.Server{Name: decName(t, "a.gtld-servers.net."), Addr: netip.MustParseAddrPort("192.5.6.30:53")},
			Question: q,
			Wire:     wire,
		},
		Result: decAs(t, obs.NoNameResult(obs.NoName{SOA: soas[0]}), "noname"),
	}
	o := decObservation(key, decName(t, "com."), nil, answer)
	f := decFile(t, "domain corp.test.", "corp.test. NS "+nsHost+" | ns2.corp.test.")

	got := Findings(f, o)
	decCheck(t, got, key, decWant{
		rule:     RuleNameServerHost,
		severity: SeverityCritical,
		expected: "corp.test. NS " + nsHost,
		seen:     []Seen{{Answer: answer, Text: "no such name: com. does not delegate " + host}},
	})

	changes := Decide(Input{Expect: f, Observation: o, Now: decT0})
	decSameChanges(t, changes, []Change{{Op: OpOpen, Finding: got[0], At: decT0}})
}
