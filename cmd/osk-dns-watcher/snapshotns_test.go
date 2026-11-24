package main

import (
	"encoding/json"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// What osk-dns-watcher snapshot says of the NS line beside the file: the servers that
// gave no answer about it, and each set of a line that accepts several with
// the servers that gave it. Each note is a comment, so the whole output is
// still a file of expectations, and nothing that a server sends can end a
// comment and start a line of the file.

var (
	snnNS = []dnswire.Record{
		cliRR("corp.test.", 3600, dnswire.NS{Host: cliName("ns1.corp.test.")}),
		cliRR("corp.test.", 3600, dnswire.NS{Host: cliName("ns2.corp.test.")}),
	}
	// 192.0.2.0/24 is neither public nor in the extra range of the tests, so
	// the servers of corp.test. are never asked: each gives not-permitted.
	snnGlue = []dnswire.Record{
		cliRR("ns1.corp.test.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.11")}),
		cliRR("ns2.corp.test.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.12")}),
	}
	snnRootSOA = cliRR(".", 3600, dnswire.SOA{MName: cliName("a.root.test."), RName: cliName("hostmaster.root.test."),
		Serial: 7, Refresh: 3600, Retry: 600, Expire: 604800, Minimum: 300})
)

// snnWorld is a root server that delegates corp.test. to two servers that
// osk-dns-watcher may not ask, and holds no DS set for it.
func snnWorld(q []byte, _ bool) []byte {
	m, err := dnswire.Parse(q)
	if err != nil || len(m.Question) != 1 {
		return nil
	}
	name, qtype := strings.ToLower(m.Question[0].Name.String()), m.Question[0].Type
	switch {
	case name == "corp.test." && qtype == dnswire.TypeDS:
		return cliAnswer(q, transportQR|transportAA, nil, []dnswire.Record{snnRootSOA}, nil)
	case name == "corp.test.", strings.HasSuffix(name, ".corp.test."):
		return cliAnswer(q, transportQR, nil, snnNS, snnGlue)
	}
	return nil
}

// snnPlain reports whether text holds only printable ASCII and line ends.
func snnPlain(text string) bool {
	return !strings.ContainsFunc(text, func(r rune) bool { return r != '\n' && (r < 0x20 || r > 0x7e) })
}

// snnParses fails unless out, the whole standard output, holds only
// printable ASCII and is a valid file whose lines are those of want.
func snnParses(t *testing.T, out, want string) {
	t.Helper()
	if !snnPlain(out) {
		t.Errorf("the output holds an octet that is not printable ASCII:\n%q", out)
	}
	g, err := expect.Parse([]byte(out))
	if err != nil {
		t.Fatalf("the output is not a valid file: %v\n%s", err, out)
	}
	if g.String() != want {
		t.Errorf("the output reads as the file\n%s\nwant\n%s", g.String(), want)
	}
}

// snnLines gives the lines of out, which must end with a line end.
func snnLines(t *testing.T, out string) []string {
	t.Helper()
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("the output does not end with a line end: %q", out)
	}
	return strings.Split(strings.TrimSuffix(out, "\n"), "\n")
}

// snnNoAnswer is the note of the servers that gave no answer about the NS set.
func snnNoAnswer(servers ...string) string {
	return "# no answer about the NS set from " + strings.Join(servers, ", ") +
		": the NS line holds what the other servers gave; if they hold another set, osk-dns-watcher alerts at its first check"
}

// A parent zone that delegates to servers that osk-dns-watcher may not ask: the NS line
// holds the parent's set alone, and a comment names each server that gave no
// answer about it. The output is still the file, and the JSON says the same.
func TestSnnSnapshotNamesTheServersTheNSLineRestsWithout(t *testing.T) {
	s := transportStart(t, snnWorld)
	args := []string{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."}
	servers := []string{"192.0.2.11:53 ns1.corp.test. (not-permitted)", "192.0.2.12:53 ns2.corp.test. (not-permitted)"}
	notPermitted := "192.0.2.11:53 ns1.corp.test. gave no answer: not-permitted"
	file := "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\n"

	code, out, errOut := transportRun(args...)
	// The address checks of the two hosts got no answer either.
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliCompare(t, snnLines(t, out), []string{
		expHeader("corp.test."),
		"domain corp.test.",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. DS none",
		"# not written: ns1.corp.test. A: " + notPermitted,
		"# not written: ns1.corp.test. AAAA: " + notPermitted,
		"# not written: ns2.corp.test. A: " + notPermitted,
		"# not written: ns2.corp.test. AAAA: " + notPermitted,
		snnNoAnswer(servers...),
	})
	snnParses(t, out, file)

	code, out, errOut = transportRun(slices.Insert(slices.Clone(args), 1, "--json")...)
	if code != 1 || errOut != "" {
		t.Errorf("--json: exit code %d, errors %q; want 1 and none", code, errOut)
	}
	lines := snnLines(t, out)
	var last struct {
		Type    string   `json:"type"`
		Servers []string `json:"servers"`
	}
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &last); err != nil || last.Type != "nsnoanswer" || !slices.Equal(last.Servers, servers) ||
		!strings.HasPrefix(lines[len(lines)-1], `{"type":"nsnoanswer","servers":[`) {
		t.Errorf("--json: the last line %q (%v); want the nsnoanswer object of %q", lines[len(lines)-1], err, servers)
	}
	if n := strings.Count(out, `"type":"nsnoanswer"`); n != 1 || strings.Contains(out, `"type":"nsset"`) {
		t.Errorf("--json: %d nsnoanswer objects, or an nsset object:\n%s", n, out)
	}
}

// snnNoGlueWorld is snnWorld with no glue in the referral: the servers of
// corp.test. lie inside it, so the walk finds no address for them.
func snnNoGlueWorld(q []byte, tcp bool) []byte {
	m, err := dnswire.Parse(q)
	if err == nil && len(m.Question) == 1 && m.Question[0].Type != dnswire.TypeDS {
		name := strings.ToLower(m.Question[0].Name.String())
		if name == "corp.test." || strings.HasSuffix(name, ".corp.test.") {
			return cliAnswer(q, transportQR, nil, snnNS, nil)
		}
	}
	return snnWorld(q, tcp)
}

// When the walk finds no path to the servers of the domain, the NS line
// holds the parent's set, and the comment says so in words, not as a
// server; the JSON gives the same text in the list of servers.
func TestSnnSnapshotSaysWhenTheWalkFoundNoPath(t *testing.T) {
	s := transportStart(t, snnNoGlueWorld)
	args := []string{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."}
	noPath := "# osk-dns-watcher could not reach the servers of corp.test. (the walk from the root found no path to them): " +
		"the NS line holds what the parent zone gave; if the servers hold another set, osk-dns-watcher alerts at its first check"
	_, out, errOut := transportRun(args...)
	if errOut != "" {
		t.Errorf("errors %q; want none", errOut)
	}
	lines := snnLines(t, out)
	if !slices.Contains(lines, "corp.test. NS ns1.corp.test. | ns2.corp.test.") || lines[len(lines)-1] != noPath ||
		strings.Contains(out, "no answer about the NS set") {
		t.Errorf("the output\n%s\nwant the NS line of the parent and, last, the comment\n%s", out, noPath)
	}
	snnParses(t, out, "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\n")

	_, out, _ = transportRun(slices.Insert(slices.Clone(args), 1, "--json")...)
	lines = snnLines(t, out)
	if want := `{"type":"nsnoanswer","servers":["` + expect.NoPath + `"]}`; lines[len(lines)-1] != want {
		t.Errorf("--json: the last line %q; want %q", lines[len(lines)-1], want)
	}
}

// A line that is not written gets no note: the fake root answers for
// corp.test. itself, so its NS set lies in the root zone.
func TestSnnSnapshotWritesNoNoteWithoutAnNSLine(t *testing.T) {
	s := transportStart(t, cliWorld)
	for _, asJSON := range []bool{false, true} {
		args := []string{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test."}
		if asJSON {
			args = slices.Insert(args, 1, "--json")
		}
		_, out, errOut := transportRun(args...)
		if errOut != "" || !strings.Contains(out, "lies in zone .") {
			t.Fatalf("osk-dns-watcher %q: errors %q, output\n%s\nwant the NS set left out", args, errOut, out)
		}
		for _, note := range []string{"no answer about the NS set", "NS set ", "nsnoanswer", "nsset"} {
			if strings.Contains(out, note) {
				t.Errorf("osk-dns-watcher %q holds %q:\n%s", args, note, out)
			}
		}
	}
}

// --- the notes of NS lines that the fake server cannot give ---

const (
	snnParent = "10.53.0.3:53"
	snnNS1    = "10.53.0.11:53"
	snnNS2    = "10.53.0.12:53"
	snnNS3    = "10.53.0.13:53"
)

func snnAnswer(host string, addr string, r obs.Result) obs.Answer {
	s := obs.Server{Name: cliName(host)}
	if addr != "" {
		s.Addr = netip.MustParseAddrPort(addr)
	}
	return obs.Answer{Proof: obs.Proof{Server: s}, Result: r}
}

func snnSet(hosts ...dnswire.Name) obs.Result {
	var set []dnswire.Record
	for _, h := range hosts {
		set = append(set, dnswire.Record{Name: cliName("corp.test."), Class: dnswire.ClassINET, TTL: 300, Data: dnswire.NS{Host: h}})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

func snnNames(texts ...string) []dnswire.Name {
	var names []dnswire.Name
	for _, s := range texts {
		names = append(names, cliName(s))
	}
	return names
}

// snnLook is the delegation of corp.test. from one parent server and its apex
// NS set from the answers given, and the DS set, none.
func snnLook(parent []dnswire.Name, apex ...obs.Answer) []obs.Observation {
	d := cliName("corp.test.")
	noDS := obs.NoDataResult(obs.NoData{SOA: cliSOAOf("test.", 300)})
	return []obs.Observation{
		{Key: obs.DelegationKey(d), Zone: cliName("test."), Answers: []obs.Answer{snnAnswer("ns.test.", snnParent, snnSet(parent...))}},
		{Key: obs.DSKey(d), Zone: cliName("test."), Answers: []obs.Answer{snnAnswer("ns.test.", snnParent, noDS)}},
		{Key: obs.RecordsKey(d, d, dnswire.TypeNS), Zone: d, Answers: apex},
	}
}

// snnFormat writes what osk-dns-watcher snapshot writes after its checks gave the
// observations: the file with its comments, then the notes of its NS line.
func snnFormat(asJSON bool, observations []obs.Observation) (out string, f *expect.File) {
	d := cliName("corp.test.")
	f, skips := expect.Snapshot(d, observations)
	l := &lines{json: asJSON}
	formatSnapshot(l, d, f, skips, expect.Unreached(observations))
	if _, ok := f.Find(d, dnswire.TypeNS); ok {
		formatNSNotes(l, d, expect.NSNoAnswer(d, observations), expect.NSSources(d, observations))
	}
	return l.String(), f
}

const snnSeveral = "# the servers of corp.test. give different NS sets now: its NS line accepts each set below, and a change to " +
	"any other set gives an alert. Remove a set that holds a name that is not one of your nameservers."

// A line of several sets: each set gets one comment with the servers that
// gave it, in the order of the line, after the note of the servers that gave
// no answer. JSON gives the same, with empty lists, not null.
func TestSnnSnapshotNamesEachSetOfTheNSLine(t *testing.T) {
	pair := snnNames("ns1.corp.test.", "ns2.corp.test.")
	three := snnNames("ns1.corp.test.", "ns2.corp.test.", "ns3.corp.test.")
	timeout := obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout, Detail: "from the test"})
	observations := snnLook(pair,
		snnAnswer("ns1.corp.test.", snnNS1, snnSet(three...)),
		snnAnswer("ns2.corp.test.", snnNS2, timeout),
		snnAnswer("ns3.corp.test.", snnNS3, snnSet(pair...)))
	ns := "corp.test. NS ns1.corp.test. | ns2.corp.test. || ns1.corp.test. | ns2.corp.test. | ns3.corp.test."

	out, f := snnFormat(false, observations)
	cliCompare(t, snnLines(t, out), []string{
		expHeader("corp.test."),
		"domain corp.test.",
		ns,
		"corp.test. DS none",
		snnNoAnswer(snnNS2 + " ns2.corp.test. (timeout)"),
		snnSeveral,
		"# NS set ns1.corp.test. | ns2.corp.test.: given by the parent zone: " + snnParent + " ns.test.; given by the servers of corp.test.: " + snnNS3 + " ns3.corp.test.",
		"# NS set ns1.corp.test. | ns2.corp.test. | ns3.corp.test.: given by the servers of corp.test.: " + snnNS1 + " ns1.corp.test.",
	})
	snnParses(t, out, f.String())

	out, _ = snnFormat(true, observations)
	cliCompare(t, snnLines(t, out), []string{
		`{"type":"line","text":"domain corp.test."}`,
		`{"type":"line","text":"` + ns + `"}`,
		`{"type":"line","text":"corp.test. DS none"}`,
		`{"type":"nsnoanswer","servers":["` + snnNS2 + ` ns2.corp.test. (timeout)"]}`,
		`{"type":"nsset","text":"ns1.corp.test. | ns2.corp.test.","parent":["` + snnParent + ` ns.test."],"zone":["` + snnNS3 + ` ns3.corp.test."]}`,
		`{"type":"nsset","text":"ns1.corp.test. | ns2.corp.test. | ns3.corp.test.","parent":[],"zone":["` + snnNS1 + ` ns1.corp.test."]}`,
	})
}

// One set, from every server: no note at all. Five sets: no NS line, its
// reason as a comment, and no note.
func TestSnnSnapshotWritesNoNoteForOneSetOrNoLine(t *testing.T) {
	pair := snnNames("ns1.corp.test.", "ns2.corp.test.")
	one := snnLook(pair, snnAnswer("ns1.corp.test.", snnNS1, snnSet(pair...)), snnAnswer("ns2.corp.test.", snnNS2, snnSet(pair...)))
	five := snnLook(pair,
		snnAnswer("ns1.corp.test.", snnNS1, snnSet(snnNames("ns1.corp.test.")...)),
		snnAnswer("ns2.corp.test.", snnNS2, snnSet(snnNames("ns2.corp.test.")...)),
		snnAnswer("ns3.corp.test.", snnNS3, snnSet(snnNames("ns3.corp.test.")...)),
		snnAnswer("ns3.corp.test.", "10.53.0.14:53", snnSet(snnNames("ns1.corp.test.", "ns3.corp.test.")...)),
		snnAnswer("ns3.corp.test.", "10.53.0.15:53", obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout})))
	for _, c := range []struct {
		name   string
		obs    []obs.Observation
		ns     bool
		lines  int
		reason string
	}{
		{"one set", one, true, 4, ""},
		{"five sets and a failure", five, false, 4, "# not written: corp.test. NS: "},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, asJSON := range []bool{false, true} {
				out, f := snnFormat(asJSON, c.obs)
				if _, ok := f.Find(cliName("corp.test."), dnswire.TypeNS); ok != c.ns {
					t.Fatalf("NS line %v; want %v\n%s", ok, c.ns, f.String())
				}
				for _, note := range []string{"no answer about the NS set", "# NS set ", "different NS sets", "nsnoanswer", "nsset"} {
					if strings.Contains(out, note) {
						t.Errorf("the output holds %q:\n%s", note, out)
					}
				}
				if !asJSON {
					lines := snnLines(t, out)
					if len(lines) != c.lines || c.reason != "" && !strings.HasPrefix(lines[len(lines)-1], c.reason) {
						t.Errorf("the output\n%s\nwant %d lines, the last the reason %q", out, c.lines, c.reason)
					}
					snnParses(t, out, f.String())
				}
			}
		})
	}
}

// Names and server names built to break the output: every octet that would
// end a comment, start a line or move the cursor is written as an escape, so
// the output has exactly the lines it should and still reads as the file.
func TestSnnSnapshotNotesStateHostileNames(t *testing.T) {
	label := func(l string) dnswire.Name {
		n, err := dnswire.NameFromLabels([]string{l, "attacker", "example"})
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	var hostile []dnswire.Name
	for _, l := range []string{"nl\ncorp.test. NS ns.attacker.example.", "cr\rx", "esc\x1b[2J", "#hash", "bar|x", "bars||x", `q"x`, `b\x`, "nul\x00", "\xff"} {
		hostile = append(hostile, label(l))
	}
	evil := obs.Server{Name: label("srv\n# x\x1b]0;t\x07"), Addr: netip.MustParseAddrPort(snnNS2)}
	pair := snnNames("ns1.corp.test.", "ns2.corp.test.")
	observations := snnLook(pair,
		snnAnswer("ns1.corp.test.", snnNS1, snnSet(pair...)),
		obs.Answer{Proof: obs.Proof{Server: evil}, Result: snnSet(hostile...)},
		obs.Answer{Proof: obs.Proof{Server: evil}, Result: obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout, Detail: "x\ncorp.test. A 6.6.6.6"})})
	out, f := snnFormat(false, observations)
	e, ok := f.Find(cliName("corp.test."), dnswire.TypeNS)
	if !ok || len(e.Sets) != 2 {
		t.Fatalf("the NS line %q; want two sets", e.String())
	}
	// The header, the domain, the NS and DS lines, the note of no answer,
	// the line about several sets and one line for each set.
	if lines := snnLines(t, out); len(lines) != 8 {
		t.Errorf("the output has %d lines; want 8:\n%s", len(lines), out)
	}
	snnParses(t, out, f.String())
	if strings.Contains(out, "6.6.6.6") {
		t.Errorf("the detail of a failure reached the output:\n%s", out)
	}
	out, _ = snnFormat(true, observations)
	for _, l := range snnLines(t, out) {
		if !json.Valid([]byte(l)) {
			t.Errorf("--json: the line %q is not one JSON object", l)
		}
	}
}
