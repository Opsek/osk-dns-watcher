//go:build lab

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// dataQuery is one question that osk-dns-watcher query and dig both ask. The status and
// the answer count are what dig must see, so that two failures that print
// alike cannot pass as a match.
type dataQuery struct {
	server  string // lab host: ns1 or tld
	name    string
	qtype   string
	flags   []string // osk-dns-watcher flags; dataDigFlags maps each to dig
	status  string
	answers int    // at least this many answer records
	has     string // a text that dig's output holds, when the zone content matters
}

var dataDigFlags = map[string]string{"--do": "+dnssec", "--cd": "+cd", "--tcp": "+tcp"}

var (
	dataID      = regexp.MustCompile(`id: [0-9]+`)
	dataAnswers = regexp.MustCompile(`ANSWER: ([0-9]+),`)
	dataBlanks  = regexp.MustCompile(`[ \t]+`)
)

var dataSections = map[string]bool{
	";; ANSWER SECTION:":     true,
	";; AUTHORITY SECTION:":  true,
	";; ADDITIONAL SECTION:": true,
}

// TestQueryMatchesDig asks osk-dns-watcher query and dig the same questions of the lab and
// compares what they print, record by record.
func TestQueryMatchesDig(t *testing.T) {
	lab := os.Getenv("LAB_ID")
	if lab == "" {
		t.Fatal("LAB_ID is not set: this test runs in the runner of the lab")
	}
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})

	zone, err := filepath.Abs(filepath.Join("testdata", "odd.test.zone"))
	if err != nil {
		t.Fatal(err)
	}
	dataTool(t, "labctl", "load-zone", "ns1", "odd.test.", zone)

	for _, q := range dataBaseQueries() {
		dataCompare(t, lab, q)
	}
	for _, q := range dataOddQueries() {
		dataCompare(t, lab, q)
	}

	dir := t.TempDir()
	ksk := dataTool(t, "dnssec-keygen", "-q", "-K", dir, "-a", "RSASHA256", "-f", "KSK", "signed.test.")
	dataTool(t, "dnssec-keygen", "-q", "-K", dir, "-a", "RSASHA256", "signed.test.")
	unsigned := filepath.Join(dir, "signed.test.zone")
	if err := os.WriteFile(unsigned, []byte(dataSignedZone), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, nsec3 := range []bool{true, false} {
		signed := filepath.Join(dir, "signed.test.signed")
		args := []string{"-q", "-S", "-K", dir, "-d", dir, "-o", "signed.test.", "-f", signed}
		if nsec3 {
			args = append(args, "-3", "ABCD")
		}
		dataTool(t, "dnssec-signzone", append(args, unsigned)...)
		dataTool(t, "labctl", "load-zone", "ns1", "signed.test.", signed)
		for _, q := range dataSignedQueries(nsec3) {
			dataCompare(t, lab, q)
		}
	}

	// A DS record lives at a delegation, so the parent must delegate first.
	ds := dataTool(t, "dnssec-dsfromkey", "-2", filepath.Join(dir, ksk+".key"))
	_, rdata, ok := strings.Cut(ds, " DS ")
	if !ok {
		t.Fatalf("dnssec-dsfromkey printed %q", ds)
	}
	dataTool(t, "labctl", "delegate", "signed.test.", "ns1.corp.test.")
	dataTool(t, "labctl", "ds", "signed.test.", rdata)
	dataCompare(t, lab, dataQuery{server: "tld", name: "signed.test.", qtype: "DS",
		flags: []string{"--do"}, status: "NOERROR", answers: 1, has: "\tDS\t" + rdata})
}

// dataSignedZone has a wildcard, so that one answer is synthesized and comes
// with its proof.
const dataSignedZone = `$TTL 300
signed.test.        SOA ns1.corp.test. hostmaster.signed.test. 1 3600 600 604800 300
signed.test.        NS  ns1.corp.test.
signed.test.        A   192.0.2.10
www.signed.test.    A   192.0.2.11
*.wild.signed.test. A   192.0.2.12
`

func dataBaseQueries() []dataQuery {
	ns1 := func(name, qtype string, answers int, flags ...string) dataQuery {
		return dataQuery{server: "ns1", name: name, qtype: qtype, flags: flags, status: "NOERROR", answers: answers}
	}
	return []dataQuery{
		ns1("corp.test.", "SOA", 1),
		ns1("corp.test.", "NS", 2),
		ns1("corp.test.", "A", 1),
		ns1("corp.test.", "AAAA", 1),
		ns1("corp.test.", "MX", 1),
		ns1("corp.test.", "TXT", 1),
		ns1("corp.test.", "CAA", 1),
		ns1("ns1.corp.test.", "A", 1),
		ns1("ns2.corp.test.", "A", 1),
		ns1("www.corp.test.", "A", 1),
		ns1("mail.corp.test.", "A", 1),
		ns1("cdn.corp.test.", "CNAME", 1),
		ns1("_dmarc.corp.test.", "TXT", 1),
		ns1("dnshost.test.", "SOA", 1),
		ns1("dnshost.test.", "NS", 2),
		ns1("ns1.dnshost.test.", "A", 1),
		ns1("ns2.dnshost.test.", "A", 1),
		ns1("edge.dnshost.test.", "A", 1),
		ns1("shop.test.", "SOA", 1),
		ns1("shop.test.", "NS", 2),
		ns1("shop.test.", "A", 1),
		ns1("corp.test.", "SOA", 1, "--cd"),
		ns1("corp.test.", "NS", 2, "--tcp"),
		{server: "ns1", name: "nosuch.corp.test.", qtype: "A", status: "NXDOMAIN"},
		// Referrals: the parent answers without the aa flag, with the NS set and glue.
		{server: "tld", name: "www.corp.test.", qtype: "A", status: "NOERROR", has: "\tNS\tns1.corp.test."},
		{server: "tld", name: "shop.test.", qtype: "A", status: "NOERROR", has: "\tNS\tns1.dnshost.test."},
		// ns1 serves no zone test.
		{server: "ns1", name: "test.", qtype: "SOA", status: "REFUSED"},
	}
}

func dataOddQueries() []dataQuery {
	q := func(name, qtype string, answers int, flags ...string) dataQuery {
		return dataQuery{server: "ns1", name: name, qtype: qtype, flags: flags, status: "NOERROR", answers: answers}
	}
	long := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." +
		strings.Repeat("d", 52) + ".odd.test."
	return []dataQuery{
		q("odd.test.", "SOA", 1),
		q("odd.test.", "NS", 1),
		q(`weird\032name.odd.test.`, "A", 1),
		q(`a\.b.odd.test.`, "A", 1),
		q(`x\@y\$z\;w\(\)\"q.odd.test.`, "A", 1),
		q(`\000\255.odd.test.`, "A", 1),
		q("MiXeD.CaSe.odd.test.", "A", 1),
		q("mixed.case.odd.test.", "A", 1),
		q(long, "A", 1),
		q("generic.odd.test.", "A", 1),
		q("v6.odd.test.", "AAAA", 6),
		q("txt.odd.test.", "TXT", 1),
		q("long.odd.test.", "TXT", 1),
		q("dkim._domainkey.odd.test.", "TXT", 1),
		// 80 records do not fit in 1232 octets: the UDP answer is truncated
		// and both tools ask again over TCP.
		q("many.odd.test.", "TXT", 80),
		q("many.odd.test.", "TXT", 80, "--tcp"),
		q("caa.odd.test.", "CAA", 3),
		q("mx.odd.test.", "MX", 1),
		q("alias.odd.test.", "CNAME", 1),
		q("alias.odd.test.", "A", 2),
		q("dn.odd.test.", "DNAME", 1),
		// The server adds a CNAME made from the DNAME.
		q("x.dn.odd.test.", "A", 2),
		q("ptr.odd.test.", "PTR", 1),
		q("spf.odd.test.", "SPF", 1),
		q("ds.odd.test.", "DS", 1),
		q("key.odd.test.", "DNSKEY", 1),
		q("sig.odd.test.", "RRSIG", 1),
		q("nsec.odd.test.", "NSEC", 1),
		q("n3p.odd.test.", "NSEC3PARAM", 2),
		q("unk.odd.test.", "TYPE65280", 1),
		q("unk0.odd.test.", "TYPE65280", 1),
		{server: "ns1", name: "nosuch.odd.test.", qtype: "A", status: "NXDOMAIN"},
		{server: "ns1", name: "txt.odd.test.", qtype: "A", status: "NOERROR"},
	}
}

// dataSignedQueries asks for a name, a missing name, a missing type and a name
// that only a wildcard covers, so that every kind of proof is printed.
func dataSignedQueries(nsec3 bool) []dataQuery {
	proof := "\tNSEC\t"
	if nsec3 {
		proof = "\tNSEC3\t"
	}
	q := func(name, qtype, status string, answers int, has string) dataQuery {
		return dataQuery{server: "ns1", name: name, qtype: qtype, flags: []string{"--do"},
			status: status, answers: answers, has: has}
	}
	queries := []dataQuery{
		q("www.signed.test.", "A", "NOERROR", 2, "\tRRSIG\tA "),
		q("nosuch.signed.test.", "A", "NXDOMAIN", 0, proof),
		q("www.signed.test.", "MX", "NOERROR", 0, proof),
		q("x.wild.signed.test.", "A", "NOERROR", 2, proof),
		q("signed.test.", "DNSKEY", "NOERROR", 3, "\tDNSKEY\t257 3 8 "),
	}
	if nsec3 {
		queries = append(queries, q("signed.test.", "NSEC3PARAM", "NOERROR", 2, "\tNSEC3PARAM\t1 0 0 ABCD"))
	}
	return queries
}

// dataCompare runs one query with both tools and compares the results.
func dataCompare(t *testing.T, lab string, q dataQuery) {
	t.Helper()
	label := strings.Join(append([]string{q.server, q.name, q.qtype}, q.flags...), " ")
	t.Run(label, func(t *testing.T) {
		server := "10.53." + lab + ".11"
		if q.server == "tld" {
			server = "10.53." + lab + ".3"
		}
		want := dataDig(t, server, q)
		got := dataOsk(t, server, q)
		if !slices.Equal(got, want) {
			t.Errorf("osk-dns-watcher query and dig differ\nosk-dns-watcher:\n%s\ndig:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
		}
	})
}

func dataDig(t *testing.T, server string, q dataQuery) []string {
	t.Helper()
	args := []string{"+norec", "+nosplit", "+noadflag", "+noidnout", "+bufsize=1232"}
	for _, f := range q.flags {
		args = append(args, dataDigFlags[f])
	}
	args = append(args, "@"+server, q.name, q.qtype, "+noall", "+comments", "+answer", "+authority", "+additional")
	out := dataTool(t, "dig", args...)
	lines := dataKeep(out, true)
	if len(lines) < 2 || !strings.Contains(lines[0], "status: "+q.status+",") {
		t.Fatalf("dig does not show status %s:\n%s", q.status, out)
	}
	m := dataAnswers.FindStringSubmatch(lines[1])
	if m == nil {
		t.Fatalf("dig shows no answer count:\n%s", out)
	}
	if n, err := strconv.Atoi(m[1]); err != nil || n < q.answers {
		t.Fatalf("dig shows fewer than %d answer records:\n%s", q.answers, out)
	}
	if !strings.Contains(strings.Join(lines, "\n"), q.has) {
		t.Fatalf("dig output lacks %q:\n%s", q.has, out)
	}
	return lines
}

func dataOsk(t *testing.T, server string, q dataQuery) []string {
	t.Helper()
	args := append([]string{"query"}, q.flags...)
	args = append(args, "@"+server, q.name, q.qtype)
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("osk-dns-watcher %s: exit %d\n%s", strings.Join(args, " "), code, stderr.String())
	}
	return dataKeep(stdout.String(), false)
}

// dataKeep keeps the lines that both tools print the same way: the header
// with its ID masked, the flags, the section headers and the records. dig
// pads its columns with blanks, so the first four runs of blanks of each
// record become one tab, as osk-dns-watcher writes them.
func dataKeep(out string, fromDig bool) []string {
	var lines []string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, ";; ->>HEADER<<-"):
			lines = append(lines, dataID.ReplaceAllString(line, "id: X"))
		case strings.HasPrefix(line, ";; flags:"), dataSections[line]:
			lines = append(lines, line)
		case line == "", strings.HasPrefix(line, ";"):
		case fromDig:
			lines = append(lines, dataTabs(line))
		default:
			lines = append(lines, line)
		}
	}
	return dataSortSets(lines)
}

func dataTabs(line string) string {
	n := 0
	return dataBlanks.ReplaceAllStringFunc(line, func(blanks string) string {
		n++
		if n > 4 {
			return blanks
		}
		return "\t"
	})
}

// dataSortSets sorts each run of records of one owner (in any case), class and
// type, because the server sends the records of a set in random order.
func dataSortSets(lines []string) []string {
	key := func(line string) string {
		f := strings.SplitN(line, "\t", 5)
		if strings.HasPrefix(line, ";") || len(f) < 5 {
			return ""
		}
		return strings.ToLower(f[0]) + "\t" + f[2] + "\t" + f[3]
	}
	for i := 0; i < len(lines); {
		k := key(lines[i])
		j := i + 1
		for k != "" && j < len(lines) && key(lines[j]) == k {
			j++
		}
		slices.Sort(lines[i:j])
		i = j
	}
	return lines
}

// dataTool runs a tool of the lab runner and returns its standard output.
func dataTool(t *testing.T, name string, args ...string) string {
	t.Helper()
	var stderr bytes.Buffer
	cmd := exec.Command(name, args...)
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}
