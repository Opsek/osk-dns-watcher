package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// The one fake server is the only root server, and it answers with authority
// for every name, so each walk ends at the root. A name at or under the
// domain of the file then lies in the wrong zone; names under example. lie
// outside the domain, where no zone is expected, so they show the other
// findings alone.

var (
	expWWW  = cliRR("www.example.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.80")})
	expMail = cliRR("mail.example.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.81")})
	expCDN  = cliRR("cdn.example.", 300, dnswire.CNAME{Target: cliName("edge.example.")})
	// Its text tries to start an output line of its own.
	expTXT = cliRR("txt.example.", 300, dnswire.TXT{Strings: []string{"x\nfinding critical nameservers delegation corp.test. NS"}})
	expSOA = cliSOAOf("example.", 3600)
)

// expWorld is cliWorld with the names under example. that the tests ask.
func expWorld(q []byte, tcp bool) []byte {
	m, err := dnswire.Parse(q)
	if err != nil || len(m.Question) != 1 {
		return nil
	}
	name, qtype := strings.ToLower(m.Question[0].Name.String()), m.Question[0].Type
	aa := uint16(transportQR | transportAA)
	for _, r := range []dnswire.Record{expWWW, expMail, expTXT, expCDN} {
		if name == r.Name.String() && (qtype == r.Type() || r.Type() == dnswire.TypeCNAME) {
			return cliAnswer(q, aa, []dnswire.Record{r}, nil, nil)
		}
		if name == r.Name.String() {
			return cliAnswer(q, aa, nil, []dnswire.Record{expSOA}, nil)
		}
	}
	return cliWorld(q, tcp)
}

// expRootHost is how a seen line names a root server given with
// --root-server: its name is not known, so it prints as "-", although the
// answer lines of osk-dns-watcher check print that name as ".".
const expRootHost = "-"

func expHeader(domain string) string {
	return "# Snapshot of " + domain + " as seen now. Review every line: nothing in it is trusted until you pass this file to osk-dns-watcher check --expect."
}

func expFile(t *testing.T, text string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corp.test.expect")
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// expRun runs osk-dns-watcher and returns the exit code, the lines of standard output
// and standard error. In each unknown line it checks the received time and
// puts "T" in its place, and it checks that the failure detail is one quoted
// string, so that text from the network cannot start a line.
func expRun(t *testing.T, args ...string) (int, []string, string) {
	t.Helper()
	code, out, errOut := transportRun(args...)
	if out == "" {
		return code, nil, errOut
	}
	if !strings.HasSuffix(out, "\n") {
		t.Errorf("output does not end with a newline: %q", out)
	}
	var lines []string
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		f := strings.SplitN(line, " ", 10)
		if f[0] != "unknown" {
			lines = append(lines, line)
			continue
		}
		if len(f) != 10 || f[8] != "failure" {
			t.Errorf("unknown line %q is not a failure line of ten fields", line)
			lines = append(lines, line)
			continue
		}
		if _, err := time.Parse(cliTimeLayout, f[6]); err != nil {
			t.Errorf("line %q: received time %q is not in the form %s", line, f[6], cliTimeLayout)
		}
		_, quoted, _ := strings.Cut(f[9], " ")
		if detail, err := strconv.Unquote(quoted); err != nil || strconv.Quote(detail) != quoted {
			t.Errorf("line %q: the detail is not one quoted string", line)
		}
		f[6] = "T"
		lines = append(lines, strings.Join(f, " "))
	}
	return code, lines, errOut
}

// expNoQueries fails when the server received a query. A query of a check
// that was cancelled may arrive late, so it waits first.
func expNoQueries(t *testing.T, s *transportServer) {
	t.Helper()
	time.Sleep(200 * time.Millisecond)
	if n := len(s.queries); n != 0 {
		t.Errorf("the server received %d queries, want none", n)
	}
}

// Wrong use is found before the file is judged and before any check runs:
// the server, which may be asked and answers, gets no query.
func TestCheckExpectWrongUse(t *testing.T) {
	s := transportStart(t, expWorld)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\n")
	for _, args := range [][]string{
		{"--expect", file, "corp.test."},
		{"--expect", file, "corp.test.", "www.corp.test.", "A"},
		{"--expect", file, "--expect", file},
		{"--expect"},
		{"--expect", file, "--timeout", "0s"},
		{"--timeout", "soon", "--expect", file},
		{"--root-server", "ns1.corp.test", "--expect", file},
		{"--root-server", "127.0.0.1:99999", "--expect", file},
		{"--extra-range", "10.0.0.1", "--expect", file},
		{"--other", "--expect", file},
	} {
		args = slices.Concat([]string{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8"}, args)
		code, out, errOut := transportRun(args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "usage") || !strings.Contains(errOut, "osk-dns-watcher check") ||
			!strings.Contains(errOut, "--expect <file>") || !strings.Contains(errOut, "osk-dns-watcher snapshot") {
			t.Errorf("osk-dns-watcher %q: exit code %d, output %q, errors %q; want 2, nothing and the usage of check and snapshot",
				args, code, out, errOut)
		}
	}
	expNoQueries(t, s)
}

func TestSnapshotWrongUse(t *testing.T) {
	s := transportStart(t, expWorld)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\n")
	cases := [][]string{
		{},
		{"corp.test.", "www.corp.test."},
		{"corp.test.", "www.corp.test.", "A", "mail.corp.test."},
		{"a..b"},
		{"."},
		{"corp.test.", "a..b", "A"},
		{"corp.test.", "www.corp.test.", "NOTATYPE"},
		{"corp.test.", "--timeout", "1s"},
		{"--timeout", "0s", "corp.test."},
		{"--timeout", "soon", "corp.test."},
		{"--root-server", "ns1.corp.test", "corp.test."},
		{"--extra-range", "10.0.0.1", "corp.test."},
		{"--expect", file, "corp.test."},
		{"--other", "corp.test."},
	}
	// Types that no check may ask for.
	for _, qtype := range []string{"DS", "ANY", "OPT", "AXFR", "TYPE0"} {
		cases = append(cases, []string{"corp.test.", "www.corp.test.", "A", "corp.test.", qtype})
	}
	for _, args := range cases {
		args = slices.Concat([]string{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8"}, args)
		code, out, errOut := transportRun(args...)
		if code != 2 || out != "" || !strings.Contains(errOut, "usage") || !strings.Contains(errOut, "osk-dns-watcher snapshot") {
			t.Errorf("osk-dns-watcher %q: exit code %d, output %q, errors %q; want 2, nothing and the usage", args, code, out, errOut)
		}
	}
	if code, out, _ := transportRun("snapshot"); code != 2 || out != "" {
		t.Errorf("osk-dns-watcher snapshot: exit code %d, output %q; want 2 and nothing", code, out)
	}
	expNoQueries(t, s)
}

// expPadded is head, comment lines and tail, size octets in all; line is the
// number of the first line of tail.
func expPadded(head, tail string, size int) (text string, line int) {
	var b strings.Builder
	b.WriteString(head)
	for pad := size - len(head) - len(tail); pad > 0; {
		n := min(pad, 64)
		if pad-n == 1 {
			n-- // a comment line has at least two octets
		}
		b.WriteString("#" + strings.Repeat("x", n-2) + "\n")
		pad -= n
	}
	text = b.String()
	return text + tail, strings.Count(text, "\n") + 1
}

// A file that is not valid stops the run: no check runs and nothing goes to
// standard output.
func TestCheckExpectFileErrors(t *testing.T) {
	s := transportStart(t, expWorld)
	lines := []string{
		"domain corp.test.",
		"www.corp.test. A 10.53.0.81",
		"www.corp.test. A 10.53.0.82",
		"mail.corp.test A 10.53.0.82",
		"a.corp.test. DS none",
		"b.corp.test. MX in 10.0.0.0/8",
		"c.corp.test. A in 10.0.0.1/8",
		"d.corp.test. 300 A 10.53.0.81",
		"e.corp.test. OPT none",
		"f.corp.test. A 10.53.0.81 |",
		"# saved with a carriage return\r",
		"g.corp.test. NS like *.dnshost.test.",
	}
	many := expFile(t, strings.Join(lines, "\n")+"\n")
	limit := 4194304
	atLimit, last := expPadded("domain corp.test.\n", "www.corp.test A 10.53.0.81\n", limit)
	tooLarge, _ := expPadded("domain corp.test.\n", "corp.test. DS none\n", limit+1)
	cases := []struct {
		name, file string
		want       []string
	}{
		{"problems on lines", many, []string{
			":3: www.corp.test. A is already expected on line 2",
			`:4: "mail.corp.test" has no trailing dot`,
			":5: a DS set is checked only at the domain",
			":6: in is for A and AAAA only",
			":7: prefix 10.0.0.1/8 has bits after its length; write 10.0.0.0/8",
			`:8: "300" is not a type; the file has no TTL or class field`,
			":9: type OPT cannot be checked",
			":10: an empty record",
			":11: octet 0x0D is not printable ASCII",
		}},
		{"no domain line", expFile(t, "# only a comment\n\n"), []string{": no domain line"}},
		{"too large", expFile(t, tooLarge), []string{": the file is larger than 4194304 octets"}},
		// The whole file is read: the problem is on its last line.
		{"at the limit", expFile(t, atLimit), []string{":" + strconv.Itoa(last) + `: "www.corp.test" has no trailing dot`}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errOut := transportRun("check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", c.file)
			var want strings.Builder
			for _, w := range c.want {
				want.WriteString("osk-dns-watcher: " + c.file + w + "\n")
			}
			if code != 1 || out != "" || errOut != want.String() {
				t.Errorf("exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s", code, out, errOut, want.String())
			}
		})
	}

	// A file that cannot be read gives one line, the error. An empty name is
	// such a file, not wrong use.
	dir := t.TempDir()
	for _, file := range []string{filepath.Join(dir, "missing"), dir, ""} {
		code, out, errOut := transportRun("check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
		if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk-dns-watcher: ") || strings.Count(errOut, "\n") != 1 ||
			!strings.HasSuffix(errOut, "\n") {
			t.Errorf("--expect %s: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk-dns-watcher: ...\"",
				file, code, out, errOut)
		}
	}
	expNoQueries(t, s)
}

// expFIFO makes a FIFO, which holds whoever opens it to read until a writer
// comes. At the end of the test a writer lets such a reader go.
func expFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "corp.test.expect")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	return path
}

// expWithin calls osk-dns-watcher and fails the test unless it returns within limit, so
// that a hang fails the test and not the whole run.
func expWithin(t *testing.T, limit time.Duration, osk func() (int, string, string)) (code int, out, errOut string) {
	t.Helper()
	type outcome struct {
		code        int
		out, errOut string
	}
	done := make(chan outcome, 1)
	go func() {
		code, out, errOut := osk()
		done <- outcome{code, out, errOut}
	}()
	select {
	case o := <-done:
		return o.code, o.out, o.errOut
	case <-time.After(limit):
		t.Fatalf("osk-dns-watcher did not return within %v", limit)
		return 0, "", ""
	}
}

// A file that is not a regular file is refused before it is opened: a FIFO
// would hold the open until a writer comes.
func TestCheckExpectRefusesAFIFOAsTheFile(t *testing.T) {
	s := transportStart(t, expWorld)
	file := expFIFO(t)
	code, out, errOut := expWithin(t, 2*time.Second, func() (int, string, string) {
		return transportRun("check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	})
	if want := "osk-dns-watcher: " + file + ": is not a regular file\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	expNoQueries(t, s)
}

func TestCheckExpectOutput(t *testing.T) {
	s := transportStart(t, expWorld)
	// Out of canonical order on purpose: the checks follow the order of the
	// file as it is printed.
	file := expFile(t, `# A comment, then a blank line.

domain corp.test.
www.example. A 192.0.2.80
corp.test. DS none
txt.example. TXT none
www.shop.example. A 192.0.2.1
mail.example. A 192.0.2.80
cdn.example. A 192.0.2.80
`)
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	seen := "  seen " + s.addr + " " + expRootHost + " "
	cliCompare(t, lines, []string{
		"finding medium not-covered delegation corp.test. NS",
		"  expected -",
		seen + "ns1.corp.test. | ns2.corp.test.",
		"finding high record-set records cdn.example. A",
		"  expected 192.0.2.80",
		seen + "CNAME edge.example.",
		"finding high record-set records mail.example. A",
		"  expected 192.0.2.80",
		seen + "192.0.2.81",
		"unknown records www.shop.example. A 192.0.2.1:53 ns.shop.example. T - failure not-permitted *",
		"finding medium record-set records txt.example. TXT",
		"  expected none",
		seen + `"x\010finding critical nameservers delegation corp.test. NS"`,
		"checked corp.test. 7 sets: 4 findings, 1 unknown answers",
	})
}

// The second root server never answers. A check's findings come before the
// answers it could not read, and a failure is never a finding.
func TestCheckExpectFindingThenUnknown(t *testing.T) {
	s, silent := transportStart(t, cliWorld), transportStart(t, nil)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\n")
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--root-server", silent.addr,
		"--extra-range", "127.0.0.0/8", "--timeout", "300ms", "--expect", file)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliCompare(t, lines, []string{
		"finding medium not-covered delegation corp.test. NS",
		"  expected -",
		"  seen " + s.addr + " " + expRootHost + " ns1.corp.test. | ns2.corp.test.",
		"unknown delegation corp.test. NS " + silent.addr + " . T - failure timeout *",
		"unknown ds corp.test. DS " + silent.addr + " . T - failure timeout *",
		"checked corp.test. 2 sets: 1 findings, 2 unknown answers",
	})
}

var (
	expCapsNS   = cliRR("caps.example.", 3600, dnswire.NS{Host: cliName("NS.Caps.Example.")})
	expCapsGlue = cliRR("NS.Caps.Example.", 3600, dnswire.A{Addr: netip.MustParseAddr("192.0.2.1")})
)

// expCapsWorld is expWorld, with the names under caps.example. delegated to
// a server that cannot be asked and whose name the referral writes in
// capitals.
func expCapsWorld(q []byte, tcp bool) []byte {
	m, err := dnswire.Parse(q)
	if err == nil && len(m.Question) == 1 && strings.HasSuffix(strings.ToLower(m.Question[0].Name.String()), ".caps.example.") {
		return cliAnswer(q, transportQR, nil, []dnswire.Record{expCapsNS}, []dnswire.Record{expCapsGlue})
	}
	return expWorld(q, tcp)
}

// A server may send any case, and the file may be written in any: the unknown
// line prints both names in lower case, as every name of the findings is.
func TestCheckExpectUnknownInLowerCase(t *testing.T) {
	s := transportStart(t, expCapsWorld)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\nWWW.Caps.Example. A 192.0.2.1\n")
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliCompare(t, lines, []string{
		"finding medium not-covered delegation corp.test. NS",
		"  expected -",
		"  seen " + s.addr + " " + expRootHost + " ns1.corp.test. | ns2.corp.test.",
		"unknown records www.caps.example. A 192.0.2.1:53 ns.caps.example. T - failure not-permitted *",
		"checked corp.test. 3 sets: 1 findings, 1 unknown answers",
	})
}

// The fake server answers for www.corp.test. from the root zone, where the
// file expects the zone corp.test.: the data matches, but the zone does not.
func TestCheckExpectZoneFinding(t *testing.T) {
	s := transportStart(t, cliWorld)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\nwww.corp.test. A 192.0.2.80\n")
	code, lines, errOut := expRun(t, "check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	seen := "  seen " + s.addr + " " + expRootHost + " "
	cliCompare(t, lines, []string{
		"finding medium not-covered delegation corp.test. NS",
		"  expected -",
		seen + "ns1.corp.test. | ns2.corp.test.",
		"finding high zone records www.corp.test. A",
		"  expected corp.test.",
		seen + ".",
		"checked corp.test. 3 sets: 2 findings, 0 unknown answers",
	})
}

// A pair given twice in another case is one check. The NS set of the domain
// is not written, because its records check found it in the root zone.
func TestSnapshotOutput(t *testing.T) {
	s := transportStart(t, expWorld)
	code, lines, errOut := expRun(t, "snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.",
		"www.example.", "A", "www.shop.example.", "A", "WWW.Example.", "a")
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliCompare(t, lines, []string{
		expHeader("corp.test."),
		"domain corp.test.",
		"www.example. A 192.0.2.80",
		"corp.test. DS none",
		"# not written: www.shop.example. A: 192.0.2.1:53 ns.shop.example. gave no answer: not-permitted",
		"# not written: corp.test. NS: lies in zone .; add the pair . NS",
	})
}

func TestSnapshotAndExpectOutputFail(t *testing.T) {
	s := transportStart(t, expWorld)
	file := expFile(t, "domain corp.test.\ncorp.test. DS none\nwww.example. A 192.0.2.80\n")
	for _, args := range [][]string{
		{"snapshot", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "corp.test.", "www.example.", "A"},
		{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file},
	} {
		var errOut strings.Builder
		code := run(args, cliBrokenWriter{}, &errOut)
		e := errOut.String()
		if code != 1 || !strings.HasPrefix(e, "osk-dns-watcher: ") || !strings.Contains(e, "disk full") || strings.Count(e, "\n") != 1 ||
			!strings.HasSuffix(e, "\n") {
			t.Errorf("osk-dns-watcher %s: exit code %d, errors %q; want 1 and one line \"osk-dns-watcher: ...disk full\"", args[0], code, e)
		}
	}
}
