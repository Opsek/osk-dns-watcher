//go:build lab

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/expect"
)

// expLab returns the start of every lab address, "10.53.<LAB_ID>.", and puts
// the lab back into its base state when the test ends.
func expLab(t *testing.T) string {
	t.Helper()
	lab := os.Getenv("LAB_ID")
	if lab == "" {
		t.Fatal("LAB_ID is not set: this test runs in the runner of the lab")
	}
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	return "10.53." + lab + "."
}

// expOsk runs an osk command that starts from the lab root and may ask every
// lab address.
func expOsk(n, command string, args ...string) (int, string, string) {
	return transportRun(append([]string{command, "--root-server", n + "2", "--extra-range", n + "0/24"}, args...)...)
}

func expSame(t *testing.T, what, out string, want []string) {
	t.Helper()
	if text := strings.Join(want, "\n") + "\n"; out != text {
		t.Errorf("%s gave:\n%s\nwant:\n%s", what, out, text)
	}
}

// expSnapshot runs osk snapshot, which must write a file with every set.
func expSnapshot(t *testing.T, n string, args ...string) string {
	t.Helper()
	code, out, errOut := expOsk(n, "snapshot", args...)
	if code != 0 || errOut != "" {
		t.Fatalf("osk snapshot %s: exit code %d, errors %q; want 0 and none; output:\n%s", strings.Join(args, " "), code, errOut, out)
	}
	return out
}

func expWrite(t *testing.T, dir, name, text string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// expCheck compares the whole output, so a finding that is missing, extra or
// out of order fails.
func expCheck(t *testing.T, n, file string, code int, want ...string) {
	t.Helper()
	got, out, errOut := expOsk(n, "check", "--expect", file)
	if got != code || errOut != "" {
		t.Errorf("osk check --expect %s: exit code %d, errors %q; want %d and none", file, got, errOut, code)
	}
	expSame(t, "osk check --expect "+file, out, want)
}

func expCtl(t *testing.T, args ...string) {
	t.Helper()
	dataTool(t, "labctl", args...)
}

// expSnapshotLines is a snapshot of corp.test. that holds the parent's NS
// set and the given lines.
func expSnapshotLines(sets ...string) []string {
	return append([]string{
		expHeader("corp.test."),
		"domain corp.test.",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
	}, sets...)
}

func TestSnapshotThenCheck(t *testing.T) {
	n := expLab(t)
	snap := expSnapshot(t, n, "corp.test.", "www.corp.test.", "A")
	expSame(t, "osk snapshot", snap, expSnapshotLines("corp.test. DS none", "www.corp.test. A "+n+"81"))
	file := expWrite(t, t.TempDir(), "corp.test.expect", snap)
	expCheck(t, n, file, 0, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")

	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", n+"99")
	expCheck(t, n, file, 1,
		"finding critical nameservers delegation corp.test. NS",
		"  expected ns1.corp.test. | ns2.corp.test.",
		"  seen "+n+"3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test.",
		"finding high record-set records www.corp.test. A",
		"  expected "+n+"81",
		"  seen "+n+"12:53 ns2.dnshost.test. "+n+"99",
		"checked corp.test. 4 sets: 2 findings, 0 unknown answers")
}

// The child zone still holds its own NS set, which matches: only the parent
// shows the new name servers.
func TestNameServersReplacedSeen(t *testing.T) {
	n := expLab(t)
	file := expWrite(t, t.TempDir(), "corp.test.expect", expSnapshot(t, n, "corp.test.", "www.corp.test.", "A"))
	expCheck(t, n, file, 0, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")

	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCheck(t, n, file, 1,
		"finding critical nameservers delegation corp.test. NS",
		"  expected ns1.corp.test. | ns2.corp.test.",
		"  seen "+n+"3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test.",
		"checked corp.test. 4 sets: 1 findings, 0 unknown answers")

	expCtl(t, "delegate", "corp.test.", "ns1.corp.test.", "ns2.corp.test.")
	expCheck(t, n, file, 0, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")
}

// Each change stays, so each check also shows the ones before it, in the
// order of the file.
func TestRecordChangedSeen(t *testing.T) {
	n := expLab(t)
	file := expWrite(t, t.TempDir(), "corp.test.expect", expSnapshot(t, n, "corp.test.",
		"www.corp.test.", "A", "corp.test.", "MX", "corp.test.", "TXT", "mail.corp.test.", "A"))
	const sets = "checked corp.test. 7 sets: "
	expCheck(t, n, file, 0, sets+"0 findings, 0 unknown answers")

	www := func(seen ...string) []string {
		return append([]string{"finding high record-set records www.corp.test. A", "  expected " + n + "81"}, seen...)
	}
	expCtl(t, "set", "ns2", "www.corp.test.", "300", "A", n+"99")
	expCheck(t, n, file, 1, slices.Concat(www("  seen "+n+"12:53 ns2.corp.test. "+n+"99"),
		[]string{sets + "1 findings, 0 unknown answers"})...)

	expCtl(t, "set", "ns1", "www.corp.test.", "300", "A", n+"99")
	wwwBoth := www("  seen "+n+"11:53 ns1.corp.test. "+n+"99", "  seen "+n+"12:53 ns2.corp.test. "+n+"99")
	expCheck(t, n, file, 1, slices.Concat(wwwBoth, []string{sets + "1 findings, 0 unknown answers"})...)

	expCtl(t, "set", "both", "corp.test.", "300", "TXT", `"v=spf1 +all"`)
	txt := []string{
		"finding medium spf records corp.test. TXT",
		`  expected "v=spf1 mx -all"`,
		"  seen " + n + `11:53 ns1.corp.test. "v=spf1 +all"`,
		"  seen " + n + `12:53 ns2.corp.test. "v=spf1 +all"`,
		"  weaker all gives pass in place of fail",
	}
	expCheck(t, n, file, 1, slices.Concat(txt, wwwBoth, []string{sets + "2 findings, 0 unknown answers"})...)

	// The name then has no record at all, so both servers answer "no such
	// name"; no data would print the same.
	expCtl(t, "del", "both", "mail.corp.test.", "A")
	mail := []string{
		"finding high record-set records mail.corp.test. A",
		"  expected " + n + "82",
		"  seen " + n + "11:53 ns1.corp.test. none",
		"  seen " + n + "12:53 ns2.corp.test. none",
	}
	expCheck(t, n, file, 1, slices.Concat(txt, mail, wwwBoth, []string{sets + "3 findings, 0 unknown answers"})...)
}

func TestSnapshotDiffIsOneLine(t *testing.T) {
	n := expLab(t)
	pairs := []string{"corp.test.", "www.corp.test.", "A", "corp.test.", "MX", "corp.test.", "TXT", "corp.test.", "CAA",
		"cdn.corp.test.", "CNAME", "_dmarc.corp.test.", "TXT"}
	s1 := expSnapshot(t, n, pairs...)
	expSame(t, "the first osk snapshot", s1, expSnapshotLines(
		"corp.test. MX 10 mail.corp.test.",
		`corp.test. TXT "v=spf1 mx -all"`,
		"corp.test. DS none",
		`corp.test. CAA 0 issue "ca.test"`,
		`_dmarc.corp.test. TXT "v=DMARC1; p=reject"`,
		"cdn.corp.test. CNAME edge.dnshost.test.",
		"www.corp.test. A "+n+"81",
	))

	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"85")
	s2 := expSnapshot(t, n, pairs...)
	a, b := strings.Split(s1, "\n"), strings.Split(s2, "\n")
	var diff []string
	for i := range min(len(a), len(b)) {
		if a[i] != b[i] {
			diff = append(diff, "- "+a[i], "+ "+b[i])
		}
	}
	want := []string{"- www.corp.test. A " + n + "81", "+ www.corp.test. A " + n + "85"}
	if len(a) != len(b) || strings.Join(diff, "\n") != strings.Join(want, "\n") {
		t.Errorf("the snapshots differ in:\n%s\nwant only:\n%s\nfirst:\n%s\nsecond:\n%s",
			strings.Join(diff, "\n"), strings.Join(want, "\n"), s1, s2)
	}

	// Without its header, the snapshot is the file as osk prints it.
	f, err := expect.Parse([]byte(s1))
	if err != nil {
		t.Fatalf("the snapshot is not a valid file: %v", err)
	}
	if _, body, _ := strings.Cut(s1, "\n"); f.String() != body {
		t.Errorf("the snapshot without its header:\n%s\nthe file as printed:\n%s", body, f.String())
	}
}

// A snapshot only shows what the servers say: it writes no file, and it
// trusts nothing, so a check with the older file still reports the change.
func TestSnapshotTrustsNothing(t *testing.T) {
	n := expLab(t)
	w := t.TempDir()
	cwd, home, tmp := t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", tmp)
	t.Chdir(cwd)

	s1 := expSnapshot(t, n, "corp.test.", "www.corp.test.", "A")
	first := expWrite(t, w, "first.expect", s1)
	expCtl(t, "set", "both", "www.corp.test.", "300", "A", n+"99")
	s2 := expSnapshot(t, n, "corp.test.", "www.corp.test.", "A")
	expSame(t, "the second osk snapshot", s2, expSnapshotLines("corp.test. DS none", "www.corp.test. A "+n+"99"))
	second := expWrite(t, w, "second.expect", s2)

	expCheck(t, n, first, 1,
		"finding high record-set records www.corp.test. A",
		"  expected "+n+"81",
		"  seen "+n+"11:53 ns1.corp.test. "+n+"99",
		"  seen "+n+"12:53 ns2.corp.test. "+n+"99",
		"checked corp.test. 4 sets: 1 findings, 0 unknown answers")
	expCheck(t, n, second, 0, "checked corp.test. 4 sets: 0 findings, 0 unknown answers")

	for _, dir := range []string{cwd, home, tmp} {
		entries, err := os.ReadDir(dir)
		if err != nil || len(entries) != 0 {
			t.Errorf("folder %s: %d entries, error %v; want it empty", dir, len(entries), err)
		}
	}
}

// Sets that the file does not name are never reported as fine, even when
// they change.
func TestUncoveredNameNotTrusted(t *testing.T) {
	n := expLab(t)
	file := expWrite(t, t.TempDir(), "corp.test.expect", "domain corp.test.\nwww.corp.test. A "+n+"81\n")
	uncovered := func(ns string) []string {
		return []string{
			"finding medium not-covered delegation corp.test. NS",
			"  expected -",
			"  seen " + n + "3:53 ns.test. " + ns,
			"finding medium not-covered ds corp.test. DS",
			"  expected -",
			"  seen " + n + "3:53 ns.test. none",
			"checked corp.test. 3 sets: 2 findings, 0 unknown answers",
		}
	}
	expCheck(t, n, file, 1, uncovered("ns1.corp.test. | ns2.corp.test.")...)

	expCtl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")
	expCheck(t, n, file, 1, uncovered("ns1.dnshost.test. | ns2.dnshost.test.")...)
}
