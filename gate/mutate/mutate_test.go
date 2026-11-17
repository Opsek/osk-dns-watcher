package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// The tests run the built command on small modules under testdata/, each
// copied first, and compare what it prints. Nothing here reads the code of the
// command, so a wrong command fails them.

const mutTestSurvivedLine = "FAIL mutate: 1 mutant survived and is not listed in gate/mutants.txt"

var mutTestBin string

func TestMain(m *testing.M) {
	os.Exit(mutTestMainRun(m))
}

func mutTestMainRun(m *testing.M) int {
	dir, err := os.MkdirTemp("", "mutate-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer func() { _ = os.RemoveAll(dir) }()
	mutTestBin = filepath.Join(dir, "mutate")
	build := exec.Command("go", "build", "-buildvcs=false", "-o", mutTestBin, ".")
	if out, err := build.CombinedOutput(); err != nil {
		fmt.Fprintf(os.Stderr, "cannot build the command: %v\n%s", err, out)
		return 1
	}
	return m.Run()
}

// mutTestEnv keeps the fixtures independent of the machine: no network, no
// workspace, no other toolchain, and no flags that assume a vendor folder.
func mutTestEnv(extra ...string) []string {
	env := append(os.Environ(), "GOFLAGS=", "GOWORK=off", "GOPROXY=off", "GOTOOLCHAIN=local", "CGO_ENABLED=0")
	return append(env, extra...)
}

// mutTestCopy copies testdata/<name> to a new folder and returns it.
func mutTestCopy(t *testing.T, name string) string {
	t.Helper()
	src := filepath.Join("testdata", name)
	dst := filepath.Join(t.TempDir(), name)
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		b, err := os.ReadFile(p)
		if err != nil {
			return err
		}
		return os.WriteFile(target, b, 0o644)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dst
}

func mutTestWriteList(t *testing.T, root, text string) {
	t.Helper()
	p := filepath.Join(root, "gate", "mutants.txt")
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(text), 0o644); err != nil {
		t.Fatal(err)
	}
}

// mutTestExec runs the command in dir and returns what it printed, both
// streams in the order written, and its exit code.
func mutTestExec(t *testing.T, dir string, env []string, args ...string) (string, int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	cmd := exec.CommandContext(ctx, mutTestBin, args...)
	cmd.Dir = dir
	cmd.Env = env
	var buf bytes.Buffer
	cmd.Stdout = &buf
	cmd.Stderr = &buf
	err := cmd.Run()
	if ctx.Err() != nil {
		t.Fatalf("the command did not stop in 5 minutes; output so far:\n%s", buf.String())
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if !errors.As(err, &exit) {
			t.Fatal(err)
		}
		code = exit.ExitCode()
	}
	return buf.String(), code
}

// mutTestRun writes the list, then runs the command from the root with the
// list gate/mutants.txt. Two workers, unless the arguments name a number.
func mutTestRun(t *testing.T, root, list string, args ...string) (string, int) {
	t.Helper()
	mutTestWriteList(t, root, list)
	return mutTestRunKeepList(t, root, nil, args...)
}

func mutTestRunKeepList(t *testing.T, root string, env []string, args ...string) (string, int) {
	t.Helper()
	full := []string{"--root", root, "--list", "gate/mutants.txt"}
	if !slices.Contains(args, "--workers") {
		full = append(full, "--workers", "2")
	}
	return mutTestExec(t, root, mutTestEnv(env...), append(full, args...)...)
}

var mutTestTimeRe = regexp.MustCompile(`(, score [0-9.]+%), \S+$`)

// mutTestLines splits the output and replaces the run time, the one thing
// that differs between two runs, with T.
func mutTestLines(out string) []string {
	lines := strings.Split(strings.TrimSuffix(out, "\n"), "\n")
	for i, l := range lines {
		if strings.HasPrefix(l, "mutate ") {
			lines[i] = mutTestTimeRe.ReplaceAllString(l, "${1}, T")
		}
	}
	return lines
}

func mutTestSummary(folder string, mutants, notViable, killed, timedOut, survived, listed int, score string) string {
	return fmt.Sprintf("mutate %s: %d mutants, %d not viable, %d killed (%d timed out), %d survived (%d listed), score %s, T",
		folder, mutants, notViable, killed, timedOut, survived, listed, score)
}

// mutTestMatch compares a printed line with a wanted one. "{?}" in a wanted
// line stands for any text.
func mutTestMatch(got, want string) bool {
	before, after, found := strings.Cut(want, "{?}")
	if !found {
		return got == want
	}
	return len(got) > len(before)+len(after) && strings.HasPrefix(got, before) && strings.HasSuffix(got, after)
}

// mutTestCompare compares the whole output. With looseLast the last line
// need only start with "FAIL mutate: ", for a count that the text of the
// line puts in the plural.
func mutTestCompare(t *testing.T, out string, want []string, looseLast bool) {
	t.Helper()
	got := mutTestLines(out)
	if looseLast {
		if len(got) == 0 || !strings.HasPrefix(got[len(got)-1], "FAIL mutate: ") {
			t.Errorf("the last line is not a FAIL mutate line; output:\n%s", out)
			return
		}
		got, want = got[:len(got)-1], want[:len(want)-1]
	}
	ok := len(got) == len(want)
	for i := 0; ok && i < len(got); i++ {
		ok = mutTestMatch(got[i], want[i])
	}
	if !ok {
		t.Errorf("output:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// mutTestProblem reports whether the output holds a list problem, with or
// without the words FAIL mutate before it.
func mutTestProblem(out, text string) bool {
	for _, l := range mutTestLines(out) {
		if l == text || l == "FAIL mutate: "+text {
			return true
		}
	}
	return false
}

func mutTestHasLine(out, want string) bool {
	return slices.ContainsFunc(mutTestLines(out), func(l string) bool { return mutTestMatch(l, want) })
}

// mutTestFailed requires exit 1, a FAIL mutate line and no ok mutate line.
func mutTestFailed(t *testing.T, out string, code int) {
	t.Helper()
	if code != 1 {
		t.Errorf("exit code %d, want 1; output:\n%s", code, out)
	}
	if !slices.ContainsFunc(mutTestLines(out), func(l string) bool { return strings.HasPrefix(l, "FAIL mutate: ") }) {
		t.Errorf("no FAIL mutate line in:\n%s", out)
	}
	if mutTestHasLine(out, "ok mutate") {
		t.Errorf("the line ok mutate is printed in:\n%s", out)
	}
}

// Each word of the mutation table, once in a package whose tests kill the
// mutant and once in a package whose tests do not. A command that says killed
// when no test failed passes the strong rows only if it also passes the weak
// ones, and the weak ones name the survivor by its exact ID and line.
func TestJudgesEachMutationWord(t *testing.T) {
	t.Parallel()
	killedAll := func(folder string, n int) []string {
		return []string{mutTestSummary(folder, n, 0, n, 0, 0, 0, "100.0%"), "ok mutate"}
	}
	oneSurvivor := func(folder string, n int, score, id string) []string {
		return []string{mutTestSummary(folder, n, 0, n-1, 0, 1, 0, score), "survived " + id, mutTestSurvivedLine}
	}
	cases := []struct {
		name, fixture string
		folders       []string
		code          int
		want          []string
		looseLast     bool
	}{
		{"negate killed", "negate", []string{"strong"}, 0, killedAll("strong", 2), false},
		{"negate survives", "negate", []string{"weak"}, 1,
			oneSurvivor("weak", 2, "50.0%", `weak/zz.go IsSet negate "x != 0" (line 5: != to ==)`), false},
		{"boundary killed, external test package", "boundary", []string{"strong"}, 0, killedAll("strong", 4), false},
		{"boundary survives", "boundary", []string{"weak"}, 1,
			oneSurvivor("weak", 4, "75.0%", `weak/zz.go Positive boundary "x > 0" (line 3: > to >=)`), false},
		{"all four ordering operators killed", "ops", []string{"strong"}, 0, killedAll("strong", 8), false},
		{"all four ordering operators survive on their boundary", "ops", []string{"weak"}, 1, []string{
			mutTestSummary("weak", 8, 0, 4, 0, 4, 0, "50.0%"),
			`survived weak/zz.go Lt boundary "x < 0" (line 3: < to <=)`,
			`survived weak/zz.go Le boundary "x <= 0" (line 5: <= to <)`,
			`survived weak/zz.go Gt boundary "x > 0" (line 7: > to >=)`,
			`survived weak/zz.go Ge boundary "x >= 0" (line 9: >= to >)`,
			"FAIL mutate: ",
		}, true},
		{"and-or killed", "andor", []string{"strong"}, 0, killedAll("strong", 3), false},
		{"and-or survives on &&, score rounds to one decimal", "andor", []string{"weak"}, 1,
			oneSurvivor("weak", 3, "66.7%", `weak/zz.go Both and-or "a && b" (line 3: && to ||)`), false},
		{"and-or survives on ||", "andor", []string{"weakor"}, 1,
			oneSurvivor("weakor", 3, "66.7%", `weakor/zz.go Either and-or "a || b" (line 5: || to &&)`), false},
		{"not killed", "not", []string{"strong"}, 0, killedAll("strong", 2), false},
		{"not survives", "not", []string{"weak"}, 1,
			oneSurvivor("weak", 2, "50.0%", `weak/zz.go Denied not "!open" (line 5: {?})`), false},
		{"bool killed", "bool", []string{"strong"}, 0, killedAll("strong", 2), false},
		{"bool survives", "bool", []string{"weak"}, 1,
			oneSurvivor("weak", 2, "50.0%", `weak/zz.go Off bool "false" (line 5: {?})`), false},
		{"arith killed, and a string literal operand is no mutant", "arith", []string{"strong"}, 0, killedAll("strong", 2), false},
		{"arith survives on +", "arith", []string{"weakadd"}, 1,
			oneSurvivor("weakadd", 2, "50.0%", `weakadd/zz.go Add arith "a + b" (line 3: + to -)`), false},
		{"arith survives on -", "arith", []string{"weaksub"}, 1,
			oneSurvivor("weaksub", 2, "50.0%", `weaksub/zz.go Sub arith "a - b" (line 5: - to +)`), false},
		{"drop-call killed, and a call to panic is no mutant", "dropcall", []string{"strong"}, 0, killedAll("strong", 2), false},
		{"drop-call survives", "dropcall", []string{"weak"}, 1,
			oneSurvivor("weak", 2, "50.0%", `weak/zz.go Pair drop-call "b.inc()" (line 9: {?})`), false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out, code := mutTestRun(t, mutTestCopy(t, c.fixture), "", c.folders...)
			if code != c.code {
				t.Errorf("exit code %d, want %d", code, c.code)
			}
			mutTestCompare(t, out, c.want, c.looseLast)
		})
	}
}

// The IDs of one file: a method, a node outside any function, the suffix #2
// for an equal ID, and files in sorted order. Every mutant survives, so every
// ID is printed.
func TestIDsOfMethodsOutsideFunctionsAndRepeats(t *testing.T) {
	t.Parallel()
	out, code := mutTestRun(t, mutTestCopy(t, "ids"), "", "zz")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	mutTestCompare(t, out, mutTestIDsOutput(), true)
}

func mutTestIDsOutput() []string {
	return []string{
		mutTestSummary("zz", 5, 0, 0, 0, 5, 0, "0.0%"),
		`survived zz/a.go Late negate "x == 2" (line 3: == to !=)`,
		`survived zz/zz.go - bool "false" (line 3: {?})`,
		`survived zz/zz.go Gauge.Full negate "n == g.max" (line 7: == to !=)`,
		`survived zz/zz.go Pick negate "x == 1" (line 10: == to !=)`,
		`survived zz/zz.go Pick negate "x == 1"#2 (line 13: == to !=)`,
		"FAIL mutate: ",
	}
}

// A node longer than 60 octets is cut. The cut text is quoted whole, and the
// ID that is printed must be accepted back in the list.
func TestLongNodeIsCutAndItsIDIsAcceptedInTheList(t *testing.T) {
	t.Parallel()
	const node = "candidateRecord.PreviousName == candidateRecord.CurrentNameValue"
	root := mutTestCopy(t, "long")
	out, code := mutTestRun(t, root, "", "zz")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	cut := node[:60]
	re := regexp.MustCompile(`^survived (zz/zz\.go Changed negate ("` + regexp.QuoteMeta(cut) + `\.\.\."|"` +
		regexp.QuoteMeta(cut) + `"\.\.\.)) \(line 6: == to !=\)$`)
	var id string
	for _, l := range mutTestLines(out) {
		if m := re.FindStringSubmatch(l); m != nil {
			id = m[1]
		}
	}
	if id == "" {
		t.Fatalf("no survivor line with the first 60 octets of the node, cut; output:\n%s", out)
	}
	out, code = mutTestRun(t, root, id+" equivalent: planted\n", "zz")
	want := []string{mutTestSummary("zz", 2, 0, 1, 0, 1, 1, "50.0%"), "ok mutate"}
	if code != 0 {
		t.Errorf("exit code %d with the ID listed, want 0", code)
	}
	mutTestCompare(t, out, want, false)
}

// A mutant that does not build is counted, and is neither killed nor a
// survivor. The score leaves it out of the divisor.
func TestMutantThatDoesNotBuildIsNotViable(t *testing.T) {
	t.Parallel()
	out, code := mutTestRun(t, mutTestCopy(t, "mixed"), "", "zz")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	mutTestCompare(t, out, []string{
		mutTestSummary("zz", 3, 1, 1, 0, 1, 0, "50.0%"),
		`survived zz/zz.go IsSet negate "x != 0" (line 7: != to ==)`,
		mutTestSurvivedLine,
	}, false)
}

// Only a mutant that survives can be listed.
func TestListLineForNotViableOrKilledMutantIsStale(t *testing.T) {
	t.Parallel()
	list := `zz/zz.go IsSet negate "x != 0" equivalent: planted
zz/zz.go Join arith "a + b" equivalent: planted
zz/zz.go IsZero negate "x == 0" equivalent: planted
`
	out, code := mutTestRun(t, mutTestCopy(t, "mixed"), list, "zz")
	mutTestFailed(t, out, code)
	for _, n := range []int{2, 3} {
		text := fmt.Sprintf("gate/mutants.txt:%d: no surviving mutant has this id", n)
		if !mutTestProblem(out, text) {
			t.Errorf("no line %q in:\n%s", text, out)
		}
	}
	if mutTestProblem(out, "gate/mutants.txt:1: no surviving mutant has this id") {
		t.Errorf("line 1 names a survivor and must not be stale:\n%s", out)
	}
}

// A package whose tests cannot run must never give killed. The command ends
// the run with a FAIL mutate line that says why, and exits 1.
func TestPackageWhoseTestsDoNotRunIsNeverKilled(t *testing.T) {
	t.Parallel()
	killedRe := regexp.MustCompile(`^mutate .* [1-9][0-9]* killed`)
	cases := []struct {
		name, fixture, want string
	}{
		{"a failing test", "fails", "FAIL mutate: the tests of zz fail without a mutant"},
		{"a test binary that exits 1 before any test", "testmain", "FAIL mutate: the tests of zz fail without a mutant"},
		{"a test file that does not build", "nobuild", "FAIL mutate: {?}"},
		{"no tests", "notests", "FAIL mutate: zz has no tests"},
		{"no Go files", "nogofiles", "FAIL mutate: zz has no Go files"},
		{"no mutants", "nomutants", "FAIL mutate: zz has no mutants"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Parallel()
			out, code := mutTestRun(t, mutTestCopy(t, c.fixture), "", "zz")
			mutTestFailed(t, out, code)
			if !mutTestHasLine(out, c.want) {
				t.Errorf("no line %q in:\n%s", c.want, out)
			}
			for _, l := range mutTestLines(out) {
				if killedRe.MatchString(l) {
					t.Errorf("a mutant is reported killed: %q", l)
				}
			}
		})
	}
}

// A test that never returns is stopped after at least 20 seconds, as the
// rule says for a baseline that takes no time, and the mutant counts as killed
// and as timed out.
func TestHangingTestIsStoppedAfterTheTimeAndCountsAsTimedOut(t *testing.T) {
	t.Parallel()
	root := mutTestCopy(t, "hang")
	start := time.Now()
	out, code := mutTestRun(t, root, "", "zz")
	elapsed := time.Since(start)
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	mutTestCompare(t, out, []string{mutTestSummary("zz", 3, 0, 3, 1, 0, 0, "100.0%"), "ok mutate"}, false)
	if elapsed < 19*time.Second {
		t.Errorf("finished in %v: a hanging test must be given at least 20 seconds", elapsed)
	}
}

// The list: what passes, what fails, and the exact text of each problem.
func TestListOfAcceptedSurvivors(t *testing.T) {
	t.Parallel()
	const id = `zz/zz.go Positive boundary "x > 0"`
	const survivor = `survived ` + id + ` (line 3: > to >=)`
	passes := []struct{ name, list string }{
		{"equivalent, with a comment and a blank line", "# a comment\n\n" + id + " equivalent: planted\n"},
		{"unreachable", id + " unreachable: planted because nothing calls it\n"},
		{"open", id + " open: planted\n"},
		// The folder of the run is zz; zzz and other are not inside it.
		{"lines of other folders are not stale", id + " equivalent: planted\n" +
			"other/other.go F negate \"a == b\" equivalent: planted\n" +
			"zzz/zz.go F negate \"a == b\" equivalent: planted\n"},
	}
	for _, c := range passes {
		t.Run("passes: "+c.name, func(t *testing.T) {
			t.Parallel()
			out, code := mutTestRun(t, mutTestCopy(t, "listcases"), c.list, "zz")
			if code != 0 {
				t.Errorf("exit code %d, want 0", code)
			}
			mutTestCompare(t, out, []string{mutTestSummary("zz", 2, 0, 1, 0, 1, 1, "50.0%"), "ok mutate"}, false)
		})
	}

	t.Run("an unlisted survivor fails with the line to list", func(t *testing.T) {
		t.Parallel()
		out, code := mutTestRun(t, mutTestCopy(t, "listcases"), "", "zz")
		if code != 1 {
			t.Errorf("exit code %d, want 1", code)
		}
		mutTestCompare(t, out, []string{mutTestSummary("zz", 2, 0, 1, 0, 1, 0, "50.0%"), survivor, mutTestSurvivedLine}, false)
	})

	problems := []struct{ name, list, line string }{
		{"a line that matches no survivor", id + " equivalent: planted\n" + `zz/zz.go Positive negate "x > 0" equivalent: planted` + "\n",
			"gate/mutants.txt:2: no surviving mutant has this id"},
		{"a reason that starts with another word", id + " why not\n",
			"gate/mutants.txt:1: the reason must start with equivalent:, unreachable: or open:"},
		{"a reason without the colon", id + " equivalent planted\n",
			"gate/mutants.txt:1: the reason must start with equivalent:, unreachable: or open:"},
		{"an unknown mutation word", `zz/zz.go Positive flip "x > 0" equivalent: planted` + "\n",
			"gate/mutants.txt:1: unknown mutation flip"},
		{"a line with too few fields", "zz/zz.go Positive boundary\n",
			"gate/mutants.txt:1: want <file> <func> <word> <quoted> <reason>"},
		{"a line without a reason", id + "\n",
			"gate/mutants.txt:1: want <file> <func> <word> <quoted> <reason>"},
		{"the same ID twice", id + " equivalent: planted\n" + id + " equivalent: planted\n",
			"gate/mutants.txt:2: already listed on line 1"},
	}
	for _, c := range problems {
		t.Run("fails: "+c.name, func(t *testing.T) {
			t.Parallel()
			out, code := mutTestRun(t, mutTestCopy(t, "listcases"), c.list, "zz")
			mutTestFailed(t, out, code)
			if !mutTestProblem(out, c.line) {
				t.Errorf("no line %q in:\n%s", c.line, out)
			}
		})
	}
}

// Every ID that the command prints for a survivor is the text to list,
// including the suffix #2 and a method.
func TestPrintedIDsAreAcceptedBackInTheList(t *testing.T) {
	t.Parallel()
	list := `zz/a.go Late negate "x == 2" equivalent: planted
zz/zz.go - bool "false" unreachable: planted
zz/zz.go Gauge.Full negate "n == g.max" equivalent: planted
zz/zz.go Pick negate "x == 1" equivalent: planted
zz/zz.go Pick negate "x == 1"#2 equivalent: planted
`
	out, code := mutTestRun(t, mutTestCopy(t, "ids"), list, "zz")
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	mutTestCompare(t, out, []string{mutTestSummary("zz", 5, 0, 0, 0, 5, 5, "0.0%"), "ok mutate"}, false)
}

// Two folders in one run: a summary line for each, in the order given, and
// one verdict at the end.
func TestTwoFoldersGiveOneSummaryEachAndOneVerdict(t *testing.T) {
	t.Parallel()
	out, code := mutTestRun(t, mutTestCopy(t, "twofolders"), "", "a", "b")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	mutTestCompare(t, out, []string{
		mutTestSummary("a", 2, 0, 2, 0, 0, 0, "100.0%"),
		mutTestSummary("b", 2, 0, 1, 0, 1, 0, "50.0%"),
		`survived b/zz.go Both and-or "a && b" (line 3: && to ||)`,
		mutTestSurvivedLine,
	}, false)
}

// Mutants are made only in the non-test files directly in the given folder:
// not in a test file, not in testdata, not in a sub-folder, and not in a
// folder that was not given. The count says it.
func TestOnlyNonTestFilesDirectlyInTheFolderAreMutated(t *testing.T) {
	t.Parallel()
	out, code := mutTestRun(t, mutTestCopy(t, "scope"), "", "zz")
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	mutTestCompare(t, out, []string{mutTestSummary("zz", 2, 0, 2, 0, 0, 0, "100.0%"), "ok mutate"}, false)
}

// A test that reads a file by a relative path passes only when the test binary
// runs in the folder of the package.
func TestTestBinaryRunsInTheFolderOfThePackage(t *testing.T) {
	t.Parallel()
	out, code := mutTestRun(t, mutTestCopy(t, "cwd"), "", "zz")
	if code != 0 {
		t.Errorf("exit code %d, want 0", code)
	}
	mutTestCompare(t, out, []string{mutTestSummary("zz", 2, 0, 2, 0, 0, 0, "100.0%"), "ok mutate"}, false)
}

// Two runs, and runs with other worker counts, print the same lines in the
// same order. Only the time differs.
func TestOutputDoesNotDependOnRunOrWorkers(t *testing.T) {
	t.Parallel()
	for _, fixture := range []string{"ids", "mixed", "ops"} {
		t.Run(fixture, func(t *testing.T) {
			t.Parallel()
			folder := "zz"
			if fixture == "ops" {
				folder = "weak"
			}
			root := mutTestCopy(t, fixture)
			mutTestWriteList(t, root, "")
			var first []string
			for i, workers := range []string{"1", "4", "4", "1"} {
				out, code := mutTestRunKeepList(t, root, nil, "--workers", workers, folder)
				if code != 1 {
					t.Fatalf("run %d: exit code %d, want 1", i, code)
				}
				lines := mutTestLines(out)
				if i == 0 {
					first = lines
					if len(lines) < 3 || !strings.HasPrefix(lines[0], "mutate "+folder+": ") {
						t.Fatalf("run 0 printed no summary and survivors:\n%s", out)
					}
					continue
				}
				if !slices.Equal(lines, first) {
					t.Errorf("run %d with %s workers differs:\n%s\nfirst run:\n%s", i, workers, strings.Join(lines, "\n"), strings.Join(first, "\n"))
				}
			}
		})
	}
}

var mutTestSurvivorRe = regexp.MustCompile(`^(survived .*) \(line ([0-9]+): (.*)\)$`)

// Lines added above a mutant move its line, and leave its ID as it was.
func TestIDDoesNotChangeWhenLinesAreAddedAbove(t *testing.T) {
	t.Parallel()
	const added = 4
	idsAndLines := func(out string) (ids []string, lines []int) {
		for _, l := range mutTestLines(out) {
			if m := mutTestSurvivorRe.FindStringSubmatch(l); m != nil {
				n, err := strconv.Atoi(m[2])
				if err != nil {
					t.Fatal(err)
				}
				ids = append(ids, m[1])
				lines = append(lines, n)
			}
		}
		return ids, lines
	}

	before := mutTestCopy(t, "ids")
	idsBefore, linesBefore := idsAndLines(func() string { out, _ := mutTestRun(t, before, "", "zz"); return out }())

	after := mutTestCopy(t, "ids")
	p := filepath.Join(after, "zz", "zz.go")
	src, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	padded := strings.Replace(string(src), "package zz\n", "package zz\n\n// padding\n// padding\n// padding\n", 1)
	if err := os.WriteFile(p, []byte(padded), 0o644); err != nil {
		t.Fatal(err)
	}
	idsAfter, linesAfter := idsAndLines(func() string { out, _ := mutTestRun(t, after, "", "zz"); return out }())

	if len(idsBefore) != 5 {
		t.Fatalf("got %d survivors before, want 5: %q", len(idsBefore), idsBefore)
	}
	if !slices.Equal(idsBefore, idsAfter) {
		t.Errorf("IDs changed:\n before %q\n after  %q", idsBefore, idsAfter)
	}
	for i := range linesBefore {
		want := linesBefore[i]
		if strings.HasPrefix(idsBefore[i], "survived zz/zz.go ") {
			want += added
		}
		if i < len(linesAfter) && linesAfter[i] != want {
			t.Errorf("%s: line %d after, want %d", idsBefore[i], linesAfter[i], want)
		}
	}
}

// The tree is never written, also when the files cannot be changed, and the
// command leaves nothing in its temporary folder.
func TestTreeIsNotWrittenAndNoTemporaryFileRemains(t *testing.T) {
	t.Parallel()
	root := mutTestCopy(t, "mixed")
	mutTestWriteList(t, root, `zz/zz.go IsSet negate "x != 0" equivalent: planted`+"\n")
	tmp := filepath.Join(t.TempDir(), "tmp")
	if err := os.Mkdir(tmp, 0o755); err != nil {
		t.Fatal(err)
	}
	mutTestReadOnly(t, root)
	before := mutTestChecksum(t, root)

	out, code := mutTestRunKeepList(t, root, []string{"TMPDIR=" + tmp}, "zz")

	if code != 0 {
		t.Errorf("exit code %d on a read-only tree, want 0; output:\n%s", code, out)
	}
	mutTestCompare(t, out, []string{mutTestSummary("zz", 3, 1, 1, 0, 1, 1, "50.0%"), "ok mutate"}, false)
	if after := mutTestChecksum(t, root); after != before {
		t.Errorf("the tree changed: checksum %s before, %s after", before, after)
	}
	left, err := os.ReadDir(tmp)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range left {
		t.Errorf("left in the temporary folder: %s", e.Name())
	}
}

// mutTestReadOnly removes the write bits of a tree now and restores them when
// the test ends, so that the folder can be removed.
func mutTestReadOnly(t *testing.T, root string) {
	t.Helper()
	setMode := func(dir, file fs.FileMode) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				return os.Chmod(p, dir)
			}
			return os.Chmod(p, file)
		})
	}
	t.Cleanup(func() {
		if err := setMode(0o755, 0o644); err != nil {
			t.Error(err)
		}
	})
	if err := setMode(0o555, 0o444); err != nil {
		t.Fatal(err)
	}
}

// mutTestChecksum covers every path, mode and byte of the tree.
func mutTestChecksum(t *testing.T, root string) string {
	t.Helper()
	h := sha256.New()
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		_, _ = fmt.Fprintf(h, "%s %v %d\n", p, info.Mode(), info.Size())
		if info.Mode().IsRegular() {
			b, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			h.Write(b)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", h.Sum(nil))
}

// Wrong use exits 2, and prints something.
func TestWrongUseExitsTwo(t *testing.T) {
	t.Parallel()
	root := mutTestCopy(t, "listcases")
	cases := [][]string{
		nil,
		{"--root", root},
		{"--bogus", "zz"},
		{"--workers", "many", "--root", root, "zz"},
		{"--root"},
		{"--list"},
		{"--workers"},
	}
	for _, args := range cases {
		out, code := mutTestExec(t, root, mutTestEnv(), args...)
		if code != 2 {
			t.Errorf("%q: exit code %d, want 2; output:\n%s", args, code, out)
		}
		if strings.TrimSpace(out) == "" {
			t.Errorf("%q: nothing printed", args)
		}
	}
}
