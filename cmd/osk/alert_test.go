package main

import (
	"bytes"
	"encoding/pem"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// slkMarker ends every Slack URL of the tests. The URL is a secret, so the
// marker may show up in no output and in no file of the state folder.
const slkMarker = "slksecret"

// Nothing listens on port 1, so every delivery fails at once.
const slkDeadURL = "https://127.0.0.1:1/x/" + slkMarker

const slkUsageLine = "       osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>]" +
	" --expect <file> [--state <folder> [--slack-min-severity <severity>]]"

// slkFile expects nothing of the delegation of corp.test., which the local
// world shows as a medium finding.
const slkFile = "domain corp.test.\ncorp.test. DS none\n"

const slkLabel = "open medium not-covered delegation corp.test. NS"

// slkShow hides the marker in a test message, because a test log line must
// not hold the secret either.
func slkShow(s string) string {
	return strings.ReplaceAll(s, slkMarker, "[marker]")
}

// slkNoMarker fails when an output, or any byte of any file in the state
// folder, holds the marker. The folder must hold a store, so that an empty
// folder cannot pass.
func slkNoMarker(t *testing.T, state string, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		if strings.Contains(o, slkMarker) {
			t.Errorf("an output holds the marker of the Slack URL:\n%s", slkShow(o))
		}
	}
	size := 0
	err := filepath.WalkDir(state, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		data, err := os.ReadFile(path)
		if err == nil && bytes.Contains(data, []byte(slkMarker)) {
			t.Errorf("%s holds the marker of the Slack URL", path)
		}
		size += len(data)
		return err
	})
	if _, serr := os.Stat(filepath.Join(state, "osk.db")); err != nil || serr != nil || size == 0 {
		t.Errorf("the state folder holds no store: %v, %v, %d octets read", err, serr, size)
	}
}

func slkWithin(t *testing.T, what string, at, from, to time.Time) {
	t.Helper()
	if at.Before(from) || at.After(to) {
		t.Errorf("%s is %s, want a time from %s to %s", what, at.UTC(), from.UTC(), to.UTC())
	}
}

// slkCheck runs osk check against the local world and gives the exit code,
// the output and the errors, and the times just before and after the run.
func slkCheck(s *transportServer, args ...string) (code int, out, errOut string, start, end time.Time) {
	start = time.Now()
	code, out, errOut = transportRun(slices.Concat([]string{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8"}, args)...)
	return code, out, errOut, start, time.Now()
}

// slkFindingLines is the output of a check of slkFile without --state.
func slkFindingLines(s *transportServer) []string {
	return []string{
		"finding medium not-covered delegation corp.test. NS",
		"  expected -",
		"  seen " + s.addr + " " + expRootHost + " ns1.corp.test. | ns2.corp.test.",
		"checked corp.test. 2 sets: 1 findings, 0 unknown answers",
	}
}

func slkSame(t *testing.T, what, out string, want []string) {
	t.Helper()
	if text := strings.Join(want, "\n") + "\n"; out != text {
		t.Errorf("%s gave:\n%s\nwant:\n%s", what, slkShow(out), slkShow(text))
	}
}

// slkNotThere fails when path exists: the folder of the store is made only
// after every wrong use and every problem of the file is ruled out.
func slkNotThere(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Lstat(path); err == nil {
		t.Errorf("%s was created", path)
	}
}

// slkFailed is the line of the one failed delivery of slkFile, with its
// reason and its next try left out.
const slkFailed = "delivery slack failed " + slkLabel + ": no answer <reason>; next try <time>"

// slkFailedLast gives out with the reason and the next try of its last line
// left out, as in slkFailed, once it has checked them: the reason is one
// quoted string with the network error, and the next try is 10 s after the
// run.
func slkFailedLast(t *testing.T, out string, start, end time.Time) string {
	t.Helper()
	head, last := "", strings.TrimSuffix(out, "\n")
	if i := strings.LastIndex(last, "\n"); i >= 0 {
		head, last = last[:i+1], last[i+1:]
	}
	prefix, _, _ := strings.Cut(slkFailed, "<reason>")
	rest, ok := strings.CutPrefix(last, prefix)
	if !ok {
		return out
	}
	reason, err := strconv.QuotedPrefix(rest)
	detail, _ := strconv.Unquote(reason)
	next, ok := strings.CutPrefix(rest[len(reason):], "; next try ")
	at, terr := time.Parse("2006-01-02T15:04:05Z", next)
	switch {
	case err != nil || !strings.HasPrefix(detail, "network: "):
		t.Errorf("the reason in %q is not one quoted string that starts \"network: \"", slkShow(last))
	case !ok || terr != nil || at.Format("2006-01-02T15:04:05Z") != next:
		t.Errorf("the line %q does not end \"; next try <time>\"", slkShow(last))
	default:
		slkWithin(t, "the next try", at, start.Add(10*time.Second).Truncate(time.Second), end.Add(10*time.Second))
		return head + slkFailed + "\n"
	}
	return out
}

func TestCheckStateUsage(t *testing.T) {
	lines := strings.Split(usage, "\n")
	if !slices.Contains(lines, slkUsageLine) {
		t.Errorf("the usage lacks the line\n%s\nusage:\n%s", slkUsageLine, usage)
	}
	for _, l := range lines {
		if strings.HasSuffix(l, "--expect <file>") {
			t.Errorf("the usage still holds the line %q", l)
		}
	}
}

// Wrong use is found before the file is read, before the store is opened and
// before any check runs. The file does not exist, so reading it would give
// exit code 1, and the server, which may be asked, must get no query.
func TestCheckStateWrongUse(t *testing.T) {
	s := transportStart(t, expWorld)
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing.expect")
	state := filepath.Join(dir, "state")
	const noURL = "--state needs the Slack webhook URL in the environment variable OSK_SLACK_URL"
	const badURL = "the environment variable OSK_SLACK_URL does not hold an https URL with a host and no user name"
	type wrong struct {
		name, url string // url "unset": the variable is not set
		args      []string
		msgs      []string // the message is one of these
		suffix    bool     // the message ends with it: the flag package adds the flag and its value before
	}
	cases := []wrong{
		{"state without expect", slkDeadURL, []string{"--state", state, "corp.test."}, []string{"--state needs --expect"}, false},
		{"severity without state", slkDeadURL, []string{"--expect", missing, "--slack-min-severity", "high"},
			[]string{"--slack-min-severity needs --state"}, false},
		{"severity without state or expect", slkDeadURL, []string{"--slack-min-severity", "high", "corp.test."},
			[]string{"--slack-min-severity needs --state"}, false},
		{"state twice", slkDeadURL, []string{"--expect", missing, "--state", state, "--state", state},
			[]string{"given more than once"}, true},
		{"no URL", "unset", []string{"--expect", missing, "--state", state}, []string{noURL}, false},
		// An empty variable holds no URL, and it is no https URL either.
		{"empty URL", "", []string{"--expect", missing, "--state", state}, []string{noURL, badURL}, false},
	}
	for _, severity := range []string{"urgent", "", "none", "lowest", "critical,high"} {
		cases = append(cases, wrong{"severity " + strconv.Quote(severity), slkDeadURL,
			[]string{"--expect", missing, "--state", state, "--slack-min-severity", severity},
			[]string{"want low, medium, high or critical"}, true})
	}
	for _, url := range []string{
		"http://hooks.example/" + slkMarker,
		"ftp://hooks.example/" + slkMarker,
		"hooks.example/" + slkMarker,
		"https:///" + slkMarker,
		"https://u@hooks.example/" + slkMarker,
		"https://u:" + slkMarker + "@hooks.example/x",
		"https:hooks.example/" + slkMarker,
		"https://[::1/" + slkMarker,
		" https://hooks.example/" + slkMarker,
	} {
		cases = append(cases, wrong{"URL " + slkShow(url), url, []string{"--expect", missing, "--state", state},
			[]string{badURL}, false})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			t.Setenv("OSK_SLACK_URL", c.url)
			if c.url == "unset" {
				if err := os.Unsetenv("OSK_SLACK_URL"); err != nil {
					t.Fatal(err)
				}
			}
			code, out, errOut, _, _ := slkCheck(s, c.args...)
			first, rest, _ := strings.Cut(errOut, "\n")
			msg, ok := strings.CutPrefix(first, "osk check: ")
			ok = ok && slices.ContainsFunc(c.msgs, func(m string) bool { return msg == m || c.suffix && strings.HasSuffix(msg, ": "+m) })
			if code != 2 || out != "" || !ok || rest != usage || !strings.Contains(rest, slkUsageLine+"\n") {
				t.Errorf("osk check %s: exit code %d, output %q, errors:\n%s\nwant 2, nothing, \"osk check: \" and one of %q, then the usage",
					slkShow(strings.Join(c.args, " ")), code, slkShow(out), slkShow(errOut), c.msgs)
			}
			if strings.Contains(errOut, slkMarker) {
				t.Errorf("the errors echo the value of OSK_SLACK_URL")
			}
			slkNotThere(t, state)
		})
	}
	expNoQueries(t, s)
}

// A file with problems stops the run as it does without --state, and the
// store is never opened.
func TestCheckStateFileProblems(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	dir := t.TempDir()
	state := filepath.Join(dir, "state")
	bad := expFile(t, "domain corp.test.\nmail.corp.test A 10.53.0.82\n")
	code, out, errOut, _, _ := slkCheck(s, "--expect", bad, "--state", state)
	if want := "osk: " + bad + `:2: "mail.corp.test" has no trailing dot` + "\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	slkNotThere(t, state)

	code, out, errOut, _, _ = slkCheck(s, "--expect", filepath.Join(dir, "missing"), "--state", state)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: ") || strings.Count(errOut, "\n") != 1 || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("a missing file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk: ...\"", code, out, errOut)
	}
	slkNotThere(t, state)
	expNoQueries(t, s)
}

// A store that cannot be opened stops the run before any check runs.
func TestCheckStateStoreErrors(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	file := expFile(t, slkFile)

	// The store makes the folder for its owner alone; it refuses one that
	// other users may enter, as a folder of the tests may be.
	busy := filepath.Join(t.TempDir(), "state")
	held, err := store.Open(busy)
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut, _, _ := slkCheck(s, "--expect", file, "--state", busy)
	if err := held.Close(); err != nil {
		t.Error(err)
	}
	if want := "osk: store: " + busy + " is in use by another osk process\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("a store in use: exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}

	// A folder cannot be made under a regular file.
	plain := filepath.Join(t.TempDir(), "plain")
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	code, out, errOut, _, _ = slkCheck(s, "--expect", file, "--state", filepath.Join(plain, "state"))
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk: ") || strings.Count(errOut, "\n") != 1 || !strings.HasSuffix(errOut, "\n") {
		t.Errorf("a folder under a file: exit code %d, output %q, errors %q; want 1, nothing and one line \"osk: ...\"", code, out, errOut)
	}
	expNoQueries(t, s)
}

// The webhook cannot be reached: the attempt is reported with the reason,
// which holds no URL, and the row waits 10 s for the next run. A second run
// with no change opens nothing and notifies nothing.
func TestCheckStateDeliveryFails(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	file := expFile(t, slkFile)
	state := filepath.Join(t.TempDir(), "state")

	code, out, errOut, start, end := slkCheck(s, "--expect", file, "--state", state)
	if code != 1 || errOut != "" {
		t.Errorf("first run: exit code %d, errors %q; want 1 and none", code, slkShow(errOut))
	}
	slkSame(t, "the first run", slkFailedLast(t, out, start, end), append(slkFindingLines(s), "alert "+slkLabel, slkFailed))

	code, out2, errOut2, _, end2 := slkCheck(s, "--expect", file, "--state", state)
	if code != 1 || errOut2 != "" {
		t.Errorf("second run: exit code %d, errors %q; want 1 and none", code, slkShow(errOut2))
	}
	slkSame(t, "the second run", out2, slkFindingLines(s))
	slkNoMarker(t, state, out, errOut, out2, errOut2)

	// The store holds the one alert as the first run opened it, and the one
	// row of its one event, after one attempt.
	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	alerts, err := st.OpenAlerts(obs.DelegationKey(cliName("corp.test.")))
	if err != nil || len(alerts) != 1 {
		t.Fatalf("open alerts %+v, error %v; want one", alerts, err)
	}
	a := alerts[0]
	if a.ID == 0 || !a.Open || a.Rule != decide.RuleNotCovered || a.Severity != decide.SeverityMedium || !a.Noticed.Equal(a.Opened) {
		t.Errorf("alert %+v; want an open not-covered alert, medium, noticed when it opened", a)
	}
	slkWithin(t, "the alert's first seen time", a.Opened, start, end)
	rows, err := st.Due("slack", end2.Add(time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Label != slkLabel || rows[0].Attempts != 1 {
		t.Errorf("rows %+v, error %v; want one row %q after one attempt", rows, err, slkLabel)
	}
}

// slkBrokenOutput is a standard output that fails every write.
type slkBrokenOutput struct{}

func (slkBrokenOutput) Write([]byte) (int, error) { return 0, errors.New("slk output closed") }

// slkOneRow checks that the store in state holds the one open alert of
// slkFile and its one row after one attempt.
func slkOneRow(t *testing.T, state string) {
	t.Helper()
	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	if alerts, err := st.OpenAlerts(obs.DelegationKey(cliName("corp.test."))); err != nil || len(alerts) != 1 {
		t.Errorf("open alerts %+v, error %v; want one", alerts, err)
	}
	rows, err := st.Due("slack", time.Now().Add(2*time.Hour))
	if err != nil || len(rows) != 1 || rows[0].Label != slkLabel || rows[0].Attempts != 1 {
		t.Errorf("rows %+v, error %v; want one row %q after one attempt", rows, err, slkLabel)
	}
}

// An output that cannot be written does not lose the alert: a later run
// would see the same difference and notify nothing. The alert is stored, its
// notice is tried, and the run ends with exit 1.
func TestCheckStateKeepsAlertWhenOutputFails(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	file := expFile(t, slkFile)
	state := filepath.Join(t.TempDir(), "state")
	var errOut bytes.Buffer
	code := run([]string{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", file, "--state", state},
		slkBrokenOutput{}, &errOut)
	if want := "osk: slk output closed\n"; code != 1 || errOut.String() != want {
		t.Errorf("exit code %d, errors %q; want 1 and %q", code, slkShow(errOut.String()), want)
	}
	slkOneRow(t, state)
}

// slkChildArgs holds the arguments of osk, one for each line, when the test
// binary runs itself as osk.
const slkChildArgs = "OSK_TEST_OSK_ARGS"

// A reader of the output that is gone does not end osk before the alert is
// stored and sent: the write fails, and the run ends with exit 1. The test
// binary runs itself as osk, with a pipe as standard output whose reading end
// is closed, and trusts the Slack server of the test through SSL_CERT_FILE.
func TestCheckStateSurvivesClosedOutputPipe(t *testing.T) {
	if args := os.Getenv(slkChildArgs); args != "" {
		os.Args = append([]string{"osk"}, strings.Split(args, "\n")...)
		// The tests may run as root, which main refuses.
		geteuid = func() int { return 1000 }
		main()
		return
	}
	s := transportStart(t, expWorld)
	var requests atomic.Int32
	srv := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { requests.Add(1) }))
	t.Cleanup(srv.Close)
	roots := filepath.Join(t.TempDir(), "roots.pem")
	if err := os.WriteFile(roots, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o600); err != nil {
		t.Fatal(err)
	}
	state := filepath.Join(t.TempDir(), "state")
	args := []string{"check", "--root-server", s.addr, "--extra-range", "127.0.0.0/8", "--expect", expFile(t, slkFile), "--state", state}
	read, write, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := read.Close(); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCheckStateSurvivesClosedOutputPipe$", "-test.count=1")
	cmd.Env = append(os.Environ(), slkChildArgs+"="+strings.Join(args, "\n"),
		"OSK_SLACK_URL="+srv.URL+"/x/"+slkMarker, "SSL_CERT_FILE="+roots)
	cmd.Stdout = write
	var errOut bytes.Buffer
	cmd.Stderr = &errOut
	err = errors.Join(cmd.Run(), write.Close())
	if code := cmd.ProcessState.ExitCode(); code != 1 || !strings.Contains(errOut.String(), "broken pipe") {
		t.Errorf("osk: exit code %d (-1: ended by a signal), %v, errors %q; want 1 and a broken pipe", code, err, slkShow(errOut.String()))
	}
	st, err := store.Open(state)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := st.Close(); err != nil {
			t.Error(err)
		}
	}()
	if alerts, err := st.OpenAlerts(obs.DelegationKey(cliName("corp.test."))); err != nil || len(alerts) != 1 {
		t.Errorf("open alerts %+v, error %v; want one", alerts, err)
	}
	// The row is sent: the server got it, and it waits for no other try.
	if rows, err := st.Due("slack", time.Now().Add(2*time.Hour)); err != nil || len(rows) != 0 || requests.Load() != 1 {
		t.Errorf("pending rows %+v, error %v, %d requests; want none, none and 1", rows, err, requests.Load())
	}
}

// The notices of a run are tried at the time of the run, so a clock that
// steps back between storing and sending cannot hold them back.
func TestCheckStateSendsAtTheTimeOfTheRun(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	file := expFile(t, slkFile)
	state := filepath.Join(t.TempDir(), "state")
	// The run takes a time half an hour ahead of the clock of the system.
	clock = func() time.Time { return time.Now().Add(30 * time.Minute) }
	t.Cleanup(func() { clock = time.Now })
	code, out, errOut, _, _ := slkCheck(s, "--expect", file, "--state", state)
	if code != 1 || errOut != "" || !strings.Contains(out, "\ndelivery slack failed "+slkLabel+": no answer ") {
		t.Errorf("exit code %d, errors %q, output:\n%s\nwant 1, none and a failed delivery", code, slkShow(errOut), slkShow(out))
	}
	slkOneRow(t, state)
}

// A channel gets a row only for an alert whose severity reaches the minimum
// of the channel.
func TestCheckStateMinSeverity(t *testing.T) {
	s := transportStart(t, expWorld)
	t.Setenv("OSK_SLACK_URL", slkDeadURL)
	file := expFile(t, slkFile)
	for _, c := range []struct {
		severity string
		rows     int
	}{{"critical", 0}, {"high", 0}, {"medium", 1}, {"low", 1}} {
		t.Run(c.severity, func(t *testing.T) {
			state := filepath.Join(t.TempDir(), "state")
			code, out, errOut, start, end := slkCheck(s, "--expect", file, "--state", state, "--slack-min-severity", c.severity)
			if code != 1 || errOut != "" {
				t.Errorf("exit code %d, errors %q; want 1 and none", code, slkShow(errOut))
			}
			if want := append(slkFindingLines(s), "alert "+slkLabel); c.rows == 0 {
				slkSame(t, "osk check", out, want)
			} else {
				slkSame(t, "osk check", slkFailedLast(t, out, start, end), append(want, slkFailed))
			}
			slkNoMarker(t, state, out, errOut)

			st, err := store.Open(state)
			if err != nil {
				t.Fatal(err)
			}
			rows, err := st.Due("slack", end.Add(time.Hour))
			if err := st.Close(); err != nil {
				t.Error(err)
			}
			if err != nil || len(rows) != c.rows {
				t.Errorf("rows %+v, error %v; want %d", rows, err, c.rows)
			}
		})
	}
}

// Without --state the variable is never read: a value that is no URL
// changes no byte of the output and not the exit code.
func TestCheckWithoutStateIgnoresSlackURL(t *testing.T) {
	s := transportStart(t, expWorld)
	file := expFile(t, slkFile)
	want := slkFindingLines(s)
	for _, url := range []string{"unset", "not a URL " + slkMarker, slkDeadURL} {
		t.Setenv("OSK_SLACK_URL", url)
		if url == "unset" {
			if err := os.Unsetenv("OSK_SLACK_URL"); err != nil {
				t.Fatal(err)
			}
		}
		code, out, errOut, _, _ := slkCheck(s, "--expect", file)
		if code != 1 || errOut != "" {
			t.Errorf("OSK_SLACK_URL %q: exit code %d, errors %q; want 1 and none", slkShow(url), code, slkShow(errOut))
		}
		slkSame(t, "osk check with OSK_SLACK_URL "+strconv.Quote(slkShow(url)), out, want)
	}
}
