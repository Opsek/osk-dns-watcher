package cli

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// cliT0 is the time of the events and notices that tests write when the
// command does not compare them with the clock.
var cliT0 = time.Date(2026, 11, 11, 12, 0, 0, 0, time.UTC)

// cliChildEnv makes the test binary act as a second process that holds the
// store of the folder it names, as osk run does, and writes to it on
// request. A Reader and a Store of one folder must never be open in one
// process: closing a descriptor of the database would drop the store's
// locks.
const cliChildEnv = "OSK_CLI_TEST_CHILD"

func TestMain(m *testing.M) {
	if dir := os.Getenv(cliChildEnv); dir != "" {
		os.Exit(cliChildMain(dir))
	}
	os.Exit(m.Run())
}

// The secret values of the config. Only validate may read them, and no
// output may hold them.
const (
	cliSlackEnv  = "OSK_CLI_TEST_SLACK"
	cliMarkSlack = "climarkslack"
	cliMarkURL   = "climarkurl"
	cliMarkKey   = "climarkkey"
)

var cliUsage = map[string]string{
	"validate":   "usage: osk validate --config <file> [--json]",
	"status":     "usage: osk status --config <file> [--json]",
	"watch":      "usage: osk watch --config <file> [--json]",
	"accept":     "usage: osk accept --config <file> [--write <code>] [--json] <alert id>",
	"test-alert": "usage: osk test-alert --config <file> [--json]",
}

// cliRun runs one command in this process. Watch and test-alert get a
// context that ends after limit, so that a command that does not stop
// cannot hold the test.
func cliRun(limit time.Duration, cmd string, args ...string) (code int, stdout, stderr string) {
	var out, errOut bytes.Buffer
	ctx, cancel := context.WithTimeout(context.Background(), limit)
	defer cancel()
	switch cmd {
	case "validate":
		code = Validate(args, &out, &errOut)
	case "status":
		code = Status(args, &out, &errOut)
	case "watch":
		code = Watch(ctx, args, &out, &errOut)
	case "accept":
		code = Accept(args, &out, &errOut)
	case "test-alert":
		code = TestAlert(ctx, args, &out, &errOut)
	default:
		panic("no command " + cmd)
	}
	return code, out.String(), errOut.String()
}

func cliLines(lines ...string) string {
	if len(lines) == 0 {
		return ""
	}
	return strings.Join(lines, "\n") + "\n"
}

func cliSame(t *testing.T, what, got string, want ...string) {
	t.Helper()
	if text := cliLines(want...); got != text {
		t.Errorf("%s gave:\n%s\nwant:\n%s", what, got, text)
	}
}

// cliWorld is a config of two domains, Slack and one webhook, with its
// expectations files, in a folder of its own. Its secrets are not set and
// its secret files do not exist, because only validate may read them.
type cliWorld struct {
	dir, config, state string
	corp, shop         string // the expectations files
}

const cliCorpFile = "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\nwww.corp.test. A 10.53.0.81\n"

const cliShopFile = "domain shop.test.\nshop.test. NS ns1.dnshost.test. | ns2.dnshost.test.\nshop.test. DS none\n"

// cliNetwork is the network object of a config; with it each command that
// prints the warnings prints cliWarnings.
const cliNetwork = `,
  "network": {"root_servers": ["10.53.0.2", "192.0.2.1:5353"], "extra_ranges": ["10.53.0.0/24"]}`

var cliWarnings = []string{
	"network.root_servers is set: osk starts its walk at 10.53.0.2:53, 192.0.2.1:5353 instead of the root servers" +
		" of the internet, so these servers decide every answer. Use it only in a lab or a private network.",
	"network.extra_ranges is set: data from DNS can now make osk send queries to 10.53.0.0/24." +
		" Use it only in a lab or a private network.",
}

// cliConfigText has one key on each line, so that a test knows the line of
// each: slack.url is on line 8, webhooks[0].url on 13, webhooks[0].key on 14.
func cliConfigText(state, extra string) string {
	return `{
  "state": "` + state + `",
  "domains": [
    {"name": "corp.test.", "expect": "corp.test.expect"},
    {"name": "shop.test.", "expect": "shop.test.expect"}
  ],
  "slack": {
    "url": {"env": "` + cliSlackEnv + `"}
  },
  "webhooks": [
    {
      "name": "siem",
      "url": {"file": "siem-url"},
      "key": {"file": "siem-key"}
    }
  ]` + extra + `
}
`
}

func cliWriteFile(t testing.TB, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func cliNewWorld(t testing.TB, network bool) *cliWorld {
	t.Helper()
	dir := t.TempDir()
	w := &cliWorld{dir: dir, config: filepath.Join(dir, "osk.json"), state: filepath.Join(dir, "state"),
		corp: filepath.Join(dir, "corp.test.expect"), shop: filepath.Join(dir, "shop.test.expect")}
	extra := ""
	if network {
		extra = cliNetwork
	}
	cliWriteFile(t, w.config, cliConfigText(w.state, extra))
	cliWriteFile(t, w.corp, cliCorpFile)
	cliWriteFile(t, w.shop, cliShopFile)
	return w
}

// cliSetSecrets gives the world's secrets their values, each with a marker.
func cliSetSecrets(t *testing.T, w *cliWorld) {
	t.Helper()
	t.Setenv(cliSlackEnv, "https://hooks.example.test/services/T0/B0/"+cliMarkSlack)
	cliWriteFile(t, filepath.Join(w.dir, "siem-url"), "https://siem.example.test/hook/"+cliMarkURL+"\n")
	cliWriteFile(t, filepath.Join(w.dir, "siem-key"), cliMarkKey+strings.Repeat("k", 40-len(cliMarkKey)))
}

// cliNoMarker fails when an output holds a secret of the config.
func cliNoMarker(t *testing.T, outputs ...string) {
	t.Helper()
	for _, o := range outputs {
		for _, m := range []string{cliMarkSlack, cliMarkURL, cliMarkKey} {
			if strings.Contains(o, m) {
				t.Errorf("an output holds the secret marker %s:\n%s", m, o)
			}
		}
	}
}

// cliStore opens the store of state, runs f and closes the store again, so
// that no store of the folder is open while a command reads it.
func cliStore(t testing.TB, state string, f func(s *store.Store)) {
	t.Helper()
	s, err := store.Open(state)
	if err != nil {
		t.Fatalf("store.Open(%s): %v", state, err)
	}
	f(s)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
}

func cliName(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(fmt.Sprintf("ParseName(%q): %v", s, err))
	}
	return n
}

func cliRecordsKey(domain, name string, t dnswire.Type) obs.Key {
	return obs.RecordsKey(cliName(domain), cliName(name), t)
}

// cliScopeKey is the key of the alerts that belong to a whole domain.
func cliScopeKey(domain string) obs.Key {
	d := cliName(domain)
	return obs.Key{Domain: d, Name: d}
}

// cliAlert is an open alert that is not stored yet, with one line for each
// text, as one server's answer each.
func cliAlert(r decide.Rule, sev decide.Severity, k obs.Key, expected string, opened time.Time, texts ...string) alert.Alert {
	a := alert.Alert{Open: true, Rule: r, Severity: sev, Peak: sev, Check: k, Expected: expected,
		Value: "problem of " + r.String(), Opened: opened, LastClean: opened.Add(-time.Minute), Noticed: opened}
	for i, text := range texts {
		host := fmt.Sprintf("ns%d.corp.test.", i+1)
		addr := netip.MustParseAddrPort(fmt.Sprintf("10.53.0.%d:53", 11+i))
		a.Lines = append(a.Lines, alert.Line{Server: obs.Server{Name: cliName(host), Addr: addr}, Text: text, TTL: 300, Received: opened})
	}
	if len(texts) > 0 {
		a.Value = "10.53.0.11:53 ns1.corp.test. " + texts[0]
	}
	return a
}

// cliEvent is the write of one event of a, with one delivery to each channel.
func cliEvent(kind alert.EventKind, a alert.Alert, was decide.Severity, at time.Time, channels ...string) store.Write {
	w := store.Write{Event: alert.Event{Kind: kind, Alert: a, Was: was, At: at}}
	for _, c := range channels {
		w.Deliveries = append(w.Deliveries, store.Delivery{Channel: c, Label: kind.String() + " to " + c, Body: []byte(`{"text":"x"}`)})
	}
	return w
}

// cliApply writes the writes in one transaction, with now as the time of
// their delivery rows.
func cliApply(t testing.TB, s *store.Store, now time.Time, writes ...store.Write) {
	t.Helper()
	if err := s.Apply(writes[0].Event.Alert.Check, false, now, writes); err != nil {
		t.Fatalf("Apply: %v", err)
	}
}

// cliStored gives the stored open alert of a's check and rule.
func cliStored(t testing.TB, s *store.Store, a alert.Alert) alert.Alert {
	t.Helper()
	open, err := s.OpenAlerts(a.Check)
	if err != nil {
		t.Fatalf("OpenAlerts: %v", err)
	}
	for _, o := range open {
		if o.Rule == a.Rule {
			return o
		}
	}
	t.Fatalf("no open %s alert of %v", a.Rule, a.Check)
	return alert.Alert{}
}

// cliOpen stores an open event of each alert, one transaction each, and
// gives the stored alerts with their ids.
func cliOpen(t testing.TB, s *store.Store, now time.Time, alerts ...alert.Alert) []alert.Alert {
	t.Helper()
	var stored []alert.Alert
	for _, a := range alerts {
		cliApply(t, s, now, cliEvent(alert.EventOpen, a, a.Severity, a.Opened))
		stored = append(stored, cliStored(t, s, a))
	}
	return stored
}

// cliRows gives the ids of the pending rows of channel whose time has come.
func cliRows(t testing.TB, s *store.Store, channel string, now time.Time) []int64 {
	t.Helper()
	rows, err := s.Due(channel, now)
	if err != nil {
		t.Fatalf("Due(%s): %v", channel, err)
	}
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

func cliRecord(t testing.TB, s *store.Store, id int64, d store.Done) {
	t.Helper()
	if err := s.Record(id, d); err != nil {
		t.Fatalf("Record(%d): %v", id, err)
	}
}

// cliBuffer is an output that a command writes while the test reads it.
type cliBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (b *cliBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.Write(p)
}

func (b *cliBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.b.String()
}

// cliWaitFor waits until ok holds, and fails the test after within.
func cliWaitFor(t *testing.T, what string, within time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(within)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("waited %v for %s", within, what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// cliMarshal is the JSON line that a test expects, made from a struct whose
// fields are in the order of the keys. Comparing whole lines checks the
// keys, their order and every value at once.
func cliMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cliCheck is the check object of the JSON output.
type cliCheck struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	RType  string `json:"rtype"`
}

// The child process. It reads one request for each line of its standard
// input and answers each with one line: "ok", a result, or "error <text>".

type cliChild struct {
	in      io.WriteCloser
	replies chan string
	done    chan error
	errOut  *cliBuffer
}

func cliStartChild(t *testing.T, state string) *cliChild {
	t.Helper()
	cmd := exec.Command(os.Args[0])
	cmd.Env = append(os.Environ(), cliChildEnv+"="+state)
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	c := &cliChild{in: in, replies: make(chan string, 100), done: make(chan error, 1), errOut: &cliBuffer{}}
	cmd.Stderr = c.errOut
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			c.replies <- sc.Text()
		}
		close(c.replies)
		c.done <- cmd.Wait()
	}()
	t.Cleanup(func() {
		_ = c.in.Close() // the child ends when its input ends
		select {
		case err := <-c.done:
			if err != nil {
				t.Errorf("the child process: %v\n%s", err, c.errOut.String())
			}
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill() // it is stuck; the test failed already or fails now
			t.Errorf("the child process did not end")
		}
	})
	if got := c.reply(t); got != "ready" {
		t.Fatalf("the child process gave %q, want ready", got)
	}
	return c
}

func (c *cliChild) send(t *testing.T, request string) {
	t.Helper()
	if _, err := io.WriteString(c.in, request+"\n"); err != nil {
		t.Fatalf("to the child process: %v", err)
	}
}

func (c *cliChild) reply(t *testing.T) string {
	t.Helper()
	select {
	case r, ok := <-c.replies:
		if !ok {
			t.Fatalf("the child process ended:\n%s", c.errOut.String())
		}
		if strings.HasPrefix(r, "error ") {
			t.Fatalf("the child process: %s", r)
		}
		return r
	case <-time.After(30 * time.Second):
		t.Fatalf("the child process gave no answer")
	}
	return ""
}

func (c *cliChild) do(t *testing.T, request string) string {
	t.Helper()
	c.send(t, request)
	return c.reply(t)
}

func cliChildMain(state string) int {
	s, err := store.Open(state)
	if err != nil {
		fmt.Println("error " + err.Error())
		return 1
	}
	fmt.Println("ready")
	sc := bufio.NewScanner(os.Stdin)
	for sc.Scan() {
		fmt.Println(cliChildDo(s, state, sc.Text()))
	}
	if err := s.Close(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func cliChildDo(s *store.Store, state, request string) string {
	word, arg, _ := strings.Cut(request, " ")
	var err error
	switch word {
	case "probe":
		err = s.Notify(store.Notice{Kind: store.NoticeTest, Lines: []string{"probe " + arg}, At: cliT0}, nil)
	case "batch":
		err = cliWatchBatch(s, arg)
	case "serve":
		return cliServe(s, state, arg)
	case "beat":
		err = s.Beat(time.Now(), nil)
	default:
		err = errors.New("unknown request")
	}
	if err != nil {
		return "error " + request + ": " + err.Error()
	}
	return "ok"
}

func TestPrintJSONIsMarshalAndOneLF(t *testing.T) {
	var out bytes.Buffer
	v := struct {
		Type string   `json:"type"`
		Text string   `json:"text"`
		List []string `json:"list"`
	}{"line", "a <b> & c", []string{}}
	if err := PrintJSON(&out, v); err != nil {
		t.Fatalf("PrintJSON: %v", err)
	}
	// json.Marshal escapes <, > and &, as a JSON encoder with HTML escaping
	// turned off would not.
	if want := `{"type":"line","text":"a \u003cb\u003e \u0026 c","list":[]}` + "\n"; out.String() != want {
		t.Errorf("PrintJSON wrote %q, want %q", out.String(), want)
	}
}

func TestPrintJSONReportsWhatItCannotMarshalAndWritesNothing(t *testing.T) {
	var out bytes.Buffer
	if err := PrintJSON(&out, map[string]any{"c": make(chan int)}); err == nil || out.Len() != 0 {
		t.Errorf("PrintJSON of a channel: error %v, wrote %q; want an error and nothing", err, out.String())
	}
}

type cliBrokenWriter struct{}

func (cliBrokenWriter) Write([]byte) (int, error) { return 0, errors.New("cli output closed") }

func TestPrintJSONReportsAFailedWrite(t *testing.T) {
	if err := PrintJSON(cliBrokenWriter{}, map[string]int{"a": 1}); err == nil {
		t.Error("PrintJSON to a broken writer gave no error")
	}
}

func TestPollTimesAreThoseOfTheCommands(t *testing.T) {
	if watchEvery != time.Second || testEvery != 500*time.Millisecond || testLimit != 30*time.Second {
		t.Errorf("watch polls every %v, test-alert every %v for %v; want 1s, 500ms and 30s", watchEvery, testEvery, testLimit)
	}
}

// Every wrong use is found before the config is read: the config named here
// does not exist, and reading it would end with exit 1.
func TestEveryWrongUseExits2WithItsTextAndTheUsageOfItsCommand(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	type use struct {
		args []string
		msg  string // the whole message; "" when package flag words it
		end  string // the end of a message that package flag words
	}
	for _, cmd := range []string{"validate", "status", "watch", "accept", "test-alert"} {
		id := []string{}
		if cmd == "accept" {
			id = []string{"7"}
		}
		uses := []use{
			{args: id, msg: "--config is required"},
			{args: slices.Concat([]string{"--config", missing, "--config", missing}, id), end: "given more than once"},
			{args: slices.Concat([]string{"--nope", "--config", missing}, id)},
			{args: slices.Concat([]string{"--json=maybe", "--config", missing}, id)},
			{args: []string{"--config"}},
		}
		if cmd == "accept" {
			uses = append(uses,
				use{args: []string{"--config", missing}, msg: "want one alert id"},
				use{args: []string{"--config", missing, "7", "8"}, msg: "want one alert id"},
				// Flags come first, so a flag after the id is a second argument.
				use{args: []string{"--config", missing, "7", "--write"}, msg: "want one alert id"},
				use{args: []string{"--config", missing, "one"}, msg: `"one" is not an alert id`},
			)
		} else {
			uses = append(uses, use{args: []string{"--config", missing, "extra"}, msg: "osk " + cmd + " takes no arguments"})
		}
		for _, u := range uses {
			code, out, errOut := cliRun(5*time.Second, cmd, u.args...)
			lines := strings.Split(errOut, "\n")
			first := lines[0]
			prefix := "osk " + cmd + ": "
			okText := strings.HasPrefix(first, prefix) && len(first) > len(prefix) &&
				(u.msg == "" || first == prefix+u.msg) && strings.HasSuffix(first, u.end)
			if code != 2 || out != "" || !okText || !slices.Contains(lines, cliUsage[cmd]) {
				want := prefix + u.msg
				if u.msg == "" {
					want = prefix + "<a text>" + u.end
				}
				t.Errorf("osk %s %q: exit code %d, output %q, errors:\n%s\nwant 2, nothing, and the errors %q and %q",
					cmd, u.args, code, out, errOut, want, cliUsage[cmd])
			}
		}
	}
}

// The reading commands print each problem of the config on standard error;
// validate prints them as its output, which its own tests check.
func TestReadingCommandsPrintTheProblemsOfTheConfigAndExit1(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "osk.json")
	state := filepath.Join(dir, "state")
	cliWriteFile(t, path, "{\n  \"state\": \""+state+"\",\n  \"slak\": 1,\n  \"domains\": []\n}\n")
	_, problems := config.Read(path)
	if len(problems) < 2 {
		t.Fatalf("the config of the test gives %d problems, want at least 2", len(problems))
	}
	var want []string
	for _, p := range problems {
		want = append(want, "osk: "+p.String())
	}
	for _, cmd := range []string{"status", "watch", "accept", "test-alert"} {
		args := []string{"--config", path}
		if cmd == "accept" {
			args = append(args, "1")
		}
		code, out, errOut := cliRun(5*time.Second, cmd, args...)
		if code != 1 || out != "" || errOut != cliLines(want...) {
			t.Errorf("osk %s: exit code %d, output %q, errors:\n%s\nwant 1, nothing and:\n%s", cmd, code, out, errOut, cliLines(want...))
		}
	}
	if _, err := os.Lstat(state); err == nil {
		t.Errorf("the state folder %s was made", state)
	}
}

func TestReadingCommandsNeedTheStateOfARunningService(t *testing.T) {
	w := cliNewWorld(t, false)
	if err := os.Mkdir(w.state, 0o700); err != nil {
		t.Fatal(err)
	}
	want := "osk: store: no state in " + w.state + " yet; start osk run there first\n"
	for _, cmd := range []string{"status", "watch", "accept", "test-alert"} {
		args := []string{"--config", w.config}
		if cmd == "accept" {
			args = append(args, "1")
		}
		code, out, errOut := cliRun(5*time.Second, cmd, args...)
		if code != 1 || out != "" || errOut != want {
			t.Errorf("osk %s: exit code %d, output %q, errors %q; want 1, nothing and %q", cmd, code, out, errOut, want)
		}
	}
	if entries, err := os.ReadDir(w.state); err != nil || len(entries) != 0 {
		t.Errorf("the state folder holds %v (%v); want it empty: no command makes a store or a request", entries, err)
	}
}

func TestReadingCommandsRefuseAStateFolderOpenToOthers(t *testing.T) {
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	if err := os.Chmod(w.state, 0o755); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf("osk: store: %s is open to other users (mode 0755); run chmod 700 %s\n", w.state, w.state)
	for _, cmd := range []string{"status", "watch", "accept", "test-alert"} {
		args := []string{"--config", w.config}
		if cmd == "accept" {
			args = append(args, "1")
		}
		code, out, errOut := cliRun(5*time.Second, cmd, args...)
		if code != 1 || out != "" || errOut != want {
			t.Errorf("osk %s: exit code %d, output %q, errors %q; want 1, nothing and %q", cmd, code, out, errOut, want)
		}
	}
	if _, err := os.Lstat(filepath.Join(w.state, "test-alert")); err == nil {
		t.Error("test-alert left a request in a folder that it refused")
	}
}

// The service holds the lock of its folder all the time; no reading command
// waits for it or takes it, and the service still writes after they ran.
func TestReadingCommandsRunBesideTheServiceAndLeaveItWriting(t *testing.T) {
	w := cliNewWorld(t, false)
	now := time.Now()
	var id int64
	cliStore(t, w.state, func(s *store.Store) {
		a := cliOpen(t, s, now, cliAlert(decide.RuleRecordSet, decide.SeverityHigh,
			cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA), "10.53.0.81", now.Add(-time.Hour), "10.53.0.99"))
		id = a[0].ID
	})
	cliSetSecrets(t, w)
	child := cliStartChild(t, w.state)
	child.do(t, "beat")

	start := time.Now()
	code, out, errOut := cliRun(5*time.Second, "status", "--config", w.config)
	if code != 0 || errOut != "" || !strings.HasPrefix(out, "healthy\n") || time.Since(start) > 2*time.Second {
		t.Errorf("osk status beside the service: exit code %d after %v, errors %q, output:\n%s\nwant 0 within 2s, none and healthy",
			code, time.Since(start), errOut, out)
	}
	cliNoMarker(t, out, errOut)
	code, out, errOut = cliRun(5*time.Second, "accept", "--config", w.config, fmt.Sprint(id))
	if code != 0 || errOut != "" {
		t.Errorf("osk accept beside the service: exit code %d, errors %q, output:\n%s\nwant 0 and none", code, errOut, out)
	}
	cliNoMarker(t, out, errOut)
	if got := child.do(t, "beat"); got != "ok" {
		t.Errorf("the service after the reading commands: %s, want ok", got)
	}
}

// cliFIFO makes a FIFO at path, which holds whoever opens it to read until a
// writer comes. At the end of the test a writer lets such a reader go.
func cliFIFO(t *testing.T, path string) {
	t.Helper()
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
}

// A FIFO or a device in place of a file is refused before it is opened, so
// that no command hangs on it or reads it to its limit: the config file of
// every reading command, and a secret file and an expectations file of
// validate.
func TestReadingCommandsRefuseFilesThatAreNotRegular(t *testing.T) {
	type outcome struct {
		code        int
		out, errOut string
	}
	within := func(cmd string, args ...string) outcome {
		t.Helper()
		done := make(chan outcome, 1)
		go func() {
			code, out, errOut := cliRun(5*time.Second, cmd, args...)
			done <- outcome{code, out, errOut}
		}()
		select {
		case o := <-done:
			return o
		case <-time.After(2 * time.Second):
			t.Fatalf("osk %s %q did not return within 2s", cmd, args)
			return outcome{}
		}
	}
	const refused = "is not a regular file"
	fifo := filepath.Join(t.TempDir(), "osk.json")
	cliFIFO(t, fifo)
	for _, cmd := range []string{"validate", "status", "watch", "accept", "test-alert"} {
		args := []string{"--config", fifo}
		if cmd == "accept" {
			args = append(args, "1")
		}
		o := within(cmd, args...)
		if text := map[bool]string{true: o.out, false: o.errOut}[cmd == "validate"]; o.code != 1 || !strings.Contains(text, refused) {
			t.Errorf("osk %s with a FIFO as the config: exit code %d, output %q, errors %q; want 1 and %q", cmd, o.code, o.out, o.errOut, refused)
		}
	}

	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	key := filepath.Join(w.dir, "siem-key")
	if err := os.Rename(key, key+".saved"); err != nil {
		t.Fatal(err)
	}
	cliFIFO(t, key)
	if o := within("validate", "--config", w.config); o.code != 1 || !strings.Contains(o.out, "webhooks[0].key: ") || !strings.Contains(o.out, refused) {
		t.Errorf("osk validate with a FIFO as the key file: exit code %d, output %q; want 1 and the key file %s", o.code, o.out, refused)
	}
	if err := errors.Join(os.Remove(key), os.Rename(key+".saved", key), os.Remove(w.corp)); err != nil {
		t.Fatal(err)
	}
	cliFIFO(t, w.corp)
	if o := within("validate", "--config", w.config); o.code != 1 || !strings.Contains(o.out, w.corp+": ") || !strings.Contains(o.out, refused) {
		t.Errorf("osk validate with a FIFO as an expectations file: exit code %d, output %q; want 1 and %s %s", o.code, o.out, w.corp, refused)
	}
	if err := errors.Join(os.Remove(w.corp), os.Symlink("/dev/zero", w.corp)); err != nil {
		t.Fatal(err)
	}
	if o := within("validate", "--config", w.config); o.code != 1 || !strings.Contains(o.out, w.corp+": ") || !strings.Contains(o.out, refused) {
		t.Errorf("osk validate with /dev/zero as an expectations file: exit code %d, output %q; want 1 and %s %s", o.code, o.out, w.corp, refused)
	}
}

// The certificates check has no name and no type of its own: its label and
// its JSON name the kind and the domain, in lower case, and leave the type
// empty.
func TestCheckLabelAndCheckOfNameTheCertificatesCheckByItsDomain(t *testing.T) {
	for _, c := range []struct {
		name  string
		key   obs.Key
		label string
		json  cliCheck
	}{
		{"certificates", obs.CertificatesKey(cliName("Corp.Test.")), "certificates corp.test.",
			cliCheck{Kind: "certificates", Domain: "corp.test.", Name: "corp.test.", RType: ""}},
		{"records", cliRecordsKey("corp.test.", "WWW.corp.test.", dnswire.TypeA), "records www.corp.test. A",
			cliCheck{Kind: "records", Domain: "corp.test.", Name: "www.corp.test.", RType: "A"}},
		{"whole domain", cliScopeKey("Corp.Test."), "corp.test.",
			cliCheck{Domain: "corp.test.", Name: "corp.test."}},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := checkLabel(c.key); got != c.label {
				t.Errorf("checkLabel = %q, want %q", got, c.label)
			}
			if got := checkOf(c.key); cliCheck(got) != c.json {
				t.Errorf("checkOf = %+v, want %+v", got, c.json)
			}
		})
	}
}
