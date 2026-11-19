//go:build lab

package start

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
)

// The lab test runs doctor in the runner of the lab, which trusts the lab's
// webhook receiver hooks.lab.test, against the lab's root server.

// docLabHost is the receiver as doctor names it.
const docLabHost = "hooks.lab.test:443"

// docLab is the start of every lab address, "10.53.<LAB_ID>.".
func docLab(t *testing.T) string {
	t.Helper()
	prefix := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(prefix + "1"); err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	return prefix
}

func docLabctl(t *testing.T, args ...string) []byte {
	t.Helper()
	out, err := exec.Command("labctl", args...).Output()
	if err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return out
}

// docLabRequest is a request that the receiver stored.
type docLabRequest struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
	Status  int                 `json:"status"`
}

func docLabHooks(t *testing.T) []docLabRequest {
	t.Helper()
	var list []docLabRequest
	lines := bufio.NewScanner(bytes.NewReader(docLabctl(t, "hooks", "list")))
	lines.Buffer(nil, 1<<20)
	for lines.Scan() {
		var r docLabRequest
		if err := json.Unmarshal(lines.Bytes(), &r); err != nil {
			t.Fatalf("hooks list: %v: %s", err, lines.Bytes())
		}
		list = append(list, r)
	}
	if err := lines.Err(); err != nil {
		t.Fatal(err)
	}
	return list
}

const docLabConfig = `{
  "state": %q,
  "domains": [{"name": "corp.test.", "expect": "corp.test.expect", "fast": ["www.corp.test."]}],
  "intervals": {"serial": "1h", "parent": "1h", "fast": "1h", "other": "1h"},
  "slack": {"url": {"env": "OSK_SLACK_URL"}},
  "webhooks": [{"name": "siem", "url": {"file": "siem-url"}, "key": {"file": "siem-key"}}],
  "network": {"root_servers": [%q], "extra_ranges": [%q]}
}
`

// Doctor in the lab passes with the lab's root server and receiver; then
// each fault alone gives its line and exit 1: a receiver that refuses or
// fails, a Date two minutes behind, a secret, the state folder or the config
// open to other users, a root server that does not answer, and a port where
// no receiver listens. --json gives the same results.
func TestDoctorSaysWhatIsWrong(t *testing.T) {
	lab := docLab(t)
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	s := &docSetup{dir: t.TempDir()}
	docChmod(t, s.dir, 0o700)
	for range 3 {
		s.markers = append(s.markers, docMarker())
	}
	s.key = []byte(s.markers[2] + strings.Repeat("k", 40-len(s.markers[2])))
	slackPath, siemPath := "/slack/T0/B0/"+s.markers[0], "/hook/"+s.markers[1]
	t.Setenv("OSK_SLACK_URL", "https://hooks.lab.test"+slackPath)
	s.siemURLFile = s.write(t, "siem-url", "https://hooks.lab.test"+siemPath+"\n")
	s.siemKeyFile = s.write(t, "siem-key", string(s.key))
	s.expect[0] = s.write(t, "corp.test.expect", "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\n"+
		"corp.test. DS none\nwww.corp.test. A "+lab+"81\n")
	s.state = filepath.Join(s.dir, "state")
	if err := os.Mkdir(s.state, 0o700); err != nil {
		t.Fatal(err)
	}
	docChmod(t, s.state, 0o700)
	setRoot := func(root string) {
		s.config = s.write(t, "config.json", fmt.Sprintf(docLabConfig, s.state, root, lab+"0/24"))
	}
	setRoot(lab + "2")

	want := func(change map[string]string) []string {
		t.Helper()
		c, problems := config.Read(s.config)
		if len(problems) > 0 {
			t.Fatalf("the config of the test has problems: %v", problems)
		}
		var warn []string
		for _, w := range c.Warnings() {
			warn = append(warn, "warn config: "+w)
		}
		return docLines(t, [][2]string{
			{"config", "ok   config: 1 domains, channels slack,siem"},
			{"warnings", strings.Join(warn, "\n")},
			{"files", docFilesOK},
			{"dns corp.test.", docDNSOK("corp.test.")},
			{"webhook slack", docSent("slack", docLabHost)},
			{"webhook siem", docSent("siem", docLabHost)},
			{"clock", docClockOK(docLabHost)},
		}, change)
	}
	// check runs doctor and compares its lines with want; the receiver's Date
	// runs ahead by planted.
	check := func(want []string, planted time.Duration, args ...string) {
		t.Helper()
		docLabctl(t, "hooks", "clear")
		code, lines := s.run(t, args...)
		if len(args) > 0 {
			lines = docFromJSON(t, lines)
		}
		docSame(t, code, docSettleClock(t, lines, map[string]time.Duration{docLabHost: planted}), want)
	}
	where := "the variable OSK_SLACK_URL"

	check(want(nil), 0)
	hooks := docLabHooks(t)
	if len(hooks) != 2 || hooks[0].Method != http.MethodPost || hooks[0].Path != slackPath ||
		hooks[1].Method != http.MethodPost || hooks[1].Path != siemPath {
		t.Fatalf("the receiver got %d requests, want a POST to the Slack path, then one to the webhook path", len(hooks))
	}
	docSlackNotice(t, []byte(hooks[0].Body), s.from, s.to)
	docWebhookNotice(t, []byte(hooks[1].Body), hooks[1].Headers, s.key, s.from, s.to)
	check(want(nil), 0, "--json")

	docLabctl(t, "hooks", "reply", "404", "1", "--body", "no_service")
	check(want(map[string]string{"webhook slack": docAnswered("slack", docLabHost, `404 "no_service"`, where)}), 0)

	docLabctl(t, "hooks", "reply", "500", "1")
	check(want(map[string]string{"webhook slack": docAnswered("slack", docLabHost, "500", where)}), 0)

	late := time.Now().Add(-2 * time.Minute).UTC()
	docLabctl(t, "hooks", "reply", "200", "2", "--header", "Date: "+late.Format(http.TimeFormat))
	check(want(map[string]string{"clock": docClockFail("ahead of", docLabHost)}),
		time.Until(late.Truncate(time.Second)))

	for _, f := range []struct {
		path       string
		mode, good os.FileMode
		line       string
	}{
		{s.siemKeyFile, 0o644, 0o600, docReadable(s.siemKeyFile)},
		{s.state, 0o755, 0o700, docOpenState(s.state)},
		{s.config, 0o664, 0o600, docWritable(s.config)},
	} {
		docChmod(t, f.path, f.mode)
		check(want(map[string]string{"files": f.line}), 0)
		docChmod(t, f.path, f.good)
	}

	setRoot(lab + "99")
	check(want(map[string]string{"dns corp.test.": docDNSFail("corp.test.", "timeout")}), 0)
	setRoot(lab + "2")

	closed := "hooks.lab.test:444"
	t.Setenv("OSK_SLACK_URL", "https://"+closed+slackPath)
	s.write(t, "siem-url", "https://"+closed+siemPath+"\n")
	check(want(map[string]string{
		"webhook slack": docNoAnswer("slack", closed, "network: cannot connect"),
		"webhook siem":  docNoAnswer("siem", closed, "network: cannot connect"),
		"clock":         docClockSkip,
	}), 0)
}
