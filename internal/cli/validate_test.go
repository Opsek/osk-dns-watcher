package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

func cliValidate(w *cliWorld, args ...string) (int, string, string) {
	return cliRun(5*time.Second, "validate", append([]string{"--config", w.config}, args...)...)
}

func cliPrefixed(prefix string, lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = prefix + l
	}
	return out
}

type cliProblemJSON struct {
	Type string `json:"type"`
	File string `json:"file"`
	Line int    `json:"line"`
	Path string `json:"path"`
	Text string `json:"text"`
}

type cliWarningJSON struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type cliResultJSON struct {
	Type     string   `json:"type"`
	Valid    bool     `json:"valid"`
	Problems int      `json:"problems"`
	Domains  int      `json:"domains"`
	Channels []string `json:"channels"`
}

// cliValidateJSON is the JSON output of validate for these problems and
// warnings and this result.
func cliValidateJSON(t *testing.T, problems []cliProblemJSON, warnings []string, result cliResultJSON) []string {
	t.Helper()
	var lines []string
	for _, p := range problems {
		p.Type = "problem"
		lines = append(lines, cliMarshal(t, p))
	}
	for _, w := range warnings {
		lines = append(lines, cliMarshal(t, cliWarningJSON{"warning", w}))
	}
	result.Type = "result"
	return append(lines, cliMarshal(t, result))
}

func TestValidateOfAValidConfigPrintsTheSummaryOnlyAndMakesNoStateFolder(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	code, out, errOut := cliValidate(w)
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, "valid: 2 domains, channels slack,siem")
	cliNoMarker(t, out, errOut)
	if _, err := os.Lstat(w.state); err == nil {
		t.Errorf("osk-dns-watcher validate made the state folder %s", w.state)
	}
}

func TestValidatePrintsTheWarningsBeforeTheSummary(t *testing.T) {
	w := cliNewWorld(t, true)
	cliSetSecrets(t, w)
	code, out, errOut := cliValidate(w)
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, append(cliPrefixed("warning ", cliWarnings), "valid: 2 domains, channels slack,siem")...)
}

// The problems of the config file are those of config.Read, each printed as
// it prints itself; a config with problems has no warnings to print.
func TestValidatePrintsEachProblemOfTheConfigFileWithItsPlace(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	cliWriteFile(t, w.config, `{
  "state": "`+w.state+`",
  "slak": {},
  "State": "x",
  "state": "y",
  "domains": [{"name": "corp.test.", "expect": "corp.test.expect"}],
  "intervals": {"fast": "4s"},
  "webhooks": [{"name": "slack", "url": {"env": "A"}, "key": {"env": "B"}}],
  "network": {"root_servers": ["10.53.0.2"]}
}
`)
	_, problems := config.Read(w.config)
	if len(problems) != 5 {
		t.Fatalf("the config of the test gives %d problems, want 5: %v", len(problems), problems)
	}
	var want []string
	var wantJSON []cliProblemJSON
	for _, p := range problems {
		want = append(want, p.String())
		wantJSON = append(wantJSON, cliProblemJSON{File: p.File, Line: p.Line, Path: p.Path, Text: p.Text})
	}
	code, out, errOut := cliValidate(w)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, append(want, "5 problems")...)

	code, out, errOut = cliValidate(w, "--json")
	if code != 1 || errOut != "" {
		t.Errorf("--json: exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate --json", out, cliValidateJSON(t, wantJSON, nil,
		cliResultJSON{Valid: false, Problems: 5, Domains: 0, Channels: []string{}})...)
	if _, err := os.Lstat(w.state); err == nil {
		t.Errorf("osk-dns-watcher validate made the state folder %s", w.state)
	}
}

// Once the config file is valid, validate reads the secrets and each
// expectations file, and prints the warnings as well.
func TestValidatePrintsTheProblemsOfTheSecretsAndOfTheExpectationsFiles(t *testing.T) {
	w := cliNewWorld(t, true)
	cliSetSecrets(t, w)
	t.Setenv(cliSlackEnv, "")
	cliWriteFile(t, filepath.Join(w.dir, "siem-key"), cliMarkKey+strings.Repeat("k", 31-len(cliMarkKey)))
	corp := "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\nwww A 10.53.0.81\n"
	cliWriteFile(t, w.corp, corp)
	cliWriteFile(t, w.shop, cliCorpFile)

	var corpErr *expect.Error
	if _, err := expect.Parse([]byte(corp)); !errors.As(err, &corpErr) || len(corpErr.Problems) != 1 {
		t.Fatalf("the corp.test. file of the test: %v, want one problem", err)
	}
	p := corpErr.Problems[0]
	want := []string{
		w.config + ":8: slack.url: the environment variable is not set",
		w.config + ":14: webhooks[0].key: the key is shorter than 32 octets",
		w.corp + ":" + strconv.Itoa(p.Line) + ": " + p.Text,
		w.shop + ":1: the file is for corp.test., not shop.test.",
	}
	code, out, errOut := cliValidate(w)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, append(append(want, cliPrefixed("warning ", cliWarnings)...), "4 problems")...)
	cliNoMarker(t, out, errOut)

	code, out, errOut = cliValidate(w, "--json")
	if code != 1 || errOut != "" {
		t.Errorf("--json: exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate --json", out, cliValidateJSON(t, []cliProblemJSON{
		{File: w.config, Line: 8, Path: "slack.url", Text: "the environment variable is not set"},
		{File: w.config, Line: 14, Path: "webhooks[0].key", Text: "the key is shorter than 32 octets"},
		{File: w.corp, Line: p.Line, Text: p.Text},
		{File: w.shop, Line: 1, Text: "the file is for corp.test., not shop.test."},
	}, cliWarnings, cliResultJSON{Valid: false, Problems: 4, Domains: 2, Channels: []string{"slack", "siem"}})...)
	cliNoMarker(t, out, errOut)
}

func TestValidateNamesAnExpectationsFileThatCannotBeRead(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	if err := os.Remove(w.shop); err != nil {
		t.Fatal(err)
	}
	_, openErr := os.Open(w.shop)
	if openErr == nil {
		t.Fatal("the removed file opens")
	}
	code, out, errOut := cliValidate(w)
	if code != 1 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, w.shop+": cannot be read: "+openErr.Error(), "1 problems")
}

// The state folder is checked as the store checks it, but only when it
// exists: validate makes nothing.
func TestValidateChecksTheStateFolderWhenItExists(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	cliStore(t, w.state, func(*store.Store) {})
	if err := os.Chmod(w.state, 0o755); err != nil {
		t.Fatal(err)
	}
	text := "store: " + w.state + " is open to other users (mode 0755); run chmod 700 " + w.state
	code, out, errOut := cliValidate(w)
	if code != 1 || errOut != "" {
		t.Errorf("open folder: exit code %d, errors %q; want 1 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate of a folder open to others", out, w.config+": state: "+text, "1 problems")
	code, out, _ = cliValidate(w, "--json")
	if code != 1 {
		t.Errorf("--json: exit code %d, want 1", code)
	}
	cliSame(t, "osk-dns-watcher validate --json of a folder open to others", out, cliValidateJSON(t,
		[]cliProblemJSON{{File: w.config, Path: "state", Text: text}}, nil,
		cliResultJSON{Valid: false, Problems: 1, Domains: 2, Channels: []string{"slack", "siem"}})...)

	if err := os.Chmod(w.state, 0o700); err != nil {
		t.Fatal(err)
	}
	code, out, errOut = cliValidate(w)
	if code != 0 || errOut != "" {
		t.Errorf("private folder: exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate of a private folder", out, "valid: 2 domains, channels slack,siem")

	if err := os.RemoveAll(w.state); err != nil {
		t.Fatal(err)
	}
	cliWriteFile(t, w.state, "not a folder")
	code, out, _ = cliValidate(w)
	if code != 1 {
		t.Errorf("a file as the state folder: exit code %d, want 1", code)
	}
	cliSame(t, "osk-dns-watcher validate of a file as the state folder", out, w.config+": state: store: "+w.state+" is not a folder", "1 problems")
}

func TestValidateJSONOfAValidConfigIsTheWarningsAndTheResult(t *testing.T) {
	w := cliNewWorld(t, true)
	cliSetSecrets(t, w)
	code, out, errOut := cliValidate(w, "--json")
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate --json", out, cliValidateJSON(t, nil, cliWarnings,
		cliResultJSON{Valid: true, Problems: 0, Domains: 2, Channels: []string{"slack", "siem"}})...)
	cliNoMarker(t, out)
}

// A URL given as a path may be a secret pasted into the wrong field: validate
// refuses it without repeating it, in text and in JSON.
func TestValidateDoesNotRepeatAURLGivenAsAPath(t *testing.T) {
	const mark = "pathurlmarker7"
	path := filepath.Join(t.TempDir(), "config.json")
	cliWriteFile(t, path, "{\n\"state\": \"https://hooks.example/state/"+mark+"\",\n"+
		"\"domains\": [{\"name\": \"corp.test.\", \"expect\": \"https://hooks.example/expect/"+mark+"\"}],\n"+
		"\"slack\": {\"url\": {\"env\": \"OSK_SLACK_URL\"}}\n}\n")
	for _, args := range [][]string{{"--config", path}, {"--json", "--config", path}} {
		code, out, errOut := cliRun(5*time.Second, "validate", args...)
		if code != 1 || errOut != "" || strings.Contains(out, mark) || strings.Count(out, "a path is expected here, not a URL") != 2 {
			t.Errorf("validate %q: exit code %d, output:\n%s\nerrors %q; want 1, two refusals of a URL and no %s", args, code, out, errOut, mark)
		}
	}
}

// A line of the expectations that no check judges is said aloud, once for
// each domain that holds one, and is no problem: the exit code is 0.
func TestValidateWarnsOfIssuerAndCertnameLinesWhenCertificatesIsNotSet(t *testing.T) {
	const text = ": the issuer and certname lines are not judged: certificates is not set in the config"
	corpIssuer := strings.Replace(cliCorpFile, "domain corp.test.\n", "domain corp.test.\nissuer ca.test\n", 1)
	shopCertname := strings.Replace(cliShopFile, "domain shop.test.\n", "domain shop.test.\ncertname *.shop.test.\n", 1)
	for _, c := range []struct {
		name       string
		corp, shop string
		warned     []string
	}{
		{"issuer line", corpIssuer, cliShopFile, []string{"corp.test."}},
		{"certname line", cliCorpFile, shopCertname, []string{"shop.test."}},
		{"both", corpIssuer, shopCertname, []string{"corp.test.", "shop.test."}},
		{"none", cliCorpFile, cliShopFile, nil},
	} {
		t.Run(c.name, func(t *testing.T) {
			w := cliNewWorld(t, false)
			cliSetSecrets(t, w)
			cliWriteFile(t, w.corp, c.corp)
			cliWriteFile(t, w.shop, c.shop)
			var warnings []string
			for _, d := range c.warned {
				warnings = append(warnings, d+text)
			}
			summary := cliResultJSON{Valid: true, Problems: 0, Domains: 2, Channels: []string{"slack", "siem"}}

			code, out, errOut := cliValidate(w)
			if code != 0 || errOut != "" {
				t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
			}
			cliSame(t, "osk-dns-watcher validate", out, append(cliPrefixed("warning ", warnings), "valid: 2 domains, channels slack,siem")...)

			code, out, errOut = cliValidate(w, "--json")
			if code != 0 || errOut != "" {
				t.Errorf("--json: exit code %d, errors %q; want 0 and none", code, errOut)
			}
			cliSame(t, "osk-dns-watcher validate --json", out, cliValidateJSON(t, nil, warnings, summary)...)
		})
	}
}

// With certificates set the lines are judged, so no warning names them; the
// config gives only its own warning.
func TestValidateDoesNotWarnOfIssuerAndCertnameLinesWhenCertificatesIsSet(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	cliWriteFile(t, w.config, cliConfigText(w.state, `,
  "certificates": {"url": "https://certs.example.test/v1/issuances", "interval": "10m"}`))
	cliWriteFile(t, w.corp, strings.Replace(cliCorpFile, "domain corp.test.\n", "domain corp.test.\nissuer ca.test\ncertname *.corp.test.\n", 1))
	c, problems := config.Read(w.config)
	if c == nil || len(c.Warnings()) != 1 {
		t.Fatalf("the config of the test: %v, %v; want it valid with one warning", c, problems)
	}
	code, out, errOut := cliValidate(w)
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk-dns-watcher validate", out, "warning "+c.Warnings()[0], "valid: 2 domains, channels slack,siem")
}
