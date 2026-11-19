//go:build lab

package deploy

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// These tests play a stranger who has only git and Docker: they run the
// quick start of README.md word for word against the lab, then look at what
// it left running. They share one deployment, so they run in the order of
// this file. They need a container with the Docker CLI, Compose and git
// that reaches the engine through its socket, LAB_ID, and
// QUICKSTART_PLATFORM, the platform of the images (linux/amd64 or
// linux/arm64).

const (
	qsRoot   = "/tmp/qs"
	qsBare   = qsRoot + "/osk.git"
	qsOwner  = qsRoot + "/owner" // the owner's clone, which makes the releases
	qsKey    = qsRoot + "/key"   // the throwaway key that signs them
	qsWork   = qsRoot + "/work"
	qsDeploy = qsWork + "/dns-monitoring/deploy"
	qsOrigin = "https://github.com/Opsek/dns-monitoring.git"
	// qsOther is the project name in compose.yaml, so a real setup on the
	// same engine has it.
	qsOther = "osk"
	qsBound = 2 * time.Minute
)

var (
	qsLab      string // LAB_ID
	qsPlatform string // QUICKSTART_PLATFORM
	qsSrc      string // the tree under test, read-only
	qsSkip     string // why the tests skip; empty when they run
	qsReady    bool   // the quick start ended with exit 0
	qsMarker   = qsRandom()
)

func qsProject() string { return "oskqs" + qsLab }
func qsNet() string     { return "10.53." + qsLab + "." }
func qsRunner() string  { return "osklab" + qsLab + "-runner-1" }
func qsPath() string    { return "/slack/T0/B0/" + qsMarker }
func qsURL() string     { return "https://hooks.lab.test" + qsPath() }

func qsRandom() string {
	b := make([]byte, 12)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func TestMain(m *testing.M) {
	qsLab, qsPlatform = os.Getenv("LAB_ID"), os.Getenv("QUICKSTART_PLATFORM")
	if qsPlatform == "" {
		qsSkip = "QUICKSTART_PLATFORM is not set: these tests run only in the quickstart phase of the gate, " +
			"which also sets LAB_ID and gives the Docker socket"
		os.Exit(m.Run())
	}
	if !regexp.MustCompile(`^[0-9]$`).MatchString(qsLab) || (qsPlatform != "linux/amd64" && qsPlatform != "linux/arm64") {
		fmt.Printf("FAIL quickstart: LAB_ID is %q and QUICKSTART_PLATFORM is %q; want a digit and linux/amd64 or linux/arm64\n", qsLab, qsPlatform)
		os.Exit(1)
	}
	wd, err := os.Getwd()
	if err != nil {
		fmt.Printf("FAIL quickstart: %v\n", err)
		os.Exit(1)
	}
	qsSrc = filepath.Dir(wd)
	os.Exit(qsMain(m))
}

// qsMain wraps the tests in the removal of the test's project and checks
// what only shows after the last removal: nothing of the project is left,
// and the project of a real setup is as it was.
func qsMain(m *testing.M) int {
	if err := os.MkdirAll(qsRoot, 0o700); err != nil {
		return qsReport(err.Error())
	}
	if err := qsClean(); err != nil {
		return qsReport("before the tests: " + err.Error())
	}
	if left := qsLeft(); left != "" {
		return qsReport("before the tests " + left)
	}
	decoy, err := qsDecoyUp()
	if err != nil {
		return qsReport(err.Error(), qsDecoyDown())
	}
	before, err := qsWitness(decoy)
	if err != nil {
		return qsReport(err.Error(), qsDecoyDown())
	}
	if r := qsRun(qsBound, "", nil, "", "docker", "exec", qsRunner(), "labctl", "hooks", "clear"); r.code != 0 {
		return qsReport(r.String(), qsDecoyDown())
	}

	code := m.Run()

	var problems []string
	if err := qsClean(); err != nil {
		problems = append(problems, "after the tests: "+err.Error())
	}
	if left := qsLeft(); left != "" {
		problems = append(problems, "after the tests "+left)
	}
	if after, err := qsWitness(decoy); err != nil {
		problems = append(problems, err.Error())
	} else if after != before {
		problems = append(problems, fmt.Sprintf("the project %s changed during the tests; before:\n%s\nafter:\n%s", qsOther, before, after))
	}
	if qsReport(append(problems, qsDecoyDown())...) != 0 {
		return 1
	}
	return code
}

// qsReport prints each problem that is not empty and gives the exit code.
func qsReport(problems ...string) int {
	code := 0
	for _, p := range problems {
		if p != "" {
			fmt.Println("FAIL quickstart: " + p)
			code = 1
		}
	}
	return code
}

// qsClean removes everything of the test's project. Some image stores keep
// the image that an update replaced, untagged but with the project's label,
// and down does not remove it; so the images go by that label too.
func qsClean() error {
	r := qsRun(5*time.Minute, "", nil, "", "docker", "compose", "-p", qsProject(),
		"-f", filepath.Join(qsSrc, "deploy", "compose.yaml"), "--profile", "setup",
		"down", "--volumes", "--rmi", "local", "--remove-orphans")
	if r.code != 0 {
		return errors.New(r.String())
	}
	r = qsRun(qsBound, "", nil, "", "docker", "image", "ls", "-q", "--filter", "label=com.docker.compose.project="+qsProject())
	if r.code != 0 {
		return errors.New(r.String())
	}
	ids := slices.Compact(slices.Sorted(slices.Values(strings.Fields(r.stdout))))
	if len(ids) == 0 {
		return nil
	}
	if r := qsRun(qsBound, "", nil, "", "docker", append([]string{"image", "rm"}, ids...)...); r.code != 0 {
		return errors.New(r.String())
	}
	return nil
}

// qsLeft names the containers, networks, volumes and images of the test's
// project, found by the label of Compose and by name. It gives "" when
// there is none.
func qsLeft() string {
	p := qsProject()
	label := "label=com.docker.compose.project=" + p
	lists := [][]string{
		{"container", "ls", "-a", "--filter", label, "--format", "container {{.Names}}"},
		{"container", "ls", "-a", "--filter", "name=" + p, "--format", "container {{.Names}}"},
		{"network", "ls", "--filter", label, "--format", "network {{.Name}}"},
		{"network", "ls", "--filter", "name=" + p, "--format", "network {{.Name}}"},
		{"volume", "ls", "--filter", label, "--format", "volume {{.Name}}"},
		{"volume", "ls", "--filter", "name=" + p, "--format", "volume {{.Name}}"},
		{"image", "ls", "--filter", label, "--format", "image {{.ID}} {{.Repository}}:{{.Tag}}"},
		{"image", "ls", "--filter", "reference=" + p + "-*", "--format", "image {{.ID}} {{.Repository}}:{{.Tag}}"},
	}
	var left []string
	for _, args := range lists {
		r := qsRun(qsBound, "", nil, "", "docker", args...)
		if r.code != 0 {
			return "the listing failed: " + r.String()
		}
		for line := range strings.Lines(r.stdout) {
			if line = strings.TrimSpace(line); line != "" {
				left = append(left, line)
			}
		}
	}
	if len(left) == 0 {
		return ""
	}
	return "the project " + p + " has: " + strings.Join(slices.Compact(slices.Sorted(slices.Values(left))), "; ")
}

// qsDecoyUp starts a stand-in for a real setup: a Compose project with the
// project, service and volume names of compose.yaml, and random bytes in
// its volume. A test that ran under the wrong project name would replace
// its container or change its volume. When a project of that name exists
// already, it starts nothing: that project is then the witness, looked at
// but never touched. It gives the id of the decoy's container, or "".
func qsDecoyUp() (string, error) {
	label := "label=com.docker.compose.project=" + qsOther
	for _, kind := range []string{"container", "volume", "network"} {
		args := []string{kind, "ls", "-q", "--filter", label}
		if kind == "container" {
			args = append(args, "-a")
		}
		r := qsRun(qsBound, "", nil, "", "docker", args...)
		if r.code != 0 {
			return "", errors.New(r.String())
		}
		if strings.TrimSpace(r.stdout) != "" {
			fmt.Printf("a Compose project %s exists on this engine; it is the witness instead of a decoy\n", qsOther)
			return "", nil
		}
	}
	// The lab's image is on the engine already, so the decoy needs no pull.
	r := qsRun(qsBound, "", nil, "", "docker", "inspect", "-f", "{{.Config.Image}}", qsRunner())
	if r.code != 0 {
		return "", errors.New(r.String())
	}
	file := filepath.Join(qsRoot, "decoy.yaml")
	text := fmt.Sprintf(`name: %[1]s
services:
  osk:
    image: %[2]s
    command: [sleep, infinity]
    network_mode: none
    labels: {osk.gate: "%[3]s"}
    volumes: [data:/data]
volumes:
  data:
    labels: {osk.gate: "%[3]s"}
`, qsOther, strings.TrimSpace(r.stdout), qsLab)
	if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
		return "", err
	}
	if r := qsRun(qsBound, "", nil, "", "docker", "compose", "-p", qsOther, "-f", file, "up", "--detach", "--wait"); r.code != 0 {
		return "", errors.New(r.String())
	}
	r = qsRun(qsBound, "", nil, "", "docker", "compose", "-p", qsOther, "-f", file, "ps", "-q", "osk")
	id := strings.TrimSpace(r.stdout)
	if r.code != 0 || id == "" {
		return "", errors.New(r.String())
	}
	if r := qsRun(qsBound, "", nil, "", "docker", "exec", id, "sh", "-c", "head -c 4096 /dev/urandom > /data/witness"); r.code != 0 {
		return "", errors.New(r.String())
	}
	return id, nil
}

// qsWitness describes the project of a real setup as the engine shows it:
// its containers, volumes, networks and images, and the bytes of the
// decoy's volume when the test made the decoy.
func qsWitness(decoy string) (string, error) {
	label := "label=com.docker.compose.project=" + qsOther
	r := qsRun(qsBound, "", nil, "", "docker", "container", "ls", "-aq", "--filter", label)
	if r.code != 0 {
		return "", errors.New(r.String())
	}
	var b strings.Builder
	if ids := strings.Fields(r.stdout); len(ids) > 0 {
		r = qsRun(qsBound, "", nil, "", "docker", append([]string{"inspect", "-f",
			"container {{.Id}} {{.Name}} {{.Image}} {{.State.Status}} {{.State.StartedAt}}"}, ids...)...)
		if r.code != 0 {
			return "", errors.New(r.String())
		}
		b.WriteString(r.stdout)
	}
	for _, args := range [][]string{
		{"volume", "ls", "--filter", label, "--format", "volume {{.Name}} {{.Driver}}"},
		{"network", "ls", "--no-trunc", "--filter", label, "--format", "network {{.ID}} {{.Name}}"},
		{"image", "ls", "--no-trunc", "--filter", "reference=" + qsOther + "-osk", "--filter", "reference=" + qsOther + "-init",
			"--format", "image {{.ID}} {{.Repository}}:{{.Tag}}"},
	} {
		r = qsRun(qsBound, "", nil, "", "docker", args...)
		if r.code != 0 {
			return "", errors.New(r.String())
		}
		b.WriteString(r.stdout)
	}
	if decoy != "" {
		r = qsRun(qsBound, "", nil, "", "docker", "exec", decoy, "sh", "-c", "tar -cf - -C /data . | sha256sum")
		if r.code != 0 {
			return b.String(), errors.New(r.String())
		}
		b.WriteString("data " + r.stdout)
	}
	return b.String(), nil
}

// qsDecoyDown removes the decoy by the labels that only the decoy has, so
// a real project of the same name is never touched. It gives a problem or
// "".
func qsDecoyDown() string {
	filters := []string{"--filter", "label=com.docker.compose.project=" + qsOther, "--filter", "label=osk.gate=" + qsLab}
	for _, kind := range []string{"container", "volume"} {
		args := append([]string{kind, "ls", "-q"}, filters...)
		if kind == "container" {
			args = append(args, "-a")
		}
		r := qsRun(qsBound, "", nil, "", "docker", args...)
		if r.code != 0 {
			return r.String()
		}
		if ids := strings.Fields(r.stdout); len(ids) > 0 {
			if r := qsRun(qsBound, "", nil, "", "docker", append([]string{kind, "rm", "-f"}, ids...)...); r.code != 0 {
				return r.String()
			}
		}
	}
	return ""
}

// qsResult is how a command ended.
type qsResult struct {
	command        string
	stdout, stderr string
	code           int // -1 when it did not end by itself within its bound or did not start
	err            error
}

func (r qsResult) String() string {
	return fmt.Sprintf("%s: exit code %d (%v)\nstandard output:\n%s\nstandard error:\n%s", r.command, r.code, r.err, r.stdout, r.stderr)
}

// qsRun runs a command within bound. A nil env is the test's own. When the
// bound passes the command is killed, and its pipes are closed soon after,
// although the processes it started may still hold them.
func qsRun(bound time.Duration, dir string, env []string, stdin, name string, args ...string) qsResult {
	ctx, cancel := context.WithTimeout(context.Background(), bound)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir, cmd.Env, cmd.Stdin = dir, env, strings.NewReader(stdin)
	cmd.WaitDelay = 10 * time.Second
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	r := qsResult{command: strings.Join(append([]string{name}, args...), " "), stdout: stdout.String(), stderr: stderr.String(), err: err}
	var exit *exec.ExitError
	switch {
	case ctx.Err() != nil:
		r.code, r.err = -1, fmt.Errorf("not done within %v", bound)
	case errors.As(err, &exit):
		r.code = exit.ExitCode()
	case err != nil:
		r.code = -1
	}
	return r
}

// qsMust gives the standard output of a command that exited 0, and fails
// the test with all of its output otherwise.
func qsMust(t *testing.T, r qsResult) string {
	t.Helper()
	if r.code != 0 {
		t.Fatal(r)
	}
	return r.stdout
}

func qsDocker(t *testing.T, args ...string) string {
	t.Helper()
	return qsMust(t, qsRun(qsBound, "", nil, "", "docker", args...))
}

func qsInspect(t *testing.T, format, id string) string {
	t.Helper()
	return strings.TrimSpace(qsDocker(t, "inspect", "-f", format, id))
}

func qsLabctl(t *testing.T, args ...string) string {
	t.Helper()
	return qsDocker(t, append([]string{"exec", qsRunner(), "labctl"}, args...)...)
}

// qsEnviron is the environment of the quick start: the test's own with an
// empty home and the lab inputs, the only differences from a stranger's
// run.
func qsEnviron() []string {
	return append(os.Environ(),
		"HOME="+qsRoot+"/home",
		"GIT_CONFIG_GLOBAL="+qsRoot+"/gitconfig",
		"COMPOSE_FILE=compose.yaml:"+qsRoot+"/lab.yaml",
		// start.sh names its Compose file itself and adds this one.
		"OSK_COMPOSE_EXTRA="+qsRoot+"/lab.yaml",
		"COMPOSE_PROJECT_NAME="+qsProject(),
		"DOCKER_DEFAULT_PLATFORM="+qsPlatform)
}

// qsCompose runs docker compose as the stranger would: in the deploy
// folder of the clone, with the environment of the quick start.
func qsCompose(bound time.Duration, args ...string) qsResult {
	return qsRun(bound, qsDeploy, qsEnviron(), "", "docker", append([]string{"compose"}, args...)...)
}

// qsExec runs a command in the service osk.
func qsExec(t *testing.T, args ...string) string {
	t.Helper()
	return qsMust(t, qsCompose(qsBound, append([]string{"exec", "-T", "osk"}, args...)...))
}

func qsContainer(t *testing.T) string {
	t.Helper()
	id := strings.TrimSpace(qsMust(t, qsCompose(qsBound, "ps", "-q", "osk")))
	if id == "" || strings.ContainsAny(id, " \n") {
		t.Fatalf("docker compose ps -q osk gave %q, want the id of one running container", id)
	}
	return id
}

func qsGit(t *testing.T, dir string, args ...string) {
	t.Helper()
	qsMust(t, qsRun(qsBound, dir, qsEnviron(), "", "git", append([]string{"-c", "user.name=osk test", "-c", "user.email=test@lab.test"}, args...)...))
}

func qsWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func qsNeed(t *testing.T, afterQuickStart bool) {
	t.Helper()
	if qsSkip != "" {
		t.Skip(qsSkip)
	}
	if afterQuickStart && !qsReady {
		t.Fatal("the quick start did not end with exit 0 (see TestQuickStartGivesTestAlert), so there is no service to look at")
	}
}

// qsPrepare makes the lab inputs: a bare repository of the tree under test,
// which the URL of the README leads to, an empty home, an empty work folder
// and the Compose file that puts the services on the lab network.
func qsPrepare(t *testing.T) {
	t.Helper()
	for _, dir := range []string{qsRoot + "/home", qsWork} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	qsWrite(t, qsRoot+"/gitconfig", fmt.Sprintf("[url \"file://%s\"]\n\tinsteadOf = %s\n", qsBare, qsOrigin))
	qsGit(t, "", "init", "-q", "--bare", qsBare)
	// The tree is read-only and belongs to another user; the index lives in
	// the bare repository.
	tree := []string{"--git-dir=" + qsBare, "--work-tree=" + qsSrc, "-c", "safe.directory=*"}
	qsGit(t, "", append(tree, "add", "-A")...)
	qsGit(t, "", append(tree, "commit", "-q", "-m", "the tree under test")...)
	// start.sh installs only a release that a key of release/allowed_signers
	// signed: the copy gets a throwaway key in place of the owner's, and the
	// release v0.0.1 signed with it.
	qsMust(t, qsRun(qsBound, "", qsEnviron(), "", "ssh-keygen", "-q", "-t", "ed25519", "-N", "", "-C", "", "-f", qsKey))
	pub, err := os.ReadFile(qsKey + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	qsGit(t, "", "clone", "-q", qsBare, qsOwner)
	qsWrite(t, qsOwner+"/release/allowed_signers", `osk-release namespaces="file,git" `+strings.TrimSpace(string(pub))+"\n")
	qsGit(t, qsOwner, "commit", "-q", "-am", "the key of the test")
	qsRelease(t, "v0.0.1")
	// The lab's volume also holds its keys. The service sees only its
	// folder ca, which holds the CA alone, so SSL_CERT_DIR adds that one
	// certificate to the image's own.
	qsWrite(t, qsRoot+"/lab.yaml", fmt.Sprintf(`services:
  osk:
    networks: [lab]
    environment: {SSL_CERT_DIR: /lab}
    volumes:
      - {type: volume, source: lab, target: /lab, read_only: true, volume: {subpath: ca}}
  init:
    networks: [lab]
    command: [init, --config, /data/osk.json, --root-server, "10.53.%[1]s.2", --extra-range, "10.53.%[1]s.0/24"]
networks:
  lab: {name: osklab%[1]s_lab, external: true}
volumes:
  lab: {name: osklab%[1]s_lab, external: true}
`, qsLab))
}

// qsSafeConfig stops the test unless the quick start will run as the
// test's project, and unless no service gets anything of the host: the
// clean container holds the engine's socket, so a mistake here reaches the
// host.
func qsSafeConfig(t *testing.T) {
	t.Helper()
	out := qsMust(t, qsRun(qsBound, filepath.Join(qsSrc, "deploy"), qsEnviron(), "", "docker",
		"compose", "--profile", "setup", "config", "--format", "json"))
	var c struct {
		Name     string                                `json:"name"`
		Services map[string]map[string]json.RawMessage `json:"services"`
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, out)
	}
	if c.Name != qsProject() {
		t.Fatalf("docker compose config gives the project %q, want %q from COMPOSE_PROJECT_NAME", c.Name, qsProject())
	}
	if len(c.Services) != 2 {
		t.Errorf("docker compose config with the profile setup gives %d services, want osk and init", len(c.Services))
	}
	for name, s := range c.Services {
		for _, key := range []string{"ports", "privileged", "cap_add", "devices", "pid", "network_mode"} {
			if v, ok := s[key]; ok && !slices.Contains([]string{"null", "false", `""`, "[]", "{}"}, string(v)) {
				t.Errorf("service %s has %s %s", name, key, v)
			}
		}
		var volumes []struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		}
		if v, ok := s["volumes"]; ok {
			if err := json.Unmarshal(v, &volumes); err != nil {
				t.Errorf("service %s: volumes %s: %v", name, v, err)
			}
		}
		for _, v := range volumes {
			if v.Type != "volume" {
				t.Errorf("service %s mounts %s as %s, want only named volumes", name, v.Target, v.Type)
			}
		}
	}
	// What the stranger types runs as the user wrote it; the lab only adds its flags.
	base := "init --config /data/osk.json"
	if got := qsInitCommand(t, "-f", "compose.yaml"); got != base {
		t.Errorf("deploy/compose.yaml alone gives the service init the command %q, want %q", got, base)
	}
	lab := base + " --root-server " + qsNet() + "2 --extra-range " + qsNet() + "0/24"
	if got := qsInitCommand(t); got != lab {
		t.Errorf("with the lab file the service init gets the command %q, want %q", got, lab)
	}
	if t.Failed() {
		t.FailNow()
	}
}

// qsInitCommand gives the command of the service init as docker compose config
// shows it, for the compose files in args, or for those of the environment of
// the quick start when there are none.
func qsInitCommand(t *testing.T, args ...string) string {
	t.Helper()
	out := qsMust(t, qsRun(qsBound, filepath.Join(qsSrc, "deploy"), qsEnviron(), "", "docker",
		append(append([]string{"compose"}, args...), "--profile", "setup", "config", "--format", "json")...))
	var c struct {
		Services map[string]struct {
			Command []string `json:"command"`
		} `json:"services"`
	}
	if err := json.Unmarshal([]byte(out), &c); err != nil {
		t.Fatalf("docker compose config: %v\n%s", err, out)
	}
	return strings.Join(c.Services["init"].Command, " ")
}

// qsScript writes the README block that starts with the line
// "```sh <name>" to a file, as it is, up to the next fence.
func qsScript(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(qsSrc, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(string(data), "\n")
	start := -1
	for i, line := range lines {
		if line == "```sh "+name {
			if start >= 0 {
				t.Fatalf("README.md holds the line \"```sh %s\" more than once", name)
			}
			start = i
		}
	}
	if start < 0 {
		t.Fatalf("README.md has no line \"```sh %s\"", name)
	}
	end := slices.IndexFunc(lines[start+1:], func(l string) bool { return strings.HasPrefix(l, "```") })
	if end < 0 {
		t.Fatalf("the block %s of README.md has no end", name)
	}
	path := filepath.Join(qsRoot, name+".sh")
	qsWrite(t, path, strings.Join(lines[start+1:start+1+end], "\n")+"\n")
	return path
}

// qsInOrder fails when the lines of want are not all among the lines of
// got, in this order.
func qsInOrder(t *testing.T, what, got string, want []string) {
	t.Helper()
	i := 0
	for line := range strings.Lines(got) {
		if i < len(want) && strings.TrimRight(line, "\r\n") == want[i] {
			i++
		}
	}
	if i < len(want) {
		t.Errorf("%s does not show, in order, the line %q and those after it:\n%s\nfull output:\n%s",
			what, want[i], strings.Join(want[i:], "\n"), got)
	}
}

func qsNoMarker(t *testing.T, what string, texts ...string) {
	t.Helper()
	for _, text := range texts {
		if strings.Contains(text, qsMarker) {
			t.Errorf("%s holds the webhook URL:\n%s", what, text)
		}
	}
}

// qsWarnings are the warnings of a config with the lab's two network
// settings.
func qsWarnings(t *testing.T) []string {
	t.Helper()
	c := config.Config{
		RootServers: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(qsNet()+"2"), 0)},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix(qsNet() + "0/24")},
	}
	w := c.Warnings()
	if len(w) != 2 {
		t.Fatalf("the lab settings give %d warnings, want 2: %q", len(w), w)
	}
	return w
}

// qsSetupLines is what osk init shows when it sets up corp.test. in the
// base state of the lab: the dialogue as a terminal shows it, but without
// its codes, and the lines of the expectations file as osk prints them.
func qsSetupLines(t *testing.T) []string {
	t.Helper()
	n := qsNet()
	f, err := expect.Parse([]byte(strings.Join([]string{
		"domain corp.test.",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. DS none",
		"corp.test. A " + n + "80",
		"corp.test. AAAA fd53:0:0:" + qsLab + "::80",
		"corp.test. MX 10 mail.corp.test.",
		`corp.test. TXT "v=spf1 mx -all"`,
		`corp.test. CAA 0 issue "ca.test"`,
		"ns1.corp.test. A " + n + "11",
		"ns1.corp.test. AAAA none",
		"ns2.corp.test. A " + n + "12",
		"ns2.corp.test. AAAA none",
		"www.corp.test. A " + n + "81",
	}, "\n") + "\n"))
	if err != nil {
		t.Fatal(err)
	}
	lines := []string{
		"Set up osk: two questions, then osk shows what it sees. Nothing is written until you type yes.",
		"",
		"Domains to watch, separated by spaces: corp.test",
		"Slack incoming webhook URL (hidden): [hidden]",
		"",
		"Asking the servers of your domains, starting from the root servers ...",
		"",
		"corp.test. as osk sees it now. Once you confirm, osk alerts when the servers differ from these lines:",
	}
	for line := range strings.Lines(f.String()) {
		lines = append(lines, "  "+strings.TrimSuffix(line, "\n"))
	}
	for _, w := range qsWarnings(t) {
		lines = append(lines, "warning "+w)
	}
	return append(lines,
		"",
		"Trust these lines and write the setup to /data? Type yes: yes",
		"Wrote /data/osk.json, /data/corp.test.expect and /data/slack-url.")
}

// qsHook is one request that the lab's receiver stored.
type qsHook struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Body   string `json:"body"`
	Status int    `json:"status"`
}

// qsTexts gives the text of each message that the receiver holds. Each must
// be a Slack message to the URL of the setup, answered 200.
func qsTexts(t *testing.T) []string {
	t.Helper()
	var texts []string
	for line := range strings.Lines(qsLabctl(t, "hooks", "list")) {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var h qsHook
		if err := json.Unmarshal([]byte(line), &h); err != nil {
			t.Fatalf("labctl hooks list: %v: %s", err, line)
		}
		var body struct {
			Text string `json:"text"`
		}
		if h.Method != "POST" || h.Path != qsPath() || h.Status != 200 || json.Unmarshal([]byte(h.Body), &body) != nil {
			t.Errorf("the receiver holds %s; want a POST of a JSON text to the path of the setup's URL, answered 200", line)
		}
		texts = append(texts, body.Text)
	}
	return texts
}

func qsCount(texts []string, prefix string) int {
	n := 0
	for _, text := range texts {
		if strings.HasPrefix(text, prefix) {
			n++
		}
	}
	return n
}

// qsWaitTexts gives the texts of the receiver once done holds for them, or
// once bound has passed.
func qsWaitTexts(t *testing.T, bound time.Duration, done func([]string) bool) []string {
	t.Helper()
	deadline := time.Now().Add(bound)
	for {
		texts := qsTexts(t)
		if done(texts) || time.Now().After(deadline) {
			return texts
		}
		time.Sleep(time.Second)
	}
}

var (
	qsClock = regexp.MustCompile(`(?m)^:clock3: (\d{2}:\d{2}:\d{2} · \d{1,2} [A-Z][a-z]{2} \d{4}) UTC$`)
	// The text pads the label of the stored line "request   <id>" by one
	// column.
	qsRequest = regexp.MustCompile(`(?m)^request    ([0-9a-f]{32})$`)
)

const (
	qsTestHead = ":test_tube: *TEST* · osk can send to this channel"
	qsDownHead = ":warning: *DOWN* · osk did not run for"
	qsWWWHead  = ":red_circle: *HIGH* · `www.corp.test. A` changed"
)

// qsTestNotice checks that text is the test notice that shows the one line
// view and was written between start and end.
func qsTestNotice(t *testing.T, text, view string, start, end time.Time) {
	t.Helper()
	m := qsClock.FindStringSubmatch(text)
	if m == nil {
		t.Errorf("the message has no time line:\n%s", text)
		return
	}
	at, err := time.Parse("15:04:05 · 2 Jan 2006", m[1])
	if err != nil || at.Before(start.Truncate(time.Second)) || at.After(end) {
		t.Errorf("the message has the time %s, want one from %s to %s (%v)", m[1], start.UTC(), end.UTC(), err)
	}
	if want := deliver.NoticeText(store.Notice{Kind: store.NoticeTest, Lines: []string{view}, At: at}); text != want {
		t.Errorf("message:\n%s\nwant:\n%s", text, want)
	}
}

// qsSums gives the SHA-256 of the files that a setup must keep as they are.
func qsSums(t *testing.T) string {
	t.Helper()
	return qsExec(t, "sha256sum", "/data/osk.json", "/data/corp.test.expect", "/data/slack-url")
}

func TestQuickStartGivesTestAlert(t *testing.T) {
	qsNeed(t, false)
	qsPrepare(t)
	qsSafeConfig(t)
	script := qsScript(t, "quickstart")
	start := time.Now()
	r := qsRun(60*time.Minute, qsWork, qsEnviron(), "corp.test\n"+qsURL()+"\nyes\n", "sh", "-eu", script)
	end := time.Now()
	if r.code != 0 {
		t.Fatal(r)
	}
	qsReady = true

	t.Run("start.sh shows the setup, then the test message, then the end", func(t *testing.T) {
		qsInOrder(t, "the quick start", r.stdout, append(qsSetupLines(t),
			"test slack sent",
			"osk is running. Your channel has a test message from it."))
		if strings.Contains(r.stdout, "Not watched") {
			t.Errorf("osk init left out sets of the lab's base state:\n%s", r.stdout)
		}
	})

	t.Run("exactly one test message reached the receiver", func(t *testing.T) {
		texts := qsTexts(t)
		if len(texts) != 1 {
			t.Fatalf("the receiver holds %d messages, want 1:\n%s", len(texts), strings.Join(texts, "\n----\n"))
		}
		id := ""
		if m := qsRequest.FindStringSubmatch(texts[0]); m != nil {
			id = m[1]
		}
		qsTestNotice(t, texts[0], "request   "+id, start, end)
	})

	t.Run("osk runs healthy as user 10001 on the platform of the test", func(t *testing.T) {
		id := qsContainer(t)
		if got := qsInspect(t, "{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}", id); got != "running healthy" {
			t.Errorf("the container of osk is %q, want running healthy", got)
		}
		image := qsInspect(t, "{{.Image}}", id)
		if got := qsInspect(t, "{{.Os}}/{{.Architecture}}", image); got != qsPlatform {
			t.Errorf("the image of osk is for %s, want %s", got, qsPlatform)
		}
		qsExec(t, "osk", "status", "--config", "/data/osk.json")
		if got := qsExec(t, "osk", "version"); !strings.HasPrefix(got, "osk 0.0.1\n") {
			t.Errorf("osk version gives:\n%s\nwant first osk 0.0.1, the version of the signed release", got)
		}
		if got := strings.TrimSpace(qsExec(t, "id", "-u")); got != "10001" {
			t.Errorf("id -u in the service gives %s, want 10001", got)
		}
		// The service process itself, not only a command started beside it.
		for line := range strings.Lines(qsExec(t, "cat", "/proc/1/status")) {
			if f := strings.Fields(line); len(f) == 5 && f[0] == "Uid:" && !slices.Equal(f[1:], []string{"10001", "10001", "10001", "10001"}) {
				t.Errorf("the first process of the service runs as %s, want 10001", line)
			}
		}
	})

	t.Run("the setup is in the volume, private to the user of osk", func(t *testing.T) {
		id := qsContainer(t)
		if got := qsInspect(t, `{{range .Mounts}}{{if eq .Destination "/data"}}{{.Type}} {{.Name}}{{end}}{{end}}`, id); got != "volume "+qsProject()+"_data" {
			t.Errorf("/data in the service is %q, want the volume %s_data", got, qsProject())
		}
		got := qsExec(t, "stat", "-c", "%a %u %n", "/data", "/data/osk.json", "/data/corp.test.expect", "/data/slack-url", "/data/state")
		want := "700 10001 /data\n600 10001 /data/osk.json\n600 10001 /data/corp.test.expect\n600 10001 /data/slack-url\n700 10001 /data/state\n"
		if got != want {
			t.Errorf("modes, owners and names:\n%s\nwant:\n%s", got, want)
		}
		if got := qsExec(t, "cat", "/data/slack-url"); got != qsURL()+"\n" {
			t.Errorf("/data/slack-url holds %q, want the URL that was typed", got)
		}
	})

	t.Run("the webhook URL is in its file only", func(t *testing.T) {
		qsNoMarker(t, "the output of the quick start", r.stdout, r.stderr)
		if got := qsExec(t, "grep", "-rlF", qsMarker, "/data"); got != "/data/slack-url\n" {
			t.Errorf("the files in /data that hold the URL:\n%s\nwant only /data/slack-url", got)
		}
		qsNoMarker(t, "the log of the service", qsMust(t, qsCompose(qsBound, "logs", "--no-color", "osk")))
	})

	t.Run("a second start asks nothing and keeps the files", func(t *testing.T) {
		before := qsSums(t)
		// No answers: a question would end with "Nothing was written." and exit 1.
		again := qsRun(20*time.Minute, qsWork, qsEnviron(), "", "dns-monitoring/deploy/start.sh")
		if again.code != 0 {
			t.Fatal(again)
		}
		qsInOrder(t, "the second start", again.stdout, []string{
			"osk is set up already: /data/osk.json exists. Nothing to ask.",
			"test slack sent",
			"osk is running. Your channel has a test message from it.",
		})
		for _, question := range []string{"Domains to watch", "Slack incoming webhook URL", "Trust these lines"} {
			if strings.Contains(again.stdout+again.stderr, question) {
				t.Errorf("the second start asks %q:\n%s", question, again)
			}
		}
		qsNoMarker(t, "the output of the second start", again.stdout, again.stderr)
		if after := qsSums(t); after != before {
			t.Errorf("the second start changed the setup; before:\n%s\nafter:\n%s", before, after)
		}
	})
}

func TestImageLooksUpAndCallsHTTPS(t *testing.T) {
	qsNeed(t, true)
	doctor := func(env ...string) qsResult {
		args := []string{"exec", "-T"}
		for _, e := range env {
			args = append(args, "-e", e)
		}
		return qsCompose(qsBound, append(args, "osk", "osk", "doctor", "--config", "/data/osk.json")...)
	}

	t.Run("osk doctor finds the receiver by name and posts to it over HTTPS", func(t *testing.T) {
		base := len(qsTexts(t))
		start := time.Now()
		r := doctor()
		end := time.Now()
		if r.code != 0 {
			t.Errorf("osk doctor exits %d, want 0:\n%s", r.code, r)
		}
		want := []string{"ok   config: 1 domains, channels slack"}
		for _, w := range qsWarnings(t) {
			want = append(want, "warn config: "+w)
		}
		want = append(want,
			"ok   files: no other user can change the config or the expectations, or read the secrets or the state",
			"ok   dns corp.test.: its parent zone answers; osk found it from the root servers, without this machine's resolver",
			"ok   webhook slack: hooks.lab.test:443 answered 200; a test message from osk doctor was sent",
			"ok   clock: <d> from the time of hooks.lab.test:443",
			"doctor: no problems")
		clock := regexp.MustCompile(`(?m)^ok   clock: [0-9hms.]+ from the time of hooks\.lab\.test:443$`)
		qsInOrder(t, "osk doctor", clock.ReplaceAllString(r.stdout, "ok   clock: <d> from the time of hooks.lab.test:443"), want)
		warnings := 0
		for line := range strings.Lines(r.stdout) {
			switch {
			case strings.HasPrefix(line, "warn"):
				warnings++
			case strings.HasPrefix(line, "FAIL"), strings.HasPrefix(line, "skip"):
				t.Errorf("osk doctor: %s", line)
			}
		}
		if warnings != 2 {
			t.Errorf("osk doctor gives %d warnings, want the 2 of the lab settings:\n%s", warnings, r.stdout)
		}
		texts := qsTexts(t)[base:]
		if len(texts) != 1 {
			t.Fatalf("osk doctor sent %d messages, want 1:\n%s", len(texts), strings.Join(texts, "\n----\n"))
		}
		qsTestNotice(t, texts[0], "from      osk doctor", start, end)
	})

	t.Run("the name comes from Docker's DNS, not from a hosts file", func(t *testing.T) {
		if resolv := qsExec(t, "cat", "/etc/resolv.conf"); !regexp.MustCompile(`(?m)^nameserver 127\.0\.0\.11$`).MatchString(resolv) {
			t.Errorf("/etc/resolv.conf of the service does not name Docker's DNS 127.0.0.11:\n%s", resolv)
		}
		if hosts := qsExec(t, "cat", "/etc/hosts"); strings.Contains(hosts, "hooks.lab.test") {
			t.Errorf("/etc/hosts of the service names hooks.lab.test:\n%s", hosts)
		}
	})

	t.Run("the lab CA is added to the image's own trust store, which stays", func(t *testing.T) {
		id := qsContainer(t)
		env := strings.Split(qsInspect(t, `{{range .Config.Env}}{{println .}}{{end}}`, id), "\n")
		if !slices.Contains(env, "SSL_CERT_DIR=/lab") || slices.ContainsFunc(env, func(e string) bool { return strings.HasPrefix(e, "SSL_CERT_FILE=") }) {
			t.Errorf("the environment of the service:\n%s\nwant SSL_CERT_DIR=/lab and no SSL_CERT_FILE", strings.Join(env, "\n"))
		}
		mounts := strings.Fields(qsInspect(t, `{{range .Mounts}}{{println .Destination}}{{end}}`, id))
		slices.Sort(mounts)
		if !slices.Equal(mounts, []string{"/data", "/lab"}) {
			t.Errorf("the service mounts %v, want /data and /lab only", mounts)
		}
		if got := qsExec(t, "ls", "-A", "/lab"); got != "ca.pem\n" {
			t.Errorf("/lab of the service holds:\n%s\nwant ca.pem only", got)
		}
		count, err := strconv.Atoi(strings.TrimSpace(qsExec(t, "grep", "-c", "BEGIN CERTIFICATE", "/etc/ssl/certs/ca-certificates.crt")))
		if err != nil || count < 100 {
			t.Errorf("the image's bundle holds %d certificates (%v), want at least 100", count, err)
		}

		base := len(qsTexts(t))
		// Without the lab's folder, only the image's bundle decides.
		r := doctor("SSL_CERT_DIR=/nonexistent")
		failed := regexp.MustCompile(`(?m)^FAIL webhook slack: no answer from hooks\.lab\.test:443: network: certificate not trusted\.`)
		if r.code != 1 || !failed.MatchString(r.stdout) {
			t.Errorf("osk doctor without the lab CA: exit %d; want 1 and a webhook line that says the certificate is not trusted:\n%s", r.code, r)
		}
		// With a folder set, Go still reads the bundle file: the lab CA as
		// that file is enough. So the service, which sets no file, trusts
		// the image's bundle and the lab CA together.
		r = doctor("SSL_CERT_FILE=/lab/ca.pem", "SSL_CERT_DIR=/nonexistent")
		if r.code != 0 || !strings.Contains(r.stdout, "\nok   webhook slack: hooks.lab.test:443 answered 200;") {
			t.Errorf("osk doctor with the lab CA as the bundle file: exit %d; want 0 and the webhook answered:\n%s", r.code, r)
		}
		if texts := qsTexts(t)[base:]; len(texts) != 1 {
			t.Errorf("the two runs sent %d messages, want 1, of the run that trusts the lab CA:\n%s", len(texts), strings.Join(texts, "\n----\n"))
		}
	})
}

// The update needs no answer, so its standard input is empty.
func TestUpdateKeepsSetup(t *testing.T) {
	qsNeed(t, true)
	t.Cleanup(func() {
		if r := qsRun(qsBound, "", nil, "", "docker", "exec", qsRunner(), "labctl", "reset"); r.code != 0 {
			t.Error(r)
		}
	})
	base := len(qsTexts(t))
	qsLabctl(t, "set", "both", "www.corp.test.", "300", "A", qsNet()+"99")
	texts := qsWaitTexts(t, 60*time.Second, func(texts []string) bool { return qsCount(texts[base:], qsWWWHead) > 0 })
	if n := qsCount(texts[base:], qsWWWHead); n != 1 {
		t.Fatalf("within 60 s the receiver got %d alerts on www.corp.test. A, want 1:\n%s", n, strings.Join(texts[base:], "\n----\n"))
	}
	alert, opened := qsOpenAlert(t)
	sums := qsSums(t)
	old := qsContainer(t)
	qsPushUpdate(t)

	base = len(texts)
	r := qsRun(20*time.Minute, qsDeploy, qsEnviron(), "", "sh", "-eu", qsScript(t, "update"))
	if r.code != 0 {
		t.Fatal(r)
	}

	t.Run("the update builds the new code and starts a new container", func(t *testing.T) {
		qsInOrder(t, "the update", r.stdout, []string{"osk is set up already: /data/osk.json exists. Nothing to ask.", "test slack sent"})
		qsNoMarker(t, "the output of the update", r.stdout, r.stderr)
		if qsContainer(t) == old {
			t.Errorf("the container of osk is still %s", old)
		}
		if got := qsExec(t, "osk", "version"); !strings.HasPrefix(got, "osk 0.0.2\n") {
			t.Errorf("osk version gives:\n%s\nwant first osk 0.0.2, the version of the new release", got)
		}
	})

	t.Run("the config, the expectations, the URL file and the open alert stay", func(t *testing.T) {
		if after := qsSums(t); after != sums {
			t.Errorf("before the update:\n%s\nafter:\n%s", sums, after)
		}
		if a, o := qsOpenAlert(t); a != alert || o != opened {
			t.Errorf("after the update the alert on www.corp.test. A is %s opened %s, want %s opened %s", a, o, alert, opened)
		}
	})

	// The update stops osk for seconds, and a down time under a minute goes
	// to the log only: such a restart is no alarm.
	t.Run("osk is healthy again and says how long it did not run", func(t *testing.T) {
		qsExec(t, "osk", "status", "--config", "/data/osk.json")
		texts := qsWaitTexts(t, 30*time.Second, func(texts []string) bool { return len(texts) >= base+2 })
		news := texts[base:]
		if len(news) != 1 || qsCount(news, qsDownHead) != 0 || qsCount(news, qsTestHead) != 1 || qsCount(texts, qsWWWHead) != 1 {
			t.Errorf("after the update the receiver got:\n%s\nwant one test notice and no down notice, and still one alert on www.corp.test. A in all",
				strings.Join(news, "\n----\n"))
		}
		if logs := qsMust(t, qsCompose(qsBound, "logs", "--no-color", "osk")); !strings.Contains(logs, `"text":"down since `) {
			t.Errorf("the log of osk after the update does not say how long it did not run:\n%s", logs)
		}
	})

	t.Run("docker compose stop stops osk cleanly", func(t *testing.T) {
		id := qsContainer(t)
		qsMust(t, qsCompose(qsBound, "stop"))
		if code := qsInspect(t, "{{.State.ExitCode}}", id); code != "0" {
			t.Errorf("osk stopped with exit code %s, want 0", code)
		}
		logs := strings.Split(strings.TrimSpace(qsMust(t, qsCompose(qsBound, "logs", "--no-color", "--no-log-prefix", "osk"))), "\n")
		if last := logs[len(logs)-1]; !strings.Contains(last, `"event":"stop"`) {
			t.Errorf("the last log line of osk is %s, want the stop line", last)
		}
	})
}

// qsOpenAlert gives the id and the opening time of the open alert on
// www.corp.test. A, as osk status --json gives them.
func qsOpenAlert(t *testing.T) (id, opened string) {
	t.Helper()
	// An open alert alone does not make osk unhealthy, but status may say
	// so for another reason; its lines are read either way.
	r := qsCompose(qsBound, "exec", "-T", "osk", "osk", "status", "--config", "/data/osk.json", "--json")
	if r.code != 0 && r.code != 1 {
		t.Fatal(r)
	}
	for line := range strings.Lines(r.stdout) {
		var s struct {
			Type string `json:"type"`
			Open []struct {
				ID    json.RawMessage `json:"id"`
				Rule  string          `json:"rule"`
				Check struct {
					Name  string `json:"name"`
					RType string `json:"rtype"`
				} `json:"check"`
				Opened json.RawMessage `json:"opened"`
			} `json:"open"`
		}
		if json.Unmarshal([]byte(line), &s) != nil || s.Type != "status" {
			continue
		}
		for _, a := range s.Open {
			if a.Rule == "record-set" && a.Check.Name == "www.corp.test." && a.Check.RType == "A" {
				return string(a.ID), string(a.Opened)
			}
		}
	}
	t.Fatalf("osk status --json shows no open alert on www.corp.test. A:\n%s", r)
	return "", ""
}

// qsPushUpdate publishes a new release, v0.0.2. The build writes the version
// of the release into osk, so osk version shows whether the update built it.
func qsPushUpdate(t *testing.T) {
	t.Helper()
	qsGit(t, qsOwner, "commit", "-q", "--allow-empty", "-m", "a new version")
	qsRelease(t, "v0.0.2")
}

// qsRelease tags the commit of qsOwner with a tag signed by the throwaway
// key, and pushes both.
func qsRelease(t *testing.T, tag string) {
	t.Helper()
	qsGit(t, qsOwner, "-c", "gpg.format=ssh", "-c", "user.signingkey="+qsKey, "tag", "-s", "-m", "osk "+strings.TrimPrefix(tag, "v"), tag)
	qsGit(t, qsOwner, "push", "-q", "origin", "HEAD", tag)
}
