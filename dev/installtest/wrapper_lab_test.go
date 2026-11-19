//go:build lab

package installtest

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// wrDocker is the stand-in docker of these tests. It writes each argument on
// a line of its own to $LOG, so an argument with a space stays one line.
const wrDocker = `#!/bin/sh
printf '%s\n' "$@" >"$LOG"
`

// wrRun runs deploy/osk-dns-watcher of the tree under test from another
// folder, with the stand-in docker first in PATH and an input that is not a
// terminal, and gives the arguments that docker got.
func wrRun(t *testing.T, args ...string) []string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(dir+"/bin", 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir+"/bin/docker", []byte(wrDocker), 0o755); err != nil {
		t.Fatal(err)
	}
	env := append(os.Environ(), "PATH="+dir+"/bin:"+os.Getenv("PATH"), "LOG="+dir+"/docker.log")
	r := qsRun(qsBound, dir, env, "", sgSrc(t)+"/deploy/osk-dns-watcher", args...)
	if r.code != 0 || r.stdout != "" || r.stderr != "" {
		t.Fatalf("osk-dns-watcher %q: exit %d; want 0 and no output of its own:\n%s", args, r.code, r)
	}
	data, err := os.ReadFile(dir + "/docker.log")
	if err != nil {
		t.Fatal(err)
	}
	return strings.Split(strings.TrimSuffix(string(data), "\n"), "\n")
}

func TestWrapperRunsCommandInService(t *testing.T) {
	deploy, err := filepath.EvalSymlinks(sgSrc(t) + "/deploy")
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name       string
		args, want []string
	}{
		{"status gets the config", []string{"status"},
			[]string{"status", "--config", "/data/config.json"}},
		{"a config of its own stays", []string{"accept", "--config", "/data/other.json", "3"},
			[]string{"accept", "--config", "/data/other.json", "3"}},
		{"a config of its own after =", []string{"status", "--config=/data/other.json", "--json"},
			[]string{"status", "--config=/data/other.json", "--json"}},
		{"a command without a config gets none", []string{"version"},
			[]string{"version"}},
		{"an argument with a space stays one", []string{"check", "--expect", "my domain.expect"},
			[]string{"check", "--expect", "my domain.expect"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			want := append([]string{"compose", "-f", deploy + "/compose.yaml", "exec", "-T", "watcher", "osk-dns-watcher"}, c.want...)
			if got := wrRun(t, c.args...); !slices.Equal(got, want) {
				t.Errorf("docker got %q, want %q", got, want)
			}
		})
	}
}
