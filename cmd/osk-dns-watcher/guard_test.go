package main

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/config"
)

// --extra-range is read by the function that reads the ranges of the config:
// a prefix with bits after its length, which may mean one address or the
// whole range, is refused with the same text by check, snapshot and init,
// before any query and before init asks its questions.
func TestGrdExtraRangeFlag(t *testing.T) {
	s := transportStart(t, nil)
	file := filepath.Join(t.TempDir(), "config.json")
	for _, r := range []struct {
		value string
		ok    bool
	}{
		{"10.0.0.1/8", false},
		{"10.0.0.0/8", true},
		{"10.53.7.30/32", true},
		{"fd00::1/8", false},
		{"fd00::/8", true},
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"10.0.0.1/0", false},
		{"::1/0", false},
		{"fe80::1%eth0/64", false},
		{"fe80::%eth0/64", false},
		{"10.0.0.1", false},
		{"10.0.0.0/33", false},
		{"not a prefix", false},
		{"", false},
	} {
		_, rangeErr := config.ParseRange(r.value)
		if (rangeErr == nil) != r.ok {
			t.Errorf("ParseRange(%q): %v; want ok %v", r.value, rangeErr, r.ok)
			continue
		}
		flagArgs := []string{"--root-server", s.addr, "--extra-range", r.value, "corp.test."}
		initArgs := []string{"--config", file, "--root-server", s.addr, "--extra-range", r.value}
		if r.ok {
			// Only read: a run would send queries, and init would ask.
			_, checkMsg := parseArgs(flagArgs, true)
			_, snapshotMsg := parseArgs(flagArgs, false)
			_, _, initMsg := parseInit(initArgs)
			if checkMsg != "" || snapshotMsg != "" || initMsg != "" {
				t.Errorf("--extra-range %q: %q, %q, %q; want it read by check, snapshot and init", r.value, checkMsg, snapshotMsg, initMsg)
			}
			continue
		}
		for _, args := range [][]string{append([]string{"check"}, flagArgs...), append([]string{"snapshot"}, flagArgs...), append([]string{"init"}, initArgs...)} {
			code, out, errOut := transportRun(args...)
			if code != 2 || out != "" || !strings.Contains(errOut, "osk-dns-watcher "+args[0]+": ") || !strings.Contains(errOut, rangeErr.Error()) {
				t.Errorf("%s --extra-range %q: exit code %d, output %q, errors %q; want 2, nothing and %q",
					args[0], r.value, code, out, errOut, rangeErr)
			}
		}
		if n := len(s.queries); n != 0 {
			t.Fatalf("--extra-range %q: the server got %d queries; want none", r.value, n)
		}
	}
	if _, err := config.ParseRange("10.0.0.1/8"); err == nil || err.Error() != "prefix 10.0.0.1/8 has bits after its length; write 10.0.0.0/8" {
		t.Errorf("ParseRange(10.0.0.1/8): %v", err)
	}
}
