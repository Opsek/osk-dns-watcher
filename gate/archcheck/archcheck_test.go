package main

import (
	"slices"
	"strings"
	"testing"
)

// Each rule has two trees under testdata/<rule>/: one that the rule passes
// and one where it finds exactly the listed faults. Each tree has a go.mod of
// its own, most with the module path osk.
func TestRules(t *testing.T) {
	const outside = ", which is not a package of ./cmd/... or ./internal/..."
	cases := []struct {
		tree string
		want []string
	}{
		{"plain-layout/pass", nil},
		{"plain-layout/fail", []string{
			"cmd/osk/main.go:4 imports osk/gate/tool" + outside,
			"cmd/osk/main.go:6 imports osk/internal/a/testdata/helper" + outside,
			"cmd/osk/main.go:7 imports osk/internal/_old" + outside,
			"internal/a/blob.syso is source code other than Go",
			"internal/a/zero.s is source code other than Go",
			"internal/b/b_arm64.go has a name that limits it to some systems",
			"internal/b/b_linux.go has a name that limits it to some systems",
			"internal/b/old.go:1 has a build constraint",
			"internal/b/tagged.go:1 has a build constraint",
		}},
		// The module path of the passing tree has a dot in its first
		// element, which no path of the standard library has.
		{"only-std-and-sqlite/pass", nil},
		{"only-std-and-sqlite/fail", []string{
			"internal/a/a.go:4 imports example.com/lib",
			"internal/a/a.go:9 imports C",
			"go.mod requires example.com/extra",
			"go.mod requires example.com/single",
			"vendor/modules.txt lists example.com/extra",
		}},
		{"no-listener/pass", nil},
		// internal/b imports syscall too, which only no-exec reports.
		{"no-listener/fail", []string{
			"internal/a/a.go:6 imports net/http/httptest", // a blank import
			"internal/a/a.go:7 imports net/rpc",
			"internal/a/a.go:12 uses net.Listen", // after a dot import
			"internal/a/a.go:13 uses net.ListenConfig",
			"internal/a/a.go:14 uses net.FileListener",
			"internal/a/a.go:15 uses net/http.Serve", // through an alias
			"internal/a/a.go:16 uses net/http.Server",
			"internal/a/a.go:17 uses net/http.ListenAndServeTLS",
			"internal/b/b.go:15 uses crypto/tls.Listen",
			"internal/b/b.go:16 uses crypto/tls.NewListener",
		}},
		// The passing tree holds folders that "go build ./..." skips.
		{"no-exec/pass", nil},
		{"no-exec/fail", []string{
			"internal/a/a.go:5 imports os/exec",
			"internal/a/a.go:6 imports plugin",
			"internal/a/a.go:7 imports syscall",
			"internal/a/a.go:12 uses os.StartProcess",
		}},
		{"no-unsafe/pass", nil},
		{"no-unsafe/fail", []string{
			"internal/a/a.go:3 imports unsafe",
			"internal/b/b.go:3 imports unsafe", // imported by no package
			"internal/c/c.go:4 imports C",
		}},
		{"import-rules/pass", nil},
		{"import-rules/fail", []string{
			`gate/imports.txt:3 is neither "<pattern> must-not-import <pattern>" nor "only <pattern> may-import <pattern>"`,
			"internal/cache/cache.go:6 imports osk/internal/store, reached from osk/internal/observe " +
				"(osk/internal/observe/... must-not-import osk/internal/store/...)",
			"internal/decide/sub/sub.go:3 imports os (osk/internal/decide/... must-not-import os)",
			"internal/expect/expect.go:5 imports os, reached from osk/internal/decide " +
				"(osk/internal/decide/... must-not-import os)",
			"internal/cache/cache.go:4 imports database/sql/driver (only osk/internal/store/... may-import database/sql/...)",
			"cmd/osk/main.go:6 imports github.com/mattn/go-sqlite3 " +
				"(only osk/internal/store/... may-import github.com/mattn/go-sqlite3/...)",
			"gate/imports.txt:7 names osk/internal/deliver/..., which matches no package",
			"gate/imports.txt:8 names osk/internal/missing, which matches no package",
		}},
		{"no-dns-update/pass", nil},
		// Every package that dials sorts before internal/dnswire, and every
		// use of net before every use of crypto/tls, so the order of the
		// faults is the same whichever of these the rule walks first.
		{"no-dns-update/fail", []string{
			"internal/d/d.go:4 imports log/syslog", // a blank import
			"internal/d/d.go:5 imports net/smtp",
			"internal/d/d.go:6 imports net/textproto", // through an alias
			"cmd/osk/main.go:10 uses net.DialTimeout",
			"internal/a/a.go:7 uses net.Dial",
			"internal/a/a.go:11 uses net.Dialer",
			"internal/a/alias.go:7 uses net.Dialer",
			"internal/b/b.go:7 uses net.DialUDP", // after a dot import
			"internal/c/alias.go:7 uses crypto/tls.Dialer",
			"internal/c/c.go:7 uses crypto/tls.Dial",
			"internal/dnswire/a.go:3 imports net outside internal/dnswire/transport.go",
			"internal/dnswire/b.go:3 imports net outside internal/dnswire/transport.go",
			"internal/dnswire/transport.go:17 uses WriteTo outside writeQuery",
			"internal/dnswire/transport.go:20 uses Write outside writeQuery",
			"internal/dnswire/transport.go:20 uses Writer outside writeQuery", // every name that starts with Write
			"internal/dnswire/transport.go:25 uses Write outside writeQuery",
			"internal/dnswire/transport.go:30 uses Writer outside writeQuery",
			"internal/dnswire/transport.go:31 uses WriteAll outside writeQuery",
			"internal/dnswire/transport.go:34 uses Writer outside writeQuery",
			"internal/dnswire/transport.go:35 uses Write outside writeQuery",
			"internal/dnswire/transport.go:41 uses Write outside writeQuery", // a method value
		}},
	}
	for _, c := range cases {
		t.Run(c.tree, func(t *testing.T) {
			name, _, _ := strings.Cut(c.tree, "/")
			got := faultsOf(t, check("testdata/"+c.tree), name)
			if !slices.Equal(got, c.want) {
				t.Errorf("faults:\n got %q\nwant %q", got, c.want)
			}
		})
	}
}

// faultsOf returns the faults of the named rule, and fails the test if the
// rule did not run.
func faultsOf(t *testing.T, results []result, name string) []string {
	t.Helper()
	for _, r := range results {
		if r.name == name {
			return r.faults
		}
	}
	t.Fatalf("rule %s did not run", name)
	return nil
}

func TestRun(t *testing.T) {
	const unread = "go.mod cannot be read; no Go files in cmd/osk"
	cases := []struct {
		root string
		code int
		out  string
	}{
		{"testdata/import-rules/pass", 0,
			"ok plain-layout\nok only-std-and-sqlite\nok no-listener\nok no-exec\nok no-unsafe\nok import-rules\n" +
				"ok no-dns-update\n"},
		{"testdata/no-unsafe/fail", 1,
			"ok plain-layout\n" +
				"FAIL only-std-and-sqlite: internal/c/c.go:4 imports C\n" +
				"ok no-listener\nok no-exec\n" +
				"FAIL no-unsafe: internal/a/a.go:3 imports unsafe; internal/b/b.go:3 imports unsafe; " +
				"internal/c/c.go:4 imports C\n" +
				"FAIL import-rules: gate/imports.txt cannot be read\n" +
				"ok no-dns-update\n"},
		// A wrong root must not pass.
		{"testdata/missing", 1,
			"FAIL plain-layout: " + unread + "\nFAIL only-std-and-sqlite: " + unread +
				"\nFAIL no-listener: " + unread + "\nFAIL no-exec: " + unread + "\nFAIL no-unsafe: " + unread +
				"\nFAIL import-rules: " + unread + "; gate/imports.txt cannot be read" +
				"\nFAIL no-dns-update: " + unread + "\n"},
	}
	for _, c := range cases {
		out, code := run([]string{"--root", c.root})
		if code != c.code || out != c.out {
			t.Errorf("--root %s: exit code %d, output:\n%s\nwant %d:\n%s", c.root, code, out, c.code, c.out)
		}
	}

	for _, args := range [][]string{{"extra"}, {"--root"}, {"--other"}, {"--root", ".", "extra"}} {
		if _, code := run(args); code != 2 {
			t.Errorf("run(%q): exit code %d, want 2", args, code)
		}
	}
}
