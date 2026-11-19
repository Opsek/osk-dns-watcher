package cli

import (
	"database/sql"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// cleOpenFiles counts the descriptors of this process that name the database
// of state; it is -1 where the process lists none.
func cleOpenFiles(t *testing.T, state string) int {
	t.Helper()
	entries, err := os.ReadDir("/proc/self/fd")
	if err != nil {
		return -1
	}
	n := 0
	for _, e := range entries {
		target, err := os.Readlink(filepath.Join("/proc/self/fd", e.Name()))
		if err == nil && strings.HasPrefix(target, filepath.Join(state, "state.db")) {
			n++
		}
	}
	return n
}

// cleBreakNotices stores a notice that cannot be read back, in the child
// process. The connection stays open: closing it would drop the locks of the
// store that the child holds.
func cleBreakNotices(state string) error {
	db, err := sql.Open("sqlite3", "file:"+filepath.Join(state, "state.db")+"?_busy_timeout=5000")
	if err != nil {
		return err
	}
	_, err = db.Exec("INSERT INTO notice (kind, domain, lines, at) VALUES ('test', '', 'not json', 1)")
	return err
}

// A reader that stays open keeps the database in use after the command has
// returned; accept closes it before it touches any file, status when it has
// read.
func TestStatusAndAcceptLeaveNoDatabaseFileOpen(t *testing.T) {
	w, ids := cliAcceptWorld(t)
	if cleOpenFiles(t, w.state) < 0 {
		t.Skip("the process lists no open files")
	}
	cliSetClock(t, cliT0)
	if code, _, errOut := cliRun(10*time.Second, "status", "--config", w.config); code > 1 {
		t.Fatalf("osk-dns-watcher status: exit code %d: %s", code, errOut)
	}
	if n := cleOpenFiles(t, w.state); n != 0 {
		t.Errorf("osk-dns-watcher status left %d database files open, want 0", n)
	}
	id := ids["www"]
	if code, _, errOut := cliAccept(w, "--", strconv.FormatInt(id, 10)); code != 0 {
		t.Fatalf("osk-dns-watcher accept: exit code %d: %s", code, errOut)
	}
	if n := cleOpenFiles(t, w.state); n != 0 {
		t.Errorf("osk-dns-watcher accept left %d database files open, want 0", n)
	}
}

// An alert id counts from 1: 0 and the negative numbers are no id, and are
// refused before the config is read.
func TestAcceptRefusesAnIdBelow1(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, id := range []string{"0", "-3"} {
		code, out, errOut := cliRun(5*time.Second, "accept", "--config", missing, "--", id)
		first, _, _ := strings.Cut(errOut, "\n")
		if want := `osk-dns-watcher accept: "` + id + `" is not an alert id`; code != 2 || out != "" || first != want {
			t.Errorf("osk-dns-watcher accept %s: exit code %d, output %q, first error line %q; want 2, nothing and %q", id, code, out, first, want)
		}
	}
}

// A change that cannot be put in place leaves the old file and no temporary
// file beside it; here the name is a folder, which no file can replace.
func TestReplaceFileClearsItsTemporaryFileWhenTheRenameFails(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "expect")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := replaceFile(target, []byte("domain corp.test.\n")); err == nil {
		t.Error("replaceFile replaced a folder, want an error")
	}
	if got := cliEntries(t, dir); len(got) != 1 || got[0] != "expect" {
		t.Errorf("the folder holds %q after the failure, want only expect", got)
	}
}

// The flag parser must not write its own complaint and usage on the process's
// standard error: the command words the message itself.
func TestWrongFlagsWriteNothingOnTheProcessStandardError(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "stderr")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	saved := os.Stderr
	os.Stderr = f
	defer func() { os.Stderr = saved }()
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, cmd := range []string{"validate", "status", "watch", "accept", "test-alert"} {
		if code, _, _ := cliRun(5*time.Second, cmd, "--nope", "--config", missing, "7"); code != 2 {
			t.Errorf("osk-dns-watcher %s --nope: exit code %d, want 2", cmd, code)
		}
	}
	if data, err := os.ReadFile(f.Name()); err != nil || len(data) != 0 {
		t.Errorf("the flag parser wrote %q on standard error (%v), want nothing", data, err)
	}
}

// Only accept takes --write; every other command refuses it as an unknown flag.
func TestOnlyAcceptTakesTheWriteFlag(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing.json")
	for _, cmd := range []string{"validate", "status", "watch", "test-alert"} {
		code, out, errOut := cliRun(5*time.Second, cmd, "--config", missing, "--write", "abc")
		first, _, _ := strings.Cut(errOut, "\n")
		if want := "osk-dns-watcher " + cmd + ": flag provided but not defined: -write"; code != 2 || out != "" || first != want {
			t.Errorf("osk-dns-watcher %s --write: exit code %d, output %q, first error line %q; want 2, nothing and %q", cmd, code, out, first, want)
		}
	}
}

// watch shows 12 lines of a notice; a notice of exactly 12 has no more lines
// to announce.
func TestNoticeItemAnnouncesOnlyTheLinesItLeavesOut(t *testing.T) {
	lines := func(n int) []string {
		var l []string
		for i := 1; i <= n; i++ {
			l = append(l, "line "+strconv.Itoa(i))
		}
		return l
	}
	for _, c := range []struct {
		lines int
		more  string
	}{{11, ""}, {12, ""}, {13, "  and 1 more lines"}} {
		n := store.Notice{ID: 5, Kind: store.NoticeDown, Domain: "corp.test.", Lines: lines(c.lines), At: cliT0}
		text := noticeItem(n).text
		got := strings.Split(text, "\n")
		last := got[len(got)-1]
		if strings.Contains(text, "more lines") != (c.more != "") || (c.more != "" && last != c.more) {
			t.Errorf("a notice of %d lines gave:\n%s\nwant the last line %q or none about more lines", c.lines, text, c.more)
		}
		if want := 1 + min(c.lines, 12) + cleExtra(c.more); len(got) != want {
			t.Errorf("a notice of %d lines gave %d lines, want %d", c.lines, len(got), want)
		}
	}
}

// When the service took the request but no test notice came, the request is
// gone already; the report is the one for a test that was not taken, not an
// error about a missing file.
func TestTestAlertReportsAnUntakenTestWhenTheRequestIsAlreadyGone(t *testing.T) {
	savedLimit, savedEvery := testLimit, testEvery
	testLimit, testEvery = 300*time.Millisecond, 20*time.Millisecond
	defer func() { testLimit, testEvery = savedLimit, savedEvery }()
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	path := filepath.Join(w.state, "test-alert")
	removed := make(chan bool, 1)
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if os.Remove(path) == nil {
				removed <- true
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		removed <- false
	}()
	code, out, errOut := cliRun(10*time.Second, "test-alert", "--config", w.config)
	want := "osk-dns-watcher: osk-dns-watcher run did not take the test within 30s; is it running on " + w.state + "?\n"
	if code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	if !<-removed {
		t.Error("test-alert wrote no request")
	}
}

// A failed read of the notices ends test-alert at once, and nobody has taken
// the request, so it must not stay for a later start of the service.
func TestTestAlertRemovesItsRequestWhenTheNoticesCannotBeRead(t *testing.T) {
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	child := cliStartChild(t, w.state)
	path := filepath.Join(w.state, "test-alert")
	go func() {
		deadline := time.Now().Add(5 * time.Second)
		for time.Now().Before(deadline) {
			if _, err := os.Stat(path); err == nil {
				child.send(t, "poison")
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	}()
	start := time.Now()
	code, out, errOut := cliRun(20*time.Second, "test-alert", "--config", w.config)
	took := time.Since(start)
	child.reply(t)
	if code != 1 || out != "" || !strings.HasPrefix(errOut, "osk-dns-watcher: ") || !strings.Contains(errOut, "notice ") || took > 5*time.Second {
		t.Errorf("exit code %d, output %q, errors %q after %v; want 1 at once, nothing and the error of the read", code, out, errOut, took)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("the request is still there after test-alert failed")
	}
}

// A row that was tried once and failed is settled: test-alert reports it at
// once and does not wait for the 30 s to pass.
func TestTestAlertDoesNotWaitForARowThatFailedOnce(t *testing.T) {
	_, _, _, took := cliTestAlert(t, "failed")
	if took > 10*time.Second {
		t.Errorf("test-alert took %v with a failed row, want an answer within 10s", took)
	}
}

// cleExtra is the number of lines that the text "more" adds.
func cleExtra(more string) int {
	if more == "" {
		return 0
	}
	return 1
}
