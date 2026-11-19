package store

import (
	"bufio"
	"bytes"
	"database/sql"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// ntcReaderEnv makes the test binary act as a reading process of the folder
// named in it: it opens a Reader and answers the commands read, write and
// close, one per line of standard input.
const ntcReaderEnv = "OSK_STORE_TEST_READER_DIR"

// ntcReaderNow is the time at which a reading process reads the health.
var ntcReaderNow = stoT0.Add(30 * time.Second)

func ntcOpenReader(t *testing.T, dir string) *Reader {
	t.Helper()
	r, err := OpenReader(dir)
	if err != nil {
		t.Fatalf("OpenReader(%q): %v", dir, err)
	}
	// Tests that check Close call it themselves.
	t.Cleanup(func() { _ = r.Close() })
	return r
}

// ntcNoStore is the error of a reader of a folder with no store.
func ntcNoStore(dir string) string {
	return "store: no state in " + dir + " yet; start osk-dns-watcher run there first"
}

func TestOpenReaderWithoutStateSaysToStartTheService(t *testing.T) {
	parent := stoDir(t)
	for _, dir := range []string{parent, filepath.Join(parent, "missing")} {
		r, err := OpenReader(dir)
		if want := ntcNoStore(dir); err == nil || err.Error() != want {
			t.Errorf("OpenReader(%q): %v, want error %q", dir, err, want)
			if err == nil {
				_ = r.Close()
			}
		}
	}
	// A reader creates nothing, not even the folder.
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Errorf("the refused readers left %v, %v; want nothing", entries, err)
	}
}

// Only its owner may enter the state folder: the writer, a reader and
// CheckFolder refuse any bit for the group or for others, with one text.
func TestOpenOpenReaderAndCheckFolderRefuseAFolderOpenToOtherUsers(t *testing.T) {
	for _, mode := range []os.FileMode{0o755, 0o740, 0o720, 0o710, 0o704, 0o702, 0o701} {
		t.Run(fmt.Sprintf("%04o", uint32(mode)), func(t *testing.T) {
			dir := stoDir(t)
			s := stoOpen(t, dir)
			if err := s.Close(); err != nil {
				t.Fatalf("Close: %v", err)
			}
			if err := os.Chmod(dir, mode); err != nil {
				t.Fatal(err)
			}
			want := fmt.Sprintf("store: %s is open to other users (mode %04o); run chmod 700 %s", dir, uint32(mode), dir)
			if err := CheckFolder(dir); err == nil || err.Error() != want {
				t.Errorf("CheckFolder: %v, want error %q", err, want)
			}
			if r, err := OpenReader(dir); err == nil || err.Error() != want {
				t.Errorf("OpenReader: %v, want error %q", err, want)
				if err == nil {
					_ = r.Close()
				}
			}
			if s, err := Open(dir); err == nil || err.Error() != want {
				t.Errorf("Open: %v, want error %q", err, want)
				if err == nil {
					_ = s.Close()
				}
			}

			// The mode alone was the fault.
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := CheckFolder(dir); err != nil {
				t.Errorf("CheckFolder of the folder made 0700: %v", err)
			}
			r := ntcOpenReader(t, dir)
			if err := r.Close(); err != nil {
				t.Errorf("Close: %v", err)
			}
		})
	}
}

// A reader checks the folder before it looks for the store in it.
func TestOpenReaderChecksTheFolderBeforeTheState(t *testing.T) {
	dir := stoDir(t)
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	r, err := OpenReader(dir)
	if want := fmt.Sprintf("store: %s is open to other users (mode 0755); run chmod 700 %s", dir, dir); err == nil || err.Error() != want {
		t.Errorf("OpenReader of an empty folder with mode 0755: %v, want error %q", err, want)
		if err == nil {
			_ = r.Close()
		}
	}
}

func TestOpenOpenReaderAndCheckFolderRefuseAFileInPlaceOfTheFolder(t *testing.T) {
	path := filepath.Join(stoDir(t), "state")
	if err := os.WriteFile(path, []byte("not a folder\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	want := "store: " + path + " is not a folder"
	if err := CheckFolder(path); err == nil || err.Error() != want {
		t.Errorf("CheckFolder: %v, want error %q", err, want)
	}
	if r, err := OpenReader(path); err == nil || err.Error() != want {
		t.Errorf("OpenReader: %v, want error %q", err, want)
		if err == nil {
			_ = r.Close()
		}
	}
	if s, err := Open(path); err == nil || err.Error() != want {
		t.Errorf("Open: %v, want error %q", err, want)
		if err == nil {
			_ = s.Close()
		}
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "not a folder\n" {
		t.Errorf("the file is now %q, %v; want it as it was", got, err)
	}
}

// ? and # end the file name in a DSN, and a name that starts with file: is
// read as a URI, so a reader refuses such folders with the writer's words
// and touches nothing.
func TestOpenReaderRefusesFolderNamesThatTheDSNWouldMisread(t *testing.T) {
	parent := stoDir(t)
	t.Chdir(parent)
	for _, dir := range []string{filepath.Join(parent, "a?b"), filepath.Join(parent, "a#b"), "file:st"} {
		_, refused := Open(dir)
		if refused == nil {
			t.Fatalf("Open(%q) worked, want it refused", dir)
		}
		r, err := OpenReader(dir)
		if err == nil || err.Error() != refused.Error() {
			t.Errorf("OpenReader(%q): %v, want error %q", dir, err, refused.Error())
			if err == nil {
				_ = r.Close()
			}
		}
	}
	if entries, err := os.ReadDir(parent); err != nil || len(entries) != 0 {
		t.Errorf("the refused names left %v, %v; want nothing", entries, err)
	}
}

// A reader only reads: a store of another version, an empty file and the
// database of another program are refused with the schema error, and the
// file stays as it was. A reading command never migrates or makes a store.
func TestOpenReaderRefusesAnotherSchemaAndLeavesTheFileAsItIs(t *testing.T) {
	for _, c := range []struct {
		name    string
		version int
		make    func(t *testing.T, dir string)
	}{
		{"a store of version 2", 2, func(t *testing.T, dir string) { ntcMakeVersion2(t, filepath.Join(dir, "state.db")) }},
		{"a store of version 4", 4, func(t *testing.T, dir string) {
			s := stoOpen(t, dir)
			stoExec(t, s, "PRAGMA user_version = 4")
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
		}},
		{"an empty file", 0, func(t *testing.T, dir string) {
			if err := os.WriteFile(filepath.Join(dir, "state.db"), nil, 0o600); err != nil {
				t.Fatal(err)
			}
		}},
		{"the database of another program", 7, func(t *testing.T, dir string) {
			beaWithFile(t, filepath.Join(dir, "state.db"), func(db *sql.DB) {
				beaExec(t, db, "CREATE TABLE other (x INTEGER); PRAGMA user_version = 7")
			})
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := stoDir(t)
			c.make(t, dir)
			path := filepath.Join(dir, "state.db")
			before, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			r, err := OpenReader(dir)
			if want := fmt.Sprintf("store: %s is not a store of this osk-dns-watcher (schema %d)", path, c.version); err == nil || err.Error() != want {
				t.Errorf("OpenReader: %v, want error %q", err, want)
				if err == nil {
					_ = r.Close()
				}
			}
			if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
				t.Errorf("OpenReader changed the file that it refused (%v)", err)
			}
		})
	}
}

// ntcEventText writes the fields of an event row other than its alert.
func ntcEventText(e EventRow) string {
	return fmt.Sprintf("%d alert %d %s %v %v %q %s", e.ID, e.Alert.ID, e.Kind, e.Severity, e.Was, e.Value, e.At.Format(time.RFC3339Nano))
}

func ntcNoticeText(n Notice) string {
	return fmt.Sprintf("%d %s %q %q %s", n.ID, n.Kind, n.Domain, n.Lines, n.At.Format(time.RFC3339Nano))
}

func ntcHealthText(h Health) string {
	return fmt.Sprintf("beat %s late %q\n%s", h.Beat.Format(time.RFC3339Nano), h.Late, ntcChannels(h))
}

func ntcUTC(t time.Time) string { return t.UTC().Format(time.RFC3339Nano) }

// The store writes alerts of each kind, events of each kind, notices of
// each kind and rows in each state, then stops; a reader opened right
// after gives back each of them.
func TestReaderGivesWhatTheStoreWrote(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	www, mail := stoWWW(t), stoMail(t)
	corp := stoName(t, "corp.test.")
	scope := obs.Key{Domain: corp, Name: corp}
	t1 := stoT0

	// Alert 1, of www: open (rows 1 and 2), update (row 3), resolve (row 4).
	a := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99")
	stoApply(t, s, www, false, t1, stoWrite(alert.EventOpen, a, a.Severity, t1, "slack", "hook"))
	opened := a.Value
	a = stoNth(t, s, www, 1, 0)
	t2 := t1.Add(time.Minute)
	a.Value, a.Noticed = a.Value+" (update)", t2
	stoApply(t, s, www, false, t2, stoWrite(alert.EventUpdate, a, a.Severity, t2, "slack"))
	t3 := t1.Add(2 * time.Minute)
	resolve := ntcClose(t, stoNth(t, s, www, 1, 0), t3)
	resolve.Deliveries = ntcRowsTo("slack")
	stoApply(t, s, www, false, t3, resolve)

	// Alert 2, of mail: open (row 5, given up, which adds event 5).
	b := stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.98")
	b.Severity, b.Peak = decide.SeverityMedium, decide.SeverityMedium
	t4 := t1.Add(3 * time.Minute)
	stoApply(t, s, mail, false, t4, stoWrite(alert.EventOpen, b, b.Severity, t4, "slack"))
	ntcRecord(t, s, 5, Done{State: RowGivenUp, Attempts: 1, Reason: `status 400 "invalid_payload"`, At: t4.Add(time.Second)})

	// Alert 3, of the whole domain: no row.
	sc := stoAlert(t, decide.RuleInvalidFile, scope, "x")
	sc.Severity, sc.Peak, sc.Expected, sc.Value, sc.Lines = decide.SeverityMedium, decide.SeverityMedium, "", "corp.test.expect:3: bad line", nil
	t5 := t1.Add(4 * time.Minute)
	stoApply(t, s, scope, false, t5, stoWrite(alert.EventOpen, sc, sc.Severity, t5))

	notices := []Notice{
		{ID: 1, Kind: NoticeTest, Lines: []string{"request   0123456789abcdef0123456789abcdef"}, At: t1.Add(5 * time.Minute)},
		{ID: 2, Kind: NoticeDown, Lines: []string{"last beat 2026-11-11 11:00:00 UTC", "started   2026-11-11 12:05:00 UTC"}, At: t1.Add(6 * time.Minute)},
		{ID: 3, Kind: NoticeExpectations, Domain: "corp.test.", Lines: []string{"- www.corp.test. A 10.53.0.81", "+ mail.corp.test. A 10.53.0.82"},
			At: t1.Add(7 * time.Minute).In(stoZone)},
	}
	ntcNotify(t, s, notices[0], ntcRowsTo("slack", "hook")...) // rows 6 and 7
	ntcNotify(t, s, notices[1])
	ntcNotify(t, s, notices[2], ntcRowsTo("slack")...) // row 8
	ntcRecord(t, s, 6, Done{State: RowGivenUp, Attempts: 1, Reason: "status 404", At: t1.Add(5*time.Minute + time.Second)})
	ntcRecord(t, s, 7, ntcSent(t1.Add(5*time.Minute+2*time.Second)))
	ntcRecord(t, s, 8, Done{State: RowPending, Attempts: 1, NextAt: t1.Add(8 * time.Minute), Reason: "status 503", At: t1.Add(7*time.Minute + time.Second)})
	if err := s.Beat(t1.Add(9*time.Minute), []string{"records corp.test. www.corp.test. A"}); err != nil {
		t.Fatal(err)
	}

	channels := []string{"slack", "hook", "siem"}
	open := ntcAllOpen(t, s)
	health := ntcHealth(t, s, ntcNow, channels...)
	alerts := map[int64]alert.Alert{1: resolve.Event.Alert}
	for _, o := range open {
		alerts[o.ID] = o
	}
	if len(alerts) != 3 || alerts[2].ID != 2 || alerts[3].ID != 3 {
		t.Fatalf("the store holds %d open alerts, want alerts 2 and 3", len(open))
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := ntcOpenReader(t, dir)

	got, err := r.AllOpenAlerts()
	if err != nil || len(got) != len(open) {
		t.Fatalf("AllOpenAlerts gives %d alerts, %v; want %d", len(got), err, len(open))
	}
	for i := range got {
		if g, w := stoAlertText(got[i]), stoAlertText(open[i]); g != w {
			t.Errorf("AllOpenAlerts of the reader gives\n%s\nthe store gave\n%s", g, w)
		}
	}
	for id, want := range alerts {
		got, err := r.Alert(id)
		if err != nil || stoAlertText(got) != stoAlertText(want) {
			t.Errorf("Alert(%d) = %v\n%s\nwant\n%s", id, err, stoAlertText(got), stoAlertText(want))
		}
	}
	if _, err := r.Alert(99); err == nil || err.Error() != "store: no alert 99" {
		t.Errorf("Alert(99): %v, want error %q", err, "store: no alert 99")
	}

	updated := alerts[1].Value
	wantEvents := []string{
		fmt.Sprintf("1 alert 1 open high high %q %s", opened, ntcUTC(t1)),
		fmt.Sprintf("2 alert 1 update high high %q %s", updated, ntcUTC(t2)),
		fmt.Sprintf("3 alert 1 resolve high high %q %s", updated, ntcUTC(t3)),
		fmt.Sprintf("4 alert 2 open medium medium %q %s", b.Value, ntcUTC(t4)),
		fmt.Sprintf("5 alert 2 given-up medium medium %q %s", `slack: status 400 "invalid_payload"`, ntcUTC(t4.Add(time.Second))),
		fmt.Sprintf("6 alert 3 open medium medium %q %s", sc.Value, ntcUTC(t5)),
	}
	for _, after := range []int64{0, 3, 6} {
		events, err := r.Events(after)
		if err != nil {
			t.Fatalf("Events(%d): %v", after, err)
		}
		var texts []string
		for _, e := range events {
			texts = append(texts, ntcEventText(e))
			// Each event carries its alert as the alert is now.
			if g, w := stoAlertText(e.Alert), stoAlertText(alerts[e.Alert.ID]); g != w {
				t.Errorf("event %d carries the alert\n%s\nwant\n%s", e.ID, g, w)
			}
		}
		if want := wantEvents[after:]; !slices.Equal(texts, want) {
			t.Errorf("Events(%d)\n got %q\nwant %q", after, texts, want)
		}
	}

	var wantNotices []string
	for _, n := range notices {
		n.At = n.At.UTC()
		wantNotices = append(wantNotices, ntcNoticeText(n))
	}
	for _, after := range []int64{0, 2, 3} {
		got, err := r.Notices(after)
		if err != nil {
			t.Fatalf("Notices(%d): %v", after, err)
		}
		var texts []string
		for _, n := range got {
			texts = append(texts, ntcNoticeText(n))
		}
		if want := wantNotices[after:]; !slices.Equal(texts, want) {
			t.Errorf("Notices(%d)\n got %q\nwant %q", after, texts, want)
		}
	}

	if event, notice, err := r.Last(); err != nil || event != 6 || notice != 3 {
		t.Errorf("Last() = %d, %d, %v; want 6, 3", event, notice, err)
	}

	for id, want := range map[int64][]string{
		1: {fmt.Sprintf(`slack given-up 1 "status 404" %s`, ntcUTC(t1.Add(5*time.Minute+time.Second))),
			fmt.Sprintf(`hook sent 1 "" %s`, ntcUTC(t1.Add(5*time.Minute+2*time.Second)))},
		2: nil,
		3: {fmt.Sprintf(`slack pending 1 "status 503" %s`, ntcUTC(t1.Add(8*time.Minute)))},
	} {
		rows, err := r.NoticeRows(id)
		if err != nil {
			t.Fatalf("NoticeRows(%d): %v", id, err)
		}
		var texts []string
		for _, row := range rows {
			texts = append(texts, fmt.Sprintf("%s %v %d %q %s", row.Channel, row.State, row.Attempts, row.Reason, row.NextAt.Format(time.RFC3339Nano)))
		}
		if !slices.Equal(texts, want) {
			t.Errorf("NoticeRows(%d)\n got %q\nwant %q", id, texts, want)
		}
	}

	if h, err := r.Health(ntcNow, channels); err != nil || ntcHealthText(h) != ntcHealthText(health) {
		t.Errorf("Health of the reader = %v\n%s\nthe store gave\n%s", err, ntcHealthText(h), ntcHealthText(health))
	}
	if err := r.Close(); err != nil {
		t.Errorf("Close: %v", err)
	}

	// What the reader left in the folder is as private as the store.
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if info, err := e.Info(); err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v (%v), want a file with 0600", e.Name(), info.Mode(), err)
		}
	}
}

func TestReaderOfAStoreWithNothingWrittenGivesNothing(t *testing.T) {
	dir := stoDir(t)
	if err := stoOpen(t, dir).Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := ntcOpenReader(t, dir)
	if event, notice, err := r.Last(); err != nil || event != 0 || notice != 0 {
		t.Errorf("Last() = %d, %d, %v; want 0, 0", event, notice, err)
	}
	if got, err := r.AllOpenAlerts(); err != nil || len(got) != 0 {
		t.Errorf("AllOpenAlerts = %d alerts, %v; want none", len(got), err)
	}
	if got, err := r.Events(0); err != nil || len(got) != 0 {
		t.Errorf("Events(0) = %d events, %v; want none", len(got), err)
	}
	if got, err := r.Notices(0); err != nil || len(got) != 0 {
		t.Errorf("Notices(0) = %d notices, %v; want none", len(got), err)
	}
	h, err := r.Health(ntcNow, []string{"slack"})
	if want := "beat 0001-01-01T00:00:00Z late []\nslack pending 0 failing false reason \"\"\n"; err != nil || ntcHealthText(h) != want {
		t.Errorf("Health = %v\n%s\nwant\n%s", err, ntcHealthText(h), want)
	}
}

// Last gives the highest ids, which differ from the counts once old
// history is gone.
func TestReaderLastGivesTheHighestIDsAfterOldHistoryIsGone(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	ago := stoT0.Add(-30 * 24 * time.Hour)
	for i := range 3 {
		ntcEpisode(t, s, fmt.Sprintf("e%d.corp.test.", i), ago, ago.Add(time.Hour))
		ntcNotice(t, s, ago)
	}
	if alerts, notices := ntcPrune(t, s, stoT0, 200); alerts != 2 || notices != 2 {
		t.Fatalf("Prune gives %d alerts and %d notices, want 2 and 2", alerts, notices)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := ntcOpenReader(t, dir)
	if event, notice, err := r.Last(); err != nil || event != 6 || notice != 3 {
		t.Errorf("Last() = %d, %d, %v; want 6, 3", event, notice, err)
	}
}

// A command that follows the store reads in pages: each call gives at most
// 1000 events or notices, the next ones by id.
func TestReaderGivesAtMost1000EventsOrNoticesByID(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	corp := stoName(t, "corp.test.")
	var writes []Write
	for i := range 1001 {
		k := obs.RecordsKey(corp, stoName(t, fmt.Sprintf("h%d.corp.test.", i)), dnswire.TypeA)
		writes = append(writes, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0))
	}
	stoApply(t, s, stoWWW(t), false, stoT0, writes...)
	// One transaction: a thousand Notify calls would each wait for the disk.
	tx, err := s.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for range 1001 {
		if _, err := tx.Exec("INSERT INTO notice (kind, domain, lines, at) VALUES ('test', '', '[]', ?)", stoT0.UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	r := ntcOpenReader(t, dir)

	span := func(ids []int64) string {
		if len(ids) == 0 {
			return "none"
		}
		ascending := true
		for i := 1; i < len(ids); i++ {
			ascending = ascending && ids[i] > ids[i-1]
		}
		return fmt.Sprintf("%d ids from %d to %d, ascending %v", len(ids), ids[0], ids[len(ids)-1], ascending)
	}
	for _, c := range []struct {
		after int64
		want  string
	}{
		{0, "1000 ids from 1 to 1000, ascending true"},
		{999, "2 ids from 1000 to 1001, ascending true"},
		{1001, "none"},
	} {
		events, err := r.Events(c.after)
		if err != nil {
			t.Fatalf("Events(%d): %v", c.after, err)
		}
		var ids []int64
		for _, e := range events {
			ids = append(ids, e.ID)
		}
		if got := span(ids); got != c.want {
			t.Errorf("Events(%d) gives %s, want %s", c.after, got, c.want)
		}
		notices, err := r.Notices(c.after)
		if err != nil {
			t.Fatalf("Notices(%d): %v", c.after, err)
		}
		ids = nil
		for _, n := range notices {
			ids = append(ids, n.ID)
		}
		if got := span(ids); got != c.want {
			t.Errorf("Notices(%d) gives %s, want %s", c.after, got, c.want)
		}
	}
}

// ntcReaderChild is the reading process. Each answer ends with the line
// end; errors are lines too, so that the test shows them.
func ntcReaderChild(dir string) {
	r, err := OpenReader(dir)
	if err != nil {
		fmt.Println("ntc-child error " + err.Error())
		return
	}
	fmt.Println("ntc-child ready")
	in := bufio.NewScanner(os.Stdin)
	for in.Scan() {
		var lines []string
		switch in.Text() {
		case "read":
			lines = ntcReadAll(r)
		case "write":
			lines = ntcTryWrites(r)
		case "close":
			lines = []string{fmt.Sprintf("closed %v", r.Close())}
		}
		for _, line := range append(lines, "end") {
			fmt.Println("ntc-child " + line)
		}
	}
}

// ntcReadAll is what a reading process tells of the store.
func ntcReadAll(r *Reader) []string {
	var out []string
	event, notice, err := r.Last()
	out = append(out, fmt.Sprintf("last %d %d %v", event, notice, err))
	open, err := r.AllOpenAlerts()
	if err != nil {
		out = append(out, "open "+err.Error())
	}
	for _, a := range open {
		out = append(out, fmt.Sprintf("open %d %s %s", a.ID, a.Rule, a.Check))
	}
	events, err := r.Events(0)
	if err != nil {
		out = append(out, "events "+err.Error())
	}
	for _, e := range events {
		out = append(out, fmt.Sprintf("event %d alert %d %s", e.ID, e.Alert.ID, e.Kind))
	}
	notices, err := r.Notices(0)
	if err != nil {
		out = append(out, "notices "+err.Error())
	}
	for _, n := range notices {
		out = append(out, fmt.Sprintf("notice %d %s %q %q", n.ID, n.Kind, n.Domain, n.Lines))
	}
	h, err := r.Health(ntcReaderNow, []string{"slack", "hook"})
	if err != nil {
		out = append(out, "health "+err.Error())
	}
	out = append(out, fmt.Sprintf("beat %s late %q", h.Beat.Format(time.RFC3339Nano), h.Late))
	for _, c := range h.Channels {
		out = append(out, fmt.Sprintf("channel %s pending %d", c.Name, c.Pending))
	}
	return out
}

// ntcTryWrites tries to change the store through the reader's own
// connection and tells, for each statement, whether it was refused.
func ntcTryWrites(r *Reader) []string {
	var out []string
	for _, q := range []string{
		"INSERT INTO loaded (domain, text, at) VALUES ('shop.test.', 'domain shop.test.', 1)",
		"UPDATE alert SET open = 0",
		"DELETE FROM delivery",
		"PRAGMA user_version = 9",
		"CREATE TABLE ntc_other (x INTEGER)",
	} {
		_, err := r.db.Exec(q)
		verb, _, _ := strings.Cut(q, " ")
		out = append(out, fmt.Sprintf("%s refused %v", verb, err != nil))
	}
	return out
}

// ntcReaderProcess is a reading process that holds its Reader open between
// commands.
type ntcReaderProcess struct {
	t     *testing.T
	in    io.WriteCloser
	lines chan string
}

func ntcStartReader(t *testing.T, dir string) *ntcReaderProcess {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestReaderInAnotherProcessReadsWhatTheOpenStoreWrites$", "-test.count=1")
	cmd.Env = append(os.Environ(), ntcReaderEnv+"="+dir)
	// A crash of the reading process shows in the output of the test.
	cmd.Stderr = os.Stderr
	in, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	out, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	p := &ntcReaderProcess{t: t, in: in, lines: make(chan string, 100)}
	go func() {
		defer close(p.lines)
		sc := bufio.NewScanner(out)
		for sc.Scan() {
			if line, ok := strings.CutPrefix(sc.Text(), "ntc-child "); ok {
				p.lines <- line
			}
		}
	}()
	t.Cleanup(func() {
		_ = in.Close()
		_ = cmd.Process.Kill()
		for range p.lines {
		}
		_ = cmd.Wait()
	})
	if got := p.next(); got != "ready" {
		t.Fatalf("the reading process says %q, want ready", got)
	}
	return p
}

// next gives the next line of the reading process; a process that hangs
// fails the test instead of holding it.
func (p *ntcReaderProcess) next() string {
	p.t.Helper()
	select {
	case line, ok := <-p.lines:
		if !ok {
			p.t.Fatalf("the reading process ended")
		}
		return line
	case <-time.After(30 * time.Second):
		p.t.Fatalf("the reading process gave no line within 30s")
	}
	return ""
}

// ask sends one command and gives the lines of the answer.
func (p *ntcReaderProcess) ask(command string) []string {
	p.t.Helper()
	if _, err := io.WriteString(p.in, command+"\n"); err != nil {
		p.t.Fatalf("send %s to the reading process: %v", command, err)
	}
	var lines []string
	for line := p.next(); line != "end"; line = p.next() {
		lines = append(lines, line)
	}
	return lines
}

func (p *ntcReaderProcess) close() {
	p.t.Helper()
	if got := p.ask("close"); !slices.Equal(got, []string{"closed <nil>"}) {
		p.t.Errorf("Close in the reading process: %q", got)
	}
}

// A second process reads while the service holds the store, sees the rows
// that the service writes after it opened, and cannot change the store
// through its own connection.
func TestReaderInAnotherProcessReadsWhatTheOpenStoreWrites(t *testing.T) {
	if dir := os.Getenv(ntcReaderEnv); dir != "" {
		ntcReaderChild(dir)
		return
	}
	dir := stoDir(t)
	s := stoOpen(t, dir)
	www, mail := stoWWW(t), stoMail(t)
	stoApply(t, s, www, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc1"}, At: stoT0.Add(time.Second)}, ntcRowsTo("slack")...)
	late := []string{"records corp.test. www.corp.test. A"}
	if err := s.Beat(stoT0.Add(2*time.Second), late); err != nil {
		t.Fatal(err)
	}
	beat := fmt.Sprintf("beat %s late %q", ntcUTC(stoT0.Add(2*time.Second)), late)

	r := ntcStartReader(t, dir)
	want := []string{
		"last 1 1 <nil>",
		"open 1 record-set records corp.test. www.corp.test. A",
		"event 1 alert 1 open",
		`notice 1 test "" ["request   ntc1"]`,
		beat,
		"channel slack pending 2",
		"channel hook pending 0",
	}
	if got := r.ask("read"); !slices.Equal(got, want) {
		t.Errorf("the reading process reads\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}

	before := ntcDump(t, s.db)
	wantRefused := []string{"INSERT refused true", "UPDATE refused true", "DELETE refused true", "PRAGMA refused true", "CREATE refused true"}
	if got := r.ask("write"); !slices.Equal(got, wantRefused) {
		t.Errorf("writes through the reader's connection: %q, want each refused", got)
	}
	if after := ntcDump(t, s.db); after != before {
		t.Errorf("the store after the writes of the reader:\n%s\nwant\n%s", after, before)
	}

	// The service goes on writing while the reader stays open.
	at := stoT0.Add(3 * time.Second)
	stoApply(t, s, mail, false, at, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.98"), decide.SeverityHigh, at, "hook"))
	ntcNotify(t, s, Notice{Kind: NoticeDown, Lines: []string{"last beat x", "started   y"}, At: at}, ntcRowsTo("hook")...)
	want = []string{
		"last 2 2 <nil>",
		"open 1 record-set records corp.test. www.corp.test. A",
		"open 2 record-set records corp.test. mail.corp.test. A",
		"event 1 alert 1 open",
		"event 2 alert 2 open",
		`notice 1 test "" ["request   ntc1"]`,
		`notice 2 down "" ["last beat x" "started   y"]`,
		beat,
		"channel slack pending 2",
		"channel hook pending 2",
	}
	if got := r.ask("read"); !slices.Equal(got, want) {
		t.Errorf("the reading process reads after more writes\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	r.close()
}

// A reader takes no lock of the writer and drops none. While a reading
// process is open, and after it closed, a third process is refused as a
// writer and the service still writes. Right after the service stopped, a
// reader opens and reads, and a writer may start while it is open.
func TestReaderInAnotherProcessNeitherTakesNorDropsTheWriterLock(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	www := stoWWW(t)
	stoApply(t, s, www, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	inUse := "store: " + dir + " is in use by another osk-dns-watcher process"

	r := ntcStartReader(t, dir)
	if got := stoChild(t, dir); got != inUse {
		t.Errorf("Open in a third process while a reader is open: %q, want %q", got, inUse)
	}
	r.close()
	if got := stoChild(t, dir); got != inUse {
		t.Errorf("Open in a third process after the reader closed: %q, want %q", got, inUse)
	}
	ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc2"}, At: stoT0.Add(time.Second)}, ntcRowsTo("slack")...)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	r = ntcStartReader(t, dir)
	want := []string{
		"last 1 1 <nil>",
		"open 1 record-set records corp.test. www.corp.test. A",
		"event 1 alert 1 open",
		`notice 1 test "" ["request   ntc2"]`,
		"beat 0001-01-01T00:00:00Z late []",
		"channel slack pending 2",
		"channel hook pending 0",
	}
	if got := r.ask("read"); !slices.Equal(got, want) {
		t.Errorf("a reader right after the service stopped reads\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if got := stoChild(t, dir); got != "opened" {
		t.Errorf("Open in another process while only a reader is open: %q, want it to open", got)
	}
	if got := r.ask("read"); !slices.Equal(got, want) {
		t.Errorf("the reader after a writer came and went reads\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	r.close()
}
