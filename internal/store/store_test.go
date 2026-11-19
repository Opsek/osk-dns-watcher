package store

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
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
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// stoT0 has a nanosecond part, so a store that keeps less is caught.
var stoT0 = time.Date(2026, 11, 11, 12, 0, 0, 123456789, time.UTC)

// stoZone is not UTC: a time must come back as the same instant whatever
// zone it was given in.
var stoZone = time.FixedZone("east", 5*60*60)

// stoChildEnv makes the test binary act as a second process that opens the
// folder named in it.
const stoChildEnv = "OSK_STORE_TEST_OPEN_DIR"

func stoName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

func stoWWW(t testing.TB) obs.Key {
	return obs.RecordsKey(stoName(t, "corp.test."), stoName(t, "www.corp.test."), dnswire.TypeA)
}

func stoMail(t testing.TB) obs.Key {
	return obs.RecordsKey(stoName(t, "corp.test."), stoName(t, "mail.corp.test."), dnswire.TypeA)
}

// stoDir is a state folder that only its owner may enter, as the store
// demands; t.TempDir makes one that other users may read.
func stoDir(t testing.TB) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return dir
}

func stoOpen(t *testing.T, dir string) *Store {
	t.Helper()
	s, err := Open(dir)
	if err != nil {
		t.Fatalf("Open(%q): %v", dir, err)
	}
	// Tests that check Close call it themselves; this second Close only
	// frees what a failed test left open, so its error does not matter.
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func stoApply(t *testing.T, s *Store, k obs.Key, clean bool, now time.Time, writes ...Write) {
	t.Helper()
	if err := s.Apply(k, clean, now, writes); err != nil {
		t.Fatalf("Apply(%v): %v", k, err)
	}
}

func stoExec(t *testing.T, s *Store, query string) {
	t.Helper()
	if _, err := s.db.Exec(query); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

// stoCounts gives the number of rows of every table.
func stoCounts(t *testing.T, s *Store) string {
	t.Helper()
	var parts []string
	for _, table := range []string{"alert", "event", "delivery", "check_state"} {
		var n int
		if err := s.db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		parts = append(parts, fmt.Sprintf("%s %d", table, n))
	}
	return strings.Join(parts, ", ")
}

func stoLine(t testing.TB, host, addr, text string, ttl uint32, received time.Time) alert.Line {
	t.Helper()
	l := alert.Line{Server: obs.Server{Name: stoName(t, host)}, Text: text, TTL: ttl, Received: received}
	if addr != "" {
		l.Server.Addr = netip.MustParseAddrPort(addr)
	}
	return l
}

// stoAlert is an open alert that is not stored yet.
func stoAlert(t testing.TB, r decide.Rule, k obs.Key, seen string) alert.Alert {
	t.Helper()
	return alert.Alert{
		Open: true, Rule: r, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh, Check: k,
		Expected: "10.53.0.81", Value: "10.53.0.11:53 ns1.corp.test. " + seen,
		Lines:  []alert.Line{stoLine(t, "ns1.corp.test.", "10.53.0.11:53", seen, 300, stoT0)},
		Opened: stoT0, LastClean: stoT0.Add(-time.Minute), Noticed: stoT0,
	}
}

// stoWrite is the event of a, with one delivery to each channel.
func stoWrite(kind alert.EventKind, a alert.Alert, was decide.Severity, at time.Time, channels ...string) Write {
	w := Write{Event: alert.Event{Kind: kind, Alert: a, Was: was, At: at}}
	for _, c := range channels {
		w.Deliveries = append(w.Deliveries, Delivery{Channel: c, Label: kind.String() + " to " + c, Body: []byte(`{"text":"` + c + `"}`)})
	}
	return w
}

func stoOpenAlerts(t *testing.T, s *Store, k obs.Key) []alert.Alert {
	t.Helper()
	got, err := s.OpenAlerts(k)
	if err != nil {
		t.Fatalf("OpenAlerts(%v): %v", k, err)
	}
	return got
}

// stoNth gives open alert i of check k, which must have n of them.
func stoNth(t *testing.T, s *Store, k obs.Key, n, i int) alert.Alert {
	t.Helper()
	got := stoOpenAlerts(t, s, k)
	if len(got) != n {
		t.Fatalf("OpenAlerts(%v) gives %d alerts, want %d", k, len(got), n)
	}
	return got[i]
}

func stoDue(t *testing.T, s *Store, channel string, now time.Time) []Row {
	t.Helper()
	rows, err := s.Due(channel, now)
	if err != nil {
		t.Fatalf("Due(%q, %v): %v", channel, now, err)
	}
	return rows
}

func stoRowIDs(rows []Row) []int64 {
	var ids []int64
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	return ids
}

// stoCols writes the columns of a row with a space between any two, which
// fmt.Sprint leaves out between two strings.
func stoCols(v ...any) string { return strings.TrimSuffix(fmt.Sprintln(v...), "\n") }

func stoTime(t time.Time) string {
	if t.IsZero() {
		return "zero"
	}
	return t.UTC().Format(time.RFC3339Nano)
}

// stoAlertText writes every field of a, so two alerts compare as text and a
// difference shows field by field. Names keep their case.
func stoAlertText(a alert.Alert) string {
	var b strings.Builder
	fmt.Fprintf(&b, "ID %d\nOpen %v\nRule %v\nSeverity %v\nPeak %v\nCheck %v %v %v %v\nExpected %q\nValue %q\n",
		a.ID, a.Open, a.Rule, a.Severity, a.Peak, a.Check.Kind, a.Check.Domain, a.Check.Name, a.Check.Type, a.Expected, a.Value)
	for _, l := range a.Lines {
		fmt.Fprintf(&b, "Line %v %v %q TTL %d received %s\n", l.Server.Name, l.Server.Addr, l.Text, l.TTL, stoTime(l.Received))
	}
	fmt.Fprintf(&b, "Opened %s\nLastClean %s\nNoticed %s\nResolved %s\n",
		stoTime(a.Opened), stoTime(a.LastClean), stoTime(a.Noticed), stoTime(a.Resolved))
	return b.String()
}

func TestOpenMakesPrivateFolderAndFiles(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s := stoOpen(t, dir)
	// A write makes SQLite create its WAL and shared-memory files too.
	k := stoWWW(t)
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))

	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if !info.IsDir() || info.Mode().Perm() != 0o700 {
		t.Errorf("folder mode %v, want a folder with 0700", info.Mode())
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
		info, err := e.Info()
		if err != nil {
			t.Fatal(err)
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			t.Errorf("%s has mode %v, want a file with 0600", e.Name(), info.Mode())
		}
	}
	for _, want := range []string{"state.lock", "state.db"} {
		if !slices.Contains(names, want) {
			t.Errorf("the folder holds %q, want %s among them", names, want)
		}
	}
}

func TestOpenRefusesFolderWithQuestionMarkOrHash(t *testing.T) {
	parent := t.TempDir()
	for _, name := range []string{"a?b", "a#b"} {
		dir := filepath.Join(parent, name)
		if s, err := Open(dir); err == nil {
			t.Errorf("Open(%q) worked, want an error: the character would end the file name in the DSN", dir)
			_ = s.Close()
		}
	}
	// The refusal is for the character, not for the place.
	stoOpen(t, filepath.Join(parent, "ab"))
}

// The SQLite driver reads a name that starts with file: as a URI, so such a
// folder would put the store elsewhere.
func TestOpenRefusesFolderThatStartsWithFile(t *testing.T) {
	t.Chdir(t.TempDir())
	s, err := Open("file:st")
	if want := "store: file:st: a folder name that starts with file: cannot be used"; err == nil || err.Error() != want {
		t.Errorf("Open(file:st): %v, want error %q", err, want)
		if err == nil {
			_ = s.Close()
		}
	}
	if entries, err := os.ReadDir("."); err != nil || len(entries) != 0 {
		t.Errorf("the refused Open left %v, %v; want nothing", entries, err)
	}
}

func TestSecondOpenOfOneFolderFailsUntilClose(t *testing.T) {
	dir := stoDir(t)
	first := stoOpen(t, dir)

	second, err := Open(dir)
	if want := "store: " + dir + " is in use by another osk-dns-watcher process"; err == nil || err.Error() != want {
		t.Errorf("second Open: %v, want error %q", err, want)
		if err == nil {
			_ = second.Close()
		}
	}
	// The refused Open left the first store working, and another folder
	// has its own lock.
	k := stoWWW(t)
	stoApply(t, first, k, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0))
	stoOpen(t, stoDir(t))

	if err := first.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	again := stoOpen(t, dir)
	if got := stoOpenAlerts(t, again, k); len(got) != 1 {
		t.Errorf("after Close and Open, OpenAlerts gives %d alerts, want the 1 written before", len(got))
	}
}

// The lock must also hold between processes: the test binary runs itself
// again with stoChildEnv set, and that copy only reports what Open gave.
func TestOpenFromAnotherProcessFailsUntilClose(t *testing.T) {
	if dir := os.Getenv(stoChildEnv); dir != "" {
		s, err := Open(dir)
		if err != nil {
			fmt.Println("sto-child " + err.Error())
			return
		}
		fmt.Println("sto-child opened")
		if err := s.Close(); err != nil {
			t.Fatal(err)
		}
		return
	}
	dir := stoDir(t)
	s := stoOpen(t, dir)
	if got, want := stoChild(t, dir), "store: "+dir+" is in use by another osk-dns-watcher process"; got != want {
		t.Errorf("Open in another process while the store is open: %q, want %q", got, want)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if got := stoChild(t, dir); got != "opened" {
		t.Errorf("Open in another process after Close: %q, want it to open", got)
	}
}

func stoChild(t *testing.T, dir string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestOpenFromAnotherProcessFailsUntilClose$", "-test.count=1")
	cmd.Env = append(os.Environ(), stoChildEnv+"="+dir)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("the second process: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if result, ok := strings.CutPrefix(line, "sto-child "); ok {
			return result
		}
	}
	t.Fatalf("the second process gave no result:\n%s", out)
	return ""
}

func TestOtherSchemaVersionIsRefusedAndLeftAsItIs(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	stoExec(t, s, "PRAGMA user_version = 4")
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db := filepath.Join(dir, "state.db")
	before, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}

	again, err := Open(dir)
	if want := "store: " + db + " is not a store of this osk-dns-watcher (schema 4)"; err == nil || err.Error() != want {
		t.Errorf("Open of a store with schema 4: %v, want error %q", err, want)
		if err == nil {
			_ = again.Close()
		}
	}
	after, err := os.ReadFile(db)
	if err != nil {
		t.Fatalf("the refused store is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("Open changed the store that it refused")
	}
}

// WAL lets other processes read while the store writes. A new store must
// get it, and a store that is opened again must keep it.
func TestOpenUsesWAL(t *testing.T) {
	dir := stoDir(t)
	for _, when := range []string{"new", "opened again"} {
		s := stoOpen(t, dir)
		var mode string
		if err := s.db.QueryRow("PRAGMA journal_mode").Scan(&mode); err != nil {
			t.Fatal(err)
		}
		if mode != "wal" {
			t.Errorf("%s store: journal mode %q, want wal", when, mode)
		}
		if err := s.Close(); err != nil {
			t.Fatalf("Close: %v", err)
		}
	}
}

// A database of another program is not in WAL mode; switching it to WAL
// would rewrite its header before the schema check refuses it.
func TestForeignDatabaseIsRefusedAndLeftAsItIs(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "state.db")
	other, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := other.Exec("CREATE TABLE other (x INTEGER); PRAGMA user_version = 7"); err != nil {
		t.Fatal(err)
	}
	if err := other.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if want := "store: " + path + " is not a store of this osk-dns-watcher (schema 7)"; err == nil || err.Error() != want {
		t.Errorf("Open of a foreign database: %v, want error %q", err, want)
		if err == nil {
			_ = s.Close()
		}
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the refused database is gone: %v", err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("Open changed the foreign database that it refused")
	}
}

func TestApplyWritesTheColumnsOfEachRow(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	// Mixed case: the columns hold the lower-case names.
	k := obs.RecordsKey(stoName(t, "Corp.Test."), stoName(t, "WWW.Corp.TEST."), dnswire.TypeA)
	opened := stoT0.In(stoZone)
	received := opened.Add(time.Second)
	a := alert.Alert{
		Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityMedium, Peak: decide.SeverityHigh, Check: k,
		Expected: "10.53.0.81", Value: "10.53.0.11:53 ns1.corp.test. 10.53.0.99\n- - 10.53.0.98",
		Lines: []alert.Line{
			stoLine(t, "NS1.Corp.Test.", "10.53.0.11:53", "10.53.0.99", 300, received),
			stoLine(t, ".", "", "10.53.0.98", 0, time.Time{}),
		},
		Opened: opened, LastClean: opened.Add(-time.Hour), Noticed: opened.Add(time.Minute),
	}
	at, now := stoT0.Add(2*time.Second), stoT0.Add(time.Hour)
	w := Write{
		Event: alert.Event{Kind: alert.EventOpen, Alert: a, Was: decide.SeverityLow, At: at},
		Deliveries: []Delivery{
			{Channel: "slack", Label: "label one", Body: []byte{0, 1, 0xff}},
			{Channel: "hook", Label: "label two", Body: []byte("{}")},
		},
	}
	stoApply(t, s, k, false, now, w)
	// No lines must still be a JSON array.
	bare := stoAlert(t, decide.RuleNotCovered, stoMail(t), "")
	bare.Lines = nil
	stoApply(t, s, bare.Check, false, now, stoWrite(alert.EventOpen, bare, bare.Severity, at))

	var (
		alertID, open, rule, kind, typ, severity, peak, openedAt, lastClean, noticed, resolved int64
		checkKey, domain, name, expected, value, lines                                         string
	)
	err := s.db.QueryRow(`SELECT id, open, rule, check_key, kind, domain, name, type, severity, peak,
		expected, value, lines, opened, last_clean, noticed, resolved FROM alert WHERE rule = ?`, int64(decide.RuleRecordSet)).
		Scan(&alertID, &open, &rule, &checkKey, &kind, &domain, &name, &typ, &severity, &peak,
			&expected, &value, &lines, &openedAt, &lastClean, &noticed, &resolved)
	if err != nil {
		t.Fatal(err)
	}
	got := stoCols(open, rule, checkKey, kind, domain, name, typ, severity, peak, expected, value, openedAt, lastClean, noticed, resolved)
	want := stoCols(1, int64(decide.RuleRecordSet), k.String(), int64(obs.KindRecords), "corp.test.", "www.corp.test.",
		int64(dnswire.TypeA), int64(decide.SeverityMedium), int64(decide.SeverityHigh), a.Expected, a.Value,
		opened.UnixNano(), opened.Add(-time.Hour).UnixNano(), opened.Add(time.Minute).UnixNano(), 0)
	if got != want {
		t.Errorf("alert row\n got %s\nwant %s", got, want)
	}

	var objects []map[string]any
	if err := json.Unmarshal([]byte(lines), &objects); err != nil {
		t.Fatalf("lines %q is not a JSON array of objects: %v", lines, err)
	}
	wantLines := []map[string]any{
		{"server": "ns1.corp.test.", "addr": "10.53.0.11:53", "text": "10.53.0.99", "ttl": 300.0, "received": "R"},
		{"server": ".", "addr": "", "text": "10.53.0.98", "ttl": 0.0, "received": ""},
	}
	if len(objects) != len(wantLines) {
		t.Fatalf("lines %s, want %d objects", lines, len(wantLines))
	}
	for i, o := range objects {
		// The first line's time is checked as a time: RFC 3339 allows more
		// than one spelling of it.
		if r, ok := o["received"].(string); ok && wantLines[i]["received"] == "R" {
			p, err := time.Parse(time.RFC3339Nano, r)
			if err != nil || !p.Equal(received) || !strings.HasSuffix(r, "Z") {
				t.Errorf("line %d received %q, want %s in RFC 3339 UTC", i, r, received.UTC().Format(time.RFC3339Nano))
			}
			o["received"] = "R"
		}
		if g, w := stoCols(o), stoCols(wantLines[i]); g != w {
			t.Errorf("line %d is %s, want %s", i, g, w)
		}
	}
	if err := s.db.QueryRow("SELECT lines FROM alert WHERE rule = ?", int64(decide.RuleNotCovered)).Scan(&lines); err != nil {
		t.Fatal(err)
	}
	var none []map[string]any
	if err := json.Unmarshal([]byte(lines), &none); err != nil || none == nil || len(none) != 0 {
		t.Errorf("lines of an alert with no line is %q, want an empty JSON array", lines)
	}

	var eventID, eventAlert, evSeverity, was, eventAt int64
	var evKind, evValue string
	err = s.db.QueryRow("SELECT id, alert, kind, severity, was, value, at FROM event WHERE alert = ?", alertID).
		Scan(&eventID, &eventAlert, &evKind, &evSeverity, &was, &evValue, &eventAt)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := stoCols(evKind, evSeverity, was, evValue, eventAt), stoCols("open", int64(decide.SeverityMedium), int64(decide.SeverityLow), a.Value, at.UnixNano()); got != want {
		t.Errorf("event row\n got %s\nwant %s", got, want)
	}

	rows, err := s.db.Query("SELECT event, channel, label, body, state, attempts, created, next_at, reason, done_at FROM delivery ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	// Frees the one connection when a scan fails.
	defer func() { _ = rows.Close() }()
	var deliveries []string
	for rows.Next() {
		var event, attempts, created, nextAt, doneAt int64
		var channel, label, state, reason string
		var body []byte
		if err := rows.Scan(&event, &channel, &label, &body, &state, &attempts, &created, &nextAt, &reason, &doneAt); err != nil {
			t.Fatal(err)
		}
		deliveries = append(deliveries, fmt.Sprintf("%d %s %s %q %s %d %d %d %q %d", event, channel, label, body, state, attempts, created, nextAt, reason, doneAt))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	n := now.UnixNano()
	wantDeliveries := []string{
		fmt.Sprintf("%d slack label one %q pending 0 %d %d \"\" 0", eventID, []byte{0, 1, 0xff}, n, n),
		fmt.Sprintf("%d hook label two %q pending 0 %d %d \"\" 0", eventID, []byte("{}"), n, n),
	}
	if !slices.Equal(deliveries, wantDeliveries) {
		t.Errorf("delivery rows\n got %q\nwant %q", deliveries, wantDeliveries)
	}
}

func TestApplyStoresEachEventKind(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	k := stoWWW(t)
	a := stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99")
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, a, decide.SeverityHigh, stoT0))
	a.ID = stoNth(t, s, k, 1, 0).ID

	at := stoT0
	step := func(kind alert.EventKind, was decide.Severity, change func(*alert.Alert)) {
		t.Helper()
		at = at.Add(time.Minute)
		change(&a)
		stoApply(t, s, k, false, at, stoWrite(kind, a, was, at))
	}
	step(alert.EventUpdate, decide.SeverityHigh, func(a *alert.Alert) { a.Value += " (update)"; a.Noticed = at })
	step(alert.EventEscalate, decide.SeverityHigh, func(a *alert.Alert) {
		a.Severity, a.Peak, a.Value, a.Noticed = decide.SeverityCritical, decide.SeverityCritical, a.Value+" (escalate)", at
	})
	step(alert.EventReminder, decide.SeverityCritical, func(a *alert.Alert) { a.Noticed = at })
	step(alert.EventResolve, decide.SeverityCritical, func(a *alert.Alert) { a.Open, a.Resolved = false, at })

	rows, err := s.db.Query("SELECT kind, severity, was FROM event ORDER BY id")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = rows.Close() }()
	var got []string
	for rows.Next() {
		var kind string
		var severity, was int64
		if err := rows.Scan(&kind, &severity, &was); err != nil {
			t.Fatal(err)
		}
		got = append(got, stoCols(kind, severity, was))
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	h, c := int64(decide.SeverityHigh), int64(decide.SeverityCritical)
	want := []string{stoCols("open", h, h), stoCols("update", h, h), stoCols("escalate", c, h),
		stoCols("reminder", c, c), stoCols("resolve", c, c)}
	if !slices.Equal(got, want) {
		t.Errorf("events (kind severity was)\n got %q\nwant %q", got, want)
	}

	var open, severity, peak, resolved int64
	if err := s.db.QueryRow("SELECT open, severity, peak, resolved FROM alert").Scan(&open, &severity, &peak, &resolved); err != nil {
		t.Fatal(err)
	}
	if got, want := stoCols(open, severity, peak, resolved), stoCols(0, c, c, at.UnixNano()); got != want {
		t.Errorf("the resolved alert row (open severity peak resolved) is %s, want %s", got, want)
	}
	if got := stoOpenAlerts(t, s, k); len(got) != 0 {
		t.Errorf("OpenAlerts gives %d alerts after the resolve, want none", len(got))
	}
}

func TestTwoOpensOfOneIdentityWriteNothing(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	k := stoWWW(t)
	first := stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack")
	second := stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.98"), decide.SeverityHigh, stoT0, "slack")

	err := s.Apply(k, true, stoT0, []Write{first, second})
	if err == nil || !strings.HasPrefix(err.Error(), "store: ") {
		t.Errorf("Apply of two opens of one identity: %v, want an error that starts with \"store: \"", err)
	}
	if got, want := stoCounts(t, s), "alert 0, event 0, delivery 0, check_state 0"; got != want {
		t.Errorf("after the refused Apply: %s, want %s", got, want)
	}

	// The same holds when the first open came in an earlier Apply.
	stoApply(t, s, k, false, stoT0, first)
	if err := s.Apply(k, false, stoT0, []Write{second}); err == nil {
		t.Errorf("Apply of a second open of an open identity worked, want an error")
	}
	if got, want := stoCounts(t, s), "alert 1, event 1, delivery 1, check_state 0"; got != want {
		t.Errorf("after the second refused Apply: %s, want %s", got, want)
	}
}

func TestOtherRuleOtherCheckOrResolvedIdentityMayOpen(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	rs := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99")
	stoApply(t, s, www, false, stoT0,
		stoWrite(alert.EventOpen, rs, rs.Severity, stoT0),
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleZone, www, "www.corp.test."), decide.SeverityHigh, stoT0))
	stoApply(t, s, mail, false, stoT0,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99"), decide.SeverityHigh, stoT0))
	if got, want := stoCounts(t, s), "alert 3, event 3, delivery 0, check_state 0"; got != want {
		t.Fatalf("after three opens of three identities: %s, want %s", got, want)
	}

	rs.ID = stoNth(t, s, www, 2, 0).ID
	rs.Open, rs.Resolved = false, stoT0.Add(time.Minute)
	stoApply(t, s, www, false, rs.Resolved, stoWrite(alert.EventResolve, rs, rs.Severity, rs.Resolved))
	again := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.97")
	stoApply(t, s, www, false, stoT0.Add(2*time.Minute), stoWrite(alert.EventOpen, again, again.Severity, stoT0.Add(2*time.Minute)))

	var rules []string
	for _, a := range stoOpenAlerts(t, s, www) {
		rules = append(rules, a.Rule.String())
		if a.Rule == decide.RuleRecordSet && (a.ID == rs.ID || len(a.Lines) != 1 || a.Lines[0].Text != "10.53.0.97") {
			t.Errorf("the open record-set alert is\n%s\nwant the new one, seen as 10.53.0.97", stoAlertText(a))
		}
	}
	if want := []string{"zone", "record-set"}; !slices.Equal(rules, want) {
		t.Errorf("open alerts of www: %q, want %q", rules, want)
	}
}

func TestUpdateOfAlertThatIsNotOpenFails(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www := stoWWW(t)
	a := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99")
	stoApply(t, s, www, false, stoT0, stoWrite(alert.EventOpen, a, a.Severity, stoT0))
	a.ID = stoNth(t, s, www, 1, 0).ID
	a.Open, a.Resolved = false, stoT0.Add(time.Minute)
	stoApply(t, s, www, false, a.Resolved, stoWrite(alert.EventResolve, a, a.Severity, a.Resolved))
	before := stoCounts(t, s)

	for _, id := range []int64{a.ID, a.ID + 100} {
		u := a
		u.ID, u.Open, u.Resolved, u.Value = id, true, time.Time{}, "10.53.0.11:53 ns1.corp.test. 10.53.0.98"
		// The new alert before it must go too.
		other := stoWrite(alert.EventOpen, stoAlert(t, decide.RuleZone, www, "www.corp.test."), decide.SeverityHigh, stoT0, "slack")
		err := s.Apply(www, true, stoT0.Add(2*time.Minute), []Write{other, stoWrite(alert.EventUpdate, u, u.Severity, stoT0.Add(2*time.Minute), "slack")})
		if want := fmt.Sprintf("store: alert %d is not open", id); err == nil || err.Error() != want {
			t.Errorf("update of alert %d: %v, want error %q", id, err, want)
		}
		if got := stoCounts(t, s); got != before {
			t.Errorf("after the refused update of %d: %s, want %s", id, got, before)
		}
	}
	var open int64
	var value string
	if err := s.db.QueryRow("SELECT open, value FROM alert WHERE id = ?", a.ID).Scan(&open, &value); err != nil {
		t.Fatal(err)
	}
	if open != 0 || value != a.Value {
		t.Errorf("the resolved alert has open %d and value %q, want 0 and %q", open, value, a.Value)
	}
}

// A trigger makes one statement of Apply fail, from the first write's rows
// to the last statement, and nothing of that Apply may stay.
func TestApplyFailureWritesNothing(t *testing.T) {
	www := stoWWW(t)
	for _, c := range []struct{ name, trigger string }{
		{"a later delivery", "BEFORE INSERT ON delivery WHEN NEW.channel = 'hook'"},
		{"the update", "BEFORE UPDATE ON alert"},
		{"a later event", "BEFORE INSERT ON event WHEN NEW.kind = 'escalate'"},
		{"a later alert", fmt.Sprintf("BEFORE INSERT ON alert WHEN NEW.rule = %d", decide.RuleNotCovered)},
		{"the clean time", "BEFORE INSERT ON check_state"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := stoOpen(t, stoDir(t))
			x := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99")
			stoApply(t, s, www, false, stoT0, stoWrite(alert.EventOpen, x, x.Severity, stoT0))
			x.ID = stoNth(t, s, www, 1, 0).ID
			before := stoCounts(t, s)

			x.Severity, x.Peak, x.Value = decide.SeverityCritical, decide.SeverityCritical, "10.53.0.11:53 ns1.corp.test. 10.53.0.98"
			now := stoT0.Add(time.Minute)
			writes := []Write{
				stoWrite(alert.EventOpen, stoAlert(t, decide.RuleZone, www, "www.corp.test."), decide.SeverityHigh, now, "slack", "hook"),
				stoWrite(alert.EventEscalate, x, decide.SeverityHigh, now, "slack"),
				stoWrite(alert.EventOpen, stoAlert(t, decide.RuleNotCovered, www, "10.53.0.99"), decide.SeverityHigh, now),
			}
			stoExec(t, s, "CREATE TRIGGER sto_fault "+c.trigger+" BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
			err := s.Apply(www, true, now, writes)
			if err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), "planted fault") {
				t.Errorf("Apply: %v, want an error that starts with \"store: \" and holds the planted fault", err)
			}
			if got := stoCounts(t, s); got != before {
				t.Errorf("after the failed Apply: %s, want %s", got, before)
			}
			if got := stoNth(t, s, www, 1, 0); got.Severity != decide.SeverityHigh {
				t.Errorf("the alert in place changed to %v, want it still high", got.Severity)
			}

			stoExec(t, s, "DROP TRIGGER sto_fault")
			stoApply(t, s, www, true, now, writes...)
			if got, want := stoCounts(t, s), "alert 3, event 4, delivery 3, check_state 1"; got != want {
				t.Errorf("after the same Apply without the fault: %s, want %s", got, want)
			}
		})
	}
}

func TestOpenAlertsGivesOpenAlertsOfTheCheckByID(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	// Record-set is written first though its rule sorts after zone.
	stoApply(t, s, www, false, stoT0,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, stoT0),
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleZone, www, "www.corp.test."), decide.SeverityHigh, stoT0),
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleNotCovered, www, "10.53.0.99"), decide.SeverityHigh, stoT0))
	stoApply(t, s, mail, false, stoT0,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99"), decide.SeverityHigh, stoT0))
	nc := stoNth(t, s, www, 3, 2)
	nc.Open, nc.Resolved = false, stoT0.Add(time.Minute)
	stoApply(t, s, www, false, nc.Resolved, stoWrite(alert.EventResolve, nc, nc.Severity, nc.Resolved))

	got := stoOpenAlerts(t, s, www)
	var rules []string
	for _, a := range got {
		rules = append(rules, a.Rule.String())
		if !a.Open || a.Check.String() != www.String() {
			t.Errorf("OpenAlerts(www) gives alert %d, open %v, of %v", a.ID, a.Open, a.Check)
		}
	}
	if want := []string{"record-set", "zone"}; !slices.Equal(rules, want) {
		t.Errorf("OpenAlerts(www) gives rules %q, want %q", rules, want)
	}
	if len(got) == 2 && got[0].ID >= got[1].ID {
		t.Errorf("OpenAlerts(www) gives ids %d, %d, want them ascending", got[0].ID, got[1].ID)
	}
	if got := stoOpenAlerts(t, s, obs.DelegationKey(stoName(t, "corp.test."))); len(got) != 0 {
		t.Errorf("OpenAlerts of a check with no alert gives %d, want none", len(got))
	}
}

func TestLastCleanIsTheLatestCleanApply(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	last := func(k obs.Key) time.Time {
		t.Helper()
		got, err := s.LastClean(k)
		if err != nil {
			t.Fatalf("LastClean(%v): %v", k, err)
		}
		return got
	}
	if got := last(www); !got.IsZero() {
		t.Errorf("LastClean of a check never clean is %v, want zero", got)
	}
	t1, t2, t3 := stoT0.In(stoZone), stoT0.Add(time.Minute), stoT0.Add(2*time.Minute)
	stoApply(t, s, www, true, t1)
	if got := last(www); !got.Equal(t1) {
		t.Errorf("LastClean after a clean Apply is %v, want %v", got, t1)
	}
	if got := last(mail); !got.IsZero() {
		t.Errorf("LastClean of another check is %v, want zero", got)
	}
	stoApply(t, s, www, false, t2)
	if got := last(www); !got.Equal(t1) {
		t.Errorf("LastClean after an Apply that is not clean is %v, want still %v", got, t1)
	}
	stoApply(t, s, www, true, t3)
	if got := last(www); !got.Equal(t3) {
		t.Errorf("LastClean after a second clean Apply is %v, want %v", got, t3)
	}
	if got, want := stoCounts(t, s), "alert 0, event 0, delivery 0, check_state 1"; got != want {
		t.Errorf("rows: %s, want %s", got, want)
	}
}

func TestZeroTimesAreStoredAsZero(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	k := stoWWW(t)
	a := stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99")
	a.LastClean = time.Time{}
	a.Lines[0].Received = time.Time{}
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, a, a.Severity, stoT0, "slack"))

	var lastClean, resolved, doneAt int64
	var lines string
	if err := s.db.QueryRow("SELECT last_clean, resolved, lines FROM alert").Scan(&lastClean, &resolved, &lines); err != nil {
		t.Fatal(err)
	}
	if lastClean != 0 || resolved != 0 {
		t.Errorf("last_clean %d and resolved %d, want 0 and 0", lastClean, resolved)
	}
	var objects []map[string]any
	if err := json.Unmarshal([]byte(lines), &objects); err != nil || len(objects) != 1 || objects[0]["received"] != "" {
		t.Errorf("lines %s, want one object with received \"\"", lines)
	}

	got := stoOpenAlerts(t, s, k)
	if len(got) != 1 {
		t.Fatalf("OpenAlerts gives %d alerts, want 1", len(got))
	}
	if !got[0].LastClean.IsZero() || !got[0].Resolved.IsZero() || len(got[0].Lines) != 1 || !got[0].Lines[0].Received.IsZero() {
		t.Errorf("zero times did not come back as zero:\n%s", stoAlertText(got[0]))
	}
	if c, err := s.LastClean(k); err != nil || !c.IsZero() {
		t.Errorf("LastClean = %v, %v; want zero", c, err)
	}

	row := stoDue(t, s, "slack", stoT0)
	if len(row) != 1 {
		t.Fatalf("Due gives %d rows, want 1", len(row))
	}
	if err := s.Record(row[0].ID, Done{State: RowPending, Attempts: 1, NextAt: stoT0.Add(10 * time.Second), Reason: "status 503", At: stoT0}); err != nil {
		t.Fatal(err)
	}
	if err := s.db.QueryRow("SELECT done_at FROM delivery").Scan(&doneAt); err != nil {
		t.Fatal(err)
	}
	if doneAt != 0 {
		t.Errorf("done_at of a pending row is %d, want 0", doneAt)
	}
}

func TestRoundTripKeepsEveryField(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	k := stoWWW(t)
	t1 := stoT0.In(stoZone)
	want := alert.Alert{
		Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityCritical, Check: k,
		Expected: `10.53.0.81 | 10.53.0.82`, Value: "10.53.0.11:53 ns1.corp.test. 10.53.0.99\n- - \"x\\\"y\"\n[fd53::12]:53 ns2.corp.test. 10.53.0.99",
		Lines: []alert.Line{
			stoLine(t, "ns1.corp.test.", "10.53.0.11:53", "10.53.0.99", 300, t1.Add(time.Second)),
			stoLine(t, ".", "", `"x\"y"`, 0, time.Time{}),
			stoLine(t, "ns2.corp.test.", "[fd53::12]:53", "10.53.0.99", 4294967295, t1.Add(1500*time.Millisecond)),
		},
		Opened: t1, LastClean: t1.Add(-time.Hour - time.Nanosecond), Noticed: t1.Add(time.Minute),
	}
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, want, want.Severity, stoT0))
	// The alert comes back from the files, not from memory.
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s = stoOpen(t, dir)

	got := stoOpenAlerts(t, s, k)
	if len(got) != 1 || got[0].ID == 0 {
		t.Fatalf("OpenAlerts gives %d alerts, want 1 with an id", len(got))
	}
	want.ID = got[0].ID
	if g, w := stoAlertText(got[0]), stoAlertText(want); g != w {
		t.Errorf("stored alert\n%s\nwant\n%s", g, w)
	}

	// An update writes its fields; the next read gives them.
	want.Severity, want.Expected, want.Value = decide.SeverityMedium, "10.53.0.83", "- ns3.corp.test. 10.53.0.98"
	want.Lines = []alert.Line{stoLine(t, "ns3.corp.test.", "", "10.53.0.98", 60, t1.Add(3*time.Minute))}
	want.Noticed = t1.Add(3 * time.Minute)
	stoApply(t, s, k, false, stoT0.Add(3*time.Minute), stoWrite(alert.EventUpdate, want, decide.SeverityHigh, stoT0.Add(3*time.Minute)))
	got = stoOpenAlerts(t, s, k)
	if len(got) != 1 {
		t.Fatalf("OpenAlerts gives %d alerts after the update, want 1", len(got))
	}
	if g, w := stoAlertText(got[0]), stoAlertText(want); g != w {
		t.Errorf("updated alert\n%s\nwant\n%s", g, w)
	}
}

func stoAnswer(t testing.TB, host, addr string, r obs.Result) obs.Answer {
	t.Helper()
	a := obs.Answer{Result: r}
	a.Server = obs.Server{Name: stoName(t, host), Addr: netip.MustParseAddrPort(addr)}
	a.Sent = stoT0
	a.Received = stoT0.Add(time.Second)
	return a
}

func stoA(t testing.TB, owner string, addrs ...string) obs.Result {
	t.Helper()
	var set []dnswire.Record
	for _, x := range addrs {
		d, err := dnswire.ParseRData(dnswire.TypeA, x)
		if err != nil {
			t.Fatal(err)
		}
		set = append(set, dnswire.Record{Name: stoName(t, owner), Class: dnswire.ClassINET, TTL: 300, Data: d})
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

func stoObservation(t testing.TB, zone string, answers ...obs.Answer) obs.Observation {
	return obs.Observation{Key: stoWWW(t), Start: stoT0, Deadline: stoT0.Add(45 * time.Second), Zone: stoName(t, zone), Answers: answers}
}

// stoChanges writes what decide's changes say; a resolve carries the open
// finding it was given, so its proof is compared by what the store keeps.
func stoChanges(changes []decide.Change) string {
	var b strings.Builder
	for _, c := range changes {
		f := c.Finding
		fmt.Fprintf(&b, "%v %v %v %v expected %q value %q\n", c.Op, f.Rule, f.Severity, f.Check, f.Expected, f.Value)
		for _, s := range f.Seen {
			fmt.Fprintf(&b, "  seen %v %v %q\n", s.Answer.Server.Name, s.Answer.Server.Addr, s.Text)
		}
	}
	return b.String()
}

func TestStoredAlertsGiveDecideTheSameChanges(t *testing.T) {
	f, err := expect.Parse([]byte("domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\nwww.corp.test. A 10.53.0.81\n"))
	if err != nil {
		t.Fatal(err)
	}
	ns1 := func(r obs.Result) obs.Answer { return stoAnswer(t, "ns1.corp.test.", "10.53.0.11:53", r) }
	ns2 := func(r obs.Result) obs.Answer { return stoAnswer(t, "ns2.corp.test.", "10.53.0.12:53", r) }
	bad, good := stoA(t, "www.corp.test.", "10.53.0.99"), stoA(t, "www.corp.test.", "10.53.0.81")
	timeout := obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout})

	// Served by a cut at www.corp.test. that the file does not declare, the
	// set gives a zone finding as well as a record-set finding.
	first := stoObservation(t, "www.corp.test.", ns1(bad), ns2(bad))
	opened := decide.Decide(decide.Input{Expect: f, Observation: first, Now: stoT0})
	if len(opened) != 2 {
		t.Fatalf("the first observation gives%s, want two opens", stoChanges(opened))
	}
	var original []decide.Finding
	var writes []Write
	for _, c := range opened {
		original = append(original, c.Finding)
		a := alert.Alert{
			Open: true, Rule: c.Finding.Rule, Severity: c.Finding.Severity, Peak: c.Finding.Severity, Check: c.Finding.Check,
			Expected: c.Finding.Expected, Value: c.Finding.Value, Opened: stoT0, Noticed: stoT0,
		}
		for _, seen := range c.Finding.Seen {
			a.Lines = append(a.Lines, alert.Line{Server: seen.Answer.Server, Text: seen.Text, TTL: 300, Received: seen.Answer.Received})
		}
		writes = append(writes, stoWrite(alert.EventOpen, a, a.Severity, stoT0))
	}
	s := stoOpen(t, stoDir(t))
	stoApply(t, s, first.Key, false, stoT0, writes...)
	var stored []decide.Finding
	for _, a := range stoOpenAlerts(t, s, first.Key) {
		stored = append(stored, a.Finding())
	}

	for _, c := range []struct {
		name    string
		next    obs.Observation
		changes int
	}{
		{"nothing changed", first, 0},
		{"a new server line", stoObservation(t, "www.corp.test.", ns1(bad), ns2(stoA(t, "www.corp.test.", "10.53.0.98"))), 1},
		{"a line is gone", stoObservation(t, "www.corp.test.", ns1(bad), ns2(good)), 0},
		{"a server that showed it fails", stoObservation(t, "corp.test.", ns1(timeout), ns2(good)), 0},
		{"all is fixed", stoObservation(t, "corp.test.", ns1(good), ns2(good)), 2},
	} {
		now := stoT0.Add(time.Minute)
		want := decide.Decide(decide.Input{Expect: f, Open: original, Observation: c.next, Now: now})
		got := decide.Decide(decide.Input{Expect: f, Open: stored, Observation: c.next, Now: now})
		if len(want) != c.changes {
			t.Fatalf("%s: the original findings give%s, want %d changes", c.name, stoChanges(want), c.changes)
		}
		if g, w := stoChanges(got), stoChanges(want); g != w {
			t.Errorf("%s: the stored alerts give\n%s\nthe original findings give\n%s", c.name, g, w)
		}
	}
}

func TestRecordWritesEachState(t *testing.T) {
	at := stoT0.Add(time.Minute)
	later := stoT0.Add(time.Hour)
	for _, c := range []struct {
		done     Done
		columns  string    // state attempts next_at reason done_at
		dueFrom  time.Time // zero: never due again
		givenUps int
	}{
		{Done{State: RowPending, Attempts: 1, NextAt: at.Add(10 * time.Second), Reason: "status 503", At: at},
			stoCols("pending", 1, at.Add(10*time.Second).UnixNano(), "status 503", 0), at.Add(10 * time.Second), 0},
		{Done{State: RowSent, Attempts: 2, NextAt: later, At: at},
			stoCols("sent", 2, at.UnixNano(), "", at.UnixNano()), time.Time{}, 0},
		{Done{State: RowGivenUp, Attempts: 30, NextAt: later, Reason: `status 400 "invalid_payload"`, At: at},
			stoCols("given-up", 30, at.UnixNano(), `status 400 "invalid_payload"`, at.UnixNano()), time.Time{}, 1},
	} {
		t.Run(c.done.State.String(), func(t *testing.T) {
			s := stoOpen(t, stoDir(t))
			k := stoWWW(t)
			stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
			rows := stoDue(t, s, "slack", stoT0)
			if len(rows) != 1 {
				t.Fatalf("Due gives %d rows, want 1", len(rows))
			}
			if err := s.Record(rows[0].ID, c.done); err != nil {
				t.Fatalf("Record: %v", err)
			}

			var state, reason string
			var attempts, nextAt, doneAt int64
			if err := s.db.QueryRow("SELECT state, attempts, next_at, reason, done_at FROM delivery").Scan(&state, &attempts, &nextAt, &reason, &doneAt); err != nil {
				t.Fatal(err)
			}
			if got := stoCols(state, attempts, nextAt, reason, doneAt); got != c.columns {
				t.Errorf("row (state attempts next_at reason done_at)\n got %s\nwant %s", got, c.columns)
			}
			var givenUps int
			if err := s.db.QueryRow("SELECT count(*) FROM event WHERE kind = 'given-up'").Scan(&givenUps); err != nil {
				t.Fatal(err)
			}
			if givenUps != c.givenUps {
				t.Errorf("%d given-up events, want %d", givenUps, c.givenUps)
			}

			if c.dueFrom.IsZero() {
				if got := stoDue(t, s, "slack", later.Add(time.Hour)); len(got) != 0 {
					t.Errorf("an ended row is due again: %v", stoRowIDs(got))
				}
				return
			}
			if got := stoDue(t, s, "slack", c.dueFrom.Add(-time.Nanosecond)); len(got) != 0 {
				t.Errorf("the row is due before its next try: %v", stoRowIDs(got))
			}
			got := stoDue(t, s, "slack", c.dueFrom)
			if len(got) != 1 || got[0].Attempts != c.done.Attempts || !got[0].NextAt.Equal(c.done.NextAt) {
				t.Errorf("Due at the next try gives %+v, want the row with %d attempts and next try %v", got, c.done.Attempts, c.done.NextAt)
			}
		})
	}
}

func TestRecordGivenUpAddsEventOnTheRowsAlert(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	other := stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99")
	a := stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99")
	// The other alert comes first, so its id differs from the alert of the row.
	stoApply(t, s, mail, false, stoT0, stoWrite(alert.EventOpen, other, other.Severity, stoT0))
	stoApply(t, s, www, false, stoT0, stoWrite(alert.EventOpen, a, a.Severity, stoT0))
	a.ID = stoNth(t, s, www, 1, 0).ID
	// An escalate, so severity and was differ.
	a.Severity, a.Peak = decide.SeverityCritical, decide.SeverityCritical
	esc := stoT0.Add(time.Minute)
	stoApply(t, s, www, false, esc, stoWrite(alert.EventEscalate, a, decide.SeverityHigh, esc, "slack"))
	rows := stoDue(t, s, "slack", esc)
	if len(rows) != 1 {
		t.Fatalf("Due gives %d rows, want 1", len(rows))
	}
	// A later update with no row: the alert and its last event now hold
	// other severities than the event of the row.
	a.Severity = decide.SeverityMedium
	stoApply(t, s, www, false, esc, stoWrite(alert.EventUpdate, a, decide.SeverityCritical, esc))
	at := esc.Add(time.Minute)
	if err := s.Record(rows[0].ID, Done{State: RowGivenUp, Attempts: 1, Reason: `status 400 "invalid_payload"`, At: at}); err != nil {
		t.Fatalf("Record: %v", err)
	}

	var alertID, severity, was, eventAt int64
	var value string
	err := s.db.QueryRow("SELECT alert, severity, was, value, at FROM event WHERE kind = 'given-up'").Scan(&alertID, &severity, &was, &value, &eventAt)
	if err != nil {
		t.Fatalf("the given-up event: %v", err)
	}
	got := stoCols(alertID, severity, was, value, eventAt)
	want := stoCols(a.ID, int64(decide.SeverityCritical), int64(decide.SeverityHigh), `slack: status 400 "invalid_payload"`, at.UnixNano())
	if got != want {
		t.Errorf("given-up event (alert severity was value at)\n got %s\nwant %s", got, want)
	}
}

func TestRecordGivenUpIsAllOrNothing(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	k := stoWWW(t)
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	rows := stoDue(t, s, "slack", stoT0)
	if len(rows) != 1 {
		t.Fatalf("Due gives %d rows, want 1", len(rows))
	}
	stoExec(t, s, "CREATE TRIGGER sto_fault BEFORE INSERT ON event BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
	if err := s.Record(rows[0].ID, Done{State: RowGivenUp, Attempts: 1, Reason: "status 404", At: stoT0}); err == nil {
		t.Errorf("Record worked though its event could not be written")
	}
	stoExec(t, s, "DROP TRIGGER sto_fault")
	if got := stoDue(t, s, "slack", stoT0); len(got) != 1 || got[0].Attempts != 0 {
		t.Errorf("after the failed Record the row is %+v, want it pending with 0 attempts", got)
	}
}

func TestRecordChangesOnlyPendingRows(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	k := stoWWW(t)
	stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	rows := stoDue(t, s, "slack", stoT0)
	if len(rows) != 1 {
		t.Fatalf("Due gives %d rows, want 1", len(rows))
	}
	id := rows[0].ID
	at := stoT0.Add(time.Minute)
	if err := s.Record(id, Done{State: RowSent, Attempts: 1, At: at}); err != nil {
		t.Fatalf("Record: %v", err)
	}
	for _, d := range []Done{
		{State: RowPending, Attempts: 2, NextAt: at, Reason: "status 503", At: at},
		{State: RowGivenUp, Attempts: 2, Reason: "status 404", At: at},
	} {
		if err := s.Record(id, d); err == nil {
			t.Errorf("Record %v of a sent row worked, want an error", d.State)
		}
	}
	if err := s.Record(id+100, Done{State: RowSent, Attempts: 1, At: at}); err == nil {
		t.Errorf("Record of a row that does not exist worked, want an error")
	}
	var state string
	var attempts int
	if err := s.db.QueryRow("SELECT state, attempts FROM delivery WHERE id = ?", id).Scan(&state, &attempts); err != nil {
		t.Fatal(err)
	}
	if state != "sent" || attempts != 1 {
		t.Errorf("the sent row is now %s with %d attempts", state, attempts)
	}
	if got, want := stoCounts(t, s), "alert 1, event 1, delivery 1, check_state 0"; got != want {
		t.Errorf("rows: %s, want %s", got, want)
	}
}

func TestDueGivesPendingRowsOfOneChannelByID(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	shop := obs.RecordsKey(stoName(t, "corp.test."), stoName(t, "shop.corp.test."), dnswire.TypeA)
	created := stoT0.In(stoZone)
	// Rows 1 to 5: slack, hook, slack, slack, slack.
	stoApply(t, s, www, false, created,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack", "hook"),
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleZone, www, "www.corp.test."), decide.SeverityHigh, stoT0, "slack"))
	stoApply(t, s, mail, false, created,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	stoApply(t, s, shop, false, created,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, shop, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	all := stoDue(t, s, "slack", created)
	if len(all) != 4 {
		t.Fatalf("Due(slack) gives %d rows, want 4", len(all))
	}
	ids := stoRowIDs(all)
	if !slices.IsSorted(ids) {
		t.Errorf("Due(slack) gives ids %v, want them ascending", ids)
	}
	first := all[0]
	if first.Channel != "slack" || first.Label != "open to slack" || string(first.Body) != `{"text":"slack"}` ||
		first.Attempts != 0 || !first.Created.Equal(created) || !first.NextAt.Equal(created) {
		t.Errorf("first row %+v, want slack, its label and body, 0 attempts, created and next try %v", first, created)
	}
	if hook := stoDue(t, s, "hook", created); len(hook) != 1 || hook[0].Channel != "hook" {
		t.Errorf("Due(hook) gives %+v, want its one row", hook)
	}
	if got := stoDue(t, s, "other", created.Add(time.Hour)); len(got) != 0 {
		t.Errorf("Due of a channel with no row gives %v", stoRowIDs(got))
	}
	if got := stoDue(t, s, "slack", created.Add(-time.Nanosecond)); len(got) != 0 {
		t.Errorf("rows are due before they were created: %v", stoRowIDs(got))
	}

	// Later tries in the reverse order of the ids, so an order by next try
	// differs from the order by id. The last row is sent.
	record := func(id int64, d Done) {
		t.Helper()
		if err := s.Record(id, d); err != nil {
			t.Fatalf("Record(%d): %v", id, err)
		}
	}
	record(ids[0], Done{State: RowPending, Attempts: 1, NextAt: created.Add(30 * time.Second), Reason: "status 503", At: created})
	record(ids[1], Done{State: RowPending, Attempts: 1, NextAt: created.Add(20 * time.Second), Reason: "status 503", At: created})
	record(ids[2], Done{State: RowPending, Attempts: 1, NextAt: created.Add(10 * time.Second), Reason: "status 503", At: created})
	record(ids[3], Done{State: RowSent, Attempts: 1, At: created})
	for _, c := range []struct {
		after time.Duration
		want  []int64
	}{
		{0, nil},
		{10*time.Second - time.Nanosecond, nil},
		{10 * time.Second, []int64{ids[2]}},
		{20 * time.Second, []int64{ids[1], ids[2]}},
		{time.Hour, []int64{ids[0], ids[1], ids[2]}},
	} {
		if got := stoRowIDs(stoDue(t, s, "slack", created.Add(c.after))); !slices.Equal(got, c.want) {
			t.Errorf("Due(slack, created + %v) gives %v, want %v", c.after, got, c.want)
		}
	}
}

// A row that failed while the clock ran ahead would wait for that clock. No
// schedule waits more than an hour, so a row whose next try lies further
// ahead is due now.
func TestDueGivesRowsAfterTheClockStepsBack(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	stoApply(t, s, www, false, stoT0,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	stoApply(t, s, mail, false, stoT0,
		stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99"), decide.SeverityHigh, stoT0, "slack"))
	ids := stoRowIDs(stoDue(t, s, "slack", stoT0))
	if len(ids) != 2 {
		t.Fatalf("due rows %v, want 2", ids)
	}
	ahead := stoT0.AddDate(10, 0, 0)
	for i, next := range []time.Time{stoT0.Add(time.Hour), ahead.Add(10 * time.Second)} {
		if err := s.Record(ids[i], Done{State: RowPending, Attempts: 1, NextAt: next, Reason: "status 503", At: ahead}); err != nil {
			t.Fatal(err)
		}
	}
	if got := stoRowIDs(stoDue(t, s, "slack", stoT0)); !slices.Equal(got, ids[1:]) {
		t.Errorf("Due(slack, now) gives %v, want only the row %d, whose next try is ten years ahead", got, ids[1])
	}
}

func TestRowStateWords(t *testing.T) {
	for s, want := range map[RowState]string{RowPending: "pending", RowSent: "sent", RowGivenUp: "given-up", 0: "row0", 9: "row9"} {
		if got := s.String(); got != want {
			t.Errorf("RowState(%d).String() = %q, want %q", uint8(s), got, want)
		}
	}
}
