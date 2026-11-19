package store

import (
	"bytes"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// beaVersion1 is the schema of a store of version 1, the last one without
// the beat table. Folders of that version exist and must still open.
const beaVersion1 = `
CREATE TABLE alert (id INTEGER PRIMARY KEY, open INTEGER NOT NULL CHECK (open IN (0, 1)),
  rule INTEGER NOT NULL, check_key TEXT NOT NULL, kind INTEGER NOT NULL, domain TEXT NOT NULL,
  name TEXT NOT NULL, type INTEGER NOT NULL, severity INTEGER NOT NULL, peak INTEGER NOT NULL,
  expected TEXT NOT NULL, value TEXT NOT NULL, lines TEXT NOT NULL, opened INTEGER NOT NULL,
  last_clean INTEGER NOT NULL, noticed INTEGER NOT NULL, resolved INTEGER NOT NULL) STRICT;
CREATE UNIQUE INDEX alert_open ON alert (check_key, rule) WHERE open = 1;
CREATE TABLE event (id INTEGER PRIMARY KEY, alert INTEGER NOT NULL REFERENCES alert (id),
  kind TEXT NOT NULL CHECK (kind IN ('open','update','escalate','reminder','resolve','given-up')),
  severity INTEGER NOT NULL, was INTEGER NOT NULL, value TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE delivery (id INTEGER PRIMARY KEY, event INTEGER NOT NULL REFERENCES event (id),
  channel TEXT NOT NULL CHECK (channel <> ''), label TEXT NOT NULL, body BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','sent','given-up')), attempts INTEGER NOT NULL,
  created INTEGER NOT NULL, next_at INTEGER NOT NULL, reason TEXT NOT NULL, done_at INTEGER NOT NULL) STRICT;
CREATE INDEX delivery_due ON delivery (channel, next_at) WHERE state = 'pending';
CREATE TABLE check_state (check_key TEXT PRIMARY KEY, last_clean INTEGER NOT NULL) STRICT;
PRAGMA user_version = 1;
`

// beaNamesV3 are the objects of a store of version 3, without the indexes
// that SQLite makes for itself.
const beaNamesV3 = `table alert
index alert_open
table beat
table check_state
table delivery
index delivery_due
index delivery_event
index delivery_notice
table event
table loaded
table notice
`

// beaBeatTableV3 is what beaBeatTable gives for the beat table of version 3.
const beaBeatTableV3 = `id INTEGER notnull 0 pk 1
at INTEGER notnull 1 pk 0
late TEXT notnull 1 pk 0
strict 1
a row with id 2 is refused true
`

// beaColumnsV1 are the columns of each table of version 1. Later versions
// add columns, and every row must keep the values of these.
var beaColumnsV1 = []struct{ table, columns string }{
	{"alert", "id, open, rule, check_key, kind, domain, name, type, severity, peak, expected, value, lines, opened, last_clean, noticed, resolved"},
	{"event", "id, alert, kind, severity, was, value, at"},
	{"delivery", "id, event, channel, label, body, state, attempts, created, next_at, reason, done_at"},
	{"check_state", "check_key, last_clean"},
}

// beaWithFile runs f on a connection of its own to the database at path and
// closes it before it returns. No store of the folder may be open then:
// closing a second descriptor of the file would drop the store's locks.
func beaWithFile(t *testing.T, path string, f func(db *sql.DB)) {
	t.Helper()
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	defer func() {
		if err := db.Close(); err != nil {
			t.Errorf("close %s: %v", path, err)
		}
	}()
	f(db)
}

func beaExec(t *testing.T, db *sql.DB, query string, args ...any) {
	t.Helper()
	if _, err := db.Exec(query, args...); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
}

func beaVersion(t *testing.T, db *sql.DB) int {
	t.Helper()
	var v int
	if err := db.QueryRow("PRAGMA user_version").Scan(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

// beaNames gives the type and name of each object of the schema, by name.
func beaNames(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query("SELECT type, name FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%' ORDER BY name")
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for rows.Next() {
		var typ, name string
		if err := rows.Scan(&typ, &name); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s\n", typ, name)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return b.String()
}

// beaBeatTable gives the columns of the beat table, whether it is strict,
// and whether it refuses a row with an id other than 1. That insert is
// rolled back, so the table stays as it was.
func beaBeatTable(t *testing.T, db *sql.DB) string {
	t.Helper()
	rows, err := db.Query(`SELECT name, type, "notnull", pk FROM pragma_table_info('beat') ORDER BY cid`)
	if err != nil {
		t.Fatal(err)
	}
	var b strings.Builder
	for rows.Next() {
		var name, typ string
		var notNull, pk int
		if err := rows.Scan(&name, &typ, &notNull, &pk); err != nil {
			t.Fatal(err)
		}
		fmt.Fprintf(&b, "%s %s notnull %d pk %d\n", name, typ, notNull, pk)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		return "no beat table\n"
	}
	var strict int
	if err := db.QueryRow("SELECT strict FROM pragma_table_list WHERE schema = 'main' AND name = 'beat'").Scan(&strict); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&b, "strict %d\n", strict)
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	_, refused := tx.Exec("INSERT INTO beat (id, at) VALUES (2, 0)")
	if err := tx.Rollback(); err != nil {
		t.Fatal(err)
	}
	fmt.Fprintf(&b, "a row with id 2 is refused %v\n", refused != nil)
	return b.String()
}

// beaRows gives every row of the tables of version 1, by table and rowid,
// with the columns of version 1.
func beaRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	var b strings.Builder
	for _, c := range beaColumnsV1 {
		table := c.table
		rows, err := db.Query("SELECT " + c.columns + " FROM " + table + " ORDER BY rowid")
		if err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
		cols, err := rows.Columns()
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			values := make([]any, len(cols))
			dest := make([]any, len(cols))
			for i := range values {
				dest[i] = &values[i]
			}
			if err := rows.Scan(dest...); err != nil {
				t.Fatalf("read %s: %v", table, err)
			}
			fmt.Fprintf(&b, "%s %#v\n", table, values)
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("read %s: %v", table, err)
		}
	}
	return b.String()
}

// beaFile gives the version, the schema and every row of the database at
// path.
func beaFile(t *testing.T, path string) string {
	t.Helper()
	var b strings.Builder
	beaWithFile(t, path, func(db *sql.DB) {
		fmt.Fprintf(&b, "user_version %d\n", beaVersion(t, db))
		rows, err := db.Query("SELECT type, name, tbl_name, coalesce(sql, '') FROM sqlite_schema ORDER BY name")
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var typ, name, table, text string
			if err := rows.Scan(&typ, &name, &table, &text); err != nil {
				t.Fatal(err)
			}
			fmt.Fprintf(&b, "%s %s on %s: %s\n", typ, name, table, text)
		}
		if err := rows.Err(); err != nil {
			t.Fatal(err)
		}
		b.WriteString(beaRows(t, db))
	})
	return b.String()
}

// beaMakeVersion1 writes a store of version 1 at path, in WAL mode as such
// a store is, with two alerts of www (one open), their events, deliveries in
// each state, and the clean times of www and mail.
func beaMakeVersion1(t *testing.T, path string) {
	t.Helper()
	www, mail := stoWWW(t), stoMail(t)
	t0 := stoT0.UnixNano()
	minute := int64(time.Minute)
	lines := `[{"server":"ns1.corp.test.","addr":"10.53.0.11:53","text":"10.53.0.99","ttl":300,"received":"2026-11-11T12:00:00.123456789Z"}]`
	beaWithFile(t, path, func(db *sql.DB) {
		beaExec(t, db, beaVersion1)
		beaExec(t, db, "PRAGMA journal_mode = WAL")
		insertAlert := "INSERT INTO alert VALUES (?, ?, ?, ?, ?, 'corp.test.', 'www.corp.test.', ?, ?, ?, '10.53.0.81', ?, ?, ?, ?, ?, ?)"
		beaExec(t, db, insertAlert, 1, 1, decide.RuleRecordSet, www.String(), www.Kind, dnswire.TypeA,
			decide.SeverityCritical, decide.SeverityCritical, "10.53.0.11:53 ns1.corp.test. 10.53.0.99", lines,
			t0, t0-minute, t0+minute, 0)
		beaExec(t, db, insertAlert, 2, 0, decide.RuleZone, www.String(), www.Kind, dnswire.TypeA,
			decide.SeverityHigh, decide.SeverityHigh, "10.53.0.11:53 ns1.corp.test. www.corp.test.", "[]",
			t0, t0-minute, t0, t0+60*minute)
		insertEvent := "INSERT INTO event VALUES (?, ?, ?, ?, ?, ?, ?)"
		beaExec(t, db, insertEvent, 1, 1, "open", decide.SeverityHigh, decide.SeverityHigh, "10.53.0.11:53 ns1.corp.test. 10.53.0.99", t0)
		beaExec(t, db, insertEvent, 2, 1, "escalate", decide.SeverityCritical, decide.SeverityHigh, "10.53.0.11:53 ns1.corp.test. 10.53.0.99", t0+minute)
		beaExec(t, db, insertEvent, 3, 2, "open", decide.SeverityHigh, decide.SeverityHigh, "10.53.0.11:53 ns1.corp.test. www.corp.test.", t0)
		beaExec(t, db, insertEvent, 4, 2, "resolve", decide.SeverityHigh, decide.SeverityHigh, "10.53.0.11:53 ns1.corp.test. www.corp.test.", t0+60*minute)
		beaExec(t, db, insertEvent, 5, 1, "given-up", decide.SeverityCritical, decide.SeverityHigh, "hook: status 404", t0+2*minute)
		insertDelivery := "INSERT INTO delivery VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
		beaExec(t, db, insertDelivery, 1, 1, "slack", "open to slack", []byte(`{"text":"open"}`), "sent", 1, t0, t0, "", t0+1)
		beaExec(t, db, insertDelivery, 2, 2, "slack", "escalate to slack", []byte(`{"text":"escalate"}`), "pending", 2, t0+minute, t0+2*minute, "status 503", 0)
		beaExec(t, db, insertDelivery, 3, 2, "hook", "escalate to hook", []byte(`{"text":"escalate"}`), "given-up", 1, t0+minute, t0+2*minute, "status 404", t0+2*minute)
		beaExec(t, db, "INSERT INTO check_state VALUES (?, ?), (?, ?)", www.String(), t0-minute, mail.String(), t0+5*minute)
	})
}

func beaBeat(t *testing.T, s *Store, at time.Time) {
	t.Helper()
	if err := s.Beat(at, nil); err != nil {
		t.Fatalf("Beat(%v): %v", at, err)
	}
}

func beaLastBeat(t *testing.T, s *Store) time.Time {
	t.Helper()
	at, err := s.LastBeat()
	if err != nil {
		t.Fatalf("LastBeat: %v", err)
	}
	return at
}

func TestNewStoreHasSchemaVersion3WithTheBeatTable(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	if v := beaVersion(t, s.db); v != 3 {
		t.Errorf("a new store has user_version %d, want 3", v)
	}
	if got := beaNames(t, s.db); got != beaNamesV3 {
		t.Errorf("a new store holds\n%s\nwant\n%s", got, beaNamesV3)
	}
	if got := beaBeatTable(t, s.db); got != beaBeatTableV3 {
		t.Errorf("the beat table of a new store:\n%s\nwant\n%s", got, beaBeatTableV3)
	}
}

// After a restart the service must find its open alerts, its pending
// deliveries and the clean time of each check in a store of version 1.
func TestVersion1StoreIsMigratedToVersion3AndKeepsEveryRow(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "state.db")
	beaMakeVersion1(t, path)
	var before string
	beaWithFile(t, path, func(db *sql.DB) { before = beaRows(t, db) })

	s := stoOpen(t, dir)
	if v := beaVersion(t, s.db); v != 3 {
		t.Errorf("the migrated store has user_version %d, want 3", v)
	}
	if got := beaNames(t, s.db); got != beaNamesV3 {
		t.Errorf("the migrated store holds\n%s\nwant\n%s", got, beaNamesV3)
	}
	if got := beaBeatTable(t, s.db); got != beaBeatTableV3 {
		t.Errorf("the beat table of the migrated store:\n%s\nwant\n%s", got, beaBeatTableV3)
	}
	if got := beaRows(t, s.db); got != before {
		t.Errorf("rows after the migration:\n%s\nwant the rows before it:\n%s", got, before)
	}

	if got := stoOpenAlerts(t, s, stoWWW(t)); len(got) != 1 || got[0].ID != 1 || got[0].Severity != decide.SeverityCritical {
		t.Errorf("OpenAlerts gives %d alerts, want only the open critical alert 1", len(got))
	}
	if got, err := s.LastClean(stoMail(t)); err != nil || !got.Equal(stoT0.Add(5*time.Minute)) {
		t.Errorf("LastClean of mail = %v, %v; want %v", got, err, stoT0.Add(5*time.Minute))
	}
	if got := stoRowIDs(stoDue(t, s, "slack", stoT0.Add(2*time.Minute))); !slices.Equal(got, []int64{2}) {
		t.Errorf("Due gives rows %v, want the pending row 2", got)
	}
	if got, err := s.LastBeat(); err != nil || !got.IsZero() {
		t.Errorf("LastBeat of the migrated store = %v, %v; want the zero time", got, err)
	}
	beaBeat(t, s, stoT0)
	if got := beaLastBeat(t, s); !got.Equal(stoT0) {
		t.Errorf("LastBeat after Beat(%v) = %v", stoT0, got)
	}
}

// SQLite refuses a table whose name an index already has, also with IF NOT
// EXISTS, so this migration must fail and must leave nothing of itself.
func TestFailedMigrationLeavesVersion1StoreAsItWas(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "state.db")
	beaMakeVersion1(t, path)
	beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, "CREATE INDEX beat ON check_state (last_clean)") })
	before := beaFile(t, path)

	s, err := Open(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "store: ") {
		t.Errorf("Open of a store whose migration fails: %v, want an error that starts with \"store: \"", err)
		if err == nil {
			_ = s.Close()
		}
	}
	if after := beaFile(t, path); after != before {
		t.Errorf("after the failed migration:\n%s\nwant the store as it was:\n%s", after, before)
	}

	// The planted index was the only fault, and the failed Open let the
	// folder go.
	beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, "DROP INDEX beat") })
	s = stoOpen(t, dir)
	if v := beaVersion(t, s.db); v != 3 {
		t.Errorf("without the planted index the store has user_version %d, want 3", v)
	}
}

// A database of another program has user_version 0, as an empty one has,
// but it holds tables; the store's tables must not be added to it.
func TestForeignDatabaseOfVersion0IsRefusedAndLeftAsItIs(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "state.db")
	beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, "CREATE TABLE other (x INTEGER)") })
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir)
	if want := "store: " + path + " is not a store of this osk-dns-watcher (schema 0)"; err == nil || err.Error() != want {
		t.Errorf("Open of a foreign database of version 0: %v, want error %q", err, want)
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

func TestLastBeatIsZeroWhenNoBeatWasStored(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	if got, err := s.LastBeat(); err != nil || !got.IsZero() {
		t.Errorf("LastBeat of a new store = %v, %v; want the zero time and no error", got, err)
	}
}

// The beat is given in another zone and with nanoseconds; it is kept as
// Unix nanoseconds and comes back as the same instant in UTC, as the other
// times of the store do.
func TestBeatComesBackAsTheSameInstantInUTC(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	at := stoT0.In(stoZone)
	beaBeat(t, s, at)
	if got := beaLastBeat(t, s); !got.Equal(at) || got.Location() != time.UTC {
		t.Errorf("LastBeat after Beat(%v) = %v, want the same instant in UTC", at, got)
	}
	var id, stored int64
	if err := s.db.QueryRow("SELECT id, at FROM beat").Scan(&id, &stored); err != nil {
		t.Fatal(err)
	}
	if id != 1 || stored != at.UnixNano() {
		t.Errorf("the beat row is (%d, %d), want (1, %d)", id, stored, at.UnixNano())
	}
}

// The last beat written is the one kept, also when its time is earlier:
// after the clock stepped back, a beat ahead of it would hide a down time.
func TestSecondBeatReplacesTheFirst(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	for _, at := range []time.Time{stoT0, stoT0.Add(10 * time.Second), stoT0.Add(-time.Hour)} {
		beaBeat(t, s, at)
		if got := beaLastBeat(t, s); !got.Equal(at) {
			t.Errorf("LastBeat after Beat(%v) = %v", at, got)
		}
	}
	var n int
	if err := s.db.QueryRow("SELECT count(*) FROM beat").Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("the beat table holds %d rows after three beats, want 1", n)
	}
}

func TestBeatSurvivesCloseAndOpen(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	beaBeat(t, s, stoT0)
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s = stoOpen(t, dir)
	if got := beaLastBeat(t, s); !got.Equal(stoT0) {
		t.Errorf("LastBeat after Close and Open = %v, want %v", got, stoT0)
	}
	if v := beaVersion(t, s.db); v != 3 {
		t.Errorf("the store opened again has user_version %d, want 3", v)
	}
}

// Planted triggers make the write of a beat fail, whether it inserts the
// row or updates it.
func TestFailedBeatIsReportedAndKeepsTheBeatBefore(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	beaBeat(t, s, stoT0)
	stoExec(t, s, "CREATE TRIGGER bea_insert BEFORE INSERT ON beat BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
	stoExec(t, s, "CREATE TRIGGER bea_update BEFORE UPDATE ON beat BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
	err := s.Beat(stoT0.Add(10*time.Second), nil)
	if err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), "planted fault") {
		t.Errorf("Beat: %v, want an error that starts with \"store: \" and holds the planted fault", err)
	}
	if got := beaLastBeat(t, s); !got.Equal(stoT0) {
		t.Errorf("LastBeat after the failed Beat = %v, want the beat before it, %v", got, stoT0)
	}
}

// Only a store with no beat gives the zero time; a beat that cannot be read
// is an error, or the service would report no down time.
func TestLastBeatReportsAReadError(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	stoExec(t, s, "DROP TABLE beat")
	if got, err := s.LastBeat(); err == nil || !strings.HasPrefix(err.Error(), "store: ") {
		t.Errorf("LastBeat without a beat table = %v, %v; want an error that starts with \"store: \"", got, err)
	}
}
