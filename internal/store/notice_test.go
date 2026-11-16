package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// ntcVersion3 is the schema that every store of version 3 must have, new or
// migrated. The tests compare its shape, not its text, so the store may
// write it in its own words.
const ntcVersion3 = `
CREATE TABLE alert (id INTEGER PRIMARY KEY, open INTEGER NOT NULL CHECK (open IN (0, 1)),
  rule INTEGER NOT NULL, check_key TEXT NOT NULL, kind INTEGER NOT NULL, domain TEXT NOT NULL,
  name TEXT NOT NULL, type INTEGER NOT NULL, severity INTEGER NOT NULL, peak INTEGER NOT NULL,
  expected TEXT NOT NULL, value TEXT NOT NULL, lines TEXT NOT NULL, opened INTEGER NOT NULL,
  last_clean INTEGER NOT NULL, noticed INTEGER NOT NULL, resolved INTEGER NOT NULL) STRICT;
CREATE UNIQUE INDEX alert_open ON alert (check_key, rule) WHERE open = 1;
CREATE TABLE event (id INTEGER PRIMARY KEY, alert INTEGER NOT NULL REFERENCES alert (id),
  kind TEXT NOT NULL CHECK (kind IN ('open','update','escalate','reminder','resolve','given-up')),
  severity INTEGER NOT NULL, was INTEGER NOT NULL, value TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE notice (id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('test','down','expectations')),
  domain TEXT NOT NULL, lines TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE delivery (id INTEGER PRIMARY KEY, event INTEGER REFERENCES event (id), notice INTEGER REFERENCES notice (id),
  channel TEXT NOT NULL CHECK (channel <> ''), label TEXT NOT NULL, body BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','sent','given-up')), attempts INTEGER NOT NULL,
  created INTEGER NOT NULL, next_at INTEGER NOT NULL, reason TEXT NOT NULL, done_at INTEGER NOT NULL,
  CHECK ((event IS NULL) <> (notice IS NULL))) STRICT;
CREATE INDEX delivery_due ON delivery (channel, next_at) WHERE state = 'pending';
CREATE INDEX delivery_event ON delivery (event);
CREATE INDEX delivery_notice ON delivery (notice);
CREATE TABLE check_state (check_key TEXT PRIMARY KEY, last_clean INTEGER NOT NULL) STRICT;
CREATE TABLE beat (id INTEGER PRIMARY KEY CHECK (id = 1), at INTEGER NOT NULL, late TEXT NOT NULL DEFAULT '') STRICT;
CREATE TABLE loaded (domain TEXT PRIMARY KEY, text TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
PRAGMA user_version = 3;
`

// ntcRulesV3 is what ntcRules gives for a store of version 3.
const ntcRulesV3 = `a notice of kind test: taken
a notice of kind down: taken
a notice of kind expectations: taken
a notice of kind other: refused
a row of an event: taken
a row of a notice: taken
a row of neither: refused
a row of both: refused
a row of an event that does not exist: refused
a row of a notice that does not exist: refused
a row with no channel: refused
a row in a state that does not exist: refused
a second text of one domain: refused
`

// ntcTables are the tables of version 3.
var ntcTables = []string{"alert", "event", "delivery", "check_state", "notice", "loaded", "beat"}

// ntcBeatV2 is the beat that ntcMakeVersion2 stores.
var ntcBeatV2 = stoT0.Add(-time.Minute)

// ntcStrings gives the one text column of each row of query.
func ntcStrings(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	// Frees the store's one connection when a scan fails.
	defer func() { _ = rows.Close() }()
	var out []string
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

// ntcTable gives each row of query as its columns joined by a space. Texts
// and blobs are quoted, so that an empty text shows.
func ntcTable(t *testing.T, db *sql.DB, query string, args ...any) []string {
	t.Helper()
	rows, err := db.Query(query, args...)
	if err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	defer func() { _ = rows.Close() }()
	cols, err := rows.Columns()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for rows.Next() {
		values := make([]any, len(cols))
		dest := make([]any, len(cols))
		for i := range values {
			dest[i] = &values[i]
		}
		if err := rows.Scan(dest...); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
		parts := make([]string, len(values))
		for i, v := range values {
			switch v := v.(type) {
			case nil:
				parts[i] = "NULL"
			case string:
				parts[i] = strconv.Quote(v)
			case []byte:
				parts[i] = strconv.Quote(string(v))
			default:
				parts[i] = fmt.Sprint(v)
			}
		}
		out = append(out, strings.Join(parts, " "))
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return out
}

// ntcIDs gives the ids that query selects.
func ntcIDs(t *testing.T, db *sql.DB, query string, args ...any) []int64 {
	t.Helper()
	var ids []int64
	for _, s := range ntcTable(t, db, query, args...) {
		id, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			t.Fatalf("%s gives %q, want an id", query, s)
		}
		ids = append(ids, id)
	}
	return ids
}

// ntcDump gives every row of every table of version 3.
func ntcDump(t *testing.T, db *sql.DB) string {
	t.Helper()
	var b strings.Builder
	for _, table := range ntcTables {
		for _, row := range ntcTable(t, db, "SELECT * FROM "+table+" ORDER BY rowid") {
			fmt.Fprintf(&b, "%s %s\n", table, row)
		}
	}
	return b.String()
}

// ntcCounts gives the number of rows of each table of version 3.
func ntcCounts(t *testing.T, db *sql.DB) string {
	t.Helper()
	var parts []string
	for _, table := range ntcTables {
		var n int
		if err := db.QueryRow("SELECT count(*) FROM " + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		parts = append(parts, fmt.Sprintf("%s %d", table, n))
	}
	return strings.Join(parts, ", ")
}

// ntcShape describes each table and index of db: the columns with their
// type, NOT NULL, default and key, whether the table is strict, its foreign
// keys, and each index with its columns and its unique and partial flags.
// CHECK rules have no pragma; ntcRules tries them.
func ntcShape(t *testing.T, db *sql.DB) string {
	t.Helper()
	var b strings.Builder
	fmt.Fprintf(&b, "user_version %d\n", beaVersion(t, db))
	tables := ntcStrings(t, db, "SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name")
	for _, table := range tables {
		strict := ntcStrings(t, db, "SELECT strict FROM pragma_table_list WHERE schema = 'main' AND name = ?", table)
		fmt.Fprintf(&b, "table %s strict %s\n", table, strict)
		for _, c := range ntcStrings(t, db, `SELECT name || ' ' || type || ' notnull ' || "notnull" || ' default ' ||
			coalesce(dflt_value, '-') || ' pk ' || pk FROM pragma_table_info(?) ORDER BY cid`, table) {
			fmt.Fprintf(&b, "  column %s\n", c)
		}
		for _, f := range ntcStrings(t, db, `SELECT "from" || ' references ' || "table" || ' (' || coalesce("to", '') || ')'
			FROM pragma_foreign_key_list(?) ORDER BY "from"`, table) {
			fmt.Fprintf(&b, "  foreign key %s\n", f)
		}
		for _, index := range ntcStrings(t, db, "SELECT name FROM pragma_index_list(?) WHERE origin = 'c' ORDER BY name", table) {
			flags := ntcStrings(t, db, `SELECT 'unique ' || "unique" || ' partial ' || partial FROM pragma_index_list(?) WHERE name = ?`, table, index)
			cols := ntcStrings(t, db, "SELECT name FROM pragma_index_info(?) ORDER BY seqno", index)
			fmt.Fprintf(&b, "  index %s on (%s) %s\n", index, strings.Join(cols, ", "), strings.Join(flags, ""))
		}
	}
	return b.String()
}

// ntcReferenceShape is the shape of ntcVersion3, made in a database of its
// own.
func ntcReferenceShape(t *testing.T) string {
	t.Helper()
	var shape string
	beaWithFile(t, filepath.Join(t.TempDir(), "reference.db"), func(db *sql.DB) {
		beaExec(t, db, ntcVersion3)
		shape = ntcShape(t, db)
	})
	return shape
}

// ntcRules tries rows that the CHECK and key rules of version 3 take or
// refuse, inside a transaction that it rolls back, and tells each answer.
func ntcRules(t *testing.T, db *sql.DB) string {
	t.Helper()
	tx, err := db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	// Only the answers count; no row of the trial may stay.
	defer func() { _ = tx.Rollback() }()
	for _, query := range []string{
		`INSERT INTO alert (id, open, rule, check_key, kind, domain, name, type, severity, peak, expected, value, lines,
			opened, last_clean, noticed, resolved) VALUES (9001, 0, 5, 'ntc', 3, 'corp.test.', 'ntc.corp.test.', 1, 2, 2, '', '', '[]', 1, 0, 1, 2)`,
		"INSERT INTO event (id, alert, kind, severity, was, value, at) VALUES (9001, 9001, 'open', 2, 2, '', 1)",
	} {
		if _, err := tx.Exec(query); err != nil {
			t.Fatalf("%s: %v", query, err)
		}
	}
	var b strings.Builder
	try := func(what, query string, args ...any) {
		answer := "taken"
		if _, err := tx.Exec(query, args...); err != nil {
			answer = "refused"
		}
		fmt.Fprintf(&b, "%s: %s\n", what, answer)
	}
	for i, kind := range []string{"test", "down", "expectations", "other"} {
		try("a notice of kind "+kind, "INSERT INTO notice (id, kind, domain, lines, at) VALUES (?, ?, '', '[]', 1)", 9001+i, kind)
	}
	row := `INSERT INTO delivery (event, notice, channel, label, body, state, attempts, created, next_at, reason, done_at)
		VALUES (?, ?, ?, 'label', x'7b7d', ?, 0, 1, 1, '', 0)`
	try("a row of an event", row, 9001, nil, "slack", "pending")
	try("a row of a notice", row, nil, 9001, "slack", "pending")
	try("a row of neither", row, nil, nil, "slack", "pending")
	try("a row of both", row, 9001, 9001, "slack", "pending")
	try("a row of an event that does not exist", row, 99999, nil, "slack", "pending")
	try("a row of a notice that does not exist", row, nil, 99999, "slack", "pending")
	try("a row with no channel", row, 9001, nil, "", "pending")
	try("a row in a state that does not exist", row, 9001, nil, "slack", "done")
	try("a second text of one domain", "INSERT INTO loaded (domain, text, at) VALUES ('ntc.test.', 'a', 1), ('ntc.test.', 'b', 1)")
	return b.String()
}

// ntcMakeVersion2 writes a store of version 2 at path: the rows of
// beaMakeVersion1, then the beat table of version 2 with a beat.
func ntcMakeVersion2(t *testing.T, path string) {
	t.Helper()
	beaMakeVersion1(t, path)
	beaWithFile(t, path, func(db *sql.DB) {
		beaExec(t, db, "CREATE TABLE beat (id INTEGER PRIMARY KEY CHECK (id = 1), at INTEGER NOT NULL) STRICT")
		beaExec(t, db, "INSERT INTO beat VALUES (1, ?)", ntcBeatV2.UnixNano())
		beaExec(t, db, "PRAGMA user_version = 2")
	})
}

func ntcBeatRows(t *testing.T, db *sql.DB) string {
	t.Helper()
	return fmt.Sprintf("beat %q\n", ntcTable(t, db, "SELECT id, at FROM beat"))
}

// ntcFile gives what beaFile gives, and the beat.
func ntcFile(t *testing.T, path string) string {
	t.Helper()
	text := beaFile(t, path)
	beaWithFile(t, path, func(db *sql.DB) { text += ntcBeatRows(t, db) })
	return text
}

func ntcNotify(t *testing.T, s *Store, n Notice, deliveries ...Delivery) {
	t.Helper()
	if err := s.Notify(n, deliveries); err != nil {
		t.Fatalf("Notify(%s at %v): %v", n.Kind, n.At, err)
	}
}

// ntcRowsTo is one delivery to each channel.
func ntcRowsTo(channels ...string) []Delivery {
	var out []Delivery
	for _, c := range channels {
		out = append(out, Delivery{Channel: c, Label: "notice to " + c, Body: []byte(`{"to":"` + c + `"}`)})
	}
	return out
}

func ntcReload(t *testing.T, s *Store, domain, text string, n *Notice, deliveries []Delivery, closed ...Write) {
	t.Helper()
	if err := s.Reload(domain, text, n, deliveries, closed); err != nil {
		t.Fatalf("Reload(%s): %v", domain, err)
	}
}

func ntcLoaded(t *testing.T, s *Store) map[string]string {
	t.Helper()
	got, err := s.Loaded()
	if err != nil {
		t.Fatalf("Loaded: %v", err)
	}
	return got
}

// ntcClose is the write that ends the stored alert a at now because its
// check left the file: a resolve with no delivery.
func ntcClose(t *testing.T, a alert.Alert, now time.Time) Write {
	t.Helper()
	out := alert.Transition(alert.Input{
		Open:    []alert.Alert{a},
		Changes: []decide.Change{{Op: decide.OpResolve, Finding: a.Finding(), At: now}},
		Now:     now,
	})
	if len(out.Events) != 1 || out.Events[0].Kind != alert.EventResolve {
		t.Fatalf("Transition of a resolve of alert %d gives %d events, want one resolve", a.ID, len(out.Events))
	}
	return Write{Event: out.Events[0]}
}

func ntcAllOpen(t *testing.T, s *Store) []alert.Alert {
	t.Helper()
	got, err := s.AllOpenAlerts()
	if err != nil {
		t.Fatalf("AllOpenAlerts: %v", err)
	}
	return got
}

func TestNewStoreHasTheShapeAndRulesOfVersion3(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	if got, want := ntcShape(t, s.db), ntcReferenceShape(t); got != want {
		t.Errorf("a new store has the shape\n%s\nwant\n%s", got, want)
	}
	if got := ntcRules(t, s.db); got != ntcRulesV3 {
		t.Errorf("the rules of a new store:\n%s\nwant\n%s", got, ntcRulesV3)
	}
}

// A store of version 2 holds the alerts, events, rows, clean times and beat
// of a service. After the migration each one is there with the same values,
// and the store has the shape and the rules of a new store of version 3.
func TestVersion2StoreIsMigratedToVersion3AndKeepsEveryRow(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "osk.db")
	ntcMakeVersion2(t, path)
	var before string
	beaWithFile(t, path, func(db *sql.DB) { before = beaRows(t, db) + ntcBeatRows(t, db) })
	want := ntcReferenceShape(t)

	s := stoOpen(t, dir)
	if got := ntcShape(t, s.db); got != want {
		t.Errorf("the migrated store has the shape\n%s\nwant\n%s", got, want)
	}
	if got := ntcRules(t, s.db); got != ntcRulesV3 {
		t.Errorf("the rules of the migrated store:\n%s\nwant\n%s", got, ntcRulesV3)
	}
	if got := beaRows(t, s.db) + ntcBeatRows(t, s.db); got != before {
		t.Errorf("rows after the migration:\n%s\nwant the rows before it:\n%s", got, before)
	}
	if got := ntcTable(t, s.db, "SELECT id FROM delivery WHERE notice IS NOT NULL"); len(got) != 0 {
		t.Errorf("rows %q of the migrated store name a notice, want none", got)
	}

	// The service goes on with the migrated rows, and the new tables take
	// rows at once.
	if got := stoOpenAlerts(t, s, stoWWW(t)); len(got) != 1 || got[0].ID != 1 {
		t.Errorf("OpenAlerts gives %d alerts, want only the open alert 1", len(got))
	}
	if got := beaLastBeat(t, s); !got.Equal(ntcBeatV2) {
		t.Errorf("LastBeat of the migrated store = %v, want %v", got, ntcBeatV2)
	}
	ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc"}, At: stoT0.Add(3 * time.Minute)}, ntcRowsTo("slack")...)
	if got := stoRowIDs(stoDue(t, s, "slack", stoT0.Add(3*time.Minute))); !slices.Equal(got, []int64{2, 4}) {
		t.Errorf("Due gives rows %v, want the migrated pending row 2 and the notice's row 4", got)
	}
	ntcReload(t, s, "corp.test.", "domain corp.test.\n", nil, nil)
	if got, err := s.Health(stoT0, nil); err != nil || !got.Beat.Equal(ntcBeatV2) || len(got.Late) != 0 {
		t.Errorf("Health of the migrated store = %+v, %v; want its beat and no late check", got, err)
	}
}

// The migration is one transaction: a planted object makes one statement
// of it fail, and the store stays as it was, rows, schema and version.
// Without the planted object the next Open migrates it.
func TestFailedMigrationLeavesVersion2StoreAsItWas(t *testing.T) {
	for _, c := range []struct{ name, plant, remove string }{
		{"an index with the name of the notice table", "CREATE INDEX notice ON check_state (last_clean)", "DROP INDEX notice"},
		{"a table with the name of the notice index", "CREATE TABLE delivery_notice (x INTEGER)", "DROP TABLE delivery_notice"},
		{"a late column already in the beat table", "ALTER TABLE beat ADD COLUMN late TEXT", "ALTER TABLE beat DROP COLUMN late"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := stoDir(t)
			path := filepath.Join(dir, "osk.db")
			ntcMakeVersion2(t, path)
			beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, c.plant) })
			before := ntcFile(t, path)

			s, err := Open(dir)
			if err == nil || !strings.HasPrefix(err.Error(), "store: ") {
				t.Errorf("Open of a store whose migration fails: %v, want an error that starts with \"store: \"", err)
				if err == nil {
					_ = s.Close()
				}
			}
			if after := ntcFile(t, path); after != before {
				t.Errorf("after the failed migration:\n%s\nwant the store as it was:\n%s", after, before)
			}

			beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, c.remove) })
			s = stoOpen(t, dir)
			if v := beaVersion(t, s.db); v != 3 {
				t.Errorf("without the planted object the store has user_version %d, want 3", v)
			}
		})
	}
}

// Each upgrade is its own transaction: a store of version 1 whose upgrade
// from 2 to 3 fails is left at version 2, with every row.
func TestVersion1StoreWhoseUpgradeTo3FailsStaysAtVersion2(t *testing.T) {
	dir := stoDir(t)
	path := filepath.Join(dir, "osk.db")
	beaMakeVersion1(t, path)
	beaWithFile(t, path, func(db *sql.DB) { beaExec(t, db, "CREATE TABLE delivery_notice (x INTEGER)") })
	var before string
	beaWithFile(t, path, func(db *sql.DB) { before = beaRows(t, db) })

	s, err := Open(dir)
	if err == nil || !strings.HasPrefix(err.Error(), "store: ") {
		t.Errorf("Open of a store whose upgrade to version 3 fails: %v, want an error that starts with \"store: \"", err)
		if err == nil {
			_ = s.Close()
		}
	}
	const beatV2 = "id INTEGER notnull 0 pk 1\nat INTEGER notnull 1 pk 0\nstrict 1\na row with id 2 is refused true\n"
	beaWithFile(t, path, func(db *sql.DB) {
		if v := beaVersion(t, db); v != 2 {
			t.Errorf("the store has user_version %d, want 2", v)
		}
		if got := beaBeatTable(t, db); got != beatV2 {
			t.Errorf("the beat table:\n%s\nwant that of version 2:\n%s", got, beatV2)
		}
		if got := ntcStrings(t, db, "SELECT name FROM sqlite_schema WHERE name IN ('notice', 'loaded', 'delivery_event')"); len(got) != 0 {
			t.Errorf("the store holds %q of version 3, want none", got)
		}
		if got := beaRows(t, db); got != before {
			t.Errorf("rows after the failed upgrade:\n%s\nwant\n%s", got, before)
		}
	})
}

func TestNotifyWritesTheNoticeAndOneRowPerDelivery(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	at := stoT0.In(stoZone)
	lines := []string{"- www.corp.test. A 10.53.0.81", `+ txt.corp.test. TXT "a \"b\" <c> & d"`}
	ntcNotify(t, s, Notice{Kind: NoticeExpectations, Domain: "corp.test.", Lines: lines, At: at}, ntcRowsTo("slack", "hook")...)
	ntcNotify(t, s, Notice{Kind: NoticeTest, At: at.Add(time.Second)})

	got := ntcTable(t, s.db, "SELECT id, kind, domain, at FROM notice ORDER BY id")
	want := []string{
		fmt.Sprintf(`1 "expectations" "corp.test." %d`, at.UnixNano()),
		fmt.Sprintf(`2 "test" "" %d`, at.Add(time.Second).UnixNano()),
	}
	if !slices.Equal(got, want) {
		t.Errorf("notice rows\n got %q\nwant %q", got, want)
	}
	for id, want := range map[int64][]string{1: lines, 2: {}} {
		var text string
		if err := s.db.QueryRow("SELECT lines FROM notice WHERE id = ?", id).Scan(&text); err != nil {
			t.Fatal(err)
		}
		var got []string
		if err := json.Unmarshal([]byte(text), &got); err != nil || got == nil || !slices.Equal(got, want) {
			t.Errorf("lines of notice %d are %s, want a JSON array of %q", id, text, want)
		}
	}

	// The time of a notice's rows is its own: Notify has no other.
	n := at.UnixNano()
	got = ntcTable(t, s.db, "SELECT id, event, notice, channel, label, body, state, attempts, created, next_at, reason, done_at FROM delivery ORDER BY id")
	want = []string{
		fmt.Sprintf(`1 NULL 1 "slack" "notice to slack" "{\"to\":\"slack\"}" "pending" 0 %d %d "" 0`, n, n),
		fmt.Sprintf(`2 NULL 1 "hook" "notice to hook" "{\"to\":\"hook\"}" "pending" 0 %d %d "" 0`, n, n),
	}
	if !slices.Equal(got, want) {
		t.Errorf("delivery rows\n got %q\nwant %q", got, want)
	}
	if rows := stoDue(t, s, "hook", at); len(rows) != 1 || rows[0].Label != "notice to hook" || string(rows[0].Body) != `{"to":"hook"}` {
		t.Errorf("Due(hook) gives %+v, want the notice's row with its label and body", rows)
	}
}

// A fault in any statement of Notify, or a kind that the store refuses,
// leaves no notice and no row: the notice is sent to all or to none.
func TestNotifyWritesNothingWhenAPartFails(t *testing.T) {
	for _, c := range []struct {
		name, trigger string
		kind          NoticeKind
	}{
		{"the notice", "BEFORE INSERT ON notice", NoticeDown},
		{"the last row", "BEFORE INSERT ON delivery WHEN NEW.channel = 'hook'", NoticeDown},
		{"a kind the store does not know", "", "other"},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := stoOpen(t, stoDir(t))
			ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc"}, At: stoT0}, ntcRowsTo("slack")...)
			before := ntcDump(t, s.db)
			if c.trigger != "" {
				stoExec(t, s, "CREATE TRIGGER ntc_fault "+c.trigger+" BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
			}
			n := Notice{Kind: c.kind, Lines: []string{"last beat 2026-11-11 11:00:00 UTC", "started   2026-11-11 12:00:00 UTC"}, At: stoT0.Add(time.Hour)}
			err := s.Notify(n, ntcRowsTo("slack", "hook"))
			if err == nil || !strings.HasPrefix(err.Error(), "store: ") || (c.trigger != "" && !strings.Contains(err.Error(), "planted fault")) {
				t.Errorf("Notify: %v, want an error that starts with \"store: \" and names the fault", err)
			}
			if after := ntcDump(t, s.db); after != before {
				t.Errorf("after the failed Notify:\n%s\nwant\n%s", after, before)
			}
			if c.trigger == "" {
				return
			}
			stoExec(t, s, "DROP TRIGGER ntc_fault")
			ntcNotify(t, s, n, ntcRowsTo("slack", "hook")...)
			if got, want := ntcCounts(t, s.db), "alert 0, event 0, delivery 3, check_state 0, notice 2, loaded 0, beat 0"; got != want {
				t.Errorf("after the same Notify without the fault: %s, want %s", got, want)
			}
		})
	}
}

// A row of a notice has no event, so the given-up event that Record adds
// for a row of an alert has no alert to go on; the row still ends.
func TestRecordOfANoticeRowAddsNoEvent(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc"}, At: stoT0}, ntcRowsTo("slack", "hook")...)
	ids := ntcIDs(t, s.db, "SELECT id FROM delivery ORDER BY id")
	if len(ids) != 2 {
		t.Fatalf("rows %v, want 2", ids)
	}
	at := stoT0.Add(time.Second)
	if err := s.Record(ids[0], Done{State: RowGivenUp, Attempts: 1, Reason: "status 404", At: at}); err != nil {
		t.Errorf("Record given-up of a notice row: %v", err)
	}
	if err := s.Record(ids[1], Done{State: RowSent, Attempts: 1, At: at}); err != nil {
		t.Errorf("Record sent of a notice row: %v", err)
	}
	got := ntcTable(t, s.db, "SELECT state, reason, done_at FROM delivery ORDER BY id")
	want := []string{fmt.Sprintf(`"given-up" "status 404" %d`, at.UnixNano()), fmt.Sprintf(`"sent" "" %d`, at.UnixNano())}
	if !slices.Equal(got, want) {
		t.Errorf("rows after Record\n got %q\nwant %q", got, want)
	}
	if got := ntcCounts(t, s.db); !strings.HasPrefix(got, "alert 0, event 0,") {
		t.Errorf("after Record of notice rows: %s, want no alert and no event", got)
	}
}

func TestLoadedGivesTheLastTextOfEachDomain(t *testing.T) {
	dir := stoDir(t)
	s := stoOpen(t, dir)
	if got := ntcLoaded(t, s); len(got) != 0 {
		t.Errorf("Loaded of a new store = %q, want nothing", got)
	}
	corp1 := "domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\n"
	corp2 := corp1 + "www.corp.test. A 10.53.0.81\n"
	shop := "domain shop.test.\nshop.test. DS none\n"
	ntcReload(t, s, "corp.test.", corp1, nil, nil)
	ntcReload(t, s, "shop.test.", shop, nil, nil)
	ntcReload(t, s, "corp.test.", corp2, nil, nil)
	want := map[string]string{"corp.test.": corp2, "shop.test.": shop}
	if got := ntcLoaded(t, s); !maps.Equal(got, want) {
		t.Errorf("Loaded = %q, want %q", got, want)
	}

	// The empty text is a domain that left the config.
	ntcReload(t, s, "shop.test.", "", nil, nil)
	delete(want, "shop.test.")
	if got := ntcLoaded(t, s); !maps.Equal(got, want) {
		t.Errorf("Loaded after the empty text of shop.test. = %q, want %q", got, want)
	}
	if got := ntcCounts(t, s.db); !strings.Contains(got, "loaded 1,") {
		t.Errorf("after three texts of two domains and one removal: %s, want one loaded row", got)
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	s = stoOpen(t, dir)
	if got := ntcLoaded(t, s); !maps.Equal(got, want) {
		t.Errorf("Loaded after Close and Open = %q, want %q", got, want)
	}
}

// ntcReloadSetup is a store that holds an old text of corp.test., two open
// alerts (www with a row to slack, mail), the clean time of www, and the
// notice and close that a change of the file makes for www.
func ntcReloadSetup(t *testing.T) (*Store, Notice, []Write) {
	t.Helper()
	s := stoOpen(t, stoDir(t))
	www, mail := stoWWW(t), stoMail(t)
	stoApply(t, s, www, true, stoT0)
	opened := stoT0.Add(time.Minute)
	stoApply(t, s, www, false, opened, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, www, "10.53.0.99"), decide.SeverityHigh, opened, "slack"))
	stoApply(t, s, mail, false, opened, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, mail, "10.53.0.99"), decide.SeverityHigh, opened))
	ntcReload(t, s, "corp.test.", "old text\n", nil, nil)
	now := stoT0.Add(time.Hour)
	n := Notice{Kind: NoticeExpectations, Domain: "corp.test.", At: now,
		Lines: []string{"- www.corp.test. A 10.53.0.81", "closed high record-set records www.corp.test. A"}}
	return s, n, []Write{ntcClose(t, stoNth(t, s, www, 1, 0), now)}
}

func TestReloadWritesTextNoticeRowsAndClosesTogether(t *testing.T) {
	s, n, closed := ntcReloadSetup(t)
	ntcReload(t, s, "corp.test.", "new text\n", &n, ntcRowsTo("slack", "hook"), closed...)
	at := n.At.UnixNano()

	for _, c := range []struct {
		query string
		want  []string
	}{
		{"SELECT domain, text, at FROM loaded", []string{fmt.Sprintf("%q %q %d", "corp.test.", "new text\n", at)}},
		{"SELECT id, kind, domain, at FROM notice", []string{fmt.Sprintf(`1 "expectations" "corp.test." %d`, at)}},
		// The open row of www stays; the notice has one row per delivery
		// and the close has none: the notice tells of it.
		{"SELECT id, event, notice, channel, state FROM delivery ORDER BY id",
			[]string{`1 1 NULL "slack" "pending"`, `2 NULL 1 "slack" "pending"`, `3 NULL 1 "hook" "pending"`}},
		{"SELECT id, alert, kind, at FROM event ORDER BY id", []string{
			fmt.Sprintf(`1 1 "open" %d`, stoT0.Add(time.Minute).UnixNano()),
			fmt.Sprintf(`2 2 "open" %d`, stoT0.Add(time.Minute).UnixNano()),
			fmt.Sprintf(`3 1 "resolve" %d`, at)}},
		{"SELECT id, open, resolved FROM alert ORDER BY id", []string{fmt.Sprintf("1 0 %d", at), "2 1 0"}},
		{"SELECT check_key, last_clean FROM check_state", []string{fmt.Sprintf("%q %d", stoWWW(t).String(), stoT0.UnixNano())}},
	} {
		if got := ntcTable(t, s.db, c.query); !slices.Equal(got, c.want) {
			t.Errorf("%s\n got %q\nwant %q", c.query, got, c.want)
		}
	}
	if got := ntcLoaded(t, s); !maps.Equal(got, map[string]string{"corp.test.": "new text\n"}) {
		t.Errorf("Loaded = %q, want the new text", got)
	}
}

// Each statement of Reload, made to fail by a planted trigger, leaves the
// store as it was: the text, the notice, its rows and the closes are one
// transaction.
func TestReloadWritesNothingWhenAPartFails(t *testing.T) {
	for _, c := range []struct {
		name     string
		text     string
		triggers []string
	}{
		{"the new text", "new text\n", []string{"BEFORE INSERT ON loaded", "BEFORE UPDATE ON loaded"}},
		{"the removal of the text", "", []string{"BEFORE DELETE ON loaded"}},
		{"the notice", "new text\n", []string{"BEFORE INSERT ON notice"}},
		{"the last row", "new text\n", []string{"BEFORE INSERT ON delivery WHEN NEW.channel = 'hook'"}},
		{"the close of the alert", "new text\n", []string{"BEFORE UPDATE ON alert"}},
		{"the event of the close", "new text\n", []string{"BEFORE INSERT ON event"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s, n, closed := ntcReloadSetup(t)
			before := ntcDump(t, s.db)
			for i, trigger := range c.triggers {
				stoExec(t, s, fmt.Sprintf("CREATE TRIGGER ntc_fault%d %s BEGIN SELECT RAISE(ABORT, 'planted fault'); END", i, trigger))
			}
			err := s.Reload("corp.test.", c.text, &n, ntcRowsTo("slack", "hook"), closed)
			if err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), "planted fault") {
				t.Errorf("Reload: %v, want an error that starts with \"store: \" and holds the planted fault", err)
			}
			if after := ntcDump(t, s.db); after != before {
				t.Errorf("after the failed Reload:\n%s\nwant\n%s", after, before)
			}

			for i := range c.triggers {
				stoExec(t, s, fmt.Sprintf("DROP TRIGGER ntc_fault%d", i))
			}
			ntcReload(t, s, "corp.test.", c.text, &n, ntcRowsTo("slack", "hook"), closed...)
			loaded := 1
			if c.text == "" {
				loaded = 0
			}
			if got, want := ntcCounts(t, s.db), fmt.Sprintf("alert 2, event 3, delivery 3, check_state 1, notice 1, loaded %d, beat 0", loaded); got != want {
				t.Errorf("after the same Reload without the fault: %s, want %s", got, want)
			}
		})
	}
}

// A close is written as Apply writes it, so an alert that is no longer open
// cannot be closed, and nothing else of that Reload stays.
func TestReloadOfAnAlertThatIsNotOpenWritesNothing(t *testing.T) {
	s, n, closed := ntcReloadSetup(t)
	ntcReload(t, s, "corp.test.", "new text\n", &n, nil, closed...)
	before := ntcDump(t, s.db)

	later := n
	later.At = n.At.Add(time.Minute)
	err := s.Reload("corp.test.", "newer text\n", &later, ntcRowsTo("slack"), closed)
	id := closed[0].Event.Alert.ID
	if want := fmt.Sprintf("alert %d is not open", id); err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), want) {
		t.Errorf("Reload with a second close of alert %d: %v, want an error that starts with \"store: \" and holds %q", id, err, want)
	}
	if after := ntcDump(t, s.db); after != before {
		t.Errorf("after the refused Reload:\n%s\nwant\n%s", after, before)
	}
}

func TestAllOpenAlertsGivesTheOpenAlertsOfEveryCheckByID(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	if got := ntcAllOpen(t, s); len(got) != 0 {
		t.Errorf("AllOpenAlerts of a new store gives %d alerts, want none", len(got))
	}
	corp := stoName(t, "corp.test.")
	www, mail := stoWWW(t), stoMail(t)
	shop := obs.DelegationKey(stoName(t, "shop.test."))
	// The scope of a whole domain has kind 0, as the invalid-file alert has.
	scope := obs.Key{Domain: corp, Name: corp}
	// Names come back in lower case.
	mixed := obs.RecordsKey(stoName(t, "Corp.TEST."), stoName(t, "Mixed.Corp.Test."), dnswire.TypeA)
	// Written out of the order of their checks, so that an order by check
	// differs from the order by id.
	keys := []obs.Key{mail, shop, www, scope, www, mixed}
	rules := []decide.Rule{decide.RuleRecordSet, decide.RuleNameServers, decide.RuleRecordSet, decide.RuleInvalidFile, decide.RuleZone, decide.RuleNotCovered}
	for i, k := range keys {
		a := stoAlert(t, rules[i], k, "10.53.0."+strconv.Itoa(90+i))
		stoApply(t, s, k, false, stoT0, stoWrite(alert.EventOpen, a, a.Severity, stoT0))
	}
	// The record-set alert of www (id 3) ends; the zone alert of www stays.
	gone := stoOpenAlerts(t, s, www)[0]
	stoApply(t, s, www, false, stoT0.Add(time.Minute), ntcClose(t, gone, stoT0.Add(time.Minute)))

	got := ntcAllOpen(t, s)
	var ids []int64
	for _, a := range got {
		ids = append(ids, a.ID)
	}
	if want := []int64{1, 2, 4, 5, 6}; !slices.Equal(ids, want) {
		t.Fatalf("AllOpenAlerts gives ids %v, want %v", ids, want)
	}
	for i, a := range got {
		k := keys[ids[i]-1]
		c := a.Check
		if c.String() != k.String() || c.Domain.String() != c.Domain.Lower().String() || c.Name.String() != c.Name.Lower().String() {
			t.Errorf("alert %d has the check %v %v %v %v, want %q in lower case", a.ID, c.Kind, c.Domain, c.Name, c.Type, k.String())
		}
		var want alert.Alert
		for _, o := range stoOpenAlerts(t, s, k) {
			if o.ID == a.ID {
				want = o
			}
		}
		// OpenAlerts gives back the key it was given; its case was checked
		// above.
		want.Check = c
		if g, w := stoAlertText(a), stoAlertText(want); g != w {
			t.Errorf("AllOpenAlerts gives\n%s\nOpenAlerts of its check gives\n%s", g, w)
		}
	}
}
