package store

import (
	"cmp"
	"database/sql"
	"fmt"
	"maps"
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

// ntcHistory is what Prune may delete, read from the tables: each row of
// each table by id, the facts that Prune decides by, and the tables that
// Prune never changes.
type ntcHistory struct {
	rows     map[string]map[int64]string // table → id → the whole row
	open     map[int64]bool              // alert → open
	resolved map[int64]int64             // alert → resolved
	alertOf  map[int64]int64             // event → its alert
	eventOf  map[int64]int64             // row → its event; 0 for a row of a notice
	noticeOf map[int64]int64             // row → its notice; 0 for a row of an event
	pending  map[int64]bool              // row → pending
	at       map[int64]int64             // notice → at
	kept     string                      // check_state, beat and loaded
}

// ntcPruned are the tables that Prune deletes from.
var ntcPruned = []string{"alert", "event", "delivery", "notice"}

// ntcInts gives the integer columns of each row of query.
func ntcInts(t *testing.T, db *sql.DB, query string) [][]int64 {
	t.Helper()
	var out [][]int64
	for _, row := range ntcTable(t, db, query) {
		var r []int64
		for _, f := range strings.Fields(row) {
			n, err := strconv.ParseInt(f, 10, 64)
			if err != nil {
				t.Fatalf("%s gives %q, want integers", query, row)
			}
			r = append(r, n)
		}
		out = append(out, r)
	}
	return out
}

func ntcReadHistory(t *testing.T, db *sql.DB) ntcHistory {
	t.Helper()
	h := ntcHistory{rows: map[string]map[int64]string{}, open: map[int64]bool{}, resolved: map[int64]int64{},
		alertOf: map[int64]int64{}, eventOf: map[int64]int64{}, noticeOf: map[int64]int64{}, pending: map[int64]bool{}, at: map[int64]int64{}}
	for _, table := range ntcPruned {
		h.rows[table] = map[int64]string{}
		for _, row := range ntcTable(t, db, "SELECT * FROM "+table) {
			first, _, _ := strings.Cut(row, " ")
			id, err := strconv.ParseInt(first, 10, 64)
			if err != nil {
				t.Fatalf("a row of %s starts with %q, want its id", table, first)
			}
			h.rows[table][id] = row
		}
	}
	for _, r := range ntcInts(t, db, "SELECT id, open, resolved FROM alert") {
		h.open[r[0]], h.resolved[r[0]] = r[1] == 1, r[2]
	}
	for _, r := range ntcInts(t, db, "SELECT id, alert FROM event") {
		h.alertOf[r[0]] = r[1]
	}
	for _, r := range ntcInts(t, db, "SELECT id, coalesce(event, 0), coalesce(notice, 0), state = 'pending' FROM delivery") {
		h.eventOf[r[0]], h.noticeOf[r[0]], h.pending[r[0]] = r[1], r[2], r[3] == 1
	}
	for _, r := range ntcInts(t, db, "SELECT id, at FROM notice") {
		h.at[r[0]] = r[1]
	}
	var b strings.Builder
	for _, table := range []string{"check_state", "beat", "loaded"} {
		for _, row := range ntcTable(t, db, "SELECT * FROM "+table+" ORDER BY rowid") {
			fmt.Fprintf(&b, "%s %s\n", table, row)
		}
	}
	h.kept = b.String()
	return h
}

// ntcLast gives the highest id of m; 0 when m is empty.
func ntcLast[V any](m map[int64]V) int64 {
	var last int64
	for id := range m {
		last = max(last, id)
	}
	return last
}

// ntcPrunable gives what Prune may delete from h: the resolved alerts and
// the notices before the cutoff that have no pending row. The row with the
// highest id of each table stays, so that no id is given twice, and with
// it the alert or notice that it belongs to. Alerts come oldest resolved
// first.
func ntcPrunable(h ntcHistory, cutoff int64) (alerts, notices []int64) {
	heldAlert, heldNotice := map[int64]bool{}, map[int64]bool{}
	hold := func(row int64) {
		if e := h.eventOf[row]; e != 0 {
			heldAlert[h.alertOf[e]] = true
		}
		if n := h.noticeOf[row]; n != 0 {
			heldNotice[n] = true
		}
	}
	for row, pending := range h.pending {
		if pending {
			hold(row)
		}
	}
	heldAlert[ntcLast(h.open)] = true
	heldAlert[h.alertOf[ntcLast(h.alertOf)]] = true
	hold(ntcLast(h.pending))
	heldNotice[ntcLast(h.at)] = true
	for id, open := range h.open {
		if !open && h.resolved[id] < cutoff && !heldAlert[id] {
			alerts = append(alerts, id)
		}
	}
	for id, at := range h.at {
		if at < cutoff && !heldNotice[id] {
			notices = append(notices, id)
		}
	}
	slices.SortFunc(alerts, func(a, b int64) int { return cmp.Or(cmp.Compare(h.resolved[a], h.resolved[b]), cmp.Compare(a, b)) })
	slices.Sort(notices)
	return alerts, notices
}

// ntcRender writes the rows of h that gone does not hold, by table and id,
// then the tables that Prune never changes.
func ntcRender(h ntcHistory, gone map[string]map[int64]bool) string {
	var b strings.Builder
	for _, table := range ntcPruned {
		for _, id := range slices.Sorted(maps.Keys(h.rows[table])) {
			if !gone[table][id] {
				fmt.Fprintf(&b, "%s %s\n", table, h.rows[table][id])
			}
		}
	}
	b.WriteString(h.kept)
	return b.String()
}

// ntcWithout is h as Prune must leave it when it deletes these alerts and
// notices: they go with every event of the alerts and every row of those
// events and of the notices, and nothing else changes.
func ntcWithout(h ntcHistory, alerts, notices []int64) string {
	gone := map[string]map[int64]bool{"alert": {}, "event": {}, "delivery": {}, "notice": {}}
	for _, id := range alerts {
		gone["alert"][id] = true
	}
	for _, id := range notices {
		gone["notice"][id] = true
	}
	for e, a := range h.alertOf {
		gone["event"][e] = gone["alert"][a]
	}
	for row := range h.pending {
		gone["delivery"][row] = gone["event"][h.eventOf[row]] || gone["notice"][h.noticeOf[row]]
	}
	return ntcRender(h, gone)
}

// ntcGone gives the keys of before that after lacks, sorted.
func ntcGone[V any](before, after map[int64]V) []int64 {
	var gone []int64
	for id := range before {
		if _, ok := after[id]; !ok {
			gone = append(gone, id)
		}
	}
	slices.Sort(gone)
	return gone
}

// ntcCheckPrune holds one call Prune(cutoff, limit), which returned alerts
// and notices, against the store before and after it.
func ntcCheckPrune(t *testing.T, where string, before, after ntcHistory, cutoff int64, limit, alerts, notices int) {
	t.Helper()
	mayAlerts, mayNotices := ntcPrunable(before, cutoff)
	goneAlerts, goneNotices := ntcGone(before.open, after.open), ntcGone(before.at, after.at)
	if alerts != len(goneAlerts) || notices != len(goneNotices) {
		t.Fatalf("%s: Prune returned %d alerts and %d notices, but deleted alerts %v and notices %v", where, alerts, notices, goneAlerts, goneNotices)
	}
	// A batch is full while work is left: the service calls again only
	// after a full batch.
	if len(goneAlerts) != min(limit, len(mayAlerts)) || len(goneNotices) != min(limit, len(mayNotices)) {
		t.Fatalf("%s: with limit %d Prune deleted alerts %v of %v and notices %v of %v that it may delete",
			where, limit, goneAlerts, mayAlerts, goneNotices, mayNotices)
	}
	for _, id := range goneAlerts {
		if !slices.Contains(mayAlerts, id) {
			t.Fatalf("%s: Prune deleted alert %d, which it may not delete; it may delete %v", where, id, mayAlerts)
		}
		for _, other := range mayAlerts {
			if !slices.Contains(goneAlerts, other) && before.resolved[other] < before.resolved[id] {
				t.Fatalf("%s: Prune deleted alert %d before the older alert %d", where, id, other)
			}
		}
	}
	for _, id := range goneNotices {
		if !slices.Contains(mayNotices, id) {
			t.Fatalf("%s: Prune deleted notice %d, which it may not delete; it may delete %v", where, id, mayNotices)
		}
	}
	if got, want := ntcRender(after, nil), ntcWithout(before, goneAlerts, goneNotices); got != want {
		t.Fatalf("%s: after Prune:\n%s\nwant:\n%s", where, got, want)
	}
	for _, table := range ntcPruned {
		if b, a := ntcLast(before.rows[table]), ntcLast(after.rows[table]); a != b {
			t.Fatalf("%s: the highest id of %s was %d before Prune and is %d after it, want it kept", where, table, b, a)
		}
	}
}

// ntcEpisode writes an alert of a check of its own: open at opened with a
// row to each channel, and, unless resolved is zero, resolved then with a
// row to each channel. It gives the alert's id.
func ntcEpisode(t *testing.T, s *Store, name string, opened, resolved time.Time, channels ...string) int64 {
	t.Helper()
	k := obs.RecordsKey(stoName(t, "corp.test."), stoName(t, name), dnswire.TypeA)
	a := stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99")
	a.Opened, a.Noticed, a.LastClean = opened, opened, opened.Add(-time.Minute)
	stoApply(t, s, k, false, opened, stoWrite(alert.EventOpen, a, a.Severity, opened, channels...))
	a = stoNth(t, s, k, 1, 0)
	if !resolved.IsZero() {
		w := ntcClose(t, a, resolved)
		w.Deliveries = stoWrite(alert.EventResolve, a, a.Severity, resolved, channels...).Deliveries
		stoApply(t, s, k, false, resolved, w)
	}
	return a.ID
}

// ntcNotice writes a test notice at at with a row to each channel and gives
// its id.
func ntcNotice(t *testing.T, s *Store, at time.Time, channels ...string) int64 {
	t.Helper()
	ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc"}, At: at}, ntcRowsTo(channels...)...)
	ids := ntcIDs(t, s.db, "SELECT max(id) FROM notice")
	return ids[0]
}

func ntcAlertRows(t *testing.T, s *Store, id int64) []int64 {
	t.Helper()
	return ntcIDs(t, s.db, "SELECT id FROM delivery WHERE event IN (SELECT id FROM event WHERE alert = ?) ORDER BY id", id)
}

func ntcNoticeRows(t *testing.T, s *Store, id int64) []int64 {
	t.Helper()
	return ntcIDs(t, s.db, "SELECT id FROM delivery WHERE notice = ? ORDER BY id", id)
}

func ntcRecord(t *testing.T, s *Store, id int64, d Done) {
	t.Helper()
	if err := s.Record(id, d); err != nil {
		t.Fatalf("Record(%d, %+v): %v", id, d, err)
	}
}

func ntcSent(at time.Time) Done { return Done{State: RowSent, Attempts: 1, At: at} }

// ntcNewest writes an open alert and then a notice at now, each with a row
// to slack, so that they hold the highest id of every table. Prune keeps
// those rows whatever their age; these would stay anyway, so a test with
// them shows the rules of age alone.
func ntcNewest(t *testing.T, s *Store, now time.Time) {
	t.Helper()
	ntcEpisode(t, s, "newest.corp.test.", now, time.Time{}, "slack")
	ntcNotice(t, s, now, "slack")
}

func ntcPrune(t *testing.T, s *Store, cutoff time.Time, limit int) (alerts, notices int) {
	t.Helper()
	alerts, notices, err := s.Prune(cutoff, limit)
	if err != nil {
		t.Fatalf("Prune(%v, %d): %v", cutoff, limit, err)
	}
	return alerts, notices
}

// A store with rows of every kind on both sides of the cutoff: only ended
// alerts and notices from before it, with nothing pending, go, with all
// that belongs to them.
func TestPruneDeletesOnlyEndedHistoryFromBeforeTheCutoff(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	cut := stoT0
	month := 30 * 24 * time.Hour
	ago := cut.Add(-month)

	// Resolved a nanosecond before the cutoff, with a sent row and a row
	// given up (which adds a given-up event): it goes, with all three
	// events.
	a1 := ntcEpisode(t, s, "a1.corp.test.", ago, cut.Add(-time.Nanosecond), "slack")
	rows := ntcAlertRows(t, s, a1)
	ntcRecord(t, s, rows[0], ntcSent(ago))
	ntcRecord(t, s, rows[1], Done{State: RowGivenUp, Attempts: 1, Reason: "status 404", At: cut.Add(-time.Nanosecond)})
	// Resolved at the cutoff: it stays.
	a2 := ntcEpisode(t, s, "a2.corp.test.", ago, cut, "slack")
	for _, id := range ntcAlertRows(t, s, a2) {
		ntcRecord(t, s, id, ntcSent(cut))
	}
	// Resolved long before, but the row of its first event is still
	// pending: it stays whole.
	a3 := ntcEpisode(t, s, "a3.corp.test.", ago, cut.Add(-time.Hour), "slack")
	rows = ntcAlertRows(t, s, a3)
	ntcRecord(t, s, rows[0], Done{State: RowPending, Attempts: 2, NextAt: cut.Add(time.Minute), Reason: "status 503", At: cut.Add(-time.Hour)})
	ntcRecord(t, s, rows[1], ntcSent(cut.Add(-time.Hour)))
	// Open for a month: it stays.
	a4 := ntcEpisode(t, s, "a4.corp.test.", ago, time.Time{}, "slack")
	ntcRecord(t, s, ntcAlertRows(t, s, a4)[0], ntcSent(ago))
	// Resolved after the cutoff: it stays.
	a5 := ntcEpisode(t, s, "a5.corp.test.", ago, cut.Add(time.Hour), "slack")
	for _, id := range ntcAlertRows(t, s, a5) {
		ntcRecord(t, s, id, ntcSent(cut.Add(time.Hour)))
	}
	// Resolved two days before, with no row at all: it goes.
	a6 := ntcEpisode(t, s, "a6.corp.test.", ago, cut.Add(-48*time.Hour))

	n1 := ntcNotice(t, s, cut.Add(-time.Nanosecond), "slack", "hook")
	rows = ntcNoticeRows(t, s, n1)
	ntcRecord(t, s, rows[0], ntcSent(cut))
	ntcRecord(t, s, rows[1], Done{State: RowGivenUp, Attempts: 1, Reason: "status 404", At: cut})
	n2 := ntcNotice(t, s, cut, "slack")
	ntcRecord(t, s, ntcNoticeRows(t, s, n2)[0], ntcSent(cut))
	n3 := ntcNotice(t, s, cut.Add(-24*time.Hour), "slack", "hook")
	ntcRecord(t, s, ntcNoticeRows(t, s, n3)[0], ntcSent(cut))
	n4 := ntcNotice(t, s, cut.Add(-24*time.Hour))
	ntcNewest(t, s, cut)

	// Old rows of the tables that Prune never touches.
	stoApply(t, s, stoWWW(t), true, ago)
	if err := s.Beat(ago, []string{"records corp.test. www.corp.test. A"}); err != nil {
		t.Fatal(err)
	}
	ntcReload(t, s, "corp.test.", "domain corp.test.\n", nil, nil)

	before := ntcReadHistory(t, s.db)
	if alerts, notices := ntcPrune(t, s, cut, 200); alerts != 2 || notices != 2 {
		t.Errorf("Prune gives %d alerts and %d notices, want 2 and 2", alerts, notices)
	}
	after := ntcReadHistory(t, s.db)
	if got, want := ntcRender(after, nil), ntcWithout(before, []int64{a1, a6}, []int64{n1, n4}); got != want {
		t.Errorf("after Prune:\n%s\nwant:\n%s", got, want)
	}
	if got, want := ntcCounts(t, s.db), "alert 5, event 8, delivery 12, check_state 1, notice 3, loaded 1, beat 1"; got != want {
		t.Errorf("after Prune: %s, want %s", got, want)
	}
	if alerts, notices := ntcPrune(t, s, cut, 200); alerts != 0 || notices != 0 {
		t.Errorf("a second Prune gives %d alerts and %d notices, want 0 and 0", alerts, notices)
	}
	if got := ntcRender(ntcReadHistory(t, s.db), nil); got != ntcRender(after, nil) {
		t.Errorf("a second Prune changed the store:\n%s", got)
	}
}

// A batch takes the alerts that were resolved first, whatever their ids,
// and an old alert that must stay does not take a place in it.
func TestPruneDeletesAtMostLimitOldestResolvedFirst(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	cut := stoT0
	ago := cut.Add(-30 * 24 * time.Hour)
	held := ntcEpisode(t, s, "held.corp.test.", ago, cut.Add(-9*time.Hour), "slack")
	var ids []int64
	for i, hours := range []time.Duration{1, 5, 3, 2, 4} {
		ids = append(ids, ntcEpisode(t, s, fmt.Sprintf("e%d.corp.test.", i), ago, cut.Add(-hours*time.Hour)))
	}
	for range 3 {
		ntcNotice(t, s, cut.Add(-time.Hour))
	}
	ntcNewest(t, s, cut)
	for i, c := range []struct {
		limit   int
		alerts  []int64
		notices int
	}{
		{1, []int64{ids[1]}, 1},
		{2, []int64{ids[4], ids[2]}, 2},
		{2, []int64{ids[3], ids[0]}, 0},
		{2, nil, 0},
	} {
		before := ntcReadHistory(t, s.db)
		alerts, notices := ntcPrune(t, s, cut, c.limit)
		gone := ntcGone(before.open, ntcReadHistory(t, s.db).open)
		want := slices.Sorted(slices.Values(c.alerts))
		if alerts != len(want) || notices != c.notices || !slices.Equal(gone, want) {
			t.Errorf("call %d, Prune(cutoff, %d): gives %d alerts and %d notices and deleted alerts %v; want %d, %d and %v",
				i, c.limit, alerts, notices, gone, len(want), c.notices, want)
		}
	}
	if _, ok := ntcReadHistory(t, s.db).open[held]; !ok {
		t.Errorf("the alert %d with a pending row was deleted", held)
	}
}

// SQLite gives a new row the highest id plus one, so Prune keeps the row
// with the highest id of each table whatever its age: an id that a command
// already showed never names another row.
func TestPruneKeepsTheHighestIDOfEachTableSoNoIDIsGivenTwice(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	cut := stoT0
	ago := cut.Add(-30 * 24 * time.Hour)
	// All is old and ended, so only the rule of the highest id keeps a row.
	for i := range 3 {
		a := ntcEpisode(t, s, fmt.Sprintf("e%d.corp.test.", i), ago, ago.Add(time.Hour), "slack")
		for _, id := range ntcAlertRows(t, s, a) {
			ntcRecord(t, s, id, ntcSent(ago))
		}
		n := ntcNotice(t, s, ago, "slack")
		ntcRecord(t, s, ntcNoticeRows(t, s, n)[0], ntcSent(ago))
	}
	last := map[string]int64{}
	for _, table := range ntcPruned {
		last[table] = ntcIDs(t, s.db, "SELECT max(id) FROM "+table)[0]
	}
	for range 10 {
		if alerts, notices := ntcPrune(t, s, cut, 200); alerts == 0 && notices == 0 {
			break
		}
	}
	for _, table := range ntcPruned {
		if got := ntcIDs(t, s.db, "SELECT max(id) FROM "+table); !slices.Equal(got, []int64{last[table]}) {
			t.Errorf("after Prune the highest id of %s is %v, want %d kept", table, got, last[table])
		}
	}
	// The alert and the notice that hold those rows stay whole; the rest
	// is gone.
	if got, want := ntcCounts(t, s.db), "alert 1, event 2, delivery 3, check_state 0, notice 1, loaded 0, beat 0"; got != want {
		t.Errorf("after Prune: %s, want %s", got, want)
	}

	k := stoWWW(t)
	stoApply(t, s, k, false, cut, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, cut, "slack"))
	ntcNotice(t, s, cut, "slack")
	for _, table := range ntcPruned {
		if got := ntcIDs(t, s.db, "SELECT max(id) FROM "+table); got[0] <= last[table] {
			t.Errorf("a new row of %s got the id %d, want one above %d, the highest it ever had", table, got[0], last[table])
		}
	}
}

// Prune is one transaction: a delete that fails in any table leaves every
// table as it was.
func TestPruneWritesNothingWhenADeleteFails(t *testing.T) {
	for _, table := range ntcPruned {
		t.Run(table, func(t *testing.T) {
			s := stoOpen(t, stoDir(t))
			cut := stoT0
			a := ntcEpisode(t, s, "a.corp.test.", cut.Add(-48*time.Hour), cut.Add(-time.Hour), "slack")
			for _, id := range ntcAlertRows(t, s, a) {
				ntcRecord(t, s, id, ntcSent(cut.Add(-time.Hour)))
			}
			n := ntcNotice(t, s, cut.Add(-time.Hour), "slack")
			ntcRecord(t, s, ntcNoticeRows(t, s, n)[0], ntcSent(cut.Add(-time.Hour)))
			ntcNewest(t, s, cut)
			before := ntcDump(t, s.db)

			stoExec(t, s, "CREATE TRIGGER ntc_fault BEFORE DELETE ON "+table+" BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
			_, _, err := s.Prune(cut, 200)
			if err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), "planted fault") {
				t.Errorf("Prune: %v, want an error that starts with \"store: \" and holds the planted fault", err)
			}
			if after := ntcDump(t, s.db); after != before {
				t.Errorf("after the failed Prune:\n%s\nwant\n%s", after, before)
			}
			stoExec(t, s, "DROP TRIGGER ntc_fault")
			if alerts, notices := ntcPrune(t, s, cut, 200); alerts != 1 || notices != 1 {
				t.Errorf("Prune without the fault gives %d alerts and %d notices, want 1 and 1", alerts, notices)
			}
		})
	}
}

// Random histories of open and resolved alerts, events, rows in every state
// and notices, at times on both sides of the cutoff. Prune(cutoff, limit)
// is called until it gives 0 and 0; each call deletes a full batch of what
// it may delete, the oldest resolved alerts first, with all that belongs to
// them, and changes nothing else.
func TestPruneProperty(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	cutoff := stoT0
	offsets := []time.Duration{-48 * time.Hour, -2 * time.Hour, -time.Hour, -time.Second, -time.Nanosecond, 0, time.Nanosecond, time.Hour}
	states := []string{"pending", "sent", "sent", "given-up"}
	for c := range ntcCases {
		rng := ntcRand(c)
		where := fmt.Sprintf("seed %d case %d", ntcSeed, c)
		when := func() int64 { return cutoff.Add(ntcPick(rng, offsets...)).UnixNano() }
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		exec := func(q string, args ...any) {
			if _, err := tx.Exec(q, args...); err != nil {
				t.Fatalf("%s: %s: %v", where, q, err)
			}
		}
		for _, table := range []string{"delivery", "event", "notice", "alert", "check_state", "beat", "loaded"} {
			exec("DELETE FROM " + table)
		}
		var row int64
		addRows := func(event, notice any) {
			for range rng.IntN(3) {
				row++
				state := ntcPick(rng, states...)
				done := int64(0)
				if state != "pending" {
					done = when()
				}
				exec(`INSERT INTO delivery (id, event, notice, channel, label, body, state, attempts, created, next_at, reason, done_at)
					VALUES (?, ?, ?, ?, 'row', x'7b7d', ?, 1, ?, ?, '', ?)`, row, event, notice, ntcPick(rng, "slack", "hook"), state, when(), when(), done)
			}
		}
		var event int64
		for i := range rng.IntN(7) {
			id := int64(i + 1)
			open := rng.IntN(3) == 0
			resolved := int64(0)
			if !open {
				resolved = when()
			}
			exec(`INSERT INTO alert (id, open, rule, check_key, kind, domain, name, type, severity, peak, expected, value, lines,
				opened, last_clean, noticed, resolved) VALUES (?, ?, 5, ?, 3, 'corp.test.', ?, 1, 3, 3, '', '', '[]', ?, 0, ?, ?)`,
				id, open, fmt.Sprintf("records corp.test. a%d.corp.test. A", id), fmt.Sprintf("a%d.corp.test.", id), when(), when(), resolved)
			for range 1 + rng.IntN(3) {
				event++
				exec("INSERT INTO event (id, alert, kind, severity, was, value, at) VALUES (?, ?, 'open', 3, 3, '', ?)", event, id, when())
				addRows(event, nil)
			}
		}
		for i := range rng.IntN(6) {
			id := int64(i + 1)
			exec("INSERT INTO notice (id, kind, domain, lines, at) VALUES (?, 'test', '', '[]', ?)", id, when())
			addRows(nil, id)
		}
		for i := range rng.IntN(3) {
			exec("INSERT INTO check_state (check_key, last_clean) VALUES (?, ?)", fmt.Sprintf("records corp.test. c%d.corp.test. A", i), when())
			exec("INSERT INTO loaded (domain, text, at) VALUES (?, 'domain x.', ?)", fmt.Sprintf("d%d.test.", i), when())
		}
		if rng.IntN(2) == 0 {
			exec("INSERT INTO beat (id, at, late) VALUES (1, ?, 'records corp.test. www.corp.test. A')", when())
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}

		limit := 1 + rng.IntN(3)
		for call := 0; ; call++ {
			if call > 20 {
				t.Fatalf("%s: Prune(cutoff, %d) did not give 0 and 0 in %d calls", where, limit, call)
			}
			before := ntcReadHistory(t, s.db)
			alerts, notices, err := s.Prune(cutoff, limit)
			if err != nil {
				t.Fatalf("%s: Prune: %v", where, err)
			}
			ntcCheckPrune(t, fmt.Sprintf("%s call %d", where, call), before, ntcReadHistory(t, s.db), cutoff.UnixNano(), limit, alerts, notices)
			if alerts == 0 && notices == 0 {
				break
			}
		}
	}
}
