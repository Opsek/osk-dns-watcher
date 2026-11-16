package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
)

// Reader reads the store of a folder while osk run writes it. Open it only
// in a process that holds no Store of the same folder, for the reason given
// at create. No method holds a transaction, so a Reader never takes the
// write lock and never holds back the writer's checkpoints for long.
type Reader struct {
	db *sql.DB
}

// page is the most rows that one call of Events or Notices gives.
const page = 1000

// OpenReader opens the store in dir for reading only.
func OpenReader(dir string) (*Reader, error) {
	if err := checkName(dir); err != nil {
		return nil, err
	}
	path := dir + "/osk.db"
	err := CheckFolder(dir)
	if err == nil {
		_, err = os.Stat(path)
		err = wrap(err)
	}
	if errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("store: no state in %s yet; start osk run there first", dir)
	}
	if err != nil {
		return nil, err
	}
	// Read-only needs the URI form of the name, in which SQLite reads %XX
	// as an escape.
	db, err := sql.Open("sqlite3", "file:"+strings.ReplaceAll(path, "%", "%25")+"?mode=ro&_busy_timeout=5000")
	if err != nil {
		return nil, wrap(err)
	}
	db.SetMaxOpenConns(1)
	var version int
	err = wrap(db.QueryRow("PRAGMA user_version").Scan(&version))
	if err == nil && version != 3 {
		err = notStore(path, version)
	}
	if err != nil {
		return nil, errors.Join(err, wrap(db.Close()))
	}
	return &Reader{db: db}, nil
}

func (r *Reader) Close() error {
	return wrap(r.db.Close())
}

func (r *Reader) Health(now time.Time, channels []string) (Health, error) {
	return health(r.db, now, channels)
}

func (r *Reader) AllOpenAlerts() ([]alert.Alert, error) {
	return allOpenAlerts(r.db)
}

// Alert gives the alert id, open or not.
func (r *Reader) Alert(id int64) (alert.Alert, error) {
	a, err := scanAlert(r.db.QueryRow("SELECT "+alertColumns+" FROM alert WHERE id = ?", id))
	if errors.Is(err, sql.ErrNoRows) {
		return alert.Alert{}, fmt.Errorf("store: no alert %d", id)
	}
	if err != nil {
		return alert.Alert{}, wrap(err)
	}
	return a, nil
}

type EventRow struct {
	ID            int64
	Alert         alert.Alert // the alert row as it is now
	Kind          string      // "open", "update", "escalate", "reminder", "resolve", "given-up"
	Severity, Was decide.Severity
	Value         string
	At            time.Time
}

// Events gives the events after the event id after, by id, at most page of
// them.
func (r *Reader) Events(after int64) ([]EventRow, error) {
	rows, err := r.db.Query(`SELECT event.id, event.kind, event.severity, event.was, event.value, event.at, `+alertColumns+`
		FROM event JOIN alert ON alert.id = event.alert WHERE event.id > ? ORDER BY event.id LIMIT ?`, after, page)
	if err != nil {
		return nil, wrap(err)
	}
	var events []EventRow
	for rows.Next() {
		var e EventRow
		var at int64
		e.Alert, err = scanAlert(rows, &e.ID, &e.Kind, &e.Severity, &e.Was, &e.Value, &at)
		if err != nil {
			return nil, wrap(errors.Join(err, rows.Close()))
		}
		e.At = fromNanos(at)
		events = append(events, e)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return events, nil
}

// Notices gives the notices after the notice id after, by id, at most page
// of them.
func (r *Reader) Notices(after int64) ([]Notice, error) {
	rows, err := r.db.Query("SELECT id, kind, domain, lines, at FROM notice WHERE id > ? ORDER BY id LIMIT ?", after, page)
	if err != nil {
		return nil, wrap(err)
	}
	var notices []Notice
	for rows.Next() {
		var n Notice
		var lines string
		var at int64
		err := rows.Scan(&n.ID, &n.Kind, &n.Domain, &lines, &at)
		if err == nil {
			err = json.Unmarshal([]byte(lines), &n.Lines)
		}
		if err != nil {
			return nil, wrap(errors.Join(fmt.Errorf("notice %d: %w", n.ID, err), rows.Close()))
		}
		n.At = fromNanos(at)
		notices = append(notices, n)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return notices, nil
}

// Last gives the highest event id and the highest notice id, 0 when there
// is none.
func (r *Reader) Last() (event, notice int64, err error) {
	err = r.db.QueryRow("SELECT (SELECT coalesce(max(id), 0) FROM event), (SELECT coalesce(max(id), 0) FROM notice)").
		Scan(&event, &notice)
	if err != nil {
		return 0, 0, wrap(err)
	}
	return event, notice, nil
}

// RowStatus is the state of one row of a notice.
type RowStatus struct {
	Channel  string
	State    RowState
	Attempts int
	Reason   string
	NextAt   time.Time
}

// NoticeRows gives the rows of the notice id, by row id.
func (r *Reader) NoticeRows(id int64) ([]RowStatus, error) {
	rows, err := r.db.Query("SELECT channel, state, attempts, reason, next_at FROM delivery WHERE notice = ? ORDER BY id", id)
	if err != nil {
		return nil, wrap(err)
	}
	var statuses []RowStatus
	for rows.Next() {
		var s RowStatus
		var state string
		var next int64
		err := rows.Scan(&s.Channel, &state, &s.Attempts, &s.Reason, &next)
		if err == nil {
			s.State, err = rowState(state)
		}
		if err != nil {
			return nil, wrap(errors.Join(err, rows.Close()))
		}
		s.NextAt = fromNanos(next)
		statuses = append(statuses, s)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return statuses, nil
}

func rowState(word string) (RowState, error) {
	for _, s := range []RowState{RowPending, RowSent, RowGivenUp} {
		if s.String() == word {
			return s, nil
		}
	}
	return 0, fmt.Errorf("unknown row state %q", word)
}
