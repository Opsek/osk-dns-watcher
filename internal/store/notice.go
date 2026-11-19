package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

type NoticeKind string

const (
	NoticeTest         NoticeKind = "test"
	NoticeDown         NoticeKind = "down"
	NoticeExpectations NoticeKind = "expectations"
)

// Notice is a message that belongs to no alert.
type Notice struct {
	ID     int64 // set by the store when read
	Kind   NoticeKind
	Domain string // lower case, trailing dot; "" when it concerns no domain
	Lines  []string
	At     time.Time
}

// Notify writes n and one pending row for each delivery, all or nothing.
func (s *Store) Notify(n Notice, deliveries []Delivery) error {
	return s.inTx(func(tx *sql.Tx) error { return notify(tx, n, deliveries) })
}

// notify makes the rows as Apply makes them, with n.At as the time of
// writing.
func notify(tx *sql.Tx, n Notice, deliveries []Delivery) error {
	lines := n.Lines
	if lines == nil {
		lines = []string{} // a JSON array, never null
	}
	text, err := json.Marshal(lines)
	if err != nil {
		return err
	}
	res, err := tx.Exec("INSERT INTO notice (kind, domain, lines, at) VALUES (?, ?, ?, ?)",
		string(n.Kind), n.Domain, string(text), nanos(n.At))
	if err != nil {
		return err
	}
	id, err := res.LastInsertId()
	if err != nil {
		return err
	}
	for _, d := range deliveries {
		_, err := tx.Exec(`INSERT INTO delivery (notice, channel, label, body, state, attempts, created, next_at, reason, done_at)
			VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, '', 0)`, id, d.Channel, d.Label, d.Body, nanos(n.At), nanos(n.At))
		if err != nil {
			return err
		}
	}
	return nil
}

// Loaded gives, for each domain, the text of the expectations that were
// last loaded.
func (s *Store) Loaded() (map[string]string, error) {
	rows, err := s.db.Query("SELECT domain, text FROM loaded")
	if err != nil {
		return nil, wrap(err)
	}
	loaded := map[string]string{}
	for rows.Next() {
		var domain, text string
		if err := rows.Scan(&domain, &text); err != nil {
			return nil, wrap(errors.Join(err, rows.Close()))
		}
		loaded[domain] = text
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return loaded, nil
}

// Reload keeps text as the loaded expectations of domain ("" forgets the
// domain), writes n with its deliveries when n is not nil, and writes the
// events of the alerts that the change closed, all or nothing: a crash
// between them would report the change twice or lose the closes.
func (s *Store) Reload(domain, text string, n *Notice, deliveries []Delivery, closed []Write) error {
	at := time.Now()
	if n != nil {
		at = n.At
	}
	return s.inTx(func(tx *sql.Tx) error {
		var err error
		if text == "" {
			_, err = tx.Exec("DELETE FROM loaded WHERE domain = ?", domain)
		} else {
			_, err = tx.Exec(`INSERT INTO loaded (domain, text, at) VALUES (?, ?, ?)
				ON CONFLICT (domain) DO UPDATE SET text = excluded.text, at = excluded.at`, domain, text, nanos(at))
		}
		if err != nil {
			return err
		}
		if n != nil {
			if err := notify(tx, *n, deliveries); err != nil {
				return err
			}
		}
		// Not clean, so the clean times of the checks stay as they are.
		return apply(tx, obs.Key{}, false, at, closed)
	})
}

// AllOpenAlerts gives every open alert, by id.
func (s *Store) AllOpenAlerts() ([]alert.Alert, error) {
	return allOpenAlerts(s.db)
}

func allOpenAlerts(db *sql.DB) ([]alert.Alert, error) {
	rows, err := db.Query("SELECT " + alertColumns + " FROM alert WHERE open = 1 ORDER BY id")
	if err != nil {
		return nil, wrap(err)
	}
	var alerts []alert.Alert
	for rows.Next() {
		a, err := scanAlert(rows)
		if err != nil {
			return nil, wrap(errors.Join(err, rows.Close()))
		}
		alerts = append(alerts, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return alerts, nil
}

// alertColumns are the columns that scanAlert reads, in its order.
const alertColumns = `alert.id, alert.open, alert.rule, alert.kind, alert.domain, alert.name, alert.type,
	alert.severity, alert.peak, alert.expected, alert.value, alert.lines,
	alert.opened, alert.last_clean, alert.noticed, alert.resolved`

// scanAlert reads an alert from the columns of alertColumns, which follow
// the columns of first. The names of its check come back in lower case, as
// they are stored.
func scanAlert(row interface{ Scan(dest ...any) error }, first ...any) (alert.Alert, error) {
	var a alert.Alert
	var domain, name, lines string
	var opened, lastClean, noticed, resolved int64
	dest := append(first, &a.ID, &a.Open, &a.Rule, &a.Check.Kind, &domain, &name, &a.Check.Type,
		&a.Severity, &a.Peak, &a.Expected, &a.Value, &lines, &opened, &lastClean, &noticed, &resolved)
	if err := row.Scan(dest...); err != nil {
		return alert.Alert{}, err
	}
	var err error
	if a.Check.Domain, err = dnswire.ParseName(domain); err == nil {
		if a.Check.Name, err = dnswire.ParseName(name); err == nil {
			a.Lines, err = readLines(lines)
		}
	}
	if err != nil {
		return alert.Alert{}, fmt.Errorf("alert %d: %w", a.ID, err)
	}
	a.Opened, a.LastClean = fromNanos(opened), fromNanos(lastClean)
	a.Noticed, a.Resolved = fromNanos(noticed), fromNanos(resolved)
	return a, nil
}
