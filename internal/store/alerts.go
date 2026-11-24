package store

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Delivery is one notice of an event to one channel.
type Delivery struct {
	Channel, Label string
	Body           []byte
}

type Write struct {
	Event      alert.Event
	Deliveries []Delivery
}

// line is how an alert.Line is kept in the column lines.
type line struct {
	Server   string `json:"server"`
	Addr     string `json:"addr"`
	Text     string `json:"text"`
	TTL      uint32 `json:"ttl"`
	Received string `json:"received"`
}

// OpenAlerts gives the open alerts of check k, by id.
func (s *Store) OpenAlerts(k obs.Key) ([]alert.Alert, error) {
	rows, err := s.db.Query(`SELECT id, rule, severity, peak, expected, value, lines,
		opened, last_clean, noticed, resolved FROM alert WHERE check_key = ? AND open = 1 ORDER BY id`, k.String())
	if err != nil {
		return nil, wrap(err)
	}
	var alerts []alert.Alert
	for rows.Next() {
		a := alert.Alert{Open: true, Check: k}
		var lines string
		var opened, lastClean, noticed, resolved int64
		err := rows.Scan(&a.ID, &a.Rule, &a.Severity, &a.Peak, &a.Expected, &a.Value, &lines,
			&opened, &lastClean, &noticed, &resolved)
		if err == nil {
			a.Lines, err = readLines(lines)
		}
		if err != nil {
			return nil, wrap(errors.Join(fmt.Errorf("alert %d: %w", a.ID, err), rows.Close()))
		}
		a.Opened, a.LastClean = fromNanos(opened), fromNanos(lastClean)
		a.Noticed, a.Resolved = fromNanos(noticed), fromNanos(resolved)
		alerts = append(alerts, a)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return alerts, nil
}

// LastClean gives the last time check k was clean; zero when it never was.
func (s *Store) LastClean(k obs.Key) (time.Time, error) {
	var at int64
	err := s.db.QueryRow("SELECT last_clean FROM check_state WHERE check_key = ?", k.String()).Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, wrap(err)
	}
	return fromNanos(at), nil
}

// Apply writes the alerts of the events, the events and their deliveries,
// and the clean time of check k when clean, all or nothing.
func (s *Store) Apply(k obs.Key, clean bool, now time.Time, writes []Write) error {
	tx, err := s.db.Begin()
	if err != nil {
		return wrap(err)
	}
	if err := apply(tx, k, clean, now, writes); err != nil {
		return wrap(errors.Join(err, tx.Rollback()))
	}
	return wrap(tx.Commit())
}

func apply(tx *sql.Tx, k obs.Key, clean bool, now time.Time, writes []Write) error {
	for _, w := range writes {
		id, err := writeAlert(tx, w.Event.Alert)
		if err != nil {
			return err
		}
		// The event rows are what was told. A refresh tells nothing: it only
		// keeps the servers of the alert row current.
		if w.Event.Kind == alert.EventRefresh {
			continue
		}
		e := w.Event
		res, err := tx.Exec("INSERT INTO event (alert, kind, severity, was, value, at) VALUES (?, ?, ?, ?, ?, ?)",
			id, e.Kind.String(), e.Alert.Severity, e.Was, e.Alert.Value, nanos(e.At))
		if err != nil {
			return err
		}
		event, err := res.LastInsertId()
		if err != nil {
			return err
		}
		for _, d := range w.Deliveries {
			_, err := tx.Exec(`INSERT INTO delivery (event, channel, label, body, state, attempts, created, next_at, reason, done_at)
				VALUES (?, ?, ?, ?, 'pending', 0, ?, ?, '', 0)`, event, d.Channel, d.Label, d.Body, nanos(now), nanos(now))
			if err != nil {
				return err
			}
		}
	}
	if !clean {
		return nil
	}
	_, err := tx.Exec(`INSERT INTO check_state VALUES (?, ?)
		ON CONFLICT (check_key) DO UPDATE SET last_clean = excluded.last_clean`, k.String(), nanos(now))
	return err
}

func writeAlert(tx *sql.Tx, a alert.Alert) (int64, error) {
	lines, err := writeLines(a.Lines)
	if err != nil {
		return 0, err
	}
	if a.ID == 0 {
		res, err := tx.Exec(`INSERT INTO alert (open, rule, check_key, kind, domain, name, type, severity, peak,
			expected, value, lines, opened, last_clean, noticed, resolved)
			VALUES (1, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.Rule, a.Check.String(), a.Check.Kind, a.Check.Domain.Lower().String(), a.Check.Name.Lower().String(),
			a.Check.Type, a.Severity, a.Peak, a.Expected, a.Value, lines,
			nanos(a.Opened), nanos(a.LastClean), nanos(a.Noticed), nanos(a.Resolved))
		if err != nil {
			return 0, err
		}
		return res.LastInsertId()
	}
	res, err := tx.Exec(`UPDATE alert SET open = ?, severity = ?, peak = ?, expected = ?, value = ?, lines = ?,
		noticed = ?, resolved = ? WHERE id = ? AND open = 1`,
		a.Open, a.Severity, a.Peak, a.Expected, a.Value, lines, nanos(a.Noticed), nanos(a.Resolved), a.ID)
	if err != nil {
		return 0, err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return 0, errors.Join(err, fmt.Errorf("alert %d is not open", a.ID))
	}
	return a.ID, nil
}

func writeLines(lines []alert.Line) (string, error) {
	out := make([]line, 0, len(lines))
	for _, l := range lines {
		j := line{Server: l.Server.Name.Lower().String(), Text: l.Text, TTL: l.TTL}
		if l.Server.Addr.IsValid() {
			j.Addr = l.Server.Addr.String()
		}
		if !l.Received.IsZero() {
			j.Received = l.Received.UTC().Format(time.RFC3339Nano)
		}
		out = append(out, j)
	}
	b, err := json.Marshal(out)
	return string(b), err
}

func readLines(s string) ([]alert.Line, error) {
	var in []line
	if err := json.Unmarshal([]byte(s), &in); err != nil {
		return nil, err
	}
	var lines []alert.Line
	for _, j := range in {
		l := alert.Line{Text: j.Text, TTL: j.TTL}
		var err error
		if l.Server.Name, err = dnswire.ParseName(j.Server); err != nil {
			return nil, err
		}
		if j.Addr != "" {
			if l.Server.Addr, err = netip.ParseAddrPort(j.Addr); err != nil {
				return nil, err
			}
		}
		if j.Received != "" {
			if l.Received, err = time.Parse(time.RFC3339Nano, j.Received); err != nil {
				return nil, err
			}
		}
		lines = append(lines, l)
	}
	return lines, nil
}

// nanos and fromNanos keep times as Unix nanoseconds, with 0 for the zero
// time.Time, whose Unix nanoseconds are out of range.
func nanos(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixNano()
}

func fromNanos(n int64) time.Time {
	if n == 0 {
		return time.Time{}
	}
	return time.Unix(0, n).UTC()
}
