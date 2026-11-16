package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strconv"
	"time"
)

type RowState uint8

const (
	RowPending RowState = iota + 1
	RowSent
	RowGivenUp
)

func (r RowState) String() string {
	switch r {
	case RowPending:
		return "pending"
	case RowSent:
		return "sent"
	case RowGivenUp:
		return "given-up"
	}
	return "row" + strconv.Itoa(int(r))
}

// Row is one pending delivery.
type Row struct {
	ID             int64
	Channel, Label string
	Body           []byte
	Attempts       int
	Created        time.Time
	NextAt         time.Time
}

// Done is the outcome of one attempt at a row.
type Done struct {
	State    RowState
	Attempts int
	NextAt   time.Time // the next attempt, when State is RowPending
	Reason   string
	At       time.Time // the attempt
}

// maxWait is the longest wait for the next attempt of a row. A next attempt
// further ahead was set while the clock ran ahead, and would otherwise hold
// the row back until the clock reaches it again.
const maxWait = time.Hour

// Due gives the pending rows of channel whose next attempt is not after now,
// or more than maxWait after it, by id.
func (s *Store) Due(channel string, now time.Time) ([]Row, error) {
	rows, err := s.db.Query(`SELECT id, label, body, attempts, created, next_at FROM delivery
		WHERE channel = ? AND state = 'pending' AND (next_at <= ? OR next_at > ?) ORDER BY id`,
		channel, nanos(now), nanos(now.Add(maxWait)))
	if err != nil {
		return nil, wrap(err)
	}
	var due []Row
	for rows.Next() {
		r := Row{Channel: channel}
		var created, next int64
		if err := rows.Scan(&r.ID, &r.Label, &r.Body, &r.Attempts, &created, &next); err != nil {
			return nil, wrap(errors.Join(err, rows.Close()))
		}
		r.Created, r.NextAt = fromNanos(created), fromNanos(next)
		due = append(due, r)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return nil, wrap(err)
	}
	return due, nil
}

// Record writes the outcome of an attempt at the pending row id. A row given
// up also gets a given-up event on its alert, in the same transaction, so
// that the failure is reported once.
func (s *Store) Record(id int64, d Done) error {
	tx, err := s.db.Begin()
	if err != nil {
		return wrap(err)
	}
	if err := record(tx, id, d); err != nil {
		return wrap(errors.Join(err, tx.Rollback()))
	}
	return wrap(tx.Commit())
}

func record(tx *sql.Tx, id int64, d Done) error {
	next, done := nanos(d.At), nanos(d.At)
	if d.State == RowPending {
		next, done = nanos(d.NextAt), 0
	}
	res, err := tx.Exec(`UPDATE delivery SET state = ?, attempts = ?, next_at = ?, reason = ?, done_at = ?
		WHERE id = ? AND state = 'pending'`, d.State.String(), d.Attempts, next, d.Reason, done, id)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil || n != 1 {
		return errors.Join(err, fmt.Errorf("delivery %d is not pending", id))
	}
	if d.State != RowGivenUp {
		return nil
	}
	_, err = tx.Exec(`INSERT INTO event (alert, kind, severity, was, value, at)
		SELECT event.alert, 'given-up', event.severity, event.was, delivery.channel || ': ' || ?, ?
		FROM delivery JOIN event ON event.id = delivery.event WHERE delivery.id = ?`, d.Reason, nanos(d.At), id)
	return err
}
