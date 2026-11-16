package store

import (
	"database/sql"
	"errors"
	"time"
)

// Beat stores now as the last time the service was alive, in place of the
// one before, so that the next start can tell how long it was down.
func (s *Store) Beat(now time.Time) error {
	_, err := s.db.Exec("INSERT INTO beat VALUES (1, ?) ON CONFLICT (id) DO UPDATE SET at = excluded.at", nanos(now))
	return wrap(err)
}

// LastBeat gives the time of the last Beat; zero when no beat was ever stored.
func (s *Store) LastBeat() (time.Time, error) {
	var at int64
	err := s.db.QueryRow("SELECT at FROM beat").Scan(&at)
	if errors.Is(err, sql.ErrNoRows) {
		return time.Time{}, nil
	}
	if err != nil {
		return time.Time{}, wrap(err)
	}
	return fromNanos(at), nil
}
