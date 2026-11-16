package store

import (
	"database/sql"
	"errors"
	"strings"
	"time"
)

// Beat stores now as the last time the service was alive, in place of the
// one before, so that the next start can tell how long it was down. late
// are the keys of the checks that were late then; another process reads
// them from the store to judge the health of the service.
func (s *Store) Beat(now time.Time, late []string) error {
	_, err := s.db.Exec(`INSERT INTO beat (id, at, late) VALUES (1, ?, ?)
		ON CONFLICT (id) DO UPDATE SET at = excluded.at, late = excluded.late`, nanos(now), strings.Join(late, "\n"))
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
