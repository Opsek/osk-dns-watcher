package store

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// BeatLimit is the age of the last beat after which the service counts as
// not running: three missed beats of the writer.
const BeatLimit = 30 * time.Second

// stuckAfter is how long a pending row may wait past its next attempt
// before the loop of its channel counts as stuck.
const stuckAfter = 60 * time.Second

type ChannelHealth struct {
	Name    string
	Pending int // pending rows of the channel
	Failing bool
	Reason  string // reason of the newest failed attempt; "" when none
}

type Health struct {
	Beat     time.Time // zero: none stored
	Late     []string  // check keys from the last beat
	Channels []ChannelHealth
}

// Problems gives what is wrong at now, in a fixed order; none means healthy.
func (h Health) Problems(now time.Time) []string {
	var problems []string
	if h.Beat.IsZero() {
		problems = append(problems, "no beat from osk run yet")
	} else if now.Sub(h.Beat) > BeatLimit {
		problems = append(problems, "no beat from osk run since "+h.Beat.UTC().Format("2006-01-02 15:04:05 UTC"))
	}
	if len(h.Late) > 0 {
		problems = append(problems, fmt.Sprintf("%d checks late", len(h.Late)))
	}
	for _, c := range h.Channels {
		if c.Failing {
			problems = append(problems, "channel "+c.Name+" fails")
		}
	}
	return problems
}

// Health reads the last beat and the rows of each of channels, in the
// order given.
func (s *Store) Health(now time.Time, channels []string) (Health, error) {
	return health(s.db, now, channels)
}

// health runs one short statement after another and holds no transaction,
// so a reader never holds back the writer's checkpoints.
func health(db *sql.DB, now time.Time, channels []string) (Health, error) {
	var at int64
	var late string
	err := db.QueryRow("SELECT at, late FROM beat").Scan(&at, &late)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Health{}, wrap(err)
	}
	h := Health{Beat: fromNanos(at)}
	if late != "" {
		h.Late = strings.Split(late, "\n")
	}
	for _, name := range channels {
		c, err := channelHealth(db, now, name)
		if err != nil {
			return Health{}, wrap(err)
		}
		h.Channels = append(h.Channels, c)
	}
	return h, nil
}

// channelHealth judges a channel by its rows: a pending row that was tried
// and failed, a pending row long past its time, or a last finished row that
// was given up. Rows of notices count like rows of alerts.
func channelHealth(db *sql.DB, now time.Time, name string) (ChannelHealth, error) {
	c := ChannelHealth{Name: name}
	var tried, stuck bool
	err := db.QueryRow(`SELECT count(*), coalesce(max(attempts >= 1), 0), coalesce(max(next_at < ?), 0)
		FROM delivery WHERE channel = ? AND state = 'pending'`, nanos(now.Add(-stuckAfter)), name).Scan(&c.Pending, &tried, &stuck)
	if err != nil {
		return c, err
	}
	if tried {
		err := db.QueryRow(`SELECT reason FROM delivery WHERE channel = ? AND state = 'pending' AND attempts >= 1
			ORDER BY id DESC LIMIT 1`, name).Scan(&c.Reason)
		// The row may have been sent since the statement before.
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return c, err
		}
	}
	var state, reason string
	err = db.QueryRow(`SELECT state, reason FROM delivery WHERE channel = ? AND state <> 'pending'
		ORDER BY done_at DESC, id DESC LIMIT 1`, name).Scan(&state, &reason)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return c, err
	}
	givenUp := state == RowGivenUp.String()
	if givenUp && !tried {
		c.Reason = reason
	}
	c.Failing = tried || stuck || givenUp
	return c, nil
}
