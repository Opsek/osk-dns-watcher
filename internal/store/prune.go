package store

import (
	"database/sql"
	"time"
)

// Prune deletes history from before cutoff, oldest first and in one
// transaction: at most limit resolved alerts with their events and the rows
// of those events, and at most limit notices with their rows. An alert or a
// notice that still has a pending row stays, so no message is lost. The
// limit keeps the transaction short, because the delivery loops share the
// store's one connection.
//
// The row with the highest id of alert, event, notice and delivery stays
// too, whatever its age: SQLite gives a new row the highest id plus one, so
// a new row never takes an id that a reader already passed.
func (s *Store) Prune(cutoff time.Time, limit int) (alerts, notices int, err error) {
	err = s.inTx(func(tx *sql.Tx) error {
		var err error
		if alerts, err = pruneAlerts(tx, nanos(cutoff), limit); err != nil {
			return err
		}
		notices, err = pruneNotices(tx, nanos(cutoff), limit)
		return err
	})
	if err != nil {
		return 0, 0, err
	}
	return alerts, notices, nil
}

func pruneAlerts(tx *sql.Tx, cutoff int64, limit int) (int, error) {
	var ids string
	err := tx.QueryRow(`SELECT json_group_array(id) FROM (SELECT id FROM alert
		WHERE open = 0 AND resolved < ? AND id NOT IN (SELECT event.alert FROM delivery
			JOIN event ON event.id = delivery.event WHERE delivery.state = 'pending')
		AND id NOT IN (SELECT max(id) FROM alert
			UNION SELECT alert FROM event WHERE id = (SELECT max(id) FROM event)
			UNION SELECT event.alert FROM delivery JOIN event ON event.id = delivery.event
				WHERE delivery.id = (SELECT max(id) FROM delivery))
		ORDER BY resolved, id LIMIT ?)`, cutoff, limit).Scan(&ids)
	if err != nil {
		return 0, err
	}
	return deleteIDs(tx, ids,
		"DELETE FROM delivery WHERE event IN (SELECT id FROM event WHERE alert IN (SELECT value FROM json_each(?)))",
		"DELETE FROM event WHERE alert IN (SELECT value FROM json_each(?))",
		"DELETE FROM alert WHERE id IN (SELECT value FROM json_each(?))")
}

func pruneNotices(tx *sql.Tx, cutoff int64, limit int) (int, error) {
	var ids string
	// NOT IN gives no row at all when its list holds a NULL.
	err := tx.QueryRow(`SELECT json_group_array(id) FROM (SELECT id FROM notice
		WHERE at < ? AND id NOT IN (SELECT notice FROM delivery WHERE state = 'pending' AND notice IS NOT NULL)
		AND id NOT IN (SELECT max(id) FROM notice
			UNION SELECT notice FROM delivery WHERE id = (SELECT max(id) FROM delivery) AND notice IS NOT NULL)
		ORDER BY at, id LIMIT ?)`, cutoff, limit).Scan(&ids)
	if err != nil {
		return 0, err
	}
	return deleteIDs(tx, ids,
		"DELETE FROM delivery WHERE notice IN (SELECT value FROM json_each(?))",
		"DELETE FROM notice WHERE id IN (SELECT value FROM json_each(?))")
}

// deleteIDs runs each statement with ids, a JSON array, as its one
// parameter, and gives the number of rows that the last one deleted. One
// array instead of one statement per id: the table event has no index on
// its alert, so each statement reads it once, not once per alert.
func deleteIDs(tx *sql.Tx, ids string, statements ...string) (int, error) {
	var n int64
	for _, q := range statements {
		res, err := tx.Exec(q, ids)
		if err != nil {
			return 0, err
		}
		if n, err = res.RowsAffected(); err != nil {
			return 0, err
		}
	}
	return int(n), nil
}
