// Package store keeps the alerts of the tool, their events, the notices that
// belong to no alert, and the deliveries of both in one SQLite database in a
// state folder. One process at a time may write a folder: Open takes the
// folder's lock and holds it until Close. Other processes read the database
// through a Reader.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	"github.com/mattn/go-sqlite3"
)

// Store is the only writer of its folder. Only Open makes one, and every
// statement runs on one connection, so its own writes run one at a time.
type Store struct {
	db   *sql.DB
	lock *sql.DB // state.lock, kept in an exclusive transaction
	held *sql.Tx
}

// schema is the whole schema of a new store.
const schema = `
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

// upgrade2 turns a store of version 1 into version 2 in place, so a folder
// keeps its alerts and its outbox.
const upgrade2 = `
CREATE TABLE beat (id INTEGER PRIMARY KEY CHECK (id = 1), at INTEGER NOT NULL) STRICT;
PRAGMA user_version = 2;
`

// upgrade3 turns a store of version 2 into version 3 in place. A row of a
// notice has no event, and SQLite cannot drop the NOT NULL of
// delivery.event, so the table is made again with every row. The indexes
// come after the rename, because the old table holds the name delivery_due
// until it is dropped.
const upgrade3 = `
CREATE TABLE notice (id INTEGER PRIMARY KEY, kind TEXT NOT NULL CHECK (kind IN ('test','down','expectations')),
  domain TEXT NOT NULL, lines TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE loaded (domain TEXT PRIMARY KEY, text TEXT NOT NULL, at INTEGER NOT NULL) STRICT;
CREATE TABLE delivery_new (id INTEGER PRIMARY KEY, event INTEGER REFERENCES event (id), notice INTEGER REFERENCES notice (id),
  channel TEXT NOT NULL CHECK (channel <> ''), label TEXT NOT NULL, body BLOB NOT NULL,
  state TEXT NOT NULL CHECK (state IN ('pending','sent','given-up')), attempts INTEGER NOT NULL,
  created INTEGER NOT NULL, next_at INTEGER NOT NULL, reason TEXT NOT NULL, done_at INTEGER NOT NULL,
  CHECK ((event IS NULL) <> (notice IS NULL))) STRICT;
INSERT INTO delivery_new SELECT id, event, NULL, channel, label, body, state, attempts, created, next_at, reason, done_at FROM delivery;
DROP TABLE delivery;
ALTER TABLE delivery_new RENAME TO delivery;
CREATE INDEX delivery_due ON delivery (channel, next_at) WHERE state = 'pending';
CREATE INDEX delivery_event ON delivery (event);
CREATE INDEX delivery_notice ON delivery (notice);
ALTER TABLE beat ADD COLUMN late TEXT NOT NULL DEFAULT '';
PRAGMA user_version = 3;
`

// Open opens the store in dir, and makes dir with mode 0700 when it is
// missing.
func Open(dir string) (*Store, error) {
	if err := checkName(dir); err != nil {
		return nil, err
	}
	if err := os.Mkdir(dir, 0o700); err != nil && !errors.Is(err, fs.ErrExist) {
		return nil, wrap(err)
	}
	if err := CheckFolder(dir); err != nil {
		return nil, err
	}
	lock, held, err := lockFolder(dir)
	if err != nil {
		return nil, err
	}
	db, err := openData(dir)
	if err != nil {
		return nil, errors.Join(err, wrap(held.Rollback()), wrap(lock.Close()))
	}
	return &Store{db: db, lock: lock, held: held}, nil
}

func checkName(dir string) error {
	// Both end the file name of a SQLite DSN.
	if strings.ContainsAny(dir, "?#") {
		return fmt.Errorf("store: %s: a folder name with ? or # cannot be used", dir)
	}
	// The driver reads such a name as a URI, which can name another file.
	if strings.HasPrefix(dir, "file:") {
		return fmt.Errorf("store: %s: a folder name that starts with file: cannot be used", dir)
	}
	return nil
}

// CheckFolder refuses dir when it is not a folder or when other users may
// enter or list it; Open and OpenReader refuse such a folder too. The mode
// alone suffices: a folder that only its owner can enter keeps every file in
// it private, whatever the mode of the file.
func CheckFolder(dir string) error {
	info, err := os.Stat(dir)
	if err != nil {
		return wrap(err)
	}
	if !info.IsDir() {
		return fmt.Errorf("store: %s is not a folder", dir)
	}
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		return fmt.Errorf("store: %s is open to other users (mode %04o); run chmod 700 %s", dir, uint32(perm), dir)
	}
	return nil
}

// lockFolder holds an exclusive transaction on dir/state.lock. SQLite keeps it
// with a lock of the operating system, which the system drops when the
// process dies, so a crash leaves no stale lock.
func lockFolder(dir string) (*sql.DB, *sql.Tx, error) {
	path := dir + "/state.lock"
	if err := create(path); err != nil {
		return nil, nil, wrap(err)
	}
	// A busy timeout of 0: a second process fails at once instead of
	// waiting for the first one to end.
	lock, err := sql.Open("sqlite3", path+"?_busy_timeout=0&_txlock=exclusive")
	if err != nil {
		return nil, nil, fmt.Errorf("store: %s: %w", path, err)
	}
	lock.SetMaxOpenConns(1)
	held, err := lock.Begin()
	if err != nil {
		var e sqlite3.Error
		if errors.As(err, &e) && e.Code == sqlite3.ErrBusy {
			err = fmt.Errorf("store: %s is in use by another osk-dns-watcher process", dir)
		} else {
			err = fmt.Errorf("store: %s: %w", path, err)
		}
		return nil, nil, errors.Join(err, wrap(lock.Close()))
	}
	return lock, held, nil
}

func openData(dir string) (*sql.DB, error) {
	path := dir + "/state.db"
	if err := create(path); err != nil {
		return nil, wrap(err)
	}
	db, err := sql.Open("sqlite3", path+"?_synchronous=FULL&_foreign_keys=1&_busy_timeout=5000&_txlock=immediate")
	if err != nil {
		return nil, wrap(err)
	}
	db.SetMaxOpenConns(1)
	if err := prepare(db, path); err != nil {
		return nil, errors.Join(err, wrap(db.Close()))
	}
	// WAL lets other processes read while this one writes. The switch
	// rewrites the file, so it waits until the file is known to be a store.
	if _, err := db.Exec("PRAGMA journal_mode = WAL"); err != nil {
		return nil, errors.Join(wrap(err), wrap(db.Close()))
	}
	return db, nil
}

// create makes the file with mode 0600 before SQLite opens it, because
// SQLite gives its journal and WAL files the mode of the database file. It
// never opens a file that exists: closing any descriptor of a file drops
// every POSIX lock that this process holds on it, the lock of a Store that
// is open here included.
func create(path string) error {
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, fs.ErrExist) {
		return nil
	}
	if err != nil {
		return err
	}
	return f.Close()
}

func prepare(db *sql.DB, path string) error {
	var version, tables int
	if err := db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return wrap(err)
	}
	switch version {
	case 1:
		if err := migrate(db, upgrade2); err != nil {
			return err
		}
		return migrate(db, upgrade3)
	case 2:
		return migrate(db, upgrade3)
	case 3:
		return nil
	}
	if err := db.QueryRow("SELECT count(*) FROM sqlite_schema").Scan(&tables); err != nil {
		return wrap(err)
	}
	if version != 0 || tables != 0 {
		return notStore(path, version)
	}
	return migrate(db, schema)
}

func notStore(path string, version int) error {
	return fmt.Errorf("store: %s is not a store of this osk-dns-watcher (schema %d)", path, version)
}

// migrate runs ddl in one transaction, so that a failed upgrade leaves the
// store of the version before as it was.
func migrate(db *sql.DB, ddl string) error {
	tx, err := db.Begin()
	if err != nil {
		return wrap(err)
	}
	if _, err := tx.Exec(ddl); err != nil {
		return wrap(errors.Join(err, tx.Rollback()))
	}
	return wrap(tx.Commit())
}

// inTx runs f in one transaction, which it commits only when f gives no
// error.
func (s *Store) inTx(f func(tx *sql.Tx) error) error {
	tx, err := s.db.Begin()
	if err != nil {
		return wrap(err)
	}
	if err := f(tx); err != nil {
		return wrap(errors.Join(err, tx.Rollback()))
	}
	return wrap(tx.Commit())
}

// Close closes the database, then ends the lock, so that the next writer
// starts only after this one is gone.
func (s *Store) Close() error {
	return wrap(errors.Join(s.db.Close(), s.held.Rollback(), s.lock.Close()))
}

func wrap(err error) error {
	if err == nil {
		return nil
	}
	return fmt.Errorf("store: %w", err)
}
