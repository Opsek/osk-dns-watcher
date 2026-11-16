package store

import (
	"database/sql"
	"errors"

	_ "github.com/mattn/go-sqlite3"
)

// SQLiteVersion returns the version of the SQLite library linked into the tool.
func SQLiteVersion() (string, error) {
	db, err := sql.Open("sqlite3", ":memory:")
	if err != nil {
		return "", err
	}
	var version string
	err = db.QueryRow("SELECT sqlite_version()").Scan(&version)
	return version, errors.Join(err, db.Close())
}
