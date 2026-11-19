package store

import (
	"database/sql"

	_ "github.com/mattn/go-sqlite3"
)

// Name is the name of the driver.
const Name = "sqlite3"

// Open opens a database in memory.
func Open() (*sql.DB, error) {
	return sql.Open(Name, ":memory:")
}
