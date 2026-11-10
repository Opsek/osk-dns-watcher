package store

import (
	"database/sql"
	"database/sql/driver"

	_ "github.com/mattn/go-sqlite3"
)

// Name is the name of the driver.
const Name = "sqlite3"

// Value is a value that the database can hold.
type Value = driver.Value

// Open opens a database in memory.
func Open() (*sql.DB, error) {
	return sql.Open(Name, ":memory:")
}
