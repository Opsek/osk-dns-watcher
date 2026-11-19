package cache

import (
	"database/sql/driver"

	"osk/internal/store"
)

// Name is the name of the store behind the cache.
var Name = store.Name

// Value is a value that the database can hold.
type Value = driver.Value
