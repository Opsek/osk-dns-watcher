package observe

import (
	"database/sql"
	"testing"

	"osk/internal/store"
)

// A test file is not linked into the tool, so it may use the database.
func TestStore(t *testing.T) {
	db, err := sql.Open(store.Name, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
}
