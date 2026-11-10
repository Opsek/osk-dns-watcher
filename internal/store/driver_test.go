package store

import (
	"strings"
	"testing"
)

func TestSQLiteVersion(t *testing.T) {
	version, err := SQLiteVersion()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(version, "3.") {
		t.Fatalf("SQLiteVersion() = %q, want a version that starts with 3.", version)
	}
}
