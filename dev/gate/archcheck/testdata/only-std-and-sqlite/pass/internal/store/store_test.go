package store

import (
	"testing"

	"example.com/testlib"
)

// A test file is not linked into the tool.
func TestOpen(t *testing.T) {
	testlib.Check(t, Name)
}
