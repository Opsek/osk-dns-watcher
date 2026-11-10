package a

import "testing"

// A test file may be limited to a system.
func TestName(t *testing.T) {
	if Name == "" {
		t.Fatal("no name")
	}
}
