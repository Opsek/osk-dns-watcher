package a

import (
	"testing"
	"unsafe"
)

// A test file is not linked into the tool, so it may use unsafe.
func TestSize(t *testing.T) {
	if unsafe.Sizeof(0) == 0 {
		t.Fatal("no size")
	}
}
