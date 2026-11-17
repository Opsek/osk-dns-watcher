package zz

import "testing"

func TestChanged(t *testing.T) {
	Changed(Record{"a", "b"})
}

func TestIsZero(t *testing.T) {
	if !IsZero(0) || IsZero(1) {
		t.Error("IsZero is wrong")
	}
}
