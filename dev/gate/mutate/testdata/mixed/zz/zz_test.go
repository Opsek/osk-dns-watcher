package zz

import "testing"

func TestJoin(t *testing.T) {
	if Join("a", "b") != "ab" {
		t.Error("Join is wrong")
	}
}

func TestIsZero(t *testing.T) {
	if !IsZero(0) || IsZero(1) {
		t.Error("IsZero is wrong")
	}
}

func TestIsSet(t *testing.T) {
	_ = IsSet(3)
}
