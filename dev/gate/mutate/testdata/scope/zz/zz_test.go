package zz

import "testing"

func TestBoth(t *testing.T) {
	got, want := IsZero(0), true
	if got != want || IsZero(1) || IsSet(0) || !IsSet(1) {
		t.Error("wrong result")
	}
}
