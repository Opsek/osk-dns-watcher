package zz

import "testing"

func TestNeverBuilt(t *testing.T) {
	if !IsZero(0) || !missing {
		t.Error("wrong result")
	}
}
