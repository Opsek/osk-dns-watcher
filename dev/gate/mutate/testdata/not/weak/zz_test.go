package zz

import "testing"

func TestAllowed(t *testing.T) {
	if !Allowed(false) || Allowed(true) {
		t.Error("Allowed is wrong")
	}
}

func TestDenied(t *testing.T) {
	_ = Denied(true)
}
