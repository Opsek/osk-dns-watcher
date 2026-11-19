package zz

import "testing"

func TestDefault(t *testing.T) {
	if !Default() {
		t.Error("Default is false")
	}
}

func TestOff(t *testing.T) {
	if Off() {
		t.Error("Off is true")
	}
}
