package zz

import (
	"os"
	"testing"
)

func TestMain(m *testing.M) {
	os.Exit(1)
}

func TestIsZero(t *testing.T) {
	if !IsZero(0) || IsZero(1) {
		t.Error("IsZero is wrong")
	}
}
