package zz

import "testing"

func TestOne(t *testing.T) {
	if One() != 1 {
		t.Error("One is wrong")
	}
}
