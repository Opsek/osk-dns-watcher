package zz

import "testing"

func TestArith(t *testing.T) {
	if Add(2, 0) != 2 || Sub(5, 3) != 2 || Greet("x") != "hi x" {
		t.Error("wrong result")
	}
}
