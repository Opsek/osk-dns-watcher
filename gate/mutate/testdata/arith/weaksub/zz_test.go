package zz

import "testing"

func TestArith(t *testing.T) {
	if Add(2, 3) != 5 || Sub(5, 0) != 5 || Greet("x") != "hi x" {
		t.Error("wrong result")
	}
}
