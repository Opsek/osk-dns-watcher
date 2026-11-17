package zz

import "testing"

func TestEither(t *testing.T) {
	if !Either(true, true) || Either(false, false) {
		t.Error("Either is wrong")
	}
}

func TestOthers(t *testing.T) {
	for _, a := range []bool{false, true} {
		for _, b := range []bool{false, true} {
			if Both(a, b) != (a && b) || Alt(a, b) != (a || b) {
				t.Errorf("wrong result for %v %v", a, b)
			}
		}
	}
}
