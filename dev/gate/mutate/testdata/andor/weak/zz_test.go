package zz

import "testing"

func TestBoth(t *testing.T) {
	if !Both(true, true) || Both(false, false) {
		t.Error("Both is wrong")
	}
}

func TestOthers(t *testing.T) {
	for _, a := range []bool{false, true} {
		for _, b := range []bool{false, true} {
			if Either(a, b) != (a || b) || Alt(a, b) != (a || b) {
				t.Errorf("wrong result for %v %v", a, b)
			}
		}
	}
}
