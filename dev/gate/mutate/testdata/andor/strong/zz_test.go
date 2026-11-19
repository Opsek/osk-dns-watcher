package zz

import "testing"

func TestTables(t *testing.T) {
	for _, a := range []bool{false, true} {
		for _, b := range []bool{false, true} {
			if Both(a, b) != (a && b) || Either(a, b) != (a || b) || Alt(a, b) != (a || b) {
				t.Errorf("wrong result for %v %v", a, b)
			}
		}
	}
}
