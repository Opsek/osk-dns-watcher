package zz

import "testing"

func TestOrdering(t *testing.T) {
	cases := []struct {
		x              int
		lt, le, gt, ge bool
	}{
		{-1, true, true, false, false},
		{1, false, false, true, true},
	}
	for _, c := range cases {
		if Lt(c.x) != c.lt || Le(c.x) != c.le || Gt(c.x) != c.gt || Ge(c.x) != c.ge {
			t.Errorf("wrong result for %d", c.x)
		}
	}
}
