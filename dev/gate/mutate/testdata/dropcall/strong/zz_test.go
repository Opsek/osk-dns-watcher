package zz

import "testing"

func TestPair(t *testing.T) {
	var a, b Counter
	Pair(&a, &b)
	if a.n != 1 || b.n != 1 {
		t.Errorf("counts %d %d, want 1 1", a.n, b.n)
	}
}

func TestMust(t *testing.T) {
	Must(false)
	defer func() {
		if recover() == nil {
			t.Error("Must(true) did not panic")
		}
	}()
	Must(true)
}
