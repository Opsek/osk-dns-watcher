package zz

import "testing"

func TestPositive(t *testing.T) {
	if !Positive(5) || Positive(-5) {
		t.Error("Positive is wrong")
	}
}

func TestAtMost(t *testing.T) {
	if !AtMost(9) || !AtMost(10) || AtMost(11) {
		t.Error("AtMost is wrong")
	}
}
