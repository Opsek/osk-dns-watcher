package zz

import "testing"

func TestPositive(t *testing.T) {
	if !Positive(5) || Positive(-5) {
		t.Error("Positive is wrong")
	}
}
