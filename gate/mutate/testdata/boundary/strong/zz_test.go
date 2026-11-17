package zz_test

import (
	"testing"

	zz "zz/strong"
)

func TestPositive(t *testing.T) {
	if !zz.Positive(5) || zz.Positive(0) || zz.Positive(-5) {
		t.Error("Positive is wrong")
	}
}

func TestAtMost(t *testing.T) {
	if !zz.AtMost(9) || !zz.AtMost(10) || zz.AtMost(11) {
		t.Error("AtMost is wrong")
	}
}
