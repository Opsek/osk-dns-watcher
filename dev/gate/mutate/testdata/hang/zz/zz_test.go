package zz

import "testing"

func TestCountdown(t *testing.T) {
	if Countdown(3) != 3 || Countdown(0) != 0 {
		t.Error("Countdown is wrong")
	}
}
