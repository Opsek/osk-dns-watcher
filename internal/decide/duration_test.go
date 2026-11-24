package decide

import (
	"testing"
	"time"
)

func TestShortDuration(t *testing.T) {
	for _, c := range []struct {
		d    time.Duration
		want string
	}{
		{-time.Second, "0 s"},
		{999 * time.Millisecond, "0 s"},
		{25 * time.Second, "25 s"},
		{5 * time.Minute, "5 min"},
		{15 * time.Minute, "15 min"},
		{2*time.Minute + time.Second, "2 min 1 s"},
		{time.Hour, "1 h"},
		{90 * time.Minute, "1 h 30 min"},
		{3 * time.Hour, "3 h"},
		{25 * time.Hour, "1 d 1 h"},
	} {
		if got := ShortDuration(c.d); got != c.want {
			t.Errorf("ShortDuration(%v) = %q, want %q", c.d, got, c.want)
		}
	}
}
