package schedule

import "time"

// Due reads the clock instead of taking the time from its caller.
func Due() time.Time {
	return time.Now()
}
