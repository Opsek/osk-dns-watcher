package decide

import (
	"slices"
	"strconv"
	"time"
)

// ShortDuration writes d, cut to whole seconds: its largest unit that is not
// zero, and the next smaller unit when that one is not zero either. Every
// message uses this form, such as "15 min" or "2 min 1 s". It lives here
// because deliver imports decide, and a Value of this package needs it too.
func ShortDuration(d time.Duration) string {
	left := max(int64(d/time.Second), 0)
	var amounts []int64
	names := []string{"d", "h", "min", "s"}
	for _, secs := range []int64{86400, 3600, 60, 1} {
		amounts = append(amounts, left/secs)
		left %= secs
	}
	i := slices.IndexFunc(amounts, func(n int64) bool { return n > 0 })
	if i < 0 {
		return "0 s"
	}
	out := strconv.FormatInt(amounts[i], 10) + " " + names[i]
	if i+1 < len(amounts) && amounts[i+1] > 0 {
		out += " " + strconv.FormatInt(amounts[i+1], 10) + " " + names[i+1]
	}
	return out
}
