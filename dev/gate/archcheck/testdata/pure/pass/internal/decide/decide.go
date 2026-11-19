package decide

import (
	"errors"
	"fmt"
	"time"

	"osk/internal/expect"
	"osk/internal/observe/obs"
)

// Decide judges an observation made at t against one made at u. After is the
// method of time.Time, which reads no clock, not the function of package time.
func Decide(f expect.File, key obs.Key, t, u time.Time) (string, error) {
	if !t.After(u) {
		return "", errors.New("the observation is not newer")
	}
	return fmt.Sprintf("%s in %s at %s", key.Name, f[key.Name], t.Format(time.RFC3339)), nil
}
