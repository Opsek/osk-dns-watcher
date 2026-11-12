package decide

import . "time"

// Age reads the clock through a dot import.
func Age(t Time) Duration {
	return Since(t)
}
