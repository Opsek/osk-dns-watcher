package decide

import (
	"fmt"
	"os"
	"time"

	"osk/internal/observe"
)

// Decide reads the environment and the clock, asks the engine and prints.
func Decide() time.Time {
	fmt.Println(os.Getenv("HOME"), observe.Name)
	return time.Now()
}
