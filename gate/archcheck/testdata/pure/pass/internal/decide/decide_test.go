package decide

import (
	"os"
	"testing"
	"time"

	"osk/internal/expect"
	"osk/internal/observe/obs"
)

// A test file is not linked into the tool, so it may read the clock and the
// environment.
func TestDecide(t *testing.T) {
	now := time.Now()
	if _, err := Decide(expect.File{}, obs.Key{Name: "example.test."}, now, now); err == nil {
		t.Fatal("an observation at the same time counts as newer")
	}
	t.Log(os.Getpid())
}
