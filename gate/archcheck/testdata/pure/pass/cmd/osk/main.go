package main

import (
	"fmt"
	"time"

	"osk/internal/decide"
	"osk/internal/expect"
	"osk/internal/observe/obs"
)

// The tool reads the clock and hands the time to decide.
func main() {
	now := time.Now()
	fmt.Println(decide.Decide(expect.File{}, obs.Key{Name: "example.test."}, now, now.Add(-time.Minute)))
}
