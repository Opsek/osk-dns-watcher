package a

import "os"

// Pid returns the process ID.
func Pid() int {
	return os.Getpid()
}
