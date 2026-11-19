package a

import (
	. "os"
	_ "os/exec"
	_ "plugin"
	sys "syscall"
)

// Pid returns the process ID after it starts two processes.
func Pid() int {
	_, _ = StartProcess("/bin/sh", nil, nil)
	_ = sys.Exec("/bin/sh", nil, nil)
	return Getpid()
}
