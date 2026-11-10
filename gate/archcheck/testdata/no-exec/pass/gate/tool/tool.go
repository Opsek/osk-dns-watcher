package tool

import (
	"os/exec"

	_ "osk/internal/_old"
)

// Run is in a folder named gate.
func Run() error {
	return exec.Command("true").Run()
}
