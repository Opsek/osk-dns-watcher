package a

import (
	"os/exec"
	"testing"
)

// A test file is not linked into the tool, so it may start a process.
func TestPid(t *testing.T) {
	if err := exec.Command("true").Run(); err != nil {
		t.Fatal(err)
	}
}
