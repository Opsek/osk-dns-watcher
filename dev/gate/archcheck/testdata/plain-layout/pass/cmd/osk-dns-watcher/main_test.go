//go:build lab

package main

import (
	"testing"

	"osk/dev/gate/tool"
)

// A test file is not linked into the tool: it may have a build constraint and
// import a package outside cmd/ and internal/.
func TestName(t *testing.T) {
	if tool.Name == "" {
		t.Fatal("no name")
	}
}
