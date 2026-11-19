package zz

import (
	"flag"
	"os"
	"testing"
)

// The first run of the tests of a mutant never returns, as when the machine
// is too busy to finish in time; a run after it ends at once. The baseline
// run is told apart by the missing -test.failfast.
func TestIsZero(t *testing.T) {
	if f := flag.Lookup("test.failfast"); f != nil && f.Value.String() == "true" {
		if _, err := os.Stat("seen"); err != nil {
			if err := os.WriteFile("seen", nil, 0o600); err != nil {
				t.Fatal(err)
			}
			select {}
		}
	}
	if !IsZero(0) || IsZero(1) {
		t.Error("IsZero is wrong")
	}
}
