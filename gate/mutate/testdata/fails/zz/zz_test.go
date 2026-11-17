package zz

import "testing"

func TestAlwaysFails(t *testing.T) {
	t.Fatal("fails without a mutant")
}
