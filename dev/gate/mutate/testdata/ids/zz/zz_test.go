package zz

import "testing"

// It calls everything and checks nothing, so every mutant survives.
func TestSmoke(t *testing.T) {
	Late(1)
	_ = Verbose
	Gauge{}.Full(1)
	Pick(1)
}
