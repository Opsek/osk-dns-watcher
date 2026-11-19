package other

import "testing"

func TestO(t *testing.T) {
	if !O(9) {
		t.Error("O is wrong")
	}
}
