package a

import u "unsafe"

// Size returns the size of an int.
func Size(string) int {
	return int(u.Sizeof(0))
}
