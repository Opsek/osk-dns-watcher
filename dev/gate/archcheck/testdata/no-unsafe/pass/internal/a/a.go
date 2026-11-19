package a

import "unicode/utf8"

// Size returns the length of a name in runes.
func Size(s string) int {
	return utf8.RuneCountInString(s)
}
