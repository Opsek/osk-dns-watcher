package c

import (
	"errors"
	"syscall"
)

// Refused names an error of syscall that the tool may not name beside one
// that it may.
func Refused(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.ECONNREFUSED)
}
