package a

import (
	"errors"
	"os/signal"
	"syscall"
)

// Quiet ignores the two signals that the tool may name.
func Quiet() {
	signal.Ignore(syscall.SIGPIPE, syscall.SIGTERM)
}

// NoRoute names the three errors of a dial that the tool may name.
func NoRoute(err error) bool {
	return errors.Is(err, syscall.ENETUNREACH) || errors.Is(err, syscall.EADDRNOTAVAIL) || errors.Is(err, syscall.EAFNOSUPPORT)
}
