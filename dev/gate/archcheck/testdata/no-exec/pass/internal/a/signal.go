package a

import (
	"os/signal"
	"syscall"
)

// Quiet ignores the two signals that the tool may name.
func Quiet() {
	signal.Ignore(syscall.SIGPIPE, syscall.SIGTERM)
}
