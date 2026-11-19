package b

import (
	"crypto/tls"
	"syscall"
)

// Socket opens a socket without package net. Only no-exec reports syscall.
func Socket() (int, error) {
	return syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, 0)
}

// Serve listens through package crypto/tls; dialing out is allowed.
func Serve(config *tls.Config) {
	l, _ := tls.Listen("tcp", ":443", config)
	_ = tls.NewListener(l, config)
	_, _ = tls.Dial("tcp", "192.0.2.1:443", config)
}
