package fake

import "net"

// Dial is in a testdata folder, which the go command does not build.
func Dial() (net.Conn, error) {
	return net.Dial("udp", "127.0.0.1:53")
}
