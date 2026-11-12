package expect

import (
	"net"

	wire "osk/internal/dnswire"
)

// Server is an address of package net.
var Server = net.IPv4(192, 0, 2, 53)

// Ask sends a query through the codec under another name.
func Ask(q []byte) ([]byte, error) {
	return wire.Exchange(q)
}
