package expect

import (
	"net/netip"
	"os"
)

// Valid reports whether the address is valid and the host has a name.
func Valid(a netip.Addr) bool {
	_, err := os.Hostname()
	return err == nil && a.IsValid()
}
