package expect

import "net/netip"

// Valid reports whether the address is valid.
func Valid(a netip.Addr) bool {
	return a.IsValid()
}
