package decide

import (
	"net/netip"

	"osk/internal/expect"
)

// Decide checks an address. A rule against net does not forbid net/netip.
func Decide(s string) bool {
	a, err := netip.ParseAddr(s)
	return err == nil && expect.Valid(a)
}
