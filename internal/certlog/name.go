package certlog

import (
	"strings"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// ldh are the octets of a label of a host name.
const ldh = "abcdefghijklmnopqrstuvwxyz0123456789-"

// Name reads one DNS name of a certificate: ASCII letters in either case,
// at most one trailing dot, labels of a-z, 0-9 and "-", and "*" as a whole
// first label only.
func Name(s string) (dnswire.Name, bool) {
	s = strings.TrimSuffix(lower(s), ".")
	// ParseName would read the empty text as the root.
	if s == "" {
		return dnswire.Name{}, false
	}
	for i, l := range strings.Split(s, ".") {
		if strings.Trim(l, ldh) != "" && !(i == 0 && l == "*") {
			return dnswire.Name{}, false
		}
	}
	// ParseName refuses an empty label, a label of more than 63 octets and a
	// name of more than 253.
	n, err := dnswire.ParseName(s + ".")
	return n, err == nil
}

// lower turns A-Z into a-z and leaves every other character as it is.
// strings.ToLower would also turn the Kelvin sign into an ASCII "k".
func lower(s string) string {
	return strings.Map(func(r rune) rune {
		if 'A' <= r && r <= 'Z' {
			return r + 'a' - 'A'
		}
		return r
	}, s)
}
