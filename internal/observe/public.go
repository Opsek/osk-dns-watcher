package observe

import (
	"net/netip"
	"slices"
)

// globalUnicast is the one IPv6 block where public addresses live. Outside
// it lie, among others, ::, ::1, the IPv4-mapped and translation prefixes
// (they embed IPv4 addresses that the IPv4 list would refuse), unique-local,
// link-local and multicast addresses.
var globalUnicast = netip.MustParsePrefix("2000::/3")

// notPublic holds the blocks of the special-purpose registries (RFC 6890)
// that are not globally reachable, and multicast. A few small reachable
// blocks inside them, such as 192.0.0.9/32 and the AS112 block in
// 2001::/23, are refused too: no nameserver of a watched domain lives there.
var notPublic = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("127.0.0.0/8"),
	netip.MustParsePrefix("169.254.0.0/16"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("224.0.0.0/4"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"), // 6to4 embeds an IPv4 address
	netip.MustParsePrefix("3fff::/20"),
}

// public reports whether a server at a may be asked without a permitted
// range. A zone ties an address to one link of this machine. An IPv4-mapped
// address is judged as IPv6, so it is never public: unmapping it would let
// a server reach an IPv4 address through a second spelling.
func public(a netip.Addr) bool {
	if !a.IsValid() || a.Zone() != "" {
		return false
	}
	if a.Is6() && !globalUnicast.Contains(a) {
		return false
	}
	return !slices.ContainsFunc(notPublic, func(p netip.Prefix) bool { return p.Contains(a) })
}

// permitted reports whether a query may go to a. A prefix contains neither
// an address with a zone nor the IPv4-mapped form of its IPv4 addresses.
func permitted(a netip.Addr, extra []netip.Prefix) bool {
	return public(a) || slices.ContainsFunc(extra, func(p netip.Prefix) bool { return p.Contains(a) })
}
