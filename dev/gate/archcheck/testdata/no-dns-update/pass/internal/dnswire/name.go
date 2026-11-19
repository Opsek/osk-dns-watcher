package dnswire

import "net/netip"

// Loopback comes from net/netip, which is not net.
var Loopback = netip.MustParseAddr("127.0.0.1")
