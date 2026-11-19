package httpclient

import "net"

// Dialer is let through in this file, and no other name that dials.
var Dialer = net.Dialer{}

// Dial is not.
var Dial = net.Dial
