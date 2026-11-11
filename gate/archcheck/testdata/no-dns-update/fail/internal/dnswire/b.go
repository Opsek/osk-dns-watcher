package dnswire

import n "net"

// Local needs package net under another name.
var Local = n.IPv4(127, 0, 0, 1)
