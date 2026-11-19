package observe

import (
	"net"
	"net/http"
)

// Dial dials out, which is allowed.
func Dial() (net.Conn, error) {
	return net.Dial("udp", "192.0.2.53:53")
}

// Client makes requests, which is allowed.
var Client = http.Client{}
