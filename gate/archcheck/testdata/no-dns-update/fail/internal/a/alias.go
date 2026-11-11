package a

import n "net"

// Secure dials through an alias.
func Secure() (n.Conn, error) {
	d := &n.Dialer{}
	return d.Dial("tcp", "192.0.2.1:853")
}
