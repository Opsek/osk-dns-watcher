package a

import "net"

// Query dials in two ways.
func Query() error {
	c, err := net.Dial("udp", "192.0.2.53:53")
	if err != nil {
		return err
	}
	var d net.Dialer
	_, _ = c, d
	return nil
}
