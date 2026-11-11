package c

import "crypto/tls"

// Probe dials over TLS.
func Probe() error {
	c, err := tls.Dial("tcp", "192.0.2.1:853", nil)
	if err != nil {
		return err
	}
	return c.Close()
}
