package c

import t "crypto/tls"

// Secure dials over TLS through an alias.
func Secure() error {
	d := &t.Dialer{Config: &t.Config{}}
	_, err := d.Dial("tcp", "192.0.2.1:853")
	return err
}
