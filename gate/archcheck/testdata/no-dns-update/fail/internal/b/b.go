package b

import . "net"

// Probe dials after a dot import.
func Probe() error {
	c, err := DialUDP("udp", nil, &UDPAddr{Port: 53})
	if err != nil {
		return err
	}
	return c.Close()
}
