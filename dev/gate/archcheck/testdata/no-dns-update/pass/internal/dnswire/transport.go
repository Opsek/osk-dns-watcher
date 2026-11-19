package dnswire

import (
	"context"
	"net"
)

// Exchange is the one place that opens a socket and writes to it.
func Exchange(ctx context.Context, server string, q []byte) ([]byte, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "udp", server)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	if err := writeQuery(c, q); err != nil {
		return nil, err
	}
	b := make([]byte, 65535)
	n, err := c.Read(b)
	return b[:n], err
}

// A function literal inside writeQuery is part of writeQuery.
func writeQuery(c net.Conn, q []byte) error {
	send := func() error {
		_, err := c.Write(q)
		return err
	}
	return send()
}
