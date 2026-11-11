package dnswire

import (
	"encoding/binary"
	"io"
	"net"
)

func writeQuery(c net.Conn, b []byte) error {
	_, err := c.Write(b)
	return err
}

// Every write below is outside writeQuery.

func reply(c net.PacketConn, to net.Addr, b []byte) error {
	if _, err := c.WriteTo(b, to); err != nil {
		return err
	}
	return binary.Write(c.(io.Writer), binary.BigEndian, uint16(len(b)))
}

func later(c net.Conn) func([]byte) error {
	return func(b []byte) error {
		_, err := c.Write(b)
		return err
	}
}

func direct(w io.Writer, b []byte) error {
	return WriteAll(w, b)
}

func WriteAll(w io.Writer, b []byte) error {
	_, err := w.Write(b)
	return err
}

// A method value writes when it is called later.
func deferred(c net.Conn) func([]byte) (int, error) {
	send := c.Write
	return send
}
