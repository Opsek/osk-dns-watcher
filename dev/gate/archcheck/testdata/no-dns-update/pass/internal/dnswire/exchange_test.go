package dnswire

import (
	"net"
	"testing"
)

// A test is not part of the tool, so it may write to any socket.
func TestWrite(t *testing.T) {
	c, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	_, _ = c.Write([]byte{0})
}
