package observe

import (
	"net"
	"testing"
)

func TestDial(t *testing.T) {
	c, err := net.Dial("udp", "127.0.0.1:53")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}
