package main

import (
	"fmt"
	"net"
	"time"
)

func main() {
	c, err := net.DialTimeout("udp", "192.0.2.53:53", time.Second)
	fmt.Println(c, err)
}
