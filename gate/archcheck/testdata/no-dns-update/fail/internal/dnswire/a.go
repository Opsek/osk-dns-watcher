package dnswire

import "net"

// Resolve reaches the network from a file other than transport.go.
func Resolve(host string) ([]net.IP, error) {
	return net.LookupIP(host)
}
