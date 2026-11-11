package main

import (
	"context"
	"fmt"
	"net"

	"osk/internal/dnswire"
	"osk/internal/observe"
)

// The standard resolver sends only queries, so it may be used anywhere.
func main() {
	var r net.Resolver
	addrs, err := r.LookupHost(context.Background(), "example.test")
	fmt.Println(addrs, err, dnswire.Exchange, observe.Dial(), observe.TLS)
}
