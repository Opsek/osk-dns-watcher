package httpclient

import (
	"context"
	"net"
	"net/netip"
	"strings"
	"time"
)

// addrTimeout bounds the connect to one address. A dead address, such as one
// behind a broken IPv6 path, must leave time for the next one within the
// request; a server that works answers in a fraction of it.
const addrTimeout = 3 * time.Second

// maxAddrs is the most addresses that one request dials. A real host needs
// one of each family and maybe a spare; a zone that lists thousands must not
// make each fetch send a packet to every one.
const maxAddrs = 4

// errRefused is ErrNotPermitted with the first address that permit refused,
// as netip writes it: where the name led is what the operator must see.
type errRefused struct{ addr netip.Addr }

func (e errRefused) Error() string {
	if !e.addr.IsValid() { // a lookup that gave no address
		return ErrNotPermitted.Error()
	}
	return ErrNotPermitted.Error() + " (" + e.addr.String() + ")"
}

func (e errRefused) Unwrap() error { return ErrNotPermitted }

// guardedDial gives a dial function that looks up the host once, keeps the
// addresses that permit accepts, and connects to the first maxAddrs of them
// in turn. It dials each address itself: a dial by name would look the name
// up again, and that second answer could name another address. The lookup
// and the dials end with ctx, which send cancels when the request fails or
// times out.
func guardedDial(permit func(netip.Addr) bool) func(ctx context.Context, network, addr string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		switch network {
		case "tcp", "tcp4", "tcp6":
		default:
			return nil, net.UnknownNetworkError(network)
		}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		// A final dot makes the resolver look the name up as it is, never
		// with a domain of its search list after it. A name of one label
		// keeps none: Go finds such a name in /etc/hosts only without it,
		// and a policy host always has more than one label.
		if _, err := netip.ParseAddr(host); err != nil && strings.Contains(host, ".") {
			host += "."
		}
		ips, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
		d := net.Dialer{Timeout: addrTimeout}
		var refused netip.Addr
		var last error
		dialled := 0
		for _, ip := range ips {
			// The resolver gives an IPv4 address of /etc/hosts or of a literal
			// in the IPv4-mapped form, and a dial of that form goes to the IPv4
			// address: judge and dial the address that is really used.
			ip = ip.Unmap()
			if !permit(ip) {
				if !refused.IsValid() {
					refused = ip
				}
				continue
			}
			c, err := d.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
			if err == nil {
				return c, nil
			}
			last = err
			dialled++
			if dialled == maxAddrs {
				break
			}
		}
		if last == nil {
			return nil, errRefused{refused}
		}
		return nil, last
	}
}
