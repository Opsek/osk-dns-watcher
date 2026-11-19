package observe

import (
	"net/netip"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// rootHints are the root servers of the root hints file named.root that IANA
// publishes, last updated November 03, 2026 (root zone version 2026110301).
// They change rarely, and a walk needs only one of them to answer.
var rootHints = []struct{ name, addr string }{
	{"a.root-servers.net.", "198.41.0.4"},
	{"a.root-servers.net.", "2001:503:ba3e::2:30"},
	{"b.root-servers.net.", "170.247.170.2"},
	{"b.root-servers.net.", "2801:1b8:10::b"},
	{"c.root-servers.net.", "192.33.4.12"},
	{"c.root-servers.net.", "2001:500:2::c"},
	{"d.root-servers.net.", "199.7.91.13"},
	{"d.root-servers.net.", "2001:500:2d::d"},
	{"e.root-servers.net.", "192.203.230.10"},
	{"e.root-servers.net.", "2001:500:a8::e"},
	{"f.root-servers.net.", "192.5.5.241"},
	{"f.root-servers.net.", "2001:500:2f::f"},
	{"g.root-servers.net.", "192.112.36.4"},
	{"g.root-servers.net.", "2001:500:12::d0d"},
	{"h.root-servers.net.", "198.97.190.53"},
	{"h.root-servers.net.", "2001:500:1::53"},
	{"i.root-servers.net.", "192.36.148.17"},
	{"i.root-servers.net.", "2001:7fe::53"},
	{"j.root-servers.net.", "192.58.128.30"},
	{"j.root-servers.net.", "2001:503:c27::2:30"},
	{"k.root-servers.net.", "193.0.14.129"},
	{"k.root-servers.net.", "2001:7fd::1"},
	{"l.root-servers.net.", "199.7.83.42"},
	{"l.root-servers.net.", "2001:500:9f::42"},
	{"m.root-servers.net.", "202.12.27.33"},
	{"m.root-servers.net.", "2001:dc3::35"},
}

func builtinRoots() []obs.Server {
	servers := make([]obs.Server, 0, len(rootHints))
	for _, h := range rootHints {
		name, err := dnswire.ParseName(h.name)
		if err != nil {
			panic(err) // the table is fixed, so this is a bug in it
		}
		servers = append(servers, obs.Server{Name: name, Addr: netip.AddrPortFrom(netip.MustParseAddr(h.addr), 53)})
	}
	return servers
}
