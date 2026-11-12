package observe

import (
	"bytes"
	"crypto/rand"
	"net/netip"
	"slices"
	"sync"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// cookieOption is the EDNS option code of DNS cookies (RFC 7873).
const cookieOption = 10

// maxCookieServers bounds the memory of the jar, however many servers are
// asked.
const maxCookieServers = 4096

// cookieJar holds the DNS cookies of each server address (RFC 7873): our
// client cookie, random for each server so that servers cannot link our
// queries, kept as long as the jar keeps the server so that a server can
// check it; and the server cookie of the last answer accepted.
type cookieJar struct {
	mu      sync.Mutex
	servers map[netip.AddrPort]*cookiePair
	order   []netip.AddrPort // the servers of the map, the oldest first
}

type cookiePair struct {
	client [8]byte
	server []byte
}

func newCookieJar() *cookieJar {
	return &cookieJar{servers: map[netip.AddrPort]*cookiePair{}}
}

// get returns the cookie option data to send to server, and the server
// cookie it holds, nil when none is known.
func (j *cookieJar) get(server netip.AddrPort) (data, serverCookie []byte) {
	j.mu.Lock()
	defer j.mu.Unlock()
	c := j.of(server)
	return slices.Concat(c.client[:], c.server), c.server
}

// accept checks the cookie of an answer from server to a query that carried
// the cookie option data sent, as get gave it. ok is false when the answer
// has a cookie option that is broken or does not carry the client cookie
// sent: such an answer was not made for our query, and nothing of it is
// kept. stored is the server cookie the answer brought, if any.
func (j *cookieJar) accept(server netip.AddrPort, sent []byte, m *dnswire.Message) (stored []byte, ok bool) {
	if m.EDNS == nil || !slices.ContainsFunc(m.EDNS.Options, func(o dnswire.Option) bool { return o.Code == cookieOption }) {
		return nil, true
	}
	client, serverCookie, valid := m.EDNS.Cookie()
	if !valid || !bytes.Equal(client, sent[:8]) {
		return nil, false
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	// The jar may have dropped the server while the query was out; a new
	// entry would hold another client cookie.
	c, kept := j.servers[server]
	if serverCookie == nil || !kept || !bytes.Equal(c.client[:], client) {
		return nil, true
	}
	c.server = slices.Clone(serverCookie)
	return c.server, true
}

// of returns the cookies of server, making the client cookie on first use.
// The caller holds j.mu.
func (j *cookieJar) of(server netip.AddrPort) *cookiePair {
	c, ok := j.servers[server]
	if !ok {
		if len(j.order) == maxCookieServers {
			delete(j.servers, j.order[0])
			j.order = j.order[1:]
		}
		c = &cookiePair{}
		_, _ = rand.Read(c.client[:]) // never fails: crypto/rand.Read crashes the program instead
		j.servers[server] = c
		j.order = append(j.order, server)
	}
	return c
}
