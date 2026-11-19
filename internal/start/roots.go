package start

import (
	"context"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
)

// someRoots are two of the root servers that osk-dns-watcher starts its walk at, run by
// two operators. Any two serve: the check asks who answers for them.
var someRoots = []netip.AddrPort{
	netip.MustParseAddrPort("198.41.0.4:53"),   // a.root-servers.net.
	netip.MustParseAddrPort("193.0.14.129:53"), // k.root-servers.net.
}

// rootTimeout is the time for one query, as observe gives it.
const rootTimeout = 2 * time.Second

// rootsAnswerDirectly reports whether the root servers themselves answer.
// Some networks answer DNS queries in their place (the DNS proxy of a VPN,
// a router or a provider), and then every answer osk-dns-watcher sees comes from them.
// It asks two root servers, the first two of roots when given, at once.
func rootsAnswerDirectly(ctx context.Context, roots []netip.AddrPort) bool {
	servers := someRoots
	if len(roots) > 0 {
		servers = roots[:min(2, len(roots))]
	}
	direct := make([]bool, len(servers))
	var wg sync.WaitGroup
	for i, s := range servers {
		if s.Port() == 0 {
			s = netip.AddrPortFrom(s.Addr(), 53)
		}
		wg.Go(func() { direct[i] = answersDirectly(ctx, s) })
	}
	wg.Wait()
	return !slices.Contains(direct, false)
}

// answersDirectly asks server for the NS set of the root over UDP, then over
// TCP, which osk-dns-watcher needs for large answers. No answer over UDP proves nothing:
// the checks of the domains then report what is wrong.
func answersDirectly(ctx context.Context, server netip.AddrPort) bool {
	m, err := askRoot(ctx, server, false)
	if err != nil {
		return true
	}
	if !fromRoot(m) {
		return false
	}
	m, err = askRoot(ctx, server, true)
	return err == nil && fromRoot(m)
}

func askRoot(ctx context.Context, server netip.AddrPort, tcp bool) (*dnswire.Message, error) {
	ctx, cancel := context.WithTimeout(ctx, rootTimeout)
	defer cancel()
	r, err := dnswire.Exchange(ctx, server, dnswire.Query{Type: dnswire.TypeNS}, tcp)
	if err != nil {
		return nil, err
	}
	return r.Msg, nil
}

// fromRoot reports an answer that only a root server gives to a query
// without recursion: with authority, without recursion, and with the NS set
// of the root. A proxy answers from its cache with recursion, or without
// authority.
func fromRoot(m *dnswire.Message) bool {
	return m.Authoritative && !m.RecursionAvailable && slices.ContainsFunc(m.Answer, func(r dnswire.Record) bool {
		_, ns := r.Data.(dnswire.NS)
		return ns && r.Class == dnswire.ClassINET && r.Name.LabelCount() == 0
	})
}
