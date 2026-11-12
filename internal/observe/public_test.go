package observe

import (
	"math/rand/v2"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func askPrefixes(s ...string) []netip.Prefix {
	var ps []netip.Prefix
	for _, x := range s {
		ps = append(ps, netip.MustParsePrefix(x))
	}
	return ps
}

// The ranges that are not public. Inside 2000::/3 only askInner6 is not
// public; every IPv6 address outside 2000::/3 is not public.
var (
	askNotPublic4 = askPrefixes("0.0.0.0/8", "10.0.0.0/8", "100.64.0.0/10", "127.0.0.0/8", "169.254.0.0/16",
		"172.16.0.0/12", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "192.168.0.0/16", "198.18.0.0/15",
		"198.51.100.0/24", "203.0.113.0/24", "224.0.0.0/4", "240.0.0.0/4")
	askGlobal6 = netip.MustParsePrefix("2000::/3")
	askInner6  = askPrefixes("2001::/23", "2001:db8::/32", "2002::/16", "3fff::/20")
	// Outside 2000::/3: the ranges named for it, and the rest of the space.
	askOuter6 = askPrefixes("::/128", "::1/128", "::ffff:0:0/96", "64:ff9b::/96", "64:ff9b:1::/48", "100::/64",
		"fc00::/7", "fe80::/10", "ff00::/8", "::/3", "4000::/2", "8000::/1")
)

// askExpectPublic is the rule, from the lists above.
func askExpectPublic(a netip.Addr) bool {
	if a.Zone() != "" {
		return false
	}
	if a.Is6() && !askGlobal6.Contains(a) {
		return false
	}
	for _, p := range slices.Concat(askNotPublic4, askInner6) {
		if p.Contains(a) {
			return false
		}
	}
	return true
}

// askRandomIn draws an address of p: its prefix bits, random bits after.
func askRandomIn(rng *rand.Rand, p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		keep := min(max(p.Bits()-8*i, 0), 8)
		mask := byte(0xff << (8 - keep))
		b[i] = b[i]&mask | byte(rng.Uint32())&^mask
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func askRandom4(rng *rand.Rand) netip.Addr {
	return askRandomIn(rng, netip.MustParsePrefix("0.0.0.0/0"))
}

func TestPublicAddressProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 11))

	for _, p := range slices.Concat(askNotPublic4, askInner6, askOuter6) {
		for range 200 {
			if a := askRandomIn(rng, p); public(a) || permitted(a, nil) {
				t.Errorf("%v from %v is public", a, p)
			}
		}
	}

	var public4 []netip.Addr
	for range 20000 {
		a := askRandom4(rng)
		if want := askExpectPublic(a); public(a) != want || permitted(a, nil) != want {
			t.Errorf("%v: public %v, want %v", a, public(a), want)
		}
		if askExpectPublic(a) {
			public4 = append(public4, a)
		}
	}
	for _, p := range askPrefixes("2000::/3", "::/0") {
		for range 20000 {
			a := askRandomIn(rng, p)
			if want := askExpectPublic(a); public(a) != want {
				t.Errorf("%v: public %v, want %v", a, public(a), want)
			}
		}
	}

	// An IPv4-mapped address is never read as the IPv4 address in it.
	for _, a := range public4[:200] {
		mapped := netip.AddrFrom16(a.As16())
		if public(mapped) || permitted(mapped, askPrefixes("0.0.0.0/0")) {
			t.Errorf("%v, the mapped form of public %v, is public or permitted by an IPv4 range", mapped, a)
		}
	}

	// An extra range permits exactly its own addresses.
	for _, extra := range askPrefixes("10.53.7.0/24", "127.0.0.0/8", "192.0.2.128/25", "fd53:0:0:7::/64", "fe80::/64") {
		for range 500 {
			if a := askRandomIn(rng, extra); !permitted(a, []netip.Prefix{extra}) {
				t.Errorf("%v is not permitted by the extra range %v", a, extra)
			}
		}
		last := askLast(extra)
		for _, a := range []netip.Addr{extra.Addr().Prev(), last.Next()} {
			if a.IsValid() && permitted(a, []netip.Prefix{extra}) != askExpectPublic(a) {
				t.Errorf("%v next to the extra range %v: permitted %v, want %v", a, extra, !askExpectPublic(a), askExpectPublic(a))
			}
		}
		for _, a := range []netip.Addr{askRandomIn(rng, netip.MustParsePrefix("10.0.0.0/8")), askRandomIn(rng, netip.MustParsePrefix("fc00::/7"))} {
			if !extra.Contains(a) && permitted(a, []netip.Prefix{extra}) {
				t.Errorf("%v outside the extra range %v is permitted", a, extra)
			}
		}
	}
}

// askLast is the last address of p.
func askLast(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().AsSlice()
	for i := range b {
		keep := min(max(p.Bits()-8*i, 0), 8)
		b[i] |= byte(0xff >> keep)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

func TestAskPublicBoundaries(t *testing.T) {
	for _, p := range slices.Concat(askNotPublic4, askInner6, askOuter6) {
		for _, a := range []netip.Addr{p.Masked().Addr(), askLast(p), p.Masked().Addr().Prev(), askLast(p).Next()} {
			if a.IsValid() && public(a) != askExpectPublic(a) {
				t.Errorf("%v at the edge of %v: public %v, want %v", a, p, public(a), askExpectPublic(a))
			}
		}
	}
	for _, c := range []struct {
		addr   string
		public bool
	}{
		{"8.8.8.8", true},
		{"2606:4700:4700::1111", true},
		{"2000::", true},
		{"3fff:1000::", true},
		{"192.31.196.1", true},    // AS112, outside the list
		{"192.175.48.1", true},    // AS112, outside the list
		{"2620:4f:8000::1", true}, // AS112, outside the list
		{"192.0.0.9", false},      // reachable, but inside 192.0.0.0/24
		{"2001:4:112::1", false},  // AS112, inside 2001::/23
		{"2001:4860:4860::8888%eth0", false},
		{"fe80::1%eth0", false},
		{"::ffff:192.0.2.1", false},
		{"64:ff9b::808:808", false},
		{"2002:808:808::1", false},
	} {
		a := netip.MustParseAddr(c.addr)
		if public(a) != c.public {
			t.Errorf("%v: public %v, want %v", a, public(a), c.public)
		}
	}
}

// An address with a zone belongs to one link of this machine: no extra range
// permits it, not even the range that holds the address without its zone.
func TestAskZonedAddressNotPermitted(t *testing.T) {
	for _, c := range []struct{ addr, extra string }{
		{"fe80::1%eth0", "fe80::/10"},
		{"fd53:0:0:7::11%eth0", "fd53:0:0:7::/64"},
		{"2001:4860:4860::8888%eth0", "::/0"},
	} {
		a, extra := netip.MustParseAddr(c.addr), askPrefixes(c.extra)
		if public(a) || permitted(a, extra) {
			t.Errorf("%v with the extra range %v: public %v, permitted %v; want neither", a, c.extra, public(a), permitted(a, extra))
		}
	}
}
