package observe

import (
	"net/netip"
	"testing"
)

// Permitted is the rule of a query for a connection that DNS chose: the same
// answer as permitted on the cases that the rule is tested on.
func TestGrdPermittedIsTheQueryRule(t *testing.T) {
	for _, c := range []struct {
		addr  string
		extra []netip.Prefix
		want  bool
	}{
		{"8.8.8.8", nil, true},
		{"2606:4700:4700::1111", nil, true},
		{"127.0.0.1", nil, false},
		{"169.254.169.254", nil, false},
		{"168.63.129.16", nil, false},
		{"168.63.129.15", nil, true},
		{"168.63.129.17", nil, true},
		{"168.63.129.16", askPrefixes("168.63.129.16/32"), true},
		{"127.0.0.1", askPrefixes("127.0.0.0/8"), true},
		{"10.53.7.255", askPrefixes("10.53.7.0/24"), true},
		{"10.53.8.0", askPrefixes("10.53.7.0/24"), false},
		{"fd53:0:0:7::11", askPrefixes("fd53:0:0:7::/64"), true},
		{"::ffff:8.8.8.8", nil, false},
		{"::ffff:127.0.0.1", askPrefixes("127.0.0.0/8"), false},
		{"fe80::1%eth0", askPrefixes("fe80::/10"), false},
		{"2001:4860:4860::8888%eth0", askPrefixes("::/0"), false},
	} {
		a := netip.MustParseAddr(c.addr)
		if got := Permitted(a, c.extra); got != c.want || got != permitted(a, c.extra) {
			t.Errorf("Permitted(%v, %v) = %v; want %v, as permitted gives", a, c.extra, got, c.want)
		}
	}
}
