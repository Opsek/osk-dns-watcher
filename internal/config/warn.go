package config

import (
	"net/netip"
	"strings"
)

// Warnings gives one line for each setting that weakens a default
// protection: other root servers decide every answer, and extra ranges let
// data from DNS steer queries into a private network.
func (c *Config) Warnings() []string {
	var lines []string
	if len(c.RootServers) > 0 {
		servers := make([]string, len(c.RootServers))
		for i, s := range c.RootServers {
			if s.Port() == 0 {
				s = netip.AddrPortFrom(s.Addr(), 53)
			}
			servers[i] = s.String()
		}
		lines = append(lines, "network.root_servers is set: osk starts its walk at "+strings.Join(servers, ", ")+
			" instead of the root servers of the internet, so these servers decide every answer."+
			" Use it only in a lab or a private network.")
	}
	if len(c.ExtraRanges) > 0 {
		ranges := make([]string, len(c.ExtraRanges))
		for i, p := range c.ExtraRanges {
			ranges[i] = p.String()
		}
		lines = append(lines, "network.extra_ranges is set: data from DNS can now make osk send queries to "+
			strings.Join(ranges, ", ")+". Use it only in a lab or a private network.")
	}
	return lines
}
