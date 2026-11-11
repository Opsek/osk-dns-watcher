package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
)

// query runs "osk query": it sends one query and prints the answer much as
// dig does, so the two can be compared line by line.
func query(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rd := flags.Bool("rd", false, "set RD, recursion desired")
	do := flags.Bool("do", false, "set DO, DNSSEC records wanted")
	cd := flags.Bool("cd", false, "set CD, checking disabled")
	tcp := flags.Bool("tcp", false, "use TCP from the start")
	timeout := flags.Duration("timeout", 5*time.Second, "time for the whole exchange")
	if err := flags.Parse(args); err != nil {
		return wrongUse(stderr, err.Error())
	}
	q, server, msg := parseQuery(flags.Args())
	if msg != "" {
		return wrongUse(stderr, msg)
	}
	if *timeout <= 0 {
		return wrongUse(stderr, "the timeout must be positive")
	}
	q.RecursionDesired, q.DNSSECOK, q.CheckingDisabled = *rd, *do, *cd
	q.Cookie = make([]byte, 8)
	_, _ = rand.Read(q.Cookie) // never fails: crypto/rand.Read crashes the program instead

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := dnswire.Exchange(ctx, server, q, *tcp)
	switch {
	case errors.Is(err, dnswire.ErrInvalidQuery):
		// A type that is no question of its own, such as AXFR or OPT.
		return wrongUse(stderr, err.Error())
	case err != nil:
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	return output(stdout, stderr, format(r.Msg))
}

func wrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk query: "+msg+"\n"+usage)
}

// parseQuery reads "@<server> <name> [<type>]". It returns a message when
// they are wrong.
func parseQuery(args []string) (dnswire.Query, netip.AddrPort, string) {
	var q dnswire.Query
	if len(args) < 2 || len(args) > 3 || !strings.HasPrefix(args[0], "@") {
		return q, netip.AddrPort{}, "want @<server> <name> [<type>] after the flags"
	}
	// Host names are refused: resolving one would trust a resolver.
	server, err := netip.ParseAddrPort(args[0][1:])
	if err != nil {
		addr, err := netip.ParseAddr(args[0][1:])
		if err != nil {
			return q, server, "the server must be an IP address with an optional port"
		}
		server = netip.AddrPortFrom(addr, 53)
	}
	if q.Name, err = dnswire.ParseName(args[1]); err != nil {
		return q, server, err.Error()
	}
	q.Type = dnswire.TypeA
	if len(args) == 3 {
		if q.Type, err = dnswire.ParseType(args[2]); err != nil {
			return q, server, err.Error()
		}
	}
	return q, server, ""
}

// format prints the answer: the header, the flags and counts, the EDNS data,
// then each section that has records. Text that comes from the network is
// printed only through Record.String, strconv.Quote or as hexadecimal.
func format(m *dnswire.Message) string {
	var b strings.Builder
	fmt.Fprintf(&b, ";; ->>HEADER<<- opcode: %v, status: %v, id: %d\n", m.Opcode, m.Rcode, m.ID)
	b.WriteString(";; flags:")
	for _, f := range []struct {
		set  bool
		name string
	}{
		{m.Response, "qr"}, {m.Authoritative, "aa"}, {m.Truncated, "tc"}, {m.RecursionDesired, "rd"},
		{m.RecursionAvailable, "ra"}, {m.AuthenticData, "ad"}, {m.CheckingDisabled, "cd"},
	} {
		if f.set {
			b.WriteString(" " + f.name)
		}
	}
	// The counts are those of the wire, so the OPT and TSIG records count,
	// although neither prints as a record.
	additional := len(m.Additional)
	if m.EDNS != nil {
		additional++
	}
	if m.HasTSIG() {
		additional++
	}
	fmt.Fprintf(&b, "; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d\n",
		len(m.Question), len(m.Answer), len(m.Authority), additional)
	if e := m.EDNS; e != nil {
		flags := ""
		if e.DO {
			flags = " do"
		}
		fmt.Fprintf(&b, "; EDNS: version: %d, flags:%s; udp: %d\n", e.Version, flags, e.UDPSize)
		if client, server, ok := e.Cookie(); ok {
			fmt.Fprintf(&b, "; COOKIE: %x%x\n", client, server)
		}
		for _, x := range e.ExtendedErrors() {
			fmt.Fprintf(&b, "; EDE: %d %s\n", x.InfoCode, strconv.Quote(x.ExtraText))
		}
	}
	for _, s := range []struct {
		name    string
		records []dnswire.Record
	}{{"ANSWER", m.Answer}, {"AUTHORITY", m.Authority}, {"ADDITIONAL", m.Additional}} {
		if len(s.records) == 0 {
			continue
		}
		b.WriteString(";; " + s.name + " SECTION:\n")
		for _, r := range s.records {
			b.WriteString(r.String() + "\n")
		}
	}
	return b.String()
}
