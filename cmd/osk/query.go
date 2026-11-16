package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
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
// dig does, so the two can be compared line by line. With --json, each line
// is a JSON object.
func query(args []string, stdout, stderr io.Writer) int {
	flags := flag.NewFlagSet("query", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	rd := flags.Bool("rd", false, "set RD, recursion desired")
	do := flags.Bool("do", false, "set DO, DNSSEC records wanted")
	cd := flags.Bool("cd", false, "set CD, checking disabled")
	tcp := flags.Bool("tcp", false, "use TCP from the start")
	timeout := flags.Duration("timeout", 5*time.Second, "time for the whole exchange")
	asJSON := flags.Bool("json", false, "print JSON Lines")
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
	out := &lines{json: *asJSON}
	format(out, r.Msg)
	return output(stdout, stderr, out.String())
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
func format(out *lines, m *dnswire.Message) {
	flags := []string{}
	for _, f := range []struct {
		set  bool
		name string
	}{
		{m.Response, "qr"}, {m.Authoritative, "aa"}, {m.Truncated, "tc"}, {m.RecursionDesired, "rd"},
		{m.RecursionAvailable, "ra"}, {m.AuthenticData, "ad"}, {m.CheckingDisabled, "cd"},
	} {
		if f.set {
			flags = append(flags, f.name)
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
	header := fmt.Sprintf(";; ->>HEADER<<- opcode: %v, status: %v, id: %d", m.Opcode, m.Rcode, m.ID)
	out.add(header, struct {
		Type   string   `json:"type"`
		Opcode string   `json:"opcode"`
		Status string   `json:"status"`
		ID     int      `json:"id"`
		Flags  []string `json:"flags"`
	}{"header", fmt.Sprint(m.Opcode), fmt.Sprint(m.Rcode), int(m.ID), flags})
	counts := fmt.Sprintf(";; flags:%s; QUERY: %d, ANSWER: %d, AUTHORITY: %d, ADDITIONAL: %d",
		strings.Join(append([]string{""}, flags...), " "), len(m.Question), len(m.Answer), len(m.Authority), additional)
	out.add(counts, struct {
		Type       string `json:"type"`
		Query      int    `json:"query"`
		Answer     int    `json:"answer"`
		Authority  int    `json:"authority"`
		Additional int    `json:"additional"`
	}{"counts", len(m.Question), len(m.Answer), len(m.Authority), additional})
	if m.EDNS != nil {
		formatEDNS(out, m.EDNS)
	}
	for _, s := range []struct {
		name    string
		records []dnswire.Record
	}{{"ANSWER", m.Answer}, {"AUTHORITY", m.Authority}, {"ADDITIONAL", m.Additional}} {
		if len(s.records) == 0 {
			continue
		}
		if !out.json {
			out.add(";; "+s.name+" SECTION:", nil)
		}
		for _, r := range s.records {
			out.add(r.String(), struct {
				Type    string `json:"type"`
				Section string `json:"section"`
				Text    string `json:"text"`
			}{"record", strings.ToLower(s.name), r.String()})
		}
	}
}

func formatEDNS(out *lines, e *dnswire.EDNS) {
	flags, words := []string{}, ""
	if e.DO {
		flags, words = []string{"do"}, " do"
	}
	cookie := ""
	if client, server, ok := e.Cookie(); ok {
		cookie = hex.EncodeToString(client) + hex.EncodeToString(server)
	}
	text := fmt.Sprintf("; EDNS: version: %d, flags:%s; udp: %d", e.Version, words, e.UDPSize)
	if cookie != "" {
		text += "\n; COOKIE: " + cookie
	}
	out.add(text, struct {
		Type    string   `json:"type"`
		Version int      `json:"version"`
		Flags   []string `json:"flags"`
		UDP     int      `json:"udp"`
		Cookie  string   `json:"cookie"`
	}{"edns", int(e.Version), flags, int(e.UDPSize), cookie})
	for _, x := range e.ExtendedErrors() {
		out.add(fmt.Sprintf("; EDE: %d %s", x.InfoCode, strconv.Quote(x.ExtraText)), struct {
			Type string `json:"type"`
			Code int    `json:"code"`
			Text string `json:"text"`
		}{"ede", int(x.InfoCode), x.ExtraText})
	}
}
