package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// checkInterval is the interval each check of "osk check" is given. The
// checks run once, so it only sets their deadline: three quarters of it.
const checkInterval = 60 * time.Second

const receivedLayout = "2006-01-02T15:04:05.000Z"

// check runs "osk check": the delegation, DS and serial checks of a domain
// and a records check for each pair of name and type, all at once. It prints
// what the walk from the root asked and every answer, each with its result.
func check(args []string, stdout, stderr io.Writer) int {
	cfg, keys, msg := parseCheck(args)
	if msg != "" {
		return checkWrongUse(stderr, msg)
	}
	o, err := observe.New(cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return checkWrongUse(stderr, err.Error())
	}
	text, failed := formatObservations(runChecks(o, keys))
	if code := output(stdout, stderr, text); code != 0 || !failed {
		return code
	}
	return 1
}

func checkWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk check: "+msg+"\n"+usage)
}

// parseCheck reads the flags and the arguments. It returns a message when
// they are wrong.
func parseCheck(args []string) (observe.Config, []obs.Key, string) {
	var cfg observe.Config
	flags := flag.NewFlagSet("check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("root-server", "a root server to start from, in place of the built-in ones", func(s string) error {
		server, err := parseServer(s)
		cfg.RootServers = append(cfg.RootServers, server)
		return err
	})
	flags.Func("extra-range", "a prefix of non-public addresses that may be asked", func(s string) error {
		prefix, err := netip.ParsePrefix(s)
		cfg.ExtraRanges = append(cfg.ExtraRanges, prefix)
		return err
	})
	flags.DurationVar(&cfg.QueryTimeout, "timeout", 2*time.Second, "time for one query")
	if err := flags.Parse(args); err != nil {
		return cfg, nil, err.Error()
	}
	if cfg.QueryTimeout <= 0 {
		return cfg, nil, "the timeout must be positive"
	}
	keys, msg := parseKeys(flags.Args())
	return cfg, keys, msg
}

// parseServer reads an IP address with an optional port. Host names are
// refused: resolving one would trust a resolver.
func parseServer(s string) (netip.AddrPort, error) {
	if server, err := netip.ParseAddrPort(s); err == nil {
		return server, nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.AddrPort{}, errors.New("not an IP address with an optional port")
	}
	return netip.AddrPortFrom(addr, 53), nil
}

// parseKeys reads "<domain> [<name> <type>]..." into the keys of the checks,
// in the order of the output. A pair given twice is one check, because two
// runs of one key at once are refused. Every key is checked here, so that
// wrong use is found before any check sends a query.
func parseKeys(args []string) ([]obs.Key, string) {
	if len(args)%2 == 0 {
		return nil, "want a domain, then pairs of name and type"
	}
	domain, err := dnswire.ParseName(args[0])
	if err != nil {
		return nil, err.Error()
	}
	if domain.LabelCount() == 0 {
		return nil, "the domain must not be the root"
	}
	keys := []obs.Key{obs.DelegationKey(domain), obs.DSKey(domain), obs.SerialKey(domain)}
	seen := map[string]bool{}
	for i := 1; i < len(args); i += 2 {
		name, err := dnswire.ParseName(args[i])
		if err != nil {
			return nil, err.Error()
		}
		t, err := dnswire.ParseType(args[i+1])
		if err != nil {
			return nil, err.Error()
		}
		k := obs.RecordsKey(domain, name, t)
		if err := (observe.Check{Key: k, Interval: checkInterval}).Validate(); err != nil {
			return nil, err.Error()
		}
		if !seen[k.String()] {
			seen[k.String()] = true
			keys = append(keys, k)
		}
	}
	return keys, ""
}

// runChecks runs every check at once and returns the observations in the
// order of keys. Run gives no error: parseKeys has validated every key and
// kept each once.
func runChecks(o *observe.Observer, keys []obs.Key) []obs.Observation {
	observations := make([]obs.Observation, len(keys))
	var wg sync.WaitGroup
	for i, k := range keys {
		wg.Go(func() {
			observations[i], _ = o.Run(context.Background(), observe.Check{Key: k, Interval: checkInterval})
		})
	}
	wg.Wait()
	return observations
}

// formatObservations gives the walk entries and then the answers of each
// observation. failed reports a failure among the answers; the walk is proof
// only, and the answers show what it led to.
func formatObservations(observations []obs.Observation) (text string, failed bool) {
	var b strings.Builder
	for _, o := range observations {
		for _, a := range o.Walk {
			formatAnswer(&b, "walk", o.Key.Kind, a)
		}
		for _, a := range o.Answers {
			if formatAnswer(&b, "answer", o.Key.Kind, a) {
				failed = true
			}
		}
	}
	return b.String(), failed
}

// formatAnswer writes one line for each record of the answer, or one line for
// its other case, and reports whether it is a failure. Text from the network
// is printed only through Name.String, Record.String and strconv.Quote, which
// escape what could start a line or a field of its own.
func formatAnswer(b *strings.Builder, role string, kind obs.Kind, a obs.Answer) (failed bool) {
	address, host, transport := "-", "-", "-"
	if a.Server.Addr.IsValid() {
		address = a.Server.Addr.String()
	}
	// A configured root server has the root as its name, and an address.
	if a.Server.Addr.IsValid() || a.Server.Name.LabelCount() > 0 {
		host = a.Server.Name.String()
	}
	if a.Wire != nil {
		transport = "udp"
		if a.TCP {
			transport = "tcp"
		}
	}
	prefix := fmt.Sprintf("%s %s %s %s %s %s %s %s ", role, kind, a.Question.Name, a.Question.Type,
		address, host, a.Received.UTC().Format(receivedLayout), transport)
	lines := obs.Match(a.Result,
		func(r obs.Records) []string {
			var lines []string
			for _, rr := range r.Set {
				lines = append(lines, "records "+rr.String())
			}
			for _, rr := range r.Glue {
				lines = append(lines, "glue "+rr.String())
			}
			return lines
		},
		func(n obs.NoData) []string {
			return []string{fmt.Sprintf("nodata %d %s", n.TTL(), n.SOA)}
		},
		func(n obs.NoName) []string {
			word := "noname"
			if n.Compact {
				word = "noname-compact"
			}
			return []string{fmt.Sprintf("%s %d %s", word, n.TTL(), n.SOA)}
		},
		func(f obs.Failure) []string {
			failed = true
			return []string{"failure " + f.Reason.String() + " " + strconv.Quote(f.Detail)}
		})
	for _, line := range lines {
		b.WriteString(prefix + line + "\n")
	}
	return failed
}
