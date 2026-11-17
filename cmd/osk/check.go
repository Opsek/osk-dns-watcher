package main

import (
	"cmp"
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

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/schedule"
)

// checkInterval is the interval each check of "osk check" is given. The
// checks run once, so it only sets their deadline: three quarters of it.
const checkInterval = 60 * time.Second

const receivedLayout = "2006-01-02T15:04:05.000Z"

// check runs "osk check". Without --expect: the delegation, DS and serial
// checks of a domain and a records check for each pair of name and type, all
// at once; it prints what the walk from the root asked and every answer, each
// with its result. With --expect: the checks of a file of expectations; it
// prints what differs from the file. With --state as well, it also keeps the
// alerts in a folder and sends their notices to Slack. With --json, each line
// is a JSON object.
func check(args []string, stdout, stderr io.Writer) int {
	a, msg := parseArgs(args, true)
	if msg != "" {
		return checkWrongUse(stderr, msg)
	}
	o, err := observe.New(a.cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return checkWrongUse(stderr, err.Error())
	}
	if a.ex != nil && a.ex.state != nil {
		return checkState(o, *a.ex, a.json, stdout, stderr)
	}
	if a.ex != nil {
		return checkExpect(o, a.ex.file, a.json, stdout, stderr)
	}
	out := &lines{json: a.json}
	failed := formatObservations(out, runChecks(o, a.keys))
	if code := output(stdout, stderr, out.String()); code != 0 || !failed {
		return code
	}
	return 1
}

func checkWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk check: "+msg+"\n"+usage)
}

// parseCheck reads the flags and the arguments of check without --expect.
func parseCheck(args []string) (observe.Config, []obs.Key, string) {
	a, msg := parseArgs(args, false)
	return a.cfg, a.keys, msg
}

// checkArgs are the flags and the arguments of check and snapshot.
type checkArgs struct {
	cfg  observe.Config
	ex   *expectArgs // nil without --expect
	keys []obs.Key   // the checks of the arguments, without --expect
	json bool
}

// expectArgs are the flags of check with --expect.
type expectArgs struct {
	file    string
	state   *string // nil without --state
	minimum decide.Severity
}

// parseArgs reads the flags and the arguments. withExpect allows --expect and
// the flags that need it, which only check takes. With --expect, ex is set and
// no argument may follow, because the file names the domain and the sets;
// without, the arguments give the keys. It returns a message when they are
// wrong.
func parseArgs(args []string, withExpect bool) (a checkArgs, msg string) {
	var file, state *string
	var minimum decide.Severity
	cfg := &a.cfg
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
	flags.BoolVar(&a.json, "json", false, "print JSON Lines")
	if withExpect {
		flags.Func("expect", "a file of expectations to compare with", func(s string) error {
			if file != nil {
				return errors.New("given more than once")
			}
			file = &s
			return nil
		})
		flags.Func("state", "a folder that keeps the alerts from run to run", func(s string) error {
			if state != nil {
				return errors.New("given more than once")
			}
			state = &s
			return nil
		})
		flags.Func("slack-min-severity", "the lowest severity of an alert that Slack hears of", func(s string) (err error) {
			minimum, err = parseSeverity(s)
			return err
		})
	}
	if err := flags.Parse(args); err != nil {
		return a, err.Error()
	}
	switch {
	case cfg.QueryTimeout <= 0:
		return a, "the timeout must be positive"
	case state != nil && file == nil:
		return a, "--state needs --expect"
	case minimum != 0 && state == nil:
		return a, "--slack-min-severity needs --state"
	case file != nil && flags.NArg() > 0:
		return a, "--expect takes no domain and no pairs: the file gives them"
	case file != nil:
		a.ex = &expectArgs{file: *file, state: state, minimum: cmp.Or(minimum, decide.SeverityLow)}
		return a, ""
	}
	a.keys, msg = parseKeys(flags.Args())
	return a, msg
}

// parseSeverity reads a severity word as the finding lines print it.
func parseSeverity(s string) (decide.Severity, error) {
	for v := decide.SeverityLow; v <= decide.SeverityCritical; v++ {
		if v.String() == s {
			return v, nil
		}
	}
	return 0, errors.New("want low, medium, high or critical")
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
// order of keys. Run gives no error, because every caller gives valid keys,
// each once: parseKeys validates each pair, snapshotKeys adds only the NS
// set at the apex, and expect.Parse refuses every type that a records check
// cannot ask, except DS, which expectKeys leaves out.
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
func formatObservations(out *lines, observations []obs.Observation) (failed bool) {
	for _, o := range observations {
		for _, a := range o.Walk {
			formatAnswer(out, "walk", o.Key.Kind, a)
		}
		for _, a := range o.Answers {
			if formatAnswer(out, "answer", o.Key.Kind, a) {
				failed = true
			}
		}
	}
	return failed
}

// answerJSON is a line of an answer with --json; "" stands for a field that
// the text prints as "-".
type answerJSON struct {
	Type      string `json:"type"`
	Kind      string `json:"kind"`
	QName     string `json:"qname"`
	QType     string `json:"qtype"`
	Address   string `json:"address"`
	Host      string `json:"host"`
	Received  string `json:"received"`
	Transport string `json:"transport"`
	Case      string `json:"case"`
	Data      string `json:"data"`
}

// formatAnswer writes one line for each record of the answer, or one line for
// its other case, and reports whether it is a failure. Text from the network
// is printed only through Name.String, Record.String and strconv.Quote, which
// escape what could start a line or a field of its own.
func formatAnswer(out *lines, role string, kind obs.Kind, a obs.Answer) (failed bool) {
	j := answerJSON{Type: role, Kind: kind.String(), QName: a.Question.Name.String(), QType: a.Question.Type.String(),
		Received: a.Received.UTC().Format(receivedLayout)}
	if a.Server.Addr.IsValid() {
		j.Address = a.Server.Addr.String()
	}
	// A configured root server has the root as its name, and an address.
	if a.Server.Addr.IsValid() || a.Server.Name.LabelCount() > 0 {
		j.Host = a.Server.Name.String()
	}
	if a.Wire != nil {
		j.Transport = "udp"
		if a.TCP {
			j.Transport = "tcp"
		}
	}
	prefix := fmt.Sprintf("%s %s %s %s %s %s %s %s ", role, kind, j.QName, j.QType,
		cmp.Or(j.Address, "-"), cmp.Or(j.Host, "-"), j.Received, cmp.Or(j.Transport, "-"))
	cases := obs.Match(a.Result,
		func(r obs.Records) [][2]string {
			var cases [][2]string
			for _, rr := range r.Set {
				cases = append(cases, [2]string{"records", rr.String()})
			}
			for _, rr := range r.Glue {
				cases = append(cases, [2]string{"glue", rr.String()})
			}
			return cases
		},
		func(n obs.NoData) [][2]string {
			return [][2]string{{"nodata", fmt.Sprintf("%d %s", n.TTL(), n.SOA)}}
		},
		func(n obs.NoName) [][2]string {
			word := "noname"
			if n.Compact {
				word = "noname-compact"
			}
			return [][2]string{{word, fmt.Sprintf("%d %s", n.TTL(), n.SOA)}}
		},
		func(f obs.Failure) [][2]string {
			failed = true
			return [][2]string{{"failure", f.Reason.String() + " " + strconv.Quote(f.Detail)}}
		})
	for _, c := range cases {
		j.Case, j.Data = c[0], c[1]
		out.add(prefix+c[0]+" "+c[1], j)
	}
	return failed
}

// checkExpect runs the checks of the file of expectations at path and prints
// each finding, each answer that could not be judged, and a count of both.
func checkExpect(o *observe.Observer, path string, asJSON bool, stdout, stderr io.Writer) int {
	f, problems := loadExpect(path)
	if f == nil {
		return fail(stderr, 1, problems)
	}
	out := &lines{json: asJSON}
	clean := formatFindings(out, f, runChecks(o, expectKeys(f)), time.Now())
	if code := output(stdout, stderr, out.String()); code != 0 || clean {
		return code
	}
	return 1
}

// loadExpect reads the file of expectations at path. When it cannot, it
// returns nil and the lines for standard error.
func loadExpect(path string) (*expect.File, string) {
	data, err := readExpect(path)
	if err != nil {
		return nil, "osk: " + err.Error() + "\n"
	}
	// One run has no earlier valid file to fall back on.
	f, err := expect.Keep(nil, data)
	if err != nil {
		return nil, problemLines(path, err)
	}
	return f, ""
}

// readExpect reads the file at path, up to one octet more than expect.Parse
// takes, so that Parse can tell a file that is too large. A refusal names
// the path, as the error of an open does.
func readExpect(path string) ([]byte, error) {
	data, err := config.ReadRegular(path, config.MaxExpectFile)
	if errors.Is(err, config.ErrNotRegular) {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return data, err
}

// problemLines gives one line for each problem of the file at path.
func problemLines(path string, err error) string {
	var e *expect.Error
	if !errors.As(err, &e) {
		return "osk: " + path + ": " + err.Error() + "\n"
	}
	var b strings.Builder
	for _, p := range e.Problems {
		if p.Line == 0 {
			fmt.Fprintf(&b, "osk: %s: %s\n", path, p.Text)
		} else {
			fmt.Fprintf(&b, "osk: %s:%d: %s\n", path, p.Line, p.Text)
		}
	}
	return b.String()
}

// expectKeys gives the checks of a file: those of the schedule without the
// serial check, so that one command and the service run the same probes.
func expectKeys(f *expect.File) []obs.Key {
	var keys []obs.Key
	for _, c := range schedule.Plan(f, nil, schedule.Defaults()) {
		if c.Key.Kind != obs.KindSerial {
			keys = append(keys, c.Key)
		}
	}
	return keys
}

// formatFindings gives for each observation the findings that decide makes of
// it, then a line for each answer that is a failure, and at the end a count of
// the checks and of both. clean reports that there are neither. decide gets no
// open alert, so that what this prints never depends on stored state.
func formatFindings(out *lines, f *expect.File, observations []obs.Observation, now time.Time) (clean bool) {
	findings, unknown := 0, 0
	for _, o := range observations {
		for _, c := range decide.Decide(decide.Input{Expect: f, Observation: o, Now: now}) {
			formatFinding(out, c.Finding)
			findings++
		}
		for _, a := range o.Answers {
			if isFailure(a.Result) {
				formatAnswer(out, "unknown", o.Key.Kind, lowerNames(a))
				unknown++
			}
		}
	}
	domain := f.Domain.Lower().String()
	out.add(fmt.Sprintf("checked %s %d sets: %d findings, %d unknown answers", domain, len(observations), findings, unknown),
		struct {
			Type     string `json:"type"`
			Domain   string `json:"domain"`
			Sets     int    `json:"sets"`
			Findings int    `json:"findings"`
			Unknown  int    `json:"unknown"`
		}{"checked", domain, len(observations), findings, unknown})
	return findings == 0 && unknown == 0
}

type findingJSON struct {
	Type     string     `json:"type"`
	Severity string     `json:"severity"`
	Rule     string     `json:"rule"`
	Kind     string     `json:"kind"`
	Name     string     `json:"name"`
	RType    string     `json:"rtype"`
	Expected string     `json:"expected"`
	Seen     []seenJSON `json:"seen"`
}

type seenJSON struct {
	Address string `json:"address"`
	Host    string `json:"host"`
	Text    string `json:"text"`
}

// formatFinding writes a finding with its proof. Value holds one line for
// each Seen answer, which decide builds only from Name.String and
// expect.SetText.
func formatFinding(out *lines, f decide.Finding) {
	k := f.Check
	j := findingJSON{Type: "finding", Severity: f.Severity.String(), Rule: f.Rule.String(), Kind: k.Kind.String(),
		Name: k.Name.Lower().String(), RType: k.Type.String(), Expected: f.Expected, Seen: []seenJSON{}}
	for _, s := range f.Seen {
		j.Seen = append(j.Seen, seenOf(s))
	}
	text := fmt.Sprintf("finding %s %s %s %s %s\n", f.Severity, f.Rule, k.Kind, j.Name, k.Type)
	text += "  expected " + cmp.Or(f.Expected, "-")
	if f.Value != "" {
		for _, line := range strings.Split(f.Value, "\n") {
			text += "\n  seen " + line
		}
	}
	out.add(text, j)
}

// seenOf names the server of a proof as decide does in Value, with "" where
// Value has "-".
func seenOf(s decide.Seen) seenJSON {
	j := seenJSON{Text: s.Text}
	if s.Answer.Server.Addr.IsValid() {
		j.Address = s.Answer.Server.Addr.String()
	}
	if s.Answer.Server.Name.LabelCount() > 0 {
		j.Host = s.Answer.Server.Name.Lower().String()
	}
	return j
}

func isFailure(r obs.Result) bool {
	return obs.Match(r,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(obs.Failure) bool { return true })
}

// lowerNames gives a copy of a with the names of its server and its question
// in lower case, as every name of the findings is: case carries no meaning in
// a name, and a server may send any.
func lowerNames(a obs.Answer) obs.Answer {
	a.Server.Name = a.Server.Name.Lower()
	a.Question.Name = a.Question.Name.Lower()
	return a
}
