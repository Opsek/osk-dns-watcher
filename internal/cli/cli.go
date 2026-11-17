// Package cli holds the commands that check a config and read the state of
// a running osk: validate, status, watch, accept and test-alert. Each runs in
// its own process beside the service. It opens the state only through a
// store.Reader, never reads standard input and never waits for a person, so
// it can never hold up the service.
package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"io"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

const (
	stampLayout = "2006-01-02T15:04:05Z"
	humanLayout = "2006-01-02 15:04:05 UTC"
)

// clock gives the time that status judges health at; a test replaces it.
var clock = time.Now

// PrintJSON writes v as one JSON line. Every command that prints JSON uses
// it, so all of them give one form.
func PrintJSON(w io.Writer, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = w.Write(append(b, '\n'))
	return err
}

// command names a command and its usage line, for the messages of wrong use.
type command struct{ name, usage string }

var (
	validateCommand  = command{"validate", "osk validate --config <file> [--json]"}
	statusCommand    = command{"status", "osk status --config <file> [--json]"}
	watchCommand     = command{"watch", "osk watch --config <file> [--json]"}
	acceptCommand    = command{"accept", "osk accept --config <file> [--write <code>] [--json] <alert id>"}
	testAlertCommand = command{"test-alert", "osk test-alert --config <file> [--json]"}
)

func (c command) wrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk "+c.name+": "+msg+"\nusage: "+c.usage+"\n")
}

type options struct {
	config string
	json   bool
	code   string // the value of --write; "" when it is not given
	args   []string
}

// parse returns a message when the flags are wrong. Flags must come before
// the arguments, because package flag stops at the first argument. Only
// accept takes --write, whose value is the code that its dry run printed.
func (c command) parse(args []string, withWrite bool) (options, string) {
	var o options
	given := false
	flags := flag.NewFlagSet(c.name, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("config", "the config file", func(s string) error {
		if given {
			return errors.New("given more than once")
		}
		given, o.config = true, s
		return nil
	})
	flags.BoolVar(&o.json, "json", false, "print JSON Lines")
	if withWrite {
		flags.Func("write", "write the change whose code the dry run printed", func(s string) error {
			if s == "" {
				return errors.New("want the code that osk accept printed")
			}
			o.code = s
			return nil
		})
	}
	if err := flags.Parse(args); err != nil {
		return o, err.Error()
	}
	if !given {
		return o, "--config is required"
	}
	o.args = flags.Args()
	return o, ""
}

func (c command) parseNoArgs(args []string) (options, string) {
	o, msg := c.parse(args, false)
	if msg == "" && len(o.args) > 0 {
		msg = "osk " + c.name + " takes no arguments"
	}
	return o, msg
}

// open reads the config but not its secrets, which a reading command never
// needs, and opens a Reader of its state folder. On failure it reports to
// stderr and returns the exit code.
func open(path string, stderr io.Writer) (*config.Config, *store.Reader, int) {
	c, problems := config.Read(path)
	if c == nil {
		return nil, nil, failErr(stderr, problemsErr(problems))
	}
	r, err := store.OpenReader(c.State)
	if err != nil {
		return nil, nil, failErr(stderr, err)
	}
	return c, r, 0
}

// closeReader ignores the error: a read-only connection has nothing to lose
// when it closes.
func closeReader(r *store.Reader) {
	_ = r.Close()
}

// checkLabel names a check as the alert lines of the service do; an alert of
// kind 0 concerns its whole domain.
func checkLabel(k obs.Key) string {
	if k.Kind == 0 {
		return k.Domain.Lower().String()
	}
	if k.Kind == obs.KindCertificates {
		return k.Kind.String() + " " + k.Domain.Lower().String()
	}
	return k.Kind.String() + " " + k.Name.Lower().String() + " " + k.Type.String()
}

type checkJSON struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	RType  string `json:"rtype"`
}

// checkOf gives "" as kind and type for kind 0, which has neither, and ""
// as type for the certificates check, which has no type.
func checkOf(k obs.Key) checkJSON {
	c := checkJSON{Domain: k.Domain.Lower().String(), Name: k.Name.Lower().String()}
	if k.Kind != 0 {
		c.Kind = k.Kind.String()
		if k.Kind != obs.KindCertificates {
			c.RType = k.Type.String()
		}
	}
	return c
}

// stamp gives "" for the zero time, which stands for none.
func stamp(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(stampLayout)
}

// list gives [] for nil, so that JSON shows an empty list and never null.
func list[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

// printer writes the result of a command as text or as JSON Lines and keeps
// the first failed write: a result that cannot be written is a failure.
type printer struct {
	w    io.Writer
	json bool
	err  error
}

func (p *printer) print(text string, v any) {
	if p.err != nil {
		return
	}
	if p.json {
		p.err = PrintJSON(p.w, v)
		return
	}
	_, p.err = io.WriteString(p.w, text+"\n")
}

func (p *printer) done(stderr io.Writer, code int) int {
	if p.err != nil {
		return failErr(stderr, p.err)
	}
	return code
}

func problemsErr(problems []config.Problem) error {
	errs := make([]error, len(problems))
	for i, p := range problems {
		errs[i] = errors.New(p.String())
	}
	return errors.Join(errs...)
}

// failErr prefixes every line, because a joined error holds one problem per
// line.
func failErr(stderr io.Writer, err error) int {
	var b strings.Builder
	for line := range strings.SplitSeq(err.Error(), "\n") {
		b.WriteString("osk: " + line + "\n")
	}
	return fail(stderr, 1, b.String())
}

// fail ignores a failed write: when stderr itself fails, nothing is left to
// report it to.
func fail(stderr io.Writer, code int, text string) int {
	_, _ = io.WriteString(stderr, text)
	return code
}
