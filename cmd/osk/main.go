// Command osk watches the DNS of the domains of its operator.
package main

import (
	"context"
	"io"
	"os"
	"os/signal"
	"runtime"
	"slices"
	"strings"
	"syscall"

	"github.com/Opsek/dns-monitoring/internal/cli"
	// The name start is taken by the function that refuses root.
	startpkg "github.com/Opsek/dns-monitoring/internal/start"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// version is set by build/static.sh with -ldflags "-X main.version=...".
// It is a var because -X cannot set a constant.
var version = "unknown"

const usage = `usage: osk version [--json]
       osk query [--rd] [--do] [--cd] [--tcp] [--timeout <duration>] [--json] @<server> <name> [<type>]
       osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
       osk snapshot [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
       osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] --expect <file> [--state <folder> [--slack-min-severity <severity>]]
       osk run --config <file>
       osk validate --config <file> [--json]
       osk status --config <file> [--json]
       osk watch --config <file> [--json]
       osk accept --config <file> [--write <code>] [--json] <alert id>
       osk test-alert --config <file> [--json]
       osk init --config <file> [--root-server <address>]... [--extra-range <prefix>]...
       osk doctor --config <file> [--json]
`

func main() {
	// A closed output pipe must fail the write, not end osk before it stores and sends the alerts.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(start(os.Args[1:], os.Stdout, os.Stderr))
}

// geteuid gives the user that osk runs as; a test that runs as root replaces
// it to reach the commands.
var geteuid = os.Geteuid

// start refuses root, so that a fault in the parsing of data from the
// network can never act as root, then runs the command. version alone is
// allowed, so that an image can be checked by running it as is.
func start(args []string, stdout, stderr io.Writer) int {
	if !isVersion(args) && geteuid() == 0 {
		return fail(stderr, 1, "osk: osk does not run as root; start it as an ordinary user\n")
	}
	return run(args, stdout, stderr)
}

func isVersion(args []string) bool {
	return slices.Equal(args, []string{"version"}) || slices.Equal(args, []string{"version", "--json"})
}

// run runs the command given by args, without the program name, and returns
// the exit code: 0 done, 1 failed, 2 wrong use.
func run(args []string, stdout, stderr io.Writer) int {
	if isVersion(args) {
		return printVersion(len(args) == 2, stdout, stderr)
	}
	if len(args) == 0 {
		return fail(stderr, 2, usage)
	}
	rest := args[1:]
	switch args[0] {
	case "query":
		return query(rest, stdout, stderr)
	case "check":
		return check(rest, stdout, stderr)
	case "snapshot":
		return snapshot(rest, stdout, stderr)
	case "run":
		return service(rest, stdout, stderr)
	case "validate":
		return cli.Validate(rest, stdout, stderr)
	case "status":
		return cli.Status(rest, stdout, stderr)
	case "accept":
		return cli.Accept(rest, stdout, stderr)
	case "watch", "test-alert":
		ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
		defer stop()
		if args[0] == "watch" {
			return cli.Watch(ctx, rest, stdout, stderr)
		}
		return cli.TestAlert(ctx, rest, stdout, stderr)
	case "init":
		return setup(rest, stdout, stderr)
	case "doctor":
		return doctor(rest, stdout, stderr)
	}
	return fail(stderr, 2, usage)
}

// doctor runs "osk doctor"; Ctrl-C ends its checks.
func doctor(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	return startpkg.Doctor(ctx, args, stdout, stderr)
}

func printVersion(asJSON bool, stdout, stderr io.Writer) int {
	sqlite, err := store.SQLiteVersion()
	if err != nil {
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	goVersion := strings.TrimPrefix(runtime.Version(), "go")
	out := &lines{json: asJSON}
	out.add("osk "+version+"\ngo "+goVersion+"\nsqlite "+sqlite, struct {
		Type   string `json:"type"`
		Osk    string `json:"osk"`
		Go     string `json:"go"`
		SQLite string `json:"sqlite"`
	}{"version", version, goVersion, sqlite})
	return output(stdout, stderr, out.String())
}

// output writes text to stdout. A result that cannot be written is a failure.
func output(stdout, stderr io.Writer, text string) int {
	if _, err := io.WriteString(stdout, text); err != nil {
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	return 0
}

// fail writes text to stderr and returns code. When stderr itself fails,
// nothing is left to report it to.
func fail(stderr io.Writer, code int, text string) int {
	_, _ = io.WriteString(stderr, text)
	return code
}

// lines are the output of a command that prints data: its text lines, or
// with --json one JSON object for each.
type lines struct {
	json bool
	b    strings.Builder
}

// add writes text, or v as JSON. v is built of strings, numbers and lists
// only, so it always marshals.
func (l *lines) add(text string, v any) {
	if l.json {
		_ = cli.PrintJSON(&l.b, v)
		return
	}
	l.b.WriteString(text + "\n")
}

func (l *lines) String() string { return l.b.String() }
