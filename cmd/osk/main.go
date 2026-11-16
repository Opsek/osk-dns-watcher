// Command osk watches the DNS of the domains of its operator.
package main

import (
	"io"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	"github.com/Opsek/dns-monitoring/internal/store"
)

// version is set by build/static.sh with -ldflags "-X main.version=...".
// It is a var because -X cannot set a constant.
var version = "unknown"

const usage = `usage: osk version
       osk query [--rd] [--do] [--cd] [--tcp] [--timeout <duration>] @<server> <name> [<type>]
       osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] <domain> [<name> <type>]...
       osk snapshot [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] <domain> [<name> <type>]...
       osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] --expect <file> [--state <folder> [--slack-min-severity <severity>]]
       osk run [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--serial-interval <duration>] [--parent-interval <duration>] [--fast-interval <duration>] [--other-interval <duration>] [--fast <name>]... [--slack-min-severity <severity>] --expect <file> --state <folder>
`

func main() {
	// A closed output pipe must fail the write, not end osk before it stores and sends the alerts.
	signal.Ignore(syscall.SIGPIPE)
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run runs the command given by args, without the program name, and returns
// the exit code: 0 done, 1 failed, 2 wrong use.
func run(args []string, stdout, stderr io.Writer) int {
	switch {
	case len(args) == 1 && args[0] == "version":
		return printVersion(stdout, stderr)
	case len(args) > 0 && args[0] == "query":
		return query(args[1:], stdout, stderr)
	case len(args) > 0 && args[0] == "check":
		return check(args[1:], stdout, stderr)
	case len(args) > 0 && args[0] == "snapshot":
		return snapshot(args[1:], stdout, stderr)
	case len(args) > 0 && args[0] == "run":
		return service(args[1:], stdout, stderr)
	}
	return fail(stderr, 2, usage)
}

func printVersion(stdout, stderr io.Writer) int {
	sqlite, err := store.SQLiteVersion()
	if err != nil {
		return fail(stderr, 1, "osk: "+err.Error()+"\n")
	}
	text := "osk " + version + "\n" +
		"go " + strings.TrimPrefix(runtime.Version(), "go") + "\n" +
		"sqlite " + sqlite + "\n"
	return output(stdout, stderr, text)
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
