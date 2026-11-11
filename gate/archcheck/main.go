// Command archcheck checks the code of the tool osk, the packages under cmd/
// and internal/, against the rules of its architecture: that it is built from
// the same Go files everywhere, which modules it may use, that it never
// listens, never starts a process, never uses unsafe or cgo, the import rules
// of gate/imports.txt, and that it sends no DNS message but a query: only the
// DNS codec in internal/dnswire opens connections, and only its function
// writeQuery writes to them.
//
// Usage:
//
//	archcheck [--root <dir>]
//
// It prints one line for each rule, "ok <rule>" or "FAIL <rule>: <reason>",
// and exits 0 if every rule passed, 1 if one failed, and 2 for wrong use.
package main

import (
	"flag"
	"io"
	"os"
	"strings"
)

const usage = "usage: archcheck [--root <dir>]\n"

// result is the outcome of one rule. The rule passed if it has no fault.
type result struct {
	name   string
	faults []string
}

func main() {
	text, code := run(os.Args[1:])
	out := os.Stdout
	if code == 2 {
		out = os.Stderr
	}
	// A verdict that cannot be printed must not count as a pass.
	if _, err := out.WriteString(text); err != nil {
		code = 2
	}
	os.Exit(code)
}

// run returns the text to print and the exit code.
func run(args []string) (string, int) {
	flags := flag.NewFlagSet("archcheck", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	root := flags.String("root", ".", "repository root")
	if err := flags.Parse(args); err != nil {
		return err.Error() + "\n" + usage, 2
	}
	if flags.NArg() > 0 {
		return usage, 2
	}
	return report(check(*root))
}

// report returns one line for each result, and the exit code.
func report(results []result) (string, int) {
	var b strings.Builder
	code := 0
	for _, r := range results {
		if len(r.faults) == 0 {
			b.WriteString("ok " + r.name + "\n")
			continue
		}
		b.WriteString("FAIL " + r.name + ": " + strings.Join(r.faults, "; ") + "\n")
		code = 1
	}
	return b.String(), code
}
