// Command mutate checks that the tests of some packages notice small changes
// of their code. For each folder it makes every mutant of its Go files that
// are not tests (an operator turned around, a condition dropped, a call
// removed), builds the tests of the package with that one change, and runs
// them. A mutant that the tests let pass survived. Each surviving mutant
// must be listed, with a reason, in the list of accepted survivors.
//
// Usage:
//
//	mutate [--root <dir>] [--list <file>] [--workers <n>] <folder>...
//
// The folders are relative to the root, which must be in a Go module. The
// tree is never written: each mutant reaches the compiler through
// "go test -c -overlay". It prints, for each folder:
//
//	mutate <folder>: <n> mutants, <n> not viable, <n> killed (<n> timed out), <n> survived (<n> listed), score <x>%, <n>s
//	survived <file> <func> <word> <quoted>[#n] (line <n>: <change>)
//
// and then "ok mutate", or "FAIL mutate: <reason>" lines. It exits 0 if
// every check passed, 1 if one failed, and 2 for wrong use.
//
// A line of the list is "<file> <func> <word> <quoted>[#n] <reason>", the
// text after "survived" up to the parenthesis, then the reason, which starts
// with "equivalent:", "unreachable:" or "open:". Lines that start with "#"
// and blank lines are ignored.
package main

import (
	"errors"
	"flag"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
)

const usage = "usage: mutate [--root <dir>] [--list <file>] [--workers <n>] <folder>...\n"

type options struct {
	root, list string
	workers    int
	folders    []string // relative to the root, with slashes
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
	o, err := parse(args)
	if err != nil {
		return err.Error() + "\n" + usage, 2
	}
	var r report
	if check(o, &r) {
		r.line("ok mutate")
		return r.String(), 0
	}
	return r.String(), 1
}

func parse(args []string) (options, error) {
	flags := flag.NewFlagSet("mutate", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var o options
	flags.StringVar(&o.root, "root", ".", "")
	flags.StringVar(&o.list, "list", "", "")
	flags.IntVar(&o.workers, "workers", runtime.NumCPU(), "")
	if err := flags.Parse(args); err != nil {
		return o, err
	}
	if flags.NArg() == 0 {
		return o, errors.New("no folder given")
	}
	if o.workers < 1 {
		return o, errors.New("--workers must be at least 1")
	}
	for _, f := range flags.Args() {
		if !filepath.IsLocal(f) {
			return o, errors.New(f + " is not a folder under the root")
		}
		o.folders = append(o.folders, filepath.ToSlash(filepath.Clean(f)))
	}
	return o, nil
}

// report is the text that run prints.
type report struct {
	strings.Builder
}

func (r *report) line(s string) {
	r.WriteString(s + "\n")
}

// fail adds a FAIL line and returns false, the verdict of a failed check.
func (r *report) fail(reason string) bool {
	r.line("FAIL mutate: " + reason)
	return false
}

// check judges the mutants of every folder against the list and adds the
// lines of the report. It reports whether every check passed.
func check(o options, r *report) bool {
	entries, err := readList(o.list)
	if err != nil {
		return r.fail(err.Error())
	}
	tmp, err := os.MkdirTemp("", "mutate")
	if err != nil {
		return r.fail(err.Error())
	}
	passed := judgeAll(o, tmp, entries, r)
	if err := os.RemoveAll(tmp); err != nil {
		return r.fail(err.Error())
	}
	return passed
}

// judgeAll judges the folders one after another; the first folder that
// cannot be judged ends the run. Then it checks the list.
func judgeAll(o options, tmp string, entries []entry, r *report) bool {
	j, err := newJudge(o, tmp)
	if err != nil {
		return r.fail(err.Error())
	}
	listed := map[string]bool{}
	for _, e := range entries {
		if e.problem == "" {
			listed[e.id] = true
		}
	}
	survivors := map[string]bool{}
	unlisted := 0
	for _, name := range o.folders {
		f, err := j.folder(name)
		if err != nil {
			return r.fail(err.Error())
		}
		r.line(f.summary(listed))
		for i, m := range f.mutants {
			if f.outcomes[i] != survived {
				continue
			}
			survivors[m.id] = true
			if !listed[m.id] {
				unlisted++
				r.line("survived " + m.id + " (" + m.change + ")")
			}
		}
		if f.viable() == 0 {
			return r.fail(name + " has no viable mutants")
		}
	}
	passed := checkList(o, entries, survivors, r)
	if unlisted > 0 {
		passed = r.fail(survivedText(unlisted, o.list))
	}
	return passed
}

func survivedText(n int, list string) string {
	text := "1 mutant survived and is not listed"
	if n > 1 {
		text = strconv.Itoa(n) + " mutants survived and are not listed"
	}
	if list != "" {
		text += " in " + list
	}
	return text
}
