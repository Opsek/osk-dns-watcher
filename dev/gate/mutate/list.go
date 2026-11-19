package main

import (
	"errors"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
)

// entry is a line of the list of accepted survivors: the ID that it lists,
// or the problem of the line.
type entry struct {
	line     int
	id, file string
	problem  string
}

var reasons = []string{"equivalent:", "unreachable:", "open:"}

const form = "want <file> <func> <word> <quoted> <reason>"

// readList reads the list file. No file is an empty list.
func readList(name string) ([]entry, error) {
	if name == "" {
		return nil, nil
	}
	data, err := os.ReadFile(name)
	if err != nil {
		return nil, errors.New(name + " cannot be read")
	}
	var entries []entry
	first := map[string]int{} // ID -> line
	for i, line := range strings.Split(string(data), "\n") {
		if strings.TrimSpace(line) == "" || strings.HasPrefix(line, "#") {
			continue
		}
		e := parseEntry(line)
		e.line = i + 1
		if e.problem == "" {
			if m, ok := first[e.id]; ok {
				e.problem = "already listed on line " + strconv.Itoa(m)
			} else {
				first[e.id] = e.line
			}
		}
		entries = append(entries, e)
	}
	return entries, nil
}

// parseEntry reads "<file> <func> <word> <quoted>[#n] <reason>".
func parseEntry(line string) entry {
	file, rest, ok1 := strings.Cut(line, " ")
	fn, rest, ok2 := strings.Cut(rest, " ")
	word, rest, ok3 := strings.Cut(rest, " ")
	quoted, err := strconv.QuotedPrefix(rest)
	if !ok1 || !ok2 || !ok3 || file == "" || fn == "" || word == "" || err != nil {
		return entry{problem: form}
	}
	tag, reason, ok := strings.Cut(rest[len(quoted):], " ")
	if !ok || reason == "" || !validTag(tag) {
		return entry{problem: form}
	}
	switch {
	case !slices.Contains(words, word):
		return entry{problem: "unknown mutation " + word}
	case !slices.ContainsFunc(reasons, func(r string) bool { return strings.HasPrefix(reason, r) }):
		return entry{problem: "the reason must start with equivalent:, unreachable: or open:"}
	}
	return entry{id: file + " " + fn + " " + word + " " + quoted + tag, file: file}
}

// validTag reports whether tag is empty or "#n" with n at least 2, as the
// IDs of mutants are written.
func validTag(tag string) bool {
	if tag == "" {
		return true
	}
	n, err := strconv.Atoi(strings.TrimPrefix(tag, "#"))
	return err == nil && n >= 2 && tag == "#"+strconv.Itoa(n)
}

// checkList adds a FAIL line for each problem of the list, and for each ID
// of a file directly in a folder of this run that is not a survivor. A run
// of some folders leaves the lines of the others alone. It reports whether
// there was no problem.
func checkList(o options, entries []entry, survivors map[string]bool, r *report) bool {
	passed := true
	for _, e := range entries {
		problem := e.problem
		if problem == "" && slices.Contains(o.folders, path.Dir(e.file)) && !survivors[e.id] {
			problem = "no surviving mutant has this id"
		}
		if problem != "" {
			passed = r.fail(o.list + ":" + strconv.Itoa(e.line) + ": " + problem)
		}
	}
	return passed
}
