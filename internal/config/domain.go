package config

import (
	"errors"
	"fmt"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/expect"
)

// Read reads the expectations file of the domain as osk check does, and
// keeps it only when its domain line names this domain.
func (d Domain) Read() (*expect.File, []Problem) {
	data, err := ReadRegular(d.Expect, MaxExpectFile)
	if err != nil {
		return nil, []Problem{ReadProblem(d.Expect, err)}
	}
	// At start there is no earlier valid file to fall back on.
	f, err := expect.Keep(nil, data)
	if err != nil {
		return nil, expectProblems(d.Expect, err)
	}
	if !f.Domain.Equal(d.Name) {
		text := fmt.Sprintf("the file is for %s, not %s", f.Domain, d.Name)
		return nil, []Problem{{File: d.Expect, Line: domainLine(data), Text: text}}
	}
	return f, nil
}

func expectProblems(file string, err error) []Problem {
	var e *expect.Error
	if !errors.As(err, &e) {
		return []Problem{{File: file, Text: err.Error()}}
	}
	problems := make([]Problem, len(e.Problems))
	for i, p := range e.Problems {
		problems[i] = Problem{File: file, Line: p.Line, Text: p.Text}
	}
	return problems
}

// domainLine gives the number of the line that names the domain. The file
// is valid, so it has exactly one, and its octets are printable ASCII or
// tabs, which Fields splits as the expectations parser does.
func domainLine(data []byte) int {
	n := 0
	for line := range strings.SplitSeq(string(data), "\n") {
		n++
		if f := strings.Fields(line); len(f) > 0 && f[0] == "domain" {
			return n
		}
	}
	return 0
}
