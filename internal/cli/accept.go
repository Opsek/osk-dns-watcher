package cli

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
)

// change is one line of an expectations file, before and after.
type change struct {
	Type    string `json:"type"`
	File    string `json:"file"`
	Line    int    `json:"line"`
	Old     string `json:"old"` // "" for an appended line: a line of the file is never empty
	New     string `json:"new"`
	Written bool   `json:"written"`
	Code    string `json:"code"` // the value of --write that writes this change
	data    []byte // the whole file after the change
}

// writeCode is the code of the change ch for alert id: the first 32 hex
// digits of the SHA-256 of the id, the file, the line it removes (none for an
// appended line), "--" and the line it writes, each followed by LF. The
// servers choose the new line, so the code has 128 bits, which no search for
// a line with the code that the operator saw can match; and it covers the
// whole change, not only that line.
func writeCode(id int64, ch change) string {
	parts := []string{strconv.FormatInt(id, 10), ch.File}
	if ch.Old != "" {
		parts = append(parts, ch.Old)
	}
	parts = append(parts, "--", ch.New)
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n") + "\n"))
	return hex.EncodeToString(sum[:])[:32]
}

// Accept runs "osk accept": it prints the change of the expectations file
// that makes what the servers of one open alert show the expected set, and
// writes it only with --write and the code of the change that it printed.
// The servers may show another set by then, and the operator must see each
// line before it becomes trusted.
func Accept(args []string, stdout, stderr io.Writer) int {
	o, msg := acceptCommand.parse(args, true)
	if msg != "" {
		return acceptCommand.wrongUse(stderr, msg)
	}
	id, msg := alertID(o.args)
	if msg != "" {
		return acceptCommand.wrongUse(stderr, msg)
	}
	c, r, code := open(o.config, stderr)
	if code != 0 {
		return code
	}
	a, err := r.Alert(id)
	// Closed before any file is touched, so the service never waits for it.
	closeReader(r)
	if err != nil {
		return failErr(stderr, err)
	}
	ch, err := changeFor(c, a)
	switch {
	case err != nil || o.code == "":
	case o.code != ch.Code:
		err = fmt.Errorf("the alert changed since you looked; run osk accept %d again", id)
	default:
		err = replaceFile(ch.File, ch.data)
		ch.Written = err == nil
	}
	if err != nil {
		return failErr(stderr, err)
	}
	p := &printer{w: stdout, json: o.json}
	p.print(ch.text(o.config, id), ch)
	return p.done(stderr, 0)
}

func alertID(args []string) (int64, string) {
	if len(args) != 1 {
		return 0, "want one alert id"
	}
	id, err := strconv.ParseInt(args[0], 10, 64)
	if err != nil || id < 1 {
		return 0, strconv.Quote(args[0]) + " is not an alert id"
	}
	return id, ""
}

func changeFor(c *config.Config, a alert.Alert) (change, error) {
	if !a.Open {
		return change{}, fmt.Errorf("alert %d is not open", a.ID)
	}
	if hint := refusal(a.Rule); hint != "" {
		return change{}, fmt.Errorf("accept cannot change the file for a %s alert: %s", a.Rule, hint)
	}
	text, err := seenText(a)
	if err != nil {
		return change{}, err
	}
	i := slices.IndexFunc(c.Domains, func(d config.Domain) bool { return d.Name.Equal(a.Check.Domain) })
	if i < 0 {
		return change{}, fmt.Errorf("%s is not a domain of the config", a.Check.Domain.Lower())
	}
	path := c.Domains[i].Expect
	data, f, err := readExpect(path)
	if err != nil {
		return change{}, err
	}
	ch, err := editFile(path, data, f, a, text)
	if err != nil {
		return change{}, err
	}
	ch.Code = writeCode(a.ID, ch)
	return ch, nil
}

// refusal gives why the file cannot be changed for an alert of rule r, or ""
// when it can: only these rules compare the set of one line with what the
// servers show.
func refusal(r decide.Rule) string {
	switch r {
	case decide.RuleNameServers, decide.RuleRecordSet, decide.RuleNotCovered, decide.RuleDS:
		return ""
	case decide.RuleGlue:
		return "edit the address line of each nameserver host that differs"
	case decide.RuleGone:
		return "nothing to accept: the domain must exist at the parent zone"
	case decide.RuleZone:
		return "add or remove the NS pair of the subzone by hand"
	case decide.RuleInvalidFile:
		return "fix the file"
	case decide.RuleCheckFailing:
		return "nothing to accept: no server answers"
	case decide.RuleZoneChanged:
		return "nothing to accept: no watched record differs"
	}
	return "edit the file by hand"
}

// seenText refuses when the servers show more than one set: accept cannot
// tell which one is right.
func seenText(a alert.Alert) (string, error) {
	var texts []string
	for _, l := range a.Lines {
		if !slices.Contains(texts, l.Text) {
			texts = append(texts, l.Text)
		}
	}
	switch len(texts) {
	case 0:
		return "", errors.New("no server gave a set for this alert; edit the file by hand")
	case 1:
		return texts[0], nil
	}
	return "", fmt.Errorf("the servers disagree: %s; edit the file by hand", strings.Join(texts, "; "))
}

// readExpect reads the file once, so that the bytes it changes are the bytes
// it parsed.
func readExpect(path string) ([]byte, *expect.File, error) {
	data, err := config.ReadRegular(path, config.MaxExpectFile)
	if err != nil {
		return nil, nil, errors.New(config.ReadProblem(path, err).String())
	}
	f, err := expect.Parse(data)
	var e *expect.Error
	if errors.As(err, &e) {
		problems := make([]config.Problem, len(e.Problems))
		for i, p := range e.Problems {
			problems[i] = config.Problem{File: path, Line: p.Line, Text: p.Text}
		}
		return nil, nil, problemsErr(problems)
	}
	return data, f, err
}

// editFile replaces the line of the alert's set, or appends one for a set
// that no line covers; every other octet stays, comments too. The alert's
// check names the set: the key of a delegation, DS or records check holds
// the name and type of the line that covers it.
func editFile(path string, data []byte, f *expect.File, a alert.Alert, text string) (change, error) {
	name, t := a.Check.Name, a.Check.Type
	set := name.Lower().String() + " " + t.String()
	line := ownerField(name) + " " + t.String() + " " + text
	e, found := f.Find(name, t)
	var ch change
	switch {
	case a.Rule == decide.RuleNotCovered && found:
		return change{}, fmt.Errorf("the file has a line for %s now", set)
	case a.Rule == decide.RuleNotCovered:
		ch = appendLine(path, string(data), line)
	case !found:
		return change{}, fmt.Errorf("the file changed since this alert: it has no line for %s", set)
	case e.FormText() != a.Expected:
		return change{}, fmt.Errorf("the file changed since this alert: %s is now %s", set, e.FormText())
	default:
		ch = replaceLine(path, string(data), e.Line, line)
	}
	if _, err := expect.Parse(ch.data); err != nil {
		return change{}, fmt.Errorf("the new line is not valid: %v; edit the file by hand", err)
	}
	return ch, nil
}

// ownerField writes a leading # with a backslash, as the file's canonical
// print does: a line that starts with # is a comment.
func ownerField(n dnswire.Name) string {
	s := n.Lower().String()
	if strings.HasPrefix(s, "#") {
		return `\` + s
	}
	return s
}

// replaceLine replaces line n, counted from 1 at each line feed as the
// parser counts.
func replaceLine(path, data string, n int, line string) change {
	lines := strings.SplitAfter(data, "\n")
	old, lf := strings.CutSuffix(lines[n-1], "\n")
	lines[n-1] = line
	if lf {
		lines[n-1] += "\n"
	}
	return change{Type: "change", File: path, Line: n, Old: old, New: line, data: []byte(strings.Join(lines, ""))}
}

func appendLine(path, data, line string) change {
	if data != "" && !strings.HasSuffix(data, "\n") {
		data += "\n"
	}
	n := strings.Count(data, "\n") + 1
	return change{Type: "change", File: path, Line: n, New: line, data: []byte(data + line + "\n")}
}

// text gives the change, then "written", or the command that writes it for
// the config file config and the alert id.
func (ch change) text(config string, id int64) string {
	lines := []string{ch.File + ":" + strconv.Itoa(ch.Line)}
	if ch.Old != "" {
		lines = append(lines, "- "+ch.Old)
	}
	lines = append(lines, "+ "+ch.New)
	if ch.Written {
		return strings.Join(append(lines, "written"), "\n")
	}
	return strings.Join(append(lines, "To write this change: osk accept --config "+config+" --write "+ch.Code+" "+strconv.FormatInt(id, 10)), "\n")
}

// replaceFile puts data in a new file beside path and renames it over path,
// so that the service reads either the old file or the new one, never a part.
// The new file gets the old one's mode. A symbolic link stays: the file that
// it names is replaced, in its own folder.
func replaceFile(path string, data []byte) error {
	path, err := filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = tmp.Write(data)
	// Sync before the rename: a crash must not leave an empty file in place.
	err = errors.Join(err, tmp.Chmod(info.Mode().Perm()), tmp.Sync(), tmp.Close())
	if err == nil {
		err = os.Rename(tmp.Name(), path)
	}
	if err != nil {
		_ = os.Remove(tmp.Name()) // the old file stands; only the new one is cleared away
	}
	return err
}
