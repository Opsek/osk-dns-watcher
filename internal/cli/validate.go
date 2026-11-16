package cli

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/store"
)

type problemJSON struct {
	Type string `json:"type"`
	File string `json:"file"`
	Line int    `json:"line"`
	Path string `json:"path"`
	Text string `json:"text"`
}

type warningJSON struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type resultJSON struct {
	Type     string   `json:"type"`
	Valid    bool     `json:"valid"`
	Problems int      `json:"problems"`
	Domains  int      `json:"domains"`
	Channels []string `json:"channels"`
}

// Validate runs "osk validate": it prints every problem of the config, of
// its secrets as this process sees them, of the expectations files and of the
// state folder. A service started with another environment may see other
// secrets.
func Validate(args []string, stdout, stderr io.Writer) int {
	o, msg := validateCommand.parseNoArgs(args)
	if msg != "" {
		return validateCommand.wrongUse(stderr, msg)
	}
	c, problems := config.Read(o.config)
	if c != nil {
		problems = deeperProblems(c)
	}
	p := &printer{w: stdout, json: o.json}
	for _, pr := range problems {
		p.print(pr.String(), problemJSON{"problem", pr.File, pr.Line, pr.Path, pr.Text})
	}
	result := resultJSON{Type: "result", Valid: len(problems) == 0, Problems: len(problems), Channels: []string{}}
	if c != nil {
		for _, w := range c.Warnings() {
			p.print("warning "+w, warningJSON{"warning", w})
		}
		result.Domains, result.Channels = len(c.Domains), list(c.Channels())
	}
	p.print(resultText(result), result)
	if len(problems) > 0 {
		return p.done(stderr, 1)
	}
	return p.done(stderr, 0)
}

// deeperProblems finds what a valid config file can still get wrong. The
// secret values are dropped at once: validate only tells whether they work.
func deeperProblems(c *config.Config) []config.Problem {
	_, problems := c.Secrets(os.LookupEnv)
	for _, d := range c.Domains {
		_, ps := d.Read()
		problems = append(problems, ps...)
	}
	// A missing folder is no problem: osk run makes it.
	if _, err := os.Stat(c.State); errors.Is(err, fs.ErrNotExist) {
		return problems
	}
	if err := store.CheckFolder(c.State); err != nil {
		problems = append(problems, config.Problem{File: c.Path, Path: "state", Text: err.Error()})
	}
	return problems
}

func resultText(r resultJSON) string {
	if !r.Valid {
		return strconv.Itoa(r.Problems) + " problems"
	}
	return "valid: " + strconv.Itoa(r.Domains) + " domains, channels " + strings.Join(r.Channels, ",")
}
