package cli

import (
	"cmp"
	"io"
	"strconv"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/store"
)

type statusJSON struct {
	Type     string        `json:"type"`
	Healthy  bool          `json:"healthy"`
	Problems []string      `json:"problems"`
	Beat     string        `json:"beat"`
	Late     []string      `json:"late"`
	Channels []channelJSON `json:"channels"`
	Open     []openJSON    `json:"open"`
	Warnings []string      `json:"warnings"`
}

type channelJSON struct {
	Name    string `json:"name"`
	Pending int    `json:"pending"`
	Failing bool   `json:"failing"`
	Reason  string `json:"reason"`
}

type openJSON struct {
	ID       int64     `json:"id"`
	Severity string    `json:"severity"`
	Rule     string    `json:"rule"`
	Check    checkJSON `json:"check"`
	Opened   string    `json:"opened"`
}

// Status runs "osk status": the health of the service as its last beat
// stored it, and the open alerts. Exit 1 when it is not healthy.
func Status(args []string, stdout, stderr io.Writer) int {
	o, msg := statusCommand.parseNoArgs(args)
	if msg != "" {
		return statusCommand.wrongUse(stderr, msg)
	}
	c, r, code := open(o.config, stderr)
	if code != 0 {
		return code
	}
	now := clock()
	h, err := r.Health(now, c.Channels())
	var alerts []alert.Alert
	if err == nil {
		alerts, err = r.AllOpenAlerts()
	}
	closeReader(r)
	if err != nil {
		return failErr(stderr, err)
	}
	problems, warnings := h.Problems(now), c.Warnings()
	p := &printer{w: stdout, json: o.json}
	p.print(statusText(h, problems, alerts, warnings), statusOf(h, problems, alerts, warnings))
	if len(problems) > 0 {
		return p.done(stderr, 1)
	}
	return p.done(stderr, 0)
}

func statusText(h store.Health, problems []string, alerts []alert.Alert, warnings []string) string {
	lines := []string{"healthy"}
	if len(problems) > 0 {
		lines[0] = "unhealthy: " + strings.Join(problems, "; ")
	}
	if h.Beat.IsZero() {
		lines = append(lines, "beat none")
	} else {
		lines = append(lines, "beat "+h.Beat.UTC().Format(humanLayout))
	}
	for _, k := range h.Late {
		lines = append(lines, "late "+k)
	}
	for _, ch := range h.Channels {
		pending := strconv.Itoa(ch.Pending) + " pending"
		if ch.Failing {
			lines = append(lines, "channel "+ch.Name+" fails, "+pending+", last reason "+cmp.Or(ch.Reason, "-"))
		} else {
			lines = append(lines, "channel "+ch.Name+" ok, "+pending)
		}
	}
	for _, a := range alerts {
		lines = append(lines, "open "+strconv.FormatInt(a.ID, 10)+" "+a.Severity.String()+" "+a.Rule.String()+" "+
			checkLabel(a.Check)+" since "+a.Opened.UTC().Format(humanLayout))
	}
	for _, w := range warnings {
		lines = append(lines, "warning "+w)
	}
	return strings.Join(lines, "\n")
}

func statusOf(h store.Health, problems []string, alerts []alert.Alert, warnings []string) statusJSON {
	s := statusJSON{Type: "status", Healthy: len(problems) == 0, Problems: list(problems), Beat: stamp(h.Beat),
		Late: list(h.Late), Channels: []channelJSON{}, Open: []openJSON{}, Warnings: list(warnings)}
	for _, ch := range h.Channels {
		s.Channels = append(s.Channels, channelJSON{ch.Name, ch.Pending, ch.Failing, ch.Reason})
	}
	for _, a := range alerts {
		s.Open = append(s.Open, openJSON{a.ID, a.Severity.String(), a.Rule.String(), checkOf(a.Check), stamp(a.Opened)})
	}
	return s
}
