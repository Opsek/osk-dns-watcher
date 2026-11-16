package cli

import (
	"context"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// watchEvery is the time between two reads of watch; a test shortens it.
var watchEvery = time.Second

// maxNoticeLines is how many lines of a notice watch shows, as the notice
// text of a channel does.
const maxNoticeLines = 12

type eventJSON struct {
	Type     string    `json:"type"`
	ID       int64     `json:"id"`
	Alert    int64     `json:"alert"`
	Kind     string    `json:"kind"`
	Severity string    `json:"severity"`
	Was      string    `json:"was"`
	Rule     string    `json:"rule"`
	Check    checkJSON `json:"check"`
	Value    string    `json:"value"`
	At       string    `json:"at"`
}

type noticeJSON struct {
	Type   string   `json:"type"`
	ID     int64    `json:"id"`
	Kind   string   `json:"kind"`
	Domain string   `json:"domain"`
	Lines  []string `json:"lines"`
	At     string   `json:"at"`
}

type item struct {
	at   time.Time
	text string
	json any
}

// Watch runs "osk watch": it prints each event and notice that the service
// stores from now on, until ctx ends.
func Watch(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, msg := watchCommand.parseNoArgs(args)
	if msg != "" {
		return watchCommand.wrongUse(stderr, msg)
	}
	_, r, code := open(o.config, stderr)
	if code != 0 {
		return code
	}
	defer closeReader(r)
	events, notices, err := r.Last()
	if err != nil {
		return failErr(stderr, err)
	}
	p := &printer{w: stdout, json: o.json}
	tick := time.NewTicker(watchEvery)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return 0
		case <-tick.C:
		}
		events, notices, err = printNew(r, p, events, notices)
		if err != nil {
			return failErr(stderr, err)
		}
		if p.err != nil {
			return p.done(stderr, 1)
		}
	}
}

func printNew(r *store.Reader, p *printer, events, notices int64) (int64, int64, error) {
	es, err := r.Events(events)
	if err != nil {
		return events, notices, err
	}
	ns, err := r.Notices(notices)
	if err != nil {
		return events, notices, err
	}
	var items []item
	for _, e := range es {
		items = append(items, eventItem(e))
		events = e.ID
	}
	for _, n := range ns {
		items = append(items, noticeItem(n))
		notices = n.ID
	}
	// Stable: at equal times the events stay before the notices, and each
	// stays in the id order that the store gave.
	slices.SortStableFunc(items, func(a, b item) int { return a.at.Compare(b.at) })
	for _, it := range items {
		p.print(it.text, it.json)
	}
	return events, notices, nil
}

func eventItem(e store.EventRow) item {
	a := e.Alert
	text := stamp(e.At) + " alert " + strconv.FormatInt(a.ID, 10) + " " + e.Kind + " " + e.Severity.String() + " " +
		a.Rule.String() + " " + checkLabel(a.Check)
	// The value of a given-up event is the channel and its reason, which
	// holds no text from the receiver except one quoted word.
	if e.Kind == "given-up" {
		text += ": " + e.Value
	}
	v := eventJSON{"event", e.ID, a.ID, e.Kind, e.Severity.String(), e.Was.String(), a.Rule.String(),
		checkOf(a.Check), e.Value, stamp(e.At)}
	return item{e.At, text, v}
}

func noticeItem(n store.Notice) item {
	domain := n.Domain
	if domain == "" {
		domain = "-"
	}
	lines := []string{stamp(n.At) + " notice " + string(n.Kind) + " " + domain}
	for _, l := range n.Lines[:min(len(n.Lines), maxNoticeLines)] {
		lines = append(lines, "  "+deliver.Clean(l, 160))
	}
	if k := len(n.Lines) - maxNoticeLines; k > 0 {
		lines = append(lines, "  and "+strconv.Itoa(k)+" more lines")
	}
	v := noticeJSON{"notice", n.ID, string(n.Kind), n.Domain, list(n.Lines), stamp(n.At)}
	return item{n.At, strings.Join(lines, "\n"), v}
}
