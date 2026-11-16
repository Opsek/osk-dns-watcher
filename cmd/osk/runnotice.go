package main

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/schedule"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// notify stores n with a row for every channel, whatever its minimum: a
// notice belongs to no alert and has no severity.
func (m *monitor) notify(n store.Notice) error {
	if err := m.store.Notify(n, deliver.NoticeWrites(n, m.channels)); err != nil {
		return err
	}
	m.noticeLine(n)
	return nil
}

func (m *monitor) noticeLine(n store.Notice) {
	m.out.log(levelInfo, n.Domain, fmt.Sprintf("notice %s %s to %d channels", n.Kind, cmp.Or(n.Domain, "-"), len(m.channels)))
}

// sync compares text, the expectations of a domain now ("" for a domain
// that left the config), with those loaded last, and ends the open alerts
// of the domain whose check left plan (all of them for a domain that left).
// A change or an end is told to every channel by one notice; an ended alert
// gets no resolve message, whose words ("as expected again") would not be
// true. The text, the notice and the ends are one transaction.
func (m *monitor) sync(label string, plan []schedule.Check, text string, now time.Time) error {
	closing, err := m.leftOver(label, plan, text == "")
	if err != nil {
		return err
	}
	old, stored := m.loaded[label]
	if len(closing) == 0 && (old == text || !stored) {
		// A first load is no change.
		if !stored && text != "" {
			m.loaded[label] = text
			return m.store.Reload(label, text, nil, nil, nil)
		}
		return nil
	}
	n := store.Notice{Kind: store.NoticeExpectations, Domain: label, Lines: summary(old, text), At: now}
	var ends []store.Write
	for _, a := range closing {
		out := alert.Transition(alert.Input{Open: []alert.Alert{a}, Now: now,
			Changes: []decide.Change{{Op: decide.OpResolve, Finding: a.Finding(), At: now}}})
		ends = append(ends, deliver.Writes(out.Events, nil)...)
		n.Lines = append(n.Lines, closedLine(a))
	}
	if err := m.store.Reload(label, text, &n, deliver.NoticeWrites(n, m.channels), ends); err != nil {
		return err
	}
	m.loaded[label] = text
	if text == "" {
		delete(m.loaded, label)
	}
	m.noticeLine(n)
	for _, w := range ends {
		m.out.log(levelInfo, label, "closed "+w.Event.Label())
	}
	return nil
}

// leftOver gives the open alerts of the domain whose check is not in plan:
// all of them when all is set. An alert of the whole domain (invalid file,
// zone changed) stays while the domain stays.
func (m *monitor) leftOver(label string, plan []schedule.Check, all bool) ([]alert.Alert, error) {
	open, err := m.store.AllOpenAlerts()
	if err != nil {
		return nil, err
	}
	keys := map[string]bool{}
	for _, c := range plan {
		keys[c.Key.String()] = true
	}
	var left []alert.Alert
	for _, a := range open {
		if a.Check.Domain.Lower().String() == label && (all || a.Check.Kind != 0 && !keys[a.Check.String()]) {
			left = append(left, a)
		}
	}
	return left, nil
}

// closedLine names an ended alert as the alert lines do, without the word
// of the event.
func closedLine(a alert.Alert) string {
	_, rest, _ := strings.Cut(alert.Event{Kind: alert.EventResolve, Alert: a}.Label(), " ")
	return "closed " + rest
}

// send is the delivery loop of one channel, so that a channel that does not
// answer holds up only its own rows, and no check waits for it. The end of
// ctx cuts a send in flight; that row stays pending for the next start.
func (m *monitor) send(ctx context.Context, c deliver.Channel) error {
	for {
		attempts, err := deliver.Pass(ctx, m.store, []deliver.Channel{c}, time.Now())
		for _, a := range attempts {
			level := levelWarning
			if a.Done.State == store.RowSent {
				level = levelInfo
			}
			m.out.log(level, "", a.Line())
		}
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			return err
		}
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(passPause):
		}
	}
}

// beater posts the outside heartbeat. A beat is neither stored nor tried
// again: one sent late would tell that osk was healthy at a time it was
// not, and a missing beat is the signal.
type beater struct {
	client *httpclient.Client
	url    string
	every  time.Duration
}

func (m *monitor) heartbeat(ctx context.Context) {
	tick := time.NewTicker(m.beatTo.every)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
		m.postBeat(ctx, time.Now())
	}
}

// postBeat posts one beat while osk is healthy. A failure is only told, in
// the words of a delivery.
func (m *monitor) postBeat(ctx context.Context, now time.Time) {
	if problems := m.health.problems(now); len(problems) > 0 {
		m.out.log(levelWarning, "", "heartbeat skipped: "+strings.Join(problems, "; "))
		return
	}
	// Marshal cannot fail on a struct of a number and two strings.
	body, _ := json.Marshal(struct {
		Schema int    `json:"schema"`
		Type   string `json:"type"`
		At     string `json:"at"`
	}{deliver.SchemaVersion, "heartbeat", now.UTC().Format(secondLayout)})
	r, err := m.beatTo.client.Post(ctx, m.beatTo.url, "application/json", body)
	switch {
	case ctx.Err() != nil:
		// The stop cut it.
	case err == nil && r.Status >= 200 && r.Status <= 299:
		m.out.print("heartbeat sent")
	default:
		o := deliver.Outcome{Status: r.Status}
		if err != nil {
			o = deliver.Outcome{Err: err.Error()}
		}
		m.out.log(levelWarning, "", "heartbeat failed: "+deliver.Next(store.Row{}, o, now).Reason)
	}
}
