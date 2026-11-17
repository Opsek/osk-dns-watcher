// Package alert turns the changes that decide finds for one check into the
// events of its alerts: open, update, escalate, reminder and resolve. It reads
// no clock, store or network: the caller passes the open alerts and the time,
// and stores the events it gets back.
package alert

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

type EventKind uint8

const (
	EventOpen EventKind = iota + 1
	EventUpdate
	EventEscalate
	EventReminder
	EventResolve
)

var kindWords = map[EventKind]string{
	EventOpen:     "open",
	EventUpdate:   "update",
	EventEscalate: "escalate",
	EventReminder: "reminder",
	EventResolve:  "resolve",
}

func (k EventKind) String() string {
	if w, ok := kindWords[k]; ok {
		return w
	}
	return "event" + strconv.Itoa(int(k))
}

// Line is one server's answer that showed the difference.
type Line struct {
	Server   obs.Server // the server whose answer showed it
	Text     string     // decide.Seen.Text
	TTL      uint32     // Records.TTL, NoData.TTL or NoName.TTL of that answer
	Received time.Time
}

type Alert struct {
	ID                int64 // store row id; 0 until stored
	Open              bool
	Rule              decide.Rule
	Severity, Peak    decide.Severity // Peak: the highest severity of this alert so far
	Check             obs.Key
	Expected, Value   string
	Lines             []Line    // one per decide.Seen, in order
	Opened, LastClean time.Time // first seen; the check's last clean time when it opened (zero: none)
	Noticed, Resolved time.Time // the last open, update, escalate or reminder; the resolve (zero while open)
}

// Identity names an alert: two changes with the same identity always address
// the same alert, and at most one alert of an identity is open.
func Identity(r decide.Rule, k obs.Key) string {
	return r.String() + " " + k.String()
}

func (a Alert) Identity() string { return Identity(a.Rule, a.Check) }

// Finding gives back what decide reads of an open finding, so that the next
// observation is judged against the alert as it was stored. The Result of each
// Seen stays zero: decide never reads it for an open finding.
func (a Alert) Finding() decide.Finding {
	var seen []decide.Seen
	for _, l := range a.Lines {
		proof := obs.Proof{Server: l.Server, Received: l.Received}
		seen = append(seen, decide.Seen{Answer: obs.Answer{Proof: proof}, Text: l.Text})
	}
	return decide.Finding{Rule: a.Rule, Severity: a.Severity, Check: a.Check,
		Expected: a.Expected, Seen: seen, Value: a.Value}
}

type Event struct {
	Kind  EventKind
	Alert Alert           // as it is after the event
	Was   decide.Severity // the severity before the event; Alert.Severity for open
	At    time.Time
}

func (e Event) Label() string {
	a := e.Alert
	words := []string{e.Kind.String(), a.Severity.String(), a.Rule.String()}
	// The invalid-file alert belongs to a whole domain, not to one check.
	if a.Check.Kind == 0 {
		return strings.Join(append(words, a.Check.Domain.Lower().String()), " ")
	}
	// The certificates check has no name or type of its own.
	if a.Check.Kind == obs.KindCertificates {
		return strings.Join(append(words, a.Check.Kind.String(), a.Check.Domain.Lower().String()), " ")
	}
	return strings.Join(append(words, a.Check.Kind.String(), a.Check.Name.Lower().String(), a.Check.Type.String()), " ")
}

type Policy struct{ Remind time.Duration } // 0: no reminder

type Input struct {
	Open      []Alert         // the open alerts of the observed check, from the store
	Changes   []decide.Change // decide.Decide of that observation, with Open as its open findings
	Failed    bool            // some answer of the observation is a failure
	LastClean time.Time       // of the check, from the store
	Now       time.Time
	Policy    Policy
}

type Output struct {
	Events []Event // at most one per alert: in Changes order, then reminders in Open order
	Clean  bool    // no alert of the check is open after the events, and Failed is false
}

// Transition gives the events of one observation. Only the first alert and
// the first change of each identity count, so no identity gets two open
// alerts and no alert gets two events from one observation.
func Transition(in Input) Output {
	open := firstOfEach(in.Open)
	var events []Event
	var done []string
	for _, c := range in.Changes {
		id := Identity(c.Finding.Rule, c.Finding.Check)
		if slices.Contains(done, id) {
			continue
		}
		done = append(done, id)
		if e, ok := onChange(c, open, in); ok {
			events = append(events, e)
		}
	}
	for _, a := range open {
		if !hasEvent(events, a) && due(a, in) {
			events = append(events, reminded(a, in.Now))
		}
	}
	return Output{Events: events, Clean: !in.Failed && !stillOpen(open, events)}
}

func firstOfEach(alerts []Alert) []Alert {
	var first []Alert
	for _, a := range alerts {
		if !slices.ContainsFunc(first, func(b Alert) bool { return b.Identity() == a.Identity() }) {
			first = append(first, a)
		}
	}
	return first
}

// onChange gives the event of c for the alert of its identity in open; a
// resolve of an alert that is not open, and an unknown Op, give none.
func onChange(c decide.Change, open []Alert, in Input) (Event, bool) {
	id := Identity(c.Finding.Rule, c.Finding.Check)
	i := slices.IndexFunc(open, func(a Alert) bool { return a.Identity() == id })
	switch c.Op {
	case decide.OpOpen, decide.OpUpdate:
		if i < 0 {
			return opened(c.Finding, in), true
		}
		return updated(open[i], c.Finding, in.Now), true
	case decide.OpResolve:
		if i < 0 {
			return Event{}, false
		}
		return resolved(open[i], c.Finding.Expected, in.Now), true
	}
	return Event{}, false
}

func opened(f decide.Finding, in Input) Event {
	a := Alert{Open: true, Rule: f.Rule, Severity: f.Severity, Peak: f.Severity, Check: f.Check,
		Expected: f.Expected, Value: f.Value, Lines: lines(f.Seen),
		Opened: in.Now, LastClean: in.LastClean, Noticed: in.Now}
	return Event{Kind: EventOpen, Alert: a, Was: f.Severity, At: in.Now}
}

// updated keeps the rule and check of a: the check of f may differ from it
// in letter case only.
func updated(a Alert, f decide.Finding, now time.Time) Event {
	kind := EventUpdate
	if f.Severity > a.Severity {
		kind = EventEscalate
	}
	was := a.Severity
	a.Severity, a.Expected, a.Value, a.Lines = f.Severity, f.Expected, f.Value, lines(f.Seen)
	a.Peak = max(a.Peak, f.Severity)
	a.Noticed = now
	return Event{Kind: kind, Alert: a, Was: was, At: now}
}

// resolved takes Expected from the change: the line in force when it resolves.
func resolved(a Alert, expected string, now time.Time) Event {
	a.Open = false
	a.Expected = expected
	a.Resolved = now
	return Event{Kind: EventResolve, Alert: a, Was: a.Severity, At: now}
}

func reminded(a Alert, now time.Time) Event {
	a.Noticed = now
	return Event{Kind: EventReminder, Alert: a, Was: a.Severity, At: now}
}

func due(a Alert, in Input) bool {
	return in.Policy.Remind > 0 && in.Now.Sub(a.Noticed) >= in.Policy.Remind
}

func hasEvent(events []Event, a Alert) bool {
	return slices.ContainsFunc(events, func(e Event) bool { return e.Alert.Identity() == a.Identity() })
}

// stillOpen reports whether an alert is open after the events: a new or
// changed one, or one of open that got no event.
func stillOpen(open []Alert, events []Event) bool {
	for _, e := range events {
		if e.Alert.Open {
			return true
		}
	}
	return slices.ContainsFunc(open, func(a Alert) bool { return !hasEvent(events, a) })
}

func lines(seen []decide.Seen) []Line {
	var out []Line
	for _, s := range seen {
		out = append(out, Line{Server: s.Answer.Server, Text: s.Text, TTL: ttl(s.Answer.Result), Received: s.Answer.Received})
	}
	return out
}

// ttl gives 0 for a failure, which decide never puts in Seen.
func ttl(r obs.Result) uint32 {
	return obs.Match(r, obs.Records.TTL, obs.NoData.TTL, obs.NoName.TTL, func(obs.Failure) uint32 { return 0 })
}
