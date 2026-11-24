package main

import (
	"context"
	"io"
	"os"
	"slices"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// checkState runs check with --expect and --state: it prints what checkExpect
// prints, then keeps the alerts of each check in the folder and makes one
// pass of their notices to Slack.
func checkState(o *observe.Observer, ex expectArgs, asJSON bool, stdout, stderr io.Writer) int {
	slack, msg := slackChannel(ex.minimum)
	if msg != "" {
		return checkWrongUse(stderr, msg)
	}
	f, problems := loadExpect(ex.file)
	if f == nil {
		return fail(stderr, 1, problems)
	}
	s, err := store.Open(*ex.state)
	if err != nil {
		return fail(stderr, 1, "osk-dns-watcher: "+err.Error()+"\n")
	}
	code := runState(o, f, s, []deliver.Channel{slack}, asJSON, stdout, stderr)
	if err := s.Close(); err != nil {
		return fail(stderr, 1, "osk-dns-watcher: "+err.Error()+"\n")
	}
	return code
}

// slackChannel gives the Slack channel of the webhook URL, or the message of
// a wrong use. The URL comes from the environment, which only the user and
// root can read, not from the command line, which every user can. No message
// holds it: anyone who knows it can post to the channel.
func slackChannel(minimum decide.Severity) (*deliver.Slack, string) {
	webhook := os.Getenv("OSK_SLACK_URL")
	if webhook == "" {
		return nil, "--state needs the Slack webhook URL in the environment variable OSK_SLACK_URL"
	}
	host, err := httpclient.HostOf(webhook)
	if err != nil {
		return nil, "the environment variable OSK_SLACK_URL does not hold an https URL with a host and no user name"
	}
	return deliver.NewSlack(httpclient.New([]string{host}, nil), webhook, minimum), ""
}

// clock gives the time of a run; a test replaces it to play a clock that
// steps.
var clock = time.Now

// runState prints the findings before it reads the store, so that nothing
// the store holds can change them. A failed write gives exit 1 only after the
// alerts are stored and sent: the next run sees the same difference and
// sends nothing, so an alert dropped here would never be told.
func runState(o *observe.Observer, f *expect.File, s *store.Store, channels []deliver.Channel, asJSON bool, stdout, stderr io.Writer) int {
	observations := runChecks(o, expectKeys(f))
	now := clock()
	findings := &lines{json: asJSON}
	clean := formatFindings(findings, f, observations, now)
	code := output(stdout, stderr, findings.String())
	for _, ob := range observations {
		alerts := &lines{json: asJSON}
		if err := storeAlerts(alerts, s, f, ob, channels, now); err != nil {
			return fail(stderr, 1, "osk-dns-watcher: "+err.Error()+"\n")
		}
		if code == 0 {
			code = output(stdout, stderr, alerts.String())
		}
	}
	attempts := &lines{json: asJSON}
	sent, err := deliverOnce(attempts, s, channels, now)
	if code == 0 {
		code = output(stdout, stderr, attempts.String())
	}
	switch {
	case err != nil:
		return fail(stderr, 1, "osk-dns-watcher: "+err.Error()+"\n")
	case code != 0 || !sent || !clean:
		return 1
	}
	return 0
}

// storeAlerts stores the events of one observation with their deliveries,
// in one transaction, and gives a line for each. A clean observation is
// stored too: it is the last clean check that later notices show.
func storeAlerts(out *lines, s *store.Store, f *expect.File, o obs.Observation, channels []deliver.Channel, now time.Time) error {
	events, err := alertEvents(s, f, o, now)
	if err == nil {
		err = s.Apply(o.Key, events.Clean, now, deliver.Writes(events.Events, channels))
	}
	if err != nil {
		return err
	}
	for _, e := range events.Events {
		out.add("alert "+e.Label(), struct {
			Type  string `json:"type"`
			Label string `json:"label"`
		}{"alert", e.Label()})
	}
	return nil
}

// alertEvents gives the alert events of one observation. decide is given the
// open alerts of the check, so a difference that stands gives no event.
func alertEvents(s *store.Store, f *expect.File, o obs.Observation, now time.Time) (alert.Output, error) {
	open, err := s.OpenAlerts(o.Key)
	if err != nil {
		return alert.Output{}, err
	}
	lastClean, err := s.LastClean(o.Key)
	if err != nil {
		return alert.Output{}, err
	}
	findings := make([]decide.Finding, len(open))
	for i, a := range open {
		findings[i] = a.Finding()
	}
	changes := decide.Decide(decide.Input{Expect: f, Open: findings, Observation: o, Now: now})
	return alert.Transition(alert.Input{Open: open, Changes: changes, Failed: missed(o), LastClean: lastClean, Now: now}), nil
}

// deliverOnce makes one attempt for each due delivery, this run's and those
// that earlier runs left, and gives a line for each, and whether all were
// sent. It takes the time of the rows just stored: a clock that stepped back
// since would leave them undue.
func deliverOnce(out *lines, s *store.Store, channels []deliver.Channel, now time.Time) (sent bool, err error) {
	attempts, err := deliver.Pass(context.Background(), s, channels, now)
	for _, a := range attempts {
		out.add(a.Line(), deliveryOf(a))
	}
	sent = !slices.ContainsFunc(attempts, func(a deliver.Attempt) bool { return a.Done.State != store.RowSent })
	return sent, err
}

type deliveryJSON struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	State   string `json:"state"` // in the words of test-alert: sent, failed, given-up
	Label   string `json:"label"`
	Reason  string `json:"reason"`
	Next    string `json:"next"` // the next try of a failed attempt
}

func deliveryOf(a deliver.Attempt) deliveryJSON {
	j := deliveryJSON{Type: "delivery", Channel: a.Channel, State: a.Done.State.String(), Label: a.Row.Label, Reason: a.Done.Reason}
	if a.Done.State == store.RowPending {
		j.State, j.Next = "failed", a.Done.NextAt.UTC().Format(secondLayout)
	}
	return j
}
