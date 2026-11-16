// Package deliver sends alert events, and notices that belong to no alert, to
// channels such as Slack or a webhook. Each message is a delivery row of the
// store. A pass tries each due row once and records the outcome, so the rows
// of a channel that fails wait for a later pass without holding up any other
// row or channel.
package deliver

import (
	"cmp"
	"context"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// A row is given up after MaxAttempts failures; with Delay between them that
// is about 21 hours.
const MaxAttempts = 30
const MaxDelay = time.Hour

// Delay is the wait after failed attempt n >= 1: it doubles from 10 s up to
// MaxDelay. The loop stops at MaxDelay, so no n can overflow it.
func Delay(n int) time.Duration {
	d := 10 * time.Second
	for i := 1; i < n && d < MaxDelay; i++ {
		d *= 2
	}
	return min(d, MaxDelay)
}

type Outcome struct {
	Status     int           // HTTP status; 0 when no answer came
	RetryAfter time.Duration // httpclient.Response.RetryAfter
	Body       []byte        // the answer when it is one of Slack's error words; else nil
	Err        string        // the httpclient error text when Status is 0
}

type Channel interface {
	Name() string // unique among the channels; stored in each row
	MinSeverity() decide.Severity
	Message(e alert.Event) []byte // the body of one event; pure
	Notice(n store.Notice) []byte // the body of a notice; pure
	Send(ctx context.Context, body []byte) Outcome
}

// Writes gives one write per event, with a delivery for each channel whose
// minimum the alert's peak severity reaches. The peak, not the severity: a
// channel that heard of an alert also hears its later notices and its end.
// Only while its minimum stays: a channel whose minimum is raised above the
// peak of an open alert misses the end of that alert.
func Writes(events []alert.Event, channels []Channel) []store.Write {
	var writes []store.Write
	for _, e := range events {
		w := store.Write{Event: e}
		for _, c := range channels {
			if e.Alert.Peak >= c.MinSeverity() {
				w.Deliveries = append(w.Deliveries, store.Delivery{Channel: c.Name(), Label: e.Label(), Body: c.Message(e)})
			}
		}
		writes = append(writes, w)
	}
	return writes
}

// NoticeWrites gives one delivery of n to every channel, in order, whatever
// its minimum: a test must reach each channel, and the other notices are rare.
func NoticeWrites(n store.Notice, channels []Channel) []store.Delivery {
	label := "notice " + string(n.Kind) + " " + cmp.Or(n.Domain, "-")
	var deliveries []store.Delivery
	for _, c := range channels {
		deliveries = append(deliveries, store.Delivery{Channel: c.Name(), Label: label, Body: c.Notice(n)})
	}
	return deliveries
}

// Next gives the state of row r after one attempt with outcome o. A 3xx or a
// 4xx other than 408 and 429 refuses the URL or the payload, so a retry
// cannot help. No jitter: osk is the only sender of its rows.
func Next(r store.Row, o Outcome, now time.Time) store.Done {
	n := r.Attempts + 1
	if o.Status >= 200 && o.Status <= 299 {
		return store.Done{State: store.RowSent, Attempts: n, At: now}
	}
	d := store.Done{State: store.RowGivenUp, Attempts: n, Reason: reason(o), At: now}
	refused := o.Status >= 300 && o.Status <= 499 && o.Status != 408 && o.Status != 429
	if !refused && n < MaxAttempts {
		d.State = store.RowPending
		d.NextAt = now.Add(max(Delay(n), wait(o)))
	}
	return d
}

// wait is how long a 429 asks to wait, at most MaxDelay.
func wait(o Outcome) time.Duration {
	if o.Status != 429 {
		return 0
	}
	return min(o.RetryAfter, MaxDelay)
}

func reason(o Outcome) string {
	if o.Status == 0 {
		return "no answer " + strconv.Quote(o.Err)
	}
	r := "status " + strconv.Itoa(o.Status)
	if w := errorWord(o.Body); w != "" {
		r += " " + strconv.Quote(w)
	}
	return r
}

// errorWords have the form of Slack's error words, such as invalid_payload.
var errorWords = regexp.MustCompile(`^[a-z_]{1,40}$`)

// errorWord gives a body that is one error word, without one LF at its end,
// and "" for any other body: a server may repeat the secret path of the URL
// in any form, so no other text of it reaches a reason.
func errorWord(body []byte) string {
	w := strings.TrimSuffix(string(body), "\n")
	if !errorWords.MatchString(w) {
		return ""
	}
	return w
}

// outcome keeps of the answer's body only a word of words that is the whole
// body, without one LF at its end. A receiver may echo a URL or a key in any
// form, padded or cut, so no other text of an answer is kept.
func outcome(r httpclient.Response, err error, words []string) Outcome {
	if err != nil {
		return Outcome{Err: err.Error()}
	}
	var word []byte
	if w := strings.TrimSuffix(string(r.Body), "\n"); slices.Contains(words, w) {
		word = []byte(w)
	}
	return Outcome{Status: r.Status, RetryAfter: r.RetryAfter, Body: word}
}

// Attempt is one try of one row.
type Attempt struct {
	Channel string
	Row     store.Row
	Outcome Outcome
	Done    store.Done
}

func (a Attempt) Line() string {
	head := "delivery " + a.Channel + " "
	switch a.Done.State {
	case store.RowSent:
		return head + "sent " + a.Row.Label
	case store.RowPending:
		return head + "failed " + a.Row.Label + ": " + a.Done.Reason +
			"; next try " + a.Done.NextAt.UTC().Format("2006-01-02T15:04:05Z")
	case store.RowGivenUp:
		return head + "given up " + a.Row.Label + ": " + a.Done.Reason
	}
	return head + a.Done.State.String() + " " + a.Row.Label
}

// Pass tries each row that is due at now once, the channels in parallel. It
// never waits: a row that fails waits in the store for a later pass. The
// attempts come by channel order, then row id. A store error ends the pass
// of its channel only, the end of ctx that of every channel; Pass returns the
// first error by channel order.
func Pass(ctx context.Context, s *store.Store, channels []Channel, now time.Time) ([]Attempt, error) {
	made := make([][]Attempt, len(channels))
	errs := make([]error, len(channels))
	var wg sync.WaitGroup
	for i, c := range channels {
		wg.Go(func() { made[i], errs[i] = passChannel(ctx, s, c, now) })
	}
	wg.Wait()
	all := slices.Concat(made...)
	for _, err := range errs {
		if err != nil {
			return all, err
		}
	}
	return all, nil
}

// passChannel tries the due rows of c in id order. An attempt whose outcome
// the store could not record is still listed: the receiver may have it. When
// ctx ends, it stops: a send that ctx cut is no attempt, so the row keeps its
// count of attempts.
func passChannel(ctx context.Context, s *store.Store, c Channel, now time.Time) ([]Attempt, error) {
	rows, err := s.Due(c.Name(), now)
	if err != nil {
		return nil, err
	}
	var made []Attempt
	for _, r := range rows {
		if ctx.Err() != nil {
			return made, ctx.Err()
		}
		o := c.Send(ctx, r.Body)
		if o.Status == 0 && ctx.Err() != nil {
			return made, ctx.Err()
		}
		d := Next(r, o, now)
		made = append(made, Attempt{Channel: c.Name(), Row: r, Outcome: o, Done: d})
		if err := s.Record(r.ID, d); err != nil {
			return made, err
		}
	}
	return made, nil
}
