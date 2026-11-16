package deliver_test

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"math"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// dlvDelays are the waits after failed attempts 1, 2, 3 and so on: 10 s
// doubling, then the cap of one hour.
var dlvDelays = []time.Duration{10 * time.Second, 20 * time.Second, 40 * time.Second, 80 * time.Second,
	160 * time.Second, 320 * time.Second, 640 * time.Second, 1280 * time.Second, 2560 * time.Second, time.Hour}

func dlvDelay(n int) time.Duration {
	return dlvDelays[min(n, len(dlvDelays))-1]
}

func TestDelayGrowsToOneHour(t *testing.T) {
	if deliver.MaxAttempts != 30 || deliver.MaxDelay != time.Hour {
		t.Errorf("MaxAttempts %d, MaxDelay %v; want 30, 1h", deliver.MaxAttempts, deliver.MaxDelay)
	}
	for n := 1; n <= 2000; n++ {
		if got := deliver.Delay(n); got != dlvDelay(n) {
			t.Errorf("Delay(%d) = %v, want %v", n, got, dlvDelay(n))
		}
		if deliver.Delay(n) > deliver.Delay(n+1) || deliver.Delay(n+1) > time.Hour {
			t.Errorf("Delay(%d) = %v, Delay(%d) = %v: not growing up to 1h", n, deliver.Delay(n), n+1, deliver.Delay(n+1))
		}
	}
	// Where 10 s times 2^(n-1) no longer fits in a Duration.
	for _, n := range []int{30, 31, 34, 35, 40, 63, 64, 65, 100, 1 << 20, math.MaxInt32, math.MaxInt - 1} {
		if got := deliver.Delay(n); got != time.Hour {
			t.Errorf("Delay(%d) = %v, want 1h", n, got)
		}
	}
}

// dlvReason is the reason that the delivery rules give for an outcome that
// is not a success. Of the body it shows only an error word: 1 to 40 octets
// of a to z and _, after one LF at its end is removed.
func dlvReason(o deliver.Outcome) string {
	if o.Status == 0 {
		return "no answer " + strconv.Quote(o.Err)
	}
	r := "status " + strconv.Itoa(o.Status)
	w := strings.TrimSuffix(string(o.Body), "\n")
	if len(w) >= 1 && len(w) <= 40 && strings.Trim(w, "abcdefghijklmnopqrstuvwxyz_") == "" {
		r += " " + strconv.Quote(w)
	}
	return r
}

func TestRetryScheduleProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 3))
	for range 20000 {
		r := store.Row{ID: rng.Int64N(1e6), Channel: "c", Label: "l", Attempts: rng.IntN(41), Created: dlvRandomTime(rng), NextAt: dlvRandomTime(rng)}
		o := deliver.Outcome{
			Status:     []int{0, 100 + rng.IntN(100), 200 + rng.IntN(400), 408, 429, 600 + rng.IntN(400)}[rng.IntN(6)],
			RetryAfter: time.Duration(rng.Int64N(int64(2*time.Hour) + 1)),
			Body:       []byte(dlvHostileText(rng, []int{0, 99, 100, 101, 300}[rng.IntN(5)])),
			Err:        dlvHostileText(rng, 60),
		}
		if o.Status == 0 {
			o.Body = nil
		}
		now := dlvRandomTime(rng)
		d := deliver.Next(r, o, now)
		n := r.Attempts + 1
		fail := func(format string, args ...any) {
			t.Fatalf("seed %d: Next(%+v, %+v, %v) = %+v: %s", seed, r, o, now, d, fmt.Sprintf(format, args...))
		}
		if d.Attempts != n || !d.At.Equal(now) {
			fail("Attempts %d and At %v, want %d and now", d.Attempts, d.At, n)
		}
		if (d.State == store.RowSent) != (o.Status >= 200 && o.Status <= 299) {
			fail("sent if and only if 2xx")
		}
		if (d.Reason == "") != (d.State == store.RowSent) {
			fail("an empty reason if and only if sent")
		}
		refused := o.Status >= 300 && o.Status <= 499 && o.Status != 408 && o.Status != 429
		switch {
		case o.Status >= 200 && o.Status <= 299:
			continue
		case refused && d.State != store.RowGivenUp:
			fail("a refusal must give up at once")
		case !refused && n >= 30 && d.State != store.RowGivenUp:
			fail("attempt %d must give up", n)
		case !refused && n < 30:
			wait := dlvDelay(n)
			if o.Status == 429 {
				wait = max(wait, min(o.RetryAfter, time.Hour))
			}
			if d.State != store.RowPending || !d.NextAt.Equal(now.Add(wait)) {
				fail("want pending until now + %v", wait)
			}
		}
		if d.Reason != dlvReason(o) {
			fail("reason %q, want %q", d.Reason, dlvReason(o))
		}
	}
}

// A body reaches the reason only as an error word: any other text of a
// server may repeat the secret path of the URL.
func TestNextReasons(t *testing.T) {
	long := strings.Repeat("é", 60)
	cases := []struct {
		o    deliver.Outcome
		want string
	}{
		{deliver.Outcome{Status: 200, Body: []byte("ok")}, ""},
		{deliver.Outcome{Status: 204}, ""},
		{deliver.Outcome{Status: 400, Body: []byte("invalid_payload")}, `status 400 "invalid_payload"`},
		{deliver.Outcome{Status: 404, Body: []byte("channel_not_found\n")}, `status 404 "channel_not_found"`},
		{deliver.Outcome{Status: 400, Body: []byte(strings.Repeat("a", 40))}, `status 400 "` + strings.Repeat("a", 40) + `"`},
		{deliver.Outcome{Status: 400, Body: []byte(strings.Repeat("a", 41))}, "status 400"},
		{deliver.Outcome{Status: 400, Body: []byte("Invalid_payload")}, "status 400"},
		{deliver.Outcome{Status: 400, Body: []byte("no team")}, "status 400"},
		{deliver.Outcome{Status: 400, Body: []byte("no_team\n\n")}, "status 400"},
		{deliver.Outcome{Status: 400, Body: []byte("\n")}, "status 400"},
		{deliver.Outcome{Status: 302}, "status 302"},
		{deliver.Outcome{Status: 503, Body: []byte("a\nb\x00\"")}, "status 503"},
		{deliver.Outcome{Status: 500, Body: []byte(long)}, "status 500"},
		{deliver.Outcome{Status: 429, RetryAfter: time.Minute, Body: []byte("\xff\xfe")}, "status 429"},
		{deliver.Outcome{Err: "network: dial tcp 127.0.0.1:1: connect: connection refused"},
			`no answer "network: dial tcp 127.0.0.1:1: connect: connection refused"`},
		{deliver.Outcome{Err: "timeout"}, `no answer "timeout"`},
		{deliver.Outcome{Err: "a\r\nb"}, `no answer "a\r\nb"`},
	}
	for _, c := range cases {
		if got := deliver.Next(store.Row{ID: 1, Attempts: 3}, c.o, dlvLater).Reason; got != c.want {
			t.Errorf("Next with %+v: reason %q, want %q", c.o, got, c.want)
		}
	}
}

func TestAttemptLine(t *testing.T) {
	row := store.Row{ID: 4, Channel: "slack", Label: "open high record-set records www.corp.test. A", Attempts: 1}
	east := time.FixedZone("east", 5*3600)
	cases := []struct {
		done store.Done
		want string
	}{
		{store.Done{State: store.RowSent, Attempts: 2, At: dlvLater},
			"delivery slack sent open high record-set records www.corp.test. A"},
		{store.Done{State: store.RowPending, Attempts: 2, NextAt: time.Date(2026, 11, 13, 14, 0, 20, 900e6, east), Reason: "status 503", At: dlvLater},
			"delivery slack failed open high record-set records www.corp.test. A: status 503; next try 2026-11-13T09:00:20Z"},
		{store.Done{State: store.RowGivenUp, Attempts: 2, Reason: `status 400 "invalid_payload"`, At: dlvLater},
			`delivery slack given up open high record-set records www.corp.test. A: status 400 "invalid_payload"`},
	}
	for _, c := range cases {
		a := deliver.Attempt{Channel: "slack", Row: row, Outcome: deliver.Outcome{Status: 503}, Done: c.done}
		if got := a.Line(); got != c.want {
			t.Errorf("Line of %v: %q, want %q", c.done.State, got, c.want)
		}
	}
}

// dlvFake is a channel of these tests. Its message names the alert's check,
// which is unique in each test, and it answers each message from a table.
type dlvFake struct {
	name    string
	min     decide.Severity
	answers map[string]deliver.Outcome
	sent    []string
}

func (f *dlvFake) Name() string                 { return f.name }
func (f *dlvFake) MinSeverity() decide.Severity { return f.min }
func (f *dlvFake) Message(e alert.Event) []byte {
	return []byte(f.name + " " + e.Alert.Check.Name.String())
}
func (f *dlvFake) Send(_ context.Context, body []byte) deliver.Outcome {
	f.sent = append(f.sent, string(body))
	if o, ok := f.answers[string(body)]; ok {
		return o
	}
	return deliver.Outcome{Status: 500, Body: []byte("not in the table")}
}

// dlvOpen is the open event of a new alert of the record set name/A.
func dlvOpen(t testing.TB, name string, sev, peak decide.Severity) alert.Event {
	return alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: sev, Peak: peak,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, name), dnswire.TypeA),
			Expected: "10.53.0.81", Lines: dlvLines(t), Opened: dlvOpened, Noticed: dlvOpened},
		Was: sev,
		At:  dlvOpened,
	}
}

// A notice goes to each channel whose minimum the alert's peak severity
// reaches, in channel order; an event with no channel still makes a write.
func TestWritesFollowThePeak(t *testing.T) {
	var channels []deliver.Channel
	for _, sev := range []decide.Severity{decide.SeverityCritical, decide.SeverityLow, decide.SeverityHigh, decide.SeverityMedium} {
		channels = append(channels, &dlvFake{name: "min-" + sev.String(), min: sev})
	}
	events := []alert.Event{
		dlvOpen(t, "a.corp.test.", decide.SeverityMedium, decide.SeverityHigh),
		dlvOpen(t, "b.corp.test.", decide.SeverityLow, decide.SeverityLow),
		dlvOpen(t, "c.corp.test.", decide.SeverityCritical, decide.SeverityCritical),
	}
	resolve := dlvOpen(t, "d.corp.test.", decide.SeverityLow, decide.SeverityCritical)
	resolve.Kind, resolve.Alert.Open = alert.EventResolve, false
	events = append(events, resolve)
	want := [][]string{
		{"min-low", "min-high", "min-medium"},
		{"min-low"},
		{"min-critical", "min-low", "min-high", "min-medium"},
		{"min-critical", "min-low", "min-high", "min-medium"},
	}
	writes := deliver.Writes(events, channels)
	if len(writes) != len(events) {
		t.Fatalf("%d writes for %d events", len(writes), len(events))
	}
	for i, w := range writes {
		if !reflect.DeepEqual(w.Event, events[i]) {
			t.Errorf("write %d holds event %+v, want %+v", i, w.Event, events[i])
		}
		var got []string
		for _, d := range w.Deliveries {
			got = append(got, d.Channel)
			k := slices.IndexFunc(channels, func(c deliver.Channel) bool { return c.Name() == d.Channel })
			if k < 0 || d.Label != events[i].Label() || string(d.Body) != string(channels[k].Message(events[i])) {
				t.Errorf("write %d to %q: label %q and body %q; want a channel's name, the event's label and the channel's message", i, d.Channel, d.Label, d.Body)
			}
		}
		if !slices.Equal(got, want[i]) {
			t.Errorf("write %d goes to %q, want %q", i, got, want[i])
		}
	}
	if len(deliver.Writes(nil, channels)) != 0 {
		t.Error("no event must give no write")
	}
}

// One pass sends each due row once, in row order on each channel, and no
// answer of one row or channel changes what another gets.
func TestChannelsIndependentProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 9))
	s, _ := dlvStore(t)
	now := dlvLater
	answers := []struct {
		kind string
		o    deliver.Outcome
	}{
		{"sent", deliver.Outcome{Status: 200}},
		{"sent", deliver.Outcome{Status: 204, Body: []byte("ok")}},
		{"sent", deliver.Outcome{Status: 299}},
		{"transient", deliver.Outcome{Err: "network: connection refused"}},
		{"transient", deliver.Outcome{Err: "timeout"}},
		{"transient", deliver.Outcome{Status: 408}},
		{"transient", deliver.Outcome{Status: 429, RetryAfter: 3 * time.Second}},
		{"transient", deliver.Outcome{Status: 500}},
		{"transient", deliver.Outcome{Status: 503, Body: []byte("busy")}},
		{"refused", deliver.Outcome{Status: 301}},
		{"refused", deliver.Outcome{Status: 400, Body: []byte("invalid_payload")}},
		{"refused", deliver.Outcome{Status: 404}},
		{"refused", deliver.Outcome{Status: 410}},
	}
	for i := range 1000 {
		fail := func(format string, args ...any) {
			t.Fatalf("seed %d, case %d: %s", seed, i, fmt.Sprintf(format, args...))
		}
		var fakes []*dlvFake
		var channels []deliver.Channel
		for j := range 1 + rng.IntN(4) {
			f := &dlvFake{name: fmt.Sprintf("c%d-%d", i, j), min: decide.Severity(1 + rng.IntN(4)), answers: map[string]deliver.Outcome{}}
			fakes, channels = append(fakes, f), append(channels, f)
		}
		for j := range 1 + rng.IntN(4) {
			sev := decide.Severity(1 + rng.IntN(4))
			e := dlvOpen(t, fmt.Sprintf("e%d.k%d.corp.test.", j, i), sev, sev+decide.Severity(rng.IntN(int(decide.SeverityCritical-sev)+1)))
			if err := s.Apply(e.Alert.Check, false, now, deliver.Writes([]alert.Event{e}, channels)); err != nil {
				fail("Apply: %v", err)
			}
		}
		// Some rows had 29 failed attempts already: one more failure ends them.
		type todo struct {
			row  store.Row
			kind string
		}
		var todos []todo
		for _, f := range fakes {
			rows, err := s.Due(f.name, now)
			if err != nil {
				fail("Due: %v", err)
			}
			slices.SortFunc(rows, func(a, b store.Row) int { return cmp.Compare(a.ID, b.ID) })
			for _, r := range rows {
				if rng.IntN(4) == 0 {
					if err := s.Record(r.ID, store.Done{State: store.RowPending, Attempts: 29, NextAt: now, At: now}); err != nil {
						fail("Record: %v", err)
					}
					r.Attempts = 29
				}
				a := answers[rng.IntN(len(answers))]
				f.answers[string(r.Body)] = a.o
				todos = append(todos, todo{r, a.kind})
			}
		}
		attempts, err := deliver.Pass(context.Background(), s, channels, now)
		if err != nil {
			fail("Pass: %v", err)
		}
		if len(attempts) != len(todos) {
			fail("%d attempts for %d due rows", len(attempts), len(todos))
		}
		for k, p := range todos {
			a := attempts[k]
			if a.Channel != p.row.Channel || a.Row.ID != p.row.ID {
				fail("attempt %d is row %d of %s, want row %d of %s (channel order, then row id)", k, a.Row.ID, a.Channel, p.row.ID, p.row.Channel)
			}
			want := map[string]store.RowState{"sent": store.RowSent, "refused": store.RowGivenUp, "transient": store.RowPending}[p.kind]
			if p.kind == "transient" && p.row.Attempts == 29 {
				want = store.RowGivenUp
			}
			if a.Done.State != want || a.Done.Attempts != p.row.Attempts+1 {
				fail("row %d of %s, answered %s after %d attempts: %v after %d attempts, want %v",
					p.row.ID, p.row.Channel, p.kind, p.row.Attempts, a.Done.State, a.Done.Attempts, want)
			}
		}
		for _, f := range fakes {
			var want []string
			var retried []int64
			for _, p := range todos {
				if p.row.Channel == f.name {
					want = append(want, string(p.row.Body))
					if p.kind == "transient" && p.row.Attempts < 29 {
						retried = append(retried, p.row.ID)
					}
				}
			}
			if !slices.Equal(f.sent, want) {
				fail("%s sent %q, want each due row once in row order: %q", f.name, f.sent, want)
			}
			if rows, err := s.Due(f.name, now); err != nil || len(rows) != 0 {
				fail("after the pass, %d rows of %s are still due (%v)", len(rows), f.name, err)
			}
			rows, err := s.Due(f.name, now.Add(10*time.Second))
			if err != nil {
				fail("Due: %v", err)
			}
			var got []int64
			for _, r := range rows {
				got = append(got, r.ID)
			}
			if !slices.Equal(got, retried) {
				fail("due 10 s later on %s: rows %v, want the transient rows below 30 attempts %v", f.name, got, retried)
			}
		}
	}
}

// dlvCut is a channel whose sends the context of the pass cuts: each one ends
// that context and gives no answer.
type dlvCut struct {
	dlvFake
	cancel context.CancelFunc
}

func (c *dlvCut) Send(ctx context.Context, body []byte) deliver.Outcome {
	c.sent = append(c.sent, string(body))
	c.cancel()
	return deliver.Outcome{Err: "network: " + ctx.Err().Error()}
}

// A pass whose context ends records nothing more: a send that the context cut
// is no attempt, and the rows not yet sent keep their attempts for a later
// pass.
func TestPassStopsWhenContextEnds(t *testing.T) {
	s, _ := dlvStore(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	c := &dlvCut{dlvFake: dlvFake{name: "c", min: decide.SeverityLow}, cancel: cancel}
	var events []alert.Event
	for _, name := range []string{"a.corp.test.", "b.corp.test.", "c.corp.test."} {
		events = append(events, dlvOpen(t, name, decide.SeverityHigh, decide.SeverityHigh))
	}
	if err := s.Apply(events[0].Alert.Check, false, dlvLater, deliver.Writes(events, []deliver.Channel{c})); err != nil {
		t.Fatal(err)
	}
	for pass := 1; pass <= 2; pass++ {
		attempts, err := deliver.Pass(ctx, s, []deliver.Channel{c}, dlvLater)
		if !errors.Is(err, context.Canceled) || len(attempts) != 0 || len(c.sent) != 1 {
			t.Errorf("pass %d: %d attempts, error %v, %d sends in all; want none, context.Canceled, 1", pass, len(attempts), err, len(c.sent))
		}
	}
	rows, err := s.Due("c", dlvLater)
	if err != nil || len(rows) != 3 {
		t.Fatalf("due rows %+v, %v; want all 3", rows, err)
	}
	for _, r := range rows {
		if r.Attempts != 0 {
			t.Errorf("row %d has %d attempts, want 0", r.ID, r.Attempts)
		}
	}
}

// A store that fails stops the pass with its error and sends nothing.
func TestPassReturnsStoreError(t *testing.T) {
	s, err := store.Open(dlvPrivateDir(t))
	if err != nil {
		t.Fatal(err)
	}
	f := &dlvFake{name: "c", min: decide.SeverityLow}
	e := dlvOpen(t, "www.corp.test.", decide.SeverityHigh, decide.SeverityHigh)
	if err := s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{f})); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := deliver.Pass(context.Background(), s, []deliver.Channel{f}, dlvLater); err == nil || len(f.sent) != 0 {
		t.Errorf("Pass on a closed store: error %v, %d sends; want an error and none", err, len(f.sent))
	}
}
