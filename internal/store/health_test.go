package store

import (
	"fmt"
	"math/rand/v2"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// ntcNow is the time at which the health tests look. Rows and beats are
// placed around it, on both sides of each limit.
var ntcNow = stoT0.Add(time.Hour)

// The property tests draw their inputs from a fixed seed, so a failure can
// be replayed; every message names the seed and the case.
const (
	ntcSeed  = 20261115
	ntcCases = 1000
)

func ntcRand(c int) *rand.Rand { return rand.New(rand.NewPCG(ntcSeed, uint64(c))) }

func ntcPick[T any](rng *rand.Rand, xs ...T) T { return xs[rng.IntN(len(xs))] }

func ntcHealth(t *testing.T, s *Store, now time.Time, channels ...string) Health {
	t.Helper()
	h, err := s.Health(now, channels)
	if err != nil {
		t.Fatalf("Health(%v, %q): %v", now, channels, err)
	}
	return h
}

// ntcChannels writes the channels of h, one per line.
func ntcChannels(h Health) string {
	var b strings.Builder
	for _, c := range h.Channels {
		fmt.Fprintf(&b, "%s pending %d failing %v reason %q\n", c.Name, c.Pending, c.Failing, c.Reason)
	}
	return b.String()
}

// ntcRowDef is one delivery row of a health test: made at created, then
// brought into the state of done as the delivery loop would. A zero done
// leaves the row pending and never tried, due at created.
type ntcRowDef struct {
	channel string
	created time.Time
	done    Done
	notice  bool // a row of a notice, not of an alert
}

// ntcRows makes the rows in order, so their ids rise in that order. Each
// row of an alert gets an alert of its own.
func ntcRows(t *testing.T, s *Store, defs ...ntcRowDef) {
	t.Helper()
	corp := stoName(t, "corp.test.")
	for i, r := range defs {
		if r.notice {
			ntcNotify(t, s, Notice{Kind: NoticeTest, Lines: []string{"request   ntc"}, At: r.created}, Delivery{Channel: r.channel, Label: "row", Body: []byte("{}")})
		} else {
			k := obs.RecordsKey(corp, stoName(t, fmt.Sprintf("r%d.corp.test.", i)), dnswire.TypeA)
			stoApply(t, s, k, false, r.created, stoWrite(alert.EventOpen, stoAlert(t, decide.RuleRecordSet, k, "10.53.0.99"), decide.SeverityHigh, r.created, r.channel))
		}
		if r.done.State == 0 {
			continue
		}
		var id int64
		if err := s.db.QueryRow("SELECT max(id) FROM delivery").Scan(&id); err != nil {
			t.Fatal(err)
		}
		if err := s.Record(id, r.done); err != nil {
			t.Fatalf("Record(%d, %+v): %v", id, r.done, err)
		}
	}
}

// ntcFailed is an attempt that failed and will be tried again later.
func ntcFailed(attempts int, reason string, next time.Time) Done {
	return Done{State: RowPending, Attempts: attempts, NextAt: next, Reason: reason, At: next.Add(-10 * time.Second)}
}

func ntcEnded(state RowState, reason string, at time.Time) Done {
	return Done{State: state, Attempts: 1, Reason: reason, At: at}
}

func TestProblemsNamesEachProblemInOrder(t *testing.T) {
	now := ntcNow
	old := now.Add(-30*time.Second - time.Nanosecond)
	since := "no beat from osk-dns-watcher run since " + old.UTC().Format("2006-01-02 15:04:05") + " UTC"
	for _, c := range []struct {
		name string
		h    Health
		want []string
	}{
		{"a beat 30s old and pending rows that do not fail", Health{Beat: now.Add(-30 * time.Second),
			Channels: []ChannelHealth{{Name: "slack", Pending: 3}}}, nil},
		{"no beat yet", Health{}, []string{"no beat from osk-dns-watcher run yet"}},
		{"a beat 30s and 1ns old", Health{Beat: old}, []string{since}},
		{"the old beat in another zone", Health{Beat: old.In(stoZone)}, []string{since}},
		{"a beat ahead of now", Health{Beat: now.Add(time.Minute)}, nil},
		{"one check late", Health{Beat: now, Late: []string{"records corp.test. www.corp.test. A"}}, []string{"1 checks late"}},
		{"failing channels in the order given", Health{Beat: now, Channels: []ChannelHealth{
			{Name: "siem", Failing: true}, {Name: "slack"}, {Name: "hook", Failing: true, Reason: "status 503"}}},
			[]string{"channel siem fails", "channel hook fails"}},
		{"every problem", Health{Late: []string{"a", "b"}, Channels: []ChannelHealth{{Name: "slack", Failing: true}}},
			[]string{"no beat from osk-dns-watcher run yet", "2 checks late", "channel slack fails"}},
	} {
		if got := c.h.Problems(now); !slices.Equal(got, c.want) {
			t.Errorf("%s: Problems = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestHealthGivesTheLastBeatAndItsLateKeys(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	if h := ntcHealth(t, s, ntcNow); !h.Beat.IsZero() || len(h.Late) != 0 || len(h.Channels) != 0 {
		t.Errorf("Health of a new store with no channel = %+v, want no beat, no late check and no channel", h)
	}

	at := stoT0.In(stoZone)
	late := []string{"delegation corp.test. corp.test. NS", "records corp.test. www.corp.test. A"}
	if err := s.Beat(at, late); err != nil {
		t.Fatalf("Beat: %v", err)
	}
	h := ntcHealth(t, s, ntcNow)
	if !h.Beat.Equal(at) || h.Beat.Location() != time.UTC || !slices.Equal(h.Late, late) {
		t.Errorf("Health after Beat(%v, %q) = beat %v, late %q; want the same instant in UTC and the same keys", at, late, h.Beat, h.Late)
	}
	if got := ntcStrings(t, s.db, "SELECT late FROM beat"); !slices.Equal(got, []string{strings.Join(late, "\n")}) {
		t.Errorf("the late column holds %q, want the keys joined by LF", got)
	}

	// The next beat replaces the late keys too.
	if err := s.Beat(at.Add(10*time.Second), nil); err != nil {
		t.Fatalf("Beat: %v", err)
	}
	if h := ntcHealth(t, s, ntcNow); !h.Beat.Equal(at.Add(10*time.Second)) || len(h.Late) != 0 {
		t.Errorf("Health after a beat with no late check = beat %v, late %q; want the new beat and none", h.Beat, h.Late)
	}
}

// Each case builds the rows of a new store and reads the health of the
// channels at ntcNow. A reason of "?" is not checked: for a channel that
// does not fail, the rules of the reason do not settle it.
func TestHealthOfAChannelFollowsItsRows(t *testing.T) {
	now := ntcNow
	t1, t2 := now.Add(-5*time.Minute), now.Add(-3*time.Minute)
	slack := func(created time.Time, d Done) ntcRowDef {
		return ntcRowDef{channel: "slack", created: created, done: d}
	}
	for _, c := range []struct {
		name     string
		rows     []ntcRowDef
		channels []string
		want     string
	}{
		{"no row", nil, []string{"slack"}, `slack pending 0 failing false reason ""`},
		{"a row not tried yet", []ntcRowDef{slack(now, Done{})}, []string{"slack"}, `slack pending 1 failing false reason ""`},
		{"a failed attempt", []ntcRowDef{slack(t1, ntcFailed(1, "status 503", now.Add(10*time.Second)))},
			[]string{"slack"}, `slack pending 1 failing true reason "status 503"`},
		// The reason is that of the failed row with the greatest id, not
		// that of the most attempts, the latest try or the last row.
		{"the reason of the failed row with the greatest id", []ntcRowDef{
			slack(t1, ntcFailed(3, "status 502", now.Add(30*time.Second))),
			slack(t1, ntcFailed(1, "status 503", now.Add(10*time.Second))),
			slack(now, Done{})},
			[]string{"slack"}, `slack pending 3 failing true reason "status 503"`},
		{"a row due exactly 60s ago", []ntcRowDef{slack(now.Add(-60*time.Second), Done{})},
			[]string{"slack"}, `slack pending 1 failing false reason ""`},
		{"a row due 60s and 1ns ago: its loop is stuck", []ntcRowDef{slack(now.Add(-60*time.Second-time.Nanosecond), Done{})},
			[]string{"slack"}, `slack pending 1 failing true reason ""`},
		{"the newest ended row was given up", []ntcRowDef{
			slack(t1, ntcEnded(RowSent, "", t1)), slack(t1, ntcEnded(RowGivenUp, "status 404", t2))},
			[]string{"slack"}, `slack pending 0 failing true reason "status 404"`},
		{"the newest ended row was sent", []ntcRowDef{
			slack(t1, ntcEnded(RowGivenUp, "status 404", t1)), slack(t1, ntcEnded(RowSent, "", t2))},
			[]string{"slack"}, `slack pending 0 failing false reason "?"`},
		{"newest by the time it ended, not by id", []ntcRowDef{
			slack(t1, ntcEnded(RowSent, "", t2)), slack(t1, ntcEnded(RowGivenUp, "status 404", t1))},
			[]string{"slack"}, `slack pending 0 failing false reason "?"`},
		{"at one end time the greater id is newer: sent", []ntcRowDef{
			slack(t1, ntcEnded(RowGivenUp, "status 404", t2)), slack(t1, ntcEnded(RowSent, "", t2))},
			[]string{"slack"}, `slack pending 0 failing false reason "?"`},
		{"at one end time the greater id is newer: given up", []ntcRowDef{
			slack(t1, ntcEnded(RowSent, "", t2)), slack(t1, ntcEnded(RowGivenUp, "status 404", t2))},
			[]string{"slack"}, `slack pending 0 failing true reason "status 404"`},
		{"a failed attempt gives the reason before a given-up row", []ntcRowDef{
			slack(t1, ntcEnded(RowGivenUp, "status 404", t2)), slack(t1, ntcFailed(1, "status 503", now.Add(10*time.Second)))},
			[]string{"slack"}, `slack pending 1 failing true reason "status 503"`},
		{"rows of a channel that is not asked for are not read", []ntcRowDef{
			{channel: "hook", created: t1, done: ntcFailed(2, "status 500", now.Add(time.Minute))},
			{channel: "hook", created: t1, done: ntcEnded(RowGivenUp, "status 404", t2)},
			slack(t1, ntcEnded(RowSent, "", t1))},
			[]string{"slack"}, `slack pending 0 failing false reason ""`},
		{"channels in the order given, each with its own rows", []ntcRowDef{
			slack(t1, ntcEnded(RowSent, "", t1)),
			{channel: "hook", created: t1, done: ntcFailed(1, "status 503", now.Add(time.Minute))}},
			[]string{"hook", "siem", "slack"},
			"hook pending 1 failing true reason \"status 503\"\nsiem pending 0 failing false reason \"\"\nslack pending 0 failing false reason \"\""},
		{"a given-up row of a notice", []ntcRowDef{
			slack(t1, ntcEnded(RowSent, "", t1)),
			{channel: "slack", created: t1, done: ntcEnded(RowGivenUp, "status 410", t2), notice: true}},
			[]string{"slack"}, `slack pending 0 failing true reason "status 410"`},
		{"a failed row of a notice", []ntcRowDef{
			{channel: "slack", created: t1, done: ntcFailed(1, "no answer", now.Add(time.Minute)), notice: true}},
			[]string{"slack"}, `slack pending 1 failing true reason "no answer"`},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := stoOpen(t, stoDir(t))
			ntcRows(t, s, c.rows...)
			got := ntcHealth(t, s, now, c.channels...)
			want := c.want + "\n"
			if strings.Contains(want, `reason "?"`) {
				for i := range got.Channels {
					got.Channels[i].Reason = "?"
				}
			}
			if g := ntcChannels(got); g != want {
				t.Errorf("Health(%q):\n%s\nwant\n%s", c.channels, g, want)
			}
		})
	}
}

// ntcHealthRow is a row of the health property, kept as the test wrote it.
type ntcHealthRow struct {
	id             int64
	channel, state string
	attempts       int
	next, done     time.Time
	reason         string
	ofAlert        bool // a row of the alert's event, else of the notice
}

// ntcWantHealth gives Failing and Pending of each channel by the rules of
// the store's health, and the reason when a failed attempt or a given-up
// newest row makes the channel fail; "?" when the rules leave it open.
func ntcWantHealth(rows []ntcHealthRow, channels []string, now time.Time) []ChannelHealth {
	var out []ChannelHealth
	for _, name := range channels {
		c := ChannelHealth{Name: name, Reason: "?"}
		var lastFailed, newest *ntcHealthRow
		stuck := false
		for i := range rows {
			r := &rows[i]
			if r.channel != name {
				continue
			}
			if r.state == "pending" {
				c.Pending++
				if r.attempts >= 1 && (lastFailed == nil || r.id > lastFailed.id) {
					lastFailed = r
				}
				stuck = stuck || r.next.Before(now.Add(-60*time.Second))
				continue
			}
			if newest == nil || r.done.After(newest.done) || (r.done.Equal(newest.done) && r.id > newest.id) {
				newest = r
			}
		}
		givenUp := newest != nil && newest.state == "given-up"
		c.Failing = lastFailed != nil || stuck || givenUp
		switch {
		case lastFailed != nil:
			c.Reason = lastFailed.reason
		case givenUp:
			c.Reason = newest.reason
		}
		out = append(out, c)
	}
	return out
}

// Random rows, beats and late lists: Pending and Failing of each channel,
// and Problems, follow the rules of the store's health.
func TestHealthProperty(t *testing.T) {
	s := stoOpen(t, stoDir(t))
	// One alert with one event, and one notice, that every row may belong to.
	for _, q := range []string{
		`INSERT INTO alert (id, open, rule, check_key, kind, domain, name, type, severity, peak, expected, value, lines,
			opened, last_clean, noticed, resolved) VALUES (1, 1, 5, 'ntc', 3, 'corp.test.', 'ntc.corp.test.', 1, 3, 3, '', '', '[]', 1, 0, 1, 0)`,
		"INSERT INTO event (id, alert, kind, severity, was, value, at) VALUES (1, 1, 'open', 3, 3, '', 1)",
		"INSERT INTO notice (id, kind, domain, lines, at) VALUES (1, 'test', '', '[]', 1)",
	} {
		stoExec(t, s, q)
	}
	now := ntcNow
	pool := []string{"slack", "hook", "siem"}
	nexts := []time.Duration{-time.Hour, -61 * time.Second, -60*time.Second - time.Nanosecond, -60 * time.Second, -59 * time.Second, 0, 10 * time.Second, 2 * time.Hour}
	ends := []time.Duration{-5 * time.Minute, -3 * time.Minute, -time.Minute}
	beats := []time.Duration{-time.Hour, -31 * time.Second, -30*time.Second - time.Nanosecond, -30 * time.Second, -29 * time.Second, 0, time.Minute}
	for c := range ntcCases {
		rng := ntcRand(c)
		where := fmt.Sprintf("seed %d case %d", ntcSeed, c)
		tx, err := s.db.Begin()
		if err != nil {
			t.Fatal(err)
		}
		mustExec := func(q string, args ...any) {
			if _, err := tx.Exec(q, args...); err != nil {
				t.Fatalf("%s: %s: %v", where, q, err)
			}
		}
		mustExec("DELETE FROM delivery")
		mustExec("DELETE FROM beat")
		var rows []ntcHealthRow
		for i := range rng.IntN(9) {
			r := ntcHealthRow{id: int64(i + 1), channel: ntcPick(rng, pool...), state: ntcPick(rng, "pending", "pending", "sent", "given-up"),
				ofAlert: rng.IntN(2) == 0}
			if r.state == "pending" {
				r.attempts = rng.IntN(3)
				r.next = now.Add(ntcPick(rng, nexts...))
			} else {
				r.attempts = 1 + rng.IntN(3)
				r.done = now.Add(ntcPick(rng, ends...))
				r.next = r.done
			}
			if r.attempts > 0 {
				r.reason = fmt.Sprintf("status %d", 500+i)
			}
			event, notice := any(nil), any(int64(1))
			if r.ofAlert {
				event, notice = int64(1), nil
			}
			mustExec(`INSERT INTO delivery (id, event, notice, channel, label, body, state, attempts, created, next_at, reason, done_at)
				VALUES (?, ?, ?, ?, 'row', x'7b7d', ?, ?, ?, ?, ?, ?)`, r.id, event, notice, r.channel, r.state, r.attempts,
				now.Add(-2*time.Hour).UnixNano(), r.next.UnixNano(), r.reason, nanos(r.done))
			rows = append(rows, r)
		}
		if err := tx.Commit(); err != nil {
			t.Fatal(err)
		}
		var beat time.Time
		var late []string
		if rng.IntN(4) != 0 {
			beat = now.Add(ntcPick(rng, beats...))
			for i := range rng.IntN(4) {
				late = append(late, fmt.Sprintf("records corp.test. n%d.corp.test. A", i))
			}
			if err := s.Beat(beat, late); err != nil {
				t.Fatalf("%s: Beat: %v", where, err)
			}
		}
		channels := slices.Clone(pool)
		rng.Shuffle(len(channels), func(i, j int) { channels[i], channels[j] = channels[j], channels[i] })
		channels = channels[:rng.IntN(len(channels)+1)]

		h, err := s.Health(now, channels)
		if err != nil {
			t.Fatalf("%s: Health: %v", where, err)
		}
		want := ntcWantHealth(rows, channels, now)
		got := slices.Clone(h.Channels)
		for i := range got {
			if i < len(want) && want[i].Reason == "?" {
				got[i].Reason = "?"
			}
		}
		if g, w := ntcChannels(Health{Channels: got}), ntcChannels(Health{Channels: want}); g != w {
			t.Fatalf("%s: rows %+v\nHealth(%q) gives\n%s\nwant\n%s", where, rows, channels, g, w)
		}
		if !h.Beat.Equal(beat) || !slices.Equal(h.Late, late) {
			t.Fatalf("%s: Health gives beat %v and late %q, want %v and %q", where, h.Beat, h.Late, beat, late)
		}
		var problems []string
		switch {
		case beat.IsZero():
			problems = append(problems, "no beat from osk-dns-watcher run yet")
		case now.Sub(beat) > 30*time.Second:
			problems = append(problems, "no beat from osk-dns-watcher run since "+beat.UTC().Format("2006-01-02 15:04:05")+" UTC")
		}
		if len(late) > 0 {
			problems = append(problems, fmt.Sprintf("%d checks late", len(late)))
		}
		for _, c := range want {
			if c.Failing {
				problems = append(problems, "channel "+c.Name+" fails")
			}
		}
		if got := h.Problems(now); !slices.Equal(got, problems) {
			t.Fatalf("%s: Problems = %q, want %q", where, got, problems)
		}
	}
}
