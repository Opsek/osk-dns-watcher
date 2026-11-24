package alert

import (
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// A server that shows the value of an open alert only after the alert opened
// sends no message, but the alert keeps it. When that server then fails while
// the first one gives the expected set again, the alert stays open: the server
// that fails may still give the changed set.
func TestAlertKeepsAServerThatShowsItsValueLater(t *testing.T) {
	file, err := expect.Parse([]byte("domain corp.test.\nwww.corp.test. A 10.53.0.81\n"))
	if err != nil {
		t.Fatal(err)
	}
	ns1 := alrServer(t, "ns1.corp.test.", "10.53.0.11:53")
	ns2 := alrServer(t, "ns2.corp.test.", "10.53.0.12:53")
	at := func(s obs.Server, data string, now time.Time) obs.Answer {
		set := obs.RecordsResult(obs.Records{Set: []dnswire.Record{alrRR(t, "www.corp.test.", dnswire.TypeA, 300, data)}})
		return alrAnswer(s, alrAs(t, set, "records"), now)
	}
	fails := func(s obs.Server, now time.Time) obs.Answer {
		return alrAnswer(s, obs.FailureResult(obs.Failure{Reason: obs.ReasonTimeout}), now)
	}
	observe := func(now time.Time, answers ...obs.Answer) obs.Observation {
		return obs.Observation{Key: alrKey(t, "www.corp.test."), Start: now, Deadline: now.Add(45 * time.Second),
			Zone: alrName(t, "corp.test."), Answers: answers}
	}
	// stored is what the store keeps of the open alert after each run.
	var stored []Alert
	run := func(o obs.Observation) []Event {
		var open []decide.Finding
		for _, a := range stored {
			open = append(open, a.Finding())
		}
		changes := decide.Decide(decide.Input{Expect: file, Open: open, Observation: o, Now: o.Start})
		out := Transition(Input{Open: stored, Changes: changes, Now: o.Start})
		for _, e := range out.Events {
			stored = nil
			if e.Alert.Open {
				e.Alert.ID = 1
				stored = []Alert{e.Alert}
			}
		}
		return out.Events
	}

	t1, t2, t3 := alrT0, alrT0.Add(time.Minute), alrT0.Add(2*time.Minute)
	if events := run(observe(t1, at(ns1, "10.53.0.99", t1), at(ns2, "10.53.0.81", t1))); len(events) != 1 || events[0].Kind != EventOpen {
		t.Fatalf("the first run gave %v, want one open", alrBrief(events))
	}
	run(observe(t2, at(ns1, "10.53.0.99", t2), at(ns2, "10.53.0.99", t2)))
	if len(stored) != 1 || len(stored[0].Lines) != 2 || !stored[0].Noticed.Equal(t1) {
		var shown []Event
		for _, a := range stored {
			shown = append(shown, Event{Alert: a})
		}
		t.Fatalf("after ns2 showed the value too, the stored alerts are%s\nwant one, open, with both servers, noticed at %s",
			alrShow(shown), alrTime(t1))
	}
	if events := run(observe(t3, at(ns1, "10.53.0.81", t3), fails(ns2, t3))); len(events) != 0 {
		t.Errorf("ns1 gives the expected set and ns2, which showed the value, fails: events %v; want the alert open and no event", alrBrief(events))
	}
}
