package main

import (
	"bytes"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

const rfrLabel = "open high record-set records www.corp.test. A"

// rfrRuns are three runs of www.corp.test. A: ns1 gives a changed set; then
// ns2 gives it too; then ns1 gives the expected set again and ns2 fails.
func rfrRuns() []obs.Observation {
	ns1, ns2 := "192.0.2.11:53", "192.0.2.12:53"
	changed := func(addr string) obs.Answer {
		set := []dnswire.Record{cliRR("www.corp.test.", 300, dnswire.A{Addr: netip.MustParseAddr("192.0.2.99")})}
		return rteAt(addr, obs.RecordsResult(obs.Records{Set: set}))
	}
	return []obs.Observation{
		rteObs(rteWWW, changed(ns1), rteFine(rteWWW, ns2)),
		rteObs(rteWWW, changed(ns1), changed(ns2)),
		rteObs(rteWWW, rteFine(rteWWW, ns1), rteFail(ns2, obs.ReasonTimeout)),
	}
}

func rfrChannels() []deliver.Channel {
	return []deliver.Channel{deliver.NewSlack(nil, "https://hooks.example/x", decide.SeverityLow)}
}

// rfrStored checks that the alert is open with both servers, and that the
// only message to send is the one of its open.
func rfrStored(t *testing.T, s *store.Store) {
	t.Helper()
	open, err := s.OpenAlerts(rteWWW)
	if err != nil || len(open) != 1 || len(open[0].Lines) != 2 {
		t.Errorf("the open alerts are %+v, %v; want one that holds both servers", open, err)
	}
	rows, err := s.Due("slack", time.Now())
	var labels []string
	for _, r := range rows {
		labels = append(labels, r.Label)
	}
	if err != nil || !slices.Equal(labels, []string{rfrLabel}) {
		t.Errorf("the messages to send are %q, %v; want only %q", labels, err, rfrLabel)
	}
}

// A server that shows the changed set of an open alert only after the alert
// opened gives no alert line and no message, but the alert keeps it. When
// that server then fails while the first one gives the expected set again,
// the alert stays open: the server that fails may still give the changed set.
func TestRunKeepsAServerThatShowsTheChangeLater(t *testing.T) {
	s := rteStore(t)
	var log bytes.Buffer
	m, d := rteMonitor(t, s, &log)
	m.channels = rfrChannels()
	for _, o := range rfrRuns() {
		if err := m.judge(result{d: d, o: o}); err != nil {
			t.Fatal(err)
		}
	}
	m.out.close(time.Second)
	var alerts []string
	for _, l := range strings.Split(strings.TrimSuffix(log.String(), "\n"), "\n") {
		line, err := runParseLine(l)
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line.text, "alert ") {
			alerts = append(alerts, line.text)
		}
	}
	if want := []string{"alert " + rfrLabel}; !slices.Equal(alerts, want) {
		t.Errorf("the alert lines are %q, want only %q", alerts, want)
	}
	rfrStored(t, s)
}

// check --state takes the same runs in the same way.
func TestCheckStateKeepsAServerThatShowsTheChangeLater(t *testing.T) {
	s := rteStore(t)
	out := &lines{}
	for _, o := range rfrRuns() {
		if err := storeAlerts(out, s, rteFile(t), o, rfrChannels(), rteNow); err != nil {
			t.Fatal(err)
		}
	}
	if got, want := out.String(), "alert "+rfrLabel+"\n"; got != want {
		t.Errorf("the lines are %q, want %q", got, want)
	}
	rfrStored(t, s)
}
