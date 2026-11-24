package main

import (
	"bytes"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

var rteNow = time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)

// rteFile watches the NS set and www of corp.test.
func rteFile(t *testing.T) *expect.File {
	t.Helper()
	f, err := expect.Parse([]byte("domain corp.test.\ncorp.test. NS ns1.corp.test.\nwww.corp.test. A 192.0.2.80\n"))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

var (
	rteWWW = obs.RecordsKey(cliName("corp.test."), cliName("www.corp.test."), dnswire.TypeA)
	rteNS  = obs.RecordsKey(cliName("corp.test."), cliName("corp.test."), dnswire.TypeNS)
)

// rteAt is the answer of ns1.corp.test. at addr.
func rteAt(addr string, r obs.Result) obs.Answer {
	s := obs.Server{Name: cliName("ns1.corp.test."), Addr: netip.MustParseAddrPort(addr)}
	return obs.Answer{Proof: obs.Proof{Server: s, Received: rteNow}, Result: r}
}

// rteFine is an answer of k that matches rteFile.
func rteFine(k obs.Key, addr string) obs.Answer {
	set := []dnswire.Record{cliWWW}
	if k.Type == dnswire.TypeNS {
		set = cliNS[:1]
	}
	return rteAt(addr, obs.RecordsResult(obs.Records{Set: set}))
}

func rteFail(addr string, reason obs.Reason) obs.Answer {
	return rteAt(addr, obs.FailureResult(obs.Failure{Reason: reason, Detail: "from the test"}))
}

func rteObs(k obs.Key, answers ...obs.Answer) obs.Observation {
	return obs.Observation{Key: k, Start: rteNow, Zone: cliName("corp.test."), Answers: answers}
}

func rteStore(t *testing.T) *store.Store {
	t.Helper()
	s, err := store.Open(filepath.Join(t.TempDir(), "state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

// rteMonitor is a service of corp.test. with the file of rteFile, whose log
// goes to out.
func rteMonitor(t *testing.T, s *store.Store, out *bytes.Buffer) (*monitor, *watched) {
	t.Helper()
	d := newWatched(config.Domain{Name: cliName("corp.test."), Expect: "/corp.test.expect"}, rteFile(t), schedule.Defaults(), rteNow)
	return &monitor{store: s, out: newLogger(out, logLines), domains: []*watched{d}}, d
}

// A run is clean when every server that this machine can send to gave a
// usable answer that matches the file. An address with no route is left
// out of that, but only beside a usable answer. A failure of any other kind
// is never left out, at an IPv6 address neither: it can come from the
// network. Both the service and check --state record the clean time so.
func TestCleanTimeLeavesOutOnlyAnAddressWithNoRoute(t *testing.T) {
	v4, v6 := "192.0.2.11:53", "[2001:db8::11]:53"
	for _, c := range []struct {
		name  string
		o     obs.Observation
		clean bool
	}{
		{"a usable answer and no route", rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNoRoute)), true},
		{"a usable answer and a network failure at IPv6", rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNetwork)), false},
		{"a usable answer and a timeout", rteObs(rteWWW, rteFine(rteWWW, v4), rteFail("192.0.2.12:53", obs.ReasonTimeout)), false},
		{"only no route", rteObs(rteWWW, rteFail(v6, obs.ReasonNoRoute), rteFail("[2001:db8::12]:53", obs.ReasonNoRoute)), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := rteStore(t)
			events, err := alertEvents(s, rteFile(t), c.o, rteNow)
			if err != nil || events.Clean != c.clean {
				t.Errorf("check --state: Clean %v, %v; want %v", events.Clean, err, c.clean)
			}

			var log bytes.Buffer
			m, d := rteMonitor(t, s, &log)
			if err := m.judge(result{d: d, o: c.o}); err != nil {
				t.Fatal(err)
			}
			m.out.close(time.Second)
			at, err := s.LastClean(rteWWW)
			if err != nil || at.IsZero() == c.clean {
				t.Errorf("run: last clean time %v, %v; want one: %v", at, err, c.clean)
			}
		})
	}
}

// The service says once that this machine has no route to some addresses,
// however many checks meet them, and once that it has a route again, when
// the last check that met one no longer does.
func TestRunTellsOnceOfAddressesWithNoRoute(t *testing.T) {
	v4, v6 := "192.0.2.11:53", "[2001:db8::11]:53"
	var log bytes.Buffer
	m, d := rteMonitor(t, rteStore(t), &log)
	for _, o := range []obs.Observation{
		rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNoRoute)),
		rteObs(rteNS, rteFine(rteNS, v4), rteFail(v6, obs.ReasonNoRoute)),
		rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNoRoute)),
		rteObs(rteWWW, rteFine(rteWWW, v4)),
		rteObs(rteNS, rteFine(rteNS, v4), rteFail(v6, obs.ReasonNetwork)),
		rteObs(rteNS, rteFail(v6, obs.ReasonNoRoute)),
	} {
		if err := m.judge(result{d: d, o: o}); err != nil {
			t.Fatal(err)
		}
	}
	m.out.close(time.Second)
	var got []string
	for _, l := range strings.Split(strings.TrimSuffix(log.String(), "\n"), "\n") {
		line, err := runParseLine(l)
		if err != nil {
			t.Fatal(err)
		}
		if line.event == "warning" || line.event == "route" {
			got = append(got, line.level+" "+line.text)
		}
	}
	want := []string{
		"warning warning this machine has no route to some addresses of the nameservers, such as 2001:db8::11. " +
			"osk-dns-watcher cannot ask them. A check counts as OK when the other servers answer.",
		"info route back: this machine has a route to every address of the nameservers again",
		"warning warning this machine has no route to some addresses of the nameservers, such as 2001:db8::11. " +
			"osk-dns-watcher cannot ask them. A check counts as OK when the other servers answer.",
	}
	if strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Errorf("the lines about routes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

// check --expect counts the addresses with no route apart, once each, and
// they do not make the exit code 1. Beside no usable answer, or as a
// network failure, a failure stays an unknown answer. check without --expect
// fails by the same rule.
func TestCheckCountsAddressesWithNoRouteApart(t *testing.T) {
	v4, v6, v6b := "192.0.2.11:53", "[2001:db8::11]:53", "[2001:db8::12]:53"
	fine := []obs.Observation{
		rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNoRoute)),
		rteObs(rteNS, rteFine(rteNS, v4), rteFail(v6, obs.ReasonNoRoute), rteFail(v6b, obs.ReasonNoRoute)),
	}
	const notAsked = "not asked: 2 IPv6 addresses of the servers, to which this machine has no route"
	for _, c := range []struct {
		name         string
		observations []obs.Observation
		unknown      int
		tail         []string
		clean        bool
	}{
		{"usable answers beside", fine, 0, []string{notAsked, "checked corp.test. 2 sets: 0 findings, 0 unknown answers"}, true},
		{"no usable answer", []obs.Observation{rteObs(rteWWW, rteFail(v6, obs.ReasonNoRoute))}, 1,
			[]string{"checked corp.test. 1 sets: 0 findings, 1 unknown answers"}, false},
		{"a network failure", []obs.Observation{rteObs(rteWWW, rteFine(rteWWW, v4), rteFail(v6, obs.ReasonNetwork))}, 1,
			[]string{"checked corp.test. 1 sets: 0 findings, 1 unknown answers"}, false},
	} {
		out := &lines{}
		clean := formatFindings(out, rteFile(t), c.observations, rteNow)
		got := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
		unknown := 0
		for _, l := range got {
			if strings.HasPrefix(l, "unknown ") {
				unknown++
			}
		}
		if tail := got[max(0, len(got)-len(c.tail)):]; clean != c.clean || unknown != c.unknown || strings.Join(tail, "\n") != strings.Join(c.tail, "\n") {
			t.Errorf("%s: clean %v, output:\n%s\nwant clean %v, %d unknown lines and at the end:\n%s",
				c.name, clean, out.String(), c.clean, c.unknown, strings.Join(c.tail, "\n"))
		}
		if failed := formatObservations(&lines{}, c.observations); failed == c.clean {
			t.Errorf("%s: check without --expect failed %v, want %v", c.name, failed, !c.clean)
		}
	}

	out := &lines{json: true}
	formatFindings(out, rteFile(t), fine, rteNow)
	if !strings.Contains(out.String(), `{"type":"notasked","addresses":2,"reason":"no-route"}`) {
		t.Errorf("JSON output:\n%s\nwant the line of the addresses with no route", out.String())
	}
}
