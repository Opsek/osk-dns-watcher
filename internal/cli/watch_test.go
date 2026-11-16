package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// The alerts of the watch tests: 1 www, 2 mail, 3 the file of corp.test.
var (
	cliWWWKey  = cliRecordsKey("corp.test.", "www.corp.test.", dnswire.TypeA)
	cliMailKey = cliRecordsKey("corp.test.", "mail.corp.test.", dnswire.TypeA)
	cliFileKey = cliScopeKey("corp.test.")
)

// cliLongNotice has more lines than the text output shows, one with octets
// that Clean must escape and one longer than 160 octets.
var cliLongNotice = append([]string{"last beat 2026-11-11 11:00:00 UTC", "a`b<c>&d\x01", strings.Repeat("x", 200)},
	"line 4", "line 5", "line 6", "line 7", "line 8", "line 9", "line 10", "line 11", "line 12", "line 13", "line 14")

func cliWatchSetup(t *testing.T, state string) {
	t.Helper()
	cliStore(t, state, func(s *store.Store) {
		cliOpen(t, s, cliT0,
			cliAlert(decide.RuleRecordSet, decide.SeverityHigh, cliWWWKey, "10.53.0.81", cliT0, "10.53.0.99"),
			cliAlert(decide.RuleNotCovered, decide.SeverityMedium, cliMailKey, "", cliT0, "10.53.0.82"),
			cliAlert(decide.RuleInvalidFile, decide.SeverityMedium, cliFileKey, "", cliT0))
		if err := s.Notify(store.Notice{Kind: store.NoticeDown, Lines: []string{"old"}, At: cliT0}, nil); err != nil {
			t.Fatal(err)
		}
	})
}

func cliCurrent(s *store.Store, k obs.Key, r decide.Rule) (alert.Alert, error) {
	open, err := s.OpenAlerts(k)
	if err != nil {
		return alert.Alert{}, err
	}
	for _, a := range open {
		if a.Rule == r {
			return a, nil
		}
	}
	return alert.Alert{}, fmt.Errorf("no open %s alert of %v", r, k)
}

// cliWatchBatch makes the writes of one batch in the child process. Each
// batch is one transaction, so a watch sees all of it in one poll; the
// times differ from the order of the ids on purpose.
func cliWatchBatch(s *store.Store, name string) error {
	www, err1 := cliCurrent(s, cliWWWKey, decide.RuleRecordSet)
	mail, err2 := cliCurrent(s, cliMailKey, decide.RuleNotCovered)
	file, err3 := cliCurrent(s, cliFileKey, decide.RuleInvalidFile)
	switch name {
	case "one":
		if err := errors.Join(err1, err2, err3); err != nil {
			return err
		}
		www.Value, www.Noticed = "10.53.0.11:53 ns1.corp.test. 10.53.0.98", cliT0.Add(20*time.Second)
		mail.Severity, mail.Peak, mail.Noticed = decide.SeverityHigh, decide.SeverityHigh, cliT0.Add(10*time.Second)
		file.Noticed = cliT0.Add(10 * time.Second)
		return s.Apply(cliWWWKey, false, cliT0.Add(10*time.Second), []store.Write{
			cliEvent(alert.EventUpdate, www, decide.SeverityHigh, cliT0.Add(20*time.Second)),
			cliEvent(alert.EventEscalate, mail, decide.SeverityMedium, cliT0.Add(10*time.Second)),
			cliEvent(alert.EventReminder, file, decide.SeverityMedium, cliT0.Add(10*time.Second), "slack"),
		})
	case "two":
		if err := errors.Join(err1, err2); err != nil {
			return err
		}
		www.Open, www.Resolved = false, cliT0.Add(40*time.Second)
		mail.Open, mail.Resolved = false, cliT0.Add(30*time.Second)
		n := store.Notice{Kind: store.NoticeExpectations, Domain: "corp.test.",
			Lines: []string{"- www.corp.test. A 10.53.0.81", "+ www.corp.test. A 10.53.0.99"}, At: cliT0.Add(30 * time.Second)}
		return s.Reload("corp.test.", cliCorpFile, &n, nil, []store.Write{
			cliEvent(alert.EventResolve, www, www.Severity, www.Resolved),
			cliEvent(alert.EventResolve, mail, mail.Severity, mail.Resolved),
		})
	case "three":
		return s.Notify(store.Notice{Kind: store.NoticeDown, Lines: cliLongNotice, At: cliT0.Add(50 * time.Second)}, nil)
	case "four":
		rows, err := s.Due("slack", cliT0.Add(time.Hour))
		if err != nil || len(rows) != 1 {
			return fmt.Errorf("rows of slack %v, %v; want one", rows, err)
		}
		return s.Record(rows[0].ID, store.Done{State: store.RowGivenUp, Attempts: 1, Reason: `status 404 "no_service"`,
			At: cliT0.Add(time.Minute)})
	}
	return errors.New("no batch " + name)
}

type cliEventJSON struct {
	Type     string   `json:"type"`
	ID       int64    `json:"id"`
	Alert    int64    `json:"alert"`
	Kind     string   `json:"kind"`
	Severity string   `json:"severity"`
	Was      string   `json:"was"`
	Rule     string   `json:"rule"`
	Check    cliCheck `json:"check"`
	Value    string   `json:"value"`
	At       string   `json:"at"`
}

type cliNoticeJSON struct {
	Type   string   `json:"type"`
	ID     int64    `json:"id"`
	Kind   string   `json:"kind"`
	Domain string   `json:"domain"`
	Lines  []string `json:"lines"`
	At     string   `json:"at"`
}

func cliAt(seconds int) string { return cliJSONTime(cliT0.Add(time.Duration(seconds) * time.Second)) }

var (
	cliWWWCheck  = cliRecordsCheck("www.corp.test.", "A")
	cliMailCheck = cliRecordsCheck("mail.corp.test.", "A")
	cliFileCheck = cliCheck{Domain: "corp.test.", Name: "corp.test."}
)

// cliWatchExpect gives, for each batch, the lines that watch prints for it,
// as text and as JSON. probes is the number of probe notices written
// before the batches, which sets the ids of the later notices.
func cliWatchExpect(t *testing.T, probes int) (text, js map[string][]string) {
	t.Helper()
	ev := func(id, a int64, kind, sev, was, rule string, check cliCheck, value string, at int) string {
		return cliMarshal(t, cliEventJSON{"event", id, a, kind, sev, was, rule, check, value, cliAt(at)})
	}
	no := func(id int64, kind, domain string, lines []string, at int) string {
		return cliMarshal(t, cliNoticeJSON{"notice", id, kind, domain, lines, cliAt(at)})
	}
	const wwwValue = "10.53.0.11:53 ns1.corp.test. 10.53.0.98"
	const mailValue = "10.53.0.11:53 ns1.corp.test. 10.53.0.82"
	expectations := []string{"- www.corp.test. A 10.53.0.81", "+ www.corp.test. A 10.53.0.99"}
	n := int64(probes) + 1 // the notice before the watch, then the probes
	text = map[string][]string{
		"one": {
			cliAt(10) + " alert 2 escalate high not-covered records mail.corp.test. A",
			cliAt(10) + " alert 3 reminder medium invalid-file corp.test.",
			cliAt(20) + " alert 1 update high record-set records www.corp.test. A",
		},
		"two": {
			cliAt(30) + " alert 2 resolve high not-covered records mail.corp.test. A",
			cliAt(30) + " notice expectations corp.test.",
			"  " + expectations[0],
			"  " + expectations[1],
			cliAt(40) + " alert 1 resolve high record-set records www.corp.test. A",
		},
		"three": {
			cliAt(50) + " notice down -",
			"  last beat 2026-11-11 11:00:00 UTC",
			`  a\096b&lt;c&gt;&amp;d\001`,
			"  " + strings.Repeat("x", 154) + " [cut]",
			"  line 4", "  line 5", "  line 6", "  line 7", "  line 8", "  line 9", "  line 10", "  line 11", "  line 12",
			"  and 2 more lines",
		},
		"four": {cliAt(60) + ` alert 3 given-up medium invalid-file corp.test.: slack: status 404 "no_service"`},
	}
	js = map[string][]string{
		"one": {
			ev(5, 2, "escalate", "high", "medium", "not-covered", cliMailCheck, mailValue, 10),
			ev(6, 3, "reminder", "medium", "medium", "invalid-file", cliFileCheck, "problem of invalid-file", 10),
			ev(4, 1, "update", "high", "high", "record-set", cliWWWCheck, wwwValue, 20),
		},
		"two": {
			ev(8, 2, "resolve", "high", "high", "not-covered", cliMailCheck, mailValue, 30),
			no(n+1, "expectations", "corp.test.", expectations, 30),
			ev(7, 1, "resolve", "high", "high", "record-set", cliWWWCheck, wwwValue, 40),
		},
		"three": {no(n+2, "down", "", cliLongNotice, 50)},
		"four":  {ev(9, 3, "given-up", "medium", "medium", "invalid-file", cliFileCheck, `slack: status 404 "no_service"`, 60)},
	}
	return text, js
}

func cliProbeText(n int) []string {
	return []string{cliJSONTime(cliT0) + " notice test -", "  probe " + strconv.Itoa(n)}
}

func cliProbeJSON(t *testing.T, n int) string {
	return cliMarshal(t, cliNoticeJSON{"notice", int64(n) + 1, "test", "", []string{"probe " + strconv.Itoa(n)}, cliJSONTime(cliT0)})
}

// cliStripProbes takes the probes from the start of the lines of one watch
// and checks that they are the last ones written, each once and in order.
func cliStripProbes(t *testing.T, what string, lines []string, sent int, probe func(int) []string) []string {
	t.Helper()
	for first := 1; first <= sent; first++ {
		var want []string
		for n := first; n <= sent; n++ {
			want = append(want, probe(n)...)
		}
		if len(lines) >= len(want) && strings.Join(lines[:len(want)], "\n") == strings.Join(want, "\n") {
			return lines[len(want):]
		}
	}
	t.Errorf("%s does not start with the last probes up to probe %d, each once:\n%s", what, sent, strings.Join(lines, "\n"))
	return lines
}

// cliWatcher is a watch that runs while the test writes; code and err may
// be read once done is closed.
type cliWatcher struct {
	out  *cliBuffer
	err  bytes.Buffer
	code int
	done chan struct{}
}

func cliStartWatch(ctx context.Context, w *cliWorld, args ...string) *cliWatcher {
	r := &cliWatcher{out: &cliBuffer{}, done: make(chan struct{})}
	go func() {
		r.code = Watch(ctx, append([]string{"--config", w.config}, args...), r.out, &r.err)
		close(r.done)
	}()
	return r
}

func cliHas(out, line string) bool { return strings.Contains("\n"+out, "\n"+line+"\n") }

// Watch prints only what is written after it starts, each event and notice
// once, in the order of their times, an event before a notice of the same
// time, in text and in JSON; it ends with exit 0 when its context ends.
func TestWatchPrintsEachNewEventAndNoticeOnceInOrderUntilItsContextEnds(t *testing.T) {
	old := watchEvery
	watchEvery = 50 * time.Millisecond
	t.Cleanup(func() { watchEvery = old })
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	cliWatchSetup(t, w.state)
	child := cliStartChild(t, w.state)

	ctx, cancel := context.WithCancel(context.Background())
	text, js := cliStartWatch(ctx, w), cliStartWatch(ctx, w, "--json")
	t.Cleanup(func() {
		cancel()
		for _, r := range []*cliWatcher{text, js} {
			select {
			case <-r.done:
			case <-time.After(5 * time.Second):
				t.Error("a watch did not end")
			}
		}
	})

	// Nothing tells when a watch has read where the store ends, so probes
	// are written until both print one; the later probes print as well.
	sent := 0
	seen := func() bool {
		return strings.Contains(text.out.String(), "  probe ") && strings.Contains(js.out.String(), `"probe `)
	}
	for !seen() {
		if sent == 30 {
			t.Fatalf("no watch printed any of %d probes; text:\n%s\nJSON:\n%s", sent, text.out.String(), js.out.String())
		}
		sent++
		child.do(t, "probe "+strconv.Itoa(sent))
		deadline := time.Now().Add(300 * time.Millisecond)
		for !seen() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
	}
	waitBoth := func(what string, textLine, jsLine string) {
		cliWaitFor(t, what, 10*time.Second, func() bool { return cliHas(text.out.String(), textLine) && cliHas(js.out.String(), jsLine) })
	}
	waitBoth("the last probe", cliProbeText(sent)[1], cliProbeJSON(t, sent))

	wantText, wantJS := cliWatchExpect(t, sent)
	var allText, allJS []string
	for _, b := range []string{"one", "two", "three", "four"} {
		child.do(t, "batch "+b)
		waitBoth("batch "+b, wantText[b][len(wantText[b])-1], wantJS[b][len(wantJS[b])-1])
		allText = append(allText, wantText[b]...)
		allJS = append(allJS, wantJS[b]...)
	}
	// Two more probes, each waited for: a watch that prints a row again in a
	// later poll shows it before them. Their notices follow the two of the
	// batches.
	for i, n := range []int{100, 101} {
		line := cliMarshal(t, cliNoticeJSON{"notice", int64(sent + 4 + i), "test", "", []string{"probe " + strconv.Itoa(n)}, cliJSONTime(cliT0)})
		child.do(t, "probe "+strconv.Itoa(n))
		waitBoth("probe "+strconv.Itoa(n), cliProbeText(n)[1], line)
		allText = append(allText, cliProbeText(n)...)
		allJS = append(allJS, line)
	}

	cancel()
	end := time.Now()
	for _, r := range []*cliWatcher{text, js} {
		select {
		case <-r.done:
			if r.code != 0 || r.err.Len() != 0 || time.Since(end) > 2*time.Second {
				t.Errorf("watch after the end of its context: exit code %d after %v, errors %q; want 0 within 2s and none",
					r.code, time.Since(end), r.err.String())
			}
		case <-time.After(2 * time.Second):
			t.Fatal("watch did not end within 2s of the end of its context")
		}
	}

	cliNoMarker(t, text.out.String(), js.out.String())
	gotText := cliStripProbes(t, "the text of watch", strings.Split(strings.TrimSuffix(text.out.String(), "\n"), "\n"), sent, cliProbeText)
	if strings.Join(gotText, "\n") != strings.Join(allText, "\n") {
		t.Errorf("watch printed after the probes:\n%s\nwant:\n%s", strings.Join(gotText, "\n"), strings.Join(allText, "\n"))
	}
	gotJS := cliStripProbes(t, "the JSON of watch", strings.Split(strings.TrimSuffix(js.out.String(), "\n"), "\n"), sent,
		func(n int) []string { return []string{cliProbeJSON(t, n)} })
	if strings.Join(gotJS, "\n") != strings.Join(allJS, "\n") {
		t.Errorf("watch --json printed after the probes:\n%s\nwant:\n%s", strings.Join(gotJS, "\n"), strings.Join(allJS, "\n"))
	}
}
