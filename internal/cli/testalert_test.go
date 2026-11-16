package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/store"
)

var cliRequest = regexp.MustCompile(`^[0-9a-f]{32}\n$`)

// cliNextTry is the next try of a row that failed in the fake service.
var cliNextTry = time.Date(2030, 1, 2, 3, 4, 5, 0, time.UTC)

func cliDeliveries(channels ...string) []store.Delivery {
	var d []store.Delivery
	for _, c := range channels {
		d = append(d, store.Delivery{Channel: c, Label: "notice test -", Body: []byte(`{"text":"test"}`)})
	}
	return d
}

func cliDue(s *store.Store, channel string) ([]store.Row, error) {
	return s.Due(channel, time.Now().Add(time.Minute))
}

// cliServe plays osk run in the child process: it takes the request of
// test-alert, writes a notice that test-alert must pass over, one of
// another kind with the same line, and then the test notice, with its rows
// in the reverse order of the config. mode says what becomes of the row of
// siem; the row of slack is sent. It answers with the mode bits of the
// request and whether its content had the right form.
func cliServe(s *store.Store, state, mode string) string {
	path := filepath.Join(state, "test-alert")
	deadline := time.Now().Add(20 * time.Second)
	var info os.FileInfo
	var data []byte
	for {
		var err error
		if info, err = os.Stat(path); err == nil {
			if data, err = os.ReadFile(path); err == nil {
				break
			}
		}
		if time.Now().After(deadline) {
			return "error no request in " + path
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err := os.Remove(path); err != nil {
		return "error " + err.Error()
	}
	line := "request   " + strings.TrimSuffix(string(data), "\n")
	now := time.Now()
	err := s.Notify(store.Notice{Kind: store.NoticeExpectations, Domain: "corp.test.", Lines: []string{line}, At: now},
		cliDeliveries("slack", "siem"))
	if err == nil {
		err = s.Notify(store.Notice{Kind: store.NoticeTest, Lines: []string{"request   " + strings.Repeat("0", 32)}, At: now},
			cliDeliveries("slack", "siem"))
	}
	for _, c := range []string{"slack", "siem"} {
		rows, derr := cliDue(s, c)
		err = errors.Join(err, derr)
		for _, r := range rows {
			err = errors.Join(err, s.Record(r.ID, store.Done{State: store.RowGivenUp, Attempts: 1, Reason: "status 410", At: now}))
		}
	}
	if err == nil {
		err = s.Notify(store.Notice{Kind: store.NoticeTest, Lines: []string{line}, At: now}, cliDeliveries("siem", "slack"))
	}
	slack, err1 := cliDue(s, "slack")
	siem, err2 := cliDue(s, "siem")
	if err != nil || err1 != nil || err2 != nil || len(slack) != 1 || len(siem) != 1 {
		return fmt.Sprintf("error the rows of the test: %v %v %v %d %d", err, err1, err2, len(slack), len(siem))
	}
	err = s.Record(slack[0].ID, store.Done{State: store.RowSent, Attempts: 1, At: now})
	if err == nil {
		switch mode {
		case "sent":
			err = s.Record(siem[0].ID, store.Done{State: store.RowSent, Attempts: 1, At: now})
		case "failed":
			err = s.Record(siem[0].ID, store.Done{State: store.RowPending, Attempts: 1, NextAt: cliNextTry, Reason: "status 503", At: now})
		case "given-up":
			err = s.Record(siem[0].ID, store.Done{State: store.RowGivenUp, Attempts: 3, Reason: `status 404 "no_service"`, At: now})
		case "untried":
		default:
			err = fmt.Errorf("no mode %q", mode)
		}
	}
	if err != nil {
		return "error " + err.Error()
	}
	return fmt.Sprintf("served %04o %t", info.Mode().Perm(), cliRequest.Match(data))
}

type cliAttemptJSON struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Next    string `json:"next"`
}

// cliTestAlert runs test-alert beside a fake service of the given mode and
// gives what test-alert gave and how long it took.
func cliTestAlert(t *testing.T, mode string, args ...string) (code int, out, errOut string, took time.Duration) {
	t.Helper()
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	child := cliStartChild(t, w.state)
	child.send(t, "serve "+mode)
	start := time.Now()
	code, out, errOut = cliRun(time.Minute, "test-alert", append([]string{"--config", w.config}, args...)...)
	took = time.Since(start)
	if got := child.reply(t); got != "served 0600 true" {
		t.Errorf("the request of test-alert: %s, want served 0600 true (mode 0600, 32 lowercase hex octets and LF)", got)
	}
	if _, err := os.Lstat(filepath.Join(w.state, "test-alert")); err == nil {
		t.Error("the request is still there after the service took it")
	}
	return code, out, errOut, took
}

func cliAttempts(t *testing.T, attempts ...cliAttemptJSON) []string {
	var lines []string
	for _, a := range attempts {
		a.Type = "attempt"
		lines = append(lines, cliMarshal(t, a))
	}
	return lines
}

func TestTestAlertExits0WhenTheServiceSentTheTestToEveryChannel(t *testing.T) {
	code, out, errOut, _ := cliTestAlert(t, "sent")
	if code != 0 || errOut != "" {
		t.Errorf("exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk test-alert", out, "test slack sent", "test siem sent")

	code, out, errOut, _ = cliTestAlert(t, "sent", "--json")
	if code != 0 || errOut != "" {
		t.Errorf("--json: exit code %d, errors %q; want 0 and none", code, errOut)
	}
	cliSame(t, "osk test-alert --json", out, cliAttempts(t,
		cliAttemptJSON{Channel: "slack", State: "sent"}, cliAttemptJSON{Channel: "siem", State: "sent"})...)
}

func TestTestAlertExits1WithTheReasonAndNextTryOfAFailedChannel(t *testing.T) {
	code, out, _, _ := cliTestAlert(t, "failed")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	cliSame(t, "osk test-alert", out, "test slack sent", "test siem failed: status 503; next try 2030-01-02T03:04:05Z")

	code, out, _, _ = cliTestAlert(t, "failed", "--json")
	if code != 1 {
		t.Errorf("--json: exit code %d, want 1", code)
	}
	cliSame(t, "osk test-alert --json", out, cliAttempts(t, cliAttemptJSON{Channel: "slack", State: "sent"},
		cliAttemptJSON{Channel: "siem", State: "failed", Reason: "status 503", Next: "2030-01-02T03:04:05Z"})...)
}

func TestTestAlertExits1WithTheReasonOfAChannelThatGaveUp(t *testing.T) {
	const reason = `status 404 "no_service"`
	code, out, _, _ := cliTestAlert(t, "given-up")
	if code != 1 {
		t.Errorf("exit code %d, want 1", code)
	}
	cliSame(t, "osk test-alert", out, "test slack sent", "test siem given up: "+reason)

	code, out, _, _ = cliTestAlert(t, "given-up", "--json")
	if code != 1 {
		t.Errorf("--json: exit code %d, want 1", code)
	}
	cliSame(t, "osk test-alert --json", out, cliAttempts(t, cliAttemptJSON{Channel: "slack", State: "sent"},
		cliAttemptJSON{Channel: "siem", State: "given-up", Reason: reason})...)
}

// A row that the service never tries is reported once the 30 s are over.
func TestTestAlertReportsAChannelNotTriedWithin30Seconds(t *testing.T) {
	t.Parallel()
	code, out, _, took := cliTestAlert(t, "untried")
	if code != 1 || took < 29500*time.Millisecond || took > 32*time.Second {
		t.Errorf("exit code %d after %v; want 1 after 30s", code, took)
	}
	cliSame(t, "osk test-alert", out, "test slack sent", "test siem not tried within 30s")
}

func TestTestAlertJSONReportsAChannelNotTriedWithin30Seconds(t *testing.T) {
	t.Parallel()
	code, out, _, took := cliTestAlert(t, "untried", "--json")
	if code != 1 || took < 29500*time.Millisecond || took > 32*time.Second {
		t.Errorf("exit code %d after %v; want 1 after 30s", code, took)
	}
	cliSame(t, "osk test-alert --json", out, cliAttempts(t, cliAttemptJSON{Channel: "slack", State: "sent"},
		cliAttemptJSON{Channel: "siem", State: "not-tried"})...)
}

// Without a service nobody takes the request: test-alert removes it after
// 30 s and says where it looked.
func TestTestAlertWithoutAServiceFailsAfter30SecondsAndRemovesItsRequest(t *testing.T) {
	t.Parallel()
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	path := filepath.Join(w.state, "test-alert")
	type result struct {
		code        int
		out, errOut string
		took        time.Duration
	}
	done := make(chan result, 1)
	start := time.Now()
	go func() {
		code, out, errOut := cliRun(time.Minute, "test-alert", "--config", w.config)
		done <- result{code, out, errOut, time.Since(start)}
	}()

	var data []byte
	var info os.FileInfo
	cliWaitFor(t, "the request of test-alert", 5*time.Second, func() bool {
		var err error
		if info, err = os.Stat(path); err != nil {
			return false
		}
		data, err = os.ReadFile(path)
		return err == nil
	})
	if !cliRequest.Match(data) || info.Mode().Perm() != 0o600 {
		t.Errorf("the request holds %q with mode %04o; want 32 lowercase hex octets and LF, mode 0600", data, info.Mode().Perm())
	}

	r := <-done
	want := "osk: osk run did not take the test within 30s; is it running on " + w.state + "?\n"
	if r.code != 1 || r.out != "" || r.errOut != want || r.took < 29500*time.Millisecond || r.took > 32*time.Second {
		t.Errorf("exit code %d after %v, output %q, errors %q; want 1 after 30s, nothing and %q", r.code, r.took, r.out, r.errOut, want)
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("the request is still there")
	}
}

func TestTestAlertLeavesARequestThatIsAlreadyWaiting(t *testing.T) {
	w := cliNewWorld(t, false)
	cliSetSecrets(t, w)
	cliStore(t, w.state, func(*store.Store) {})
	path := filepath.Join(w.state, "test-alert")
	waiting := strings.Repeat("ab", 16) + "\n"
	cliWriteFile(t, path, waiting)
	code, out, errOut := cliRun(10*time.Second, "test-alert", "--config", w.config)
	if want := "osk: a test is already waiting for osk run\n"; code != 1 || out != "" || errOut != want {
		t.Errorf("exit code %d, output %q, errors %q; want 1, nothing and %q", code, out, errOut, want)
	}
	cliNoMarker(t, out, errOut)
	if data, err := os.ReadFile(path); err != nil || string(data) != waiting {
		t.Errorf("the waiting request holds %q (%v), want %q", data, err, waiting)
	}
}

func TestTestAlertStopsAtTheEndOfItsContextAndRemovesItsRequest(t *testing.T) {
	w := cliNewWorld(t, false)
	cliStore(t, w.state, func(*store.Store) {})
	path := filepath.Join(w.state, "test-alert")
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	seen := make(chan bool, 1)
	go func() {
		// The request is there once test-alert waits for the service.
		deadline := time.Now().Add(5 * time.Second)
		ok := false
		for !ok && time.Now().Before(deadline) {
			_, err := os.Stat(path)
			ok = err == nil
			time.Sleep(10 * time.Millisecond)
		}
		cancel()
		seen <- ok
	}()
	var out, errOut strings.Builder
	start := time.Now()
	code := TestAlert(ctx, []string{"--config", w.config}, &out, &errOut)
	if code != 1 || out.String() != "" || errOut.String() != "osk: context canceled\n" || time.Since(start) > 7*time.Second {
		t.Errorf("exit code %d after %v, output %q, errors %q; want 1 soon after the end of the context, nothing and %q",
			code, time.Since(start), out.String(), errOut.String(), "osk: context canceled\n")
	}
	if !<-seen {
		t.Error("test-alert wrote no request")
	}
	if _, err := os.Lstat(path); err == nil {
		t.Error("the request is still there")
	}
}
