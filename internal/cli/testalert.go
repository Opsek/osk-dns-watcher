package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"time"

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// testEvery and testLimit pace test-alert; a test shortens them.
var (
	testEvery = 500 * time.Millisecond
	testLimit = 30 * time.Second
)

type attempt struct {
	Type    string `json:"type"`
	Channel string `json:"channel"`
	State   string `json:"state"`
	Reason  string `json:"reason"`
	Next    string `json:"next"`
}

// TestAlert runs "osk test-alert": it asks the running service, through a
// request file in the state folder, to send a test notice to every channel,
// and prints what each channel did with it.
func TestAlert(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	o, msg := testAlertCommand.parseNoArgs(args)
	if msg != "" {
		return testAlertCommand.wrongUse(stderr, msg)
	}
	c, r, code := open(o.config, stderr)
	if code != 0 {
		return code
	}
	defer closeReader(r)
	// The cursor is taken before the request, so the test notice lies after it.
	_, after, err := r.Last()
	if err != nil {
		return failErr(stderr, err)
	}
	path := filepath.Join(c.State, "test-alert")
	nonce, err := request(path)
	if err != nil {
		return failErr(stderr, err)
	}
	rows, taken, err := awaitTest(ctx, r, after, nonce)
	if !taken {
		// The service removes the file when it takes it; otherwise no
		// request may stay behind for a later start.
		if rmErr := os.Remove(path); !errors.Is(rmErr, fs.ErrNotExist) {
			err = errors.Join(err, rmErr)
		}
	}
	switch {
	case err != nil:
		return failErr(stderr, err)
	case !taken:
		return fail(stderr, 1, "osk: osk run did not take the test within 30s; is it running on "+c.State+"?\n")
	}
	return printAttempts(c, rows, o.json, stdout, stderr)
}

// request writes the nonce under a temporary name and then links it to path,
// so the service never reads a request half written. Link, unlike Rename,
// fails when path exists, so a request that waits is never replaced.
func request(path string) (string, error) {
	b := make([]byte, 16)
	_, _ = rand.Read(b) // crypto/rand.Read never returns an error
	nonce := hex.EncodeToString(b)
	tmp, err := os.CreateTemp(filepath.Dir(path), ".test-alert-*")
	if err != nil {
		return "", err
	}
	_, err = tmp.WriteString(nonce + "\n")
	err = errors.Join(err, tmp.Close())
	if err == nil {
		err = os.Link(tmp.Name(), path)
	}
	// A temporary file left behind harms nothing: the service reads only path.
	_ = os.Remove(tmp.Name())
	if errors.Is(err, fs.ErrExist) {
		return "", errors.New("a test is already waiting for osk run")
	}
	if err != nil {
		return "", err
	}
	return nonce, nil
}

// awaitTest polls until the test notice of nonce is stored and every one of
// its rows is sent, given up or tried once, or until testLimit has passed.
// taken reports that the notice was found.
func awaitTest(ctx context.Context, r *store.Reader, after int64, nonce string) (rows []store.RowStatus, taken bool, err error) {
	deadline := time.Now().Add(testLimit)
	tick := time.NewTicker(testEvery)
	defer tick.Stop()
	var id int64
	for {
		if id == 0 {
			id, after, err = findTest(r, after, nonce)
		}
		if err == nil && id != 0 {
			rows, err = r.NoticeRows(id)
		}
		if err != nil {
			return nil, id != 0, err
		}
		if id != 0 && settled(rows) || !time.Now().Before(deadline) {
			return rows, id != 0, nil
		}
		select {
		case <-ctx.Done():
			return nil, id != 0, ctx.Err()
		case <-tick.C:
		}
	}
}

// findTest gives the id of the test notice of nonce, 0 when it is not
// stored yet, and the cursor after the notices it read.
func findTest(r *store.Reader, after int64, nonce string) (id, cursor int64, err error) {
	notices, err := r.Notices(after)
	if err != nil {
		return 0, after, err
	}
	for _, n := range notices {
		if n.Kind == store.NoticeTest && slices.Contains(n.Lines, "request   "+nonce) {
			return n.ID, n.ID, nil
		}
		after = n.ID
	}
	return 0, after, nil
}

func settled(rows []store.RowStatus) bool {
	return !slices.ContainsFunc(rows, func(r store.RowStatus) bool {
		return r.State == store.RowPending && r.Attempts == 0
	})
}

func printAttempts(c *config.Config, rows []store.RowStatus, json bool, stdout, stderr io.Writer) int {
	p := &printer{w: stdout, json: json}
	code := 0
	for _, name := range c.Channels() {
		a := attemptOf(name, rows)
		p.print(a.text(), a)
		if a.State != "sent" {
			code = 1
		}
	}
	return p.done(stderr, code)
}

// attemptOf gives the outcome of the row of channel; a channel with no row,
// or whose row was not tried, was not tried within the limit.
func attemptOf(channel string, rows []store.RowStatus) attempt {
	a := attempt{Type: "attempt", Channel: channel, State: "not-tried"}
	i := slices.IndexFunc(rows, func(r store.RowStatus) bool { return r.Channel == channel })
	if i < 0 {
		return a
	}
	r := rows[i]
	switch r.State {
	case store.RowSent:
		a.State = "sent"
	case store.RowGivenUp:
		a.State, a.Reason = "given-up", r.Reason
	case store.RowPending:
		if r.Attempts > 0 {
			a.State, a.Reason, a.Next = "failed", r.Reason, stamp(r.NextAt)
		}
	}
	return a
}

func (a attempt) text() string {
	prefix := "test " + a.Channel + " "
	switch a.State {
	case "sent":
		return prefix + "sent"
	case "failed":
		return prefix + "failed: " + a.Reason + "; next try " + a.Next
	case "given-up":
		return prefix + "given up: " + a.Reason
	}
	return prefix + "not tried within 30s"
}
