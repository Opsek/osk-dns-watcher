package httpclient

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"
)

// The top letter of each range is a name octet, and capitals read back in
// lower case.
func TestHostOfTakesTheLastLetters(t *testing.T) {
	for _, c := range []struct{ url, want string }{
		{"https://hostz.test/x", "hostz.test:443"},
		{"https://zz.test/x", "zz.test:443"},
		{"https://HOSTZ.TEST/x", "hostz.test:443"},
		{"https://ZZ.Test/x", "zz.test:443"},
		{"https://a9.test/x", "a9.test:443"},
	} {
		if got, err := HostOf(c.url); err != nil || got != c.want {
			t.Errorf("HostOf(%q) = %q, %v; want %q", c.url, got, err, c.want)
		}
	}
}

// Retry-After takes every digit, 9 among them.
func TestRetryAfterTakesTheDigitNine(t *testing.T) {
	for _, c := range []struct {
		value string
		want  time.Duration
	}{
		{"9", 9 * time.Second},
		{"19", 19 * time.Second},
		{"90", 90 * time.Second},
		{"99", 99 * time.Second},
	} {
		if got := retryAfter(c.value); got != c.want {
			t.Errorf("retryAfter(%q) = %v; want %v", c.value, got, c.want)
		}
	}
}

// hceTimeout is a network error that reports a timeout but is no context
// deadline.
type hceTimeout struct{ timeout bool }

func (e hceTimeout) Error() string { return "hce: i/o" }
func (e hceTimeout) Timeout() bool { return e.timeout }

// A context deadline and a network timeout each count as a timeout, wrapped
// or not; an error that is neither does not.
func TestDoErrorTimeouts(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want error
	}{
		{"context deadline", context.DeadlineExceeded, ErrTimeout},
		{"wrapped context deadline", fmt.Errorf("hce: %w", context.DeadlineExceeded), ErrTimeout},
		{"network timeout", hceTimeout{true}, ErrTimeout},
		{"wrapped network timeout", fmt.Errorf("hce: %w", hceTimeout{true}), ErrTimeout},
		{"network error without timeout", hceTimeout{false}, errAnswer},
		{"other error", errors.New("hce: other"), errAnswer},
	} {
		if got := doError(c.err); got != c.want {
			t.Errorf("%s: doError gives %v; want %v", c.name, got, c.want)
		}
	}
}
