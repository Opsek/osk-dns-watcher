package main

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// logLines is how many lines wait for an output that takes them slowly;
	// beyond, lines are dropped and counted.
	logLines = 1024
	// logDrain is how long the stop waits for the output to take them.
	logDrain = time.Second
)

const (
	levelInfo    = "info"
	levelWarning = "warning"
	levelError   = "error"
)

// logLine is one line of standard output, a JSON object with its keys in
// this order.
type logLine struct {
	Time   string `json:"time"`
	Level  string `json:"level"`
	Event  string `json:"event"`
	Domain string `json:"domain,omitempty"`
	Text   string `json:"text"`
}

// logger writes the lines of standard output from a goroutine of its own, so
// that an output that nobody reads cannot stop the checks. Each line holds
// the time it was printed and is one Write; the lines are queued under the
// mutex, so they never mix and stand in time order.
type logger struct {
	mu      sync.Mutex
	lines   chan string
	dropped int
	done    chan struct{} // closed when every queued line was written
}

func newLogger(w io.Writer, size int) *logger {
	l := &logger{lines: make(chan string, size), done: make(chan struct{})}
	go func() {
		defer close(l.done)
		for line := range l.lines {
			// A broken log must not blind the monitor.
			_, _ = io.WriteString(w, line)
		}
	}()
	return l
}

// print prints text as an ordinary line about no one domain.
func (l *logger) print(text string) {
	l.log(levelInfo, "", text)
}

// log prints text at level; domain names the domain that the line is about,
// "" for none. It never waits: a line that finds the queue full is dropped,
// and the next line that finds room is preceded by the count.
func (l *logger) log(level, domain, text string) {
	now := time.Now()
	l.mu.Lock()
	defer l.mu.Unlock()
	// Only log adds to the queue, under the mutex, so the room seen here
	// stays until the sends below.
	if l.dropped > 0 && cap(l.lines)-len(l.lines) >= 2 {
		l.lines <- jsonLine(now, levelInfo, "", "dropped "+strconv.Itoa(l.dropped)+" lines: the output was not read")
		l.dropped = 0
	}
	if l.dropped > 0 || len(l.lines) == cap(l.lines) {
		l.dropped++
		return
	}
	l.lines <- jsonLine(now, level, domain, text)
}

// jsonLine gives the line of text, whose event is its first word.
func jsonLine(now time.Time, level, domain, text string) string {
	event, _, _ := strings.Cut(text, " ")
	// Marshal cannot fail on a struct of strings.
	b, _ := json.Marshal(logLine{now.UTC().Format(receivedLayout), level, event, domain, text})
	return string(b) + "\n"
}

// close lets the output take the queued lines for at most wait: a write that
// never ends must not hold the stop. Nothing may print after it.
func (l *logger) close(wait time.Duration) {
	close(l.lines)
	select {
	case <-l.done:
	case <-time.After(wait):
	}
}
