package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// readFile reads an expectations file again; a variable only so that a test
// can play a read that hangs or gives the file in part.
var readFile = readRegular

// readRegular is readExpect for the file lines of the service, which name
// the path themselves.
func readRegular(path string) ([]byte, error) {
	data, err := readExpect(path)
	if errors.Is(err, config.ErrNotRegular) {
		return nil, config.ErrNotRegular
	}
	return data, err
}

// fileRead is the outcome of one read of a file: its octets, or the text of
// the error. The zero value stands for no read yet, and equals no read.
type fileRead struct {
	done bool
	data []byte
	err  string
}

func (r fileRead) same(o fileRead) bool {
	return r.done == o.done && bytes.Equal(r.data, o.data) && r.err == o.err
}

// domainRead is a read of the file of d.
type domainRead struct {
	d *watched
	r fileRead
}

// startReads reads each file and the test request again, each off the
// writer, so that a path that holds its reader (a FIFO swapped in, a mount
// that stopped answering) cannot stop the checks. No read of a file starts
// while one is in flight; one that has not ended after readStuck is reported
// once.
func (m *monitor) startReads(reads chan<- domainRead, requests chan<- request, now time.Time) error {
	if !m.asking {
		m.asking = true
		path := filepath.Join(m.cfg.State, "test-alert")
		go func() { requests <- readRequest(path) }()
	}
	for _, d := range m.domains {
		if err := m.startRead(d, reads, now); err != nil {
			return err
		}
	}
	return nil
}

func (m *monitor) startRead(d *watched, reads chan<- domainRead, now time.Time) error {
	if d.reading.IsZero() {
		d.reading, d.stuck = now, false
		read, path := readFile, d.path
		go func() {
			data, err := read(path)
			r := fileRead{done: true, data: data}
			if err != nil {
				r = fileRead{done: true, err: err.Error()}
			}
			reads <- domainRead{d, r}
		}()
		return nil
	}
	if d.stuck || now.Sub(d.reading) < readStuck {
		return nil
	}
	d.stuck = true
	return m.take(d, fileRead{done: true, err: "the read has not ended after " + readStuck.String()}, now)
}

// reread takes a read of the file once it is settled: a file read while it
// is written, in part or empty, must not replace the file in force, nor
// open and end an alert. A valid read is settled when the read before gave
// the same; one that is not valid when it stayed so for readSettle. The same
// outcome as the one taken last changes nothing, so a lasting problem is
// printed once.
func (m *monitor) reread(d *watched, r fileRead, now time.Time) error {
	if !r.same(d.next) {
		d.next, d.since = r, now
		return nil
	}
	if r.same(d.last) {
		return nil
	}
	if _, problem := d.parse(r); problem != nil && now.Sub(d.since) < readSettle {
		return nil
	}
	return m.take(d, r, now)
}

// parse gives the file that a read holds, or the problem that keeps it out.
func (d *watched) parse(r fileRead) (*expect.File, error) {
	if r.err != "" {
		return nil, errors.New(r.err)
	}
	f, err := expect.Keep(d.file, r.data)
	if err != nil {
		return nil, err
	}
	if !f.Domain.Equal(d.name) {
		return nil, &expect.Error{Problems: []expect.Problem{{
			Text: fmt.Sprintf("the file is for %s, not %s; fix the file or the config", f.Domain, d.name)}}}
	}
	return f, nil
}

// take puts the outcome of a read in force. A valid file becomes the file
// in force when its content differs, and the change is told; a file that
// cannot be read or is not valid leaves the one in force and opens or
// updates the invalid-file alert.
func (m *monitor) take(d *watched, r fileRead, now time.Time) error {
	d.last = r
	f, problem := d.parse(r)
	if problem != nil {
		for _, line := range fileLines(d.path, problem) {
			m.out.log(levelWarning, d.label, line)
		}
	}
	if err := m.fileChanges(d, problem, now); err != nil {
		return err
	}
	if problem != nil || f.String() == d.file.String() {
		return nil
	}
	d.file = f
	d.sched.Replace(f)
	d.replan(now)
	m.out.log(levelInfo, d.label, fmt.Sprintf("file %s changed: %d checks", d.path, len(d.sched.Checks())))
	m.printUnused(d)
	return m.sync(d.label, d.sched.Checks(), f.String(), now)
}

// fileLines gives a line for each problem of a read of the file.
func fileLines(path string, problem error) []string {
	var e *expect.Error
	if !errors.As(problem, &e) {
		return []string{"file " + path + ": " + problem.Error()}
	}
	lines := make([]string, len(e.Problems))
	for i, p := range e.Problems {
		lines[i] = "file " + path + ": " + p.Text
		if p.Line > 0 {
			lines[i] = fmt.Sprintf("file %s:%d: %s", path, p.Line, p.Text)
		}
	}
	return lines
}

// request is what a read of the test request found; err is that of its
// removal.
type request struct {
	found bool
	data  []byte
	err   error
}

// maxRequest is more than a request holds, so that a longer file reads as
// no request.
const maxRequest = 64

var requestForm = regexp.MustCompile(`^[0-9a-f]{32}\n$`)

// readRequest reads the test request that osk-dns-watcher test-alert left and removes
// it, so that it is taken once. Only a regular file is opened: a FIFO would
// hold the open.
func readRequest(path string) request {
	info, err := os.Lstat(path)
	if err != nil {
		return request{}
	}
	var data []byte
	if info.Mode().IsRegular() {
		if f, err := os.Open(path); err == nil {
			// A read that fails leaves no request to take.
			data, _ = io.ReadAll(io.LimitReader(f, maxRequest))
			_ = f.Close() // the file was only read, so closing it can lose nothing
		}
	}
	return request{found: true, data: data, err: os.Remove(path)}
}

// takeRequest sends a test notice to every channel for a valid request. A
// request that could not be removed is not taken: it would be taken again
// at every read.
func (m *monitor) takeRequest(r request, now time.Time) error {
	switch {
	case !r.found:
		return nil
	case r.err != nil:
		m.out.log(levelWarning, "", "test-alert ignored: "+r.err.Error())
		return nil
	case !requestForm.Match(r.data):
		m.out.log(levelWarning, "", "test-alert ignored: not a request")
		return nil
	}
	nonce := string(r.data[:32])
	m.out.print("test-alert " + nonce)
	return m.notify(store.Notice{Kind: store.NoticeTest, Lines: []string{"request   " + nonce}, At: now})
}
