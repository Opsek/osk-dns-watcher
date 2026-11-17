package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// outcome is the judgement of one mutant.
type outcome int

const (
	survived outcome = iota
	killed
	timedOut // killed: the tests still ran at the time limit
	notViable
)

// minLimit is the least time that the tests of a mutant may run before the
// mutant counts as killed. Tests of this command shorten it.
var minLimit = 20 * time.Second

// compileError matches the line that the go command prints for an error at
// a place in a Go file. A build that fails without such a line did not fail
// because of the mutant.
var compileError = regexp.MustCompile(`(?m)\.go:\d+:\d+: `)

// judge builds and runs tests in a temporary folder that holds the build
// cache too: no compiled mutant stays in a shared cache, and removing the
// folder removes every file that the go command and the tests made.
type judge struct {
	root, tmp string // absolute
	env       []string
	workers   int
}

func newJudge(o options, tmp string) (judge, error) {
	root, err := filepath.Abs(o.root)
	if err != nil {
		return judge{}, err
	}
	cache, temp := filepath.Join(tmp, "cache"), filepath.Join(tmp, "tmp")
	for _, dir := range []string{cache, temp} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			return judge{}, err
		}
	}
	// GOFLAGS is cleared, so that no build tag and no race detector reach
	// the builds.
	env := append(os.Environ(), "GOCACHE="+cache, "GOTMPDIR="+temp, "TMPDIR="+temp, "GOFLAGS=")
	return judge{root, tmp, env, o.workers}, nil
}

// folder holds the mutants of one package and their outcomes, in the same
// order.
type folder struct {
	name     string
	mutants  []mutant
	outcomes []outcome
	took     time.Duration
}

func (f folder) viable() int {
	return len(f.outcomes) - f.count(notViable)
}

func (f folder) count(o outcome) int {
	n := 0
	for _, got := range f.outcomes {
		if got == o {
			n++
		}
	}
	return n
}

// summary is the score line of the folder. Listed survivors count as
// survivors.
func (f folder) summary(listed map[string]bool) string {
	n := 0
	for i, o := range f.outcomes {
		if o == survived && listed[f.mutants[i].id] {
			n++
		}
	}
	killedAll := f.count(killed) + f.count(timedOut)
	score := 0.0
	if f.viable() > 0 {
		score = 100 * float64(killedAll) / float64(f.viable())
	}
	return fmt.Sprintf("mutate %s: %d mutants, %d not viable, %d killed (%d timed out), %d survived (%d listed), score %.1f%%, %ds",
		f.name, len(f.mutants), f.count(notViable), killedAll, f.count(timedOut), f.count(survived), n, score,
		int(f.took.Round(time.Second).Seconds()))
}

// folder judges every mutant of the package in the folder name. Mutants run
// in parallel; their outcomes keep the order of the mutants.
func (j judge) folder(name string) (folder, error) {
	start := time.Now()
	f := folder{name: name}
	ms, srcs, err := j.mutants(name)
	if err != nil {
		return f, err
	}
	limit, err := j.baseline(name)
	if err != nil {
		return f, err
	}
	f.mutants = ms
	f.outcomes = make([]outcome, len(ms))
	errs := make([]error, len(ms))
	j.each(len(ms), func(i int) {
		f.outcomes[i], errs[i] = j.mutant(name, ms[i], srcs[ms[i].file], i, limit)
	})
	for _, err := range errs {
		if err != nil {
			return f, err
		}
	}
	f.took = time.Since(start)
	return f, nil
}

// mutants returns the mutants of the package in the folder name, file by
// file in name order, and the source of each file.
func (j judge) mutants(name string) ([]mutant, map[string][]byte, error) {
	files, err := j.sources(name)
	if err != nil {
		return nil, nil, err
	}
	var all []mutant
	srcs := map[string][]byte{}
	for _, file := range files {
		src, err := os.ReadFile(filepath.Join(j.root, filepath.FromSlash(file)))
		if err != nil {
			return nil, nil, err
		}
		ms, err := mutate(file, src)
		if err != nil {
			return nil, nil, err
		}
		srcs[file] = src
		all = append(all, ms...)
	}
	if len(all) == 0 {
		return nil, nil, errors.New(name + " has no mutants")
	}
	return all, srcs, nil
}

// sources returns the files of the package in the folder name that a build
// without tags compiles, tests excluded, relative to the root and sorted.
// The package must have tests that such a build compiles.
func (j judge) sources(name string) ([]string, error) {
	p, err := build.ImportDir(filepath.Join(j.root, filepath.FromSlash(name)), 0)
	if len(p.GoFiles) == 0 {
		return nil, errors.New(name + " has no Go files")
	}
	if err != nil {
		return nil, err
	}
	if len(p.TestGoFiles)+len(p.XTestGoFiles) == 0 {
		return nil, errors.New(name + " has no tests")
	}
	files := make([]string, len(p.GoFiles))
	for i, f := range p.GoFiles {
		files[i] = path.Join(name, f)
	}
	slices.Sort(files)
	return files, nil
}

// baseline builds and runs the tests of the unchanged package, and returns
// the time limit for the tests of each mutant.
func (j judge) baseline(name string) (time.Duration, error) {
	failed := errors.New("the tests of " + name + " fail without a mutant")
	bin := filepath.Join(j.tmp, "baseline")
	built, _, err := j.build(name, "", bin)
	if err != nil {
		return 0, err
	}
	if !built {
		return 0, failed
	}
	start := time.Now()
	passed, _, err := j.test(name, bin, 0, "-test.count=1")
	took := time.Since(start)
	if err != nil {
		return 0, err
	}
	if !passed {
		return 0, failed
	}
	return max(minLimit, 10*took), nil
}

// mutant judges one mutant in a folder of its own, which it removes.
func (j judge) mutant(name string, m mutant, src []byte, i int, limit time.Duration) (outcome, error) {
	dir := filepath.Join(j.tmp, strconv.Itoa(i))
	o, err := j.try(name, m, src, dir, limit)
	if rmErr := os.RemoveAll(dir); err == nil {
		err = rmErr
	}
	return o, err
}

func (j judge) try(name string, m mutant, src []byte, dir string, limit time.Duration) (outcome, error) {
	overlay, err := writeOverlay(dir, filepath.Join(j.root, filepath.FromSlash(m.file)), m.apply(src))
	if err != nil {
		return 0, err
	}
	bin := filepath.Join(dir, "test")
	built, out, err := j.build(name, overlay, bin)
	switch {
	case err != nil:
		return 0, err
	case !built && compileError.Match(out):
		return notViable, nil
	case !built:
		return 0, fmt.Errorf("the build of %s failed: %s", m.id, lastLine(out))
	}
	passed, late, err := j.test(name, bin, limit, "-test.failfast", "-test.timeout="+limit.String())
	switch {
	case err != nil:
		return 0, fmt.Errorf("the tests of %s did not run: %w", m.id, err)
	case passed:
		return survived, nil
	case late:
		return timedOut, nil
	}
	return killed, nil
}

// writeOverlay writes, in the new folder dir, the changed source of the file
// at path file and the overlay file that puts it in place of that file. It
// returns the path of the overlay file.
func writeOverlay(dir, file string, src []byte) (string, error) {
	if err := os.Mkdir(dir, 0o700); err != nil {
		return "", err
	}
	changed := filepath.Join(dir, filepath.Base(file))
	overlay := filepath.Join(dir, "overlay.json")
	data, err := json.Marshal(map[string]map[string]string{"Replace": {file: changed}})
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(changed, src, 0o600); err != nil {
		return "", err
	}
	return overlay, os.WriteFile(overlay, data, 0o600)
}

// build compiles the tests of the package in the folder name into bin, with
// the replacements of the overlay file, if one is given. It reports whether
// the build passed, with the output of the go command; an error means that
// the go command did not run.
func (j judge) build(name, overlay, bin string) (bool, []byte, error) {
	args := []string{"test", "-c", "-vet=off", "-o", bin}
	if overlay != "" {
		args = append(args, "-overlay", overlay)
	}
	cmd := exec.Command("go", append(args, "./"+name)...)
	cmd.Dir = j.root
	cmd.Env = j.env
	out, err := cmd.CombinedOutput()
	if cmd.ProcessState == nil {
		return false, out, err
	}
	return cmd.ProcessState.Success(), out, nil
}

// test runs the test binary bin from the folder name, and stops it at limit
// (0: no limit). It reports whether every test passed and whether the run
// was stopped. An error means that the binary never ran, so nothing can be
// judged from it.
func (j judge) test(name, bin string, limit time.Duration, args ...string) (passed, late bool, err error) {
	ctx := context.Background()
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, limit)
		defer cancel()
	}
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Dir = filepath.Join(j.root, filepath.FromSlash(name))
	cmd.Env = j.env
	// Start fails when the limit passed before the binary started.
	if err := cmd.Start(); err != nil {
		return false, false, err
	}
	err = cmd.Wait()
	switch {
	case cmd.ProcessState == nil:
		return false, false, err
	case cmd.ProcessState.Success():
		// The exit status decides, also when the limit passed as the
		// binary ended.
		return true, false, nil
	}
	return false, ctx.Err() != nil, nil
}

// each calls do with 0 to n-1 on j.workers goroutines.
func (j judge) each(n int, do func(i int)) {
	next := make(chan int)
	var wg sync.WaitGroup
	for range j.workers {
		wg.Go(func() {
			for i := range next {
				do(i)
			}
		})
	}
	for i := range n {
		next <- i
	}
	close(next)
	wg.Wait()
}

// lastLine is the line of the go command's output that names the problem;
// the lines before it say where.
func lastLine(out []byte) string {
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	return lines[len(lines)-1]
}
