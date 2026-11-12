//go:build lab

package decide

import (
	"context"
	"errors"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// decLab is the start of every lab address, "10.53.<LAB_ID>.".
func decLab(t *testing.T) string {
	t.Helper()
	prefix := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(prefix + "1"); err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	return prefix
}

func decLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// decLabWWW observes www.corp.test. A with a walk from the lab's root.
func decLabWWW(t *testing.T) obs.Observation {
	t.Helper()
	lab := decLab(t)
	o, err := observe.New(observe.Config{
		RootServers: []netip.AddrPort{netip.MustParseAddrPort(lab + "2:53")},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix(lab + "0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := obs.RecordsKey(decName(t, "corp.test."), decName(t, "www.corp.test."), dnswire.TypeA)
	ob, err := o.Run(context.Background(), observe.Check{Key: key, Interval: time.Minute})
	if err != nil {
		t.Fatalf("Run(%v): %v", key, err)
	}
	return ob
}

func decLabOne(t *testing.T, what string, got []Change, op Op, rule Rule) Finding {
	t.Helper()
	if len(got) != 1 || got[0].Op != op || got[0].Finding.Rule != rule {
		t.Fatalf("%s: want one change %v %v, got%s", what, op, rule, decShowChanges(got))
	}
	return got[0].Finding
}

// An operator who tries to mark a change as expected and breaks the file
// gets an alert for the file, and the change is still judged against the
// last valid file.
func TestInvalidFileKeepsLast(t *testing.T) {
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	lab := decLab(t)
	corp := decName(t, "corp.test.")
	// The www line is line 3.
	file := func(www string) []byte {
		return []byte("domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\n" + www + "\n")
	}
	now := time.Now()

	f0, err := expect.Keep(nil, file("www.corp.test. A "+lab+"81"))
	if err != nil || f0 == nil {
		t.Fatalf("Keep of the valid file: %v, %v", f0, err)
	}

	decLabctl(t, "set", "both", "www.corp.test.", "300", "A", lab+"99")

	kept, err := expect.Keep(f0, file("www.corp.test. A "+lab+"99 |"))
	if kept != f0 {
		t.Errorf("Keep of the broken file gave another file than the last valid one")
	}
	var bad *expect.Error
	if !errors.As(err, &bad) || len(bad.Problems) == 0 {
		t.Fatalf("Keep of the broken file: error %v, want an *expect.Error", err)
	}
	for _, p := range bad.Problems {
		if p.Line != 3 {
			t.Errorf("a problem on line %d: %q; only line 3 is broken", p.Line, p.Text)
		}
	}

	invalid := decLabOne(t, "FileChanges of the broken file", FileChanges(corp, err, nil, now), OpOpen, RuleInvalidFile)
	if invalid.Severity != SeverityMedium || invalid.Value != err.Error() {
		t.Errorf("the file finding is%s", decShow([]Finding{invalid}))
	}

	// The open file finding belongs to no check, so Decide passes it by.
	open := []Finding{invalid}
	found := decLabOne(t, "Decide with the kept file",
		Decide(Input{Expect: kept, Open: open, Observation: decLabWWW(t), Now: now}), OpOpen, RuleRecordSet)
	if found.Severity != SeverityHigh || found.Expected != lab+"81" {
		t.Errorf("the www finding is%s", decShow([]Finding{found}))
	}
	var seenAt []string
	for _, s := range found.Seen {
		seenAt = append(seenAt, s.Answer.Server.Addr.String())
		if s.Text != lab+"99" {
			t.Errorf("%v is seen with %q, want %s99", s.Answer.Server, s.Text, lab)
		}
	}
	slices.Sort(seenAt)
	if want := []string{lab + "11:53", lab + "12:53"}; !slices.Equal(seenAt, want) {
		t.Errorf("seen at %q, want %q", seenAt, want)
	}

	fixed, err := expect.Keep(kept, file("www.corp.test. A "+lab+"99"))
	if err != nil || fixed == nil || fixed == kept {
		t.Fatalf("Keep of the fixed file: %v, %v", fixed, err)
	}
	open = append(open, found)
	if got := decLabOne(t, "FileChanges of the fixed file", FileChanges(corp, nil, open, now), OpResolve, RuleInvalidFile); got.Value != invalid.Value {
		t.Errorf("the resolved finding is%s", decShow([]Finding{got}))
	}
	decLabOne(t, "Decide with the fixed file",
		Decide(Input{Expect: fixed, Open: open, Observation: decLabWWW(t), Now: now}), OpResolve, RuleRecordSet)
}
