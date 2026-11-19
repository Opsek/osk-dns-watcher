//go:build lab

package store

import (
	"context"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// stoLab is the start of every lab address, "10.53.<LAB_ID>.".
func stoLab(t *testing.T) string {
	t.Helper()
	prefix := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(prefix + "1"); err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	return prefix
}

func stoLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// A state change of a real observation is written whole or not at all: a
// fault in its last insert leaves no alert, event, delivery or clean time.
func TestStateChangeAllOrNothing(t *testing.T) {
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	lab := stoLab(t)
	stoLabctl(t, "delegate", "corp.test.", "ns1.dnshost.test.", "ns2.dnshost.test.")

	o, err := observe.New(observe.Config{
		RootServers: []netip.AddrPort{netip.MustParseAddrPort(lab + "2:53")},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix(lab + "0/24")},
	})
	if err != nil {
		t.Fatal(err)
	}
	key := obs.DelegationKey(stoName(t, "corp.test."))
	ob, err := o.Run(context.Background(), observe.Check{Key: key, Interval: time.Minute})
	if err != nil {
		t.Fatalf("Run(%v): %v", key, err)
	}
	file, err := expect.Parse([]byte("domain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\ncorp.test. DS none\n"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	changes := decide.Decide(decide.Input{Expect: file, Observation: ob, Now: now})
	out := alert.Transition(alert.Input{Changes: changes, Now: now})
	if len(out.Events) != 1 || out.Events[0].Kind != alert.EventOpen {
		t.Fatalf("Transition of %d changes gives %d events, want one open", len(changes), len(out.Events))
	}
	e := out.Events[0]
	writes := []Write{{Event: e, Deliveries: []Delivery{{Channel: "slack", Label: e.Label(), Body: []byte("{}")}}}}

	s := stoOpen(t, stoDir(t))
	stoExec(t, s, "CREATE TRIGGER sto_fault BEFORE INSERT ON delivery BEGIN SELECT RAISE(ABORT, 'planted fault'); END")
	err = s.Apply(key, out.Clean, now, writes)
	if err == nil || !strings.HasPrefix(err.Error(), "store: ") || !strings.Contains(err.Error(), "planted fault") {
		t.Errorf("Apply with the planted fault: %v, want an error that starts with \"store: \" and holds the planted fault", err)
	}
	if got, want := stoCounts(t, s), "alert 0, event 0, delivery 0, check_state 0"; got != want {
		t.Errorf("after the failed Apply: %s, want %s", got, want)
	}

	stoExec(t, s, "DROP TRIGGER sto_fault")
	stoApply(t, s, key, out.Clean, now, writes...)
	if got, want := stoCounts(t, s), "alert 1, event 1, delivery 1, check_state 0"; got != want {
		t.Errorf("after the Apply without the fault: %s, want %s", got, want)
	}
	open := stoOpenAlerts(t, s, key)
	if len(open) != 1 || open[0].ID == 0 {
		t.Fatalf("OpenAlerts gives %d alerts, want 1 with an id", len(open))
	}
	lines := open[0].Lines
	if len(lines) != 1 || lines[0].Server.Addr != netip.MustParseAddrPort(lab+"3:53") ||
		lines[0].Server.Name.String() != "ns.test." || lines[0].TTL != 300 {
		t.Errorf("the stored alert has the lines\n%s\nwant one line of %s3:53 ns.test. with TTL 300", stoAlertText(open[0]), lab)
	}
	if rows := stoDue(t, s, "slack", now); len(rows) != 1 {
		t.Errorf("Due(slack) gives %d rows, want 1", len(rows))
	}
}
