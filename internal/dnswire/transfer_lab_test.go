//go:build lab

package dnswire

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

// TestTransferMatchesDig transfers zones from ns1 with the TSIG key of the
// lab, and compares the records with those that dig prints for the same
// transfer.
func TestTransferMatchesDig(t *testing.T) {
	t.Cleanup(func() { transportLabctl(t, "reset") })
	ns1, err := netip.ParseAddr("10.53." + os.Getenv("LAB_ID") + ".11")
	if err != nil {
		t.Fatalf("LAB_ID: %v", err)
	}
	server := netip.AddrPortFrom(ns1, 53)
	key := transportReadKey(t, "/lab/xfr.key")

	// BIND sends a zone of this size in several messages, so the MAC chain
	// over a stream is checked against a real server.
	zone := filepath.Join(t.TempDir(), "bulk.test.zone")
	var b strings.Builder
	b.WriteString("$TTL 300\nbulk.test. SOA ns1.bulk.test. hostmaster.bulk.test. 7 3600 600 604800 300\n")
	b.WriteString("bulk.test. NS ns1.bulk.test.\nns1.bulk.test. A " + ns1.String() + "\n")
	for i := 1; i <= 600; i++ {
		fmt.Fprintf(&b, "host%03d.bulk.test. TXT \"record %03d of a zone that needs several messages\"\n", i, i)
	}
	if err := os.WriteFile(zone, []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	transportLabctl(t, "load-zone", "ns1", "bulk.test.", zone)

	dig := func(t *testing.T, args ...string) []string {
		return transportDig(t, append([]string{"-k", "/lab/xfr.key", "@" + ns1.String()}, args...)...)
	}
	for _, z := range []string{"corp.test.", "bulk.test."} {
		t.Run(z, func(t *testing.T) {
			var seen []*Message
			q := Query{Name: transportName(t, z), Type: TypeAXFR}
			if err := Transfer(transportCtx(t, 30*time.Second), server, q, key, transportCollect(&seen)); err != nil {
				t.Fatal(err)
			}
			transportCompare(t, transportLines(seen), dig(t, z, "AXFR"))
			if z == "bulk.test." && len(seen) < 2 {
				t.Errorf("the zone came in %d message, want several", len(seen))
			}
		})
	}

	t.Run("IXFR at the current serial", func(t *testing.T) {
		out, err := exec.Command("labctl", "serial", "ns1", "corp.test.").Output()
		if err != nil {
			t.Fatal(err)
		}
		serial, err := strconv.ParseUint(strings.TrimSpace(string(out)), 10, 32)
		if err != nil {
			t.Fatal(err)
		}
		var seen []*Message
		q := Query{Name: transportName(t, "corp.test."), Type: TypeIXFR, IXFRSerial: uint32(serial)}
		each := func(m *Message) (bool, error) {
			seen = append(seen, m)
			return true, nil
		}
		if err := Transfer(transportCtx(t, 30*time.Second), server, q, key, each); err != nil {
			t.Fatal(err)
		}
		got := transportLines(seen)
		transportCompare(t, got, dig(t, "corp.test.", fmt.Sprintf("IXFR=%d", serial)))
		if len(got) != 1 {
			t.Errorf("records %q, want one SOA", got)
		}
	})

	t.Run("wrong secret", func(t *testing.T) {
		wrong := &TSIGKey{Name: key.Name, Secret: slices.Clone(key.Secret)}
		wrong.Secret[0] ^= 1
		called := false
		q := Query{Name: transportName(t, "corp.test."), Type: TypeAXFR}
		err := Transfer(transportCtx(t, 30*time.Second), server, q, wrong, func(*Message) (bool, error) {
			called = true
			return false, nil
		})
		if !errors.Is(err, ErrTSIG) || called {
			t.Errorf("error %v, each called: %v; want ErrTSIG and no call", err, called)
		}
	})
}

func transportLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Errorf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// transportReadKey reads a key file of BIND:
//
//	key "<name>" { algorithm hmac-sha256; secret "<base64>"; };
func transportReadKey(t *testing.T, path string) *TSIGKey {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	f := strings.FieldsFunc(string(data), func(r rune) bool { return strings.ContainsRune(" \t\n{};\"", r) })
	value := map[string]string{}
	for i := 0; i+1 < len(f); i += 2 {
		value[f[i]] = f[i+1]
	}
	if value["algorithm"] != "hmac-sha256" {
		t.Fatalf("%s: algorithm %q, want hmac-sha256", path, value["algorithm"])
	}
	secret, err := base64.StdEncoding.DecodeString(value["secret"])
	if err != nil {
		t.Fatalf("%s: secret: %v", path, err)
	}
	return &TSIGKey{Name: transportName(t, value["key"]), Secret: secret}
}

// transportLines returns the answer records of the messages, one line each.
func transportLines(msgs []*Message) []string {
	var lines []string
	for _, m := range msgs {
		for _, r := range m.Answer {
			lines = append(lines, r.String())
		}
	}
	return lines
}

// transportDig runs dig and returns its record lines with each of the first
// four runs of blanks made one TAB, as Record.String separates the fields.
func transportDig(t *testing.T, args ...string) []string {
	t.Helper()
	args = append([]string{"+nosplit", "+noall", "+answer"}, args...)
	out, err := exec.Command("dig", args...).Output()
	if err != nil {
		t.Fatalf("dig %s: %v", strings.Join(args, " "), err)
	}
	var lines []string
	for _, l := range strings.Split(string(out), "\n") {
		if l == "" || strings.HasPrefix(l, ";") {
			continue
		}
		var b strings.Builder
		runs, blank := 0, false
		for i := 0; i < len(l); i++ {
			c := l[i]
			if (c == ' ' || c == '\t') && runs < 4 {
				blank = true
				continue
			}
			if blank {
				b.WriteByte('\t')
				runs++
				blank = false
			}
			b.WriteByte(c)
		}
		lines = append(lines, b.String())
	}
	return lines
}

// transportCompare fails the test unless the two lists of record lines are
// equal once each run of lines with the same owner, class and type is
// sorted, because BIND orders a record set at random.
func transportCompare(t *testing.T, got, want []string) {
	t.Helper()
	got, want = transportSortRuns(got), transportSortRuns(want)
	for i := range max(len(got), len(want)) {
		g, w := "(none)", "(none)"
		if i < len(got) {
			g = got[i]
		}
		if i < len(want) {
			w = want[i]
		}
		if g != w {
			t.Fatalf("%d records, dig printed %d; first difference at %d:\n got %q\nwant %q", len(got), len(want), i, g, w)
		}
	}
}

func transportSortRuns(lines []string) []string {
	key := func(l string) string {
		f := strings.SplitN(l, "\t", 5)
		if len(f) < 5 {
			return l
		}
		return strings.ToLower(f[0]) + "\t" + f[2] + "\t" + f[3]
	}
	out := slices.Clone(lines)
	for i := 0; i < len(out); {
		j := i + 1
		for j < len(out) && key(out[j]) == key(out[i]) {
			j++
		}
		slices.Sort(out[i:j])
		i = j
	}
	return out
}
