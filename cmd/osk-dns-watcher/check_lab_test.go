//go:build lab

package main

import (
	"bytes"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"
)

// cliGroup is one answer of osk-dns-watcher check: the lines of one server for one
// question.
type cliGroup struct {
	key                      string
	kind, qname, qtype, addr string
	kase                     string   // records, nodata, noname, noname-compact or failure
	records, glue            []string // Record.String() of each line
	rest                     string   // what follows the case of any other line
	line                     string   // the first line, for messages
}

func cliGroups(t *testing.T, out string) []cliGroup {
	t.Helper()
	var groups []cliGroup
	for _, line := range strings.Split(strings.TrimSuffix(out, "\n"), "\n") {
		f := strings.SplitN(line, " ", 10)
		if len(f) != 10 {
			t.Fatalf("line %q has fewer than ten fields", line)
		}
		if f[0] != "answer" {
			continue
		}
		key := strings.Join(f[1:6], " ")
		if len(groups) == 0 || groups[len(groups)-1].key != key {
			groups = append(groups, cliGroup{key: key, kind: f[1], qname: f[2], qtype: f[3], addr: f[4], kase: f[8], line: line})
		}
		g := &groups[len(groups)-1]
		switch f[8] {
		case "records":
			g.records = append(g.records, f[9])
		case "glue":
			g.glue = append(g.glue, f[9])
		default:
			g.rest = f[9]
		}
	}
	return groups
}

// cliDig is what dig printed: the status, and the record lines of each
// section with the blanks of dig's columns turned into tabs.
type cliDig struct {
	status   string
	sections map[string][]string
}

var cliStatus = regexp.MustCompile(`status: ([A-Z0-9]+),`)

func cliAskDig(t *testing.T, addr, qname, qtype string) cliDig {
	t.Helper()
	server, err := netip.ParseAddrPort(addr)
	if err != nil {
		t.Fatalf("address %q: %v", addr, err)
	}
	out := dataTool(t, "dig", "+norec", "+dnssec", "+nosplit", "-p", strconv.Itoa(int(server.Port())),
		"@"+server.Addr().String(), qname, qtype, "+noall", "+comments", "+answer", "+authority", "+additional")
	d := cliDig{sections: map[string][]string{}}
	section := ""
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, ";; ->>HEADER<<-"):
			if m := cliStatus.FindStringSubmatch(line); m != nil {
				d.status = m[1]
			}
		case strings.HasPrefix(line, ";; ") && strings.HasSuffix(line, " SECTION:"):
			section = strings.TrimSuffix(strings.TrimPrefix(line, ";; "), " SECTION:")
		case line == "", strings.HasPrefix(line, ";"):
		default:
			d.sections[section] = append(d.sections[section], dataTabs(line))
		}
	}
	return d
}

// cliPick keeps the record lines of one of the types, or of any type when
// none is given, and of the owner unless it is empty.
func cliPick(lines []string, owner string, types ...string) []string {
	var keep []string
	for _, l := range lines {
		f := strings.SplitN(l, "\t", 5)
		if len(f) == 5 && (len(types) == 0 || slices.Contains(types, f[3])) && (owner == "" || strings.EqualFold(f[0], owner)) {
			keep = append(keep, l)
		}
	}
	return keep
}

// cliSameSet compares two lists of records in any order: a server sends the
// records of a set in random order.
func cliSameSet(a, b []string) bool {
	return slices.Equal(slices.Sorted(slices.Values(a)), slices.Sorted(slices.Values(b)))
}

// cliMatchDig asks dig the question of one answer at the same server and
// compares what both saw.
func cliMatchDig(t *testing.T, g cliGroup) {
	t.Helper()
	d := cliAskDig(t, g.addr, g.qname, g.qtype)
	switch g.kase {
	case "records":
		// A delegation is a referral: its records are in the authority
		// section and its glue in the additional section.
		want, wantGlue := cliPick(d.sections["ANSWER"], g.qname), []string(nil)
		if g.kind == "delegation" {
			want = cliPick(d.sections["AUTHORITY"], "", "NS")
			wantGlue = cliPick(d.sections["ADDITIONAL"], "", "A", "AAAA")
		}
		if !cliSameSet(g.records, want) || !cliSameSet(g.glue, wantGlue) {
			t.Errorf("%s:\nosk-dns-watcher records %q, glue %q\ndig records %q, glue %q", g.key, g.records, g.glue, want, wantGlue)
		}
	case "nodata", "noname":
		status := map[string]string{"nodata": "NOERROR", "noname": "NXDOMAIN"}[g.kase]
		ttl, soa, _ := strings.Cut(g.rest, " ")
		soas := cliPick(d.sections["AUTHORITY"], "", "SOA")
		if d.status != status || len(soas) != 1 || soas[0] != soa {
			t.Errorf("%s: osk-dns-watcher %s %q; dig status %s, SOA lines %q", g.key, g.kase, soa, d.status, soas)
			return
		}
		f := strings.SplitN(soas[0], "\t", 5)
		soaTTL, err1 := strconv.Atoi(f[1])
		data := strings.Fields(f[4])
		minimum, err2 := strconv.Atoi(data[len(data)-1])
		if err1 != nil || err2 != nil || ttl != strconv.Itoa(min(soaTTL, minimum)) {
			t.Errorf("%s: osk-dns-watcher TTL %s; dig SOA %q", g.key, ttl, soas[0])
		}
	default:
		t.Errorf("%s: want records, nodata or noname", g.line)
	}
}

// TestCheckMatchesDig runs osk-dns-watcher check in the lab and asks dig each question of
// each answer at the same server.
func TestCheckMatchesDig(t *testing.T) {
	lab := os.Getenv("LAB_ID")
	if lab == "" {
		t.Fatal("LAB_ID is not set: this test runs in the runner of the lab")
	}
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	subnet := "10.53." + lab + "."
	args := []string{"check", "--root-server", subnet + "2", "--extra-range", subnet + "0/24", "corp.test.",
		"www.corp.test.", "A", "corp.test.", "MX", "corp.test.", "TXT", "corp.test.", "CAA",
		"cdn.corp.test.", "A", "nx.corp.test.", "A", "shop.test.", "A"}
	var stdout, stderr bytes.Buffer
	if code := run(args, &stdout, &stderr); code != 0 {
		t.Fatalf("osk-dns-watcher %s: exit %d\n%s%s", strings.Join(args, " "), code, stdout.String(), stderr.String())
	}
	groups := cliGroups(t, stdout.String())
	// Every check must have answered, or an empty output would pass.
	for _, q := range []string{"delegation corp.test. NS", "ds corp.test. DS", "serial corp.test. SOA",
		"records www.corp.test. A", "records corp.test. MX", "records corp.test. TXT", "records corp.test. CAA",
		"records cdn.corp.test. A", "records nx.corp.test. A", "records shop.test. A"} {
		if !slices.ContainsFunc(groups, func(g cliGroup) bool { return g.kind+" "+g.qname+" "+g.qtype == q }) {
			t.Errorf("no answer for %s in:\n%s", q, stdout.String())
		}
	}
	for _, g := range groups {
		cliMatchDig(t, g)
	}

	// A server that never answers fails the run, at its own address only.
	dataTool(t, "labctl", "glue", "ns2.corp.test.", subnet+"99")
	stdout.Reset()
	stderr.Reset()
	if code := run(args, &stdout, &stderr); code != 1 {
		t.Errorf("with ns2 at %s99: exit %d, want 1\n%s", subnet, code, stderr.String())
	}
	dead := subnet + "99:53"
	seen := false
	for _, g := range cliGroups(t, stdout.String()) {
		failed := g.kase == "failure"
		switch {
		case g.addr == dead && (!failed || !strings.HasPrefix(g.rest, "timeout ")):
			t.Errorf("%s: want failure timeout", g.line)
		case g.addr != dead && failed:
			t.Errorf("%s: only %s may fail", g.line, dead)
		}
		seen = seen || g.addr == dead
	}
	if !seen {
		t.Errorf("no answer names %s:\n%s", dead, stdout.String())
	}
}
