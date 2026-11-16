package main

import (
	"io"
	"strings"

	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// snapshot runs "osk snapshot": it writes what the servers of a domain give
// now as a file of expectations, for the operator to review. It writes only
// to standard output, so a snapshot is trusted only once the operator saves
// it and passes it to check.
func snapshot(args []string, stdout, stderr io.Writer) int {
	a, msg := parseArgs(args, false)
	if msg != "" {
		return snapshotWrongUse(stderr, msg)
	}
	o, err := observe.New(a.cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return snapshotWrongUse(stderr, err.Error())
	}
	domain := a.keys[0].Domain
	f, skips := expect.Snapshot(domain, runChecks(o, snapshotKeys(domain, a.keys)))
	out := &lines{json: a.json}
	formatSnapshot(out, domain, f, skips)
	if code := output(stdout, stderr, out.String()); code != 0 || len(skips) == 0 {
		return code
	}
	return 1
}

func snapshotWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk snapshot: "+msg+"\n"+usage)
}

// snapshotKeys gives the checks of a snapshot from those of check: no serial,
// which no line of the file holds, and the NS set at the apex, which shares
// the NS line of the domain with the delegation.
func snapshotKeys(domain dnswire.Name, keys []obs.Key) []obs.Key {
	apex := obs.RecordsKey(domain, domain, dnswire.TypeNS)
	snap := []obs.Key{obs.DelegationKey(domain), obs.DSKey(domain), apex}
	for _, k := range keys {
		if k.Kind == obs.KindRecords && k.String() != apex.String() {
			snap = append(snap, k)
		}
	}
	return snap
}

type snapshotLine struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type snapshotSkip struct {
	Type  string `json:"type"`
	Name  string `json:"name"`
	RType string `json:"rtype"`
	Why   string `json:"why"`
}

// formatSnapshot gives the file under a header that marks it for review, and
// a comment line for each set that it leaves out, so the output stays a valid
// file. The JSON lines hold the lines of the file and the sets left out.
func formatSnapshot(out *lines, domain dnswire.Name, f *expect.File, skips []expect.Skip) {
	if !out.json {
		out.add("# Snapshot of "+domain.Lower().String()+" as seen now. Review every line: "+
			"nothing in it is trusted until you pass this file to osk check --expect.", nil)
	}
	for _, line := range strings.Split(strings.TrimSuffix(f.String(), "\n"), "\n") {
		out.add(line, snapshotLine{"line", line})
	}
	for _, s := range skips {
		name := s.Name.Lower().String()
		out.add("# not written: "+name+" "+s.Type.String()+": "+s.Why, snapshotSkip{"skip", name, s.Type.String(), s.Why})
	}
}
