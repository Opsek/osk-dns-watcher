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
	cfg, keys, msg := parseCheck(args)
	if msg != "" {
		return snapshotWrongUse(stderr, msg)
	}
	o, err := observe.New(cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return snapshotWrongUse(stderr, err.Error())
	}
	domain := keys[0].Domain
	f, skips := expect.Snapshot(domain, runChecks(o, snapshotKeys(domain, keys)))
	if code := output(stdout, stderr, formatSnapshot(domain, f, skips)); code != 0 || len(skips) == 0 {
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

// formatSnapshot gives the file under a header that marks it for review, and
// a comment line for each set that it leaves out, so the output stays a valid
// file.
func formatSnapshot(domain dnswire.Name, f *expect.File, skips []expect.Skip) string {
	var b strings.Builder
	b.WriteString("# Snapshot of " + domain.Lower().String() + " as seen now. Review every line: " +
		"nothing in it is trusted until you pass this file to osk check --expect.\n")
	b.WriteString(f.String())
	for _, s := range skips {
		b.WriteString("# not written: " + s.Name.Lower().String() + " " + s.Type.String() + ": " + s.Why + "\n")
	}
	return b.String()
}
