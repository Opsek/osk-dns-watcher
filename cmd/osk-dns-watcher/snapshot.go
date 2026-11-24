package main

import (
	"io"
	"slices"
	"strings"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/mtasts"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	startpkg "github.com/Opsek/osk-dns-watcher/internal/start"
)

// snapshot runs "osk-dns-watcher snapshot": it writes what the servers of a domain give
// now as a file of expectations, for the operator to review. It writes only
// to standard output, so a snapshot is trusted only once the operator saves
// it and passes it to check.
func snapshot(args []string, stdout, stderr io.Writer) int {
	a, msg := parseArgs(args, false)
	if msg != "" {
		return snapshotWrongUse(stderr, msg)
	}
	a.cfg.Policy = mtasts.Fetcher(a.cfg.ExtraRanges)
	o, err := observe.New(a.cfg)
	if err != nil {
		// Only the flags fill the configuration.
		return snapshotWrongUse(stderr, err.Error())
	}
	domain := a.keys[0].Domain
	observations := runChecks(o, snapshotKeys(domain, a.keys))
	// The first answers say what else to ask: the addresses of the
	// nameserver hosts inside the domain, whose lines watch their glue, and
	// the policy file, only once the _mta-sts record is seen to be on, so
	// that no request goes to a host that the domain never set up.
	more, _ := startpkg.NameServerKeys(domain, observations)
	if policy, ok := startpkg.WantsPolicy(domain, observations); ok {
		more = append(more, policy)
	}
	observations = append(observations, runChecks(o, more)...)
	f, skips := expect.Snapshot(domain, observations)
	out := &lines{json: a.json}
	formatSnapshot(out, domain, f, skips, expect.Unreached(observations))
	if _, ok := f.Find(domain, dnswire.TypeNS); ok {
		formatNSNotes(out, domain, expect.NSNoAnswer(domain, observations), expect.NSSources(domain, observations))
	}
	if code := output(stdout, stderr, out.String()); code != 0 || len(skips) == 0 {
		return code
	}
	return 1
}

func snapshotWrongUse(stderr io.Writer, msg string) int {
	return fail(stderr, 2, "osk-dns-watcher snapshot: "+msg+"\n"+usage)
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
// file. One more comment counts the addresses that the lines do not rest
// on, because this machine has no route to them, when there are any. The
// JSON lines hold the lines of the file and the sets left out.
func formatSnapshot(out *lines, domain dnswire.Name, f *expect.File, skips []expect.Skip, unreached []obs.Server) {
	if !out.json {
		out.add("# Snapshot of "+domain.Lower().String()+" as seen now. Review every line: "+
			"nothing in it is trusted until you pass this file to osk-dns-watcher check --expect.", nil)
		if len(unreached) > 0 {
			out.add("# not asked: "+startpkg.AddressCount(unreached)+" of the servers, to which this machine has no route", nil)
		}
	}
	for _, line := range strings.Split(strings.TrimSuffix(f.String(), "\n"), "\n") {
		out.add(line, snapshotLine{"line", line})
	}
	for _, s := range skips {
		name := s.Name.Lower().String()
		out.add("# not written: "+name+" "+s.Type.String()+": "+s.Why, snapshotSkip{"skip", name, s.Type.String(), s.Why})
	}
}

type snapshotNSSet struct {
	Type   string   `json:"type"`
	Text   string   `json:"text"`
	Parent []string `json:"parent"`
	Zone   []string `json:"zone"`
}

type snapshotNoAnswer struct {
	Type    string   `json:"type"`
	Servers []string `json:"servers"`
}

// formatNSNotes says, as comments, what the NS line rests on: the servers
// that gave no answer about it, and each set of a line that accepts several
// with the servers that gave it. A server that lies gets its set into the
// line, so the operator must be able to see a set that is not theirs.
func formatNSNotes(out *lines, domain dnswire.Name, noAnswer []string, sources []expect.NSSource) {
	d := domain.Lower().String()
	if out.json && len(noAnswer) > 0 {
		out.add("", snapshotNoAnswer{"nsnoanswer", noAnswer})
	}
	servers := slices.DeleteFunc(slices.Clone(noAnswer), func(s string) bool { return s == expect.NoPath })
	if !out.json && len(servers) < len(noAnswer) {
		out.add("# osk-dns-watcher could not reach the servers of "+d+" (the walk from the root found no path to them): the NS line "+
			"holds what the parent zone gave; if the servers hold another set, osk-dns-watcher alerts at its first check", nil)
	}
	if !out.json && len(servers) > 0 {
		out.add("# no answer about the NS set from "+strings.Join(servers, ", ")+": the NS line holds what the other "+
			"servers gave; if they hold another set, osk-dns-watcher alerts at its first check", nil)
	}
	if len(sources) == 0 {
		return
	}
	if !out.json {
		out.add("# the servers of "+d+" give different NS sets now: its NS line accepts each set below, and a change to "+
			"any other set gives an alert. Remove a set that holds a name that is not one of your nameservers.", nil)
	}
	for _, s := range sources {
		var from []string
		if len(s.Parent) > 0 {
			from = append(from, "given by the parent zone: "+strings.Join(s.Parent, ", "))
		}
		if len(s.Zone) > 0 {
			from = append(from, "given by the servers of "+d+": "+strings.Join(s.Zone, ", "))
		}
		// Empty lists, not null, for a reader of the JSON.
		out.add("# NS set "+s.Text+": "+strings.Join(from, "; "),
			snapshotNSSet{"nsset", s.Text, append([]string{}, s.Parent...), append([]string{}, s.Zone...)})
	}
}
