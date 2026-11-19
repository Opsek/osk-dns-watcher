package decide

import (
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// Failed reports whether no answer of o is records, no data or no such name.
// The tool's own failures count too: it is blind then, whatever the cause.
// One dead server of two is not a failed run, because the check still sees
// the zone.
func Failed(o obs.Observation) bool {
	return !slices.ContainsFunc(o.Answers, func(a obs.Answer) bool {
		_, ok := answerSet(a)
		return ok
	})
}

// checkFailing gives the check-failing finding of a run with no usable
// answer whose series has lasted FailLimit. Its Value names the limit and no
// time, so a restart or a new reason of failure sends no update.
func checkFailing(in Input) (Finding, bool) {
	o := in.Observation
	if !Failed(o) || in.FailingSince.IsZero() || in.FailLimit <= 0 || in.Now.Sub(in.FailingSince) < in.FailLimit {
		return Finding{}, false
	}
	return Finding{Rule: RuleCheckFailing, Severity: severity(RuleCheckFailing, o.Key.Type), Check: o.Key,
		Value: "no usable answer for " + in.FailLimit.String()}, true
}

// Move is a change of the serial that one server gives for the zone.
type Move struct {
	Server       obs.Server
	From, To     uint32    // the serial that the server gave before, and now
	Until, Since time.Time // From was last seen there at Until; To was first seen there at Since
}

// moveTime is in UTC, so the time zone of the machine stays out of a Value.
const moveTime = "2006-01-02T15:04:05Z"

// ZoneChanges opens or updates the zone-changed alert of the domain with one
// line for each move, and resolves it when moves is empty.
func ZoneChanges(domain dnswire.Name, moves []Move, open []Finding, now time.Time) []Change {
	scope := domainScope(domain)
	mine := firstOpen(open, scope.String())
	if len(moves) == 0 {
		return resolveRule(mine, RuleZoneChanged, now)
	}
	lines := make([]string, len(moves))
	for i, m := range moves {
		lines[i] = serverText(m.Server) +
			" serial " + strconv.FormatUint(uint64(m.From), 10) + " until " + m.Until.UTC().Format(moveTime) +
			", " + strconv.FormatUint(uint64(m.To), 10) + " since " + m.Since.UTC().Format(moveTime)
	}
	f := Finding{Rule: RuleZoneChanged, Severity: severity(RuleZoneChanged, 0), Check: scope, Value: strings.Join(lines, "\n")}
	return openOrUpdate([]Finding{f}, mine, now)
}
