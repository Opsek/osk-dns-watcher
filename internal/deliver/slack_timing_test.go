package deliver

import (
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

var (
	timOpened   = time.Date(2026, 11, 13, 10, 0, 5, 0, time.UTC)
	timLastOK   = time.Date(2026, 11, 13, 9, 59, 5, 0, time.UTC)
	timResolved = time.Date(2026, 11, 13, 10, 7, 41, 0, time.UTC)
)

const (
	timFailingAction = ":point_right: Find out why no server of `corp.test.` answers this machine; until one does, a change there is not seen."
	timChangedAction = ":point_right: If you did not change the zone, find out who did; only a zone transfer shows which record changed."
	timResolveAction = ":point_right: If you did not make or undo this change yourself, find out who did."
	timClockOpen     = ":clock3: First seen 10:00:05 · last OK 09:59:05 · 13 Nov 2026 UTC"
	timClockNoClean  = ":clock3: First seen 10:00:05 · no clean check before · 13 Nov 2026 UTC"
	timClockResolved = ":clock3: Open for 7 min 36 s · first seen 10:00:05 · resolved 10:07:41 · 13 Nov 2026 UTC"
)

func timName(t *testing.T, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("ParseName(%q): %v", s, err)
	}
	return n
}

// timText is a notice in the layout of every notice: the headline, the code block,
// the times and the action, one empty line between each two.
func timText(headline string, view []string, clock, action string) string {
	lines := append([]string{headline, "", "```"}, view...)
	return strings.Join(append(lines, "```", "", clock, "", action), "\n")
}

// timEvent is an event of kind on an alert of rule about check, opened at
// timOpened; LastClean is zero when lastOK is false.
func timEvent(kind alert.EventKind, rule decide.Rule, severity decide.Severity, check obs.Key, value string, lastOK bool) alert.Event {
	a := alert.Alert{ID: 7, Open: kind != alert.EventResolve, Rule: rule, Severity: severity, Peak: severity,
		Check: check, Value: value, Opened: timOpened, Noticed: timOpened}
	if lastOK {
		a.LastClean = timLastOK
	}
	at := timOpened
	if kind == alert.EventResolve {
		at = timResolved
		a.Resolved = at
	}
	return alert.Event{Kind: kind, Alert: a, Was: severity, At: at}
}

func timSameText(t *testing.T, got, want string) {
	t.Helper()
	if got != want {
		t.Errorf("text\n%s\n\nwant\n%s", got, want)
	}
}

func TestSlackTextOfCheckFailingForOpenUpdateAndResolve(t *testing.T) {
	www := obs.RecordsKey(timName(t, "corp.test."), timName(t, "WWW.Corp.Test."), dnswire.TypeA)
	head := "the records check of `www.corp.test. A` has had no usable answer for too long"
	for _, c := range []struct {
		name string
		e    alert.Event
		want string
	}{
		{"open", timEvent(alert.EventOpen, decide.RuleCheckFailing, decide.SeverityMedium, www, "no usable answer for 25s", true),
			timText(":large_orange_circle: *MEDIUM* · "+head, []string{"problem    no usable answer for 25s"}, timClockOpen, timFailingAction)},
		{"update", timEvent(alert.EventUpdate, decide.RuleCheckFailing, decide.SeverityMedium, www, "no usable answer for 5m0s", false),
			timText(":large_orange_circle: *MEDIUM*, changed again · "+head, []string{"problem    no usable answer for 5m0s"}, timClockNoClean, timFailingAction)},
		{"resolve", timEvent(alert.EventResolve, decide.RuleCheckFailing, decide.SeverityMedium, www, "no usable answer for 25s", true),
			timText(":white_check_mark: *RESOLVED* · the records check of `www.corp.test. A` has usable answers again",
				[]string{"now        a server answers"}, timClockResolved, timResolveAction)},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSameText(t, SlackText(c.e), c.want)
		})
	}
}

func TestSlackTextOfCheckFailingNamesTheKindOfCheck(t *testing.T) {
	corp := timName(t, "Corp.Test.")
	for _, c := range []struct {
		key     obs.Key
		subject string
	}{
		{obs.DelegationKey(corp), "the delegation check of `corp.test. NS`"},
		{obs.DSKey(corp), "the ds check of `corp.test. DS`"},
		{obs.SerialKey(corp), "the serial check of `corp.test. SOA`"},
	} {
		t.Run(c.key.Kind.String(), func(t *testing.T) {
			open := timEvent(alert.EventOpen, decide.RuleCheckFailing, decide.SeverityMedium, c.key, "no usable answer for 15m0s", true)
			timSameText(t, SlackText(open), timText(":large_orange_circle: *MEDIUM* · "+c.subject+" has had no usable answer for too long",
				[]string{"problem    no usable answer for 15m0s"}, timClockOpen, timFailingAction))
			resolve := timEvent(alert.EventResolve, decide.RuleCheckFailing, decide.SeverityMedium, c.key, "no usable answer for 15m0s", true)
			timSameText(t, SlackText(resolve), timText(":white_check_mark: *RESOLVED* · "+c.subject+" has usable answers again",
				[]string{"now        a server answers"}, timClockResolved, timResolveAction))
		})
	}
}

const (
	timLineNS2   = "10.53.0.12:53 ns2.corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:15Z"
	timLineNS1   = "10.53.0.11:53 ns1.corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:16Z"
	timLineAgain = "10.53.0.12:53 ns2.corp.test. serial 2 until 2026-11-13T10:00:15Z, 3 since 2026-11-13T10:05:00Z"
)

func timScope(t *testing.T) obs.Key {
	corp := timName(t, "Corp.Test.")
	return obs.Key{Domain: corp, Name: corp}
}

func TestSlackTextOfZoneChangedForOpenUpdateAndResolve(t *testing.T) {
	scope := timScope(t)
	head := "the zone `corp.test.` changed, and no watched record differs"
	two := timLineNS2 + "\n" + timLineNS1
	for _, c := range []struct {
		name string
		e    alert.Event
		want string
	}{
		{"open", timEvent(alert.EventOpen, decide.RuleZoneChanged, decide.SeverityLow, scope, two, false),
			timText(":large_yellow_circle: *LOW* · "+head, []string{timLineNS2, timLineNS1}, timClockNoClean, timChangedAction)},
		{"update", timEvent(alert.EventUpdate, decide.RuleZoneChanged, decide.SeverityLow, scope, timLineAgain, true),
			timText(":large_yellow_circle: *LOW*, changed again · "+head, []string{timLineAgain}, timClockOpen, timChangedAction)},
		{"resolve", timEvent(alert.EventResolve, decide.RuleZoneChanged, decide.SeverityLow, scope, two, true),
			timText(":white_check_mark: *RESOLVED* · the zone `corp.test.` has not changed again for a while",
				[]string{"now        no new change of the serial"}, timClockResolved, timResolveAction)},
	} {
		t.Run(c.name, func(t *testing.T) {
			timSameText(t, SlackText(c.e), c.want)
		})
	}
}

func TestSlackTextOfZoneChangedShowsAtMostSixServers(t *testing.T) {
	scope := timScope(t)
	head := ":large_yellow_circle: *LOW* · the zone `corp.test.` changed, and no watched record differs"
	var lines []string
	for i := range 8 {
		lines = append(lines, "10.53.0."+strconv.Itoa(11+i)+":53 ns"+strconv.Itoa(1+i)+".corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:15Z")
	}
	for _, c := range []struct {
		n    int
		view []string
	}{
		{6, lines[:6]},
		{7, append(lines[:6:6], "and 1 more servers")},
		{8, append(lines[:6:6], "and 2 more servers")},
	} {
		t.Run(strconv.Itoa(c.n), func(t *testing.T) {
			e := timEvent(alert.EventOpen, decide.RuleZoneChanged, decide.SeverityLow, scope, strings.Join(lines[:c.n], "\n"), true)
			timSameText(t, SlackText(e), timText(head, c.view, timClockOpen, timChangedAction))
		})
	}
}

// The store gives the Value back as it was written; whatever it holds stays
// inside the code block, escaped and cut as every other text from outside.
func TestSlackTextOfTimingRulesCleansTheValue(t *testing.T) {
	www := obs.RecordsKey(timName(t, "corp.test."), timName(t, "www.corp.test."), dnswire.TypeA)
	odd := "a `b` <!here> & " + strings.Repeat("x", 200)
	long := "10.53.0.12:53 " + strings.Repeat("n", 60) + "." + strings.Repeat("s", 60) + ".corp.test. serial 1 until 2026-11-13T10:00:00Z, 2 since 2026-11-13T10:00:15Z"

	failing := timEvent(alert.EventOpen, decide.RuleCheckFailing, decide.SeverityMedium, www, odd, true)
	text := SlackText(failing)
	timSameText(t, text, timText(":large_orange_circle: *MEDIUM* · the records check of `www.corp.test. A` has had no usable answer for too long",
		[]string{"problem    " + Clean(odd, 160)}, timClockOpen, timFailingAction))
	timPlainText(t, text, 2)

	var value []string
	for range 9 {
		value = append(value, odd, long)
	}
	changed := timEvent(alert.EventUpdate, decide.RuleZoneChanged, decide.SeverityLow, timScope(t), strings.Join(value, "\n"), true)
	text = SlackText(changed)
	view := []string{Clean(odd, 160), Clean(long, 160), Clean(odd, 160), Clean(long, 160), Clean(odd, 160), Clean(long, 160), "and 12 more servers"}
	timSameText(t, text, timText(":large_yellow_circle: *LOW*, changed again · the zone `corp.test.` changed, and no watched record differs",
		view, timClockOpen, timChangedAction))
	timPlainText(t, text, 1)
}

// timPlainText checks what holds for every notice: printable ASCII and LF
// only, besides the middle dot with a space on each side, no < or >, the
// code block and f code spans, at most 3000 octets.
func timPlainText(t *testing.T, text string, f int) {
	t.Helper()
	ascii := strings.ReplaceAll(text, " · ", " . ")
	for i := 0; i < len(ascii); i++ {
		if c := ascii[i]; ((c < 0x20 || c > 0x7e) && c != '\n') || c == '<' || c == '>' {
			t.Errorf("octet %#x at %d", c, i)
		}
	}
	if n := strings.Count(text, "`"); n != 6+2*f {
		t.Errorf("%d backticks, want %d", n, 6+2*f)
	}
	if len(text) > 3000 {
		t.Errorf("%d octets, want at most 3000", len(text))
	}
}
