package deliver_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// The Slack text as the message rules describe it, written apart from the
// code under test.

var (
	dlvEmoji = map[decide.Severity]string{
		decide.SeverityLow: ":large_yellow_circle:", decide.SeverityMedium: ":large_orange_circle:",
		decide.SeverityHigh: ":red_circle:", decide.SeverityCritical: ":rotating_light:",
	}
	dlvWord = map[decide.Severity]string{
		decide.SeverityLow: "LOW", decide.SeverityMedium: "MEDIUM", decide.SeverityHigh: "HIGH", decide.SeverityCritical: "CRITICAL",
	}
	// dlvSpans is the number of code spans of a text that is not a resolve.
	dlvSpans = map[decide.Rule]int{
		decide.RuleNameServers: 1, decide.RuleRecordSet: 1, decide.RuleZone: 2, decide.RuleNotCovered: 3, decide.RuleInvalidFile: 1,
	}
)

const dlvResolveAction = "If you did not make or undo this change yourself, find out who did."

func dlvTime(t time.Time) string {
	return t.UTC().Format("2006-01-02 15:04:05 UTC")
}

func dlvServerLine(l alert.Line) string {
	addr, host := "-", "-"
	if l.Server.Addr.IsValid() {
		addr = dlvClean(l.Server.Addr.String(), 64)
	}
	if l.Server.Name.LabelCount() > 0 {
		host = dlvClean(l.Server.Name.Lower().String(), 64)
	}
	return "now       " + dlvClean(l.Text, 160) + "   at " + host + " (" + addr + "), TTL " + strconv.FormatUint(uint64(l.TTL), 10)
}

func dlvSlackText(e alert.Event) string {
	a, k := e.Alert, e.Alert.Check
	d := "`" + dlvClean(k.Domain.Lower().String(), 100) + "`"
	n := "`" + dlvClean(k.Name.Lower().String(), 100) + "`"
	nt := "`" + dlvClean(k.Name.Lower().String(), 100) + " " + dlvClean(k.Type.String(), 20) + "`"
	head := dlvEmoji[a.Severity] + " " + dlvWord[a.Severity] + map[alert.EventKind]string{
		alert.EventOpen:     "",
		alert.EventUpdate:   ", changed again",
		alert.EventEscalate: ", raised from " + e.Was.String(),
		alert.EventReminder: ", still open",
		alert.EventResolve:  "",
	}[e.Kind]
	type words struct{ phrase, resolved, action, now string }
	w := map[decide.Rule]words{
		decide.RuleNameServers: {"nameservers of " + d + " changed at the parent zone", "nameservers of " + d + " are as expected again",
			"If you did not change the nameservers, contact your registrar now.", "as expected again"},
		decide.RuleRecordSet: {nt + " changed", nt + " is as expected again",
			"If you did not make this change, check your DNS provider account now.", "as expected again"},
		decide.RuleZone: {n + " is answered from an unexpected zone", n + " is answered from the expected zone again",
			"If you did not create this zone, check the delegations under " + d + " at your DNS provider.", "as expected again"},
		decide.RuleNotCovered: {nt + " has no expectation and is not checked", nt + " has an expectation now",
			"Add a line for " + nt + " to the expectations file of " + d + ".", "covered by the expectations"},
		decide.RuleInvalidFile: {"the expectations file of " + d + " is not valid", "the expectations file of " + d + " is valid again",
			"Fix the file. Until then the last valid file is used.", "the file is valid"},
	}[a.Rule]
	resolve := e.Kind == alert.EventResolve
	phrase, action := w.phrase, w.action
	if resolve {
		head, phrase, action = ":white_check_mark: RESOLVED", w.resolved, dlvResolveAction
	}
	var view []string
	if a.Rule == decide.RuleInvalidFile && !resolve {
		view = []string{"problem   " + dlvClean(a.Value, 160)}
	} else {
		expected := "-"
		if a.Expected != "" {
			expected = dlvClean(a.Expected, 160)
		}
		view = []string{"expected  " + expected}
		if resolve {
			view = append(view, "now       "+w.now)
		}
		for i, l := range a.Lines {
			if resolve {
				break
			}
			if i == 6 {
				view = append(view, fmt.Sprintf("and %d more servers", len(a.Lines)-6))
				break
			}
			view = append(view, dlvServerLine(l))
		}
	}
	times := ":clock3: First seen " + dlvTime(a.Opened) + " / "
	switch {
	case resolve:
		times += "Resolved " + dlvTime(e.At)
	case a.LastClean.IsZero():
		times += "Last OK: no clean check recorded"
	default:
		times += "Last OK " + dlvTime(a.LastClean)
	}
	lines := append([]string{head + ": " + phrase, "", "```"}, view...)
	return strings.Join(append(lines, "```", "", times, "", ":point_right: "+action), "\n")
}

// dlvMessageFault checks the message of e against the safety rules of a
// Slack text and against the text the rules give, and describes the first
// fault, or returns "".
func dlvMessageFault(e alert.Event) string {
	text := deliver.SlackText(e)
	body := deliver.SlackMessage(e)
	var fields map[string]any
	if err := json.Unmarshal(body, &fields); err != nil {
		return fmt.Sprintf("the body is not a JSON object: %v", err)
	}
	if got, ok := fields["text"].(string); len(fields) != 1 || !ok || got != text {
		return fmt.Sprintf("the body %q is not one key text with SlackText", body)
	}
	if want, err := json.Marshal(struct {
		Text string `json:"text"`
	}{text}); err != nil || !bytes.Equal(body, want) {
		return fmt.Sprintf("the body %q is not the JSON encoding of the text", body)
	}
	if len(text) > 3000 {
		return fmt.Sprintf("%d octets, more than 3000", len(text))
	}
	for i := 0; i < len(text); i++ {
		switch c := text[i]; {
		case (c < 0x20 || c > 0x7E) && c != '\n', c == '<', c == '>':
			return fmt.Sprintf("octet %#02x at %d", c, i)
		case c == '&' && !strings.HasPrefix(text[i:], "&amp;") && !strings.HasPrefix(text[i:], "&lt;") &&
			!strings.HasPrefix(text[i:], "&gt;"):
			return fmt.Sprintf("an & at %d that starts no escape", i)
		}
	}
	spans := 1
	if e.Kind != alert.EventResolve {
		spans = dlvSpans[e.Alert.Rule]
	}
	if got := strings.Count(text, "`"); got != 6+2*spans {
		return fmt.Sprintf("%d backticks, want %d", got, 6+2*spans)
	}
	// By position: headline, empty line, fence, view lines, fence, empty
	// line, times, empty line, action. Data from DNS cannot hold LF after
	// Clean, so each view line is one line.
	ref := dlvSlackText(e)
	lines := strings.Split(text, "\n")
	want := strings.Split(ref, "\n")
	if lines[0] != want[0] {
		return fmt.Sprintf("headline %q, want %q", lines[0], want[0])
	}
	n := len(lines)
	if n < 9 || lines[1] != "" || lines[2] != "```" || lines[n-5] != "```" || lines[n-4] != "" || lines[n-2] != "" {
		return fmt.Sprintf("not four parts with a code block in the second:\n%s", text)
	}
	now := 0
	for _, l := range lines[3 : n-5] {
		if strings.HasPrefix(l, "now ") {
			now++
		}
	}
	if now > 6 {
		return fmt.Sprintf("%d now lines", now)
	}
	if text != ref {
		return fmt.Sprintf("text:\n%s\nwant:\n%s", text, ref)
	}
	return ""
}

func TestSlackMessageProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 7))
	for range 2000 {
		e := dlvHostileEvent(rng)
		if fault := dlvMessageFault(e); fault != "" {
			t.Fatalf("seed %d: event %+v: %s", seed, e, fault)
		}
	}
}

func dlvName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// The times of the fixtures are in a zone east of UTC and carry fractions of
// a second, so a text must convert them and must not round.
var (
	dlvEast      = time.FixedZone("east", 5*3600)
	dlvOpened    = time.Date(2026, 11, 11, 19, 2, 7, 999e6, dlvEast)  // 14:02:07 UTC
	dlvLastClean = time.Date(2026, 11, 11, 19, 1, 7, 0, dlvEast)      // 14:01:07 UTC
	dlvResolved  = time.Date(2026, 11, 12, 13, 30, 0, 500e6, dlvEast) // 08:30:00 UTC
	dlvNoticed   = time.Date(2026, 11, 11, 20, 0, 0, 0, dlvEast)      // in no text
	dlvReceived  = time.Date(2026, 11, 11, 19, 2, 6, 0, dlvEast)      // in no text
	dlvLater     = time.Date(2026, 11, 13, 9, 0, 0, 0, time.UTC)      // the time of a pass
	dlvGateTime  = time.Date(2026, 11, 11, 14, 2, 7, 0, time.UTC)     // the gate example
	dlvGateClean = time.Date(2026, 11, 11, 14, 1, 7, 0, time.UTC)     // the gate example
)

// dlvLines are two servers: one with a name and an address, and one with
// neither, as the walk may give a root server.
func dlvLines(t testing.TB) []alert.Line {
	return []alert.Line{
		{Server: obs.Server{Name: dlvName(t, "NS1.Corp.Test."), Addr: netip.MustParseAddrPort("10.53.0.11:53")},
			Text: "10.53.0.99", TTL: 120, Received: dlvReceived},
		{Server: obs.Server{}, Text: "none", TTL: 300, Received: dlvReceived},
	}
}

// Each kind of event of each rule gives the text of the message rules, word
// for word.
func TestSlackTextForEachKindAndRule(t *testing.T) {
	servers := []string{
		"now       10.53.0.99   at ns1.corp.test. (10.53.0.11:53), TTL 120",
		"now       none   at - (-), TTL 300",
	}
	rules := []struct {
		rule                     decide.Rule
		check                    obs.Key
		expected                 string
		phrase, resolved, action string
		view, resolvedView       []string
	}{
		{decide.RuleNameServers, obs.DelegationKey(dlvName(t, "Corp.TEST.")), "ns1.corp.test. | ns2.corp.test.",
			"nameservers of `corp.test.` changed at the parent zone",
			"nameservers of `corp.test.` are as expected again",
			"If you did not change the nameservers, contact your registrar now.",
			append([]string{"expected  ns1.corp.test. | ns2.corp.test."}, servers...),
			[]string{"expected  ns1.corp.test. | ns2.corp.test.", "now       as expected again"}},
		{decide.RuleRecordSet, obs.RecordsKey(dlvName(t, "Corp.TEST."), dlvName(t, "WWW.corp.test."), dnswire.TypeA), "10.53.0.81",
			"`www.corp.test. A` changed",
			"`www.corp.test. A` is as expected again",
			"If you did not make this change, check your DNS provider account now.",
			append([]string{"expected  10.53.0.81"}, servers...),
			[]string{"expected  10.53.0.81", "now       as expected again"}},
		{decide.RuleZone, obs.RecordsKey(dlvName(t, "Corp.Test."), dlvName(t, "Shop.Corp.Test."), dnswire.TypeA), "corp.test.",
			"`shop.corp.test.` is answered from an unexpected zone",
			"`shop.corp.test.` is answered from the expected zone again",
			"If you did not create this zone, check the delegations under `corp.test.` at your DNS provider.",
			append([]string{"expected  corp.test."}, servers...),
			[]string{"expected  corp.test.", "now       as expected again"}},
		{decide.RuleNotCovered, obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "MAIL.corp.test."), dnswire.TypeTXT), "",
			"`mail.corp.test. TXT` has no expectation and is not checked",
			"`mail.corp.test. TXT` has an expectation now",
			"Add a line for `mail.corp.test. TXT` to the expectations file of `corp.test.`.",
			append([]string{"expected  -"}, servers...),
			[]string{"expected  -", "now       covered by the expectations"}},
		{decide.RuleInvalidFile, obs.Key{Domain: dlvName(t, "Corp.Test."), Name: dlvName(t, "Corp.Test.")}, "",
			"the expectations file of `corp.test.` is not valid",
			"the expectations file of `corp.test.` is valid again",
			"Fix the file. Until then the last valid file is used.",
			[]string{"problem   line 3: want a type after the name"},
			[]string{"expected  -", "now       the file is valid"}},
	}
	kinds := []struct {
		kind alert.EventKind
		head string
	}{
		{alert.EventOpen, ":red_circle: HIGH"},
		{alert.EventUpdate, ":red_circle: HIGH, changed again"},
		{alert.EventEscalate, ":red_circle: HIGH, raised from medium"},
		{alert.EventReminder, ":red_circle: HIGH, still open"},
		{alert.EventResolve, ":white_check_mark: RESOLVED"},
	}
	for _, r := range rules {
		for _, k := range kinds {
			e := alert.Event{
				Kind: k.kind,
				Alert: alert.Alert{ID: 7, Open: k.kind != alert.EventResolve, Rule: r.rule,
					Severity: decide.SeverityHigh, Peak: decide.SeverityCritical, Check: r.check,
					Expected: r.expected, Value: "line 3: want a type after the name", Lines: dlvLines(t),
					Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed},
				Was: decide.SeverityMedium,
				At:  dlvResolved,
			}
			lines := append([]string{k.head + ": " + r.phrase, "", "```"}, r.view...)
			lines = append(lines, "```", "", ":clock3: First seen 2026-11-11 14:02:07 UTC / Last OK 2026-11-11 14:01:07 UTC",
				"", ":point_right: "+r.action)
			if k.kind == alert.EventResolve {
				e.Alert.Resolved = dlvResolved
				lines = append([]string{k.head + ": " + r.resolved, "", "```"}, r.resolvedView...)
				lines = append(lines, "```", "", ":clock3: First seen 2026-11-11 14:02:07 UTC / Resolved 2026-11-12 08:30:00 UTC",
					"", ":point_right: "+dlvResolveAction)
			}
			want := strings.Join(lines, "\n")
			if got := deliver.SlackText(e); got != want {
				t.Errorf("%v %v:\n%s\nwant:\n%s", k.kind, r.rule, got, want)
			}
			if got := dlvSlackText(e); got != want {
				t.Errorf("the reference text of this test is wrong for %v %v:\n%s", k.kind, r.rule, got)
			}
		}
	}
}

func dlvRecordSetEvent(t testing.TB, kind alert.EventKind, sev decide.Severity, lines []alert.Line) alert.Event {
	return alert.Event{
		Kind: kind,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: sev, Peak: sev,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), dlvName(t, "www.corp.test."), dnswire.TypeA),
			Expected: "10.53.0.81", Lines: lines, Opened: dlvOpened, LastClean: dlvLastClean},
		Was: decide.SeverityLow,
		At:  dlvOpened,
	}
}

// The emoji and the word follow the severity after the event; the severity
// before it is named in lower case.
func TestSlackTextSeverityWords(t *testing.T) {
	for sev, head := range map[decide.Severity]string{
		decide.SeverityLow:      ":large_yellow_circle: LOW",
		decide.SeverityMedium:   ":large_orange_circle: MEDIUM",
		decide.SeverityHigh:     ":red_circle: HIGH",
		decide.SeverityCritical: ":rotating_light: CRITICAL",
	} {
		e := dlvRecordSetEvent(t, alert.EventOpen, sev, nil)
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], head+": `www.corp.test. A` changed"; got != want {
			t.Errorf("open %v: headline %q, want %q", sev, got, want)
		}
		e = dlvRecordSetEvent(t, alert.EventEscalate, decide.SeverityCritical, nil)
		e.Was = sev
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], ":rotating_light: CRITICAL, raised from "+sev.String()+": `www.corp.test. A` changed"; got != want {
			t.Errorf("escalate from %v: headline %q, want %q", sev, got, want)
		}
		e = dlvRecordSetEvent(t, alert.EventResolve, sev, nil)
		if got, want := strings.Split(deliver.SlackText(e), "\n")[0], ":white_check_mark: RESOLVED: `www.corp.test. A` is as expected again"; got != want {
			t.Errorf("resolve at %v: headline %q, want %q", sev, got, want)
		}
	}
}

// At most six servers are shown; the rest are counted.
func TestSlackTextShowsSixServers(t *testing.T) {
	server := func(i int) alert.Line {
		return alert.Line{Server: obs.Server{Name: dlvName(t, fmt.Sprintf("ns%d.corp.test.", i)),
			Addr: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 53, 0, byte(i)}), 53)}, Text: "10.53.0.99", TTL: 60}
	}
	for _, c := range []struct {
		servers int
		last    string
	}{
		{0, "expected  10.53.0.81"},
		{1, "now       10.53.0.99   at ns1.corp.test. (10.53.0.1:53), TTL 60"},
		{6, "now       10.53.0.99   at ns6.corp.test. (10.53.0.6:53), TTL 60"},
		{7, "and 1 more servers"},
		{40, "and 34 more servers"},
	} {
		var lines []alert.Line
		for i := range c.servers {
			lines = append(lines, server(i+1))
		}
		text := strings.Split(deliver.SlackText(dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, lines)), "\n")
		view := min(c.servers, 6) + 1
		if c.servers > 6 {
			view++
		}
		// Besides the view: headline, three empty lines, two fences, times, action.
		if len(text) != view+8 || text[len(text)-6] != c.last {
			t.Errorf("%d servers: text\n%s\nwant %d view lines, the last %q", c.servers, strings.Join(text, "\n"), view, c.last)
		}
	}
}

func TestSlackTextWithoutCleanCheck(t *testing.T) {
	e := dlvRecordSetEvent(t, alert.EventReminder, decide.SeverityHigh, nil)
	e.Alert.LastClean = time.Time{}
	lines := strings.Split(deliver.SlackText(e), "\n")
	if want := ":clock3: First seen 2026-11-11 14:02:07 UTC / Last OK: no clean check recorded"; len(lines) < 3 || lines[len(lines)-3] != want {
		t.Errorf("text:\n%s\nwant the times line %q", strings.Join(lines, "\n"), want)
	}
}

// Data from DNS that tries to leave its code span, to mention or to link is
// shown as text.
func TestSlackTextCleansHostileData(t *testing.T) {
	name, err := dnswire.NameFromLabels([]string{"<!channel>", "`x`", "corp", "test"})
	if err != nil {
		t.Fatal(err)
	}
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), name, dnswire.TypeTXT),
			Expected: "<https://x|y> & *_~",
			Lines: []alert.Line{{Server: obs.Server{Name: name, Addr: netip.MustParseAddrPort("10.53.0.11:53")},
				Text: "\"a\"\n```\n<@U123>\r\x00é", TTL: 1}},
			Opened: dlvOpened, LastClean: dlvLastClean},
		Was: decide.SeverityHigh,
		At:  dlvOpened,
	}
	want := ":red_circle: HIGH: `&lt;!channel&gt;.\\096x\\096.corp.test. TXT` changed\n\n" +
		"```\n" +
		"expected  &lt;https://x|y&gt; &amp; *_~\n" +
		"now       \"a\"\\010\\096\\096\\096\\010&lt;@U123&gt;\\013\\000\\195\\169   at &lt;!channel&gt;.\\096x\\096.corp.test. (10.53.0.11:53), TTL 1\n" +
		"```\n\n" +
		":clock3: First seen 2026-11-11 14:02:07 UTC / Last OK 2026-11-11 14:01:07 UTC\n\n" +
		":point_right: If you did not make this change, check your DNS provider account now."
	if got := deliver.SlackText(e); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
}

// The messages of the gate run of lab 0, byte for byte.
func TestSlackMessageOfTheGateExample(t *testing.T) {
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleNameServers, Severity: decide.SeverityCritical, Peak: decide.SeverityCritical,
			Check:    obs.DelegationKey(dlvName(t, "corp.test.")),
			Expected: "ns1.corp.test. | ns2.corp.test.",
			Value:    "10.53.0.3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test.",
			Lines: []alert.Line{{Server: obs.Server{Name: dlvName(t, "ns.test."), Addr: netip.MustParseAddrPort("10.53.0.3:53")},
				Text: "ns1.dnshost.test. | ns2.dnshost.test.", TTL: 300, Received: dlvGateTime}},
			Opened: dlvGateTime, LastClean: dlvGateClean, Noticed: dlvGateTime},
		Was: decide.SeverityCritical,
		At:  dlvGateTime,
	}
	want := "{\"text\":\":rotating_light: CRITICAL: nameservers of `corp.test.` changed at the parent zone\\n\\n```\\n" +
		"expected  ns1.corp.test. | ns2.corp.test.\\n" +
		"now       ns1.dnshost.test. | ns2.dnshost.test.   at ns.test. (10.53.0.3:53), TTL 300\\n```\\n\\n" +
		":clock3: First seen 2026-11-11 14:02:07 UTC / Last OK 2026-11-11 14:01:07 UTC\\n\\n" +
		":point_right: If you did not change the nameservers, contact your registrar now.\"}"
	if got := deliver.SlackMessage(e); string(got) != want {
		t.Errorf("message:\n%s\nwant:\n%s", got, want)
	}

	resolved := time.Date(2026, 11, 11, 14, 9, 41, 0, time.UTC)
	e.Kind, e.Alert.Open, e.Alert.Resolved, e.At = alert.EventResolve, false, resolved, resolved
	want = "{\"text\":\":white_check_mark: RESOLVED: nameservers of `corp.test.` are as expected again\\n\\n```\\n" +
		"expected  ns1.corp.test. | ns2.corp.test.\\nnow       as expected again\\n```\\n\\n" +
		":clock3: First seen 2026-11-11 14:02:07 UTC / Resolved 2026-11-11 14:09:41 UTC\\n\\n" +
		":point_right: If you did not make or undo this change yourself, find out who did.\"}"
	if got := deliver.SlackMessage(e); string(got) != want {
		t.Errorf("resolved message:\n%s\nwant:\n%s", got, want)
	}
}

// dlvServer is a TLS test server and a client that trusts it and may post to
// it.
func dlvServer(t *testing.T, h http.HandlerFunc) (*httptest.Server, *httpclient.Client) {
	t.Helper()
	srv := httptest.NewTLSServer(h)
	t.Cleanup(srv.Close)
	pool := x509.NewCertPool()
	pool.AddCert(srv.Certificate())
	host, err := httpclient.HostOf(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return srv, httpclient.New([]string{host}, pool)
}

func TestSlackSendPostsTheMessage(t *testing.T) {
	type request struct {
		method, path, contentType string
		body                      []byte
	}
	got := make(chan request, 1)
	srv, c := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- request{r.Method, r.URL.Path, r.Header.Get("Content-Type"), body}
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := io.WriteString(w, "slow down"); err != nil {
			t.Error(err)
		}
	})
	slack := deliver.NewSlack(c, srv.URL+"/services/T0/B0/dlvsecret", decide.SeverityHigh)
	if slack.Name() != "slack" || slack.MinSeverity() != decide.SeverityHigh {
		t.Errorf("Name %q, MinSeverity %v; want slack, high", slack.Name(), slack.MinSeverity())
	}
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
	if !bytes.Equal(slack.Message(e), deliver.SlackMessage(e)) {
		t.Errorf("Message %q, want SlackMessage %q", slack.Message(e), deliver.SlackMessage(e))
	}
	o := slack.Send(context.Background(), deliver.SlackMessage(e))
	// "slow down" is no error word, so Send passes on no body.
	want := deliver.Outcome{Status: 429, RetryAfter: 30 * time.Second}
	if !reflect.DeepEqual(o, want) {
		t.Errorf("Send gave %+v, want %+v", o, want)
	}
	select {
	case r := <-got:
		if r.method != http.MethodPost || r.path != "/services/T0/B0/dlvsecret" || r.contentType != "application/json" ||
			!bytes.Equal(r.body, deliver.SlackMessage(e)) {
			t.Errorf("the server got %s %s, Content-Type %q, body %q", r.method, r.path, r.contentType, r.body)
		}
	default:
		t.Error("the server got no request")
	}
}

// The URL of a Slack channel is its secret, so a printed channel shows only
// its name.
func TestSlackPrintsNoURL(t *testing.T) {
	slack := deliver.NewSlack(httpclient.New(nil, nil), "https://hooks.slack.test/services/T0/B0/dlvprinted", decide.SeverityLow)
	for _, format := range []string{"%v", "%+v", "%#v", "%s"} {
		for _, v := range []any{slack, *slack} {
			if got := fmt.Sprintf(format, v); got != "slack" {
				t.Errorf("Sprintf(%q, %T) = %q, want slack", format, v, strings.ReplaceAll(got, "dlvprinted", "[marker]"))
			}
		}
	}
}

// dlvStore opens a store in a new folder and closes it at the end of the
// test.
func dlvStore(t *testing.T) (*store.Store, string) {
	t.Helper()
	dir := t.TempDir()
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := s.Close(); err != nil {
			t.Error(err)
		}
	})
	return s, dir
}

// dlvFolderHolds reports whether a file in the folder holds the text.
func dlvFolderHolds(t *testing.T, dir, text string) bool {
	t.Helper()
	files, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		data, err := os.ReadFile(filepath.Join(dir, f.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(data, []byte(text)) {
			return true
		}
	}
	return false
}

// The path of a Slack webhook URL is its secret. Whatever goes wrong, it
// never reaches an error, a reason, a line of output or the store.
func TestWebhookSecretNeverLeaves(t *testing.T) {
	const secret = "dlvT0B0secret"
	// The server does not see a client leave while it reads nothing, so the
	// silent handler waits for the end of the test too.
	release := make(chan struct{})
	srv, trusting := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.HasPrefix(r.URL.Path, "/redirect/"):
			w.Header().Set("Location", "https://"+r.Host+"/elsewhere")
			w.WriteHeader(http.StatusFound)
		case strings.HasPrefix(r.URL.Path, "/payload/"):
			w.WriteHeader(http.StatusBadRequest)
			if _, err := io.WriteString(w, "invalid_payload"); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/echo/"):
			w.WriteHeader(http.StatusBadRequest)
			if _, err := io.WriteString(w, "no_team: "+r.URL.Path); err != nil {
				t.Error(err)
			}
		case strings.HasPrefix(r.URL.Path, "/busy/"):
			w.WriteHeader(http.StatusServiceUnavailable)
		case strings.HasPrefix(r.URL.Path, "/silent/"):
			select {
			case <-r.Context().Done():
			case <-release:
			}
		}
	})
	t.Cleanup(func() { close(release) })
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, _ := httpclient.HostOf(srv.URL)
	untrusting := httpclient.New([]string{host}, nil)
	closed := dlvClosedPort(t)
	refusing := httpclient.New([]string{"127.0.0.1:" + closed}, nil)
	const badURL = `no answer "not an https URL with a host and no user name"`
	cases := []struct {
		name   string
		c      *httpclient.Client
		url    string
		reason string // exact, or a prefix when it ends in a space
		state  store.RowState
	}{
		{"not https", trusting, "http://" + addr + "/services/" + secret, badURL, store.RowPending},
		{"user info", trusting, "https://u:" + secret + "@" + addr + "/services/" + secret, badURL, store.RowPending},
		{"bad escape", trusting, "https://" + addr + "/services/" + secret + "%zz", badURL, store.RowPending},
		{"bad port", trusting, "https://127.0.0.1:8x/services/" + secret, badURL, store.RowPending},
		{"control octet", trusting, "https://" + addr + "/services/" + secret + "\n", badURL, store.RowPending},
		{"host not listed", trusting, "https://127.0.0.9:" + strconv.Itoa(srv.Listener.Addr().(*net.TCPAddr).Port) + "/services/" + secret,
			`no answer "host not allowed"`, store.RowPending},
		{"refused connection", refusing, "https://127.0.0.1:" + closed + "/services/" + secret, `no answer "network: `, store.RowPending},
		{"timeout", trusting, "https://" + addr + "/silent/" + secret, `no answer "timeout"`, store.RowPending},
		{"untrusted certificate", untrusting, "https://" + addr + "/services/" + secret, `no answer "network: `, store.RowPending},
		{"redirect", trusting, "https://" + addr + "/redirect/" + secret, "status 302", store.RowGivenUp},
		{"4xx with a body", trusting, "https://" + addr + "/payload/" + secret, `status 400 "invalid_payload"`, store.RowGivenUp},
		{"4xx that repeats the path", trusting, "https://" + addr + "/echo/" + secret, "status 400", store.RowGivenUp},
		{"5xx", trusting, "https://" + addr + "/busy/" + secret, "status 503", store.RowPending},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			// The store is closed once, before its files are read; the
			// cleanup closes it only when the test stops before that.
			dir := t.TempDir()
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			closed := false
			t.Cleanup(func() {
				if !closed {
					_ = s.Close()
				}
			})
			slack := deliver.NewSlack(c.c, c.url, decide.SeverityLow)
			e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
			if err := s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{slack})); err != nil {
				t.Fatal(err)
			}
			// The silent server is left by the client's own timeout: a
			// send that the context of the pass cut would be no attempt.
			ctx, cancel := context.WithTimeout(context.Background(), httpclient.Timeout+5*time.Second)
			defer cancel()
			attempts, err := deliver.Pass(ctx, s, []deliver.Channel{slack}, dlvLater)
			if err != nil {
				t.Fatal(err)
			}
			if len(attempts) != 1 {
				t.Fatalf("%d attempts, want 1", len(attempts))
			}
			a := attempts[0]
			reason := a.Done.Reason
			if prefix := strings.HasSuffix(c.reason, " "); !prefix && reason != c.reason || prefix && !strings.HasPrefix(reason, c.reason) {
				t.Errorf("reason %q, want %q", reason, c.reason)
			}
			if a.Done.State != c.state {
				t.Errorf("state %v, want %v", a.Done.State, c.state)
			}
			for what, text := range map[string]string{"error": a.Outcome.Err, "body": string(a.Outcome.Body), "reason": reason, "line": a.Line()} {
				if strings.Contains(text, secret) {
					t.Errorf("the %s holds the secret: %q", what, text)
				}
			}
			closed = true
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if !dlvFolderHolds(t, dir, e.Label()) {
				t.Errorf("no file of the store holds the label %q, so the search for the secret saw no row", e.Label())
			}
			if dlvFolderHolds(t, dir, secret) {
				t.Error("a file of the store holds the secret")
			}
		})
	}
}

// dlvAnswer is a raw HTTP answer with this status and body.
func dlvAnswer(status, body string) string {
	return "HTTP/1.1 " + status + "\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body
}

// A server may repeat the secret path of the webhook URL in any form: cut,
// escaped, in lower case, inside a longer text, or in a header that the client
// cannot read. None of its text reaches a result, a reason, a line or the
// store, except one short error word that the URL does not hold.
func TestServerTextReachesNoReason(t *testing.T) {
	const m = "dlvEchoMarker7"
	const short = "dlvMk7z" // shorter than 8 octets
	const word = "dlvwordsecret"
	const p = "/services/T0/B0/" + m
	const noAnswer = `no answer "network: no usable answer"`
	cases := []struct {
		name, path, marker, answer, reason string
	}{
		{"path without its slash", p, m, dlvAnswer("400 Bad Request", p[1:]), "status 400"},
		{"last segment", p, m, dlvAnswer("400 Bad Request", m), "status 400"},
		{"JSON-escaped path", p, m, dlvAnswer("400 Bad Request", `{"error":"`+strings.ReplaceAll(p, "/", `\/`)+`"}`), "status 400"},
		{"URL-encoded path", p, m, dlvAnswer("400 Bad Request", url.QueryEscape(p)), "status 400"},
		{"path in lower case", p, m, dlvAnswer("400 Bad Request", strings.ToLower(p)), "status 400"},
		{"path in a bad Location", p, m, "HTTP/1.1 302 Found\r\nLocation: %zz" + p[1:] + "\r\nContent-Length: 0\r\n\r\n", noAnswer},
		{"path in a bad header line", p, m, "HTTP/1.1 200 OK\r\nX" + p[1:] + "\r\n\r\n", noAnswer},
		{"part of a longer segment", "/hooks/id-" + m + ".json", m, dlvAnswer("400 Bad Request", "unknown token "+m), "status 400"},
		{"query key", "/services/T0?v=1&" + m, m, dlvAnswer("400 Bad Request", "unknown parameter "+m), "status 400"},
		{"short segment", "/services/T0/B0/" + short, short, dlvAnswer("400 Bad Request", "token "+short+" revoked"), "status 400"},
		{"word of the URL", "/services/T0/B0/" + word, word, dlvAnswer("400 Bad Request", word), "status 400"},
		{"Slack error word", p, m, dlvAnswer("400 Bad Request", "invalid_payload\n"), `status 400 "invalid_payload"`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err != nil {
					t.Error(err)
					return
				}
				_, err = io.WriteString(conn, c.answer)
				if err := errors.Join(err, conn.Close()); err != nil {
					t.Error(err)
				}
			})
			show := func(text string) string { return strings.ReplaceAll(text, c.marker, "[marker]") }
			holds := func(text string) bool { return strings.Contains(strings.ToLower(text), strings.ToLower(c.marker)) }
			// The store is closed before its files are read.
			dir := t.TempDir()
			s, err := store.Open(dir)
			if err != nil {
				t.Fatal(err)
			}
			slack := deliver.NewSlack(client, srv.URL+c.path, decide.SeverityLow)
			e := dlvOpen(t, "www.corp.test.", decide.SeverityHigh, decide.SeverityHigh)
			var attempts []deliver.Attempt
			err = s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{slack}))
			if err == nil {
				attempts, err = deliver.Pass(context.Background(), s, []deliver.Channel{slack}, dlvLater)
			}
			if err := errors.Join(err, s.Close()); err != nil || len(attempts) != 1 {
				t.Fatalf("Apply, Pass and Close: %d attempts, %v; want 1 and no error", len(attempts), err)
			}
			a := attempts[0]
			if a.Done.Reason != c.reason {
				t.Errorf("reason %q, want %q", show(a.Done.Reason), c.reason)
			}
			for what, text := range map[string]string{"error": a.Outcome.Err, "body": string(a.Outcome.Body), "reason": a.Done.Reason, "line": a.Line()} {
				if holds(text) {
					t.Errorf("the %s holds the secret: %q", what, show(text))
				}
			}
			files, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range files {
				data, err := os.ReadFile(filepath.Join(dir, f.Name()))
				if err != nil {
					t.Fatal(err)
				}
				if holds(string(data)) {
					t.Errorf("%s holds the secret", f.Name())
				}
			}
			if !dlvFolderHolds(t, dir, e.Label()) {
				t.Error("no file of the store holds the label of the row, so the search saw no row")
			}
		})
	}
}

// dlvClosedPort returns a port of 127.0.0.1 where nothing listens.
func dlvClosedPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := strconv.Itoa(l.Addr().(*net.TCPAddr).Port)
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	return port
}
