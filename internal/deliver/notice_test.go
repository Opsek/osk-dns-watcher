package deliver_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/store"
)

// The text of a notice as the message rules describe it, written apart from
// the code under test: the layout of an alert's text, with a headline and an
// action for each kind of notice.

const ntcTimeLayout = "2006-01-02 15:04:05 UTC"

// ntcDownFor is how long osk did not run, from the two lines of a down
// notice: the last beat and the start. Lines that do not give both times
// give "an unknown time".
func ntcDownFor(n store.Notice) string {
	const unknown = "an unknown time"
	if len(n.Lines) != 2 {
		return unknown
	}
	beat, err := time.Parse(ntcTimeLayout, strings.TrimPrefix(n.Lines[0], "last beat "))
	if err != nil {
		return unknown
	}
	started, err := time.Parse(ntcTimeLayout, strings.TrimPrefix(n.Lines[1], "started   "))
	if err != nil {
		return unknown
	}
	return dlvDuration(started.Sub(beat).Round(time.Second))
}

// ntcLabels are the labels of the stored lines of each kind of notice; the
// text pads them from 10 to 11 columns.
var ntcLabels = map[store.NoticeKind][]string{
	store.NoticeTest: {"request"},
	store.NoticeDown: {"last beat", "started"},
}

func ntcText(n store.Notice) string {
	words := map[store.NoticeKind][2]string{
		store.NoticeTest: {":test_tube: *TEST* · osk can send to this channel",
			"Nothing to do: this message only tests the path from osk to this channel."},
		store.NoticeDown: {":warning: *DOWN* · osk did not run for " + ntcDownFor(n),
			"Changes in this time were not seen when they happened. If you did not stop osk, find out who did."},
		store.NoticeExpectations: {":memo: *CHANGED* · the expectations of `" + dlvClean(n.Domain, 100) + "` changed",
			"If you did not make this change, find out who did and restore the file."},
	}[n.Kind]
	lines := []string{words[0], "", "```"}
	for i, l := range n.Lines {
		if i == 12 {
			lines = append(lines, fmt.Sprintf("and %d more lines", len(n.Lines)-12))
			break
		}
		c := dlvClean(l, 160)
		for _, label := range ntcLabels[n.Kind] {
			if strings.HasPrefix(c, label+" ") {
				c = c[:10] + " " + c[10:]
				break
			}
		}
		lines = append(lines, c)
	}
	at := n.At.UTC()
	clock := ":clock3: " + at.Format("15:04:05") + " · " + at.Format("2 Jan 2006") + " UTC"
	lines = append(lines, "```", "", clock, "", ":point_right: "+words[1])
	return strings.Join(lines, "\n")
}

// ntcAt is the time of the notices of these tests: in a zone east of UTC,
// with a fraction of a second that a text must drop, not round.
var ntcAt = time.Date(2026, 11, 13, 15, 0, 5, 700e6, dlvEast) // 10:00:05.7 UTC

func ntcTest() store.Notice {
	return store.Notice{Kind: store.NoticeTest, Lines: []string{"request   0123456789abcdef0123456789abcdef"}, At: ntcAt}
}

// ntcDown is the notice of a start after osk was down from beat to started.
// Its time is the start, so it holds no fraction of a second.
func ntcDown(beat, started time.Time) store.Notice {
	return store.Notice{Kind: store.NoticeDown, At: started, Lines: []string{
		"last beat " + beat.UTC().Format(ntcTimeLayout),
		"started   " + started.UTC().Format(ntcTimeLayout),
	}}
}

func ntcExpectations() store.Notice {
	return store.Notice{Kind: store.NoticeExpectations, Domain: "corp.test.", At: ntcAt, Lines: []string{
		"- www.corp.test. A 10.53.0.81",
		"+ mail.corp.test. A 10.53.0.82",
		"closed high record-set records www.corp.test. A",
	}}
}

// Each kind of notice gives the text of the message rules, word for word.
func TestNoticeTextForEachKind(t *testing.T) {
	started := time.Date(2026, 11, 13, 10, 0, 5, 0, time.UTC)
	cases := []struct {
		n    store.Notice
		want string
	}{
		{ntcTest(), ":test_tube: *TEST* · osk can send to this channel\n\n" +
			"```\nrequest    0123456789abcdef0123456789abcdef\n```\n\n" +
			":clock3: 10:00:05 · 13 Nov 2026 UTC\n\n" +
			":point_right: Nothing to do: this message only tests the path from osk to this channel."},
		{ntcDown(time.Date(2026, 11, 13, 7, 59, 0, 0, time.UTC), started), ":warning: *DOWN* · osk did not run for 2 h 1 min\n\n" +
			"```\nlast beat  2026-11-13 07:59:00 UTC\nstarted    2026-11-13 10:00:05 UTC\n```\n\n" +
			":clock3: 10:00:05 · 13 Nov 2026 UTC\n\n" +
			":point_right: Changes in this time were not seen when they happened. If you did not stop osk, find out who did."},
		{ntcExpectations(), ":memo: *CHANGED* · the expectations of `corp.test.` changed\n\n" +
			"```\n- www.corp.test. A 10.53.0.81\n+ mail.corp.test. A 10.53.0.82\nclosed high record-set records www.corp.test. A\n```\n\n" +
			":clock3: 10:00:05 · 13 Nov 2026 UTC\n\n" +
			":point_right: If you did not make this change, find out who did and restore the file."},
	}
	for _, c := range cases {
		if got := deliver.NoticeText(c.n); got != c.want {
			t.Errorf("%s notice:\n%s\nwant:\n%s", c.n.Kind, got, c.want)
		}
		if got := ntcText(c.n); got != c.want {
			t.Errorf("the reference text of this test is wrong for the %s notice:\n%s", c.n.Kind, got)
		}
	}
}

// The headline of a down notice gives the time from the last beat to the
// start in its largest unit that is not zero and the next smaller one when
// that is not zero.
func TestNoticeTextDownTellsTheTimeAway(t *testing.T) {
	started := time.Date(2026, 11, 13, 10, 0, 5, 0, time.UTC)
	for _, c := range []struct {
		away time.Duration
		want string
	}{
		{0, "0 s"},
		{2 * time.Second, "2 s"},
		{67 * time.Second, "1 min 7 s"},
		{59*time.Minute + 59*time.Second, "59 min 59 s"},
		{time.Hour + 5*time.Second, "1 h"},
		{49*time.Hour + time.Second, "2 d 1 h"},
	} {
		n := ntcDown(started.Add(-c.away), started)
		head, _, _ := strings.Cut(deliver.NoticeText(n), "\n")
		if want := ":warning: *DOWN* · osk did not run for " + c.want; head != want {
			t.Errorf("down for %v: headline %q, want %q", c.away, head, want)
		}
	}
}

// A down notice whose lines do not give both times tells an unknown time
// instead of a wrong one.
func TestNoticeTextDownWithoutTimesTellsUnknownTime(t *testing.T) {
	for _, lines := range [][]string{
		nil,
		{"started   2026-11-13 10:00:05 UTC"},
		{"last beat soon", "started   2026-11-13 10:00:05 UTC"},
		{"last beat 2026-11-13 08:00:05 UTC", "started   2026-11-13T10:00:05Z"},
	} {
		n := store.Notice{Kind: store.NoticeDown, Lines: lines, At: ntcAt}
		head, _, _ := strings.Cut(deliver.NoticeText(n), "\n")
		if want := ":warning: *DOWN* · osk did not run for an unknown time"; head != want {
			t.Errorf("lines %q: headline %q, want %q", lines, head, want)
		}
	}
}

// A notice of a kind this version does not know has no headline and no
// action, and no text of the notice leaves its code.
func TestNoticeTextOfUnknownKindIsEmpty(t *testing.T) {
	n := store.Notice{Kind: store.NoticeKind("other"), Domain: "corp.test.", Lines: []string{"x`<y>"}, At: ntcAt}
	text := deliver.NoticeText(n)
	lines := strings.Split(text, "\n")
	if lines[0] != "" || strings.Contains(text, "<") || strings.Count(text, "`") != 6 || !strings.Contains(text, "x\\096&lt;y&gt;") {
		t.Errorf("text:\n%s\nwant an empty headline and only the cleaned line in code", text)
	}
	if last := lines[len(lines)-1]; strings.TrimSpace(strings.TrimPrefix(last, ":point_right:")) != "" {
		t.Errorf("action line %q, want none", last)
	}
	var body map[string]any
	if err := json.Unmarshal(deliver.WebhookNotice(n), &body); err != nil || body["notice"] != "other" || body["text"] != text {
		t.Errorf("webhook body %v (%v): want notice other and the text", body, err)
	}
}

// At most twelve lines are shown; the rest are counted.
func TestNoticeTextShowsTwelveLines(t *testing.T) {
	for _, c := range []struct {
		lines int
		last  string
	}{
		{1, "+ n1.corp.test. A 10.53.0.1"},
		{12, "+ n12.corp.test. A 10.53.0.1"},
		{13, "and 1 more lines"},
		{250, "and 238 more lines"},
	} {
		n := ntcExpectations()
		n.Lines = nil
		for i := range c.lines {
			n.Lines = append(n.Lines, fmt.Sprintf("+ n%d.corp.test. A 10.53.0.1", i+1))
		}
		text := strings.Split(deliver.NoticeText(n), "\n")
		view := min(c.lines, 12)
		if c.lines > 12 {
			view++
		}
		// Besides the view: headline, three empty lines, two fences, times, action.
		if len(text) != view+8 || text[len(text)-6] != c.last {
			t.Errorf("%d lines: text\n%s\nwant %d view lines, the last %q", c.lines, strings.Join(text, "\n"), view, c.last)
		}
	}
}

// A domain or a line that tries to leave its code, to mention or to link is
// shown as text, and a long line is cut.
func TestNoticeTextCleansHostileData(t *testing.T) {
	n := store.Notice{Kind: store.NoticeExpectations, Domain: "`x`<!channel>&.test.", At: ntcAt, Lines: []string{
		"\"a\"\n```\n<@U123>\r\x00é",
		"+ <https://x|y> @here *_~",
		strings.Repeat("x", 200),
	}}
	want := ":memo: *CHANGED* · the expectations of `\\096x\\096&lt;!channel&gt;&amp;.test.` changed\n\n" +
		"```\n" +
		"\"a\"\\010\\096\\096\\096\\010&lt;@U123&gt;\\013\\000\\195\\169\n" +
		"+ &lt;https://x|y&gt; @here *_~\n" +
		strings.Repeat("x", 154) + " [cut]\n" +
		"```\n\n" +
		":clock3: 10:00:05 · 13 Nov 2026 UTC\n\n" +
		":point_right: If you did not make this change, find out who did and restore the file."
	if got := deliver.NoticeText(n); got != want {
		t.Errorf("text:\n%s\nwant:\n%s", got, want)
	}
}

// ntcHostileNotice returns a notice of any kind. The lines and the domain of
// an expectations notice come from files and are hostile; a down notice
// tells its times in its lines, and its time is its start.
func ntcHostileNotice(rng *rand.Rand) store.Notice {
	n := store.Notice{ID: rng.Int64N(1000), At: dlvRandomTime(rng)}
	switch rng.IntN(3) {
	case 0:
		n.Kind = store.NoticeTest
		n.Lines = []string{"request   " + dlvHostileText(rng, 30)}
	case 1:
		started := time.Unix(n.At.Unix(), 0).In(n.At.Location())
		n = ntcDown(started.Add(-time.Duration(rng.Int64N(400*24*3600))*time.Second), started)
	default:
		n.Kind = store.NoticeExpectations
		n.Domain = dlvHostileText(rng, dlvSize(rng))
		for range 1 + rng.IntN([]int{3, 13, 40, 260}[rng.IntN(4)]) {
			n.Lines = append(n.Lines, dlvHostileText(rng, dlvSize(rng)))
		}
	}
	return n
}

// ntcTextFault checks the text of n against the safety rules of a notice
// text and against the text the rules give, and describes the first fault,
// or returns "".
func ntcTextFault(n store.Notice) string {
	text := deliver.NoticeText(n)
	if len(text) > 3000 {
		return fmt.Sprintf("%d octets, more than 3000", len(text))
	}
	// The middle dot is allowed with a space on each side.
	ascii := strings.ReplaceAll(text, " · ", " . ")
	for i := 0; i < len(ascii); i++ {
		if c := ascii[i]; (c < 0x20 || c > 0x7E) && c != '\n' {
			return fmt.Sprintf("octet %#02x at %d", c, i)
		}
	}
	spans := 0
	if n.Kind == store.NoticeExpectations {
		spans = 1
	}
	if got := strings.Count(text, "`"); got != 6+2*spans {
		return fmt.Sprintf("%d backticks, want %d", got, 6+2*spans)
	}
	if want := ntcText(n); text != want {
		return fmt.Sprintf("text:\n%s\nwant:\n%s", text, want)
	}
	return ""
}

func TestNoticeTextSafeForAnyNoticeProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 17))
	for range 2000 {
		n := ntcHostileNotice(rng)
		if fault := ntcTextFault(n); fault != "" {
			t.Fatalf("seed %d: notice %+v: %s", seed, n, fault)
		}
	}
}

// The Slack body of a notice is its text as the one key of a JSON object,
// as for an alert.
func TestSlackNoticeIsTheTextAsJSON(t *testing.T) {
	slack := deliver.NewSlack(httpclient.New(nil, nil), "https://hooks.slack.test/services/T0/B0/ntcsecret", decide.SeverityCritical)
	hostile := ntcExpectations()
	hostile.Lines = append(hostile.Lines, "\"}<!channel>\x00\xff")
	for _, n := range []store.Notice{ntcTest(), ntcDown(ntcAt.Add(-time.Hour), ntcAt.Truncate(time.Second)), ntcExpectations(), hostile} {
		want, err := json.Marshal(struct {
			Text string `json:"text"`
		}{deliver.NoticeText(n)})
		if err != nil {
			t.Fatal(err)
		}
		body := slack.Notice(n)
		if !bytes.Equal(body, want) {
			t.Errorf("%s notice: body %s, want %s", n.Kind, body, want)
		}
		var fields map[string]any
		if err := json.Unmarshal(body, &fields); err != nil || len(fields) != 1 || fields["text"] != deliver.NoticeText(n) {
			t.Errorf("%s notice: body %s is not one key text with NoticeText (%v)", n.Kind, body, err)
		}
	}
}

// A notice goes to every channel in channel order, whatever the channel's
// minimum severity: a test must reach each channel, and the other notices
// are rare.
func TestNoticeWritesReachEveryChannelWhateverItsMinimum(t *testing.T) {
	client := httpclient.New(nil, nil)
	channels := []deliver.Channel{
		&dlvFake{name: "fake-critical", min: decide.SeverityCritical},
		deliver.NewSlack(client, "https://hooks.slack.test/services/T0/B0/ntcsecret", decide.SeverityCritical),
		deliver.NewWebhook(client, "siem", "https://hooks.siem.test/hook/ntcsecret", []byte(strings.Repeat("k", 32)), decide.SeverityCritical),
		&dlvFake{name: "fake-low", min: decide.SeverityLow},
	}
	for _, c := range []struct {
		n     store.Notice
		label string
	}{
		{ntcTest(), "notice test -"},
		{ntcDown(ntcAt.Add(-time.Hour), ntcAt.Truncate(time.Second)), "notice down -"},
		{ntcExpectations(), "notice expectations corp.test."},
	} {
		got := deliver.NoticeWrites(c.n, channels)
		if len(got) != len(channels) {
			t.Errorf("%s notice: %d deliveries for %d channels", c.n.Kind, len(got), len(channels))
			continue
		}
		for i, d := range got {
			if d.Channel != channels[i].Name() || d.Label != c.label || !bytes.Equal(d.Body, channels[i].Notice(c.n)) || len(d.Body) == 0 {
				t.Errorf("%s notice, delivery %d: channel %q, label %q, body %q; want %q, %q and that channel's notice body",
					c.n.Kind, i, d.Channel, d.Label, d.Body, channels[i].Name(), c.label)
			}
		}
		if len(deliver.NoticeWrites(c.n, nil)) != 0 {
			t.Errorf("%s notice: deliveries with no channel", c.n.Kind)
		}
	}
}
