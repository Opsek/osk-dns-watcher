package deliver

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/store"
)

// noticeWording is the text of one kind of notice. {d} stands for the time
// osk was down, {D} for the domain as inline code.
type noticeWording struct {
	headline, action string
}

var noticeWordings = map[store.NoticeKind]noticeWording{
	store.NoticeTest: {
		headline: ":test_tube: TEST: osk can send to this channel",
		action:   "Nothing to do: this message only tests the path from osk to this channel.",
	},
	store.NoticeDown: {
		headline: ":warning: DOWN: osk did not run for {d}",
		action:   "Changes in this time were not seen when they happened. If you did not stop osk, find out who did.",
	},
	store.NoticeExpectations: {
		headline: ":memo: CHANGED: the expectations of {D} changed",
		action:   "If you did not make this change, find out who did and restore the file.",
	},
}

// maxNoticeLines caps the lines of a notice text, which keeps it within 3000
// octets.
const maxNoticeLines = 12

// NoticeText is the Slack text of n, in the layout of SlackText. Its lines
// pass through Clean and stand inside the code block; a kind without wording
// gives empty words.
func NoticeText(n store.Notice) string {
	w := noticeWordings[n.Kind]
	fill := strings.NewReplacer("{d}", downTime(n.Lines), "{D}", "`"+Clean(n.Domain, 100)+"`")
	lines := []string{fill.Replace(w.headline), "", "```"}
	lines = append(lines, noticeView(n.Lines)...)
	lines = append(lines, "```", "", ":clock3: "+n.At.UTC().Format(timeLayout), "", ":point_right: "+w.action)
	return strings.Join(lines, "\n")
}

func (s *Slack) Notice(n store.Notice) []byte {
	// Marshal cannot fail on a struct of one string.
	body, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{NoticeText(n)})
	return body
}

func noticeView(lines []string) []string {
	view := cleanLines(lines, maxNoticeLines)
	if more := len(lines) - maxNoticeLines; more > 0 {
		view = append(view, "and "+strconv.Itoa(more)+" more lines")
	}
	return view
}

// cleanLines gives at most n lines, each through Clean. It is never nil, so
// a JSON body holds [] and not null when there is no line.
func cleanLines(lines []string, n int) []string {
	cleaned := []string{}
	for _, l := range lines[:min(len(lines), n)] {
		cleaned = append(cleaned, Clean(l, 160))
	}
	return cleaned
}

// downTime is the time from the last beat to the start, read back from the
// lines of a down notice, which alone hold both times. Lines that do not
// hold them give a fixed text, never their own.
func downTime(lines []string) string {
	last, ok := lineTime(lines, "last beat ")
	started, ok2 := lineTime(lines, "started   ")
	if !ok || !ok2 {
		return "an unknown time"
	}
	return started.Sub(last).Round(time.Second).String()
}

func lineTime(lines []string, label string) (time.Time, bool) {
	for _, l := range lines {
		if v, found := strings.CutPrefix(l, label); found {
			t, err := time.Parse(timeLayout, v)
			return t, err == nil
		}
	}
	return time.Time{}, false
}
