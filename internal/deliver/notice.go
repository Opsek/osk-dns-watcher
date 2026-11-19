package deliver

import (
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// timeLayout is how the lines of a down notice write their times.
const timeLayout = "2006-01-02 15:04:05 UTC"

// noticeWording is the text of one kind of notice. {d} stands for the time
// osk-dns-watcher was down, {D} for the domain as inline code.
type noticeWording struct {
	emoji, word, phrase, action string
}

var noticeWordings = map[store.NoticeKind]noticeWording{
	store.NoticeTest: {
		emoji:  ":test_tube:",
		word:   "TEST",
		phrase: "osk-dns-watcher can send to this channel",
		action: "Nothing to do: this message only tests the path from osk-dns-watcher to this channel.",
	},
	store.NoticeDown: {
		emoji:  ":warning:",
		word:   "DOWN",
		phrase: "osk-dns-watcher did not run for {d}",
		action: "Changes in this time were not seen when they happened. If you did not stop osk-dns-watcher, find out who did.",
	},
	store.NoticeExpectations: {
		emoji:  ":memo:",
		word:   "CHANGED",
		phrase: "the expectations of {D} changed",
		action: "If you did not make this change, find out who did and restore the file.",
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
	at := n.At.UTC()
	times := ":clock3: " + at.Format(timeOfDay) + dot + at.Format(dateLayout) + " UTC"
	headline := ""
	if w.word != "" {
		headline = title(w.emoji, w.word, "") + dot + fill.Replace(w.phrase)
	}
	return compose(headline, noticeView(n), times, w.action)
}

func (s *Slack) Notice(n store.Notice) []byte {
	// Marshal cannot fail on a struct of one string.
	body, _ := json.Marshal(struct {
		Text string `json:"text"`
	}{NoticeText(n)})
	return body
}

func noticeView(n store.Notice) []string {
	lines := n.Lines
	switch n.Kind {
	case store.NoticeTest, store.NoticeDown:
		lines = widenLabels(lines)
	case store.NoticeExpectations:
	}
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
	return openFor(started.Sub(last).Round(time.Second))
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

// storedLabelWidth is the width of the labels in the stored lines of a test
// and a down notice, which the webhook sends as they are.
const storedLabelWidth = 10

// widenLabels gives the stored lines the label width of the view by one more
// space after the label.
func widenLabels(lines []string) []string {
	out := make([]string, len(lines))
	for i, l := range lines {
		out[i] = l
		if len(l) >= storedLabelWidth && l[storedLabelWidth-1] == ' ' {
			out[i] = l[:storedLabelWidth] + strings.Repeat(" ", labelWidth-storedLabelWidth) + l[storedLabelWidth:]
		}
	}
	return out
}
