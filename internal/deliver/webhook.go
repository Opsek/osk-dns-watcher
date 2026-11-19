package deliver

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strconv"
	"strings"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// SchemaVersion is the "schema" of every webhook body. It changes only when a
// receiver must change to read the body.
const SchemaVersion = 1

// Webhook posts JSON to a receiver of the user's own. Each request is signed
// with a key that osk-dns-watcher and the receiver share, so the receiver can refuse a
// forged or replayed body.
type Webhook struct {
	name string
	min  decide.Severity
	// post alone holds the URL, which may carry a secret as a Slack URL does,
	// and the key. fmt prints a func as an address, so no verb, and no print
	// of a value that holds a Webhook, can show them.
	post func(ctx context.Context, body []byte) Outcome
}

// NewWebhook makes a channel whose signature is made at each attempt, so a
// retried row carries a fresh time and the key never reaches the store. Its
// answers have no known words, so a failure is told by its status alone.
func NewWebhook(c *httpclient.Client, name, url string, key []byte, min decide.Severity) *Webhook {
	post := func(ctx context.Context, body []byte) Outcome {
		ts, sig := Sign(key, body, time.Now().Unix())
		r, err := c.Post(ctx, url, "application/json", body,
			httpclient.Header{Name: "Osk-Timestamp", Value: ts}, httpclient.Header{Name: "Osk-Signature", Value: sig})
		return outcome(r, err, nil)
	}
	return &Webhook{name: name, min: min, post: post}
}

func (w *Webhook) Name() string { return w.name }

func (w *Webhook) MinSeverity() decide.Severity { return w.min }

func (w *Webhook) Message(e alert.Event) []byte { return WebhookMessage(e) }

func (w *Webhook) Notice(n store.Notice) []byte { return WebhookNotice(n) }

func (w *Webhook) Send(ctx context.Context, body []byte) Outcome { return w.post(ctx, body) }

// Sign gives the headers Osk-Timestamp and Osk-Signature of body sent at the
// Unix time unix. The HMAC-SHA256 covers the timestamp, so a receiver that
// refuses an old timestamp also refuses an old body sent again.
func Sign(key, body []byte, unix int64) (timestamp, signature string) {
	timestamp = strconv.FormatInt(unix, 10)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(timestamp + "."))
	mac.Write(body)
	return timestamp, "sha256=" + hex.EncodeToString(mac.Sum(nil))
}

type alertJSON struct {
	Schema    int        `json:"schema"`
	Type      string     `json:"type"`
	ID        string     `json:"id"`
	At        string     `json:"at"`
	Event     string     `json:"event"`
	Severity  string     `json:"severity"`
	Was       string     `json:"was"`
	Rule      string     `json:"rule"`
	Check     checkJSON  `json:"check"`
	Expected  string     `json:"expected"`
	Seen      []seenJSON `json:"seen"`
	More      int        `json:"more"`
	Value     []string   `json:"value"`
	FirstSeen string     `json:"first_seen"`
	LastClean string     `json:"last_clean"`
	Resolved  string     `json:"resolved"`
	Text      string     `json:"text"`
}

type checkJSON struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	RType  string `json:"rtype"`
}

type seenJSON struct {
	Server  string `json:"server"`
	Address string `json:"address"`
	Text    string `json:"text"`
	TTL     uint32 `json:"ttl"`
}

type noticeJSON struct {
	Schema int      `json:"schema"`
	Type   string   `json:"type"`
	ID     string   `json:"id"`
	At     string   `json:"at"`
	Notice string   `json:"notice"`
	Domain string   `json:"domain"`
	Lines  []string `json:"lines"`
	Text   string   `json:"text"`
}

const maxBodyLines = 200

// WebhookMessage is the body of e. Every string from DNS or a file passes
// through Clean with the caps of the Slack text, so a receiver that shows a
// value is as safe as Slack; text is the Slack text itself.
func WebhookMessage(e alert.Event) []byte {
	a := e.Alert
	seen, more := seenOf(e)
	var value []string
	if a.Value != "" {
		value = strings.Split(a.Value, "\n")
	}
	// Marshal cannot fail on strings, numbers and lists of them.
	body, _ := json.Marshal(alertJSON{
		Schema:    SchemaVersion,
		Type:      "alert",
		ID:        bodyID(a.Identity(), e.Kind.String(), strconv.FormatInt(e.At.UnixNano(), 10)),
		At:        jsonTime(e.At),
		Event:     e.Kind.String(),
		Severity:  a.Severity.String(),
		Was:       e.Was.String(),
		Rule:      a.Rule.String(),
		Check:     checkOf(a.Check),
		Expected:  Clean(a.Expected, 160),
		Seen:      seen,
		More:      more,
		Value:     cleanLines(valueLines(a.Rule, value), maxBodyLines),
		FirstSeen: jsonTime(a.Opened),
		LastClean: jsonTime(a.LastClean),
		Resolved:  jsonTime(a.Resolved),
		Text:      SlackText(e),
	})
	return body
}

// WebhookNotice is the body of n, cleaned as WebhookMessage cleans.
func WebhookNotice(n store.Notice) []byte {
	// Marshal cannot fail on strings, numbers and lists of them.
	body, _ := json.Marshal(noticeJSON{
		Schema: SchemaVersion,
		Type:   "notice",
		ID:     bodyID("notice", string(n.Kind), n.Domain, strconv.FormatInt(n.At.UnixNano(), 10)),
		At:     jsonTime(n.At),
		Notice: string(n.Kind),
		Domain: Clean(n.Domain, 100),
		Lines:  cleanLines(n.Lines, maxBodyLines),
		Text:   NoticeText(n),
	})
	return body
}

// bodyID lets a receiver drop a body it saw before. Equal parts give equal
// ids, and a retry sends the stored body, so its id never changes.
func bodyID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:16])
}

func jsonTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// valueLines gives the lines of Value that a body holds. The certificate
// rules list names, and a receiver wants all of them; every other rule shows
// what the Slack text shows.
func valueLines(r decide.Rule, lines []string) []string {
	if r == decide.RuleIssuer || r == decide.RuleCertName || r == decide.RuleHostnames {
		return lines
	}
	mail := r == decide.RuleSPF || r == decide.RuleDMARC || r == decide.RuleDKIM || r == decide.RuleMTASTS
	if !mail {
		return lines[:min(len(lines), maxServers)]
	}
	// The server lines are cut as for any rule; every word stays.
	var out []string
	servers := 0
	for _, l := range lines {
		if strings.HasPrefix(l, "weaker ") {
			out = append(out, l)
		} else if servers < maxServers {
			out = append(out, l)
			servers++
		}
	}
	return out
}

// checkOf leaves kind and rtype empty for an alert about a whole domain,
// whose check has no kind and no type, and rtype empty for a check of the
// certificates, which has no type.
func checkOf(k obs.Key) checkJSON {
	c := checkJSON{Domain: Clean(k.Domain.Lower().String(), 100), Name: Clean(k.Name.Lower().String(), 100)}
	if k.Kind != 0 {
		c.Kind = k.Kind.String()
		if k.Kind != obs.KindCertificates {
			c.RType = Clean(k.Type.String(), 20)
		}
	}
	return c
}

// seenOf gives the servers that the Slack text shows, and how many it leaves
// out. A resolve shows none.
func seenOf(e alert.Event) ([]seenJSON, int) {
	seen := []seenJSON{}
	if e.Kind == alert.EventResolve {
		return seen, 0
	}
	lines := e.Alert.Lines
	for _, l := range lines[:min(len(lines), maxServers)] {
		s := seenJSON{Text: Clean(l.Text, 160), TTL: l.TTL}
		if l.Server.Name.LabelCount() > 0 {
			s.Server = Clean(l.Server.Name.Lower().String(), 64)
		}
		if l.Server.Addr.IsValid() {
			s.Address = Clean(l.Server.Addr.String(), 64)
		}
		seen = append(seen, s)
	}
	return seen, len(lines) - len(seen)
}
