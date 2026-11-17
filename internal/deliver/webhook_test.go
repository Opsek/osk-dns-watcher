package deliver_test

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
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

// wbhVerify is the check of a receiver, as the webhook format describes it.
func wbhVerify(key, body []byte, h http.Header, now time.Time) bool {
	ts := h.Get("Osk-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec < now.Unix()-300 || sec > now.Unix()+300 {
		return false // not fresh: a replay or a wrong clock
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(h.Get("Osk-Signature")))
}

func wbhHeader(ts, sig string) http.Header {
	h := http.Header{}
	h.Set("Osk-Timestamp", ts)
	h.Set("Osk-Signature", sig)
	return h
}

// wbhID is the id of a body: the first 16 octets of SHA-256 of the parts
// joined by LF, in lower-case hex.
func wbhID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return hex.EncodeToString(sum[:16])
}

func wbhNanos(t time.Time) string { return strconv.FormatInt(t.UnixNano(), 10) }

func wbhTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format("2006-01-02T15:04:05Z")
}

// The bodies, with their keys in the order of the format.
type wbhCheck struct {
	Kind   string `json:"kind"`
	Domain string `json:"domain"`
	Name   string `json:"name"`
	Rtype  string `json:"rtype"`
}

type wbhSeen struct {
	Server  string `json:"server"`
	Address string `json:"address"`
	Text    string `json:"text"`
	TTL     uint32 `json:"ttl"`
}

type wbhAlert struct {
	Schema    int       `json:"schema"`
	Type      string    `json:"type"`
	ID        string    `json:"id"`
	At        string    `json:"at"`
	Event     string    `json:"event"`
	Severity  string    `json:"severity"`
	Was       string    `json:"was"`
	Rule      string    `json:"rule"`
	Check     wbhCheck  `json:"check"`
	Expected  string    `json:"expected"`
	Seen      []wbhSeen `json:"seen"`
	More      int       `json:"more"`
	Value     []string  `json:"value"`
	FirstSeen string    `json:"first_seen"`
	LastClean string    `json:"last_clean"`
	Resolved  string    `json:"resolved"`
	Text      string    `json:"text"`
}

type wbhNotice struct {
	Schema int      `json:"schema"`
	Type   string   `json:"type"`
	ID     string   `json:"id"`
	At     string   `json:"at"`
	Notice string   `json:"notice"`
	Domain string   `json:"domain"`
	Lines  []string `json:"lines"`
	Text   string   `json:"text"`
}

func wbhAlertKeys(seen int) []string {
	keys := []string{"schema", "type", "id", "at", "event", "severity", "was", "rule",
		"check", "check.kind", "check.domain", "check.name", "check.rtype", "expected", "seen"}
	for range seen {
		keys = append(keys, "seen[].server", "seen[].address", "seen[].text", "seen[].ttl")
	}
	return append(keys, "more", "value", "first_seen", "last_clean", "resolved", "text")
}

var wbhNoticeKeys = []string{"schema", "type", "id", "at", "notice", "domain", "lines", "text"}

// wbhKeys gives the keys of the JSON object in body in their order: the keys
// of a nested object as parent.key, those of an object in a list as
// parent[].key. The format has no null, so a null is an error, and so is
// anything after the object.
func wbhKeys(body []byte) ([]string, error) {
	dec := json.NewDecoder(bytes.NewReader(body))
	var keys []string
	var walk func(path string) error
	walk = func(path string) error {
		tok, err := dec.Token()
		if err != nil {
			return err
		}
		switch tok {
		case nil:
			return fmt.Errorf("null at %q", path)
		case json.Delim('{'):
			for dec.More() {
				k, err := dec.Token()
				if err != nil {
					return err
				}
				name, _ := k.(string)
				if path != "" {
					name = path + "." + name
				}
				keys = append(keys, name)
				if err := walk(name); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		case json.Delim('['):
			for dec.More() {
				if err := walk(path + "[]"); err != nil {
					return err
				}
			}
			_, err = dec.Token()
			return err
		}
		return nil
	}
	if err := walk(""); err != nil {
		return nil, err
	}
	if _, err := dec.Token(); err != io.EOF {
		return nil, fmt.Errorf("data after the object (%v)", err)
	}
	return keys, nil
}

// wbhDecode decodes body into v, which must hold every key of body.
func wbhDecode(body []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(body))
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

// wbhPlain reports whether s holds only octets 0x20-0x7E, and no backtick,
// < or >: text that cannot leave code or form a link anywhere it is shown.
func wbhPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7E || c == '`' || c == '<' || c == '>' {
			return false
		}
	}
	return true
}

var (
	wbhHexID   = regexp.MustCompile(`^[0-9a-f]{32}$`)
	wbhSigForm = regexp.MustCompile(`^sha256=[0-9a-f]{64}$`)
)

// wbhValueLines are the lines of an alert's value as decide joins them: none
// for an empty value.
func wbhValueLines(v string) []string {
	if v == "" {
		return nil
	}
	return strings.Split(v, "\n")
}

// wbhWantAlert is the body of e as the format describes it. Strings from DNS
// and from the file pass through Clean with the caps of the Slack text, and
// names are in lower case as in that text.
func wbhWantAlert(e alert.Event) wbhAlert {
	a, k := e.Alert, e.Alert.Check
	w := wbhAlert{
		Schema: 1, Type: "alert", ID: wbhID(a.Identity(), e.Kind.String(), wbhNanos(e.At)), At: wbhTime(e.At),
		Event: e.Kind.String(), Severity: a.Severity.String(), Was: e.Was.String(), Rule: a.Rule.String(),
		Check: wbhCheck{Domain: dlvClean(k.Domain.Lower().String(), 100), Name: dlvClean(k.Name.Lower().String(), 100),
			Rtype: dlvClean(k.Type.String(), 20)},
		Expected: dlvClean(a.Expected, 160), Seen: []wbhSeen{}, Value: []string{},
		FirstSeen: wbhTime(a.Opened), LastClean: wbhTime(a.LastClean), Resolved: wbhTime(a.Resolved), Text: deliver.SlackText(e),
	}
	// A check of a whole domain has no kind and no type.
	if k.Kind != 0 {
		w.Check.Kind = k.Kind.String()
	} else {
		w.Check.Rtype = ""
	}
	if e.Kind != alert.EventResolve {
		for i, l := range a.Lines {
			if i == 6 {
				w.More = len(a.Lines) - 6
				break
			}
			s := wbhSeen{Text: dlvClean(l.Text, 160), TTL: l.TTL}
			if l.Server.Name.LabelCount() > 0 {
				s.Server = dlvClean(l.Server.Name.Lower().String(), 64)
			}
			if l.Server.Addr.IsValid() {
				s.Address = dlvClean(l.Server.Addr.String(), 64)
			}
			w.Seen = append(w.Seen, s)
		}
	}
	for i, l := range wbhValueLines(a.Value) {
		if i == 6 {
			break
		}
		w.Value = append(w.Value, dlvClean(l, 160))
	}
	return w
}

func wbhWantNotice(n store.Notice) wbhNotice {
	w := wbhNotice{Schema: 1, Type: "notice", ID: wbhID("notice", string(n.Kind), n.Domain, wbhNanos(n.At)), At: wbhTime(n.At),
		Notice: string(n.Kind), Domain: dlvClean(n.Domain, 100), Lines: []string{}, Text: deliver.NoticeText(n)}
	for i, l := range n.Lines {
		if i == 200 {
			break
		}
		w.Lines = append(w.Lines, dlvClean(l, 160))
	}
	return w
}

// wbhShapeFault checks what every body must be: JSON with the keys in order,
// no null and no key beyond the format. It decodes body into into.
func wbhShapeFault(body []byte, want []string, into any) string {
	keys, err := wbhKeys(body)
	if err != nil {
		return fmt.Sprintf("body %s: %v", body, err)
	}
	if !reflect.DeepEqual(keys, want) {
		return fmt.Sprintf("keys %q, want %q", keys, want)
	}
	if err := wbhDecode(body, into); err != nil {
		return fmt.Sprintf("body %s: %v", body, err)
	}
	return ""
}

// wbhAlertFault checks the body of e and describes the first fault, or
// returns "". It accepts a name in the letter case of the event; a test of
// its own asks for lower case.
func wbhAlertFault(e alert.Event) string {
	body := deliver.WebhookMessage(e)
	if again := deliver.WebhookMessage(e); !bytes.Equal(body, again) {
		return fmt.Sprintf("two bodies of one event differ:\n%s\n%s", body, again)
	}
	var got wbhAlert
	want := wbhWantAlert(e)
	if fault := wbhShapeFault(body, wbhAlertKeys(len(want.Seen)), &got); fault != "" {
		return fault
	}
	if !wbhHexID.MatchString(got.ID) {
		return fmt.Sprintf("id %q is not 32 lower-case hex digits", got.ID)
	}
	strs := []string{got.Type, got.ID, got.At, got.Event, got.Severity, got.Was, got.Rule, got.Check.Kind, got.Check.Domain,
		got.Check.Name, got.Check.Rtype, got.Expected, got.FirstSeen, got.LastClean, got.Resolved}
	for _, s := range got.Seen {
		strs = append(strs, s.Server, s.Address, s.Text)
	}
	for _, s := range append(strs, got.Value...) {
		if !wbhPlain(s) {
			return fmt.Sprintf("the string %q holds an octet outside 0x20-0x7E, a backtick, < or >", s)
		}
	}
	if strings.EqualFold(got.Check.Domain, want.Check.Domain) {
		want.Check.Domain = got.Check.Domain
	}
	if strings.EqualFold(got.Check.Name, want.Check.Name) {
		want.Check.Name = got.Check.Name
	}
	for i := range min(len(got.Seen), len(want.Seen)) {
		if strings.EqualFold(got.Seen[i].Server, want.Seen[i].Server) {
			want.Seen[i].Server = got.Seen[i].Server
		}
	}
	if !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("body decodes to\n%+v\nwant\n%+v", got, want)
	}
	return ""
}

func wbhNoticeFault(n store.Notice) string {
	body := deliver.WebhookNotice(n)
	if again := deliver.WebhookNotice(n); !bytes.Equal(body, again) {
		return fmt.Sprintf("two bodies of one notice differ:\n%s\n%s", body, again)
	}
	var got wbhNotice
	if fault := wbhShapeFault(body, wbhNoticeKeys, &got); fault != "" {
		return fault
	}
	if !wbhHexID.MatchString(got.ID) {
		return fmt.Sprintf("id %q is not 32 lower-case hex digits", got.ID)
	}
	for _, s := range append([]string{got.Type, got.ID, got.At, got.Notice, got.Domain}, got.Lines...) {
		if !wbhPlain(s) {
			return fmt.Sprintf("the string %q holds an octet outside 0x20-0x7E, a backtick, < or >", s)
		}
	}
	if want := wbhWantNotice(n); !reflect.DeepEqual(got, want) {
		return fmt.Sprintf("body decodes to\n%+v\nwant\n%+v", got, want)
	}
	return ""
}

// wbhSignFault signs a random body with a random key and time, and checks
// the signature as a receiver does at a random time near it.
func wbhSignFault(rng *rand.Rand) string {
	key := make([]byte, 32+rng.IntN(33))
	for i := range key {
		key[i] = byte(rng.IntN(256))
	}
	body := []byte(dlvHostileText(rng, []int{0, 1, 100, 3000}[rng.IntN(4)]))
	t := 946684800 + rng.Int64N(3155760000)
	ts, sig := deliver.Sign(key, body, t)
	if ts != strconv.FormatInt(t, 10) || !wbhSigForm.MatchString(sig) {
		return fmt.Sprintf("Sign(%x, %q, %d) = %q, %q; want the decimal time and sha256= with 64 lower-case hex digits", key, body, t, ts, sig)
	}
	h := wbhHeader(ts, sig)
	d := []int64{rng.Int64N(1201) - 600, 300, -300, 301, -301, 0}[rng.IntN(6)]
	if got := wbhVerify(key, body, h, time.Unix(t+d, rng.Int64N(1e9))); got != (d >= -300 && d <= 300) {
		return fmt.Sprintf("key %x, body %q, time %d: the check %d s later gives %v", key, body, t, d, got)
	}
	other := bytes.Clone(key)
	other[rng.IntN(len(other))] ^= byte(1 + rng.IntN(255))
	if wbhVerify(other, body, h, time.Unix(t, 0)) {
		return fmt.Sprintf("key %x, body %q, time %d: the signature passes with the key %x", key, body, t, other)
	}
	if len(body) > 0 {
		changed := bytes.Clone(body)
		changed[rng.IntN(len(changed))] ^= byte(1 + rng.IntN(255))
		if wbhVerify(key, changed, h, time.Unix(t, 0)) {
			return fmt.Sprintf("key %x, body %q, time %d: the signature passes for the body %q", key, body, t, changed)
		}
	}
	return ""
}

// wbhHostileEvent is an event of any kind, rule and severity with hostile
// data, made as decide and Transition make them: the check of a whole domain
// names the domain, and only a resolve closes its alert and sets its end.
func wbhHostileEvent(rng *rand.Rand) alert.Event {
	rules := []decide.Rule{decide.RuleInvalidFile, decide.RuleNotCovered, decide.RuleZone, decide.RuleNameServers,
		decide.RuleRecordSet, decide.RuleCheckFailing, decide.RuleZoneChanged}
	e := dlvHostileEvent(rng)
	e.Alert.Rule = rules[rng.IntN(len(rules))]
	if e.Alert.Check.Kind == 0 {
		e.Alert.Check.Name, e.Alert.Check.Type = e.Alert.Check.Domain, 0
	}
	e.Alert.Open = e.Kind != alert.EventResolve
	e.Alert.Resolved = time.Time{}
	if !e.Alert.Open {
		e.Alert.Resolved = e.At
	}
	return e
}

func TestWebhookProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 11))
	for i := range 2000 {
		if i%2 == 0 {
			e := wbhHostileEvent(rng)
			if fault := wbhAlertFault(e); fault != "" {
				t.Fatalf("seed %d: event %+v: %s", seed, e, fault)
			}
		} else {
			n := ntcHostileNotice(rng)
			if fault := wbhNoticeFault(n); fault != "" {
				t.Fatalf("seed %d: notice %+v: %s", seed, n, fault)
			}
		}
		if fault := wbhSignFault(rng); fault != "" {
			t.Fatalf("seed %d: %s", seed, fault)
		}
	}
}

// wbhGateEvent is the open event of the gate run of lab 0.
func wbhGateEvent(t *testing.T) alert.Event {
	return alert.Event{
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
}

// The two bodies of the gate run of lab 0, byte for byte. Their ids were
// computed apart from Go, with sha256sum.
func TestWebhookBodiesOfTheGateExample(t *testing.T) {
	if deliver.SchemaVersion != 1 {
		t.Errorf("SchemaVersion %d, want 1", deliver.SchemaVersion)
	}
	e := wbhGateEvent(t)
	id := wbhID("nameservers delegation corp.test. corp.test. NS", "open", wbhNanos(e.At))
	if id != "3001ed9f217c534d93f5b199f2ad9d7b" {
		t.Fatalf("the id of this test is %s, want the one sha256sum gives", id)
	}
	want := `{"schema":1,"type":"alert","id":"3001ed9f217c534d93f5b199f2ad9d7b","at":"2026-11-11T14:02:07Z","event":"open",` +
		`"severity":"critical","was":"critical","rule":"nameservers",` +
		`"check":{"kind":"delegation","domain":"corp.test.","name":"corp.test.","rtype":"NS"},` +
		`"expected":"ns1.corp.test. | ns2.corp.test.",` +
		`"seen":[{"server":"ns.test.","address":"10.53.0.3:53","text":"ns1.dnshost.test. | ns2.dnshost.test.","ttl":300}],` +
		`"more":0,"value":["10.53.0.3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test."],` +
		`"first_seen":"2026-11-11T14:02:07Z","last_clean":"2026-11-11T14:01:07Z","resolved":"",` +
		"\"text\":\":rotating_light: CRITICAL: nameservers of `corp.test.` changed at the parent zone\\n\\n```\\n" +
		"expected  ns1.corp.test. | ns2.corp.test.\\n" +
		"now       ns1.dnshost.test. | ns2.dnshost.test.   at ns.test. (10.53.0.3:53), TTL 300\\n```\\n\\n" +
		":clock3: First seen 2026-11-11 14:02:07 UTC / Last OK 2026-11-11 14:01:07 UTC\\n\\n" +
		":point_right: If you did not change the nameservers, contact your registrar now.\"}"
	if got := deliver.WebhookMessage(e); string(got) != want {
		t.Errorf("open body:\n%s\nwant:\n%s", got, want)
	}

	resolved := time.Date(2026, 11, 11, 14, 9, 41, 0, time.UTC)
	e.Kind, e.Alert.Open, e.Alert.Resolved, e.At = alert.EventResolve, false, resolved, resolved
	id = wbhID("nameservers delegation corp.test. corp.test. NS", "resolve", wbhNanos(e.At))
	if id != "23795d1dfd6bddcaba2f5fb8904d3f42" {
		t.Fatalf("the id of this test is %s, want the one sha256sum gives", id)
	}
	want = `{"schema":1,"type":"alert","id":"23795d1dfd6bddcaba2f5fb8904d3f42","at":"2026-11-11T14:09:41Z","event":"resolve",` +
		`"severity":"critical","was":"critical","rule":"nameservers",` +
		`"check":{"kind":"delegation","domain":"corp.test.","name":"corp.test.","rtype":"NS"},` +
		`"expected":"ns1.corp.test. | ns2.corp.test.","seen":[],` +
		`"more":0,"value":["10.53.0.3:53 ns.test. ns1.dnshost.test. | ns2.dnshost.test."],` +
		`"first_seen":"2026-11-11T14:02:07Z","last_clean":"2026-11-11T14:01:07Z","resolved":"2026-11-11T14:09:41Z",` +
		"\"text\":\":white_check_mark: RESOLVED: nameservers of `corp.test.` are as expected again\\n\\n```\\n" +
		"expected  ns1.corp.test. | ns2.corp.test.\\nnow       as expected again\\n```\\n\\n" +
		":clock3: First seen 2026-11-11 14:02:07 UTC / Resolved 2026-11-11 14:09:41 UTC\\n\\n" +
		":point_right: If you did not make or undo this change yourself, find out who did.\"}"
	if got := deliver.WebhookMessage(e); string(got) != want {
		t.Errorf("resolved body:\n%s\nwant:\n%s", got, want)
	}
}

// wbhRecordSetEvent is an event of a record-set alert as Transition makes
// it, with two servers, one of them without a name or an address, names in
// mixed case, and times east of UTC with fractions of a second.
func wbhRecordSetEvent(t *testing.T, kind alert.EventKind) alert.Event {
	was := map[alert.EventKind]decide.Severity{alert.EventOpen: decide.SeverityHigh, alert.EventUpdate: decide.SeverityHigh,
		alert.EventEscalate: decide.SeverityMedium, alert.EventReminder: decide.SeverityHigh, alert.EventResolve: decide.SeverityHigh}
	e := alert.Event{
		Kind: kind,
		Alert: alert.Alert{ID: 7, Open: kind != alert.EventResolve, Rule: decide.RuleRecordSet,
			Severity: decide.SeverityHigh, Peak: decide.SeverityCritical,
			Check:    obs.RecordsKey(dlvName(t, "Corp.TEST."), dlvName(t, "WWW.corp.test."), dnswire.TypeA),
			Expected: "10.53.0.81", Value: "10.53.0.11:53 ns1.corp.test. 10.53.0.99\n- - none", Lines: dlvLines(t),
			Opened: dlvOpened, LastClean: dlvLastClean, Noticed: dlvNoticed},
		Was: was[kind],
		At:  dlvResolved,
	}
	if kind == alert.EventResolve {
		e.Alert.Resolved = dlvResolved
	}
	return e
}

// wbhBodyFault compares body with the JSON of want, byte for byte.
func wbhBodyFault(body []byte, want any) string {
	data, err := json.Marshal(want)
	if err != nil {
		return err.Error()
	}
	if !bytes.Equal(body, data) {
		return fmt.Sprintf("body:\n%s\nwant:\n%s", body, data)
	}
	return ""
}

// Every field of the body of each kind of event, with names in lower case,
// times in UTC without fractions, and a server without a name or an address
// shown as "".
func TestWebhookBodyFieldsForEachEventKind(t *testing.T) {
	for _, c := range []struct {
		kind      alert.EventKind
		word, was string
	}{
		{alert.EventOpen, "open", "high"},
		{alert.EventUpdate, "update", "high"},
		{alert.EventEscalate, "escalate", "medium"},
		{alert.EventReminder, "reminder", "high"},
		{alert.EventResolve, "resolve", "high"},
	} {
		e := wbhRecordSetEvent(t, c.kind)
		want := wbhAlert{
			Schema: 1, Type: "alert", ID: wbhID("record-set records corp.test. www.corp.test. A", c.word, wbhNanos(dlvResolved)),
			At: "2026-11-12T08:30:00Z", Event: c.word, Severity: "high", Was: c.was, Rule: "record-set",
			Check:    wbhCheck{Kind: "records", Domain: "corp.test.", Name: "www.corp.test.", Rtype: "A"},
			Expected: "10.53.0.81",
			Seen: []wbhSeen{{Server: "ns1.corp.test.", Address: "10.53.0.11:53", Text: "10.53.0.99", TTL: 120},
				{Server: "", Address: "", Text: "none", TTL: 300}},
			More: 0, Value: []string{"10.53.0.11:53 ns1.corp.test. 10.53.0.99", "- - none"},
			FirstSeen: "2026-11-11T14:02:07Z", LastClean: "2026-11-11T14:01:07Z", Resolved: "",
			Text: deliver.SlackText(e),
		}
		if c.kind == alert.EventResolve {
			want.Seen, want.Resolved = []wbhSeen{}, "2026-11-12T08:30:00Z"
		}
		if fault := wbhBodyFault(deliver.WebhookMessage(e), want); fault != "" {
			t.Errorf("%s: %s", c.word, fault)
		}
	}
}

// At most six servers and six lines of the value are in the body; the
// servers left out are counted. An alert with no clean check has "" for it.
func TestWebhookBodyCapsServersAndValueLines(t *testing.T) {
	e := wbhRecordSetEvent(t, alert.EventOpen)
	e.Alert.LastClean = time.Time{}
	e.Alert.Lines, e.Alert.Value = nil, ""
	want := wbhAlert{
		Schema: 1, Type: "alert", ID: wbhID("record-set records corp.test. www.corp.test. A", "open", wbhNanos(dlvResolved)),
		At: "2026-11-12T08:30:00Z", Event: "open", Severity: "high", Was: "high", Rule: "record-set",
		Check:    wbhCheck{Kind: "records", Domain: "corp.test.", Name: "www.corp.test.", Rtype: "A"},
		Expected: "10.53.0.81", More: 2,
		FirstSeen: "2026-11-11T14:02:07Z", LastClean: "", Resolved: "",
	}
	for i := 1; i <= 8; i++ {
		addr := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 53, 0, byte(i)}), 53)
		if i == 8 {
			addr = netip.MustParseAddrPort("[fd53::12]:53")
		}
		e.Alert.Lines = append(e.Alert.Lines, alert.Line{Server: obs.Server{Name: dlvName(t, fmt.Sprintf("NS%d.Corp.Test.", i)), Addr: addr},
			Text: "10.53.0.99", TTL: uint32(60 + i)})
		e.Alert.Value += fmt.Sprintf("%s ns%d.corp.test. 10.53.0.99\n", addr, i)
		if i <= 6 {
			want.Seen = append(want.Seen, wbhSeen{Server: fmt.Sprintf("ns%d.corp.test.", i), Address: addr.String(), Text: "10.53.0.99", TTL: uint32(60 + i)})
			want.Value = append(want.Value, fmt.Sprintf("%s ns%d.corp.test. 10.53.0.99", addr, i))
		}
	}
	e.Alert.Value = strings.TrimSuffix(e.Alert.Value, "\n")
	want.Text = deliver.SlackText(e)
	if fault := wbhBodyFault(deliver.WebhookMessage(e), want); fault != "" {
		t.Error(fault)
	}
}

// An alert about a whole domain, such as a file that is not valid, has no
// kind of check and no type, its name is the domain, and it has no
// expectation and no server; its lists stay lists.
func TestWebhookBodyOfDomainAlert(t *testing.T) {
	e := alert.Event{
		Kind: alert.EventOpen,
		Alert: alert.Alert{Open: true, Rule: decide.RuleInvalidFile, Severity: decide.SeverityMedium, Peak: decide.SeverityMedium,
			Check: obs.Key{Domain: dlvName(t, "Corp.Test."), Name: dlvName(t, "Corp.Test.")},
			Value: "line 3: want a type after the name", Opened: dlvOpened, Noticed: dlvOpened},
		Was: decide.SeverityMedium,
		At:  dlvOpened,
	}
	body := deliver.WebhookMessage(e)
	var got wbhAlert
	if fault := wbhShapeFault(body, wbhAlertKeys(0), &got); fault != "" {
		t.Fatal(fault)
	}
	want := wbhAlert{
		Schema: 1, Type: "alert", ID: wbhID("invalid-file kind0 corp.test. corp.test. TYPE0", "open", wbhNanos(dlvOpened)),
		At: "2026-11-11T14:02:07Z", Event: "open", Severity: "medium", Was: "medium", Rule: "invalid-file",
		Check: wbhCheck{Kind: "", Domain: "corp.test.", Name: "corp.test.", Rtype: ""}, Expected: "", Seen: []wbhSeen{}, More: 0,
		Value: []string{"line 3: want a type after the name"}, FirstSeen: "2026-11-11T14:02:07Z", LastClean: "", Resolved: "",
		Text: deliver.SlackText(e),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body decodes to\n%+v\nwant\n%+v", got, want)
	}
	if !bytes.Contains(body, []byte(`"seen":[]`)) {
		t.Errorf("body %s: want an empty list of servers", body)
	}
}

// A resolve lists no server and counts none as left out, however many
// servers its alert holds.
func TestWebhookBodyOfResolveCountsNoServer(t *testing.T) {
	e := wbhRecordSetEvent(t, alert.EventResolve)
	for i := range 9 {
		e.Alert.Lines = append(e.Alert.Lines, alert.Line{Server: obs.Server{Name: dlvName(t, fmt.Sprintf("ns%d.corp.test.", i))}, Text: "x", TTL: 1})
	}
	var got wbhAlert
	if err := wbhDecode(deliver.WebhookMessage(e), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Seen) != 0 || got.More != 0 || got.Resolved != "2026-11-12T08:30:00Z" {
		t.Errorf("seen %v, more %d, resolved %q; want none, 0 and the time of the resolve", got.Seen, got.More, got.Resolved)
	}
}

// An empty value has no lines: the list is empty, not null and not one
// empty line.
func TestWebhookBodyOfEmptyValueIsEmptyList(t *testing.T) {
	e := wbhRecordSetEvent(t, alert.EventOpen)
	e.Alert.Value = ""
	if body := deliver.WebhookMessage(e); !bytes.Contains(body, []byte(`"value":[]`)) {
		t.Errorf("body %s: want \"value\":[]", body)
	}
}

// Data from DNS and the file that tries to leave code, to link, to mention or
// to break the JSON reaches the receiver as the same cleaned text, and the
// body holds no < or > at all.
func TestWebhookBodyCleansHostileData(t *testing.T) {
	name, err := dnswire.NameFromLabels([]string{"<!channel>", "`x`", "Corp", "test"})
	if err != nil {
		t.Fatal(err)
	}
	e := alert.Event{
		Kind: alert.EventUpdate,
		Alert: alert.Alert{Open: true, Rule: decide.RuleRecordSet, Severity: decide.SeverityHigh, Peak: decide.SeverityHigh,
			Check:    obs.RecordsKey(dlvName(t, "corp.test."), name, dnswire.TypeTXT),
			Expected: "<https://x|y> & *_~ </script>",
			Value:    "x\r\n`y`\n<z>\n\"\\\x00\xff",
			Lines: []alert.Line{{Server: obs.Server{Name: name, Addr: netip.MustParseAddrPort("10.53.0.11:53")},
				Text: "\"a\"\n```\n<@U123>\r\x00é", TTL: 1}},
			Opened: dlvOpened, LastClean: dlvLastClean},
		Was: decide.SeverityHigh,
		At:  dlvOpened,
	}
	body := deliver.WebhookMessage(e)
	if bytes.ContainsAny(body, "<>") {
		t.Errorf("the body holds < or >: %s", body)
	}
	var got wbhAlert
	if err := wbhDecode(body, &got); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	cleanName := "&lt;!channel&gt;.\\096x\\096.corp.test."
	want := wbhAlert{
		Schema: 1, Type: "alert", ID: wbhID(e.Alert.Identity(), "update", wbhNanos(dlvOpened)),
		At: "2026-11-11T14:02:07Z", Event: "update", Severity: "high", Was: "high", Rule: "record-set",
		Check:    wbhCheck{Kind: "records", Domain: "corp.test.", Name: cleanName, Rtype: "TXT"},
		Expected: "&lt;https://x|y&gt; &amp; *_~ &lt;/script&gt;",
		Seen: []wbhSeen{{Server: cleanName, Address: "10.53.0.11:53",
			Text: "\"a\"\\010\\096\\096\\096\\010&lt;@U123&gt;\\013\\000\\195\\169", TTL: 1}},
		Value:     []string{"x\\013", "\\096y\\096", "&lt;z&gt;", "\"\\\\000\\255"},
		FirstSeen: "2026-11-11T14:02:07Z", LastClean: "2026-11-11T14:01:07Z", Text: deliver.SlackText(e),
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("body decodes to\n%+v\nwant\n%+v", got, want)
	}
}

// Every field of the body of each kind of notice.
func TestWebhookNoticeBodyForEachKind(t *testing.T) {
	if id := wbhID("notice", "test", "", wbhNanos(ntcAt)); id != "9203ce6cde56cacc4aae75cea43e8004" {
		t.Fatalf("the id of this test is %s, want the one sha256sum gives", id)
	}
	started := time.Date(2026, 11, 13, 10, 0, 5, 0, time.UTC)
	down := ntcDown(started.Add(-2*time.Hour), started)
	for _, c := range []struct {
		n    store.Notice
		want wbhNotice
	}{
		{ntcTest(), wbhNotice{ID: "9203ce6cde56cacc4aae75cea43e8004", At: "2026-11-13T10:00:05Z", Notice: "test", Domain: "",
			Lines: []string{"request   0123456789abcdef0123456789abcdef"}}},
		{down, wbhNotice{ID: wbhID("notice", "down", "", wbhNanos(started)), At: "2026-11-13T10:00:05Z", Notice: "down", Domain: "",
			Lines: []string{"last beat 2026-11-13 08:00:05 UTC", "started   2026-11-13 10:00:05 UTC"}}},
		{ntcExpectations(), wbhNotice{ID: wbhID("notice", "expectations", "corp.test.", wbhNanos(ntcAt)), At: "2026-11-13T10:00:05Z",
			Notice: "expectations", Domain: "corp.test.",
			Lines: []string{"- www.corp.test. A 10.53.0.81", "+ mail.corp.test. A 10.53.0.82", "closed high record-set records www.corp.test. A"}}},
	} {
		c.want.Schema, c.want.Type, c.want.Text = 1, "notice", deliver.NoticeText(c.n)
		if fault := wbhBodyFault(deliver.WebhookNotice(c.n), c.want); fault != "" {
			t.Errorf("%s notice: %s", c.n.Kind, fault)
		}
	}
}

// A notice body holds at most the first 200 lines of the notice.
func TestWebhookNoticeBodyKeepsTwoHundredLines(t *testing.T) {
	n := ntcExpectations()
	n.Lines = nil
	for i := range 250 {
		n.Lines = append(n.Lines, fmt.Sprintf("+ n%d.corp.test. A 10.53.0.1", i))
	}
	var got wbhNotice
	if err := wbhDecode(deliver.WebhookNotice(n), &got); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got.Lines, n.Lines[:200]) {
		t.Errorf("%d lines, want the first 200 of 250", len(got.Lines))
	}
}

func wbhBodyID(t *testing.T, body []byte) string {
	t.Helper()
	var v struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(body, &v); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	return v.ID
}

// The id names one event or notice: a retry carries the same body, while
// another event, kind, time or domain gets another id.
func TestWebhookIDSameForRetriesOtherForOtherEvents(t *testing.T) {
	e := wbhRecordSetEvent(t, alert.EventUpdate)
	id := wbhBodyID(t, deliver.WebhookMessage(e))
	if !bytes.Equal(deliver.WebhookMessage(e), deliver.WebhookMessage(e)) {
		t.Error("two bodies of one event differ")
	}
	same := e
	same.Alert.Value, same.Alert.Lines, same.Alert.Severity = "other", nil, decide.SeverityCritical
	if got := wbhBodyID(t, deliver.WebhookMessage(same)); got != id {
		t.Errorf("the same alert, kind and time with other data: id %s, want %s", got, id)
	}
	later, other, reminder := e, e, e
	later.At = e.At.Add(time.Nanosecond)
	other.Alert.Check.Name = dlvName(t, "mail.corp.test.")
	reminder.Kind = alert.EventReminder
	for what, ev := range map[string]alert.Event{"1 ns later": later, "another check": other, "another kind": reminder} {
		if got := wbhBodyID(t, deliver.WebhookMessage(ev)); got == id {
			t.Errorf("%s: the same id %s", what, got)
		}
	}

	n := ntcExpectations()
	nid := wbhBodyID(t, deliver.WebhookNotice(n))
	if !bytes.Equal(deliver.WebhookNotice(n), deliver.WebhookNotice(n)) {
		t.Error("two bodies of one notice differ")
	}
	moreLines := n
	moreLines.Lines = append([]string{"+ cdn.corp.test. CNAME edge.dnshost.test."}, n.Lines...)
	if got := wbhBodyID(t, deliver.WebhookNotice(moreLines)); got != nid {
		t.Errorf("the same notice with other lines: id %s, want %s", got, nid)
	}
	nLater, nDomain, nKind := n, n, n
	nLater.At = n.At.Add(time.Nanosecond)
	nDomain.Domain = "shop.test."
	nKind.Kind = store.NoticeTest
	for what, x := range map[string]store.Notice{"1 ns later": nLater, "another domain": nDomain, "another kind": nKind} {
		if got := wbhBodyID(t, deliver.WebhookNotice(x)); got == nid {
			t.Errorf("notice %s: the same id %s", what, got)
		}
	}
}

// One vector computed apart from the code under test.
func TestSignFixedVector(t *testing.T) {
	key := []byte("osk-signing-key-for-a-fixed-vector-0123")
	body := []byte(`{"schema":1,"type":"notice","id":"0","at":"","notice":"test","domain":"","lines":[],"text":""}`)
	ts, sig := deliver.Sign(key, body, 1794405727)
	if ts != "1794405727" || sig != "sha256=3a2e06f7df598094a7567ed38bbb69a15449a8c91453c74d8550b4193a78055d" {
		t.Errorf("Sign = %q, %q", ts, sig)
	}
}

// wbhKeyMarker starts the key of these tests; no other text holds it.
const wbhKeyMarker = "wbhKEYsecret7"

func wbhKey() []byte {
	return []byte(wbhKeyMarker + "-" + strings.Repeat("Zq9", 10))
}

// wbhRequest is a request as the receiver got it.
type wbhRequest struct {
	method, uri string
	header      http.Header
	body        []byte
}

// wbhSigned sends body through a webhook to a TLS receiver and returns the
// request the receiver got, and the bracket of Unix seconds around the send.
func wbhSigned(t *testing.T, key, body []byte) (wbhRequest, int64, int64) {
	t.Helper()
	got := make(chan wbhRequest, 1)
	srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		data, err := io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		got <- wbhRequest{r.Method, r.URL.RequestURI(), r.Header.Clone(), data}
		w.WriteHeader(http.StatusAccepted)
	})
	hook := deliver.NewWebhook(client, "siem", srv.URL+"/hook/wbhPATH7?x=1", key, decide.SeverityLow)
	before := time.Now().Unix()
	o := hook.Send(context.Background(), body)
	after := time.Now().Unix()
	// The Date of the answer has a test of its own.
	o.Date = time.Time{}
	if !reflect.DeepEqual(o, deliver.Outcome{Status: http.StatusAccepted}) {
		t.Fatalf("Send gave %+v, want status 202", o)
	}
	select {
	case r := <-got:
		return r, before, after
	default:
		t.Fatal("the receiver got no request")
	}
	return wbhRequest{}, 0, 0
}

var wbhBody = []byte(`{"schema":1,"type":"notice","id":"0","notice":"test","lines":["request   0123"],"text":"x"}`)

// The request carries the body as given, the content type and the two
// headers of the signature in their exact form; the signature passes the
// receiver's check, and the key itself never goes out.
func TestWebhookRequestIsSignedAndVerifies(t *testing.T) {
	key := wbhKey()
	r, before, after := wbhSigned(t, key, wbhBody)
	if r.method != http.MethodPost || r.uri != "/hook/wbhPATH7?x=1" || r.header.Get("Content-Type") != "application/json" ||
		!bytes.Equal(r.body, wbhBody) {
		t.Errorf("the receiver got %s %s, Content-Type %q, body %q", r.method, r.uri, r.header.Get("Content-Type"), r.body)
	}
	ts, sig := r.header.Values("Osk-Timestamp"), r.header.Values("Osk-Signature")
	if len(ts) != 1 || len(sig) != 1 {
		t.Fatalf("Osk-Timestamp %q and Osk-Signature %q, want one value each", ts, sig)
	}
	sec, err := strconv.ParseInt(ts[0], 10, 64)
	if err != nil || !regexp.MustCompile(`^[1-9][0-9]*$`).MatchString(ts[0]) || sec < before || sec > after {
		t.Errorf("Osk-Timestamp %q, want the decimal Unix time of the send, from %d to %d", ts[0], before, after)
	}
	if !wbhSigForm.MatchString(sig[0]) {
		t.Errorf("Osk-Signature %q, want sha256= and 64 lower-case hex digits", sig[0])
	}
	if !wbhVerify(key, r.body, r.header, time.Unix(sec, 0)) || !wbhVerify(key, r.body, r.header, time.Now()) {
		t.Errorf("the request does not pass the receiver's check: %v", r.header)
	}
	for name, values := range r.header {
		switch name {
		case "Content-Type", "Content-Length", "User-Agent", "Osk-Timestamp", "Osk-Signature":
		case "Connection":
			if strings.Join(values, ",") != "close" {
				t.Errorf("Connection %q", values)
			}
		default:
			t.Errorf("the request carries the header %s: %q", name, values)
		}
		for _, v := range values {
			if leak := wbhLeak(v, key, "wbhPATH7"); leak != "" {
				t.Errorf("the header %s holds %s", name, leak)
			}
		}
	}
}

// One changed octet anywhere in the body, one more or one fewer, fails the
// receiver's check.
func TestWebhookSignatureFailsForChangedBody(t *testing.T) {
	key := wbhKey()
	r, _, _ := wbhSigned(t, key, wbhBody)
	now := time.Now()
	if !wbhVerify(key, r.body, r.header, now) {
		t.Fatal("the request as sent does not pass the check")
	}
	for i := range r.body {
		for _, flip := range []byte{0x01, 0x20, 0x80} {
			changed := bytes.Clone(r.body)
			changed[i] ^= flip
			if wbhVerify(key, changed, r.header, now) {
				t.Errorf("the body with octet %d changed by %#02x passes the check", i, flip)
			}
		}
	}
	for what, b := range map[string][]byte{"one more octet": append(bytes.Clone(r.body), ' '), "one fewer octet": r.body[:len(r.body)-1], "empty": nil} {
		if wbhVerify(key, b, r.header, now) {
			t.Errorf("the body with %s passes the check", what)
		}
	}
}

// A changed or missing header fails the receiver's check, also when the
// timestamp stays fresh or parses to the same second: the signature covers
// the timestamp exactly as sent.
func TestWebhookSignatureFailsForChangedHeaders(t *testing.T) {
	key := wbhKey()
	r, _, _ := wbhSigned(t, key, wbhBody)
	ts, sig := r.header.Get("Osk-Timestamp"), r.header.Get("Osk-Signature")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(sec, 0)
	flip := func(s string, i int) string {
		b := []byte(s)
		b[i] = "0123456789abcdef"[(strings.IndexByte("0123456789abcdef", b[i])+1)%16]
		return string(b)
	}
	cases := map[string]http.Header{
		"timestamp + 1":              wbhHeader(strconv.FormatInt(sec+1, 10), sig),
		"timestamp - 1":              wbhHeader(strconv.FormatInt(sec-1, 10), sig),
		"timestamp with a leading 0": wbhHeader("0"+ts, sig),
		"timestamp with a plus":      wbhHeader("+"+ts, sig),
		"first hex digit changed":    wbhHeader(ts, flip(sig, len("sha256="))),
		"last hex digit changed":     wbhHeader(ts, flip(sig, len(sig)-1)),
		"hex in upper case":          wbhHeader(ts, "sha256="+strings.ToUpper(strings.TrimPrefix(sig, "sha256="))),
		"no sha256= prefix":          wbhHeader(ts, strings.TrimPrefix(sig, "sha256=")),
		"no signature":               {"Osk-Timestamp": {ts}},
		"no timestamp":               {"Osk-Signature": {sig}},
		"no header":                  {},
	}
	for what, h := range cases {
		if wbhVerify(key, r.body, h, now) {
			t.Errorf("%s: the request passes the check", what)
		}
	}
}

// A request replayed more than 300 s after it was signed, or signed more than
// 300 s ahead of the receiver's clock, fails the check; up to 300 s passes.
func TestWebhookSignatureFailsWhenOld(t *testing.T) {
	key := wbhKey()
	r, _, _ := wbhSigned(t, key, wbhBody)
	sec, err := strconv.ParseInt(r.header.Get("Osk-Timestamp"), 10, 64)
	if err != nil {
		t.Fatal(err)
	}
	for d, want := range map[int64]bool{-301: false, -300: true, 0: true, 300: true, 301: false, 3600: false} {
		if got := wbhVerify(key, r.body, r.header, time.Unix(sec+d, 999e6)); got != want {
			t.Errorf("checked %d s after the signature: %v, want %v", d, got, want)
		}
	}
}

// Only the key that signed passes the check.
func TestWebhookSignatureFailsForAnotherKey(t *testing.T) {
	key := wbhKey()
	r, _, _ := wbhSigned(t, key, wbhBody)
	now := time.Now()
	changed := bytes.Clone(key)
	changed[len(changed)-1] ^= 0x01
	for what, other := range map[string][]byte{
		"one octet changed": changed,
		"one octet fewer":   key[:len(key)-1],
		"one octet more":    append(bytes.Clone(key), 'x'),
		"another key":       []byte(strings.Repeat("k", 40)),
	} {
		if wbhVerify(other, r.body, r.header, now) {
			t.Errorf("%s: the request passes the check", what)
		}
	}
}

// Each attempt is signed when it is made: the same body sent again in a
// later second carries that second, and both pass the check.
func TestWebhookSignsEachAttemptAfresh(t *testing.T) {
	key := wbhKey()
	first, before1, after1 := wbhSigned(t, key, wbhBody)
	for deadline := time.Now().Add(2 * time.Second); time.Now().Unix() <= after1 && time.Now().Before(deadline); {
		time.Sleep(10 * time.Millisecond)
	}
	second, before2, after2 := wbhSigned(t, key, wbhBody)
	ts1, _ := strconv.ParseInt(first.header.Get("Osk-Timestamp"), 10, 64)
	ts2, _ := strconv.ParseInt(second.header.Get("Osk-Timestamp"), 10, 64)
	if ts1 < before1 || ts1 > after1 || ts2 < before2 || ts2 > after2 || ts1 == ts2 {
		t.Errorf("timestamps %d (send from %d to %d) and %d (send from %d to %d): want each the second of its own send",
			ts1, before1, after1, ts2, before2, after2)
	}
	if first.header.Get("Osk-Signature") == second.header.Get("Osk-Signature") {
		t.Error("two attempts in different seconds carry the same signature")
	}
	for i, r := range []wbhRequest{first, second} {
		if !wbhVerify(key, r.body, r.header, time.Now()) {
			t.Errorf("attempt %d does not pass the check", i+1)
		}
	}
}

// A webhook is a channel by its name and minimum; its bodies are those of
// the format, and its outcome is made as for Slack: a body that is no error
// word does not reach it.
func TestWebhookChannel(t *testing.T) {
	srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Retry-After", "30")
		w.WriteHeader(http.StatusTooManyRequests)
		if _, err := io.WriteString(w, "slow down"); err != nil {
			t.Error(err)
		}
	})
	hook := deliver.NewWebhook(client, "siem-2", srv.URL+"/hook/wbhPATH7", wbhKey(), decide.SeverityMedium)
	if hook.Name() != "siem-2" || hook.MinSeverity() != decide.SeverityMedium {
		t.Errorf("Name %q, MinSeverity %v; want siem-2, medium", hook.Name(), hook.MinSeverity())
	}
	e := wbhRecordSetEvent(t, alert.EventOpen)
	if got := hook.Message(e); !bytes.Equal(got, deliver.WebhookMessage(e)) || len(got) == 0 {
		t.Errorf("Message %s, want WebhookMessage %s", got, deliver.WebhookMessage(e))
	}
	n := ntcExpectations()
	if got := hook.Notice(n); !bytes.Equal(got, deliver.WebhookNotice(n)) || len(got) == 0 {
		t.Errorf("Notice %s, want WebhookNotice %s", got, deliver.WebhookNotice(n))
	}
	o := hook.Send(context.Background(), wbhBody)
	// The Date of the answer has a test of its own.
	o.Date = time.Time{}
	if !reflect.DeepEqual(o, deliver.Outcome{Status: 429, RetryAfter: 30 * time.Second}) {
		t.Errorf("Send gave %+v, want status 429 and Retry-After 30 s", o)
	}
}

// wbhLeak names the secret that text holds in any form that fmt or a hex
// encoding gives: the URL's marker in any letter case, or the key.
func wbhLeak(text string, key []byte, marker string) string {
	lower := strings.ToLower(text)
	for what, form := range map[string]string{
		"the URL's secret":        marker,
		"the URL's secret in hex": hex.EncodeToString([]byte(marker)),
		"the key":                 string(key),
		"the start of the key":    wbhKeyMarker,
		"the key in hex":          hex.EncodeToString(key),
		"the key's start in hex":  hex.EncodeToString([]byte(wbhKeyMarker)),
		"the key as numbers":      strings.Trim(fmt.Sprint(key), "[]"),
		"the key as Go bytes":     strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", key), "[]byte{"), "}"),
	} {
		if strings.Contains(lower, strings.ToLower(form)) {
			return what
		}
	}
	return ""
}

// wbhVerbs are the print verbs of fmt; each must keep a channel's secrets.
var wbhVerbs = []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X", "%o", "%b", "%p", "%T"}

// wbhPrintable reports whether a channel can keep its secrets under verb. For
// %p of a struct value, fmt prints the fields without asking any method of
// the value, so only a pointer is checked.
func wbhPrintable(verb string, pointer bool) bool {
	return verb != "%p" || pointer
}

// Neither channel shows its URL or its key under any print verb: as a
// pointer, as a value, or in a list of channels.
func TestChannelsPrintNoSecretUnderAnyVerb(t *testing.T) {
	const marker = "wbhPRINTsecret7"
	key := wbhKey()
	client := httpclient.New(nil, nil)
	slack := deliver.NewSlack(client, "https://hooks.slack.test/services/T0/B0/"+marker, decide.SeverityLow)
	hook := deliver.NewWebhook(client, "siem", "https://hooks.siem.test/hook/"+marker+"?k="+marker, key, decide.SeverityLow)
	values := map[string]any{"*Slack": slack, "Slack": *slack, "*Webhook": hook, "Webhook": *hook,
		"[]Channel": []deliver.Channel{slack, hook}}
	for _, verb := range wbhVerbs {
		for name, v := range values {
			if !wbhPrintable(verb, name != "Slack" && name != "Webhook") {
				continue
			}
			if leak := wbhLeak(fmt.Sprintf(verb, v), key, marker); leak != "" {
				t.Errorf("Sprintf(%q) of a %s holds %s", verb, name, leak)
			}
		}
	}
	for name, v := range values {
		if leak := wbhLeak(fmt.Sprint(v)+fmt.Sprintln(v), key, marker); leak != "" {
			t.Errorf("Sprint of a %s holds %s", name, leak)
		}
	}
}

// wbhQuick is a webhook whose every send gives up after one second, so that
// a silent receiver costs a test one second, not the client's timeout.
type wbhQuick struct{ *deliver.Webhook }

func (q wbhQuick) Send(_ context.Context, body []byte) deliver.Outcome {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return q.Webhook.Send(ctx, body)
}

// The URL of a webhook and its key are secrets. Whatever goes wrong, neither
// reaches an error, a reason, a line, the printed form of a channel or an
// attempt, or a file of the state folder.
func TestWebhookKeyAndURLNeverLeave(t *testing.T) {
	const marker = "wbhURLsecret7"
	const urlWord = "wbhurlwordsecret"
	key := wbhKey()
	release := make(chan struct{})
	srv, trusting := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		answer := func(status int, body string) {
			w.WriteHeader(status)
			if _, err := io.WriteString(w, body); err != nil {
				t.Error(err)
			}
		}
		switch strings.Split(r.URL.Path, "/")[1] {
		case "redirect":
			w.Header().Set("Location", "https://"+r.Host+"/elsewhere/"+marker)
			w.WriteHeader(http.StatusFound)
		case "echo":
			answer(http.StatusBadRequest, "unknown hook "+r.URL.RequestURI())
		case "echokey":
			answer(http.StatusUnauthorized, "bad signature: want key "+string(key)+" "+hex.EncodeToString(key))
		case "urlword":
			answer(http.StatusBadRequest, urlWord)
		case "payload":
			answer(http.StatusBadRequest, "invalid_signature")
		case "busy":
			answer(http.StatusServiceUnavailable, marker)
		case "silent":
			select {
			case <-r.Context().Done():
			case <-release:
			}
		case "ok":
			answer(http.StatusOK, "ok "+marker)
		}
	})
	t.Cleanup(func() { close(release) })
	addr := strings.TrimPrefix(srv.URL, "https://")
	host, err := httpclient.HostOf(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	untrusting := httpclient.New([]string{host}, nil)
	closed := dlvClosedPort(t)
	refusing := httpclient.New([]string{"127.0.0.1:" + closed}, nil)
	const badURL = `no answer "not an https URL with a host and no user name"`
	cases := []struct {
		name   string
		c      *httpclient.Client
		url    string
		quick  bool
		reason string
		state  store.RowState
	}{
		{"not https", trusting, "http://" + addr + "/ok/" + marker, false, badURL, store.RowPending},
		{"user info", trusting, "https://u:" + marker + "@" + addr + "/ok/" + marker, false, badURL, store.RowPending},
		{"bad escape", trusting, "https://" + addr + "/ok/" + marker + "%zz", false, badURL, store.RowPending},
		{"control octet", trusting, "https://" + addr + "/ok/" + marker + "\n", false, badURL, store.RowPending},
		{"host not listed", trusting, "https://127.0.0.9:" + strings.Split(addr, ":")[1] + "/ok/" + marker, false,
			`no answer "host not allowed"`, store.RowPending},
		{"refused connection", refusing, "https://127.0.0.1:" + closed + "/ok/" + marker, false,
			`no answer "network: cannot connect"`, store.RowPending},
		{"timeout", trusting, "https://" + addr + "/silent/" + marker, true, `no answer "timeout"`, store.RowPending},
		{"untrusted certificate", untrusting, "https://" + addr + "/ok/" + marker, false,
			`no answer "network: certificate not trusted"`, store.RowPending},
		{"redirect", trusting, "https://" + addr + "/redirect/" + marker, false, "status 302", store.RowGivenUp},
		{"4xx that repeats the path", trusting, "https://" + addr + "/echo/" + marker + "?k=" + marker, false, "status 400", store.RowGivenUp},
		{"4xx that repeats the key", trusting, "https://" + addr + "/echokey/" + marker, false, "status 401", store.RowGivenUp},
		{"4xx with an error word of the URL", trusting, "https://" + addr + "/urlword/" + urlWord, false, "status 400", store.RowGivenUp},
		{"4xx with an error word", trusting, "https://" + addr + "/payload/" + marker, false, "status 400", store.RowGivenUp},
		{"5xx", trusting, "https://" + addr + "/busy/" + marker, false, "status 503", store.RowPending},
		{"sent", trusting, "https://" + addr + "/ok/" + marker, false, "", store.RowSent},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			secret := marker
			if strings.Contains(c.url, urlWord) {
				secret = urlWord
			}
			// The store is closed once, before its files are read; the
			// cleanup closes it only when the test stops before that.
			dir := dlvPrivateDir(t)
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
			hook := deliver.NewWebhook(c.c, "siem", c.url, key, decide.SeverityLow)
			var ch deliver.Channel = hook
			if c.quick {
				ch = wbhQuick{hook}
			}
			e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
			if err := s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{ch})); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), httpclient.Timeout+5*time.Second)
			defer cancel()
			start := time.Now()
			attempts, err := deliver.Pass(ctx, s, []deliver.Channel{ch}, dlvLater)
			if err != nil {
				t.Fatal(err)
			}
			if c.quick && time.Since(start) > 5*time.Second {
				t.Errorf("Send took %v after its context ended at 1 s", time.Since(start))
			}
			if len(attempts) != 1 {
				t.Fatalf("%d attempts, want 1", len(attempts))
			}
			a := attempts[0]
			if a.Done.Reason != c.reason || a.Done.State != c.state {
				t.Errorf("reason %q and state %v, want %q and %v", strings.ReplaceAll(a.Done.Reason, secret, "[marker]"), a.Done.State, c.reason, c.state)
			}
			texts := map[string]string{"error": a.Outcome.Err, "body": string(a.Outcome.Body), "reason": a.Done.Reason, "line": a.Line()}
			for _, verb := range wbhVerbs {
				texts["attempt "+verb] = fmt.Sprintf(verb, a)
				texts["channel "+verb] = fmt.Sprintf(verb, hook)
				texts["channel list "+verb] = fmt.Sprintf(verb, []deliver.Channel{hook})
				if wbhPrintable(verb, false) {
					texts["channel value "+verb] = fmt.Sprintf(verb, *hook)
				}
			}
			for what, text := range texts {
				if leak := wbhLeak(text, key, secret); leak != "" {
					t.Errorf("the %s holds %s", what, leak)
				}
			}
			closed = true
			if err := s.Close(); err != nil {
				t.Fatal(err)
			}
			if !dlvFolderHolds(t, dir, e.Label()) {
				t.Errorf("no file of the store holds the label %q, so the search for the secrets saw no row", e.Label())
			}
			wbhFolderNoLeak(t, dir, key, secret)
		})
	}
}

// wbhFolderNoLeak fails the test when a file of the folder holds a secret.
func wbhFolderNoLeak(t *testing.T, dir string, key []byte, marker string) {
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
		if leak := wbhLeak(string(data), key, marker); leak != "" {
			t.Errorf("%s holds %s", f.Name(), leak)
		}
	}
}

// A key of lower-case letters has the form of an error word, and the URL
// does not hold it. A receiver that answers with the key as its whole body
// still gets it into no reason, line or file of the state folder.
func TestWebhookKeyEchoedAsErrorWordReachesNoReason(t *testing.T) {
	key := []byte(strings.Repeat("echoedkey", 4) + "abcd") // 40 octets of a to z
	srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		if _, err := w.Write(key); err != nil {
			t.Error(err)
		}
	})
	dir := dlvPrivateDir(t)
	s, err := store.Open(dir)
	if err != nil {
		t.Fatal(err)
	}
	hook := deliver.NewWebhook(client, "siem", srv.URL+"/hook/wbhPATH7", key, decide.SeverityLow)
	e := dlvRecordSetEvent(t, alert.EventOpen, decide.SeverityHigh, dlvLines(t))
	var attempts []deliver.Attempt
	err = s.Apply(e.Alert.Check, false, dlvLater, deliver.Writes([]alert.Event{e}, []deliver.Channel{hook}))
	if err == nil {
		attempts, err = deliver.Pass(context.Background(), s, []deliver.Channel{hook}, dlvLater)
	}
	if err := errors.Join(err, s.Close()); err != nil || len(attempts) != 1 {
		t.Fatalf("Apply, Pass and Close: %d attempts, %v; want 1 and no error", len(attempts), err)
	}
	a := attempts[0]
	if a.Done.Reason != "status 400" {
		t.Errorf("reason %q, want status 400", strings.ReplaceAll(a.Done.Reason, string(key), "[key]"))
	}
	for what, text := range map[string]string{"body": string(a.Outcome.Body), "reason": a.Done.Reason, "line": a.Line()} {
		if strings.Contains(text, string(key)) {
			t.Errorf("the %s holds the key", what)
		}
	}
	if dlvFolderHolds(t, dir, string(key)) {
		t.Error("a file of the store holds the key")
	}
	if !dlvFolderHolds(t, dir, e.Label()) {
		t.Error("no file of the store holds the label of the row, so the search saw no row")
	}
}

// Each channel's rows go out in its own time: a receiver that never answers
// holds up only the rows of its own channel, whichever channel that is and
// wherever it stands in the channel order.
func TestHungChannelDelaysNoOther(t *testing.T) {
	for _, hung := range []string{"webhook", "slack"} {
		t.Run(hung+" hangs", func(t *testing.T) {
			t.Parallel()
			release := make(chan struct{})
			arrived := make(chan time.Time, 16)
			srv, client := dlvServer(t, func(w http.ResponseWriter, r *http.Request) {
				if strings.HasPrefix(r.URL.Path, "/hang/") {
					select {
					case <-r.Context().Done():
					case <-release:
					}
					return
				}
				arrived <- time.Now()
			})
			t.Cleanup(func() { close(release) })
			hookPath, slackPath := "/ok/siem", "/hang/slack"
			if hung == "webhook" {
				hookPath, slackPath = "/hang/siem", "/ok/slack"
			}
			hook := deliver.NewWebhook(client, "siem", srv.URL+hookPath, wbhKey(), decide.SeverityLow)
			slack := deliver.NewSlack(client, srv.URL+slackPath, decide.SeverityLow)
			channels := []deliver.Channel{hook, slack}
			if hung == "slack" {
				channels = []deliver.Channel{slack, hook}
			}
			s, _ := dlvStore(t)
			now := time.Now()
			for _, name := range []string{"a.corp.test.", "b.corp.test."} {
				e := dlvOpen(t, name, decide.SeverityHigh, decide.SeverityHigh)
				if err := s.Apply(e.Alert.Check, false, now, deliver.Writes([]alert.Event{e}, channels)); err != nil {
					t.Fatal(err)
				}
			}
			n := store.Notice{Kind: store.NoticeTest, Lines: []string{"request   " + strings.Repeat("0a", 16)}, At: now}
			if err := s.Notify(n, deliver.NoticeWrites(n, channels)); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
			defer cancel()
			begin := time.Now()
			attempts, err := deliver.Pass(ctx, s, channels, now.Add(time.Minute))
			took := time.Since(begin)
			if !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("Pass: error %v, want the end of its context from the hung channel", err)
			}
			if took > 8*time.Second {
				t.Errorf("Pass took %v; its context ended after 4 s", took)
			}
			var late []time.Duration
			for len(arrived) > 0 {
				if d := (<-arrived).Sub(begin); d > 2*time.Second {
					late = append(late, d)
				}
			}
			var sent []string
			for _, a := range attempts {
				if a.Channel == channels[0].Name() {
					t.Errorf("the hung channel has the attempt %q", a.Line())
				} else if a.Done.State == store.RowSent {
					sent = append(sent, a.Row.Label)
				}
			}
			if len(sent) != 3 || len(late) != 0 {
				t.Errorf("%s sent %q, %d of them later than 2 s (%v); want 3 rows within 2 s while %s hangs",
					channels[1].Name(), sent, len(late), late, hung)
			}
		})
	}
}
