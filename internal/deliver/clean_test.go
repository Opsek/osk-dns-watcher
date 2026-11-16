package deliver_test

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/alert"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/deliver"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// dlvUnit is the unit that Clean makes of each octet: \DDD for an octet
// outside 0x20-0x7E and for the backtick, the three escapes of Slack for
// & < >, and every other octet as it is.
var dlvUnit = func() (units [256]string) {
	for c := range 256 {
		switch {
		case c < 0x20 || c > 0x7E || c == '`':
			units[c] = fmt.Sprintf(`\%03d`, c)
		case c == '&':
			units[c] = "&amp;"
		case c == '<':
			units[c] = "&lt;"
		case c == '>':
			units[c] = "&gt;"
		default:
			units[c] = string(rune(c))
		}
	}
	return units
}()

// dlvClean is what Clean(s, limit) must give: every unit when they fit in M,
// else the longest run of whole units that fits in M - 6, then " [cut]".
func dlvClean(s string, limit int) string {
	m := max(limit, 16)
	total := 0
	for i := 0; i < len(s); i++ {
		total += len(dlvUnit[s[i]])
	}
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		u := dlvUnit[s[i]]
		if total > m && b.Len()+len(u) > m-6 {
			return b.String() + " [cut]"
		}
		b.WriteString(u)
	}
	return b.String()
}

// dlvCleanFault checks r = Clean(s, limit) and describes the first fault, or
// returns "".
func dlvCleanFault(s string, limit int, r string) string {
	m := max(limit, 16)
	if len(r) > m {
		return fmt.Sprintf("%d octets, more than %d", len(r), m)
	}
	for i := 0; i < len(r); i++ {
		switch c := r[i]; {
		case c < 0x20 || c > 0x7E || c == '`' || c == '<' || c == '>':
			return fmt.Sprintf("octet %#02x at %d", c, i)
		case c == '&' && !strings.HasPrefix(r[i:], "&amp;") && !strings.HasPrefix(r[i:], "&lt;") &&
			!strings.HasPrefix(r[i:], "&gt;"):
			return fmt.Sprintf("an & at %d that starts no escape", i)
		}
	}
	if dlvPlain(s) && len(s) <= m && r != s {
		return "plain text was changed"
	}
	if want := dlvClean(s, limit); r != want {
		return fmt.Sprintf("got %q, want %q", r, want)
	}
	return ""
}

// dlvPlain reports whether s is printable ASCII without ` < > &, which Clean
// keeps as it is.
func dlvPlain(s string) bool {
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c > 0x7E || strings.IndexByte("`<>&", c) >= 0 {
			return false
		}
	}
	return true
}

// dlvPieces are fragments that try to leave a code span or make Slack format,
// link or mention, and octets that are not text.
var dlvPieces = []string{
	"`", "```", "<!channel>", "<!here>", "@here", "@channel", "<@U123>", "<#C123>", "<https://x|y>",
	"<mailto:a@b|c>", "&", "&amp;", "&lt;", "*", "_", "~", "*_~", ">", "> quote", "\r", "\n", "\r\n",
	"\x00", "\x1b[31m", "\x7f", "é", "日本", "\u202e", "\xff", "\xc3", "\x80", `\`, `\096`, " ", "|",
	"corp.test.", "a", "0", ":", "%", "\t",
}

// dlvHostileText returns up to n octets: pieces, random octets or plain text.
func dlvHostileText(rng *rand.Rand, n int) string {
	size := rng.IntN(n + 1)
	var b strings.Builder
	for b.Len() < size {
		switch rng.IntN(4) {
		case 0:
			b.WriteByte(byte(rng.IntN(256)))
		case 1:
			b.WriteString(strings.Repeat("x", 1+rng.IntN(40)))
		default:
			b.WriteString(dlvPieces[rng.IntN(len(dlvPieces))])
		}
	}
	return b.String()[:size]
}

// dlvSize returns a length for a hostile text: mostly short, sometimes far
// beyond every cap of a message.
func dlvSize(rng *rand.Rand) int {
	if rng.IntN(20) == 0 {
		return 10000
	}
	return []int{0, 20, 50, 400}[rng.IntN(4)]
}

// dlvHostileName returns a name whose labels hold any octets, or the root.
func dlvHostileName(rng *rand.Rand) dnswire.Name {
	if rng.IntN(10) == 0 {
		return dnswire.Name{}
	}
	var labels []string
	for range 1 + rng.IntN(5) {
		l := dlvHostileText(rng, 63)
		if l == "" {
			l = "a"
		}
		labels = append(labels, l)
	}
	for {
		n, err := dnswire.NameFromLabels(labels)
		if err == nil {
			return n
		}
		labels = labels[1:]
	}
}

// dlvHostileAddr returns no address, a plain one, or an IPv6 address with a
// zone that holds any octets.
func dlvHostileAddr(rng *rand.Rand) netip.AddrPort {
	switch rng.IntN(4) {
	case 0:
		return netip.AddrPort{}
	case 1:
		return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 53, 0, byte(rng.IntN(256))}), 53)
	case 2:
		return netip.MustParseAddrPort("[fd53::12]:53")
	default:
		zone := dlvHostileText(rng, 40)
		if zone == "" {
			zone = "`"
		}
		return netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone(zone), uint16(rng.IntN(65536)))
	}
}

// dlvHostileEvent returns an event of any kind and rule whose text fields
// come from the network or the file, and are hostile.
func dlvHostileEvent(rng *rand.Rand) alert.Event {
	kinds := []alert.EventKind{alert.EventOpen, alert.EventUpdate, alert.EventEscalate, alert.EventReminder, alert.EventResolve}
	rules := []decide.Rule{decide.RuleNameServers, decide.RuleRecordSet, decide.RuleZone, decide.RuleNotCovered, decide.RuleInvalidFile}
	kindsOfCheck := []obs.Kind{0, obs.KindDelegation, obs.KindDS, obs.KindRecords, obs.KindSerial}
	sev := decide.Severity(1 + rng.IntN(4))
	a := alert.Alert{
		ID:       rng.Int64N(1000),
		Open:     rng.IntN(2) == 0,
		Rule:     rules[rng.IntN(len(rules))],
		Severity: sev,
		Peak:     sev + decide.Severity(rng.IntN(int(decide.SeverityCritical-sev)+1)),
		Check: obs.Key{
			Kind:   kindsOfCheck[rng.IntN(len(kindsOfCheck))],
			Domain: dlvHostileName(rng),
			Name:   dlvHostileName(rng),
			Type:   dnswire.Type(rng.IntN(65536)),
		},
		Expected: dlvHostileText(rng, dlvSize(rng)),
		Value:    dlvHostileText(rng, dlvSize(rng)),
		Opened:   dlvRandomTime(rng),
		Noticed:  dlvRandomTime(rng),
	}
	if rng.IntN(3) > 0 {
		a.LastClean = dlvRandomTime(rng)
	}
	for range rng.IntN(41) {
		a.Lines = append(a.Lines, alert.Line{
			Server:   obs.Server{Name: dlvHostileName(rng), Addr: dlvHostileAddr(rng)},
			Text:     dlvHostileText(rng, dlvSize(rng)),
			TTL:      rng.Uint32(),
			Received: dlvRandomTime(rng),
		})
	}
	return alert.Event{
		Kind:  kinds[rng.IntN(len(kinds))],
		Alert: a,
		Was:   decide.Severity(1 + rng.IntN(4)),
		At:    dlvRandomTime(rng),
	}
}

// dlvRandomTime returns a time between 2000 and 2100, in UTC or another zone.
func dlvRandomTime(rng *rand.Rand) time.Time {
	t := time.Unix(946684800+rng.Int64N(3155760000), rng.Int64N(1e9))
	if rng.IntN(2) == 0 {
		return t.In(time.FixedZone("", (rng.IntN(27)-12)*3600))
	}
	return t.UTC()
}

func TestCleanProperty(t *testing.T) {
	seed := uint64(time.Now().UnixNano())
	t.Logf("seed %d", seed)
	rng := rand.New(rand.NewPCG(seed, 5))
	for i := range 5000 {
		s := dlvHostileText(rng, dlvSize(rng))
		if i%5 == 0 {
			s = strings.Repeat("plain text ", rng.IntN(30))
		}
		m := []int{rng.IntN(400) - 20, 0, 15, 16, 17, 100, 160, 1 << 30}[rng.IntN(8)]
		if fault := dlvCleanFault(s, m, deliver.Clean(s, m)); fault != "" {
			t.Fatalf("seed %d: Clean(%q, %d): %s", seed, s, m, fault)
		}
	}
}

func TestCleanCases(t *testing.T) {
	cases := []struct {
		s    string
		max  int
		want string
	}{
		{"", 100, ""},
		{"ns1.corp.test. | ns2.corp.test.", 100, "ns1.corp.test. | ns2.corp.test."},
		{" ~", 100, " ~"},
		{"a`b", 100, `a\096b`},
		{"```", 100, `\096\096\096`},
		{"<!channel>", 100, "&lt;!channel&gt;"},
		{"<@U123>", 100, "&lt;@U123&gt;"},
		{"<https://x|y>", 100, "&lt;https://x|y&gt;"},
		{"a&b", 100, "a&amp;b"},
		{"&amp;", 100, "&amp;amp;"},
		{"*_~ @here", 100, "*_~ @here"},
		{"\r\n\x00\t\x1f\x7f", 100, `\013\010\000\009\031\127`},
		{"é", 100, `\195\169`},
		{"\xff\xc3", 100, `\255\195`},
		{`\096`, 100, `\096`},
		{strings.Repeat("a", 16), 16, strings.Repeat("a", 16)},
		{strings.Repeat("a", 16), 0, strings.Repeat("a", 16)},
		{strings.Repeat("a", 17), 16, "aaaaaaaaaa [cut]"},
		{strings.Repeat("a", 17), -5, "aaaaaaaaaa [cut]"},
		// A cut never splits a unit, so the result may be shorter than the cap.
		{"aaaaaaaa`zzzzzzzzzz", 16, "aaaaaaaa [cut]"},
		{"aaaaaaaaa&zzzzzzzz", 16, "aaaaaaaaa [cut]"},
		{"aaaaaa<\nzzzzzzzzzz", 16, "aaaaaa&lt; [cut]"},
		{strings.Repeat("x", 10000), 100, strings.Repeat("x", 94) + " [cut]"},
	}
	for _, c := range cases {
		if got := deliver.Clean(c.s, c.max); got != c.want {
			t.Errorf("Clean(%q, %d) = %q, want %q", c.s, c.max, got, c.want)
		}
	}
}

func FuzzClean(f *testing.F) {
	for _, p := range dlvPieces {
		f.Add(p, 16)
		f.Add(strings.Repeat(p, 30), 100)
	}
	f.Add(strings.Repeat("a", 17), -1)
	f.Add("aaaaaaaa`zzzzzzzzzz", 16)
	f.Fuzz(func(t *testing.T, s string, m int) {
		if fault := dlvCleanFault(s, m, deliver.Clean(s, m)); fault != "" {
			t.Fatalf("Clean(%q, %d): %s", s, m, fault)
		}
	})
}

func FuzzSlackMessage(f *testing.F) {
	f.Add(uint8(0), uint8(0), uint8(3), uint8(1), "corp.test.", "www.corp.test.", "10.53.0.99", "10.53.0.81", "", uint8(2), uint32(300))
	f.Add(uint8(4), uint8(4), uint8(1), uint8(2), "<!channel>", "`a`.<@U123>", "a\nb\r\x00", "<https://x|y>", "*_~&", uint8(40), uint32(0))
	f.Add(uint8(2), uint8(3), uint8(0), uint8(3), "\xff\xc3", "é.日本", strings.Repeat("`", 300), "&&&", "\n\n\n", uint8(7), uint32(4294967295))
	f.Fuzz(func(t *testing.T, kind, rule, sev, was uint8, domain, name, text, expected, value string, lines uint8, ttl uint32) {
		kinds := []alert.EventKind{alert.EventOpen, alert.EventUpdate, alert.EventEscalate, alert.EventReminder, alert.EventResolve}
		rules := []decide.Rule{decide.RuleNameServers, decide.RuleRecordSet, decide.RuleZone, decide.RuleNotCovered, decide.RuleInvalidFile}
		a := alert.Alert{
			Rule:     rules[int(rule)%len(rules)],
			Severity: decide.Severity(1 + sev%4),
			Peak:     decide.SeverityCritical,
			Check:    obs.Key{Kind: obs.KindRecords, Domain: dlvFuzzName(domain), Name: dlvFuzzName(name), Type: dnswire.Type(ttl)},
			Expected: expected,
			Value:    value,
			Opened:   time.Unix(int64(ttl), 0),
		}
		if ttl%2 == 0 {
			a.LastClean = time.Unix(int64(ttl/2), 0)
		}
		for i := range int(lines) % 41 {
			addr := netip.AddrPortFrom(netip.MustParseAddr("fe80::1").WithZone(text), uint16(i))
			if i%2 == 0 {
				addr = netip.AddrPort{}
			}
			a.Lines = append(a.Lines, alert.Line{
				Server: obs.Server{Name: dlvFuzzName(name), Addr: addr},
				Text:   text,
				TTL:    ttl + uint32(i),
			})
		}
		e := alert.Event{Kind: kinds[int(kind)%len(kinds)], Alert: a, Was: decide.Severity(1 + was%4), At: time.Unix(int64(ttl)+1, 0)}
		if fault := dlvMessageFault(e); fault != "" {
			t.Fatalf("%+v: %s", e, fault)
		}
	})
}

// dlvFuzzName makes a name from any text: its labels are the parts between
// dots, as far as they make a valid name.
func dlvFuzzName(s string) dnswire.Name {
	var labels []string
	for _, l := range strings.Split(s, ".") {
		if l != "" && len(l) <= 63 {
			labels = append(labels, l)
		}
	}
	for {
		n, err := dnswire.NameFromLabels(labels)
		if err == nil {
			return n
		}
		labels = labels[1:]
	}
}
