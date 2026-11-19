package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
)

// cfgFile names every parsed text. It is absolute, so the relative paths in
// a config are read against cfgDir and the expected paths are fixed.
const (
	cfgFile = "/etc/osk-dns-watcher/config.json"
	cfgDir  = "/etc/osk-dns-watcher"
)

// cfgSeed fixes every generated input, so that a failure can be run again.
const cfgSeed = 7

// The members of the smallest valid config. cfgDoc puts "{" alone on line 1
// and each member on its own line, so these are on lines 2, 3 and 4, and a
// member after them starts on line 5.
const (
	cfgState   = `"state": "/var/lib/osk-dns-watcher"`
	cfgDomains = `"domains": [{"name": "corp.test.", "expect": "/etc/osk-dns-watcher/corp.test.expect"}]`
	cfgSlack   = `"slack": {"url": {"env": "OSK_SLACK_URL"}}`
)

// Texts that several tests expect.
const (
	cfgWantSecret  = `want {"env": "<NAME>"} or {"file": "<path>"}`
	cfgWantSev     = "want low, medium, high or critical"
	cfgWantRemind  = "want 0s, or 1h0m0s to 720h0m0s"
	cfgWantHook    = "want a name of 1 to 32 octets of a-z, 0-9 and -"
	cfgWantChannel = "want at least one channel: slack or a webhook"
	cfgWantURL     = "the value is not an https URL with a host and no user name"
	// The value is not repeated: a person may paste the URL there by mistake.
	cfgWantEnvName = "the name of an environment variable holds only A to Z, 0 to 9 and _, and does not start with a digit"
)

func cfgDoc(members ...string) string {
	return "{\n" + strings.Join(members, ",\n") + "\n}\n"
}

// cfgWith is the smallest valid config with one more member, on line 5.
func cfgWith(member string) string {
	return cfgDoc(cfgState, cfgDomains, cfgSlack, member)
}

// cfgHook is a valid webhook entry on one line.
func cfgHook(name string) string {
	return fmt.Sprintf(`{"name": %q, "url": {"env": "HOOK_URL"}, "key": {"env": "HOOK_KEY"}}`, name)
}

func cfgHooks(names ...string) string {
	entries := make([]string, len(names))
	for i, n := range names {
		entries[i] = cfgHook(n)
	}
	return `"webhooks": [` + strings.Join(entries, ", ") + `]`
}

// cfgQuote writes s as a JSON string, so a temporary path can go into a
// config whatever octets it holds.
func cfgQuote(t testing.TB, s string) string {
	t.Helper()
	b, err := json.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// cfgList is a JSON list of n strings made by item.
func cfgList(n int, item func(i int) string) string {
	items := make([]string, n)
	for i := range items {
		items[i] = fmt.Sprintf("%q", item(i))
	}
	return "[" + strings.Join(items, ", ") + "]"
}

func cfgName(t testing.TB, s string) dnswire.Name {
	t.Helper()
	n, err := dnswire.ParseName(s)
	if err != nil {
		t.Fatalf("name %q: %v", s, err)
	}
	return n
}

// cfgBadName is the problem text for a name that dnswire refuses, with the
// error text that dnswire itself gives.
func cfgBadName(t testing.TB, s string) string {
	t.Helper()
	_, err := dnswire.ParseName(s)
	if err == nil {
		t.Fatalf("name %q is valid", s)
	}
	return fmt.Sprintf("bad name %q: %v", s, err)
}

func cfgBelow(d time.Duration) string {
	return fmt.Sprintf("%v is below the floor of %v", d, schedule.Floor)
}

func cfgAbove(d, ceiling time.Duration) string {
	return fmt.Sprintf("%v is above %v", d, ceiling)
}

func cfgWrite(t testing.TB, path, data string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}

// cfgEnv is a lookup that knows only vars, so that no test depends on the
// environment it runs in.
func cfgEnv(vars map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		v, ok := vars[name]
		return v, ok
	}
}

// cfgShort keeps failure messages readable when the text is large.
func cfgShort(s string) string {
	if len(s) > 600 {
		return fmt.Sprintf("%q... (%d octets)", s[:600], len(s))
	}
	return fmt.Sprintf("%q", s)
}

// cfgP is a problem that a test expects: its line, its path, and the texts
// that the format allows for it (most often one).
type cfgP struct {
	line  int
	path  string
	texts []string
}

func (p cfgP) String() string {
	return fmt.Sprintf("line %d, path %q, text %q", p.line, p.path, p.texts)
}

func (p cfgP) matches(file string, g Problem) bool {
	return g.File == file && g.Line == p.line && g.Path == p.path && slices.Contains(p.texts, g.Text)
}

func cfgAt(line int, path, text string) cfgP {
	return cfgP{line: line, path: path, texts: []string{text}}
}

func cfgJoin(obj, key string) string {
	if obj == "" {
		return key
	}
	return obj + "." + key
}

// cfgUnknown and cfgTwice are the problems of a key of the object at obj,
// at the line where the key starts. Their text names the key, so their path
// is that of the object.
func cfgUnknown(line int, obj, key string) cfgP {
	return cfgAt(line, obj, fmt.Sprintf("unknown key %q", key))
}

func cfgTwice(line int, obj, key string) cfgP {
	return cfgAt(line, obj, fmt.Sprintf("key %q is given twice", key))
}

// cfgRequired is the problem of a missing key: at the line of the "{" of
// its object, and its own path, because the text does not name it.
func cfgRequired(objLine int, obj, key string) cfgP {
	return cfgAt(objLine, cfgJoin(obj, key), "is required")
}

// cfgMatch gives the differences between the problems got and want, in any
// order. Each problem must name file.
func cfgMatch(file string, got []Problem, want []cfgP) []string {
	used := make([]bool, len(got))
	var diffs []string
	for _, w := range want {
		found := false
		for i, g := range got {
			if !used[i] && w.matches(file, g) {
				used[i], found = true, true
				break
			}
		}
		if !found {
			diffs = append(diffs, "missing: "+w.String())
		}
	}
	for i, g := range got {
		if !used[i] {
			diffs = append(diffs, fmt.Sprintf("not expected: %+v", g))
		}
	}
	return diffs
}

// cfgRefused parses text and fails unless it gives no config and exactly
// the problems want.
func cfgRefused(t *testing.T, text string, want ...cfgP) {
	t.Helper()
	c, problems := Parse(cfgFile, []byte(text))
	if c != nil {
		t.Errorf("Parse(%s) gave a config; want none", cfgShort(text))
	}
	if diffs := cfgMatch(cfgFile, problems, want); len(diffs) > 0 {
		t.Errorf("Parse(%s):\n%s", cfgShort(text), strings.Join(diffs, "\n"))
	}
}

// cfgOK parses text that must be valid.
func cfgOK(t *testing.T, text string) *Config {
	t.Helper()
	c, problems := Parse(cfgFile, []byte(text))
	if len(problems) > 0 {
		t.Fatalf("Parse(%s): %v", cfgShort(text), problems)
	}
	if c == nil {
		t.Fatalf("Parse(%s) gave neither a config nor a problem", cfgShort(text))
	}
	return c
}

// cfgSameList is slices.Equal that also tells nil from empty: an empty list
// of a config is nil.
func cfgSameList[T comparable](a, b []T) bool {
	return (a == nil) == (b == nil) && slices.Equal(a, b)
}

// cfgDiff compares two configs field by field. Names compare by Equal,
// because the case of a name as written is not part of the format.
func cfgDiff(got, want *Config) []string {
	var diffs []string
	add := func(field string, g, w any) {
		diffs = append(diffs, fmt.Sprintf("%s = %+v; want %+v", field, g, w))
	}
	if got.Path != want.Path {
		add("Path", got.Path, want.Path)
	}
	if got.State != want.State {
		add("State", got.State, want.State)
	}
	if !slices.EqualFunc(got.Domains, want.Domains, cfgSameDomain) {
		add("Domains", got.Domains, want.Domains)
	}
	if got.Intervals != want.Intervals {
		add("Intervals", got.Intervals, want.Intervals)
	}
	if (got.Slack == nil) != (want.Slack == nil) || got.Slack != nil && *got.Slack != *want.Slack {
		add("Slack", got.Slack, want.Slack)
	}
	if !cfgSameList(got.Webhooks, want.Webhooks) {
		add("Webhooks", got.Webhooks, want.Webhooks)
	}
	if (got.Heartbeat == nil) != (want.Heartbeat == nil) || got.Heartbeat != nil && *got.Heartbeat != *want.Heartbeat {
		add("Heartbeat", got.Heartbeat, want.Heartbeat)
	}
	if got.HistoryDays != want.HistoryDays {
		add("HistoryDays", got.HistoryDays, want.HistoryDays)
	}
	if got.Remind != want.Remind {
		add("Remind", got.Remind, want.Remind)
	}
	if !cfgSameList(got.RootServers, want.RootServers) {
		add("RootServers", got.RootServers, want.RootServers)
	}
	if !cfgSameList(got.ExtraRanges, want.ExtraRanges) {
		add("ExtraRanges", got.ExtraRanges, want.ExtraRanges)
	}
	return diffs
}

func cfgSameDomain(a, b Domain) bool {
	return a.Name.Equal(b.Name) && a.Expect == b.Expect && a.Line == b.Line &&
		(a.Fast == nil) == (b.Fast == nil) && slices.EqualFunc(a.Fast, b.Fast, dnswire.Name.Equal)
}

func TestProblemStringLeavesOutEmptyLineAndPath(t *testing.T) {
	for _, c := range []struct {
		p    Problem
		want string
	}{
		{Problem{File: "config.json", Line: 3, Path: "webhooks[0].key.file", Text: "want a path"},
			"config.json:3: webhooks[0].key.file: want a path"},
		{Problem{File: "config.json", Line: 1, Text: cfgWantChannel},
			"config.json:1: " + cfgWantChannel},
		{Problem{File: "/etc/osk-dns-watcher/config.json", Text: "cannot be read: open /etc/osk-dns-watcher/config.json: permission denied"},
			"/etc/osk-dns-watcher/config.json: cannot be read: open /etc/osk-dns-watcher/config.json: permission denied"},
		{Problem{File: "config.json", Path: "slack.url", Text: "the environment variable OSK_SLACK_URL is not set or empty"},
			"config.json: slack.url: the environment variable OSK_SLACK_URL is not set or empty"},
	} {
		if got := c.p.String(); got != c.want {
			t.Errorf("%+v.String() = %q; want %q", c.p, got, c.want)
		}
	}
}

// cfgExample is the example config of the format: two domains, Slack, one
// webhook and a heartbeat.
const cfgExample = `{"state": "/var/lib/osk-dns-watcher",
 "domains": [{"name": "example.com.", "expect": "example.com.expect", "fast": ["login.example.com."]},
             {"name": "example.org.", "expect": "example.org.expect"}],
 "slack": {"url": {"env": "OSK_SLACK_URL"}, "min_severity": "medium"},
 "webhooks": [{"name": "siem", "url": {"file": "/run/secrets/siem_url"}, "key": {"file": "/run/secrets/siem_key"}, "min_severity": "high"}],
 "heartbeat": {"url": {"env": "OSK_HEARTBEAT_URL"}, "interval": "60s"},
 "intervals": {"serial": "15s", "parent": "60s", "fast": "60s", "other": "5m"},
 "history_days": 90, "remind": "0s"}
`

func TestExampleConfigParsesToTheValuesWritten(t *testing.T) {
	c := cfgOK(t, cfgExample)
	want := &Config{
		Path:  cfgFile,
		State: "/var/lib/osk-dns-watcher",
		Domains: []Domain{
			{Name: cfgName(t, "example.com."), Expect: "/etc/osk-dns-watcher/example.com.expect",
				Fast: []dnswire.Name{cfgName(t, "login.example.com.")}, Line: 2},
			{Name: cfgName(t, "example.org."), Expect: "/etc/osk-dns-watcher/example.org.expect", Line: 3},
		},
		Intervals: schedule.Intervals{Serial: 15 * time.Second, Parent: time.Minute, Fast: time.Minute, Other: 5 * time.Minute},
		Slack:     &Slack{URL: Secret{Env: "OSK_SLACK_URL", Path: "slack.url", Line: 4}, MinSeverity: decide.SeverityMedium},
		Webhooks: []Webhook{{
			Name:        "siem",
			URL:         Secret{File: "/run/secrets/siem_url", Path: "webhooks[0].url", Line: 5},
			Key:         Secret{File: "/run/secrets/siem_key", Path: "webhooks[0].key", Line: 5},
			MinSeverity: decide.SeverityHigh,
		}},
		Heartbeat:   &Heartbeat{URL: Secret{Env: "OSK_HEARTBEAT_URL", Path: "heartbeat.url", Line: 6}, Interval: time.Minute},
		HistoryDays: 90,
	}
	for _, d := range cfgDiff(c, want) {
		t.Error(d)
	}
	if got := c.Channels(); !slices.Equal(got, []string{"slack", "siem"}) {
		t.Errorf("Channels() = %q; want [slack siem]", got)
	}
	if got := c.Warnings(); got != nil {
		t.Errorf("Warnings() = %q; want none", got)
	}
}

// cfgEvery is a valid config with every key, one member per line, and
// values at the edges of their limits. A member after the first of its
// object starts with a comma, so that a test can drop the line of a later
// member and keep the JSON valid and every other line where it was.
var cfgEvery = []string{
	`{`,
	`"history_days": 3650`,
	`, "state": "state"`,
	`, "remind": "720h"`,
	`, "domains": [`,
	`{`,
	`"fast": ["login.example.com.", "www.example.com."]`,
	`, "name": "Example.COM."`,
	`, "expect": "example.com.expect"`,
	`}`,
	`, {`,
	`"fast": []`,
	`, "name": "example.org."`,
	`, "expect": "/srv/osk-dns-watcher/example.org.expect"`,
	`}`,
	`]`,
	`, "intervals": {`,
	`"serial": "5s"`,
	`, "parent": "24h"`,
	`, "fast": "90s"`,
	`, "other": "1h30m"`,
	`}`,
	`, "slack": {`,
	`"min_severity": "critical"`,
	`, "url": {"env": "OSK_SLACK_URL"}`,
	`}`,
	`, "webhooks": [`,
	`{`,
	`"min_severity": "medium"`,
	`, "name": "siem-1"`,
	`, "url": {"file": "/run/secrets/siem_url"}`,
	`, "key": {"file": "siem_key"}`,
	`}`,
	`, {`,
	`"min_severity": "low"`,
	`, "name": "pager"`,
	`, "url": {"env": "PAGER_URL"}`,
	`, "key": {"env": "PAGER_KEY"}`,
	`}`,
	`]`,
	`, "heartbeat": {`,
	`"interval": "1h"`,
	`, "url": {"env": "OSK_HEARTBEAT_URL"}`,
	`}`,
	`, "network": {`,
	`"root_servers": ["10.53.0.2:53", "[fd00::2]:5353"]`,
	`, "extra_ranges": ["10.53.0.0/24", "fd00::/64"]`,
	`}`,
	`}`,
}

// cfgEveryWant is the config that cfgEvery holds, with the lines of its
// entries and secrets.
func cfgEveryWant(t testing.TB) *Config {
	return &Config{
		Path:  cfgFile,
		State: "/etc/osk-dns-watcher/state",
		Domains: []Domain{
			{Name: cfgName(t, "Example.COM."), Expect: "/etc/osk-dns-watcher/example.com.expect",
				Fast: []dnswire.Name{cfgName(t, "login.example.com."), cfgName(t, "www.example.com.")}, Line: 6},
			{Name: cfgName(t, "example.org."), Expect: "/srv/osk-dns-watcher/example.org.expect", Line: 11},
		},
		Intervals: schedule.Intervals{Serial: 5 * time.Second, Parent: 24 * time.Hour, Fast: 90 * time.Second, Other: 90 * time.Minute},
		Slack:     &Slack{URL: Secret{Env: "OSK_SLACK_URL", Path: "slack.url", Line: 25}, MinSeverity: decide.SeverityCritical},
		Webhooks: []Webhook{
			{Name: "siem-1", URL: Secret{File: "/run/secrets/siem_url", Path: "webhooks[0].url", Line: 31},
				Key: Secret{File: "/etc/osk-dns-watcher/siem_key", Path: "webhooks[0].key", Line: 32}, MinSeverity: decide.SeverityMedium},
			{Name: "pager", URL: Secret{Env: "PAGER_URL", Path: "webhooks[1].url", Line: 37},
				Key: Secret{Env: "PAGER_KEY", Path: "webhooks[1].key", Line: 38}, MinSeverity: decide.SeverityLow},
		},
		Heartbeat:   &Heartbeat{URL: Secret{Env: "OSK_HEARTBEAT_URL", Path: "heartbeat.url", Line: 43}, Interval: time.Hour},
		HistoryDays: 3650,
		Remind:      720 * time.Hour,
		RootServers: []netip.AddrPort{netip.MustParseAddrPort("10.53.0.2:53"), netip.MustParseAddrPort("[fd00::2]:5353")},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix("10.53.0.0/24"), netip.MustParsePrefix("fd00::/64")},
	}
}

func TestEveryKeyParsesToItsValues(t *testing.T) {
	c := cfgOK(t, strings.Join(cfgEvery, "\n")+"\n")
	for _, d := range cfgDiff(c, cfgEveryWant(t)) {
		t.Error(d)
	}
	if got := c.Channels(); !slices.Equal(got, []string{"slack", "siem-1", "pager"}) {
		t.Errorf("Channels() = %q; want [slack siem-1 pager]", got)
	}
}

func TestDefaultsWhenOptionalKeysAreAbsent(t *testing.T) {
	c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack))
	// An empty list is nil, also the problems of a valid config.
	if _, problems := Parse(cfgFile, []byte(cfgDoc(cfgState, cfgDomains, cfgSlack))); problems != nil {
		t.Errorf("Parse of a valid config gave %#v; want nil problems", problems)
	}
	want := &Config{
		Path:        cfgFile,
		State:       "/var/lib/osk-dns-watcher",
		Domains:     []Domain{{Name: cfgName(t, "corp.test."), Expect: "/etc/osk-dns-watcher/corp.test.expect", Line: 3}},
		Intervals:   schedule.Defaults(),
		Slack:       &Slack{URL: Secret{Env: "OSK_SLACK_URL", Path: "slack.url", Line: 4}, MinSeverity: decide.SeverityLow},
		HistoryDays: 90,
	}
	for _, d := range cfgDiff(c, want) {
		t.Error(d)
	}

	c = cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgHooks("siem"), `"heartbeat": {"url": {"env": "BEAT_URL"}}`))
	if c.Slack != nil {
		t.Errorf("Slack = %+v; want nil when the key is absent", *c.Slack)
	}
	if len(c.Webhooks) != 1 || c.Webhooks[0].MinSeverity != decide.SeverityLow {
		t.Errorf("Webhooks = %+v; want one with the minimum low", c.Webhooks)
	}
	if c.Heartbeat == nil || c.Heartbeat.Interval != time.Minute {
		t.Errorf("Heartbeat = %+v; want the interval 60s", c.Heartbeat)
	}
}

func TestRelativePathsAreReadAgainstTheConfigFolder(t *testing.T) {
	c := cfgOK(t, cfgDoc(`"state": "state"`,
		`"domains": [{"name": "corp.test.", "expect": "zones/corp.expect"}, {"name": "shop.test.", "expect": "/srv/shop.expect"}]`,
		`"slack": {"url": {"file": "secrets/slack_url"}}`,
		`"webhooks": [{"name": "siem", "url": {"file": "/run/secrets/siem_url"}, "key": {"file": "siem_key"}}]`))
	for _, f := range []struct{ name, got, want string }{
		{"State", c.State, filepath.Join(cfgDir, "state")},
		{"Domains[0].Expect", c.Domains[0].Expect, filepath.Join(cfgDir, "zones/corp.expect")},
		{"Domains[1].Expect", c.Domains[1].Expect, "/srv/shop.expect"},
		{"Slack.URL.File", c.Slack.URL.File, filepath.Join(cfgDir, "secrets/slack_url")},
		{"Webhooks[0].URL.File", c.Webhooks[0].URL.File, "/run/secrets/siem_url"},
		{"Webhooks[0].Key.File", c.Webhooks[0].Key.File, filepath.Join(cfgDir, "siem_key")},
	} {
		if f.got != f.want {
			t.Errorf("%s = %q; want %q", f.name, f.got, f.want)
		}
	}
	if c.Path != cfgFile {
		t.Errorf("Path = %q; want the file as given, %q", c.Path, cfgFile)
	}

	// A config named by a relative path still gives absolute paths, made
	// from the working folder.
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	c, problems := Parse("conf/config.json", []byte(cfgDoc(`"state": "state"`, cfgDomains, cfgSlack)))
	if c == nil || len(problems) > 0 {
		t.Fatalf("Parse gave %v", problems)
	}
	if want := filepath.Join(wd, "conf", "state"); c.State != want || c.Path != "conf/config.json" {
		t.Errorf("State %q, Path %q; want %q and the path as given", c.State, c.Path, want)
	}
}

func TestStateIsAFolderWithoutQuestionMarkOrHash(t *testing.T) {
	if c := cfgOK(t, cfgDoc(`"state": "/var/lib/osk-dns-watcher-1"`, cfgDomains, cfgSlack)); c.State != "/var/lib/osk-dns-watcher-1" {
		t.Errorf("State = %q; want /var/lib/osk-dns-watcher-1", c.State)
	}
	for _, c := range []struct{ value, text string }{
		{`""`, "want a path"},
		{`5`, "want a string"},
		{`["/var/lib/osk-dns-watcher"]`, "want a string"},
		{`"/var/lib/osk-dns-watcher?mode=ro"`, "a folder name with ? or # cannot be used"},
		{`"/var/lib/osk-dns-watcher#1"`, "a folder name with ? or # cannot be used"},
	} {
		cfgRefused(t, cfgDoc(`"state": `+c.value, cfgDomains, cfgSlack), cfgAt(2, "state", c.text))
	}
}

func TestRequiredKeyIsNamedAtTheBraceOfItsObject(t *testing.T) {
	cfgRefused(t, "{}", cfgRequired(1, "", "state"), cfgRequired(1, "", "domains"), cfgAt(1, "", cfgWantChannel))
	cfgRefused(t, "\n\n{\n"+cfgDomains+",\n"+cfgSlack+"\n}\n", cfgRequired(3, "", "state"))
	cfgRefused(t, cfgDoc(cfgState, cfgSlack), cfgRequired(1, "", "domains"))
	cfgRefused(t, cfgDoc(cfgState, "\"domains\": [\n{\"fast\": []}]", cfgSlack),
		cfgRequired(4, "domains[0]", "name"), cfgRequired(4, "domains[0]", "expect"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, "\"slack\": {\n\"min_severity\": \"low\"}"), cfgRequired(4, "slack", "url"))
	cfgRefused(t, cfgWith(`"webhooks": [{"min_severity": "low"}]`),
		cfgRequired(5, "webhooks[0]", "name"), cfgRequired(5, "webhooks[0]", "url"), cfgRequired(5, "webhooks[0]", "key"))
	cfgRefused(t, cfgWith(`"heartbeat": {"interval": "60s"}`), cfgRequired(5, "heartbeat", "url"))
}

func TestAtLeastOneChannelIsNamedAtTheTopBrace(t *testing.T) {
	cfgRefused(t, "\n"+cfgDoc(cfgState, cfgDomains), cfgAt(2, "", cfgWantChannel))
	cfgRefused(t, "\n"+cfgDoc(cfgState, cfgDomains, `"webhooks": []`), cfgAt(2, "", cfgWantChannel))
	cfgRefused(t, "\n"+cfgDoc(cfgState, cfgDomains, `"heartbeat": {"url": {"env": "BEAT_URL"}}`), cfgAt(2, "", cfgWantChannel))
	// A slack key or a webhook entry, even a faulty one, is a channel: its
	// own problem says what to fix.
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, `"slack": null`), cfgAt(4, "slack", "want an object"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, `"slack": {}`), cfgRequired(4, "slack", "url"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, `"webhooks": [5]`), cfgAt(4, "webhooks[0]", "want an object"))
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgHooks("siem"))); c.Slack != nil || len(c.Webhooks) != 1 {
		t.Errorf("one webhook and no Slack gave Slack %v, Webhooks %+v", c.Slack, c.Webhooks)
	}
}

func cfgDomainList(n int) string {
	entries := make([]string, n)
	for i := range entries {
		entries[i] = fmt.Sprintf(`{"name": "d%d.test.", "expect": "/e/d%d"}`, i, i)
	}
	return `"domains": [` + strings.Join(entries, ", ") + `]`
}

func TestDomainsHoldOneToHundredObjects(t *testing.T) {
	for _, n := range []int{1, 100} {
		c := cfgOK(t, cfgDoc(cfgState, cfgDomainList(n), cfgSlack))
		if len(c.Domains) != n {
			t.Fatalf("%d domains gave %d", n, len(c.Domains))
		}
		last := c.Domains[n-1]
		if !last.Name.Equal(cfgName(t, fmt.Sprintf("d%d.test.", n-1))) || last.Expect != fmt.Sprintf("/e/d%d", n-1) {
			t.Errorf("the last of %d domains is %v %q; want config order", n, last.Name, last.Expect)
		}
	}
	for _, n := range []int{0, 101} {
		cfgRefused(t, cfgDoc(cfgState, cfgDomainList(n), cfgSlack), cfgAt(3, "domains", "want 1 to 100 domains"))
	}
	for _, v := range []string{`{}`, `"corp.test."`, `5`} {
		cfgRefused(t, cfgDoc(cfgState, `"domains": `+v, cfgSlack), cfgAt(3, "domains", "want a list"))
	}
	for _, v := range []string{`[5]`, `["corp.test."]`, `[[]]`} {
		cfgRefused(t, cfgDoc(cfgState, `"domains": `+v, cfgSlack), cfgAt(3, "domains[0]", "want an object"))
	}
	cfgRefused(t, cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e"}, true]`, cfgSlack),
		cfgAt(3, "domains[1]", "want an object"))
}

func TestDomainNameHasItsDotIsNotTheRootAndIsListedOnce(t *testing.T) {
	doc := func(name string) string {
		return cfgDoc(cfgState, `"domains": [{"name": `+name+`, "expect": "/e"}]`, cfgSlack)
	}
	if c := cfgOK(t, doc(`"Corp.Test."`)); !c.Domains[0].Name.Equal(cfgName(t, "corp.test.")) {
		t.Errorf("Name = %v; want corp.test.", c.Domains[0].Name)
	}
	long := strings.Repeat("a", 64) + ".test."
	for _, c := range []struct{ value, text string }{
		{`"corp.test"`, `"corp.test" has no trailing dot`},
		{`"."`, "the root cannot be watched"},
		{`"a..test."`, cfgBadName(t, "a..test.")},
		// A problem repeats at most 40 octets of a value.
		{`"` + long + `"`, strings.Replace(cfgBadName(t, long), long, long[:40]+"…", 1)},
		{`5`, "want a string"},
		{`["corp.test."]`, "want a string"},
	} {
		cfgRefused(t, doc(c.value), cfgAt(3, "domains[0].name", c.text))
	}

	three := func(third string) string {
		return cfgDoc(cfgState, "\"domains\": [\n"+
			`{"name": "corp.test.", "expect": "/a"},`+"\n"+
			`{"name": "shop.test.", "expect": "/b"},`+"\n"+
			`{"name": "`+third+`", "expect": "/c"}]`, cfgSlack)
	}
	cfgRefused(t, three("corp.test."), cfgAt(6, "domains[2].name", "domain corp.test. is listed twice"))
	// The format does not say whether the name is printed as written or in
	// lower case.
	cfgRefused(t, three("CORP.Test."), cfgP{line: 6, path: "domains[2].name",
		texts: []string{"domain CORP.Test. is listed twice", "domain corp.test. is listed twice"}})
}

func TestDomainExpectIsAPath(t *testing.T) {
	doc := func(expect string) string {
		return cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": `+expect+`}]`, cfgSlack)
	}
	if c := cfgOK(t, doc(`"corp.test.expect"`)); c.Domains[0].Expect != "/etc/osk-dns-watcher/corp.test.expect" {
		t.Errorf("Expect = %q; want /etc/osk-dns-watcher/corp.test.expect", c.Domains[0].Expect)
	}
	cfgRefused(t, doc(`""`), cfgAt(3, "domains[0].expect", "want a path"))
	cfgRefused(t, doc(`5`), cfgAt(3, "domains[0].expect", "want a string"))
	cfgRefused(t, doc(`{"file": "/e"}`), cfgAt(3, "domains[0].expect", "want a string"))
}

func TestFastNamesHaveTheirDotAndAreAtMostHundred(t *testing.T) {
	doc := func(fast string) string {
		return cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e", "fast": `+fast+`}]`, cfgSlack)
	}
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack)); c.Domains[0].Fast != nil {
		t.Errorf("Fast = %v; want none when the key is absent", c.Domains[0].Fast)
	}
	if c := cfgOK(t, doc(`[]`)); c.Domains[0].Fast != nil {
		t.Errorf("Fast = %v; want none", c.Domains[0].Fast)
	}
	hundred := cfgList(100, func(i int) string { return fmt.Sprintf("h%d.corp.test.", i) })
	c := cfgOK(t, doc(hundred))
	if len(c.Domains[0].Fast) != 100 || !c.Domains[0].Fast[99].Equal(cfgName(t, "h99.corp.test.")) ||
		!c.Domains[0].Fast[0].Equal(cfgName(t, "h0.corp.test.")) {
		t.Errorf("100 fast names gave %v; want them in config order", c.Domains[0].Fast)
	}
	tooMany := cfgList(101, func(i int) string { return fmt.Sprintf("h%d.corp.test.", i) })
	cfgRefused(t, doc(tooMany), cfgAt(3, "domains[0].fast", "want at most 100 fast names"))
	cfgRefused(t, doc(`["www.corp.test"]`), cfgAt(3, "domains[0].fast[0]", `"www.corp.test" has no trailing dot`))
	cfgRefused(t, doc(`["www.corp.test.", "a..corp.test."]`), cfgAt(3, "domains[0].fast[1]", cfgBadName(t, "a..corp.test.")))
	cfgRefused(t, doc(`[5]`), cfgAt(3, "domains[0].fast[0]", "want a string"))
	cfgRefused(t, doc(`"www.corp.test."`), cfgAt(3, "domains[0].fast", "want a list"))
	cfgRefused(t, doc(`{}`), cfgAt(3, "domains[0].fast", "want a list"))
}

func cfgInterval(iv schedule.Intervals, key string) time.Duration {
	switch key {
	case "serial":
		return iv.Serial
	case "parent":
		return iv.Parent
	case "fast":
		return iv.Fast
	}
	return iv.Other
}

func TestIntervalsGoFromTheFloorToTheCeiling(t *testing.T) {
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack)); c.Intervals != schedule.Defaults() {
		t.Errorf("Intervals = %+v; want the defaults %+v", c.Intervals, schedule.Defaults())
	}
	if c := cfgOK(t, cfgWith(`"intervals": {}`)); c.Intervals != schedule.Defaults() {
		t.Errorf("Intervals = %+v; want the defaults %+v", c.Intervals, schedule.Defaults())
	}
	want := schedule.Defaults()
	want.Fast = 10 * time.Second
	if c := cfgOK(t, cfgWith(`"intervals": {"fast": "10s"}`)); c.Intervals != want {
		t.Errorf("Intervals = %+v; want %+v", c.Intervals, want)
	}
	for _, key := range []string{"serial", "parent", "fast", "other"} {
		for _, v := range []struct {
			text string
			want time.Duration
		}{{"5s", schedule.Floor}, {"5000ms", schedule.Floor}, {"24h", schedule.Ceiling}, {"90m", 90 * time.Minute}} {
			c := cfgOK(t, cfgWith(fmt.Sprintf(`"intervals": {%q: %q}`, key, v.text)))
			if got := cfgInterval(c.Intervals, key); got != v.want {
				t.Errorf("intervals.%s %q gave %v; want %v", key, v.text, got, v.want)
			}
		}
		for _, v := range []struct{ value, text string }{
			{`"4999ms"`, cfgBelow(4999 * time.Millisecond)},
			{`"0s"`, cfgBelow(0)},
			{`"-5s"`, cfgBelow(-5 * time.Second)},
			{`"24h0m0.000000001s"`, cfgAbove(schedule.Ceiling+1, schedule.Ceiling)},
			{`"1d"`, `"1d" is not a duration`},
			{`""`, `"" is not a duration`},
			{`15`, "want a string"},
		} {
			cfgRefused(t, cfgWith(fmt.Sprintf(`"intervals": {%q: %s}`, key, v.value)), cfgAt(5, "intervals."+key, v.text))
		}
	}
	cfgRefused(t, cfgWith(`"intervals": ["15s"]`), cfgAt(5, "intervals", "want an object"))
	cfgRefused(t, cfgWith(`"intervals": {"slow": "1h"}`), cfgUnknown(5, "intervals", "slow"))
}

func TestMinSeverityIsOneOfFourWords(t *testing.T) {
	slackDoc := func(v string) string {
		return cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": "OSK_SLACK_URL"}, "min_severity": `+v+`}`)
	}
	hookDoc := func(v string) string {
		return cfgWith(`"webhooks": [{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}, "min_severity": ` + v + `}]`)
	}
	for word, want := range map[string]decide.Severity{
		"low": decide.SeverityLow, "medium": decide.SeverityMedium, "high": decide.SeverityHigh, "critical": decide.SeverityCritical,
	} {
		if c := cfgOK(t, slackDoc(`"`+word+`"`)); c.Slack.MinSeverity != want {
			t.Errorf("slack.min_severity %q gave %v", word, c.Slack.MinSeverity)
		}
		if c := cfgOK(t, hookDoc(`"`+word+`"`)); c.Webhooks[0].MinSeverity != want {
			t.Errorf("webhooks[0].min_severity %q gave %v", word, c.Webhooks[0].MinSeverity)
		}
	}
	for _, v := range []struct{ value, text string }{
		{`"Low"`, cfgWantSev},
		{`"urgent"`, cfgWantSev},
		{`""`, cfgWantSev},
		{`3`, "want a string"},
	} {
		cfgRefused(t, slackDoc(v.value), cfgAt(4, "slack.min_severity", v.text))
		cfgRefused(t, hookDoc(v.value), cfgAt(5, "webhooks[0].min_severity", v.text))
	}
}

func TestWebhooksAreAtMostEight(t *testing.T) {
	eight := []string{"h1", "h2", "h3", "h4", "h5", "h6", "h7", "h8"}
	c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgHooks(eight...)))
	if len(c.Webhooks) != 8 || c.Webhooks[7].Name != "h8" {
		t.Errorf("8 webhooks gave %+v", c.Webhooks)
	}
	if c := cfgOK(t, cfgWith(`"webhooks": []`)); c.Webhooks != nil {
		t.Errorf("Webhooks = %+v; want none", c.Webhooks)
	}
	cfgRefused(t, cfgWith(cfgHooks(append(eight, "h9")...)), cfgAt(5, "webhooks", "want at most 8 webhooks"))
	for _, v := range []string{`{}`, `"siem"`} {
		cfgRefused(t, cfgWith(`"webhooks": `+v), cfgAt(5, "webhooks", "want a list"))
	}
	cfgRefused(t, cfgWith(`"webhooks": [5]`), cfgAt(5, "webhooks[0]", "want an object"))
}

func TestWebhookNameIsShortLowerCaseNotSlackAndListedOnce(t *testing.T) {
	doc := func(name string) string {
		return cfgWith(`"webhooks": [{"name": ` + name + `, "url": {"env": "U"}, "key": {"env": "K"}}]`)
	}
	longest := strings.Repeat("a-9", 10) + "zz"
	for _, name := range []string{"a", "0", "-", "siem-1", longest} {
		if c := cfgOK(t, doc(`"`+name+`"`)); c.Webhooks[0].Name != name {
			t.Errorf("name %q gave %q", name, c.Webhooks[0].Name)
		}
	}
	for _, v := range []struct{ value, text string }{
		{`""`, cfgWantHook},
		{`"` + longest + `x"`, cfgWantHook},
		{`"Siem"`, cfgWantHook},
		{`"si_em"`, cfgWantHook},
		{`"siem.1"`, cfgWantHook},
		{`"sïem"`, cfgWantHook},
		{`"slack"`, "the name slack belongs to the Slack channel"},
		{`7`, "want a string"},
	} {
		cfgRefused(t, doc(v.value), cfgAt(5, "webhooks[0].name", v.text))
	}
	cfgRefused(t, cfgWith(cfgHooks("siem", "pager", "siem")), cfgAt(5, "webhooks[2].name", "webhook siem is listed twice"))
}

func TestHeartbeatNeedsAURLAndAnIntervalOfFiveSecondsToOneHour(t *testing.T) {
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack)); c.Heartbeat != nil {
		t.Errorf("Heartbeat = %+v; want nil when the key is absent", *c.Heartbeat)
	}
	c := cfgOK(t, cfgWith(`"heartbeat": {"url": {"env": "BEAT_URL"}}`))
	if want := (Heartbeat{URL: Secret{Env: "BEAT_URL", Path: "heartbeat.url", Line: 5}, Interval: time.Minute}); c.Heartbeat == nil || *c.Heartbeat != want {
		t.Errorf("Heartbeat = %+v; want %+v", c.Heartbeat, want)
	}
	for _, v := range []struct {
		text string
		want time.Duration
	}{{"5s", 5 * time.Second}, {"1h", time.Hour}, {"90s", 90 * time.Second}} {
		c := cfgOK(t, cfgWith(`"heartbeat": {"url": {"env": "BEAT_URL"}, "interval": "`+v.text+`"}`))
		if c.Heartbeat.Interval != v.want {
			t.Errorf("heartbeat.interval %q gave %v", v.text, c.Heartbeat.Interval)
		}
	}
	for _, v := range []struct{ value, text string }{
		{`"4999ms"`, cfgBelow(4999 * time.Millisecond)},
		{`"1h0m0.000000001s"`, cfgAbove(time.Hour+1, time.Hour)},
		{`"2h"`, cfgAbove(2*time.Hour, time.Hour)},
		{`"often"`, `"often" is not a duration`},
		{`60`, "want a string"},
	} {
		cfgRefused(t, cfgWith(`"heartbeat": {"url": {"env": "BEAT_URL"}, "interval": `+v.value+`}`), cfgAt(5, "heartbeat.interval", v.text))
	}
	cfgRefused(t, cfgWith(`"heartbeat": ["https://beat.example/"]`), cfgAt(5, "heartbeat", "want an object"))
}

func TestHistoryDaysIsAnIntegerFromOneTo3650(t *testing.T) {
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack)); c.HistoryDays != 90 {
		t.Errorf("HistoryDays = %d; want 90 when the key is absent", c.HistoryDays)
	}
	for _, n := range []int{1, 3650, 7} {
		if c := cfgOK(t, cfgWith(fmt.Sprintf(`"history_days": %d`, n))); c.HistoryDays != n {
			t.Errorf("history_days %d gave %d", n, c.HistoryDays)
		}
	}
	for _, v := range []string{`0`, `3651`, `-1`} {
		cfgRefused(t, cfgWith(`"history_days": `+v), cfgAt(5, "history_days", "want 1 to 3650"))
	}
	for _, v := range []string{`1.5`, `90.0`, `1e2`, `9E1`, `1e0`, `"90"`, `true`, `[90]`, `{"days": 90}`} {
		cfgRefused(t, cfgWith(`"history_days": `+v), cfgAt(5, "history_days", "want an integer"))
	}
	// An integer too large for any Go integer: the format allows either text.
	cfgRefused(t, cfgWith(`"history_days": 99999999999999999999`),
		cfgP{line: 5, path: "history_days", texts: []string{"want 1 to 3650", "want an integer"}})
}

func TestRemindIsOffOrFromOneTo720Hours(t *testing.T) {
	if c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack)); c.Remind != 0 {
		t.Errorf("Remind = %v; want 0 when the key is absent", c.Remind)
	}
	for _, v := range []struct {
		text string
		want time.Duration
	}{{"0s", 0}, {"0", 0}, {"1h", time.Hour}, {"60m", time.Hour}, {"720h", 720 * time.Hour}, {"36h", 36 * time.Hour}} {
		if c := cfgOK(t, cfgWith(`"remind": "`+v.text+`"`)); c.Remind != v.want {
			t.Errorf("remind %q gave %v; want %v", v.text, c.Remind, v.want)
		}
	}
	for _, v := range []struct{ value, text string }{
		{`"59m59.999999999s"`, cfgWantRemind},
		{`"720h0m0.000000001s"`, cfgWantRemind},
		{`"1s"`, cfgWantRemind},
		{`"30m"`, cfgWantRemind},
		{`"-1h"`, cfgWantRemind},
		{`"later"`, `"later" is not a duration`},
		{`3600`, "want a string"},
	} {
		cfgRefused(t, cfgWith(`"remind": `+v.value), cfgAt(5, "remind", v.text))
	}
}

func TestRootServersAreAddressesWithAnOptionalPortAtMost16(t *testing.T) {
	doc := func(list string) string { return cfgWith(`"network": {"root_servers": ` + list + `}`) }
	c := cfgOK(t, doc(`["10.53.0.2", "10.53.0.3:5353", "[fd00::2]:53", "fd00::3"]`))
	got := c.RootServers
	if len(got) != 4 {
		t.Fatalf("RootServers = %v; want 4", got)
	}
	// An address without a port keeps port 0, which the service reads as 53.
	for i, addr := range map[int]string{0: "10.53.0.2", 3: "fd00::3"} {
		if want := netip.AddrPortFrom(netip.MustParseAddr(addr), 0); got[i] != want {
			t.Errorf("RootServers[%d] = %v; want %v", i, got[i], want)
		}
	}
	for i, ap := range map[int]string{1: "10.53.0.3:5353", 2: "[fd00::2]:53"} {
		if got[i] != netip.MustParseAddrPort(ap) {
			t.Errorf("RootServers[%d] = %v; want %s", i, got[i], ap)
		}
	}
	addr := func(i int) string { return fmt.Sprintf("10.53.0.%d", i+1) }
	if c := cfgOK(t, doc(`[]`)); c.RootServers != nil {
		t.Errorf("an empty list gave %#v; want nil", c.RootServers)
	}
	if c := cfgOK(t, doc(cfgList(16, addr))); len(c.RootServers) != 16 {
		t.Errorf("16 root servers gave %v", c.RootServers)
	}
	cfgRefused(t, doc(cfgList(17, addr)), cfgAt(5, "network.root_servers", "want at most 16 root servers"))
	for _, v := range []string{"dns.example", "10.53.0.2:99999", "", "10.53.0.256", "10.53.0.2:"} {
		cfgRefused(t, doc(`["10.53.0.9", "`+v+`"]`),
			cfgAt(5, "network.root_servers[1]", fmt.Sprintf("%q is not an IP address with an optional port", v)))
	}
	cfgRefused(t, doc(`[5]`), cfgAt(5, "network.root_servers[0]", "want a string"))
	cfgRefused(t, doc(`"10.53.0.2"`), cfgAt(5, "network.root_servers", "want a list"))
}

func TestExtraRangesArePrefixesWithNoBitsAfterTheLengthAtMost64(t *testing.T) {
	doc := func(list string) string { return cfgWith(`"network": {"extra_ranges": ` + list + `}`) }
	c := cfgOK(t, doc(`["10.53.0.0/24", "fd00::/64", "192.0.2.7/32"]`))
	want := []netip.Prefix{netip.MustParsePrefix("10.53.0.0/24"), netip.MustParsePrefix("fd00::/64"), netip.MustParsePrefix("192.0.2.7/32")}
	if !slices.Equal(c.ExtraRanges, want) {
		t.Errorf("ExtraRanges = %v; want %v", c.ExtraRanges, want)
	}
	prefix := func(i int) string { return fmt.Sprintf("10.%d.0.0/16", i) }
	if c := cfgOK(t, doc(`[]`)); c.ExtraRanges != nil {
		t.Errorf("an empty list gave %#v; want nil", c.ExtraRanges)
	}
	if c := cfgOK(t, doc(cfgList(64, prefix))); len(c.ExtraRanges) != 64 {
		t.Errorf("64 ranges gave %d", len(c.ExtraRanges))
	}
	cfgRefused(t, doc(cfgList(65, prefix)), cfgAt(5, "network.extra_ranges", "want at most 64 ranges"))
	for _, v := range []struct{ value, text string }{
		{"10.53.0.0", `bad prefix "10.53.0.0"`},
		{"x", `bad prefix "x"`},
		{"", `bad prefix ""`},
		{"10.53.0.0/33", `bad prefix "10.53.0.0/33"`},
		{"10.53.0.1/24", "prefix 10.53.0.1/24 has bits after its length; write 10.53.0.0/24"},
		{"fd00::1/64", "prefix fd00::1/64 has bits after its length; write fd00::/64"},
	} {
		cfgRefused(t, doc(`["10.9.0.0/16", "`+v.value+`"]`), cfgAt(5, "network.extra_ranges[1]", v.text))
	}
	cfgRefused(t, doc(`[24]`), cfgAt(5, "network.extra_ranges[0]", "want a string"))
	cfgRefused(t, doc(`{}`), cfgAt(5, "network.extra_ranges", "want a list"))
	cfgRefused(t, cfgWith(`"network": ["10.53.0.0/24"]`), cfgAt(5, "network", "want an object"))
}

func TestOptionalObjectsWantObjects(t *testing.T) {
	hook := cfgHooks("siem")
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, hook, `"slack": "https://hooks.example/x"`), cfgAt(5, "slack", "want an object"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, hook, `"slack": []`), cfgAt(5, "slack", "want an object"))
	cfgRefused(t, cfgWith(`"heartbeat": 5`), cfgAt(5, "heartbeat", "want an object"))
	cfgRefused(t, cfgWith(`"intervals": "60s"`), cfgAt(5, "intervals", "want an object"))
	cfgRefused(t, cfgWith(`"network": true`), cfgAt(5, "network", "want an object"))
}

func TestSecretIsAnObjectWithEnvOrFile(t *testing.T) {
	doc := func(secret string) string {
		return cfgDoc(cfgState, cfgDomains, `"slack": {"url": `+secret+`}`)
	}
	for _, c := range []struct {
		secret string
		want   Secret
	}{
		{`{"env": "OSK_SLACK_URL"}`, Secret{Env: "OSK_SLACK_URL", Path: "slack.url", Line: 4}},
		{`{"file": "/run/secrets/slack"}`, Secret{File: "/run/secrets/slack", Path: "slack.url", Line: 4}},
		{`{"file": "secrets/slack"}`, Secret{File: "/etc/osk-dns-watcher/secrets/slack", Path: "slack.url", Line: 4}},
	} {
		if got := cfgOK(t, doc(c.secret)).Slack.URL; got != c.want {
			t.Errorf("%s gave %+v; want %+v", c.secret, got, c.want)
		}
	}
	for _, name := range []string{"A", "_", "A_1", "_9", strings.Repeat("Z", 64)} {
		if got := cfgOK(t, doc(`{"env": "`+name+`"}`)).Slack.URL.Env; got != name {
			t.Errorf("env %q gave %q", name, got)
		}
	}
	for _, name := range []string{"a", "1A", "A-B", "", "OSK_slack", "A B", "https://hooks.example/services/T0/B0/inlinemarker"} {
		cfgRefused(t, doc(`{"env": "`+name+`"}`), cfgAt(4, "slack.url.env", cfgWantEnvName))
	}
	// A name of 65 octets is too long; the format gives no text of its own
	// for that, so only the place is checked, and that the name is not shown.
	long := strings.Repeat("Z", 65)
	if c, problems := Parse(cfgFile, []byte(doc(`{"env": "`+long+`"}`))); c != nil || len(problems) != 1 ||
		problems[0].Line != 4 || problems[0].Path != "slack.url.env" || strings.Contains(problems[0].Text, long) {
		t.Errorf("a name of 65 octets gave config %v and problems %v; want one problem at slack.url.env", c, problems)
	}
	cfgRefused(t, doc(`{"env": 5}`), cfgAt(4, "slack.url.env", "want a string"))
	cfgRefused(t, doc(`{"file": 5}`), cfgAt(4, "slack.url.file", "want a string"))
	cfgRefused(t, doc(`{"file": ""}`), cfgAt(4, "slack.url.file", "want a path"))
	cfgRefused(t, doc(`{}`), cfgAt(4, "slack.url", cfgWantSecret))
	cfgRefused(t, doc(`{"env": "OSK_SLACK_URL", "file": "/run/secrets/slack"}`), cfgAt(4, "slack.url", cfgWantSecret))
	// The text sits where the secret's "{" is.
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, "\"slack\": {\"url\":\n{\"env\": \"A\",\n\"file\": \"/b\"}}"), cfgAt(5, "slack.url", cfgWantSecret))
	// A value written in place of a secret is not repeated.
	for _, v := range []string{`"https://hooks.example/services/T0/B0/inlinemarker"`, `null`, `5`, `["OSK_SLACK_URL"]`} {
		cfgRefused(t, doc(v), cfgAt(4, "slack.url", cfgWantSecret))
	}
	c, problems := Parse(cfgFile, []byte(doc(`{"value": "inlinemarker"}`)))
	if c != nil || len(problems) == 0 {
		t.Errorf(`a secret {"value": …} gave config %v and problems %v; want problems only`, c, problems)
	}
	for _, p := range problems {
		if p.Line != 4 || !strings.HasPrefix(p.Path, "slack.url") || strings.Contains(p.String(), "inlinemarker") {
			t.Errorf(`a secret {"value": …} gave %+v; want line 4, a path in slack.url and no value`, p)
		}
	}
}

func TestUnknownKeyIsRefusedAndItsValueSkipped(t *testing.T) {
	cfgRefused(t, cfgWith(`"slak": {"url": {"env": "OSK_SLACK_URL"}, "x": [1, {"y": null}]}`), cfgUnknown(5, "", "slak"))
	cfgRefused(t, cfgWith(`"_comment": "the config of osk-dns-watcher"`), cfgUnknown(5, "", "_comment"))
	// The trust anchor is not a setting of this file: its key is refused like any other.
	cfgRefused(t, cfgWith(`"dnssec": {"trust_anchor": "/etc/osk-dns-watcher/root.key"}`), cfgUnknown(5, "", "dnssec"))
	cfgRefused(t, cfgWith(`"network": {"trust_anchor": "/etc/osk-dns-watcher/root.key"}`), cfgUnknown(5, "network", "trust_anchor"))
	cfgRefused(t, cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e", "fastt": []}]`, cfgSlack),
		cfgUnknown(3, "domains[0]", "fastt"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": "U"}, "channel": "#dns"}`), cfgUnknown(4, "slack", "channel"))
	cfgRefused(t, cfgWith(`"webhooks": [{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}, "secret": "x"}]`),
		cfgUnknown(5, "webhooks[0]", "secret"))
	cfgRefused(t, cfgWith(`"heartbeat": {"url": {"env": "U"}, "every": "1m"}`), cfgUnknown(5, "heartbeat", "every"))
	// The line of the key, not of its value.
	cfgRefused(t, "{\n"+cfgState+",\n"+cfgDomains+",\n"+cfgSlack+", \"zz\"\n:\n1}\n", cfgUnknown(4, "", "zz"))
}

func TestKeyInAnotherCaseIsUnknown(t *testing.T) {
	cfgRefused(t, cfgWith(`"State": "/tmp/osk-dns-watcher"`), cfgUnknown(5, "", "State"))
	cfgRefused(t, cfgWith(`"STATE": "/tmp/osk-dns-watcher"`), cfgUnknown(5, "", "STATE"))
	cfgRefused(t, cfgDoc(`"State": "/var/lib/osk-dns-watcher"`, cfgDomains, cfgSlack), cfgUnknown(2, "", "State"), cfgRequired(1, "", "state"))
	cfgRefused(t, cfgDoc(cfgState, `"domains": [{"Name": "corp.test.", "name": "corp.test.", "expect": "/e"}]`, cfgSlack),
		cfgUnknown(3, "domains[0]", "Name"))
	cfgRefused(t, cfgWith(`"intervals": {"Fast": "10s"}`), cfgUnknown(5, "intervals", "Fast"))
	cfgRefused(t, cfgWith(`"History_days": 5`), cfgUnknown(5, "", "History_days"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": "U"}, "Min_Severity": "high"}`),
		cfgUnknown(4, "slack", "Min_Severity"))
}

func TestKeyGivenTwiceIsRefused(t *testing.T) {
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, cfgSlack, cfgState), cfgTwice(5, "", "state"))
	cfgRefused(t, cfgDoc(cfgState, cfgDomains, cfgSlack, cfgSlack), cfgTwice(5, "", "slack"))
	cfgRefused(t, cfgWith(`"history_days": 5, "history_days": 6`), cfgTwice(5, "", "history_days"))
	cfgRefused(t, cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "name": "corp.test.", "expect": "/e"}]`, cfgSlack),
		cfgTwice(3, "domains[0]", "name"))
	cfgRefused(t, cfgWith(`"intervals": {"fast": "10s", "fast": "10s"}`), cfgTwice(5, "intervals", "fast"))
	cfgRefused(t, cfgWith(`"webhooks": [{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}, "key": {"env": "K"}}]`),
		cfgTwice(5, "webhooks[0]", "key"))
}

func TestNullIsAWrongTypeForEveryKey(t *testing.T) {
	hook := cfgHooks("siem")
	for _, c := range []struct {
		text string
		want cfgP
	}{
		{cfgDoc(`"state": null`, cfgDomains, cfgSlack), cfgAt(2, "state", "want a string")},
		{cfgDoc(cfgState, `"domains": null`, cfgSlack), cfgAt(3, "domains", "want a list")},
		{cfgDoc(cfgState, `"domains": [null]`, cfgSlack), cfgAt(3, "domains[0]", "want an object")},
		{cfgDoc(cfgState, `"domains": [{"name": null, "expect": "/e"}]`, cfgSlack), cfgAt(3, "domains[0].name", "want a string")},
		{cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": null}]`, cfgSlack), cfgAt(3, "domains[0].expect", "want a string")},
		{cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e", "fast": null}]`, cfgSlack), cfgAt(3, "domains[0].fast", "want a list")},
		{cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e", "fast": [null]}]`, cfgSlack), cfgAt(3, "domains[0].fast[0]", "want a string")},
		{cfgWith(`"intervals": null`), cfgAt(5, "intervals", "want an object")},
		{cfgWith(`"intervals": {"serial": null}`), cfgAt(5, "intervals.serial", "want a string")},
		{cfgDoc(cfgState, cfgDomains, hook, `"slack": null`), cfgAt(5, "slack", "want an object")},
		{cfgDoc(cfgState, cfgDomains, `"slack": {"url": null}`), cfgAt(4, "slack.url", cfgWantSecret)},
		{cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": null}}`), cfgAt(4, "slack.url.env", "want a string")},
		{cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"file": null}}`), cfgAt(4, "slack.url.file", "want a string")},
		{cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": "U"}, "min_severity": null}`), cfgAt(4, "slack.min_severity", "want a string")},
		{cfgWith(`"webhooks": null`), cfgAt(5, "webhooks", "want a list")},
		{cfgWith(`"webhooks": [null]`), cfgAt(5, "webhooks[0]", "want an object")},
		{cfgWith(`"webhooks": [{"name": null, "url": {"env": "U"}, "key": {"env": "K"}}]`), cfgAt(5, "webhooks[0].name", "want a string")},
		{cfgWith(`"webhooks": [{"name": "siem", "url": null, "key": {"env": "K"}}]`), cfgAt(5, "webhooks[0].url", cfgWantSecret)},
		{cfgWith(`"webhooks": [{"name": "siem", "url": {"env": "U"}, "key": null}]`), cfgAt(5, "webhooks[0].key", cfgWantSecret)},
		{cfgWith(`"webhooks": [{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}, "min_severity": null}]`), cfgAt(5, "webhooks[0].min_severity", "want a string")},
		{cfgWith(`"heartbeat": null`), cfgAt(5, "heartbeat", "want an object")},
		{cfgWith(`"heartbeat": {"url": null}`), cfgAt(5, "heartbeat.url", cfgWantSecret)},
		{cfgWith(`"heartbeat": {"url": {"env": "U"}, "interval": null}`), cfgAt(5, "heartbeat.interval", "want a string")},
		{cfgWith(`"history_days": null`), cfgAt(5, "history_days", "want an integer")},
		{cfgWith(`"remind": null`), cfgAt(5, "remind", "want a string")},
		{cfgWith(`"network": null`), cfgAt(5, "network", "want an object")},
		{cfgWith(`"network": {"root_servers": null}`), cfgAt(5, "network.root_servers", "want a list")},
		{cfgWith(`"network": {"root_servers": [null]}`), cfgAt(5, "network.root_servers[0]", "want a string")},
		{cfgWith(`"network": {"extra_ranges": null}`), cfgAt(5, "network.extra_ranges", "want a list")},
		{cfgWith(`"network": {"extra_ranges": [null]}`), cfgAt(5, "network.extra_ranges[0]", "want a string")},
	} {
		cfgRefused(t, c.text, c.want)
	}
}

// The walk keeps going after a wrong value, also one that is an object or a
// list, and each problem is at the line where its key or value starts.
// Lines are counted by LF, so CR LF ends give the same lines.
func TestProblemLineIsWhereItsKeyOrValueStarts(t *testing.T) {
	lines := []string{
		``,
		`{`,
		`"state":`,
		`  5,`,
		`"domains": [{"name": "corp.test.", "expect": "/e"}],`,
		`"slack":`,
		`{"url": {"env": "OSK_SLACK_URL"}},`,
		`"zz"`,
		`: 1,`,
		`"history_days": {"a": [1,`,
		`2]},`,
		`"remind": "soon",`,
		`"webhooks": [`,
		`{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}},`,
		`{"name": "siem", "url": {"env": "U"}, "key": {"env": "K"}}`,
		`]`,
		`}`,
	}
	want := []cfgP{
		cfgAt(4, "state", "want a string"),
		cfgUnknown(8, "", "zz"),
		cfgAt(10, "history_days", "want an integer"),
		cfgAt(12, "remind", `"soon" is not a duration`),
		cfgAt(15, "webhooks[1].name", "webhook siem is listed twice"),
	}
	for _, eol := range []string{"\n", "\r\n"} {
		cfgRefused(t, strings.Join(lines, eol)+eol, want...)
	}
}

// cfgSyntax checks a text that is not valid JSON: no config, and one
// problem of the whole file and nothing else, whatever comes after the
// fault. Its words and line come from encoding/json and are not fixed here.
func cfgSyntax(t *testing.T, text string) Problem {
	t.Helper()
	c, problems := Parse(cfgFile, []byte(text))
	if c != nil || len(problems) != 1 {
		t.Errorf("Parse(%s) gave config %v and problems %v; want one problem", cfgShort(text), c, problems)
		return Problem{}
	}
	p := problems[0]
	if p.File != cfgFile || p.Path != "" || !strings.HasPrefix(p.Text, "not valid JSON: ") {
		t.Errorf("Parse(%s) gave %+v; want the file, no path and not valid JSON: <err>", cfgShort(text), p)
	}
	return p
}

// The faults before and after the syntax error (unknown keys, keys it
// leaves missing) are not reported.
func TestSyntaxErrorGivesOneProblemAndNothingElse(t *testing.T) {
	for _, text := range []string{
		"{\n\"state\": \"/var/lib/osk-dns-watcher\",\n\"domains\": ]\n\"slak\": 1, \"State\": 2}\n",
		"{\n\"state\": \"/var/lib/osk-dns-watcher\"\n\"domains\": [], \"zz\": 1}\n",
		"{\n\"slak\": 1,\n\"history_days\": 0,\n\"state\" \"/var/lib/osk-dns-watcher\"}\n",
		"\n\n{\"state\": \"/var/lib/osk-dns-watcher\",, \"slak\": 1}\n",
		"{\"history_days\": tru}",
		"{\"history_days\": 1.}",
		"{'state': '/var/lib/osk-dns-watcher'}",
		"{\"state\": \"/var/lib/osk-dns-watcher\", /* note */ \"domains\": []}",
	} {
		cfgSyntax(t, text)
	}
}

// A line break inside a string is the fault, and the line it ends is not.
func TestRawLineBreakInAStringIsReportedOnTheNextLine(t *testing.T) {
	text := "{\n\"state\": \"/var/lib\nosk-dns-watcher\",\n" + cfgDomains + ",\n" + cfgSlack + "\n}\n"
	if p := cfgSyntax(t, text); p.Line != 3 {
		t.Errorf("a line break in the string of line 2 gave line %d; want 3", p.Line)
	}
}

// A cut file, one with more after its object, and one that holds no value
// are not valid JSON.
func TestCutEmptyOrTrailingTextIsNotValidJSON(t *testing.T) {
	valid := cfgDoc(cfgState, cfgDomains, cfgSlack)
	for _, text := range []string{
		valid[:len(valid)-3],
		"{\"state\": \"/var/lib/osk-dns-watcher\",",
		"{\"state\": \"/var/lib",
		valid + "x",
		valid + "{}",
		valid + `"slack"`,
		"",
		" \n\t\n",
	} {
		cfgSyntax(t, text)
	}
	if c := cfgOK(t, "\r\n\t "+valid+" \r\n\n"); c.State != "/var/lib/osk-dns-watcher" {
		t.Errorf("blanks around the object changed State to %q", c.State)
	}
}

func TestTopLevelMustBeAnObject(t *testing.T) {
	for _, v := range []string{`[]`, `"/var/lib/osk-dns-watcher"`, `5`, `null`, `true`, `[{"state": "/var/lib/osk-dns-watcher"}]`} {
		cfgRefused(t, "\n"+v+"\n", cfgAt(2, "", "want an object"))
	}
}

func TestFileOfOneMebibyteIsTheLargest(t *testing.T) {
	valid := cfgDoc(cfgState, cfgDomains, cfgSlack)
	exact := valid + strings.Repeat(" ", 1048576-len(valid))
	cfgOK(t, exact)
	cfgRefused(t, exact+" ", cfgAt(0, "", "the file is larger than 1048576 octets"))
	// The size is the only problem: nothing in the file is read.
	faulty := cfgWith(`"slak": 1`)
	cfgRefused(t, faulty+strings.Repeat(" ", 1048577-len(faulty)), cfgAt(0, "", "the file is larger than 1048576 octets"))
}

// The problem is of the whole file, so it has no line, and it is the only
// one.
func TestFileMustBeUTF8(t *testing.T) {
	for _, text := range []string{
		cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e`+"\xff"+`"}]`, cfgSlack),
		cfgDoc(cfgState, "\"dom\xc3ains\": []", cfgSlack),
		cfgDoc(cfgState, `"domains": [{"name": "corp.test.", "expect": "/e`+"\xed\xa0\x80"+`"}]`, cfgSlack),
	} {
		cfgRefused(t, text, cfgAt(0, "", "the file is not valid UTF-8"))
	}
	if c := cfgOK(t, cfgDoc(`"state": "/var/lib/ösk-状態"`, cfgDomains, cfgSlack)); c.State != "/var/lib/ösk-状態" {
		t.Errorf("State = %q; want the UTF-8 text as written", c.State)
	}
}

func TestOnlyTheFirstHundredProblemsAreKept(t *testing.T) {
	members := []string{cfgState, cfgDomains, cfgSlack}
	var want []cfgP
	for i := range 150 {
		key := fmt.Sprintf("k%03d", i)
		members = append(members, fmt.Sprintf("%q: %d", key, i))
		if i < 100 {
			want = append(want, cfgUnknown(5+i, "", key))
		}
	}
	cfgRefused(t, cfgDoc(members...), want...)
}

// cfgSortedByLine fails unless the lines of problems never go down.
func cfgSortedByLine(t *testing.T, problems []Problem) {
	t.Helper()
	if !slices.IsSortedFunc(problems, func(a, b Problem) int { return a.Line - b.Line }) {
		t.Errorf("problems %v are not sorted by line", problems)
	}
}

// A missing key is found at the end of its object but named at its "{", so
// it comes before the problems inside the object.
func TestProblemsAreSortedByLine(t *testing.T) {
	text := cfgDoc(cfgState, "\"domains\": [\n{\n\"fast\": [5],\n\"expect\": \"\"}],\n\"remind\": \"1s\"", cfgSlack)
	c, problems := Parse(cfgFile, []byte(text))
	want := []Problem{
		{File: cfgFile, Line: 4, Path: "domains[0].name", Text: "is required"},
		{File: cfgFile, Line: 5, Path: "domains[0].fast[0]", Text: "want a string"},
		{File: cfgFile, Line: 6, Path: "domains[0].expect", Text: "want a path"},
		{File: cfgFile, Line: 7, Path: "remind", Text: cfgWantRemind},
	}
	if c != nil || !slices.Equal(problems, want) {
		t.Errorf("Parse gave config %v and problems\n%+v\nwant\n%+v", c, problems, want)
	}
	_, problems = Parse(cfgFile, []byte("{\n"+cfgSlack+",\n\"slak\": 1\n}"))
	want = []Problem{
		{File: cfgFile, Line: 1, Path: "domains", Text: "is required"},
		{File: cfgFile, Line: 1, Path: "state", Text: "is required"},
		{File: cfgFile, Line: 3, Text: `unknown key "slak"`},
	}
	cfgSortedByLine(t, problems)
	slices.SortStableFunc(problems, func(a, b Problem) int { return strings.Compare(a.Path, b.Path) })
	slices.SortStableFunc(problems, func(a, b Problem) int { return a.Line - b.Line })
	if !slices.Equal(problems, want) {
		t.Errorf("Parse gave %+v; want %+v in some order of one line", problems, want)
	}
}

// The five faults of a hand-edited config, one per line, come out in the
// order of their lines, so that a person fixes them from the top.
func TestEveryProblemIsReportedInTheOrderOfTheFile(t *testing.T) {
	text := cfgDoc(cfgState,
		`"domains": [{"name": "corp.test.", "expect": "/etc/osk-dns-watcher/corp.test.expect"}]`,
		`"slak": {"url": {"env": "OSK_SLACK_URL"}}`,
		`"intervals": {"fast": "4s"}`,
		`"webhooks": [{"name": "slack", "url": {"env": "HOOK_URL"}, "key": {"env": "HOOK_KEY"}}]`,
		`"State": "/var/lib/osk-dns-watcher"`,
		cfgState)
	want := []cfgP{
		cfgUnknown(4, "", "slak"),
		cfgAt(5, "intervals.fast", cfgBelow(4*time.Second)),
		cfgAt(6, "webhooks[0].name", "the name slack belongs to the Slack channel"),
		cfgUnknown(7, "", "State"),
		cfgTwice(8, "", "state"),
	}
	c, problems := Parse(cfgFile, []byte(text))
	if c != nil || len(problems) != len(want) {
		t.Fatalf("Parse gave config %v and problems %v; want the %d problems %v", c, problems, len(want), want)
	}
	for i, w := range want {
		if !w.matches(cfgFile, problems[i]) {
			t.Errorf("problem %d is %+v; want %v", i, problems[i], w)
		}
	}
	if got, want := problems[1].String(), "/etc/osk-dns-watcher/config.json:5: intervals.fast: 4s is below the floor of 5s"; got != want {
		t.Errorf("String() = %q; want %q", got, want)
	}
}

func TestReadNamesAFileThatCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	c, problems := Read(path)
	if c != nil || len(problems) != 1 {
		t.Fatalf("Read(%q) gave config %v and problems %v; want one problem", path, c, problems)
	}
	p := problems[0]
	if p.File != path || p.Line != 0 || p.Path != "" || !strings.HasPrefix(p.Text, "cannot be read: ") {
		t.Errorf("Read(%q) gave %+v; want the file, no line, no path, and cannot be read: <err>", path, p)
	}
	if !strings.HasPrefix(p.String(), path+": cannot be read: ") {
		t.Errorf("String() = %q; want it to start with %q", p.String(), path+": cannot be read: ")
	}
}

// cfgFIFO makes a FIFO, which holds whoever opens it to read until a writer
// comes. At the end of the test a writer lets such a reader go.
func cfgFIFO(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if f, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = f.Close()
		}
	})
	return path
}

// cfgWithin fails the test unless read returns within 2 s, so that a hang
// fails the test and not the whole run.
func cfgWithin(t *testing.T, read func() []Problem) []Problem {
	t.Helper()
	done := make(chan []Problem, 1)
	go func() { done <- read() }()
	select {
	case p := <-done:
		return p
	case <-time.After(2 * time.Second):
		t.Fatal("the read did not return within 2s")
		return nil
	}
}

// The config file, a secret file and an expectations file are refused
// before they are opened when they are not regular files: a FIFO would hold
// the open until a writer came.
func TestFilesThatAreNotRegularAreRefusedBeforeTheyAreOpened(t *testing.T) {
	for _, path := range []string{cfgFIFO(t), t.TempDir()} {
		got := cfgWithin(t, func() []Problem { _, p := Read(path); return p })
		want := []Problem{{File: path, Text: "is not a regular file"}}
		if !slices.Equal(got, want) {
			t.Errorf("Read(%q) gave %+v; want %+v", path, got, want)
		}

		c := cfgOK(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": `+cfgQuote(t, path)+`}`, cfgEnvBeat))
		got = cfgWithin(t, func() []Problem { _, p := c.Secrets(cfgEnv(cfgVars())); return p })
		want = []Problem{{File: cfgFile, Line: 5, Path: "webhooks[0].key", Text: "the secret file cannot be read: it is not a regular file"}}
		if !slices.Equal(got, want) {
			t.Errorf("Secrets with the key file %q gave %+v; want %+v", path, got, want)
		}

		d := cfgDomain(t, "corp.test.", path)
		got = cfgWithin(t, func() []Problem { _, p := d.Read(); return p })
		want = []Problem{{File: path, Text: "is not a regular file"}}
		if !slices.Equal(got, want) {
			t.Errorf("Read of the expectations file %q gave %+v; want %+v", path, got, want)
		}
	}
}

// A token pasted as the name of a variable never comes back: the problem of
// a variable that is not set names no variable; the key path and the line
// say which.
func TestUnsetVariableIsNotNamed(t *testing.T) {
	const mark = "T0B0ZQSECRETMARKERQ"
	_, got := cfgSecretProblems(t, cfgSecretDoc(`{"env": "`+mark+`"}`, cfgEnvURL, cfgEnvKey, cfgEnvBeat), cfgVars())
	want := []Problem{{File: cfgFile, Line: 4, Path: "slack.url", Text: "the environment variable is not set"}}
	if !slices.Equal(got, want) {
		t.Errorf("Secrets gave %+v; want %+v", got, want)
	}
}

// A secret pasted into the wrong field never comes back in a problem: a URL
// as the path of a secret file is refused without repeating it, a secret
// file that cannot be read is named by its key path only, and a value that
// a problem repeats is cut after 40 octets.
func TestProblemsDoNotRepeatAPastedSecret(t *testing.T) {
	const mark = "pastedsecretmark"
	cfgRefused(t, cfgSecretDoc(cfgEnvSlack, `{"file": "https://hooks.example/`+mark+`"}`, cfgEnvKey, cfgEnvBeat),
		cfgAt(5, "webhooks[0].url.file", "a path is expected here, not a URL"))

	dir := t.TempDir()
	for file, why := range map[string]string{filepath.Join(dir, mark): "it does not exist", dir: "it is not a regular file"} {
		c := cfgOK(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": `+cfgQuote(t, file)+`}`, cfgEnvBeat))
		_, got := c.Secrets(cfgEnv(cfgVars()))
		want := []Problem{{File: cfgFile, Line: 5, Path: "webhooks[0].key", Text: "the secret file cannot be read: " + why}}
		if !slices.Equal(got, want) {
			t.Errorf("Secrets with the key file %q gave %+v; want %+v", file, got, want)
		}
	}

	long := mark + strings.Repeat("x", 1000)
	cfgRefused(t, cfgWith(cfgQuote(t, long)+`: 1`), cfgAt(5, "", `unknown key "`+long[:40]+`…"`))
	cfgRefused(t, cfgWith(`"remind": `+cfgQuote(t, long)), cfgAt(5, "remind", `"`+long[:40]+`…" is not a duration`))
	// A cut never splits a character: é takes the octets 40 and 41.
	split := strings.Repeat("a", 39) + "é" + mark
	cfgRefused(t, cfgWith(cfgQuote(t, split)+`: 1`), cfgAt(5, "", `unknown key "`+split[:39]+`…"`))
	short := strings.Repeat("b", 40)
	cfgRefused(t, cfgWith(cfgQuote(t, short)+`: 1`), cfgAt(5, "", `unknown key "`+short+`"`))
}

func TestReadParsesTheFileAgainstItsFolder(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	cfgWrite(t, path, cfgDoc(`"state": "state"`, `"domains": [{"name": "corp.test.", "expect": "corp.expect"}]`, cfgSlack))
	c, problems := Read(path)
	if len(problems) > 0 || c == nil {
		t.Fatalf("Read gave config %v and problems %v", c, problems)
	}
	if c.Path != path || c.State != filepath.Join(dir, "state") || c.Domains[0].Expect != filepath.Join(dir, "corp.expect") {
		t.Errorf("Read gave Path %q, State %q, Expect %q; want paths in %s", c.Path, c.State, c.Domains[0].Expect, dir)
	}

	cfgWrite(t, path, cfgWith(`"remind": "1s"`))
	c, problems = Read(path)
	if c != nil || len(problems) != 1 || problems[0] != (Problem{File: path, Line: 5, Path: "remind", Text: cfgWantRemind}) {
		t.Errorf("Read gave config %v and problems %+v; want the remind problem in %s", c, problems, path)
	}

	valid := cfgDoc(cfgState, cfgDomains, cfgSlack)
	cfgWrite(t, path, valid+strings.Repeat("\n", 2<<20))
	c, problems = Read(path)
	if c != nil || len(problems) != 1 || problems[0] != (Problem{File: path, Text: "the file is larger than 1048576 octets"}) {
		t.Errorf("Read of a file of 2 MiB gave config %v and problems %+v; want the size problem only", c, problems)
	}
}

func TestChannelsAreSlackThenTheWebhooksInOrder(t *testing.T) {
	for _, c := range []struct {
		text string
		want []string
	}{
		{cfgDoc(cfgState, cfgDomains, cfgSlack), []string{"slack"}},
		{cfgWith(cfgHooks("zeta", "alpha")), []string{"slack", "zeta", "alpha"}},
		{cfgDoc(cfgState, cfgDomains, cfgHooks("b", "a", "c")), []string{"b", "a", "c"}},
	} {
		if got := cfgOK(t, c.text).Channels(); !slices.Equal(got, c.want) {
			t.Errorf("Channels() = %q; want %q", got, c.want)
		}
	}
}

const (
	cfgRootWarning  = "network.root_servers is set: osk-dns-watcher starts its walk at 10.53.0.2:53, 10.53.0.3:5353, [fd00::2]:53, [fd00::3]:53 instead of the root servers of the internet, so these servers decide every answer. Use it only in a lab or a private network."
	cfgRangeWarning = "network.extra_ranges is set: data from DNS can now make osk-dns-watcher send queries and HTTPS requests for MTA-STS policy files to 10.53.0.0/24, fd00::/64. Use it only in a lab or a private network."
	cfgRoots        = `"root_servers": ["10.53.0.2", "10.53.0.3:5353", "[fd00::2]:53", "fd00::3"]`
	cfgRanges       = `"extra_ranges": ["10.53.0.0/24", "fd00::/64"]`
)

// An empty list is the default, so it counts as not set: a warning that
// names no server would be false.
func TestWarningsOnlyForNetworkKeysThatAreSet(t *testing.T) {
	for _, c := range []struct {
		text string
		want []string
	}{
		{cfgDoc(cfgState, cfgDomains, cfgSlack), nil},
		{cfgWith(`"network": {}`), nil},
		{cfgWith(`"network": {"root_servers": [], "extra_ranges": []}`), nil},
		{cfgWith(`"network": {` + cfgRoots + `}`), []string{cfgRootWarning}},
		{cfgWith(`"network": {` + cfgRanges + `}`), []string{cfgRangeWarning}},
		{cfgWith(`"network": {` + cfgRanges + `, ` + cfgRoots + `}`), []string{cfgRootWarning, cfgRangeWarning}},
	} {
		if got := cfgOK(t, c.text).Warnings(); !cfgSameList(got, c.want) {
			t.Errorf("Warnings() = %q; want %q", got, c.want)
		}
	}
}

// cfgSecretDoc is a config with a Slack URL, one webhook and a heartbeat,
// each secret given as JSON text; their keys are on lines 4, 5 and 6.
func cfgSecretDoc(slackURL, hookURL, hookKey, beatURL string) string {
	return cfgDoc(cfgState, cfgDomains,
		`"slack": {"url": `+slackURL+`}`,
		`"webhooks": [{"name": "siem", "url": `+hookURL+`, "key": `+hookKey+`}]`,
		`"heartbeat": {"url": `+beatURL+`}`)
}

const (
	cfgEnvSlack = `{"env": "OSK_SLACK_URL"}`
	cfgEnvURL   = `{"env": "HOOK_URL"}`
	cfgEnvKey   = `{"env": "HOOK_KEY"}`
	cfgEnvBeat  = `{"env": "OSK_HEARTBEAT_URL"}`
)

// cfgVars are good values for the four variables of cfgSecretDoc.
func cfgVars() map[string]string {
	return map[string]string{
		"OSK_SLACK_URL":     "https://hooks.slack.example/services/T0/B0/s1",
		"HOOK_URL":          "https://siem.example:8443/hook/h1",
		"HOOK_KEY":          strings.Repeat("k", 32),
		"OSK_HEARTBEAT_URL": "https://beat.example/b1",
	}
}

// cfgSecretProblems parses text, which must be valid, and gives what
// Secrets gives with vars.
func cfgSecretProblems(t *testing.T, text string, vars map[string]string) (Values, []Problem) {
	t.Helper()
	return cfgOK(t, text).Secrets(cfgEnv(vars))
}

// cfgSecretRefused checks that Secrets gives exactly the problems want.
func cfgSecretRefused(t *testing.T, text string, vars map[string]string, want ...cfgP) {
	t.Helper()
	_, problems := cfgSecretProblems(t, text, vars)
	if diffs := cfgMatch(cfgFile, problems, want); len(diffs) > 0 {
		t.Errorf("Secrets of %s:\n%s", cfgShort(text), strings.Join(diffs, "\n"))
	}
}

func TestSecretsComeFromTheLookupAndFromFiles(t *testing.T) {
	dir := t.TempDir()
	urlFile, keyFile := filepath.Join(dir, "siem_url"), filepath.Join(dir, "siem_key")
	cfgWrite(t, urlFile, "https://siem.example:8443/hook/h1\n")
	key := strings.Repeat("0123456789", 4)
	cfgWrite(t, keyFile, key+"\r\n")
	text := cfgDoc(cfgState, cfgDomains, `"slack": {"url": {"env": "OSK_SLACK_URL"}}`,
		`"webhooks": [{"name": "siem", "url": {"file": `+cfgQuote(t, urlFile)+`}, "key": {"file": `+cfgQuote(t, keyFile)+`}}, `+
			`{"name": "pager", "url": {"env": "PAGER_URL"}, "key": {"env": "PAGER_KEY"}}]`,
		`"heartbeat": {"url": {"env": "OSK_HEARTBEAT_URL"}}`)
	// The real environment holds another value: only the lookup counts.
	t.Setenv("OSK_SLACK_URL", "https://real.example/not-from-the-lookup")
	vars := map[string]string{
		"OSK_SLACK_URL":     "https://hooks.slack.example/services/T0/B0/s1",
		"PAGER_URL":         "https://pager.example/p1",
		"PAGER_KEY":         strings.Repeat("p", 32),
		"OSK_HEARTBEAT_URL": "https://beat.example/b1",
	}
	v, problems := cfgSecretProblems(t, text, vars)
	if len(problems) > 0 {
		t.Fatalf("Secrets: %v", problems)
	}
	if v.SlackURL != vars["OSK_SLACK_URL"] || v.HeartbeatURL != vars["OSK_HEARTBEAT_URL"] {
		t.Errorf("SlackURL %q, HeartbeatURL %q; want the values of the lookup", v.SlackURL, v.HeartbeatURL)
	}
	if want := []string{"https://siem.example:8443/hook/h1", "https://pager.example/p1"}; !slices.Equal(v.WebhookURLs, want) {
		t.Errorf("WebhookURLs = %q; want %q", v.WebhookURLs, want)
	}
	if len(v.WebhookKeys) != 2 || string(v.WebhookKeys[0]) != key || string(v.WebhookKeys[1]) != vars["PAGER_KEY"] {
		t.Errorf("WebhookKeys = %q; want %q and %q", v.WebhookKeys, key, vars["PAGER_KEY"])
	}

	// Without Slack and heartbeat their values stay empty.
	v, problems = cfgSecretProblems(t, cfgDoc(cfgState, cfgDomains, cfgHooks("siem")), cfgVars())
	if len(problems) > 0 || v.SlackURL != "" || v.HeartbeatURL != "" || len(v.WebhookURLs) != 1 {
		t.Errorf("Secrets gave %d URLs, Slack %q, heartbeat %q, problems %v", len(v.WebhookURLs), v.SlackURL, v.HeartbeatURL, problems)
	}
}

func TestSecretFileLosesOneLFThenOneCR(t *testing.T) {
	dir := t.TempDir()
	keyFile := filepath.Join(dir, "key")
	text := cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": `+cfgQuote(t, keyFile)+`}`, cfgEnvBeat)
	k := strings.Repeat("k", 32)
	for _, c := range []struct{ file, want string }{
		{k, k},
		{k + "\n", k},
		{k + "\r\n", k},
		{k + "\n\n", k + "\n"},
		{k + "\r\n\r\n", k + "\r\n"},
		{k + " \n", k + " "},
		{"\n" + k + "\n", "\n" + k},
	} {
		cfgWrite(t, keyFile, c.file)
		v, problems := cfgSecretProblems(t, text, cfgVars())
		if len(problems) > 0 || len(v.WebhookKeys) != 1 || string(v.WebhookKeys[0]) != c.want {
			t.Errorf("key file %q gave keys %q and problems %v; want %q", c.file, v.WebhookKeys, problems, c.want)
		}
	}
	urlFile := filepath.Join(dir, "url")
	cfgWrite(t, urlFile, "https://siem.example/h1\r\n")
	v, problems := cfgSecretProblems(t, cfgSecretDoc(cfgEnvSlack, `{"file": `+cfgQuote(t, urlFile)+`}`, cfgEnvKey, cfgEnvBeat), cfgVars())
	if len(problems) > 0 || len(v.WebhookURLs) != 1 || v.WebhookURLs[0] != "https://siem.example/h1" {
		t.Errorf("URL file with CR LF gave %q and problems %v", v.WebhookURLs, problems)
	}
}

func TestEmptySecretIsRefused(t *testing.T) {
	vars := cfgVars()
	vars["HOOK_URL"] = ""
	cfgSecretRefused(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat), vars,
		cfgAt(5, "webhooks[0].url", "the environment variable is not set"))
	vars = cfgVars()
	delete(vars, "OSK_HEARTBEAT_URL")
	cfgSecretRefused(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat), vars,
		cfgAt(6, "heartbeat.url", "the environment variable is not set"))

	keyFile := filepath.Join(t.TempDir(), "key")
	text := cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": `+cfgQuote(t, keyFile)+`}`, cfgEnvBeat)
	for _, data := range []string{"", "\n", "\r\n"} {
		cfgWrite(t, keyFile, data)
		cfgSecretRefused(t, text, cfgVars(), cfgAt(5, "webhooks[0].key", "the file "+keyFile+" is empty"))
	}
}

func TestSecretFileOver4096OctetsIsRefused(t *testing.T) {
	dir := t.TempDir()
	keyFile, urlFile := filepath.Join(dir, "key"), filepath.Join(dir, "url")
	text := cfgSecretDoc(cfgEnvSlack, `{"file": `+cfgQuote(t, urlFile)+`}`, `{"file": `+cfgQuote(t, keyFile)+`}`, cfgEnvBeat)
	cfgWrite(t, urlFile, "https://siem.example/h1")
	cfgWrite(t, keyFile, strings.Repeat("k", 4096))
	if v, problems := cfgSecretProblems(t, text, cfgVars()); len(problems) > 0 || len(v.WebhookKeys) != 1 || len(v.WebhookKeys[0]) != 4096 {
		t.Errorf("a key of 4096 octets gave problems %v", problems)
	}
	for _, n := range []int{4097, 100000} {
		cfgWrite(t, keyFile, strings.Repeat("k", n))
		cfgSecretRefused(t, text, cfgVars(), cfgAt(5, "webhooks[0].key", "the file "+keyFile+" is larger than 4096 octets"))
	}
	cfgWrite(t, keyFile, strings.Repeat("k", 40))
	cfgWrite(t, urlFile, "https://siem.example/"+strings.Repeat("u", 4097))
	cfgSecretRefused(t, text, cfgVars(), cfgAt(5, "webhooks[0].url", "the file "+urlFile+" is larger than 4096 octets"))
}

// A key from a variable has the same limit of 4096 octets as one from a
// file.
func TestWebhookKeyFromEnvOver4096OctetsIsRefused(t *testing.T) {
	text := cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat)
	vars := cfgVars()
	vars["HOOK_KEY"] = strings.Repeat("k", 4096)
	if v, problems := cfgSecretProblems(t, text, vars); len(problems) > 0 || len(v.WebhookKeys[0]) != 4096 {
		t.Errorf("a key of 4096 octets gave problems %v", problems)
	}
	for _, key := range []string{strings.Repeat("k", 4097), strings.Repeat("zq7longkey", 410)} {
		vars["HOOK_KEY"] = key
		cfgSecretRefused(t, text, vars, cfgAt(5, "webhooks[0].key", "the key is longer than 4096 octets"))
	}
}

func TestMissingVariableOrFileIsNamed(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "no", "such", "key")
	text := cfgSecretDoc(`{"env": "OSK_NOT_THERE"}`, cfgEnvURL, `{"file": `+cfgQuote(t, missing)+`}`, cfgEnvBeat)
	_, problems := cfgSecretProblems(t, text, cfgVars())
	if len(problems) != 2 {
		t.Fatalf("Secrets gave %v; want two problems", problems)
	}
	slices.SortFunc(problems, func(a, b Problem) int { return a.Line - b.Line })
	if want := (Problem{File: cfgFile, Line: 4, Path: "slack.url", Text: "the environment variable is not set"}); problems[0] != want {
		t.Errorf("problem %+v; want %+v", problems[0], want)
	}
	p := problems[1]
	if want := (Problem{File: cfgFile, Line: 5, Path: "webhooks[0].key", Text: "the secret file cannot be read: it does not exist"}); p != want {
		t.Errorf("problem %+v; want %+v", p, want)
	}

	// A relative file is read against the folder of the config.
	path := filepath.Join(dir, "config.json")
	c, ps := Parse(path, []byte(cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": "keys/siem"}`, cfgEnvBeat)))
	if len(ps) > 0 {
		t.Fatal(ps)
	}
	if got := c.Webhooks[0].Key.File; got != filepath.Join(dir, "keys/siem") {
		t.Errorf("the key file is %q, want %q", got, filepath.Join(dir, "keys/siem"))
	}
	_, problems = c.Secrets(cfgEnv(cfgVars()))
	want := "the secret file cannot be read: it does not exist"
	if len(problems) != 1 || problems[0].File != path || problems[0].Text != want {
		t.Errorf("Secrets gave %v; want one problem in %s: %q", problems, path, want)
	}
}

func TestSecretURLIsHTTPSWithAHostAndNoUserName(t *testing.T) {
	for _, u := range []string{"https://hooks.example/x", "https://hooks.example:8443/x?a=b", "https://[fd00::1]/x"} {
		vars := cfgVars()
		vars["OSK_SLACK_URL"], vars["HOOK_URL"], vars["OSK_HEARTBEAT_URL"] = u, u, u
		if _, problems := cfgSecretProblems(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat), vars); len(problems) > 0 {
			t.Errorf("URL %q gave %v", u, problems)
		}
	}
	for _, u := range []string{
		"http://hooks.example/x", "https://user@hooks.example/x", "https://u:p@hooks.example/x",
		"https:///x", "hooks.example/x", "ftp://hooks.example/x", "https://hooks.ex%zzample/x", "https:hooks.example",
	} {
		for _, place := range []struct {
			name string
			line int
			path string
		}{{"OSK_SLACK_URL", 4, "slack.url"}, {"HOOK_URL", 5, "webhooks[0].url"}, {"OSK_HEARTBEAT_URL", 6, "heartbeat.url"}} {
			vars := cfgVars()
			vars[place.name] = u
			cfgSecretRefused(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat), vars, cfgAt(place.line, place.path, cfgWantURL))
		}
	}
	// A key is not a URL.
	vars := cfgVars()
	vars["HOOK_KEY"] = "http://this is a key of more than 32 octets"
	if _, problems := cfgSecretProblems(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat), vars); len(problems) > 0 {
		t.Errorf("a key that looks like a URL gave %v", problems)
	}
}

func TestWebhookKeyHasAtLeast32Octets(t *testing.T) {
	text := cfgSecretDoc(cfgEnvSlack, cfgEnvURL, cfgEnvKey, cfgEnvBeat)
	vars := cfgVars()
	vars["HOOK_KEY"] = strings.Repeat("k", 31)
	cfgSecretRefused(t, text, vars, cfgAt(5, "webhooks[0].key", "the key is shorter than 32 octets"))
	vars["HOOK_KEY"] = "a"
	cfgSecretRefused(t, text, vars, cfgAt(5, "webhooks[0].key", "the key is shorter than 32 octets"))
	vars["HOOK_KEY"] = strings.Repeat("k", 32)
	if v, problems := cfgSecretProblems(t, text, vars); len(problems) > 0 || string(v.WebhookKeys[0]) != vars["HOOK_KEY"] {
		t.Errorf("a key of 32 octets gave %q and %v", v.WebhookKeys, problems)
	}
	// The length counts after the line end is removed.
	keyFile := filepath.Join(t.TempDir(), "key")
	cfgWrite(t, keyFile, strings.Repeat("k", 31)+"\n")
	cfgSecretRefused(t, cfgSecretDoc(cfgEnvSlack, cfgEnvURL, `{"file": `+cfgQuote(t, keyFile)+`}`, cfgEnvBeat), cfgVars(),
		cfgAt(5, "webhooks[0].key", "the key is shorter than 32 octets"))
}

// A problem of a secret is at the line of its key, even when its value
// starts on a later line.
func TestSecretProblemIsAtTheLineOfItsKey(t *testing.T) {
	text := strings.Join([]string{
		`{`,
		cfgState + `,`,
		cfgDomains + `,`,
		`"slack": {"url":`,
		`{"env": "OSK_SLACK_URL"}},`,
		`"webhooks": [{"name": "siem",`,
		`"url": {"env": "HOOK_URL"},`,
		`"key":`,
		`  {"env": "HOOK_KEY"}}]`,
		`}`,
	}, "\n")
	cfgSecretRefused(t, text, nil,
		cfgAt(4, "slack.url", "the environment variable is not set"),
		cfgAt(7, "webhooks[0].url", "the environment variable is not set"),
		cfgAt(8, "webhooks[0].key", "the environment variable is not set"))
}

// cfgLeak reports whether s shows secret in any form that fmt prints: as
// text, as decimal or hexadecimal octets, or as a hex string.
func cfgLeak(s, secret string) bool {
	b := []byte(secret)
	decimal := strings.Trim(fmt.Sprint(b), "[]")
	goHex := strings.TrimSuffix(strings.TrimPrefix(fmt.Sprintf("%#v", b), "[]byte{"), "}")
	return strings.Contains(s, secret) || strings.Contains(s, decimal) || strings.Contains(s, goHex) ||
		strings.Contains(s, fmt.Sprintf("%x", b)) || strings.Contains(s, fmt.Sprintf("%X", b))
}

// cfgMarkers are the parts of the secret values that no output may show.
var cfgMarkers = []string{"zq1slackmark", "zq2hookurlmark", "zq3hookkeymark", "zq4beatmark"}

// cfgMarkedSecrets gives a parsed config whose four secrets hold the
// markers, the URL of the webhook from a file, and their Values.
func cfgMarkedSecrets(t *testing.T) (*Config, Values) {
	t.Helper()
	urlFile := filepath.Join(t.TempDir(), "url")
	cfgWrite(t, urlFile, "https://siem.example/"+cfgMarkers[1]+"\n")
	c := cfgOK(t, cfgSecretDoc(cfgEnvSlack, `{"file": `+cfgQuote(t, urlFile)+`}`, cfgEnvKey, cfgEnvBeat))
	v, problems := c.Secrets(cfgEnv(map[string]string{
		"OSK_SLACK_URL":     "https://hooks.slack.example/services/T0/B0/" + cfgMarkers[0],
		"HOOK_KEY":          cfgMarkers[2] + strings.Repeat("k", 32),
		"OSK_HEARTBEAT_URL": "https://beat.example/" + cfgMarkers[3],
	}))
	if len(problems) > 0 {
		t.Fatalf("Secrets: %v", problems)
	}
	if !strings.Contains(v.SlackURL, cfgMarkers[0]) || !strings.Contains(v.WebhookURLs[0], cfgMarkers[1]) ||
		!strings.Contains(string(v.WebhookKeys[0]), cfgMarkers[2]) || !strings.Contains(v.HeartbeatURL, cfgMarkers[3]) {
		t.Fatalf("Values do not hold the values given")
	}
	return c, v
}

// cfgNoLeak fails when any print of each value with each verb shows a marker.
func cfgNoLeak(t *testing.T, verbs []string, values map[string]any) {
	t.Helper()
	for name, value := range values {
		for _, verb := range verbs {
			s := fmt.Sprintf(verb, value)
			for _, m := range cfgMarkers {
				if cfgLeak(s, m) {
					t.Errorf("%s of %s shows the secret %s: %s", verb, name, m, s)
				}
			}
		}
	}
}

func TestSecretValueIsInNoProblemAndNoPrint(t *testing.T) {
	c, v := cfgMarkedSecrets(t)
	if v.String() != "[hidden]" {
		t.Errorf("Values.String() = %q; want [hidden]", v.String())
	}
	for _, verb := range []string{"%v", "%+v", "%s"} {
		for name, value := range map[string]any{"Values": v, "*Values": &v} {
			if got := fmt.Sprintf(verb, value); got != "[hidden]" {
				t.Errorf("%s of %s = %q; want [hidden]", verb, name, got)
			}
		}
	}
	// The config keeps names and paths only, also after Secrets ran.
	all := []string{"%v", "%+v", "%#v", "%s"}
	cfgNoLeak(t, all, map[string]any{
		"*Config": c, "Config": *c, "Slack": *c.Slack, "Webhooks": c.Webhooks, "Webhook": c.Webhooks[0],
		"Heartbeat": *c.Heartbeat, "Secret": c.Webhooks[0].Key, "Domains": c.Domains,
	})

	// Values that are refused are not shown either.
	keyFile := filepath.Join(t.TempDir(), "key")
	cfgWrite(t, keyFile, cfgMarkers[2])
	urlFile := filepath.Join(t.TempDir(), "url")
	cfgWrite(t, urlFile, "ftp://siem.example/"+cfgMarkers[1])
	text := cfgSecretDoc(cfgEnvSlack, `{"file": `+cfgQuote(t, urlFile)+`}`, `{"file": `+cfgQuote(t, keyFile)+`}`, cfgEnvBeat)
	_, problems := cfgSecretProblems(t, text, map[string]string{
		"OSK_SLACK_URL":     "http://hooks.slack.example/services/T0/B0/" + cfgMarkers[0],
		"OSK_HEARTBEAT_URL": "https://u:" + cfgMarkers[3] + "@beat.example/",
	})
	if len(problems) != 4 {
		t.Errorf("Secrets gave %v; want four problems", problems)
	}
	texts := map[string]any{"problems": problems}
	for i, p := range problems {
		texts[fmt.Sprintf("problem %d text", i)] = p.Text
		texts[fmt.Sprintf("problem %d", i)] = p.String()
	}
	cfgNoLeak(t, all, texts)
}

// %#v and %d print a struct field by field unless the type formats itself,
// so String alone would not hide the values from them.
func TestValuesPrintHiddenWithEveryVerb(t *testing.T) {
	_, v := cfgMarkedSecrets(t)
	for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%d"} {
		for name, value := range map[string]any{"Values": v, "*Values": &v} {
			if got := fmt.Sprintf(verb, value); got != "[hidden]" {
				t.Errorf("%s of %s = %q; want [hidden]", verb, name, got)
			}
		}
	}
	cfgNoLeak(t, []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%T"},
		map[string]any{"Values": v, "*Values": &v, "[]Values": []Values{v}, "struct": struct{ V Values }{v}})
}

// Parse reads no secret and no expectations file, so a config with a
// problem gives that problem only, though its variable is not set and its
// files do not exist.
func TestNothingIsReadWhileTheConfigHasProblems(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("OSK_CFG_TEST_UNSET", "")
	if err := os.Unsetenv("OSK_CFG_TEST_UNSET"); err != nil {
		t.Fatal(err)
	}
	t.Setenv("OSK_CFG_TEST_SET", "https://hooks.example/"+cfgMarkers[0])
	members := []string{cfgState,
		`"domains": [{"name": "corp.test.", "expect": ` + cfgQuote(t, filepath.Join(dir, "missing.expect")) + `}]`,
		`"slack": {"url": {"env": "OSK_CFG_TEST_UNSET"}}`,
		`"webhooks": [{"name": "siem", "url": {"file": ` + cfgQuote(t, filepath.Join(dir, "missing_url")) + `}, "key": {"env": "OSK_CFG_TEST_SET"}}]`,
	}
	faulty := cfgDoc(append(members, `"history_days": 0`)...)
	cfgRefused(t, faulty, cfgAt(6, "history_days", "want 1 to 3650"))

	path := filepath.Join(dir, "config.json")
	cfgWrite(t, path, faulty)
	c, problems := Read(path)
	if c != nil || len(problems) != 1 || problems[0] != (Problem{File: path, Line: 6, Path: "history_days", Text: "want 1 to 3650"}) {
		t.Errorf("Read gave config %v and problems %+v; want the history_days problem only", c, problems)
	}

	// Without the fault the config is valid: Parse does not judge secrets.
	c = cfgOK(t, cfgDoc(members...))
	// The lookup decides, not the environment, where OSK_CFG_TEST_SET is set.
	_, problems = c.Secrets(cfgEnv(nil))
	if len(problems) != 3 {
		t.Fatalf("Secrets gave %v; want three problems", problems)
	}
	slices.SortFunc(problems, func(a, b Problem) int { return strings.Compare(a.Path, b.Path) })
	if want := (Problem{File: cfgFile, Line: 4, Path: "slack.url", Text: "the environment variable is not set"}); problems[0] != want {
		t.Errorf("problem %+v; want %+v", problems[0], want)
	}
	if want := (Problem{File: cfgFile, Line: 5, Path: "webhooks[0].key", Text: "the environment variable is not set"}); problems[1] != want {
		t.Errorf("problem %+v; want %+v", problems[1], want)
	}
	if p := problems[2]; p.Line != 5 || p.Path != "webhooks[0].url" || p.Text != "the secret file cannot be read: it does not exist" {
		t.Errorf("problem %+v; want the missing URL file", p)
	}
}

func TestHostsAreTheURLHostsInConfigOrderOnce(t *testing.T) {
	text := cfgDoc(cfgState, cfgDomains, cfgSlack,
		`"webhooks": [{"name": "a", "url": {"env": "A_URL"}, "key": {"env": "KEY"}}, `+
			`{"name": "b", "url": {"env": "B_URL"}, "key": {"env": "KEY"}}, `+
			`{"name": "c", "url": {"env": "C_URL"}, "key": {"env": "KEY"}}, `+
			`{"name": "d", "url": {"env": "D_URL"}, "key": {"env": "KEY"}}]`,
		`"heartbeat": {"url": {"env": "BEAT_URL"}}`)
	v, problems := cfgSecretProblems(t, text, map[string]string{
		"OSK_SLACK_URL": "https://Hooks.Example/services/T0/B0/x",
		"A_URL":         "https://siem.example:8443/a",
		"B_URL":         "https://hooks.example:443/b",
		"C_URL":         "https://[FD00::1]:8443/c",
		"D_URL":         "https://other.example/d",
		"KEY":           strings.Repeat("k", 32),
		"BEAT_URL":      "https://beat.example/x",
	})
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	want := []string{"hooks.example:443", "siem.example:8443", "[fd00::1]:8443", "other.example:443", "beat.example:443"}
	if got := v.Hosts(); !slices.Equal(got, want) {
		t.Errorf("Hosts() = %q; want %q", got, want)
	}

	v, problems = cfgSecretProblems(t, cfgDoc(cfgState, cfgDomains, cfgHooks("siem"), `"heartbeat": {"url": {"env": "BEAT_URL"}}`),
		map[string]string{"HOOK_URL": "https://siem.example/x", "HOOK_KEY": strings.Repeat("k", 32), "BEAT_URL": "https://SIEM.example/beat"})
	if len(problems) > 0 {
		t.Fatal(problems)
	}
	if got := v.Hosts(); !slices.Equal(got, []string{"siem.example:443"}) {
		t.Errorf("Hosts() = %q; want [siem.example:443]", got)
	}
}

// cfgDomain parses a config whose one domain is name with its file at path.
func cfgDomain(t *testing.T, name, path string) Domain {
	t.Helper()
	c := cfgOK(t, cfgDoc(cfgState, `"domains": [{"name": `+cfgQuote(t, name)+`, "expect": `+cfgQuote(t, path)+`}]`, cfgSlack))
	return c.Domains[0]
}

func TestDomainReadGivesTheParsedFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corp.expect")
	data := "# corp\ndomain corp.test.\ncorp.test. NS ns1.corp.test. | ns2.corp.test.\nwww.corp.test. A 10.53.0.81\n"
	cfgWrite(t, path, data)
	want, err := expect.Parse([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	f, problems := cfgDomain(t, "corp.test.", path).Read()
	if len(problems) > 0 || f == nil {
		t.Fatalf("Read gave file %v and problems %v", f, problems)
	}
	if f.String() != want.String() {
		t.Errorf("Read gave\n%s\nwant\n%s", f.String(), want.String())
	}
	// Names compare without case, as everywhere in DNS.
	if _, problems := cfgDomain(t, "CORP.Test.", path).Read(); len(problems) > 0 {
		t.Errorf("the name CORP.Test. and the domain line corp.test. gave %v", problems)
	}
}

func TestDomainLineMustEqualTheConfigName(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corp.expect")
	cfgWrite(t, path, "# not corp\ndomain shop.test.\nshop.test. DS none\n")
	_, problems := cfgDomain(t, "corp.test.", path).Read()
	want := Problem{File: path, Line: 2, Text: "the file is for shop.test., not corp.test."}
	if len(problems) != 1 || problems[0] != want {
		t.Fatalf("Read gave %+v; want %+v", problems, want)
	}
	if got := problems[0].String(); got != path+":2: the file is for shop.test., not corp.test." {
		t.Errorf("String() = %q", got)
	}
}

func TestDomainReadGivesTheProblemsOfTheFileWithTheirLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corp.expect")
	d := cfgDomain(t, "corp.test.", path)
	for _, data := range []string{
		"domain corp.test.\nwww A 10.0.0.1\nwww.corp.test. A 10.0.0.1\nwww.corp.test. A 10.0.0.2\n",
		"",
		"# only a comment\n",
		"domain corp.test.\r\ncorp.test. DS none\n",
	} {
		cfgWrite(t, path, data)
		_, err := expect.Parse([]byte(data))
		var e *expect.Error
		if !errors.As(err, &e) {
			t.Fatalf("expect.Parse(%q) gave %v", data, err)
		}
		var want []Problem
		for _, p := range e.Problems {
			want = append(want, Problem{File: path, Line: p.Line, Text: p.Text})
		}
		if _, got := d.Read(); !slices.Equal(got, want) {
			t.Errorf("Read of %q gave %+v; want %+v", data, got, want)
		}
	}
}

func TestDomainReadNamesAFileThatCannotBeRead(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.expect")
	f, problems := cfgDomain(t, "corp.test.", path).Read()
	if f != nil || len(problems) != 1 {
		t.Fatalf("Read gave file %v and problems %v; want one problem", f, problems)
	}
	if p := problems[0]; p.File != path || p.Line != 0 || p.Path != "" || !strings.HasPrefix(p.Text, "cannot be read: ") {
		t.Errorf("Read gave %+v; want %s, no line, cannot be read: <err>", p, path)
	}
}

// The file is read as osk-dns-watcher check reads it: up to the size that expect.Parse
// takes, and one octet more so that Parse can tell a larger one.
func TestDomainReadTakesFilesUpToTheLimitOfTheFormat(t *testing.T) {
	path := filepath.Join(t.TempDir(), "corp.expect")
	d := cfgDomain(t, "corp.test.", path)
	head := "domain corp.test.\ncorp.test. DS none\n"
	const limit = 4194304
	data := head + "#" + strings.Repeat("x", limit-len(head)-2) + "\n"
	cfgWrite(t, path, data)
	if f, problems := d.Read(); len(problems) > 0 || f == nil {
		t.Errorf("a file of %d octets gave %v", len(data), problems)
	}
	cfgWrite(t, path, data+"\n")
	want := []Problem{{File: path, Text: "the file is larger than 4194304 octets"}}
	if _, problems := d.Read(); !slices.Equal(problems, want) {
		t.Errorf("a file of %d octets gave %+v; want %+v", len(data)+1, problems, want)
	}
}

// cfgSlot is a line of cfgEvery that holds one member, and the values that
// break it. A required member is never the first of its object.
type cfgSlot struct {
	line    int    // 1-based
	obj     string // the path of the object that holds the member
	objLine int    // the line of that object's "{"
	need    bool   // required
	bad     []cfgBad
}

// cfgBad is a value of the wrong type or one step past a limit, the part of
// the path that it adds to the member's own path, and its problem text.
type cfgBad struct {
	value, at, text string
}

var cfgSlots = []cfgSlot{
	{line: 2, obj: "", objLine: 1, bad: []cfgBad{{`"3650"`, "", "want an integer"}, {`3650.0`, "", "want an integer"},
		{`3.65e3`, "", "want an integer"}, {`3651`, "", "want 1 to 3650"}, {`0`, "", "want 1 to 3650"}}},
	{line: 3, obj: "", objLine: 1, need: true, bad: []cfgBad{{`5`, "", "want a string"}, {`""`, "", "want a path"},
		{`"st#ate"`, "", "a folder name with ? or # cannot be used"}}},
	{line: 4, obj: "", objLine: 1, bad: []cfgBad{{`3600`, "", "want a string"}, {`"720h0m0.000000001s"`, "", cfgWantRemind},
		{`"59m59.999999999s"`, "", cfgWantRemind}, {`"soon"`, "", `"soon" is not a duration`}}},
	{line: 7, obj: "domains[0]", objLine: 6, bad: []cfgBad{{`{}`, "", "want a list"}, {`[5]`, "[0]", "want a string"},
		{`["login.example.com"]`, "[0]", `"login.example.com" has no trailing dot`},
		{cfgList(101, func(i int) string { return fmt.Sprintf("n%d.example.com.", i) }), "", "want at most 100 fast names"}}},
	{line: 8, obj: "domains[0]", objLine: 6, need: true, bad: []cfgBad{{`5`, "", "want a string"},
		{`"example.com"`, "", `"example.com" has no trailing dot`}, {`"."`, "", "the root cannot be watched"}}},
	{line: 9, obj: "domains[0]", objLine: 6, need: true, bad: []cfgBad{{`""`, "", "want a path"}, {`[]`, "", "want a string"}}},
	{line: 12, obj: "domains[1]", objLine: 11, bad: []cfgBad{{`null`, "", "want a list"}}},
	{line: 13, obj: "domains[1]", objLine: 11, need: true, bad: []cfgBad{{`true`, "", "want a string"}}},
	{line: 14, obj: "domains[1]", objLine: 11, need: true, bad: []cfgBad{{`{}`, "", "want a string"}}},
	{line: 18, obj: "intervals", objLine: 17, bad: []cfgBad{{`"4999ms"`, "", cfgBelow(4999 * time.Millisecond)}, {`15`, "", "want a string"}}},
	{line: 19, obj: "intervals", objLine: 17, bad: []cfgBad{{`"24h0m0.000000001s"`, "", cfgAbove(schedule.Ceiling+1, schedule.Ceiling)}}},
	{line: 20, obj: "intervals", objLine: 17, bad: []cfgBad{{`"-1s"`, "", cfgBelow(-time.Second)}, {`"fast"`, "", `"fast" is not a duration`}}},
	{line: 21, obj: "intervals", objLine: 17, bad: []cfgBad{{`"0"`, "", cfgBelow(0)}}},
	{line: 24, obj: "slack", objLine: 23, bad: []cfgBad{{`"urgent"`, "", cfgWantSev}, {`"High"`, "", cfgWantSev}, {`1`, "", "want a string"}}},
	{line: 25, obj: "slack", objLine: 23, need: true, bad: []cfgBad{{`{"env": 5}`, ".env", "want a string"},
		{`{"env": "osk_slack_url"}`, ".env", cfgWantEnvName},
		{`{"env": "https://hooks.example/T0/B0/x"}`, ".env", cfgWantEnvName},
		{`{"file": ""}`, ".file", "want a path"}}},
	{line: 29, obj: "webhooks[0]", objLine: 28, bad: []cfgBad{{`""`, "", cfgWantSev}}},
	{line: 30, obj: "webhooks[0]", objLine: 28, need: true, bad: []cfgBad{{`"slack"`, "", "the name slack belongs to the Slack channel"},
		{`"Siem"`, "", cfgWantHook}, {`"` + strings.Repeat("s", 33) + `"`, "", cfgWantHook}, {`7`, "", "want a string"}}},
	{line: 31, obj: "webhooks[0]", objLine: 28, need: true, bad: []cfgBad{{`{"file": 5}`, ".file", "want a string"}}},
	{line: 32, obj: "webhooks[0]", objLine: 28, need: true, bad: []cfgBad{{`{"env": "9KEY"}`, ".env", cfgWantEnvName}}},
	{line: 35, obj: "webhooks[1]", objLine: 34, bad: []cfgBad{{`"none"`, "", cfgWantSev}}},
	{line: 36, obj: "webhooks[1]", objLine: 34, need: true, bad: []cfgBad{{`""`, "", cfgWantHook}}},
	{line: 37, obj: "webhooks[1]", objLine: 34, need: true, bad: []cfgBad{{`{"env": ""}`, ".env", cfgWantEnvName}}},
	{line: 38, obj: "webhooks[1]", objLine: 34, need: true, bad: []cfgBad{{`{"file": null}`, ".file", "want a string"}}},
	{line: 42, obj: "heartbeat", objLine: 41, bad: []cfgBad{{`"1h0m0.000000001s"`, "", cfgAbove(time.Hour+1, time.Hour)},
		{`"4s"`, "", cfgBelow(4 * time.Second)}}},
	{line: 43, obj: "heartbeat", objLine: 41, need: true, bad: []cfgBad{{`{"env": "a"}`, ".env", cfgWantEnvName}}},
	{line: 46, obj: "network", objLine: 45, bad: []cfgBad{{`"10.53.0.2"`, "", "want a list"},
		{`["dns.example"]`, "[0]", `"dns.example" is not an IP address with an optional port`},
		{cfgList(17, func(i int) string { return fmt.Sprintf("10.53.0.%d", i+1) }), "", "want at most 16 root servers"}}},
	{line: 47, obj: "network", objLine: 45, bad: []cfgBad{{`["10.53.0.1/24"]`, "[0]", "prefix 10.53.0.1/24 has bits after its length; write 10.53.0.0/24"},
		{`["10.53.0.0"]`, "[0]", `bad prefix "10.53.0.0"`},
		{cfgList(65, func(i int) string { return fmt.Sprintf("10.%d.0.0/16", i) }), "", "want at most 64 ranges"}}},
}

// cfgMutate changes the line of slot s, which is now text, in one way of
// the table: a key renamed, in another case, given twice, a bad value, a
// required member dropped, or an unknown key added. It gives the new line
// and the problems that the change must cause.
func cfgMutate(r *rand.Rand, s cfgSlot, text string) (string, []cfgP) {
	rest, first := strings.CutPrefix(text, ", ")
	lead := ""
	if first {
		lead = ", "
	}
	key, value, _ := strings.Cut(strings.TrimPrefix(rest, `"`), `": `)
	member := func(k, v string) string { return fmt.Sprintf("%q: %s", k, v) }
	path := cfgJoin(s.obj, key)
	var missing []cfgP
	if s.need {
		missing = []cfgP{cfgRequired(s.objLine, s.obj, key)}
	}
	kinds := []string{"rename", "case", "twice", "unknown", "bad"}
	if s.need {
		kinds = append(kinds, "drop")
	}
	switch kinds[r.IntN(len(kinds))] {
	case "rename":
		k := key + "x"
		return lead + member(k, value), append(missing, cfgUnknown(s.line, s.obj, k))
	case "case":
		k := strings.ToUpper(key[:1]) + key[1:]
		return lead + member(k, value), append(missing, cfgUnknown(s.line, s.obj, k))
	case "twice":
		return lead + member(key, value) + ", " + member(key, value), []cfgP{cfgTwice(s.line, s.obj, key)}
	case "unknown":
		// One unknown key per line, so that two in one object are not one key
		// given twice.
		k := fmt.Sprintf("zz%d", s.line)
		return lead + member(key, value) + ", " + member(k, `[1, {"a": null}]`), []cfgP{cfgUnknown(s.line, s.obj, k)}
	case "drop":
		return "", missing
	}
	b := s.bad[r.IntN(len(s.bad))]
	return lead + member(key, b.value), []cfgP{cfgAt(s.line, path+b.at, b.text)}
}

// TestConfigProperty: a valid config with every key and 0 to 5 mutations
// on distinct lines. No mutation gives no problem and the config written;
// else no config, and exactly the problems of the mutations, at their lines
// and paths, with their texts, however the lines are indented and ended.
func TestConfigProperty(t *testing.T) {
	want := cfgEveryWant(t)
	failed := 0
	for i := range 1500 {
		r := rand.New(rand.NewPCG(cfgSeed, uint64(i)))
		lines := slices.Clone(cfgEvery)
		var expected []cfgP
		n := r.IntN(6)
		for _, k := range r.Perm(len(cfgSlots))[:n] {
			s := cfgSlots[k]
			var ps []cfgP
			lines[s.line-1], ps = cfgMutate(r, s, lines[s.line-1])
			expected = append(expected, ps...)
		}
		for j := range lines {
			lines[j] = strings.Repeat(" \t"[r.IntN(2):][:1], r.IntN(3)) + lines[j]
		}
		eol := "\n"
		if r.IntN(2) == 0 {
			eol = "\r\n"
		}
		text := strings.Join(lines, eol) + eol
		c, got := Parse(cfgFile, []byte(text))
		var diffs []string
		switch {
		case n == 0 && (c == nil || len(got) > 0):
			diffs = append(diffs, fmt.Sprintf("no mutation gave config %v and problems %v", c, got))
		case n == 0:
			diffs = cfgDiff(c, want)
		default:
			if c != nil {
				diffs = append(diffs, "a config came with the problems")
			}
			diffs = append(diffs, cfgMatch(cfgFile, got, expected)...)
		}
		if len(got) > 100 {
			diffs = append(diffs, fmt.Sprintf("%d problems; want at most 100", len(got)))
		}
		if !slices.IsSortedFunc(got, func(a, b Problem) int { return a.Line - b.Line }) {
			diffs = append(diffs, "the problems are not sorted by line")
		}
		if len(diffs) > 0 {
			t.Errorf("seed %d, case %d, %d mutations:\n%s\n%s", cfgSeed, i, n, text, strings.Join(diffs, "\n"))
			if failed++; failed == 3 {
				t.Fatal("stopped after 3 failing cases")
			}
		}
	}
}

// cfgParseNoPanic runs Parse and turns a panic into a failure that names
// the case.
func cfgParseNoPanic(t *testing.T, data []byte, i int) (c *Config, problems []Problem) {
	t.Helper()
	defer func() {
		if v := recover(); v != nil {
			t.Fatalf("seed %d, case %d: Parse panicked: %v\ninput %q", cfgSeed, i, v, data)
		}
	}()
	return Parse(cfgFile, data)
}

// Damaged text never makes Parse panic, and it gives a config or problems,
// never both, at most 100, each in the file and at a line that it has.
func TestParseNeverPanicsOnDamagedText(t *testing.T) {
	base := []byte(strings.Join(cfgEvery, "\n") + "\n")
	alphabet := []byte("{}[]\":,\\ \n\r\t0123456789.eE+-abfnrtuxEN_\xff\x00\xc3")
	for i := range 3000 {
		r := rand.New(rand.NewPCG(cfgSeed, uint64(i)+1<<32))
		data := slices.Clone(base)
		for range 1 + r.IntN(4) {
			at := r.IntN(len(data) + 1)
			switch r.IntN(5) {
			case 0:
				data = slices.Delete(data, at, min(len(data), at+1+r.IntN(8)))
			case 1:
				data = slices.Insert(data, at, alphabet[r.IntN(len(alphabet))])
			case 2:
				if at < len(data) {
					data[at] = alphabet[r.IntN(len(alphabet))]
				}
			case 3:
				data = data[:at]
			case 4:
				end := min(len(data), at+1+r.IntN(40))
				data = slices.Insert(data, at, data[at:end]...)
			}
		}
		c, problems := cfgParseNoPanic(t, data, i)
		lines := bytes.Count(data, []byte("\n")) + 1
		if (c == nil) == (len(problems) == 0) || len(problems) > 100 {
			t.Fatalf("seed %d, case %d: config %v with %d problems\ninput %q", cfgSeed, i, c, len(problems), data)
		}
		for _, p := range problems {
			if p.File != cfgFile || p.Line < 0 || p.Line > lines || p.Text == "" {
				t.Fatalf("seed %d, case %d: problem %+v in a text of %d lines\ninput %q", cfgSeed, i, p, lines, data)
			}
		}
	}
}
