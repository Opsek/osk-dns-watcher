// Package config reads the one config file of osk: strict JSON, with every
// problem named by its line and key path. The file never holds a secret: it
// names an environment variable or a file for each, and Secrets reads them
// only once the config is valid.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/schedule"
	"github.com/Opsek/dns-monitoring/internal/sources/certlog"
)

const (
	maxFileSize    = 1048576
	maxDomains     = 100
	maxFast        = 100
	maxWebhooks    = 8
	maxWebhookName = 32
	maxRootServers = 16
	maxRanges      = 64
	maxHistoryDays = 3650
	minBeat        = 5 * time.Second
	maxBeat        = time.Hour
	minRemind      = time.Hour
	maxRemind      = 720 * time.Hour

	// The source asks for its own gap between two polls; this is the gap
	// when it asks for none.
	defaultCertificatesInterval = 10 * time.Minute
)

type Secret struct {
	Env, File string // exactly one is set; File is absolute
	Path      string // "slack.url", "webhooks[1].key", …
	Line      int
}

type Domain struct {
	Name   dnswire.Name
	Expect string // absolute
	Fast   []dnswire.Name
	Line   int // the line of the entry's {
}

type Slack struct {
	URL         Secret
	MinSeverity decide.Severity
}

type Webhook struct {
	Name        string
	URL, Key    Secret
	MinSeverity decide.Severity
}

type Heartbeat struct {
	URL      Secret
	Interval time.Duration
}

// Certificates is the optional read of the certificate logs.
type Certificates struct {
	URL      string
	Key      *Secret // nil: none
	Interval time.Duration
}

type Config struct {
	Path         string // the config file as given
	State        string // absolute
	Domains      []Domain
	Intervals    schedule.Intervals
	Slack        *Slack // nil: none
	Webhooks     []Webhook
	Heartbeat    *Heartbeat    // nil: none
	Certificates *Certificates // nil: the certificate logs are not read
	HistoryDays  int
	Remind       time.Duration
	RootServers  []netip.AddrPort // port 0: 53
	ExtraRanges  []netip.Prefix
}

type Problem struct {
	File       string
	Line       int
	Path, Text string
}

// String gives "<file>:<line>: <path>: <text>", without the line when it
// is 0 and without the path when it is empty.
func (p Problem) String() string {
	s := p.File
	if p.Line != 0 {
		s += ":" + strconv.Itoa(p.Line)
	}
	if p.Path != "" {
		s += ": " + p.Path
	}
	return s + ": " + p.Text
}

// Parse reads a config; path names the file in the problems and anchors
// relative paths. The Config is nil when there is a problem.
func Parse(path string, data []byte) (*Config, []Problem) {
	if p, bad := fileProblem(path, data); bad {
		return nil, []Problem{p}
	}
	w := newWalker(path, folder(path), data)
	c := w.config()
	if len(w.problems) > 0 {
		sortProblems(w.problems)
		return nil, w.problems
	}
	return c, nil
}

// fileProblem gives the problem of a file that cannot be walked at all.
func fileProblem(path string, data []byte) (Problem, bool) {
	if len(data) > maxFileSize {
		return Problem{File: path, Text: fmt.Sprintf("the file is larger than %d octets", maxFileSize)}, true
	}
	// The decoder would silently turn a bad octet into U+FFFD.
	if !utf8.Valid(data) {
		return Problem{File: path, Text: "the file is not valid UTF-8"}, true
	}
	// Unmarshal checks the whole input before it decodes, and gives a
	// *json.SyntaxError with an offset for every fault; the decoder's tokens
	// give none for a cut-off file and none for text after the top value.
	var syntax *json.SyntaxError
	if errors.As(json.Unmarshal(data, new(json.RawMessage)), &syntax) {
		return Problem{File: path, Line: newLines(data).at(syntax.Offset), Text: "not valid JSON: " + syntax.Error()}, true
	}
	return Problem{}, false
}

// folder gives the absolute folder of the config file. Abs reads the
// working folder only when path is relative; if that fails, the folder is
// gone and no relative name could be opened anyway.
func folder(path string) string {
	dir := filepath.Dir(path)
	if abs, err := filepath.Abs(dir); err == nil {
		return abs
	}
	return dir
}

func Read(path string) (*Config, []Problem) {
	data, err := ReadRegular(path, maxFileSize)
	if err != nil {
		return nil, []Problem{ReadProblem(path, err)}
	}
	return Parse(path, data)
}

// ReadProblem is the problem of a file that ReadRegular could not read.
func ReadProblem(file string, err error) Problem {
	if errors.Is(err, ErrNotRegular) {
		return Problem{File: file, Text: err.Error()}
	}
	return Problem{File: file, Text: "cannot be read: " + err.Error()}
}

// ErrNotRegular refuses a FIFO or a device, which can hold whoever opens or
// reads it for ever.
var ErrNotRegular = errors.New("is not a regular file")

// MaxExpectFile is the largest expectations file that expect.Parse takes.
const MaxExpectFile = 4194304

// ReadRegular reads every file that osk reads: at most limit + 1 octets, so
// that the caller can tell a file that is too large without reading all of
// it. Only a regular file is opened; a failed Stat is left to the open, whose
// error names the path.
func ReadRegular(path string, limit int64) ([]byte, error) {
	if info, err := os.Stat(path); err == nil && !info.Mode().IsRegular() {
		return nil, ErrNotRegular
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(io.LimitReader(f, limit+1))
	_ = f.Close() // the file was only read, so closing it can lose nothing
	return data, err
}

// Channels gives the channel names: "slack" when it is set, then the
// webhooks in config order.
func (c *Config) Channels() []string {
	var names []string
	if c.Slack != nil {
		names = append(names, "slack")
	}
	for _, h := range c.Webhooks {
		names = append(names, h.Name)
	}
	return names
}

func (w *walker) config() *Config {
	c := &Config{Path: w.file, Intervals: schedule.Defaults(), HistoryDays: 90}
	seen, at := w.object("", fields{
		"state":     func(p string, _ int64) { c.State = w.state(p) },
		"domains":   func(p string, _ int64) { c.Domains = w.domains(p) },
		"intervals": func(p string, _ int64) { w.intervals(p, &c.Intervals) },
		"slack":     func(p string, _ int64) { c.Slack = w.slack(p) },
		"webhooks":  func(p string, _ int64) { c.Webhooks = w.webhooks(p) },
		"heartbeat": func(p string, _ int64) { c.Heartbeat = w.heartbeat(p) },
		"certificates": func(p string, _ int64) {
			c.Certificates = w.certificates(p)
			c.Intervals.Certificates = c.Certificates.Interval
		},
		"history_days": func(p string, _ int64) { c.HistoryDays = w.days(p) },
		"remind":       func(p string, _ int64) { c.Remind = w.remind(p) },
		"network":      func(p string, _ int64) { w.network(p, c) },
	}, "state", "domains")
	// seen is nil when the file holds no object, which is reported already.
	// A slack key or a webhook entry with a fault of its own still counts,
	// so that one fault is not reported twice.
	if seen != nil && !seen["slack"] && len(c.Webhooks) == 0 {
		w.add(at, "", "want at least one channel: slack or a webhook")
	}
	return c
}

// state reads the state folder. The store opens its database by a URI, in
// which ? or # would start the query or the fragment.
func (w *walker) state(path string) string {
	dir, at, ok := w.filePath(path)
	if ok && strings.ContainsAny(dir, "?#") {
		w.add(at, path, "a folder name with ? or # cannot be used")
	}
	return dir
}

// filePath reads a file or folder name. A relative one is read against the
// folder of the config file, so that it does not depend on where osk was
// started. A URL there may be a secret pasted into the wrong field, so the
// problem does not repeat it.
func (w *walker) filePath(path string) (string, int64, bool) {
	s, at, ok := w.str(path)
	switch {
	case !ok:
		return "", at, false
	case s == "":
		w.add(at, path, "want a path")
		return "", at, false
	case strings.Contains(s, "://"):
		w.add(at, path, "a path is expected here, not a URL")
		return "", at, false
	case filepath.IsAbs(s):
		return s, at, true
	}
	return filepath.Join(w.dir, s), at, true
}

func (w *walker) domains(path string) []Domain {
	var domains []Domain
	names := map[string]bool{} // by Name.Key, so case does not count
	n, at, ok := w.list(path, func(p string) { domains = append(domains, w.domain(p, names)) })
	if ok && (n < 1 || n > maxDomains) {
		w.add(at, path, fmt.Sprintf("want 1 to %d domains", maxDomains))
	}
	return domains
}

func (w *walker) domain(path string, names map[string]bool) Domain {
	var d Domain
	_, at := w.object(path, fields{
		"name":   func(p string, _ int64) { d.Name = w.domainName(p, names) },
		"expect": func(p string, _ int64) { d.Expect, _, _ = w.filePath(p) },
		"fast":   func(p string, _ int64) { d.Fast = w.fast(p) },
	}, "name", "expect")
	d.Line = w.lines.at(at)
	return d
}

func (w *walker) domainName(path string, names map[string]bool) dnswire.Name {
	n, at, ok := w.name(path)
	switch {
	case !ok:
	case n.LabelCount() == 0:
		w.add(at, path, "the root cannot be watched")
	case names[n.Key()]:
		w.add(at, path, fmt.Sprintf("domain %s is listed twice", shown(n.String())))
	default:
		names[n.Key()] = true
	}
	return n
}

func (w *walker) fast(path string) []dnswire.Name {
	var names []dnswire.Name
	n, at, ok := w.list(path, func(p string) {
		if name, _, ok := w.name(p); ok {
			names = append(names, name)
		}
	})
	if ok && n > maxFast {
		w.add(at, path, fmt.Sprintf("want at most %d fast names", maxFast))
	}
	return names
}

// name reads a name with its trailing dot. Without the rule, "www" meant
// as "www.example.com." would be read as a name under the root.
func (w *walker) name(path string) (dnswire.Name, int64, bool) {
	s, at, ok := w.str(path)
	if !ok {
		return dnswire.Name{}, at, false
	}
	if !hasTrailingDot(s) {
		w.add(at, path, fmt.Sprintf("%q has no trailing dot", shown(s)))
		return dnswire.Name{}, at, false
	}
	n, err := dnswire.ParseName(s)
	if err != nil {
		w.add(at, path, fmt.Sprintf("bad name %q: %v", shown(s), err))
		return dnswire.Name{}, at, false
	}
	return n, at, true
}

// hasTrailingDot reports whether s ends with a dot that no backslash keeps
// in its label.
func hasTrailingDot(s string) bool {
	body, ok := strings.CutSuffix(s, ".")
	return ok && (len(body)-len(strings.TrimRight(body, `\`)))%2 == 0
}

func (w *walker) intervals(path string, iv *schedule.Intervals) {
	w.object(path, fields{
		"serial": func(p string, _ int64) { iv.Serial = w.interval(p, schedule.Floor, schedule.Ceiling) },
		"parent": func(p string, _ int64) { iv.Parent = w.interval(p, schedule.Floor, schedule.Ceiling) },
		"fast":   func(p string, _ int64) { iv.Fast = w.interval(p, schedule.Floor, schedule.Ceiling) },
		"other":  func(p string, _ int64) { iv.Other = w.interval(p, schedule.Floor, schedule.Ceiling) },
	})
}

func (w *walker) interval(path string, floor, ceiling time.Duration) time.Duration {
	d, at, ok := w.duration(path)
	switch {
	case !ok:
	case d < floor:
		w.add(at, path, fmt.Sprintf("%v is below the floor of %v", d, floor))
	case d > ceiling:
		w.add(at, path, fmt.Sprintf("%v is above %v", d, ceiling))
	}
	return d
}

// duration reads a duration in the form of Go, such as "90s" or "5m".
func (w *walker) duration(path string) (time.Duration, int64, bool) {
	s, at, ok := w.str(path)
	if !ok {
		return 0, at, false
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		w.add(at, path, fmt.Sprintf("%q is not a duration", shown(s)))
		return 0, at, false
	}
	return d, at, true
}

// remind reads the time between reminders of an open alert; 0 turns them
// off.
func (w *walker) remind(path string) time.Duration {
	d, at, ok := w.duration(path)
	if ok && d != 0 && (d < minRemind || d > maxRemind) {
		w.add(at, path, fmt.Sprintf("want 0s, or %v to %v", minRemind, maxRemind))
	}
	return d
}

func (w *walker) days(path string) int {
	s, at, ok := w.integer(path)
	if !ok {
		return 0
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 || n > maxHistoryDays {
		w.add(at, path, fmt.Sprintf("want 1 to %d", maxHistoryDays))
	}
	return n
}

func (w *walker) severity(path string) decide.Severity {
	s, at, ok := w.str(path)
	if !ok {
		return 0
	}
	for v := decide.SeverityLow; v <= decide.SeverityCritical; v++ {
		if v.String() == s {
			return v
		}
	}
	w.add(at, path, "want low, medium, high or critical")
	return 0
}

func (w *walker) slack(path string) *Slack {
	s := &Slack{MinSeverity: decide.SeverityLow}
	w.object(path, fields{
		"url":          func(p string, keyAt int64) { s.URL = w.secret(p, keyAt) },
		"min_severity": func(p string, _ int64) { s.MinSeverity = w.severity(p) },
	}, "url")
	return s
}

func (w *walker) webhooks(path string) []Webhook {
	var hooks []Webhook
	names := map[string]bool{}
	n, at, ok := w.list(path, func(p string) { hooks = append(hooks, w.webhook(p, names)) })
	if ok && n > maxWebhooks {
		w.add(at, path, fmt.Sprintf("want at most %d webhooks", maxWebhooks))
	}
	return hooks
}

func (w *walker) webhook(path string, names map[string]bool) Webhook {
	h := Webhook{MinSeverity: decide.SeverityLow}
	w.object(path, fields{
		"name":         func(p string, _ int64) { h.Name = w.webhookName(p, names) },
		"url":          func(p string, keyAt int64) { h.URL = w.secret(p, keyAt) },
		"key":          func(p string, keyAt int64) { h.Key = w.secret(p, keyAt) },
		"min_severity": func(p string, _ int64) { h.MinSeverity = w.severity(p) },
	}, "name", "url", "key")
	return h
}

// webhookName reads the name of a webhook, which the store keeps in each
// of its delivery rows and the log lines print.
func (w *walker) webhookName(path string, names map[string]bool) string {
	s, at, ok := w.str(path)
	switch {
	case !ok:
	case !validWebhookName(s):
		w.add(at, path, fmt.Sprintf("want a name of 1 to %d octets of a-z, 0-9 and -", maxWebhookName))
	case s == "slack":
		w.add(at, path, "the name slack belongs to the Slack channel")
	case names[s]:
		w.add(at, path, fmt.Sprintf("webhook %s is listed twice", shown(s)))
	default:
		names[s] = true
	}
	return s
}

func validWebhookName(s string) bool {
	if s == "" || len(s) > maxWebhookName {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '-') {
			return false
		}
	}
	return true
}

func (w *walker) heartbeat(path string) *Heartbeat {
	h := &Heartbeat{Interval: time.Minute}
	w.object(path, fields{
		"url":      func(p string, keyAt int64) { h.URL = w.secret(p, keyAt) },
		"interval": func(p string, _ int64) { h.Interval = w.interval(p, minBeat, maxBeat) },
	}, "url")
	return h
}

func (w *walker) certificates(path string) *Certificates {
	c := &Certificates{URL: certlog.DefaultURL, Interval: defaultCertificatesInterval}
	w.object(path, fields{
		"url":      func(p string, _ int64) { c.URL = w.certificatesURL(p) },
		"key":      func(p string, keyAt int64) { k := w.secret(p, keyAt); c.Key = &k },
		"interval": func(p string, _ int64) { c.Interval = w.interval(p, schedule.Floor, schedule.Ceiling) },
	})
	return c
}

// certificatesURL reads the endpoint of the certificate source. The request
// adds its own query, so one given here would be sent twice. The text holds
// no part of the URL.
func (w *walker) certificatesURL(path string) string {
	s, at, ok := w.str(path)
	if !ok {
		return ""
	}
	if _, err := httpclient.HostOf(s); err != nil || strings.ContainsAny(s, "?#") {
		w.add(at, path, "want an https URL with a host and no query")
	}
	return s
}

func (w *walker) network(path string, c *Config) {
	w.object(path, fields{
		"root_servers": func(p string, _ int64) { c.RootServers = w.rootServers(p) },
		"extra_ranges": func(p string, _ int64) { c.ExtraRanges = w.extraRanges(p) },
	})
}

func (w *walker) rootServers(path string) []netip.AddrPort {
	var servers []netip.AddrPort
	n, at, ok := w.list(path, func(p string) {
		if server, ok := w.rootServer(p); ok {
			servers = append(servers, server)
		}
	})
	if ok && n > maxRootServers {
		w.add(at, path, fmt.Sprintf("want at most %d root servers", maxRootServers))
	}
	return servers
}

// rootServer reads an IP address with an optional port; port 0 stands for
// 53. A host name is refused: resolving it would trust a resolver.
func (w *walker) rootServer(path string) (netip.AddrPort, bool) {
	s, at, ok := w.str(path)
	if !ok {
		return netip.AddrPort{}, false
	}
	if server, err := netip.ParseAddrPort(s); err == nil {
		return server, true
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		w.add(at, path, fmt.Sprintf("%q is not an IP address with an optional port", shown(s)))
		return netip.AddrPort{}, false
	}
	return netip.AddrPortFrom(addr, 0), true
}

func (w *walker) extraRanges(path string) []netip.Prefix {
	var ranges []netip.Prefix
	n, at, ok := w.list(path, func(p string) {
		if prefix, ok := w.extraRange(p); ok {
			ranges = append(ranges, prefix)
		}
	})
	if ok && n > maxRanges {
		w.add(at, path, fmt.Sprintf("want at most %d ranges", maxRanges))
	}
	return ranges
}

// extraRange reads a prefix. One with bits after its length, such as
// 10.0.0.1/8, may mean one address or the whole range, so the writer must
// say which.
func (w *walker) extraRange(path string) (netip.Prefix, bool) {
	s, at, ok := w.str(path)
	if !ok {
		return netip.Prefix{}, false
	}
	prefix, err := netip.ParsePrefix(s)
	switch {
	case err != nil:
		w.add(at, path, fmt.Sprintf("bad prefix %q", shown(s)))
	case prefix != prefix.Masked():
		w.add(at, path, fmt.Sprintf("prefix %s has bits after its length; write %s", prefix, prefix.Masked()))
	default:
		return prefix, true
	}
	return netip.Prefix{}, false
}
