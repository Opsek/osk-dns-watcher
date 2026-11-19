package start

import (
	"context"
	"crypto/x509"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/cli"
	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

const doctorUsage = "usage: osk-dns-watcher doctor --config <file> [--json]\n"

// The texts of the results, in the order doctor gives them.
const (
	textConfigOK   = "%d domains, channels %s"
	textChangeable = "other users can change %s. Run: chmod go-w %s"
	textSecretOpen = "other users can read or change %s, which holds a secret. Run: chmod 600 %s"
	textNotFolder  = "%s is not a folder"
	textFolderOpen = "%s is open to other users. Run: chmod 700 %s"
	textFilesOK    = "no other user can change the config or the expectations, or read the secrets or the state"
	textDNSOK      = "its parent zone answers; osk-dns-watcher found it from the root servers, without this machine's resolver"
	textDNSFail    = "no answer from the root servers or its parent zone (%s). " +
		"osk-dns-watcher asks them itself on port 53, over UDP and TCP: allow that traffic to the internet."
	textSent      = "%s answered %d; a test message from osk-dns-watcher doctor was sent"
	textRefused   = "%s answered %d%s. Check the URL in %s: a deleted or revoked webhook answers like this."
	textUnreached = "no answer from %s: %s. Check that this machine can reach %s over HTTPS."
	textClockOK   = "%v from the time of %s"
	textClockOff  = "this machine is %v %s %s. Set its clock, for example with NTP: webhook signatures and alert times depend on it."
	textNoClock   = "no webhook answered, so there is no outside time to compare with"

	textNoProblems = "doctor: no problems"
	textOneProblem = "doctor: 1 problem"
	textProblems   = "doctor: %d problems"
)

// maxSkew is how far this machine's clock may be from a webhook host's.
const maxSkew = 30 * time.Second

// doctorRoots is the trust store of the HTTPS client: nil is the system's.
// A test sets the authority of its own servers.
var doctorRoots *x509.CertPool

// Doctor runs "osk-dns-watcher doctor": it checks this machine and the setup that osk-dns-watcher run
// would use, and says what to fix. It opens no store, so it runs beside the
// service. The exit code is 0 when no check failed, 1 when one did, 2 on
// wrong use.
func Doctor(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	path, asJSON, msg := parseDoctor(args)
	if msg != "" {
		_, _ = io.WriteString(stderr, "osk-dns-watcher doctor: "+msg+"\n"+doctorUsage)
		return 2
	}
	r := &report{w: stdout, json: asJSON}
	s := readSetup(path)
	proxy, proxied := proxyCheck(ctx, s.config)
	if proxied {
		r.add(proxy)
	}
	r.add(configCheck(s)...)
	if len(s.problems) > 0 {
		return r.end(stderr)
	}
	r.add(filesCheck(s.config)...)
	if !proxied {
		// Through a proxy, an answer about a domain proves nothing.
		r.add(dnsCheck(ctx, s.observer, s.config.Domains)...)
	}
	sends := sendTests(ctx, s.config, s.values)
	for _, sd := range sends {
		r.add(webhookCheck(sd))
	}
	r.add(clockCheck(sends))
	return r.end(stderr)
}

func parseDoctor(args []string) (path string, asJSON bool, msg string) {
	var file *string
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("config", "the config file", func(s string) error {
		if file != nil {
			return errors.New("given more than once")
		}
		file = &s
		return nil
	})
	flags.BoolVar(&asJSON, "json", false, "print JSON Lines")
	if err := flags.Parse(args); err != nil {
		return "", false, err.Error()
	}
	switch {
	case file == nil || *file == "":
		return "", false, "--config is required"
	case flags.NArg() > 0:
		return "", false, "osk-dns-watcher doctor takes no arguments"
	}
	return *file, asJSON, ""
}

// result is one line of the report: "<result> <check>: <text>".
type result struct {
	Type   string `json:"type"`
	Result string `json:"result"` // ok, FAIL, warn or skip
	Check  string `json:"check"`
	Text   string `json:"text"`
}

func newResult(res, check, text string) result {
	return result{Type: "check", Result: res, Check: check, Text: text}
}

// report prints each result as soon as it is known, so a slow check does not
// hide the ones before it. It keeps the first failed write: a report that
// cannot be written is a failure.
type report struct {
	w        io.Writer
	json     bool
	problems int
	err      error
}

func (r *report) add(results ...result) {
	for _, res := range results {
		if res.Result == "FAIL" {
			r.problems++
		}
		r.write(fmt.Sprintf("%-4s %s: %s", res.Result, res.Check, res.Text), res)
	}
}

func (r *report) write(text string, v any) {
	if r.err != nil {
		return
	}
	if r.json {
		r.err = cli.PrintJSON(r.w, v)
		return
	}
	_, r.err = io.WriteString(r.w, text+"\n")
}

// end prints the count of problems and gives the exit code. warn and skip
// are no problems.
func (r *report) end(stderr io.Writer) int {
	text := fmt.Sprintf(textProblems, r.problems)
	switch r.problems {
	case 0:
		text = textNoProblems
	case 1:
		text = textOneProblem
	}
	r.write(text, struct {
		Type     string `json:"type"`
		Problems int    `json:"problems"`
	}{"result", r.problems})
	switch {
	case r.err != nil:
		_, _ = io.WriteString(stderr, "osk-dns-watcher: "+r.err.Error()+"\n")
		return 1
	case r.problems > 0:
		return 1
	}
	return 0
}

// setup is what doctor reads before it asks anything of the network.
type setup struct {
	config   *config.Config // nil when the file is not a valid config
	values   config.Values
	observer *observe.Observer
	problems []config.Problem
}

// readSetup reads the config, its secrets and the expectations as osk-dns-watcher run
// does at its start.
func readSetup(path string) setup {
	c, problems := config.Read(path)
	s := setup{config: c, problems: problems}
	if c == nil {
		return s
	}
	s.values, s.problems = c.Secrets(os.LookupEnv)
	for _, d := range c.Domains {
		_, ps := d.Read()
		s.problems = append(s.problems, ps...)
	}
	var err error
	s.observer, err = observe.New(observe.Config{RootServers: c.RootServers, ExtraRanges: c.ExtraRanges})
	if err != nil {
		// The config takes any IP address as a root server; the observer
		// refuses an unspecified one.
		s.problems = append(s.problems, config.Problem{File: c.Path, Path: "network.root_servers", Text: err.Error()})
	}
	return s
}

// proxyCheck comes first: when the network answers in place of the root
// servers, every DNS answer shows that network, not the internet. proxied is
// false, and there is no result, when the root servers answer themselves.
func proxyCheck(ctx context.Context, c *config.Config) (res result, proxied bool) {
	var roots []netip.AddrPort
	if c != nil {
		roots = c.RootServers
	}
	if rootsAnswerDirectly(ctx, roots) {
		return result{}, false
	}
	// The words of init, on the one line of a result.
	return newResult("FAIL", "dns", strings.ReplaceAll(strings.TrimSuffix(textProxy, "\n"), "\n", " ")), true
}

// configCheck reports every problem; with one, doctor checks nothing else,
// since it would not know which hosts and domains osk-dns-watcher run would use.
func configCheck(s setup) []result {
	var results []result
	for _, p := range s.problems {
		results = append(results, newResult("FAIL", "config", p.String()))
	}
	if len(results) > 0 {
		return results
	}
	c := s.config
	results = append(results, newResult("ok", "config", fmt.Sprintf(textConfigOK, len(c.Domains), strings.Join(c.Channels(), ","))))
	for _, w := range c.Warnings() {
		results = append(results, newResult("warn", "config", w))
	}
	return results
}

// filesCheck reads the mode bits only: telling the owner of a file needs
// syscall, which osk-dns-watcher does not use. A file that cannot be read was reported by
// the config check already.
func filesCheck(c *config.Config) []result {
	var results []result
	add := func(format string, a ...any) {
		results = append(results, newResult("FAIL", "files", fmt.Sprintf(format, a...)))
	}
	for _, path := range append([]string{c.Path}, expectFiles(c)...) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o022 != 0 {
			add(textChangeable, path, path)
		}
	}
	for _, path := range secretFiles(c) {
		if info, err := os.Stat(path); err == nil && info.Mode().Perm()&0o077 != 0 {
			add(textSecretOpen, path, path)
		}
	}
	// A state folder that does not exist yet is no problem: osk-dns-watcher run makes it.
	if info, err := os.Stat(c.State); err == nil {
		switch {
		case !info.IsDir():
			add(textNotFolder, c.State)
		case info.Mode().Perm()&0o077 != 0:
			add(textFolderOpen, c.State, c.State)
		}
	}
	if len(results) == 0 {
		return []result{newResult("ok", "files", textFilesOK)}
	}
	return results
}

func expectFiles(c *config.Config) []string {
	var files []string
	for _, d := range c.Domains {
		files = append(files, d.Expect)
	}
	return files
}

// secretFiles gives the files that hold a secret, in config order.
func secretFiles(c *config.Config) []string {
	var secrets []config.Secret
	if c.Slack != nil {
		secrets = append(secrets, c.Slack.URL)
	}
	for _, h := range c.Webhooks {
		secrets = append(secrets, h.URL, h.Key)
	}
	if c.Heartbeat != nil {
		secrets = append(secrets, c.Heartbeat.URL)
	}
	var files []string
	for _, s := range secrets {
		if s.File != "" {
			files = append(files, s.File)
		}
	}
	return files
}

// dnsCheck asks the parent zone of every domain at once: each check ends by
// itself within its interval, so a domain that gets no answer holds up no
// other. The results keep the config order.
func dnsCheck(ctx context.Context, o *observe.Observer, domains []config.Domain) []result {
	results := make([]result, len(domains))
	var wg sync.WaitGroup
	for i, d := range domains {
		wg.Go(func() { results[i] = dnsResult(d.Name, delegation(ctx, o, d.Name)) })
	}
	wg.Wait()
	return results
}

func delegation(ctx context.Context, o *observe.Observer, domain dnswire.Name) obs.Observation {
	key := obs.DelegationKey(domain)
	ob, err := o.Run(ctx, observe.Check{Key: key, Interval: checkInterval})
	if err != nil {
		// Only a check that is not valid or already running fails, and
		// nothing was sent: it reads as no answer.
		return obs.Observation{Key: key, Answers: []obs.Answer{{}}}
	}
	return ob
}

func dnsResult(domain dnswire.Name, o obs.Observation) result {
	check := "dns " + domain.Lower().String()
	if decide.Failed(o) {
		return newResult("FAIL", check, fmt.Sprintf(textDNSFail, strings.Join(failureWords(o), ",")))
	}
	return newResult("ok", check, textDNSOK)
}

// sent is the test message to one channel and its answer. t0 and t1 bracket
// the request, so on a true clock the answer's Date lies between them.
type sent struct {
	channel string
	host    string // host:port of the URL, which holds no secret
	where   string // where the URL is set: "file <path>" or "the variable <NAME>"
	t0, t1  time.Time
	outcome deliver.Outcome
}

// sendTests sends a test notice through every channel, by the code that
// sends the alerts: a POST is the only way to learn that a webhook answers.
// They go one after another, each within the client's time limit, so a
// receiver that several channels share gets them in channel order. The
// heartbeat gets none: a beat from doctor would tell the outside service that
// osk-dns-watcher run is healthy.
func sendTests(ctx context.Context, c *config.Config, v config.Values) []sent {
	sends := targets(c, v)
	n := store.Notice{Kind: store.NoticeTest, Lines: []string{"from      osk-dns-watcher doctor"}, At: time.Now()}
	for i, ch := range Channels(c, v, httpclient.New(v.Hosts(), doctorRoots)) {
		body := ch.Notice(n)
		sends[i].t0 = time.Now()
		sends[i].outcome = ch.Send(ctx, body)
		sends[i].t1 = time.Now()
	}
	return sends
}

// targets gives, in the order of Channels, each channel with the host of
// its URL and where that URL is set.
func targets(c *config.Config, v config.Values) []sent {
	var sends []sent
	add := func(name, url string, s config.Secret) {
		host, _ := httpclient.HostOf(url) // Secrets has checked every URL
		where := "file " + s.File
		if s.Env != "" {
			where = "the variable " + s.Env
		}
		sends = append(sends, sent{channel: name, host: host, where: where})
	}
	if c.Slack != nil {
		add("slack", v.SlackURL, c.Slack.URL)
	}
	for i, h := range c.Webhooks {
		add(h.Name, v.WebhookURLs[i], h.URL)
	}
	return sends
}

func webhookCheck(s sent) result {
	check := "webhook " + s.channel
	o := s.outcome
	switch {
	case o.Status >= 200 && o.Status <= 299:
		return newResult("ok", check, fmt.Sprintf(textSent, s.host, o.Status))
	case o.Status != 0:
		// Body holds at most one error word that no secret holds; any other
		// text of the server may repeat the URL.
		word := ""
		if len(o.Body) > 0 {
			word = " " + strconv.Quote(string(o.Body))
		}
		return newResult("FAIL", check, fmt.Sprintf(textRefused, s.host, o.Status, word, s.where))
	}
	return newResult("FAIL", check, fmt.Sprintf(textUnreached, s.host, o.Err, s.host))
}

// clockCheck compares this machine's clock with the Date of the first answer
// that has one, the only outside time osk-dns-watcher may ask for: it posts to no host
// but those of the config. The middle of the request stands for the moment
// the server read its clock.
func clockCheck(sends []sent) result {
	for _, s := range sends {
		if s.outcome.Status == 0 || s.outcome.Date.IsZero() {
			continue
		}
		d := s.outcome.Date.Sub(s.t0.Add(s.t1.Sub(s.t0) / 2)).Round(time.Second)
		switch {
		case d.Abs() <= maxSkew:
			return newResult("ok", "clock", fmt.Sprintf(textClockOK, d.Abs(), s.host))
		case d < 0:
			return newResult("FAIL", "clock", fmt.Sprintf(textClockOff, d.Abs(), "ahead of", s.host))
		}
		return newResult("FAIL", "clock", fmt.Sprintf(textClockOff, d.Abs(), "behind", s.host))
	}
	return newResult("skip", "clock", textNoClock)
}
