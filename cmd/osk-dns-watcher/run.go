package main

import (
	"cmp"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"os/signal"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/alert"
	"github.com/Opsek/osk-dns-watcher/internal/certlog"
	"github.com/Opsek/osk-dns-watcher/internal/cli"
	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/deliver"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
	"github.com/Opsek/osk-dns-watcher/internal/mtasts"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/schedule"
	"github.com/Opsek/osk-dns-watcher/internal/store"
)

// The fixed periods of the service. They are variables only so that a test
// can shorten them.
var (
	beatEvery  = 10 * time.Second // after a crash, the stored beat is at most this old
	readEvery  = 5 * time.Second  // a change of a file is taken within two of these
	passPause  = time.Second      // from the end of one delivery pass to the next
	readStuck  = 30 * time.Second // a read that has not ended by then is a problem of the file
	readSettle = 30 * time.Second // how long a file that is not valid must stay so before it counts
	// downNotice is the shortest down time that the channels hear of: a
	// restart for a change of the config takes seconds and is no alarm.
	downNotice = time.Minute
)

const (
	// pruneBatch bounds the history deleted in one transaction, because the
	// delivery loops wait for the store's one connection meanwhile.
	pruneBatch = 200
	pruneEvery = time.Hour
)

const (
	secondLayout = "2006-01-02T15:04:05Z"
	humanLayout  = "2006-01-02 15:04:05 UTC"
)

var tiers = []schedule.Tier{schedule.TierSerial, schedule.TierParent, schedule.TierFast, schedule.TierOther, schedule.TierCertificates}

// service runs "osk-dns-watcher run" until SIGINT or SIGTERM, each a clean stop.
func service(args []string, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return serve(ctx, args, stdout, stderr)
}

// serve runs "osk-dns-watcher run" until ctx ends: it runs each check of each domain of
// the config at the interval of its tier, keeps the alerts in the state
// folder and sends their notices to every channel. args are those after the
// command word.
func serve(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	path, msg := parseRun(args)
	if msg != "" {
		return fail(stderr, 2, "osk-dns-watcher run: "+msg+"\n"+usage)
	}
	c, problems := config.Read(path)
	if len(problems) > 0 {
		return fail(stderr, 1, problemText(problems))
	}
	values, o, files, text := prepare(c)
	if text != "" {
		return fail(stderr, 1, text)
	}
	s, err := store.Open(c.State)
	if err != nil {
		return fail(stderr, 1, "osk-dns-watcher: "+err.Error()+"\n")
	}
	m := newMonitor(c, values, o, files, s, stdout)
	err = m.start()
	if err == nil {
		err = m.watch(ctx)
	}
	return m.stop(err)
}

// parseRun reads the flags of run and gives the path of the config, or the
// message of a wrong use.
func parseRun(args []string) (string, string) {
	var path *string
	flags := flag.NewFlagSet("run", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	flags.Func("config", "the config file", once(&path))
	if err := flags.Parse(args); err != nil {
		return "", err.Error()
	}
	switch {
	case path == nil:
		return "", "--config is required"
	case flags.NArg() > 0:
		return "", "takes no arguments: the file gives the domains and the sets"
	}
	return *path, ""
}

// once gives a flag function that keeps the value in *p and refuses a
// second value.
func once(p **string) func(string) error {
	return func(s string) error {
		if *p != nil {
			return errors.New("given more than once")
		}
		*p = &s
		return nil
	}
}

func problemText(problems []config.Problem) string {
	var b strings.Builder
	for _, p := range problems {
		b.WriteString("osk-dns-watcher: " + p.String() + "\n")
	}
	return b.String()
}

// prepare reads what the service needs besides the store: the secrets, the
// settings of the queries and the expectations of each domain. text holds a
// line for each problem.
func prepare(c *config.Config) (values config.Values, o *observe.Observer, files []*expect.File, text string) {
	values, problems := c.Secrets(os.LookupEnv)
	text = problemText(problems)
	o, err := observe.New(observe.Config{RootServers: c.RootServers, ExtraRanges: c.ExtraRanges, Policy: mtasts.Fetcher(c.ExtraRanges)})
	if err != nil {
		text += "osk-dns-watcher: " + err.Error() + "\n"
	}
	for _, d := range c.Domains {
		f, problems := d.Read()
		files = append(files, f)
		text += problemText(problems)
	}
	return values, o, files, text
}

func newMonitor(c *config.Config, values config.Values, o *observe.Observer, files []*expect.File, s *store.Store, stdout io.Writer) *monitor {
	now := time.Now()
	// The one client for every channel, the heartbeat and the certificate
	// source: it asks only the hosts of the URLs of the config.
	client := httpclient.New(values.Hosts(), nil)
	m := &monitor{
		cfg:      c,
		observer: o,
		store:    s,
		channels: channels(c, values, client),
		out:      newLogger(stdout, logLines),
		policy:   alert.Policy{Remind: c.Remind},
	}
	if c.Heartbeat != nil {
		m.beatTo = &beater{client: client, url: values.HeartbeatURL, every: c.Heartbeat.Interval}
	}
	for i, d := range c.Domains {
		w := newWatched(d, files[i], c.Intervals, now)
		if c.Certificates != nil {
			w.certs = certlog.New(client, values.CertificatesURL, values.CertificatesKey, d.Name)
		}
		m.domains = append(m.domains, w)
	}
	return m
}

func channels(c *config.Config, values config.Values, client *httpclient.Client) []deliver.Channel {
	var list []deliver.Channel
	if c.Slack != nil {
		list = append(list, deliver.NewSlack(client, values.SlackURL, c.Slack.MinSeverity))
	}
	for i, h := range c.Webhooks {
		list = append(list, deliver.NewWebhook(client, h.Name, values.WebhookURLs[i], values.WebhookKeys[i], h.MinSeverity))
	}
	return list
}

// start prints the start lines, tells how long osk-dns-watcher was down, ends the alerts
// whose check or domain left the expectations while it was down, ends an
// invalid-file alert left by the last run (every file is valid now) and
// deletes old history.
func (m *monitor) start() error {
	now := time.Now()
	m.started = now
	m.out.print(fmt.Sprintf("config %s: %d domains, channels %s", m.cfg.Path, len(m.domains), strings.Join(m.cfg.Channels(), ",")))
	for _, w := range m.cfg.Warnings() {
		m.out.log(levelWarning, "", "warning "+w)
	}
	for _, d := range m.domains {
		if w := cli.CertLinesWarning(m.cfg, d.file); w != "" {
			m.out.log(levelWarning, d.label, "warning "+w)
		}
	}
	for _, d := range m.domains {
		m.printPlan(d)
	}
	if err := m.startBeat(now); err != nil {
		return err
	}
	if err := m.syncAll(now); err != nil {
		return err
	}
	for _, d := range m.domains {
		if err := m.fileChanges(d, nil, now); err != nil {
			return err
		}
	}
	return m.prune(now)
}

func (m *monitor) printPlan(d *watched) {
	checks := d.sched.Checks()
	m.out.log(levelInfo, d.label, fmt.Sprintf("start %s %d checks, state %s", d.label, len(checks), m.cfg.State))
	for _, t := range tiers {
		// The certificates tier has no interval while the source is off.
		if m.cfg.Intervals.Of(t) == 0 {
			continue
		}
		n := 0
		for _, c := range checks {
			if c.Tier == t {
				n++
			}
		}
		m.out.log(levelInfo, d.label, fmt.Sprintf("plan %s every %v %d checks", t, m.cfg.Intervals.Of(t), n))
	}
	m.printUnused(d)
}

func (m *monitor) printUnused(d *watched) {
	for _, n := range schedule.Unused(d.file, d.fast) {
		m.out.log(levelInfo, d.label, "fast "+n.Lower().String()+" has no line in the file")
	}
}

// startBeat tells how long osk-dns-watcher was down, to the channels too from
// downNotice on, then stores the beat of this start. The notice is stored
// first: a crash between the two sends it again, never loses it.
func (m *monitor) startBeat(now time.Time) error {
	last, err := m.store.LastBeat()
	if err != nil {
		return err
	}
	switch {
	case last.IsZero():
	case last.After(now):
		m.out.log(levelWarning, "", "down: the stored time "+last.UTC().Format(secondLayout)+
			" is ahead of the clock; the down time is not known")
	default:
		m.out.log(levelWarning, "", "down since "+last.UTC().Format(secondLayout)+" for "+now.Sub(last).Round(time.Second).String())
		if now.Sub(last) < downNotice {
			break
		}
		n := store.Notice{Kind: store.NoticeDown, At: now,
			Lines: []string{"last beat " + last.UTC().Format(humanLayout), "started   " + now.UTC().Format(humanLayout)}}
		if err := m.notify(n); err != nil {
			return err
		}
	}
	return m.beat(now, nil)
}

// syncAll compares the expectations of each domain with those loaded last,
// then ends what the store holds of each domain that left the config.
func (m *monitor) syncAll(now time.Time) error {
	loaded, err := m.store.Loaded()
	if err != nil {
		return err
	}
	m.loaded = loaded
	for _, d := range m.domains {
		if err := m.sync(d.label, d.sched.Checks(), d.file.String(), now); err != nil {
			return err
		}
	}
	gone, err := m.gone()
	if err != nil {
		return err
	}
	for _, label := range gone {
		if err := m.sync(label, nil, "", now); err != nil {
			return err
		}
	}
	return nil
}

// gone gives the domains that the store knows, by their loaded expectations
// or their open alerts, and that the config no longer names. A store made
// before it kept the expectations knows a domain only by its alerts.
func (m *monitor) gone() ([]string, error) {
	open, err := m.store.AllOpenAlerts()
	if err != nil {
		return nil, err
	}
	labels := slices.Collect(maps.Keys(m.loaded))
	for _, a := range open {
		labels = append(labels, a.Check.Domain.Lower().String())
	}
	slices.Sort(labels)
	return slices.DeleteFunc(slices.Compact(labels), func(label string) bool {
		return slices.ContainsFunc(m.domains, func(d *watched) bool { return d.label == label })
	}), nil
}

// stop tells the moves that the rate bound of zone-changed still holds,
// stores the beat of the stop and closes the store. err is what ended the
// service, nil for the end of its context. Only the first error is told:
// after a store error, the others are mostly its echo.
func (m *monitor) stop(err error) int {
	now := time.Now()
	if err == nil {
		err = m.flush(now)
	}
	beatErr := m.store.Beat(now, m.late(now))
	closeErr := m.store.Close()
	if err := cmp.Or(err, beatErr, closeErr); err != nil {
		m.out.log(levelError, "", "error "+err.Error())
		m.out.close(logDrain)
		return 1
	}
	m.out.print("stop")
	m.out.close(logDrain)
	return 0
}
