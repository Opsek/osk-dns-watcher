// Package start sets osk up: init asks two questions, shows what the servers
// give now and writes the setup; doctor checks a setup and says what to fix.
package start

import (
	"bufio"
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/Opsek/dns-monitoring/internal/config"
	"github.com/Opsek/dns-monitoring/internal/decide"
	"github.com/Opsek/dns-monitoring/internal/dnswire"
	"github.com/Opsek/dns-monitoring/internal/expect"
	"github.com/Opsek/dns-monitoring/internal/httpclient"
	"github.com/Opsek/dns-monitoring/internal/observe"
	"github.com/Opsek/dns-monitoring/internal/observe/obs"
)

// Runner runs one check; *observe.Observer is one.
type Runner interface {
	Run(ctx context.Context, c observe.Check) (obs.Observation, error)
}

// Init is "osk init". It reads one answer per line of In, so a pipe can
// answer as a person does.
type Init struct {
	Config      string           // as given
	RootServers []netip.AddrPort // the flags; also given to the Observer
	ExtraRanges []netip.Prefix
	Observer    Runner
	In          io.Reader
	Out         io.Writer
	Term        bool // In and Out are a terminal, which echoes each answer
	Now         func() time.Time
}

// The words of the dialogue, in the order a person meets them.
const (
	textSetUp = "osk is set up already: %s exists. Nothing to ask.\n"
	textProxy = "The network between this machine and the DNS root servers answers DNS queries itself (a VPN, router or provider does this).\n" +
		"osk must reach the root servers directly on port 53, over UDP and TCP. Run osk on another network or machine.\n"
	textHeader = "Set up osk: two questions, then osk shows what it sees. Nothing is written until you type yes.\n\n"

	askDomains   = "Domains to watch, separated by spaces: "
	textNotPlain = `A domain name holds only letters, digits, "-", "_" and ".". ` +
		"Write an international name in its xn-- form, and do not paste a URL here. Try again.\n"
	textBadName  = "%q is not a domain name (%v). Try again.\n"
	textRoot     = "osk does not watch the root. Try again.\n"
	textNoDomain = "Name at least one domain. Try again.\n"
	textMany     = "osk watches at most %d domains. Try again.\n"

	askURL     = "Slack incoming webhook URL (hidden): "
	textHidden = "[hidden]\n"
	textBadURL = "That is not an https URL with a host and no user name. Try again.\n"

	textAsking   = "\nAsking the servers of your domains, starting from the root servers ...\n"
	textNoAnswer = "osk got no answer about %s from its parent zone (%s). " +
		"Check the name, and that this machine may send DNS queries (port 53) to the internet.\n"
	textNotDelegated = "The parent zone says that %s does not exist or has no nameservers. Check the name.\n"

	textSees     = "\n%s as osk sees it now. Once you confirm, osk alerts when the servers differ from these lines:\n"
	textSkips    = "Not watched, and why:\n"
	textNotAsked = "Not asked: %s of the servers, which this machine cannot reach.\n"
	textOneIPv6  = "1 IPv6 address"
	textIPv6     = "%d IPv6 addresses"
	textNoNS     = "warning osk cannot watch the nameservers of %s yet. Until its file has an NS line, " +
		"a change of the nameservers gives no critical alert, only an update of the alert about the missing line; " +
		"osk sends that alert at its first check.\n"
	textNSNoAnswer = "warning %s gave no answer about the nameservers of %s, so its NS line holds what the other servers gave. " +
		"If they hold another set, osk alerts at its first check.\n"
	textNSNoPath = "warning osk could not reach the servers of %s (the walk from the root found no path to them), " +
		"so its NS line holds what the parent zone gave. If the servers hold another set, osk alerts at its first check.\n"
	textNSSets = "warning the servers of %s give different nameserver sets now. The NS line above accepts each set below; " +
		"a change of the nameservers to any other set gives an alert:\n"
	textNSSet    = "  %s\n"
	textNSParent = "    given by the parent zone: %s\n"
	textNSZone   = "    given by the servers of %s: %s\n"
	textNSFix    = "If a name in these sets is not one of your nameservers, do not type yes. Else make the sets equal " +
		"at your registrar and DNS provider, then run osk snapshot %s and put its NS line in the file.\n"
	textManyHosts = "warning osk does not watch the addresses of the nameservers of %s, because its NS line names more than %d hosts " +
		"inside the domain. Add their A and AAAA lines by hand.\n"
	textNoSets = "warning osk watches no record set of %s yet: each one is listed above with its reason. " +
		"Until its file has those lines, a change of them gives no alert.\n"
	textWarning = "warning %s\n"

	askTrust    = "\nTrust these lines and write the setup to %s? Type yes: "
	textNothing = "Nothing was written.\n"
	textError   = "osk: %v\n"
	textWrote   = "Wrote %s and %s.\n"

	textExpectHeader = "# Written by osk init at %s from what the servers gave. Edit a line to change what osk trusts.\n"
)

// Terminal codes: concealed text on and off, and the cursor up one line to
// the start of an emptied line.
const (
	conceal    = "\x1b[8m"
	reveal     = "\x1b[28m"
	eraseAbove = "\x1b[1A\r\x1b[2K"
)

const (
	maxDomains  = 100
	secretFile  = "slack-url"
	stateFolder = "state"
	timeLayout  = "2006-01-02 15:04:05"
)

// Run asks, shows what the servers give, and writes the setup only when the
// answer is yes. It gives the exit code: 0 written or set up already, 1 not.
func (i Init) Run(ctx context.Context) int {
	d := &dialogue{in: bufio.NewReader(i.In), out: i.Out, term: i.Term}
	if _, err := os.Lstat(i.Config); err == nil {
		// A script can then run init on every start.
		d.say(fmt.Sprintf(textSetUp, i.Config))
		return 0
	}
	if !rootsAnswerDirectly(ctx, i.RootServers) {
		return d.stop(textProxy)
	}
	path, err := filepath.Abs(i.Config)
	if err != nil {
		return d.stop(fmt.Sprintf(textError, err))
	}
	d.say(textHeader)
	domains, ok := d.domains(ctx)
	if !ok {
		return d.stop(textNothing)
	}
	url, ok := d.webhook(ctx)
	if !ok {
		return d.stop(textNothing)
	}
	d.say(textAsking)
	views := lookAll(ctx, i.Observer, domains)
	if ctx.Err() != nil {
		return d.stop(textNothing)
	}
	for _, v := range views {
		if text := refusal(v); text != "" {
			return d.stop(text + textNothing)
		}
	}
	d.say(show(views))
	data := configJSON(domains, i.RootServers, i.ExtraRanges)
	c, problems := config.Parse(path, data)
	if len(problems) > 0 {
		// The flags can hold what a config refuses, such as a prefix with
		// bits after its length.
		return d.stop(problemLines(problems) + textNothing)
	}
	for _, w := range c.Warnings() {
		d.say(fmt.Sprintf(textWarning, w))
	}
	if answer, ok := d.ask(ctx, fmt.Sprintf(askTrust, filepath.Dir(path))); !ok || answer != "yes" {
		return d.stop(textNothing)
	}
	written, err := writeSetup(path, url, views, data, i.Now())
	if err != nil {
		return d.stop(fmt.Sprintf(textError, err))
	}
	d.say(fmt.Sprintf(textWrote, strings.Join(written[:len(written)-1], ", "), written[len(written)-1]))
	return 0
}

// dialogue asks the questions. Without a terminal nothing echoes an answer,
// so it writes the answer itself, and the output reads the same either way.
type dialogue struct {
	in   *bufio.Reader
	out  io.Writer
	term bool
}

// say writes text. A failed write is not reported: there is no other place
// to report it.
func (d *dialogue) say(text string) { _, _ = io.WriteString(d.out, text) }

// stop says text and gives the exit code of a run that wrote nothing.
func (d *dialogue) stop(text string) int {
	d.say(text)
	return 1
}

// ask writes the question and gives the answer. ok is false when the input
// or ctx ends; the line of the question is ended then too. An answer that
// plainNames refuses is written back as [hidden].
func (d *dialogue) ask(ctx context.Context, question string) (answer string, ok bool) {
	d.say(question)
	answer, ok = d.read(ctx)
	switch {
	case !ok:
		d.say("\n")
	case d.term:
	case plainNames(answer):
		d.say(answer + "\n")
	default:
		d.say(textHidden)
	}
	return answer, ok
}

// askHidden asks for a value that must never be shown. A terminal conceals
// it while it is typed and its line is drawn again after Enter; a terminal
// that cannot conceal shows it until then.
func (d *dialogue) askHidden(ctx context.Context, question string) (string, bool) {
	d.say(question)
	if d.term {
		d.say(conceal)
	}
	answer, ok := d.read(ctx)
	if d.term {
		d.say(reveal)
	}
	if !ok {
		d.say("\n")
		return "", false
	}
	if d.term {
		d.say(eraseAbove + question)
	}
	d.say(textHidden)
	return answer, true
}

// read gives the next line of input without blanks at its ends; a last line
// without a line end counts too. A read cannot be stopped, so it runs aside:
// Ctrl-C then ends the wait at once, and the process ends soon after.
func (d *dialogue) read(ctx context.Context) (string, bool) {
	type result struct {
		line string
		err  error
	}
	done := make(chan result, 1)
	go func() {
		line, err := d.in.ReadString('\n')
		done <- result{line, err}
	}()
	select {
	case r := <-done:
		if r.err != nil && r.line == "" {
			return "", false
		}
		return strings.TrimSpace(r.line), true
	case <-ctx.Done():
		return "", false
	}
}

func (d *dialogue) domains(ctx context.Context) ([]dnswire.Name, bool) {
	for {
		answer, ok := d.ask(ctx, askDomains)
		if !ok {
			return nil, false
		}
		domains, problem := parseDomains(answer)
		if problem == "" {
			return domains, true
		}
		d.say(problem)
	}
}

func (d *dialogue) webhook(ctx context.Context) (string, bool) {
	for {
		url, ok := d.askHidden(ctx, askURL)
		if !ok {
			return "", false
		}
		if _, err := httpclient.HostOf(url); err == nil {
			return url, true
		}
		d.say(textBadURL)
	}
}

// parseDomains reads the answer to the first question. It gives the names in
// lower case without repeats, or the text that asks again.
func parseDomains(answer string) ([]dnswire.Name, string) {
	if !plainNames(answer) {
		return nil, textNotPlain
	}
	var names []dnswire.Name
	seen := map[string]bool{}
	for _, field := range strings.Fields(answer) {
		text := field
		if !strings.HasSuffix(text, ".") {
			text += "."
		}
		name, err := dnswire.ParseName(text)
		switch {
		case err != nil:
			return nil, fmt.Sprintf(textBadName, field, err)
		case name.LabelCount() == 0:
			return nil, textRoot
		case !seen[name.Key()]:
			seen[name.Key()] = true
			names = append(names, name.Lower())
		}
	}
	switch {
	case len(names) == 0:
		return nil, textNoDomain
	case len(names) > maxDomains:
		return nil, fmt.Sprintf(textMany, maxDomains)
	}
	return names, ""
}

// plainNames reports whether each field of answer holds only ASCII letters,
// digits, "-", "_" and ".". Any other octet may belong to a secret pasted at
// the wrong question, such as the webhook URL, so such an answer is never
// parsed, asked about or printed. It reads octets, not runes, so no other
// script and no escape passes.
func plainNames(answer string) bool {
	for _, field := range strings.Fields(answer) {
		for i := range len(field) {
			c := field[i]
			if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '-' || c == '_' || c == '.') {
				return false
			}
		}
	}
	return true
}

// refusal gives why a domain cannot be set up, or "" when it can. Without
// an answer from its parent zone, osk would trust nothing it could check.
func refusal(v view) string {
	if decide.Failed(v.delegation) {
		return fmt.Sprintf(textNoAnswer, v.domain, strings.Join(failureWords(v.delegation), ","))
	}
	if slices.ContainsFunc(v.delegation.Answers, denies) {
		return fmt.Sprintf(textNotDelegated, v.domain)
	}
	return ""
}

// failureWords gives the reason of each failed answer, each once, in answer
// order.
func failureWords(o obs.Observation) []string {
	var words []string
	for _, a := range o.Answers {
		word := obs.Match(a.Result,
			func(obs.Records) string { return "" },
			func(obs.NoData) string { return "" },
			func(obs.NoName) string { return "" },
			func(f obs.Failure) string { return f.Reason.String() })
		if word != "" && !slices.Contains(words, word) {
			words = append(words, word)
		}
	}
	return words
}

// denies reports an answer of no data or no such name.
func denies(a obs.Answer) bool {
	return obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return true },
		func(obs.NoName) bool { return true },
		func(obs.Failure) bool { return false })
}

// show gives the lines of each domain and the sets it leaves out. A file
// without an NS line, or with no set to compare, is still written, and so is
// an NS line that accepts several sets: servers that disagree on the
// nameservers are common, and that alone must not stop the setup, so the gap
// or the wider trust is said instead.
func show(views []view) string {
	var b strings.Builder
	for _, v := range views {
		fmt.Fprintf(&b, textSees, v.domain)
		for line := range strings.Lines(v.file.String()) {
			b.WriteString("  " + line)
		}
		if len(v.skips) > 0 {
			b.WriteString(textSkips)
		}
		for _, s := range v.skips {
			b.WriteString("  " + s.Name.Lower().String() + " " + s.Type.String() + ": " + s.Why + "\n")
		}
		if v.unreached > 0 {
			fmt.Fprintf(&b, textNotAsked, ipv6Count(v.unreached))
		}
		if _, ok := v.file.Find(v.domain, dnswire.TypeNS); !ok {
			fmt.Fprintf(&b, textNoNS, v.domain)
		} else {
			servers := slices.DeleteFunc(slices.Clone(v.nsNoAnswer), func(s string) bool { return s == expect.NoPath })
			if len(servers) < len(v.nsNoAnswer) {
				fmt.Fprintf(&b, textNSNoPath, v.domain)
			}
			if len(servers) > 0 {
				fmt.Fprintf(&b, textNSNoAnswer, strings.Join(servers, ", "), v.domain)
			}
			if len(v.nsSources) > 1 {
				b.WriteString(nsSetsText(v.domain, v.nsSources))
			}
		}
		if v.manyHosts {
			fmt.Fprintf(&b, textManyHosts, v.domain, maxNSHosts)
		}
		if !slices.ContainsFunc(v.file.Expectations, comparesRecords) {
			fmt.Fprintf(&b, textNoSets, v.domain)
		}
	}
	return b.String()
}

// nsSetsText names each set that the NS line of domain accepts and the
// servers that gave it. A server that lies during init gets its set into the
// line, so the person who confirms must be able to see a set that is not
// theirs.
func nsSetsText(domain dnswire.Name, sources []expect.NSSource) string {
	var b strings.Builder
	fmt.Fprintf(&b, textNSSets, domain)
	for _, s := range sources {
		fmt.Fprintf(&b, textNSSet, s.Text)
		if len(s.Parent) > 0 {
			fmt.Fprintf(&b, textNSParent, strings.Join(s.Parent, ", "))
		}
		if len(s.Zone) > 0 {
			fmt.Fprintf(&b, textNSZone, domain, strings.Join(s.Zone, ", "))
		}
	}
	fmt.Fprintf(&b, textNSFix, domain)
	return b.String()
}

// comparesRecords reports a line of another type than NS and DS: the NS
// line is warned about by itself, and DS data is not compared.
func comparesRecords(e expect.Expectation) bool {
	return e.Type != dnswire.TypeNS && e.Type != dnswire.TypeDS
}

func ipv6Count(n int) string {
	if n == 1 {
		return textOneIPv6
	}
	return fmt.Sprintf(textIPv6, n)
}

func problemLines(problems []config.Problem) string {
	var b strings.Builder
	for _, p := range problems {
		fmt.Fprintf(&b, textError, p)
	}
	return b.String()
}

// The config that init writes, its keys in this order. Its paths are
// relative to its folder, so they hold wherever the folder is mounted, and
// it names the file of the webhook URL, never the URL.
type configFile struct {
	State   string         `json:"state"`
	Domains []configDomain `json:"domains"`
	Slack   configSlack    `json:"slack"`
	Network *configNetwork `json:"network,omitempty"`
}

type configDomain struct {
	Name   string `json:"name"`
	Expect string `json:"expect"`
}

type configSlack struct {
	URL fileSecret `json:"url"`
}

type fileSecret struct {
	File string `json:"file"`
}

type configNetwork struct {
	RootServers []string `json:"root_servers"`
	ExtraRanges []string `json:"extra_ranges"`
}

func configJSON(domains []dnswire.Name, roots []netip.AddrPort, ranges []netip.Prefix) []byte {
	c := configFile{State: stateFolder, Slack: configSlack{URL: fileSecret{File: secretFile}}}
	for _, d := range domains {
		c.Domains = append(c.Domains, configDomain{Name: d.String(), Expect: expectName(d)})
	}
	if len(roots) > 0 || len(ranges) > 0 {
		// Empty lists, not null, which the config refuses.
		c.Network = &configNetwork{RootServers: []string{}, ExtraRanges: []string{}}
		for _, r := range roots {
			text := r.String()
			if r.Port() == 0 {
				text = r.Addr().String()
			}
			c.Network.RootServers = append(c.Network.RootServers, text)
		}
		for _, p := range ranges {
			c.Network.ExtraRanges = append(c.Network.ExtraRanges, p.String())
		}
	}
	// Strings and lists of strings always marshal.
	data, _ := json.MarshalIndent(c, "", "  ")
	return append(data, '\n')
}

func expectName(domain dnswire.Name) string {
	return strings.TrimSuffix(domain.String(), ".") + ".expect"
}

// writeSetup writes the files beside the config, the config last: a run cut
// before it leaves no config, and the next run starts again. It gives the
// paths in the order of the Wrote line.
func writeSetup(path, url string, views []view, data []byte, now time.Time) ([]string, error) {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	secret := filepath.Join(dir, secretFile)
	if err := writeFile(secret, []byte(url+"\n"), true); err != nil {
		return nil, err
	}
	written := []string{path}
	header := fmt.Sprintf(textExpectHeader, now.UTC().Format(timeLayout)+" UTC")
	for _, v := range views {
		file := filepath.Join(dir, expectName(v.domain))
		if err := writeFile(file, []byte(header+v.file.String()), true); err != nil {
			return nil, err
		}
		written = append(written, file)
	}
	if err := writeFile(path, data, false); err != nil {
		return nil, err
	}
	return append(written, secret), nil
}

// writeFile puts data at path through a new file of mode 0600 beside it, so
// that no reader ever sees part of it. With replace false, a file at path is
// kept, and that is an error.
func writeFile(path string, data []byte, replace bool) error {
	f, err := os.CreateTemp(filepath.Dir(path), "."+filepath.Base(path)+".*")
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	err = cmp.Or(err, f.Sync(), f.Close())
	switch {
	case err != nil:
	case replace:
		err = os.Rename(f.Name(), path)
	default:
		// Unlike a rename, a link fails when path exists.
		err = os.Link(f.Name(), path)
	}
	if err != nil || !replace {
		// Once renamed it is gone; once linked, path holds the data.
		_ = os.Remove(f.Name())
	}
	return err
}
