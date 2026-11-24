package start

import (
	"context"
	"encoding/binary"
	"io"
	"io/fs"
	"maps"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// The ordinary tests run init with a fake observer, which sends nothing, and
// two fake root servers on 127.0.0.1, which pass the check that the root
// servers answer for themselves. That check reaches the root servers of the
// internet when no root server is given, so every test gives them, and the
// dialogue carries the network warnings.
//
// The fake world gives each domain d the sets of the example that a stranger
// reads first: a server of the parent zone delegates d to ns1.example.net.
// and ns2.example.net.; both agree on every set of the apex; www.<d> is an
// alias, which an A line cannot hold.

const (
	iniHello    = "Set up osk-dns-watcher: two questions, then osk-dns-watcher shows what it sees. Nothing is written until you type yes.\n\n"
	iniDomainsQ = "Domains to watch, separated by spaces: "
	iniURLQ     = "Slack incoming webhook URL (hidden): "
	iniAsking   = "Asking the servers of your domains, starting from the root servers ...\n"
	iniNothing  = "Nothing was written.\n"
	iniBadURL   = "That is not an https URL with a host and no user name. Try again.\n"
	iniProxy    = "The network between this machine and the DNS root servers answers DNS queries itself (a VPN, router or provider does this).\n" +
		"osk-dns-watcher must reach the root servers directly on port 53, over UDP and TCP. Run osk-dns-watcher on another network or machine.\n"
	// iniStamp is the first line of each expectations file, at iniNow.
	iniStamp = "# Written by osk-dns-watcher init at 2026-11-15 14:02:07 UTC from what the servers gave. Edit a line to change what osk-dns-watcher trusts.\n"

	// iniMark is in the webhook URL, so that a test can find every copy of it.
	iniMark = "q7Zm2Kx9Tv4P"
	iniURL  = "https://hooks.example/services/T0/B0/" + iniMark

	iniParentHost = "ns.parent.example."
	iniParentAddr = "192.0.2.53:53"
	iniNS1Addr    = "198.51.100.53:53"
	iniNS2Addr    = "198.51.100.54:53"
	iniNS1v6Addr  = "[2001:db8::53]:53"
	iniNS2v6Addr  = "[2001:db8::54]:53"
)

// iniNow is not in UTC, so the stamp shows that init turns it into UTC.
var iniNow = time.Date(2026, 11, 15, 15, 2, 7, 0, time.FixedZone("UTC+1", 3600))

// The names and records of these tests are fixed, so a bad one is a mistake
// in the test: the helpers panic, also inside the observer's goroutines.

func iniName(s string) dnswire.Name {
	n, err := dnswire.ParseName(s)
	if err != nil {
		panic(err)
	}
	return n
}

func iniRR(owner string, t dnswire.Type, data string) dnswire.Record {
	d, err := dnswire.ParseRData(t, data)
	if err != nil {
		panic(err)
	}
	return dnswire.Record{Name: iniName(owner), Class: dnswire.ClassINET, TTL: 300, Data: d}
}

func iniRecords(owner string, t dnswire.Type, data ...string) obs.Result {
	var set []dnswire.Record
	for _, d := range data {
		set = append(set, iniRR(owner, t, d))
	}
	return obs.RecordsResult(obs.Records{Set: set})
}

func iniSOA(zone string) dnswire.Record {
	return iniRR(zone, dnswire.TypeSOA, "ns.example.net. hostmaster.example.net. 1 3600 600 86400 300")
}

func iniNoData(zone string) obs.Result { return obs.NoDataResult(obs.NoData{SOA: iniSOA(zone)}) }

func iniNoName(zone string) obs.Result { return obs.NoNameResult(obs.NoName{SOA: iniSOA(zone)}) }

func iniFail(reason obs.Reason) obs.Result {
	return obs.FailureResult(obs.Failure{Reason: reason, Detail: "from the fake world"})
}

func iniAt(host, addr string, r obs.Result) obs.Answer {
	s := obs.Server{Name: iniName(host), Addr: netip.MustParseAddrPort(addr)}
	return obs.Answer{Proof: obs.Proof{Server: s}, Result: r}
}

// iniBoth is one result from both servers of the domain, in the order that
// observe gives answers.
func iniBoth(r obs.Result) []obs.Answer {
	return []obs.Answer{iniAt("ns1.example.net.", iniNS1Addr, r), iniAt("ns2.example.net.", iniNS2Addr, r)}
}

var iniApex = map[dnswire.Type][]string{
	dnswire.TypeNS:   {"ns1.example.net.", "ns2.example.net."},
	dnswire.TypeA:    {"192.0.2.10"},
	dnswire.TypeAAAA: {"2001:db8::10"},
	dnswire.TypeTXT:  {`"v=spf1 mx -all"`},
	dnswire.TypeCAA:  {`0 issue "letsencrypt.org"`},
}

// iniBase is what the fake world answers to the check k.
func iniBase(k obs.Key) []obs.Answer {
	d := k.Domain.Lower().String()
	if k.Kind == obs.KindDelegation {
		ns := iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")
		return []obs.Answer{iniAt(iniParentHost, iniParentAddr, ns)}
	}
	if k.Kind == obs.KindDS {
		return []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniNoData(k.Domain.Parent().Lower().String()))}
	}
	name := k.Name.Lower().String()
	r := iniNoName(d)
	switch {
	case name == "www."+d && k.Type == dnswire.TypeA:
		r = iniRecords(name, dnswire.TypeCNAME, "cdn.example.net.")
	case name == d && k.Type == dnswire.TypeMX:
		r = iniRecords(d, k.Type, "10 mail."+d)
	case name == d && iniApex[k.Type] != nil:
		r = iniRecords(d, k.Type, iniApex[k.Type]...)
	}
	return iniBoth(r)
}

// iniLines are the lines of domain d of the fake world, as File.String
// prints them: the sets of the apex, then the names under it where the fake
// world has no record.
func iniLines(d string) []string {
	return []string{
		"domain " + d,
		d + " A 192.0.2.10",
		d + " NS ns1.example.net. | ns2.example.net.",
		d + " MX 10 mail." + d,
		d + ` TXT "v=spf1 mx -all"`,
		d + " AAAA 2001:db8::10",
		d + " DS none",
		d + ` CAA 0 issue "letsencrypt.org"`,
		"*." + d + " A none",
		"_acme-challenge." + d + " TXT none",
		"_dmarc." + d + " TXT none",
		"_mta-sts." + d + " TXT none",
		"_acme-challenge.www." + d + " TXT none",
	}
}

func iniAliasSkip(d string) string {
	return "www." + d + " A: " + iniNS1Addr + " ns1.example.net. answers with a CNAME record; snapshot www." + d + " CNAME instead"
}

func iniKey(domain, name string, t dnswire.Type) string {
	return obs.RecordsKey(iniName(domain), iniName(name), t).String()
}

// iniKeys are the checks of a snapshot of d: the delegation, the DS set, the
// NS set of the apex, the five other sets of the apex and, when under is
// true, the six names under d: www, the DMARC and MTA-STS names, the two
// challenge names and the wildcard.
func iniKeys(d string, under bool) []string {
	n := iniName(d)
	keys := []string{obs.DelegationKey(n).String(), obs.DSKey(n).String()}
	for _, t := range []dnswire.Type{dnswire.TypeNS, dnswire.TypeA, dnswire.TypeAAAA, dnswire.TypeMX, dnswire.TypeTXT, dnswire.TypeCAA} {
		keys = append(keys, iniKey(d, d, t))
	}
	if under {
		keys = append(keys, iniKey(d, "www."+d, dnswire.TypeA), iniKey(d, "_dmarc."+d, dnswire.TypeTXT),
			iniKey(d, "_mta-sts."+d, dnswire.TypeTXT), iniKey(d, "_acme-challenge."+d, dnswire.TypeTXT),
			iniKey(d, "_acme-challenge.www."+d, dnswire.TypeTXT), iniKey(d, "*."+d, dnswire.TypeA))
	}
	return keys
}

// iniRunner is the observer of the ordinary tests. It gives each check the
// answers of over that its Key.String() names, else those of the fake world.
type iniRunner struct {
	over   map[string][]obs.Answer
	during func(calls int) // runs inside each check when set
	mu     sync.Mutex
	checks []observe.Check
	seen   []obs.Observation
}

func (r *iniRunner) Run(_ context.Context, c observe.Check) (obs.Observation, error) {
	r.mu.Lock()
	r.checks = append(r.checks, c)
	calls := len(r.checks)
	r.mu.Unlock()
	if r.during != nil {
		r.during(calls)
	}
	answers, ok := r.over[c.Key.String()]
	if !ok {
		answers = iniBase(c.Key)
	}
	// The servers of a delegation and of a DS set are those of the parent.
	zone := c.Key.Domain
	if c.Key.Kind == obs.KindDelegation || c.Key.Kind == obs.KindDS {
		zone = zone.Parent()
	}
	o := obs.Observation{Key: c.Key, Zone: zone, Answers: answers}
	r.mu.Lock()
	r.seen = append(r.seen, o)
	r.mu.Unlock()
	return o, nil
}

func (r *iniRunner) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.checks)
}

func (r *iniRunner) keys() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	var keys []string
	for _, c := range r.checks {
		keys = append(keys, c.Key.String())
	}
	return keys
}

func (r *iniRunner) observations() []obs.Observation {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.seen)
}

// iniCounted counts the checks of a real observer.
type iniCounted struct {
	Runner
	mu    sync.Mutex
	calls int
}

func (c *iniCounted) Run(ctx context.Context, check observe.Check) (obs.Observation, error) {
	c.mu.Lock()
	c.calls++
	c.mu.Unlock()
	return c.Runner.Run(ctx, check)
}

func (c *iniCounted) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.calls
}

const (
	iniQR = 0x8000
	iniAA = 0x0400
	iniRA = 0x0080
)

// iniRoot is a fake root server on 127.0.0.1. Each answer carries flags, and
// with nsSet the answer to ". NS" holds the NS set of the root zone. Without
// tcp its TCP port is closed.
type iniRoot struct {
	addr    netip.AddrPort
	flags   uint16
	nsSet   bool
	mu      sync.Mutex
	queries []iniQuery
}

type iniQuery struct {
	question string // "<name> <TYPE>"
	rd       bool
}

func iniStartRoot(t *testing.T, flags uint16, nsSet, tcp bool) *iniRoot {
	t.Helper()
	var pc net.PacketConn
	var ln net.Listener
	for range 20 {
		var err error
		if pc, err = net.ListenPacket("udp", "127.0.0.1:0"); err != nil {
			t.Fatal(err)
		}
		if ln, err = net.Listen("tcp", pc.LocalAddr().String()); err == nil {
			break
		}
		_ = pc.Close()
		ln = nil
	}
	if ln == nil {
		t.Fatal("no port of 127.0.0.1 is free for both UDP and TCP")
	}
	r := &iniRoot{addr: netip.MustParseAddrPort(pc.LocalAddr().String()), flags: flags, nsSet: nsSet}
	t.Cleanup(func() {
		_ = pc.Close()
		_ = ln.Close()
	})
	go func() {
		buf := make([]byte, 65535)
		for {
			n, from, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			if a := r.answer(buf[:n], false); a != nil {
				_, _ = pc.WriteTo(a, from)
			}
		}
	}()
	if !tcp {
		// The port was free for TCP a moment ago; closing it now makes it a
		// closed port, which refuses connections.
		_ = ln.Close()
		return r
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			var size [2]byte
			if _, err := io.ReadFull(c, size[:]); err == nil {
				q := make([]byte, binary.BigEndian.Uint16(size[:]))
				if _, err := io.ReadFull(c, q); err == nil {
					if a := r.answer(q, true); a != nil {
						_, _ = c.Write(append(binary.BigEndian.AppendUint16(nil, uint16(len(a))), a...))
					}
				}
			}
			_ = c.Close()
		}
	}()
	return r
}

// answer gives the reply to the query q: its ID and question, the flags of
// the root, and the NS set of the root zone for ". NS".
func (r *iniRoot) answer(q []byte, _ bool) []byte {
	m, err := dnswire.Parse(q)
	question := iniQuestion(q)
	if err != nil || len(m.Question) != 1 || question == nil {
		return nil
	}
	asked := m.Question[0]
	r.mu.Lock()
	r.queries = append(r.queries, iniQuery{question: asked.Name.Lower().String() + " " + asked.Type.String(), rd: m.RecursionDesired})
	r.mu.Unlock()
	var records [][]byte
	if r.nsSet && asked.Name.LabelCount() == 0 && asked.Type == dnswire.TypeNS {
		for _, l := range "abcdefghijklm" {
			records = append(records, dnswire.AppendRecord(nil, iniRR(".", dnswire.TypeNS, string(l)+".root-servers.net.")))
		}
	}
	b := slices.Clone(q[:2])
	b = binary.BigEndian.AppendUint16(b, r.flags)
	for _, n := range []int{1, len(records), 0, 0} {
		b = binary.BigEndian.AppendUint16(b, uint16(n))
	}
	b = append(b, question...)
	for _, rec := range records {
		b = append(b, rec...)
	}
	return b
}

// iniQuestion gives the question section of a query, whose name a query
// never compresses, or nil.
func iniQuestion(q []byte) []byte {
	if len(q) < 12 || binary.BigEndian.Uint16(q[4:]) != 1 {
		return nil
	}
	i := 12
	for i < len(q) && q[i] != 0 {
		i += int(q[i]) + 1
	}
	if i+5 > len(q) {
		return nil
	}
	return q[12 : i+5]
}

func (r *iniRoot) asked() []iniQuery {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.queries)
}

// iniOut is standard output. Init may read its input in a goroutine of its
// own, so the test reads the text under a lock.
type iniOut struct {
	mu sync.Mutex
	b  strings.Builder
}

func (o *iniOut) Write(p []byte) (int, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.Write(p)
}

func (o *iniOut) String() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.b.String()
}

// iniInput is a person who answers: before each answer it waits until init
// has shown the next question, then types one line. So an init that reads
// its input ahead, as one that can be interrupted does, gets each line only
// after it asked for it. At each question it calls ask. It never calls the
// testing.T: a reader that init leaves running may outlive the test.
type iniInput struct {
	lines []string
	out   *iniOut
	term  bool // as Init.Term
	ask   func() iniMoment
	// When interrupt is set, the input does not end after the last line:
	// at the next question it calls interrupt, as Ctrl-C does, and waits
	// for the run to end.
	interrupt func()
	stop      chan struct{} // closed when the run has ended
	stopOnce  sync.Once
	mu        sync.Mutex
	next      int
	mark      int // the length of the output when the last line was typed
	rest      []byte
	moments   []iniMoment
}

// iniMoment is what the test saw while init waited for an answer.
type iniMoment struct {
	out     string
	changed []string // paths that are not as they were at the start
	checks  int      // checks that the observer had run
}

// iniQuestions are the endings of the output at which init waits for an
// answer.
var iniQuestions = []string{iniDomainsQ, iniURLQ, iniURLQ + "\x1b[8m", "Type yes: "}

func (in *iniInput) Read(p []byte) (int, error) {
	in.mu.Lock()
	defer in.mu.Unlock()
	if len(in.rest) == 0 {
		if in.next == len(in.lines) && in.interrupt == nil {
			return 0, io.EOF
		}
		mark := in.mark
		in.mu.Unlock()
		in.waitForQuestion(mark)
		var m iniMoment
		if in.ask != nil {
			m = in.ask()
		}
		in.mu.Lock()
		in.moments = append(in.moments, m)
		if in.next == len(in.lines) {
			in.mu.Unlock()
			in.interrupt()
			<-in.stop
			in.mu.Lock()
			return 0, io.EOF
		}
		in.rest = []byte(in.lines[in.next] + "\n")
		in.next++
		in.mark = len(in.out.String())
	}
	n := copy(p, in.rest)
	in.rest = in.rest[n:]
	return n, nil
}

// waitForQuestion waits until the output has grown since mark and ends with
// a question, for at most 10 seconds or until the run ends. On a terminal
// the URL question counts only with the code that conceals the answer.
func (in *iniInput) waitForQuestion(mark int) {
	deadline := time.After(10 * time.Second)
	asks := func(out, q string) bool { return strings.HasSuffix(out, q) && !(in.term && q == iniURLQ) }
	for {
		out := in.out.String()
		if len(out) > mark && slices.ContainsFunc(iniQuestions, func(q string) bool { return asks(out, q) }) {
			return
		}
		select {
		case <-in.stop:
			return
		case <-deadline:
			return
		case <-time.After(2 * time.Millisecond):
		}
	}
}

func (in *iniInput) end() { in.stopOnce.Do(func() { close(in.stop) }) }

func (in *iniInput) seen() []iniMoment {
	in.mu.Lock()
	defer in.mu.Unlock()
	return slices.Clone(in.moments)
}

// typed gives the number of lines that init got.
func (in *iniInput) typed() int {
	in.mu.Lock()
	defer in.mu.Unlock()
	return in.next
}

// iniSetup is one run of init with a config in a folder that does not exist
// yet. Every place where init could leave a file is watched: that folder's
// parent, the home folder, the folder of temporary files and the working
// folder, each empty at the start.
type iniSetup struct {
	t       *testing.T
	dir     string
	folder  string
	config  string
	watched []string
	before  map[string]string
	roots   []*iniRoot
	runner  *iniRunner
	in      *iniInput
	out     *iniOut
	ctx     context.Context
	init    Init
}

func iniNew(t *testing.T, answers ...string) *iniSetup {
	t.Helper()
	dir, home, tmp, cwd := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("TMPDIR", tmp)
	t.Chdir(cwd)
	s := &iniSetup{t: t, dir: dir, folder: filepath.Join(dir, "setup"), watched: []string{dir, home, tmp, cwd}}
	s.config = filepath.Join(s.folder, "config.json")
	s.roots = []*iniRoot{iniStartRoot(t, iniQR|iniAA, true, true), iniStartRoot(t, iniQR|iniAA, true, true)}
	s.runner = &iniRunner{}
	s.out = &iniOut{}
	s.ctx = t.Context()
	s.in = &iniInput{lines: answers, out: s.out, stop: make(chan struct{})}
	t.Cleanup(s.in.end)
	s.in.ask = func() iniMoment {
		return iniMoment{out: s.out.String(), changed: iniChanged(s.before, iniTree(s.watched...)), checks: s.runner.count()}
	}
	s.init = Init{
		Config:      s.config,
		RootServers: []netip.AddrPort{s.roots[0].addr, s.roots[1].addr},
		ExtraRanges: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")},
		Observer:    s.runner,
		In:          s.in,
		Out:         s.out,
		Now:         func() time.Time { return iniNow },
	}
	return s
}

func (s *iniSetup) run() (int, string) {
	s.before = iniTree(s.watched...)
	code := s.init.Run(s.ctx)
	s.in.end()
	return code, s.out.String()
}

// iniTree gives the type, mode and content of everything under dirs. A
// folder that cannot be read gets an entry that says why, which then shows
// as a change.
func iniTree(dirs ...string) map[string]string {
	tree := map[string]string{}
	for _, dir := range dirs {
		err := filepath.WalkDir(dir, func(path string, _ fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			info, err := os.Lstat(path)
			if err != nil {
				return err
			}
			v := info.Mode().String()
			switch {
			case info.Mode().IsRegular():
				data, err := os.ReadFile(path)
				if err != nil {
					return err
				}
				v += " " + string(data)
			case info.Mode()&fs.ModeSymlink != 0:
				target, err := os.Readlink(path)
				if err != nil {
					return err
				}
				v += " -> " + target
			}
			tree[path] = v
			return nil
		})
		if err != nil {
			tree[dir+" cannot be read"] = err.Error()
		}
	}
	return tree
}

func iniChanged(before, now map[string]string) []string {
	var changed []string
	for path := range maps.Keys(before) {
		if now[path] != before[path] {
			changed = append(changed, path)
		}
	}
	for path := range maps.Keys(now) {
		if _, ok := before[path]; !ok {
			changed = append(changed, path)
		}
	}
	slices.Sort(changed)
	return changed
}

// nothingWritten checks that every watched folder stayed as it was while
// init waited for each answer and after it ended.
func (s *iniSetup) nothingWritten() {
	s.t.Helper()
	moments := s.in.seen()
	for i, m := range moments {
		if len(m.changed) > 0 {
			s.t.Errorf("while init waited for answer %d, these changed: %q", i+1, m.changed)
		}
	}
	if changed := iniChanged(s.before, iniTree(s.watched...)); len(changed) > 0 {
		s.t.Errorf("init changed %q; want nothing written", changed)
	}
}

// written checks that the folder holds exactly the config, one expectations
// file for each domain and the URL file, each a plain file of mode 0600, and
// gives their texts by name.
func (s *iniSetup) written(domains ...string) map[string]string {
	s.t.Helper()
	want := []string{"config.json", "slack-url"}
	for _, d := range domains {
		want = append(want, strings.TrimSuffix(d, ".")+".expect")
	}
	slices.Sort(want)
	entries, err := os.ReadDir(s.folder)
	if err != nil {
		s.t.Fatalf("the folder of the setup: %v", err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	if !slices.Equal(names, want) {
		s.t.Errorf("the folder holds %q; want exactly %q", names, want)
	}
	texts := map[string]string{}
	for _, name := range want {
		path := filepath.Join(s.folder, name)
		info, err := os.Lstat(path)
		if err != nil {
			s.t.Errorf("%s: %v", name, err)
			continue
		}
		if !info.Mode().IsRegular() || info.Mode().Perm() != 0o600 {
			s.t.Errorf("%s has mode %v; want a plain file of mode 0600", name, info.Mode())
		}
		data, err := os.ReadFile(path)
		if err != nil {
			s.t.Errorf("%s: %v", name, err)
		}
		texts[name] = string(data)
	}
	return texts
}

// holding gives every watched file whose content holds text.
func (s *iniSetup) holding(text string) []string {
	var paths []string
	for path, v := range iniTree(s.watched...) {
		if strings.Contains(v, text) {
			paths = append(paths, path)
		}
	}
	slices.Sort(paths)
	return paths
}

// iniBlock is how init shows the snapshot of one domain.
func iniBlock(d string, lines []string, skips ...string) string {
	var b strings.Builder
	b.WriteString("\n" + d + " as osk-dns-watcher sees it now. Once you confirm, osk-dns-watcher alerts when the servers differ from these lines:\n")
	for _, l := range lines {
		b.WriteString("  " + l + "\n")
	}
	if len(skips) > 0 {
		b.WriteString("Not watched, and why:\n")
		for _, l := range skips {
			b.WriteString("  " + l + "\n")
		}
	}
	return b.String()
}

// iniSetsWarning is the warning after the block of domain d when its NS line
// accepts several sets: each set, in the order of the line, with the servers
// of the parent zone and of the domain that gave it.
func iniSetsWarning(d string, sets ...expect.NSSource) string {
	var b strings.Builder
	b.WriteString("warning the servers of " + d + " give different nameserver sets now. The NS line above accepts each set below; " +
		"a change of the nameservers to any other set gives an alert:\n")
	for _, s := range sets {
		b.WriteString("  " + s.Text + "\n")
		if len(s.Parent) > 0 {
			b.WriteString("    given by the parent zone: " + strings.Join(s.Parent, ", ") + "\n")
		}
		if len(s.Zone) > 0 {
			b.WriteString("    given by the servers of " + d + ": " + strings.Join(s.Zone, ", ") + "\n")
		}
	}
	b.WriteString("If a name in these sets is not one of your nameservers, do not type yes. Else make the sets equal " +
		"at your registrar and DNS provider, then run osk-dns-watcher snapshot " + d + " and put its NS line in the file.\n")
	return b.String()
}

// warnings are the lines of the network flags of the run, as the config
// gives them: one for each list that is not empty, and a root server
// without a port is asked on port 53.
func (s *iniSetup) warnings() string {
	var w string
	if len(s.init.RootServers) > 0 {
		var roots []string
		for _, a := range s.init.RootServers {
			roots = append(roots, iniRootText(a))
		}
		w += "warning network.root_servers is set: osk-dns-watcher starts its walk at " + strings.Join(roots, ", ") +
			" instead of the root servers of the internet, so these servers decide every answer. Use it only in a lab or a private network.\n"
	}
	if len(s.init.ExtraRanges) > 0 {
		var ranges []string
		for _, p := range s.init.ExtraRanges {
			ranges = append(ranges, p.String())
		}
		w += "warning network.extra_ranges is set: data from DNS can now make osk-dns-watcher send queries and HTTPS requests for MTA-STS policy files to " +
			strings.Join(ranges, ", ") + ". Use it only in a lab or a private network.\n"
	}
	return w
}

func iniRootText(a netip.AddrPort) string {
	if a.Port() == 0 {
		a = netip.AddrPortFrom(a.Addr(), 53)
	}
	return a.String()
}

func (s *iniSetup) confirm() string {
	return "\nTrust these lines and write the setup to " + s.folder + "? Type yes: "
}

func (s *iniSetup) wrote(domains ...string) string {
	paths := []string{s.config}
	for _, d := range domains {
		paths = append(paths, filepath.Join(s.folder, strings.TrimSuffix(d, ".")+".expect"))
	}
	return "Wrote " + strings.Join(paths, ", ") + " and " + filepath.Join(s.folder, "slack-url") + ".\n"
}

// shown is the dialogue of a run without a terminal up to the question that
// asks for yes, when the domains answer and the URL each pass at the first
// try. No terminal echoes an answer, so init writes each one back, the URL
// as [hidden].
func (s *iniSetup) shown(domains string, blocks ...string) string {
	return iniHello + iniDomainsQ + domains + "\n" + iniURLQ + "[hidden]\n\n" + iniAsking + strings.Join(blocks, "") +
		s.warnings() + s.confirm()
}

// refused is the dialogue of a run that a domain stops after the snapshot.
func (s *iniSetup) refused(domains, why string) string {
	return iniHello + iniDomainsQ + domains + "\n" + iniURLQ + "[hidden]\n\n" + iniAsking + why + "\n" + iniNothing
}

// iniNotAsked is the line after the block of a domain when this machine has
// no route to some IPv6 addresses of its servers.
func iniNotAsked(n int) string {
	if n == 1 {
		return "Not asked: 1 IPv6 address of the servers, to which this machine has no route.\n"
	}
	return "Not asked: " + strconv.Itoa(n) + " IPv6 addresses of the servers, to which this machine has no route.\n"
}

// configText is the config that init writes for the domains and the network
// flags of the run, in the layout of json.MarshalIndent with two blanks.
func (s *iniSetup) configText(domains ...string) string {
	var b strings.Builder
	b.WriteString("{\n  \"state\": \"state\",\n  \"domains\": [\n")
	for i, d := range domains {
		b.WriteString("    {\n      \"name\": \"" + d + "\",\n      \"expect\": \"" + strings.TrimSuffix(d, ".") + ".expect\"\n    }")
		if i < len(domains)-1 {
			b.WriteString(",")
		}
		b.WriteString("\n")
	}
	var roots, ranges []string
	for _, a := range s.init.RootServers {
		// The config keeps a root server as it was given: no port when none was.
		text := a.String()
		if a.Port() == 0 {
			text = a.Addr().String()
		}
		roots = append(roots, text)
	}
	for _, p := range s.init.ExtraRanges {
		ranges = append(ranges, p.String())
	}
	b.WriteString("  ],\n  \"slack\": {\n    \"url\": {\n      \"file\": \"slack-url\"\n    }\n  },\n  \"network\": {\n" +
		"    \"root_servers\": " + iniList(roots) + ",\n    \"extra_ranges\": " + iniList(ranges) + "\n  }\n}\n")
	return b.String()
}

func iniList(items []string) string {
	if len(items) == 0 {
		return "[]"
	}
	return "[\n      \"" + strings.Join(items, "\",\n      \"") + "\"\n    ]"
}

// iniShown gives the lines that init showed for domain d, without their two
// blanks, and the lines under "Not watched, and why".
func iniShown(out, d string) (lines, skips []string) {
	all := strings.Split(out, "\n")
	i := slices.Index(all, d+" as osk-dns-watcher sees it now. Once you confirm, osk-dns-watcher alerts when the servers differ from these lines:")
	if i < 0 {
		return nil, nil
	}
	into := &lines
	for _, l := range all[i+1:] {
		switch {
		case l == "Not watched, and why:" && into == &lines:
			into = &skips
		case strings.HasPrefix(l, "  "):
			*into = append(*into, l[2:])
		default:
			return lines, skips
		}
	}
	return lines, skips
}

// iniLinesOf gives the lines of a text that are not empty.
func iniLinesOf(text string) []string {
	var lines []string
	for _, l := range strings.Split(text, "\n") {
		if l != "" {
			lines = append(lines, l)
		}
	}
	return lines
}

// iniSame compares two texts and names the first line where they differ.
func iniSame(t *testing.T, what, got, want string) {
	t.Helper()
	if got == want {
		return
	}
	g, w := strings.SplitAfter(got, "\n"), strings.SplitAfter(want, "\n")
	i := 0
	for i < len(g) && i < len(w) && g[i] == w[i] {
		i++
	}
	var gl, wl string
	if i < len(g) {
		gl = g[i]
	}
	if i < len(w) {
		wl = w[i]
	}
	t.Errorf("%s differs at line %d: got %q, want %q\ngot:\n%s\nwant:\n%s", what, i+1, gl, wl, got, want)
}

// iniNoFindings checks that a check run right after init finds nothing in a
// set that init wrote: decide judges each observation that init made of a
// written set against the file as osk-dns-watcher reads it.
func iniNoFindings(t *testing.T, data string, seen []obs.Observation) {
	t.Helper()
	f, err := expect.Parse([]byte(data))
	if err != nil {
		t.Errorf("the expectations file does not parse: %v\n%s", err, data)
		return
	}
	judged := 0
	for _, o := range seen {
		if _, ok := f.Find(o.Key.Name, o.Key.Type); !ok || !o.Key.Domain.Equal(f.Domain) {
			continue
		}
		judged++
		if found := decide.Findings(f, o); len(found) != 0 {
			t.Errorf("check %s right after init finds %d findings, the first %s %s", o.Key, len(found), found[0].Rule, found[0].Value)
		}
	}
	if judged == 0 {
		t.Errorf("no observation of %s is of a set that init wrote", f.Domain)
	}
}

// The first thing a stranger sees, as a pipe gives it: init writes each
// answer back, which no terminal echoed, so the text is that of a terminal.
func TestInitShowsTheDialogueWithoutATerminal(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	code, out := s.run()
	d := "example.com."
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+"yes\n"+s.wrote(d))
}

// On a terminal, concealed text hides the URL while it is typed, and its line
// is then replaced by one that says it was hidden. The terminal echoes the
// answers, so init does not.
func TestInitHidesTheURLOnATerminal(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	s.init.Term, s.in.term = true, true
	code, out := s.run()
	d := "example.com."
	want := iniHello + iniDomainsQ + iniURLQ + "\x1b[8m" + "\x1b[28m\x1b[1A\r\x1b[2K" + iniURLQ + "[hidden]\n\n" + iniAsking +
		iniBlock(d, iniLines(d), iniAliasSkip(d)) + s.warnings() + s.confirm() + s.wrote(d)
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue on a terminal", out, want)
	moments := s.in.seen()
	if len(moments) < 2 || !strings.HasSuffix(moments[1].out, iniURLQ+"\x1b[8m") {
		t.Errorf("while init waited for the URL, the output did not end with the question and the code of concealed text")
	}
	if strings.Contains(out, iniMark) {
		t.Errorf("the output holds the URL")
	}
}

// Nothing is on disk while init waits for any answer, and the question waits
// at the end of the output each time: a piped run gets the same order.
func TestInitWritesNothingBeforeYes(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	code, out := s.run()
	d := "example.com."
	moments := s.in.seen()
	if len(moments) < 3 {
		t.Fatalf("init waited for %d answers; want 3", len(moments))
	}
	shown := s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))
	for i, want := range []string{iniHello + iniDomainsQ, iniHello + iniDomainsQ + "example.com\n" + iniURLQ, shown} {
		iniSame(t, "the output while init waited for answer "+strconv.Itoa(i+1), moments[i].out, want)
		if len(moments[i].changed) > 0 {
			t.Errorf("while init waited for answer %d, these changed: %q", i+1, moments[i].changed)
		}
	}
	// What is written is what was shown: no check runs after the answer.
	if n := s.runner.count(); moments[2].checks != 14 || n != 14 {
		t.Errorf("%d checks had run when yes was asked, %d at the end; want 14 and 14", moments[2].checks, n)
	}
	if code != 0 || !strings.HasSuffix(out, "yes\n"+s.wrote(d)) {
		t.Errorf("exit code %d, output ends %q; want 0 and the written files", code, out[max(0, len(out)-200):])
	}
	s.written(d)
}

func TestInitWritesTheFilesItNamesPrivately(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	d := "example.com."
	files := s.written(d)
	info, err := os.Stat(s.folder)
	if err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the folder that init made: %v; want mode 0700", err)
		if err == nil {
			t.Errorf("its mode is %v", info.Mode())
		}
	}
	iniSame(t, "config.json", files["config.json"], s.configText(d))
	if files["slack-url"] != iniURL+"\n" {
		t.Errorf("slack-url holds %q; want the URL and a line end", files["slack-url"])
	}
	if _, err := os.Lstat(filepath.Join(s.folder, "state")); err == nil {
		t.Errorf("init made the state folder; it opens no store")
	}
}

// The config is one that osk-dns-watcher reads: it names each expectations file and the
// file of the URL, which give the domain's lines and the URL itself.
func TestInitWritesAConfigThatOskReads(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	c, problems := config.Read(s.config)
	if len(problems) != 0 {
		t.Fatalf("config.Read: %v", problems)
	}
	v, problems := c.Secrets(func(string) (string, bool) { return "", false })
	if len(problems) != 0 || v.SlackURL != iniURL {
		t.Errorf("Secrets: %v; want the URL and no problem", problems)
	}
	if c.Slack == nil || c.Slack.URL.File != filepath.Join(s.folder, "slack-url") || c.State != filepath.Join(s.folder, "state") {
		t.Errorf("the config does not name the URL file and the state folder in %s", s.folder)
	}
	if !slices.Equal(c.RootServers, s.init.RootServers) || !slices.Equal(c.ExtraRanges, s.init.ExtraRanges) {
		t.Errorf("the config names root servers %v and ranges %v; want %v and %v", c.RootServers, c.ExtraRanges, s.init.RootServers, s.init.ExtraRanges)
	}
	if len(c.Domains) != 1 || !c.Domains[0].Name.Equal(iniName("example.com.")) || c.Domains[0].Expect != filepath.Join(s.folder, "example.com.expect") {
		t.Fatalf("the config names domains %v; want example.com. with its file in %s", c.Domains, s.folder)
	}
	f, problems := c.Domains[0].Read()
	if len(problems) != 0 {
		t.Fatalf("Domain.Read: %v", problems)
	}
	iniSame(t, "the file as osk-dns-watcher reads it", f.String(), strings.Join(iniLines("example.com."), "\n")+"\n")
}

// The expectations file holds what the dialogue showed, under the stamp; osk-dns-watcher
// prints it back to the same text, and a check right after init finds
// nothing in it.
func TestInitWritesTheLinesItShowed(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	code, out := s.run()
	if code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	d := "example.com."
	lines, _ := iniShown(out, d)
	if !slices.Equal(lines, iniLines(d)) {
		t.Errorf("init showed %q; want %q", lines, iniLines(d))
	}
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
	if f, err := expect.Parse([]byte(data)); err == nil {
		iniSame(t, "the file printed back", f.String(), strings.TrimPrefix(data, iniStamp))
	}
	iniNoFindings(t, data, s.runner.observations())
}

func TestInitKeepsTheURLOnlyInItsFile(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	code, out := s.run()
	if code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	if strings.Contains(out, iniMark) {
		t.Errorf("the output holds the URL")
	}
	if got, want := s.holding(iniMark), []string{filepath.Join(s.folder, "slack-url")}; !slices.Equal(got, want) {
		t.Errorf("the URL is in %q; want it only in %q", got, want)
	}
}

func TestInitWritesOnlyForExactlyYes(t *testing.T) {
	d := "example.com."
	for _, answer := range []string{"no", "", "Yes", "YES", "y", "yes please", "yes."} {
		t.Run(strconv.Quote(answer), func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, answer)
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+answer+"\n"+iniNothing)
			if n := s.runner.count(); n != 14 {
				t.Errorf("%d checks ran; want 14", n)
			}
			s.nothingWritten()
		})
	}
	// Blanks at both ends of an answer are cut.
	t.Run("yes between blanks", func(t *testing.T) {
		s := iniNew(t, "example.com", iniURL, "   yes  ")
		code, out := s.run()
		if code != 0 || !strings.HasSuffix(out, s.wrote(d)) {
			t.Errorf("exit code %d, output:\n%s\nwant 0 and the written files", code, out)
		}
		s.written(d)
	})
}

func TestInitEndOfInputWritesNothing(t *testing.T) {
	d := "example.com."
	for _, c := range []struct {
		name    string
		answers []string
		want    func(s *iniSetup) string
	}{
		{"at the domains", nil, func(*iniSetup) string { return iniHello + iniDomainsQ + "\n" + iniNothing }},
		{"at the URL", []string{"example.com"}, func(*iniSetup) string {
			return iniHello + iniDomainsQ + "example.com\n" + iniURLQ + "\n" + iniNothing
		}},
		{"at yes", []string{"example.com", iniURL}, func(s *iniSetup) string {
			return s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))) + "\n" + iniNothing
		}},
		{"after a name that is not valid", []string{"a..b"}, func(*iniSetup) string {
			return iniHello + iniDomainsQ + "a..b\n" + iniNameProblem(t, "a..b") + iniDomainsQ + "\n" + iniNothing
		}},
		{"after a URL that is not valid", []string{"example.com", "http://hooks.example/x"}, func(*iniSetup) string {
			return iniHello + iniDomainsQ + "example.com\n" + iniURLQ + "[hidden]\n" + iniBadURL + iniURLQ + "\n" + iniNothing
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, c.answers...)
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, c.want(s))
			s.nothingWritten()
		})
	}
}

// Ctrl-C while init waits for yes ends it like the end of input.
func TestInitInterruptWritesNothing(t *testing.T) {
	s := iniNew(t, "example.com", iniURL)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	s.ctx = ctx
	s.in.interrupt = cancel
	done := make(chan int, 1)
	go func() {
		code, _ := s.run()
		done <- code
	}()
	var code int
	select {
	case code = <-done:
	case <-time.After(10 * time.Second):
		t.Fatalf("init did not stop within 10s of the interrupt; output:\n%s", s.out.String())
	}
	d := "example.com."
	if code == 0 {
		t.Errorf("exit code 0; want a failure")
	}
	iniSame(t, "the dialogue", s.out.String(), s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+"\n"+iniNothing)
	s.nothingWritten()
}

// iniNameProblem is the text that refuses a typed field, which init reads
// with a trailing dot added.
func iniNameProblem(t *testing.T, field string) string {
	t.Helper()
	_, err := dnswire.ParseName(field + ".")
	if err == nil {
		t.Fatalf("%q is a valid name", field)
	}
	return `"` + field + `" is not a domain name (` + err.Error() + "). Try again.\n"
}

// iniDomainsList gives n domains, d0.test to d<n-1>.test, as typed.
func iniDomainsList(n int) []string {
	var domains []string
	for i := range n {
		domains = append(domains, "d"+strconv.Itoa(i)+".test")
	}
	return domains
}

func TestInitAsksAgainForDomainsThatAreNotValid(t *testing.T) {
	long := strings.Repeat("x", 64) + ".test"
	many := strings.Join(iniDomainsList(101), " ")
	s := iniNew(t, "a..b example.com", long, ".", "example.com .", "", many, "example.com", iniURL, "no")
	code, out := s.run()
	d := "example.com."
	var want strings.Builder
	want.WriteString(iniHello)
	for _, c := range []struct{ answer, problem string }{
		{"a..b example.com", iniNameProblem(t, "a..b")},
		{long, iniNameProblem(t, long)},
		{".", "osk-dns-watcher does not watch the root. Try again.\n"},
		{"example.com .", "osk-dns-watcher does not watch the root. Try again.\n"},
		{"", "Name at least one domain. Try again.\n"},
		{many, "osk-dns-watcher watches at most 100 domains. Try again.\n"},
	} {
		want.WriteString(iniDomainsQ + c.answer + "\n" + c.problem)
	}
	want.WriteString(strings.TrimPrefix(s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))), iniHello) + "no\n" + iniNothing)
	if code != 1 {
		t.Errorf("exit code %d; want 1", code)
	}
	iniSame(t, "the dialogue", out, want.String())
	keys := s.runner.keys()
	slices.Sort(keys)
	if want := iniKeys(d, true); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
		t.Errorf("checks %q; want only those of %s", keys, d)
	}
}

// A refused URL is never printed and never written, also when a good one
// follows; blanks around the good one are cut.
func TestInitAsksAgainForAURLWithoutShowingIt(t *testing.T) {
	bad := []string{
		"http://hooks.example/Pq3bad1",
		"https://user@hooks.example/Pq3bad2",
		"https:///Pq3bad3",
		"Pq3bad4",
		"",
	}
	s := iniNew(t, slices.Concat([]string{"example.com"}, bad, []string{"  " + iniURL + "  ", "yes"})...)
	code, out := s.run()
	d := "example.com."
	want := iniHello + iniDomainsQ + "example.com\n" + strings.Repeat(iniURLQ+"[hidden]\n"+iniBadURL, len(bad)) +
		strings.TrimPrefix(s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d))), iniHello+iniDomainsQ+"example.com\n") +
		"yes\n" + s.wrote(d)
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, want)
	if strings.Contains(out, "Pq3bad") {
		t.Errorf("the output holds a refused URL")
	}
	if paths := s.holding("Pq3bad"); len(paths) != 0 {
		t.Errorf("%q hold a refused URL", paths)
	}
	if text := s.written(d)["slack-url"]; text != iniURL+"\n" {
		t.Errorf("slack-url holds %q; want the URL without blanks and a line end", text)
	}
}

// Each field gets a trailing dot and lower case; a name given twice is kept
// once, where it came first.
func TestInitCleansAndDeduplicatesTheDomains(t *testing.T) {
	answer := "Shop.TEST example.com. shop.test.\tEXAMPLE.COM"
	s := iniNew(t, answer, iniURL, "yes")
	code, out := s.run()
	a, b := "shop.test.", "example.com."
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out,
		s.shown(answer, iniBlock(a, iniLines(a), iniAliasSkip(a)), iniBlock(b, iniLines(b), iniAliasSkip(b)))+"yes\n"+s.wrote(a, b))
	files := s.written(a, b)
	iniSame(t, "config.json", files["config.json"], s.configText(a, b))
	keys := s.runner.keys()
	slices.Sort(keys)
	if want := slices.Concat(iniKeys(a, true), iniKeys(b, true)); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
		t.Errorf("checks %q; want each of %q once", keys, want)
	}
}

// The limit counts distinct domains.
func TestInitTakesAtMostHundredDomains(t *testing.T) {
	many := strings.Join(iniDomainsList(101), " ")
	hundred := strings.Join(append(iniDomainsList(100), "D0.test."), " ")
	s := iniNew(t, many, hundred, iniURL, "no")
	code, out := s.run()
	start := iniHello + iniDomainsQ + many + "\nosk-dns-watcher watches at most 100 domains. Try again.\n" + iniDomainsQ + hundred + "\n" + iniURLQ + "[hidden]\n"
	if code != 1 || !strings.HasPrefix(out, start) {
		t.Errorf("exit code %d, output starts:\n%s\nwant 1, and 101 domains asked again, 100 taken", code, out[:min(len(out), len(start)+100)])
	}
	if n := strings.Count(out, " as osk-dns-watcher sees it now."); n != 100 {
		t.Errorf("init showed %d domains; want 100", n)
	}
	if n := s.runner.count(); n != 1400 {
		t.Errorf("%d checks ran; want 1400", n)
	}
	s.nothingWritten()
}

// The checks of a domain are those of "osk-dns-watcher snapshot" for the six sets, www,
// the DMARC and MTA-STS names, the two challenge names and the wildcard name,
// with the interval of the faster checks, and they run at once: the observer
// answers no check before all fourteen have started.
func TestInitRunsTheFourteenChecksOfADomainAtOnce(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "no")
	all := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	apart := false
	deadline := time.Now().Add(5 * time.Second)
	s.runner.during = func(calls int) {
		if calls == 14 {
			once.Do(func() { close(all) })
		}
		select {
		case <-all:
		case <-time.After(time.Until(deadline)):
			mu.Lock()
			apart = true
			mu.Unlock()
		}
	}
	code, _ := s.run()
	if code != 1 {
		t.Errorf("exit code %d; want 1", code)
	}
	mu.Lock()
	if apart {
		t.Errorf("the fourteen checks did not run at once")
	}
	mu.Unlock()
	keys := s.runner.keys()
	slices.Sort(keys)
	if want := iniKeys("example.com.", true); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
		t.Errorf("checks %q; want each of %q once", keys, want)
	}
	s.runner.mu.Lock()
	for _, c := range s.runner.checks {
		if c.Interval != time.Minute {
			t.Errorf("check %s has interval %v; want 1m0s", c.Key, c.Interval)
		}
	}
	s.runner.mu.Unlock()
}

// No name under <d> may be longer than a name may be, so none of the four
// pairs under it is asked.
func TestInitLeavesOutTheChecksUnderALongName(t *testing.T) {
	d := strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61) + "."
	if _, err := dnswire.ParseName(d); err != nil {
		t.Fatalf("%s: %v", d, err)
	}
	if _, err := dnswire.ParseName("www." + d); err == nil {
		t.Fatalf("www.%s is a valid name", d)
	}
	s := iniNew(t, d, iniURL, "no")
	// Its mail host could not be a name either.
	s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeMX): iniBoth(iniRecords(d, dnswire.TypeMX, "10 mail.example.net."))}
	code, out := s.run()
	if code != 1 || !strings.Contains(out, d+" as osk-dns-watcher sees it now.") {
		t.Errorf("exit code %d, output:\n%s\nwant 1 and the snapshot of %s", code, out, d)
	}
	keys := s.runner.keys()
	slices.Sort(keys)
	if want := iniKeys(d, false); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
		t.Errorf("checks %q; want each of %q once", keys, want)
	}
}

func iniNoAnswer(d, reasons string) string {
	return "osk-dns-watcher got no answer about " + d + " from its parent zone (" + reasons +
		"). Check the name, and that this machine may send DNS queries (port 53) to the internet."
}

func iniDenied(d string) string {
	return "The parent zone says that " + d + " does not exist or has no nameservers. Check the name."
}

// A refusal comes before any domain is shown, so its text is the only one.
func TestInitRefusesADomainThatGivesNoAnswer(t *testing.T) {
	for _, c := range []struct {
		name, domains, refused, why string
		answers                     []obs.Answer
	}{
		{"every parent server failed", "example.com", "example.com.", iniNoAnswer("example.com.", "timeout,network"), []obs.Answer{
			iniAt("a.parent.example.", "192.0.2.1:53", iniFail(obs.ReasonTimeout)),
			iniAt("b.parent.example.", "192.0.2.2:53", iniFail(obs.ReasonNetwork)),
			iniAt("c.parent.example.", "192.0.2.3:53", iniFail(obs.ReasonTimeout)),
		}},
		{"the walk failed", "example.com", "example.com.", iniNoAnswer("example.com.", "walk"),
			[]obs.Answer{{Result: iniFail(obs.ReasonWalk)}}},
		{"the second of two domains", "example.com example.org", "example.org.", iniNoAnswer("example.org.", "refused"),
			[]obs.Answer{iniAt(iniParentHost, iniParentAddr, iniFail(obs.ReasonRefused))}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, c.domains, iniURL, "yes")
			s.runner.over = map[string][]obs.Answer{obs.DelegationKey(iniName(c.refused)).String(): c.answers}
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, s.refused(c.domains, c.why))
			s.nothingWritten()
		})
	}
}

func TestInitRefusesADomainThatTheParentDenies(t *testing.T) {
	d := "example.com."
	for _, c := range []struct {
		name    string
		answers []obs.Answer
	}{
		{"no such name", []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniNoName("com."))}},
		{"no data", []obs.Answer{iniAt(iniParentHost, iniParentAddr, iniNoData("com."))}},
		{"one server of two says no such name", []obs.Answer{
			iniAt("a.parent.example.", "192.0.2.1:53", iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
			iniAt("b.parent.example.", "192.0.2.2:53", iniNoName("com.")),
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = map[string][]obs.Answer{obs.DelegationKey(iniName(d)).String(): c.answers}
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the dialogue", out, s.refused("example.com", iniDenied(d)))
			s.nothingWritten()
		})
	}
	// Domains are judged in the order given: the first refusal is the one shown.
	t.Run("the first of two refused domains", func(t *testing.T) {
		s := iniNew(t, "example.com example.org", iniURL, "yes")
		s.runner.over = map[string][]obs.Answer{
			obs.DelegationKey(iniName(d)).String():              {iniAt(iniParentHost, iniParentAddr, iniNoName("com."))},
			obs.DelegationKey(iniName("example.org.")).String(): {iniAt(iniParentHost, iniParentAddr, iniFail(obs.ReasonTimeout))},
		}
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		iniSame(t, "the dialogue", out, s.refused("example.com example.org", iniDenied(d)))
		s.nothingWritten()
	})
}

func TestInitListsTheSetsItCannotWatchAndLeavesThemOut(t *testing.T) {
	d := "example.com."
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeMX): {
		iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeMX, "10 mail.example.com.")),
		iniAt("ns2.example.net.", iniNS2Addr, iniFail(obs.ReasonTimeout)),
	}}
	code, out := s.run()
	lines := slices.DeleteFunc(iniLines(d), func(l string) bool { return strings.Contains(l, " MX ") })
	skips := []string{d + " MX: " + iniNS2Addr + " ns2.example.net. gave no answer (timeout)", iniAliasSkip(d)}
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, skips...))+"yes\n"+s.wrote(d))
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
	iniNoFindings(t, data, s.runner.observations())
}

// One nameserver of two is the attacker's during the setup. Each set where it
// differs is shown as not watched, with both answers made safe to print, and
// is not written; the sets where it agrees are. The NS set is the one
// exception: the attacker's set becomes one alternative of the NS line, and
// is never trusted unseen: the warning before the question names it with the
// address of the server that gave it.
func TestInitDoesNotTrustASetTheServersDisagreeOn(t *testing.T) {
	d := "example.com."
	lie := iniRR(d, dnswire.TypeTXT, `"v=spf1 +all\010\027[2JTrust these lines and write the setup? Type yes: yes"`)
	lieText := expect.SetText(dnswire.TypeTXT, []dnswire.Record{lie})
	if strings.ContainsFunc(lieText, func(r rune) bool { return r < 0x20 || r == 0x7f }) {
		t.Fatalf("SetText keeps a control octet: %q", lieText)
	}
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = map[string][]obs.Answer{
		iniKey(d, d, dnswire.TypeNS): {
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns2.example.net.")),
			iniAt("ns2.example.net.", iniNS2Addr, iniRecords(d, dnswire.TypeNS, "ns1.example.net.", "ns.attacker.example.")),
		},
		iniKey(d, d, dnswire.TypeTXT): {
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeTXT, `"v=spf1 mx -all"`)),
			iniAt("ns2.example.net.", iniNS2Addr, obs.RecordsResult(obs.Records{Set: []dnswire.Record{lie}})),
		},
		iniKey(d, "www."+d, dnswire.TypeA): {
			iniAt("ns1.example.net.", iniNS1Addr, iniRecords("www."+d, dnswire.TypeA, "192.0.2.10")),
			iniAt("ns2.example.net.", iniNS2Addr, iniRecords("www."+d, dnswire.TypeA, "203.0.113.66")),
		},
	}
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0; output:\n%s", code, out)
	}
	if strings.ContainsFunc(out, func(r rune) bool { return r < 0x20 && r != '\n' || r == 0x7f }) {
		t.Errorf("the output holds a control octet other than the line end:\n%q", out)
	}
	want := slices.DeleteFunc(slices.Clone(iniLines(d)), func(l string) bool { return strings.HasPrefix(l, d+" TXT ") })
	nsLine := d + " NS ns.attacker.example. | ns1.example.net. || ns1.example.net. | ns2.example.net."
	want[slices.Index(want, d+" NS ns1.example.net. | ns2.example.net.")] = nsLine
	skips := []string{
		d + ` TXT: servers disagree: ` + iniNS1Addr + ` ns1.example.net. gives "v=spf1 mx -all"; ` + iniNS2Addr + " ns2.example.net. gives " + lieText,
		"www." + d + " A: servers disagree: " + iniNS1Addr + " ns1.example.net. gives 192.0.2.10; " + iniNS2Addr + " ns2.example.net. gives 203.0.113.66",
	}
	warning := iniSetsWarning(d,
		expect.NSSource{Text: "ns.attacker.example. | ns1.example.net.", Zone: []string{iniNS2Addr + " ns2.example.net."}},
		expect.NSSource{Text: "ns1.example.net. | ns2.example.net.", Parent: []string{iniParentAddr + " " + iniParentHost},
			Zone: []string{iniNS1Addr + " ns1.example.net."}})
	// The whole dialogue: the warning ends the block, before the question.
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, want, skips...)+warning)+"yes\n"+s.wrote(d))
	data := s.written(d)["example.com.expect"]
	iniSame(t, "example.com.expect", data, iniStamp+strings.Join(want, "\n")+"\n")
	for _, text := range []string{"203.0.113.66", "+all"} {
		if paths := s.holding(text); len(paths) != 0 {
			t.Errorf("%q hold %q", paths, text)
		}
	}
	// The attacker's set is in the file only as an alternative of the NS line.
	if paths := s.holding("attacker"); !slices.Equal(paths, []string{filepath.Join(s.folder, "example.com.expect")}) {
		t.Errorf("%q hold the attacker's name; want only the expectations file", paths)
	}
	for l := range strings.Lines(data) {
		if strings.Contains(l, "attacker") && strings.TrimSuffix(l, "\n") != nsLine {
			t.Errorf("the line %q holds the attacker's name", l)
		}
	}
}

// A machine without IPv6 has no route to an IPv6 address of a server. That
// alone does not keep a set out of the file when another address answers and
// all that answer agree: the set is written, the file says nothing of the
// address, and the dialogue counts each such address once under the domain.
// Every other failure still keeps the set out.
func TestInitWritesASetWhoseOnlyFailureIsAnAddressWithNoRoute(t *testing.T) {
	d := "example.com."
	a := func(data string) obs.Result { return iniRecords(d, dnswire.TypeA, data) }
	ok := []obs.Answer{iniAt("ns1.example.net.", iniNS1Addr, a("192.0.2.10"))}
	unreached := func(addr string) obs.Answer { return iniAt("ns1.example.net.", addr, iniFail(obs.ReasonNoRoute)) }
	ns2 := iniAt("ns2.example.net.", iniNS2Addr, a("192.0.2.10"))
	mx := func(answers ...obs.Answer) []obs.Answer { return answers }
	for _, c := range []struct {
		name     string
		over     map[string][]obs.Answer
		notAsked int
	}{
		{"one address", map[string][]obs.Answer{
			iniKey(d, d, dnswire.TypeA): slices.Concat(ok, []obs.Answer{unreached(iniNS1v6Addr), ns2}),
		}, 1},
		{"one address in two sets", map[string][]obs.Answer{
			iniKey(d, d, dnswire.TypeA): slices.Concat(ok, []obs.Answer{unreached(iniNS1v6Addr), ns2}),
			iniKey(d, d, dnswire.TypeMX): mx(
				iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeMX, "10 mail."+d)),
				iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
				iniAt("ns2.example.net.", iniNS2Addr, iniRecords(d, dnswire.TypeMX, "10 mail."+d))),
		}, 1},
		{"two addresses", map[string][]obs.Answer{
			iniKey(d, d, dnswire.TypeA): slices.Concat(ok, []obs.Answer{unreached(iniNS1v6Addr), ns2}),
			iniKey(d, d, dnswire.TypeMX): mx(
				iniAt("ns1.example.net.", iniNS1Addr, iniRecords(d, dnswire.TypeMX, "10 mail."+d)),
				iniAt("ns2.example.net.", iniNS2Addr, iniRecords(d, dnswire.TypeMX, "10 mail."+d)),
				iniAt("ns2.example.net.", iniNS2v6Addr, iniFail(obs.ReasonNoRoute))),
		}, 2},
		// www.<d> has an address here, so no set is left out and the count
		// follows the lines.
		{"one address, every set watched", map[string][]obs.Answer{
			iniKey(d, d, dnswire.TypeA):        slices.Concat(ok, []obs.Answer{unreached(iniNS1v6Addr), ns2}),
			iniKey(d, "www."+d, dnswire.TypeA): iniBoth(iniRecords("www."+d, dnswire.TypeA, "192.0.2.80")),
		}, 1},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = c.over
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			lines, skips := iniLines(d), []string{iniAliasSkip(d)}
			if _, ok := c.over[iniKey(d, "www."+d, dnswire.TypeA)]; ok {
				// It sorts before the challenge name under it.
				at := slices.Index(lines, "_acme-challenge.www."+d+" TXT none")
				lines, skips = slices.Insert(lines, at, "www."+d+" A 192.0.2.80"), nil
			}
			iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, skips...)+iniNotAsked(c.notAsked))+"yes\n"+s.wrote(d))
			data := s.written(d)["example.com.expect"]
			iniSame(t, "example.com.expect", data, iniStamp+strings.Join(lines, "\n")+"\n")
			iniNoFindings(t, data, s.runner.observations())
		})
	}
}

func TestInitDoesNotWatchASetWithAnyOtherFailure(t *testing.T) {
	d := "example.com."
	a := func(data string) obs.Result { return iniRecords(d, dnswire.TypeA, data) }
	without := slices.DeleteFunc(iniLines(d), func(l string) bool { return strings.HasPrefix(l, d+" A ") })
	for _, c := range []struct {
		name    string
		answers []obs.Answer
		why     string // the reason it is not watched; "" when it depends on the order of the rules
	}{
		{"an IPv4 address that cannot be reached", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a("192.0.2.10")),
			iniAt("ns2.example.net.", iniNS2Addr, iniFail(obs.ReasonNetwork)),
		}, iniNS2Addr + " ns2.example.net. gave no answer (network)"},
		{"an IPv6 address that timed out", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a("192.0.2.10")),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonTimeout)),
			iniAt("ns2.example.net.", iniNS2Addr, a("192.0.2.10")),
		}, iniNS1v6Addr + " ns1.example.net. gave no answer (timeout)"},
		{"an IPv6 address with a network failure", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a("192.0.2.10")),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNetwork)),
			iniAt("ns2.example.net.", iniNS2Addr, a("192.0.2.10")),
		}, iniNS1v6Addr + " ns1.example.net. gave no answer (network)"},
		{"only IPv6 addresses, none with a route", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
			iniAt("ns2.example.net.", iniNS2v6Addr, iniFail(obs.ReasonNoRoute)),
		}, iniNS1v6Addr + " ns1.example.net. gave no answer (no-route)"},
		{"an IPv6 address with no route, and answers that differ", []obs.Answer{
			iniAt("ns1.example.net.", iniNS1Addr, a("192.0.2.10")),
			iniAt("ns1.example.net.", iniNS1v6Addr, iniFail(obs.ReasonNoRoute)),
			iniAt("ns2.example.net.", iniNS2Addr, a("203.0.113.66")),
		}, ""},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeA): c.answers}
			code, out := s.run()
			if code != 0 {
				t.Errorf("exit code %d; want 0", code)
			}
			if c.why != "" {
				iniSame(t, "the dialogue", out,
					s.shown("example.com", iniBlock(d, without, d+" A: "+c.why, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
			}
			lines, skips := iniShown(out, d)
			if !slices.Equal(lines, without) || len(skips) != 2 || !strings.HasPrefix(skips[0], d+" A: ") {
				t.Errorf("shown %q, not watched %q; want %s A only under not watched", lines, skips, d)
			}
			if strings.Contains(out, "Not asked:") {
				t.Errorf("init counts an address of a set that it does not write")
			}
			iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(without, "\n")+"\n")
		})
	}
}

// A VPN, router or provider that answers for the root servers would decide
// every answer. Init finds it before it asks anything, with the observer of
// the real tool, so it stops whichever way it asks the root servers.
func TestInitStopsBeforeAnyQuestionBehindADNSProxy(t *testing.T) {
	for _, c := range []struct {
		name  string
		roots func(t *testing.T) []*iniRoot
	}{
		{"an answer with recursion and without authority", func(t *testing.T) []*iniRoot {
			return []*iniRoot{iniStartRoot(t, iniQR|iniRA, true, true)}
		}},
		{"an answer with recursion and authority", func(t *testing.T) []*iniRoot {
			return []*iniRoot{iniStartRoot(t, iniQR|iniAA|iniRA, true, true)}
		}},
		{"an answer without the NS set of the root", func(t *testing.T) []*iniRoot {
			return []*iniRoot{iniStartRoot(t, iniQR|iniAA, false, true)}
		}},
		{"a closed TCP port", func(t *testing.T) []*iniRoot {
			return []*iniRoot{iniStartRoot(t, iniQR|iniAA, true, false)}
		}},
		{"the second of two root servers", func(t *testing.T) []*iniRoot {
			return []*iniRoot{iniStartRoot(t, iniQR|iniAA, true, true), iniStartRoot(t, iniQR|iniRA, true, true)}
		}},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			var addrs []netip.AddrPort
			for _, r := range c.roots(t) {
				addrs = append(addrs, r.addr)
			}
			o, err := observe.New(observe.Config{RootServers: addrs, ExtraRanges: s.init.ExtraRanges})
			if err != nil {
				t.Fatal(err)
			}
			counted := &iniCounted{Runner: o}
			s.init.RootServers, s.init.Observer = addrs, counted
			code, out := s.run()
			if code != 1 {
				t.Errorf("exit code %d; want 1", code)
			}
			iniSame(t, "the output", out, iniProxy)
			if typed := s.in.typed(); typed != 0 || counted.count() != 0 {
				t.Errorf("init got %d answers and ran %d checks; want neither", typed, counted.count())
			}
			s.nothingWritten()
		})
	}
}

// Each root server given is asked for the NS set of the root without the
// flag that asks for recursion.
func TestInitAsksEachRootServerWithoutRecursion(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	for _, r := range s.roots {
		queries := r.asked()
		if !slices.ContainsFunc(queries, func(q iniQuery) bool { return q.question == ". NS" }) {
			t.Errorf("root server %v was not asked for . NS; it got %v", r.addr, queries)
		}
		for _, q := range queries {
			if q.rd {
				t.Errorf("root server %v got %s with recursion desired", r.addr, q.question)
			}
		}
	}
}

// A setup that exists is left alone before anything else is done, also on a
// network that would stop init, so that every start may run init.
func TestInitRefusesAnExistingSetup(t *testing.T) {
	for _, c := range []struct {
		name  string
		make  func(path string) error
		proxy bool
	}{
		{"a file", func(path string) error { return os.WriteFile(path, []byte("not even a config\n"), 0o644) }, false},
		{"a folder", func(path string) error { return os.Mkdir(path, 0o755) }, false},
		{"a link to nothing", func(path string) error { return os.Symlink("missing", path) }, false},
		{"a file, behind a DNS proxy", func(path string) error { return os.WriteFile(path, []byte("{}\n"), 0o600) }, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			s := iniNew(t, "example.com", iniURL, "yes")
			if c.proxy {
				s.init.RootServers = []netip.AddrPort{iniStartRoot(t, iniQR|iniRA, true, true).addr}
			}
			if err := os.Mkdir(s.folder, 0o700); err != nil {
				t.Fatal(err)
			}
			if err := c.make(s.config); err != nil {
				t.Fatal(err)
			}
			code, out := s.run()
			if want := "osk-dns-watcher is set up already: " + s.config + " exists. Nothing to ask.\n"; code != 0 || out != want {
				t.Errorf("exit code %d, output %q; want 0 and %q", code, out, want)
			}
			if typed := s.in.typed(); typed != 0 || s.runner.count() != 0 {
				t.Errorf("init got %d answers and ran %d checks; want neither", typed, s.runner.count())
			}
			s.nothingWritten()
		})
	}
}

// A list of the network that no flag gave is written empty, and has no
// warning.
func TestInitWritesAnEmptyListForAFlagNotGiven(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	s.init.ExtraRanges = nil
	code, out := s.run()
	d := "example.com."
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	iniSame(t, "config.json", s.written(d)["config.json"], s.configText(d))
	if _, problems := config.Read(s.config); len(problems) != 0 {
		t.Errorf("config.Read: %v", problems)
	}
}

// Flags that make a config osk-dns-watcher refuses stop init before the question.
func TestInitStopsWhenTheFlagsMakeAConfigThatOskRefuses(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	for port := range 15 {
		s.init.RootServers = append(s.init.RootServers, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), uint16(1000+port)))
	}
	code, out := s.run()
	lines := iniLinesOf(out)
	n := len(lines)
	if code != 1 || n < 2 || lines[n-1] != strings.TrimSuffix(iniNothing, "\n") ||
		!strings.HasPrefix(lines[n-2], "osk-dns-watcher: ") || !strings.Contains(lines[n-2], "want at most 16 root servers") {
		t.Errorf("exit code %d, output:\n%s\nwant 1, the problem of the root servers as \"osk-dns-watcher: ...\" and %q", code, out, iniNothing)
	}
	if strings.Contains(out, "Type yes") {
		t.Errorf("init asked for yes")
	}
	s.nothingWritten()
}

// A run that was cut can leave the URL file and expectations files, of any
// mode. The next run writes them again, private.
func TestInitRewritesLeftoverFilesAsPrivate(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	if err := os.Mkdir(s.folder, 0o700); err != nil {
		t.Fatal(err)
	}
	for name, mode := range map[string]os.FileMode{"slack-url": 0o644, "example.com.expect": 0o666} {
		path := filepath.Join(s.folder, name)
		if err := os.WriteFile(path, []byte("left from a run that was cut, longer than the new text of the file ...\n"), mode); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, mode); err != nil {
			t.Fatal(err)
		}
	}
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	files := s.written("example.com.")
	if files["slack-url"] != iniURL+"\n" {
		t.Errorf("slack-url holds %q; want the URL and a line end", files["slack-url"])
	}
	iniSame(t, "example.com.expect", files["example.com.expect"], iniStamp+strings.Join(iniLines("example.com."), "\n")+"\n")
}

// Another run may write the config while this one waits: this one does not
// replace it.
func TestInitDoesNotReplaceAConfigWrittenMeanwhile(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	other := "{\"written\": \"by another run\"}\n"
	var once sync.Once
	s.runner.during = func(int) {
		once.Do(func() {
			if err := os.MkdirAll(s.folder, 0o700); err != nil {
				t.Error(err)
			}
			if err := os.WriteFile(s.config, []byte(other), 0o600); err != nil {
				t.Error(err)
			}
		})
	}
	code, out := s.run()
	lines := iniLinesOf(out)
	if code != 1 || len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "osk-dns-watcher: ") || !strings.Contains(out, "Type yes: ") {
		t.Errorf("exit code %d, output:\n%s\nwant 1, and a last line \"osk-dns-watcher: ...\" after the question", code, out)
	}
	if data, err := os.ReadFile(s.config); err != nil || string(data) != other {
		t.Errorf("the config now holds %q, %v; want %q", data, err, other)
	}
	if strings.Contains(out, iniMark) {
		t.Errorf("the output holds the URL")
	}
}

// The config is written last, so a run that fails while writing leaves no
// config, and the next run starts again.
func TestInitWriteErrorLeavesNoConfig(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	if err := os.MkdirAll(filepath.Join(s.folder, "slack-url"), 0o700); err != nil {
		t.Fatal(err)
	}
	code, out := s.run()
	lines := iniLinesOf(out)
	if code != 1 || len(lines) == 0 || !strings.HasPrefix(lines[len(lines)-1], "osk-dns-watcher: ") || !strings.Contains(out, "Type yes: ") {
		t.Errorf("exit code %d, output:\n%s\nwant 1, and a last line \"osk-dns-watcher: ...\" after the question", code, out)
	}
	if _, err := os.Lstat(s.config); err == nil {
		t.Errorf("a config was written")
	}
	if strings.Contains(out, iniMark) {
		t.Errorf("the output holds the URL")
	}
}

// The paths that init prints are absolute; those in the config stay relative
// to its folder.
func TestInitGivesAbsolutePathsForARelativeConfig(t *testing.T) {
	s := iniNew(t, "example.com", iniURL, "yes")
	s.init.Config = filepath.Join("setup", "config.json")
	folder, err := filepath.Abs("setup")
	if err != nil {
		t.Fatal(err)
	}
	s.folder, s.config = folder, filepath.Join(folder, "config.json")
	code, out := s.run()
	d := "example.com."
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, iniLines(d), iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	iniSame(t, "config.json", s.written(d)["config.json"], s.configText(d))
}

// --- the challenge names and the wildcard name ---

// iniLongName gives a name of n octets in wire form: three labels of 63
// octets and a first label that makes up the rest.
func iniLongName(t *testing.T, n int) string {
	t.Helper()
	d := strings.Repeat("e", n-194) + "." + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "."
	if _, err := dnswire.ParseName(d); err != nil {
		t.Fatalf("a name of %d octets: %v", n, err)
	}
	return d
}

// The names under the domain follow www in the order that osk-dns-watcher snapshot
// gives its sets, and every one is a records check.
func TestLookKeysAsksTheChallengeAndWildcardNamesAfterWWW(t *testing.T) {
	d := "example.com."
	got := lookKeys(iniName(d))
	var texts []string
	for _, k := range got {
		texts = append(texts, k.String())
	}
	want := []string{
		obs.DelegationKey(iniName(d)).String(),
		obs.DSKey(iniName(d)).String(),
		iniKey(d, d, dnswire.TypeNS),
		iniKey(d, d, dnswire.TypeA),
		iniKey(d, d, dnswire.TypeAAAA),
		iniKey(d, d, dnswire.TypeMX),
		iniKey(d, d, dnswire.TypeTXT),
		iniKey(d, d, dnswire.TypeCAA),
		iniKey(d, "www."+d, dnswire.TypeA),
		iniKey(d, "_dmarc."+d, dnswire.TypeTXT),
		iniKey(d, "_mta-sts."+d, dnswire.TypeTXT),
		iniKey(d, "_acme-challenge."+d, dnswire.TypeTXT),
		iniKey(d, "_acme-challenge.www."+d, dnswire.TypeTXT),
		iniKey(d, "*."+d, dnswire.TypeA),
	}
	if !slices.Equal(texts, want) {
		t.Errorf("lookKeys gave\n%s\nwant\n%s", strings.Join(texts, "\n"), strings.Join(want, "\n"))
	}
	for _, k := range got[8:] {
		if k.Kind != obs.KindRecords {
			t.Errorf("%s is a check of kind %v; want a records check", k, k.Kind)
		}
	}
}

// Each name is left out when it is longer than a name may be, and not
// before: a name may have 255 octets, and each prefix adds its own length.
func TestLookKeysLeavesOutEachNameThatWouldBeTooLong(t *testing.T) {
	for _, c := range []struct {
		octets int
		under  []string // the names kept, in order
	}{
		{235, []string{"www", "_dmarc", "_mta-sts", "_acme-challenge", "_acme-challenge.www", "*"}},
		{236, []string{"www", "_dmarc", "_mta-sts", "_acme-challenge", "*"}},
		{239, []string{"www", "_dmarc", "_mta-sts", "_acme-challenge", "*"}},
		{240, []string{"www", "_dmarc", "_mta-sts", "*"}},
		{246, []string{"www", "_dmarc", "_mta-sts", "*"}},
		{247, []string{"www", "_dmarc", "*"}},
		{248, []string{"www", "_dmarc", "*"}},
		{249, []string{"www", "*"}},
		{251, []string{"www", "*"}},
		{252, []string{"*"}},
		{253, []string{"*"}},
		{254, nil},
		{255, nil},
	} {
		t.Run(strconv.Itoa(c.octets), func(t *testing.T) {
			d := iniLongName(t, c.octets)
			var got []string
			for _, k := range lookKeys(iniName(d)) {
				got = append(got, k.String())
			}
			want := iniKeys(d, false)
			for _, prefix := range c.under {
				typ := dnswire.TypeTXT
				if prefix == "www" || prefix == "*" {
					typ = dnswire.TypeA
				}
				want = append(want, iniKey(d, prefix+"."+d, typ))
			}
			if !slices.Equal(got, want) {
				t.Errorf("lookKeys of a name of %d octets gave\n%s\nwant\n%s", c.octets, strings.Join(got, "\n"), strings.Join(want, "\n"))
			}
		})
	}
}

// A name that has room for the wildcard name only is asked that one name,
// and init shows its line.
func TestInitAsksOnlyTheWildcardNameOfALongName(t *testing.T) {
	d := iniLongName(t, 253)
	s := iniNew(t, d, iniURL, "no")
	s.runner.over = map[string][]obs.Answer{iniKey(d, d, dnswire.TypeMX): iniBoth(iniRecords(d, dnswire.TypeMX, "10 mail.example.net."))}
	code, out := s.run()
	if code != 1 {
		t.Errorf("exit code %d; want 1", code)
	}
	keys := s.runner.keys()
	slices.Sort(keys)
	if want := append(iniKeys(d, false), iniKey(d, "*."+d, dnswire.TypeA)); !slices.Equal(keys, slices.Sorted(slices.Values(want))) {
		t.Errorf("checks %q; want each of %q once", keys, want)
	}
	lines, _ := iniShown(out, d)
	if want := "*." + d + " A none"; !slices.Contains(lines, want) {
		t.Errorf("init showed %q; want the line %q among them", lines, want)
	}
}

// A wildcard that answers has a data line at the name, in the place of the
// none line.
func TestInitWritesTheAddressOfAWildcardThatAnswers(t *testing.T) {
	d := "example.com."
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = map[string][]obs.Answer{iniKey(d, "*."+d, dnswire.TypeA): iniBoth(iniRecords("*."+d, dnswire.TypeA, "192.0.2.99"))}
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0; output:\n%s", code, out)
	}
	lines := slices.Clone(iniLines(d))
	lines[slices.Index(lines, "*."+d+" A none")] = "*." + d + " A 192.0.2.99"
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
}

// A certificate-challenge record that is there during the setup would give
// an alert at once, as an exact line, when it goes; init leaves the name out
// and says why.
func TestInitLeavesOutAChallengeRecordThatIsThere(t *testing.T) {
	d := "example.com."
	s := iniNew(t, "example.com", iniURL, "yes")
	s.runner.over = map[string][]obs.Answer{
		iniKey(d, "_acme-challenge."+d, dnswire.TypeTXT): iniBoth(iniRecords("_acme-challenge."+d, dnswire.TypeTXT, `"t0ken1"`)),
	}
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0; output:\n%s", code, out)
	}
	lines := slices.DeleteFunc(slices.Clone(iniLines(d)), func(l string) bool { return l == "_acme-challenge."+d+" TXT none" })
	challenge := "_acme-challenge." + d + " TXT: a certificate-challenge record is there now; write none once it is gone, or no line if you use DNS challenges"
	iniSame(t, "the dialogue", out, s.shown("example.com", iniBlock(d, lines, challenge, iniAliasSkip(d)))+"yes\n"+s.wrote(d))
	iniSame(t, "example.com.expect", s.written(d)["example.com.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
}
