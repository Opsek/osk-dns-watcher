//go:build lab

package start

import (
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/osk-dns-watcher/internal/config"
	"github.com/Opsek/osk-dns-watcher/internal/decide"
	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/expect"
	"github.com/Opsek/osk-dns-watcher/internal/observe"
	"github.com/Opsek/osk-dns-watcher/internal/observe/obs"
)

// iniLab gives the start of every lab address, "10.53.<LAB_ID>.", and puts
// the lab back into its base state when the test ends.
func iniLab(t *testing.T) string {
	t.Helper()
	n := "10.53." + os.Getenv("LAB_ID") + "."
	if _, err := netip.ParseAddr(n + "1"); err != nil {
		t.Fatalf("LAB_ID: %v; this test runs in the runner of the lab", err)
	}
	t.Cleanup(func() {
		if out, err := exec.Command("labctl", "reset").CombinedOutput(); err != nil {
			t.Errorf("labctl reset: %v\n%s", err, out)
		}
	})
	return n
}

func iniLabctl(t *testing.T, args ...string) {
	t.Helper()
	if out, err := exec.Command("labctl", args...).CombinedOutput(); err != nil {
		t.Fatalf("labctl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// iniLabNew is init as "osk-dns-watcher init --root-server <root> --extra-range
// 10.53.N.0/24" runs it, with the real observer, in a fresh folder.
func iniLabNew(t *testing.T, n, root string, answers ...string) *iniSetup {
	t.Helper()
	s := iniNew(t, answers...)
	s.init.RootServers = []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr(root), 0)}
	s.init.ExtraRanges = []netip.Prefix{netip.MustParsePrefix(n + "0/24")}
	o, err := observe.New(observe.Config{RootServers: s.init.RootServers, ExtraRanges: s.init.ExtraRanges})
	if err != nil {
		t.Fatal(err)
	}
	s.init.Observer = o
	return s
}

// iniLabLines are the lines of corp.test. in the base state of the lab. Its
// two nameservers lie inside it, so init writes their addresses too: an A
// address each and no IPv6 address.
func iniLabLines(n string) []string {
	aaaa := netip.MustParseAddr("fd53:0:0:" + os.Getenv("LAB_ID") + "::80").String()
	return []string{
		"domain corp.test.",
		"corp.test. A " + n + "80",
		"corp.test. NS ns1.corp.test. | ns2.corp.test.",
		"corp.test. MX 10 mail.corp.test.",
		`corp.test. TXT "v=spf1 mx -all"`,
		"corp.test. AAAA " + aaaa,
		"corp.test. DS none",
		`corp.test. CAA 0 issue "ca.test"`,
		"*.corp.test. A none",
		"_acme-challenge.corp.test. TXT none",
		`_dmarc.corp.test. TXT "v=DMARC1; p=reject"`,
		"_mta-sts.corp.test. TXT none",
		"ns1.corp.test. A " + n + "11",
		"ns1.corp.test. AAAA none",
		"ns2.corp.test. A " + n + "12",
		"ns2.corp.test. AAAA none",
		"www.corp.test. A " + n + "81",
		"_acme-challenge.www.corp.test. TXT none",
	}
}

// iniLabURL is a URL of the lab's receiver with a mark of this run.
func iniLabURL() (url, mark string) {
	mark = "m" + strconv.FormatInt(time.Now().UnixNano(), 36)
	return "https://hooks.lab.test/slack/T0/B0/" + mark, mark
}

func TestInitAsksShowsThenWrites(t *testing.T) {
	n := iniLab(t)
	url, mark := iniLabURL()
	d := "corp.test."
	block := iniBlock(d, iniLabLines(n))

	s := iniLabNew(t, n, n+"2", "corp.test", url, "yes")
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("corp.test", block)+"yes\n"+s.wrote(d))
	moments := s.in.seen()
	for i, m := range moments {
		if len(m.changed) > 0 {
			t.Errorf("while init waited for answer %d, these changed: %q", i+1, m.changed)
		}
	}
	files := s.written(d)
	if info, err := os.Stat(s.folder); err != nil || info.Mode().Perm() != 0o700 {
		t.Errorf("the folder that init made: %v; want mode 0700", err)
	}
	iniSame(t, "config.json", files["config.json"], s.configText(d))
	iniSame(t, "corp.test.expect", files["corp.test.expect"], iniStamp+strings.Join(iniLabLines(n), "\n")+"\n")
	c, problems := config.Read(s.config)
	if len(problems) != 0 {
		t.Fatalf("config.Read: %v", problems)
	}
	if v, problems := c.Secrets(func(string) (string, bool) { return "", false }); len(problems) != 0 || v.SlackURL != url {
		t.Errorf("Secrets: %v; want the URL and no problem", problems)
	}
	if f, err := expect.Parse([]byte(files["corp.test.expect"])); err != nil {
		t.Errorf("corp.test.expect does not parse: %v", err)
	} else {
		iniSame(t, "the file printed back", f.String(), strings.TrimPrefix(files["corp.test.expect"], iniStamp))
	}
	if _, err := os.Lstat(filepath.Join(s.folder, "state")); err == nil {
		t.Errorf("init made the state folder; it opens no store")
	}
	if got, want := s.holding(mark), []string{filepath.Join(s.folder, "slack-url")}; strings.Contains(out, mark) || !slices.Equal(got, want) {
		t.Errorf("the URL is in the output or in %q; want it only in %q", got, want)
	}

	t.Run("the answer no", func(t *testing.T) {
		s := iniLabNew(t, n, n+"2", "corp.test", url, "no")
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		iniSame(t, "the dialogue", out, s.shown("corp.test", block)+"no\n"+iniNothing)
		s.nothingWritten()
	})
	t.Run("input that ends after the URL", func(t *testing.T) {
		s := iniLabNew(t, n, n+"2", "corp.test", url)
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		iniSame(t, "the dialogue", out, s.shown("corp.test", block)+"\n"+iniNothing)
		s.nothingWritten()
	})
	t.Run("a domain that does not exist", func(t *testing.T) {
		s := iniLabNew(t, n, n+"2", "gone.test", url, "yes")
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		iniSame(t, "the dialogue", out, s.refused("gone.test", iniDenied("gone.test.")))
		s.nothingWritten()
	})
	// A root server that does not answer at all is not taken for a proxy:
	// the snapshot then finds that nothing answers.
	t.Run("a root server that does not answer", func(t *testing.T) {
		s := iniLabNew(t, n, n+"99", "corp.test", url, "yes")
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		iniSame(t, "the dialogue", out, s.refused("corp.test", iniNoAnswer(d, "timeout")))
		s.nothingWritten()
	})
	t.Run("answers asked again", func(t *testing.T) {
		s := iniLabNew(t, n, n+"2", "a..b corp.test", "corp.test", "http://x", url, "no")
		code, out := s.run()
		if code != 1 {
			t.Errorf("exit code %d; want 1", code)
		}
		want := iniHello + iniDomainsQ + "a..b corp.test\n" + iniNameProblem(t, "a..b") + iniDomainsQ + "corp.test\n" +
			iniURLQ + "[hidden]\n" + iniBadURL + strings.TrimPrefix(s.shown("corp.test", block), iniHello+iniDomainsQ+"corp.test\n") +
			"no\n" + iniNothing
		iniSame(t, "the dialogue", out, want)
		s.nothingWritten()
	})
	t.Run("a second run", func(t *testing.T) {
		before := iniTree(s.folder)
		again := iniLabNew(t, n, n+"2", "corp.test", url, "yes")
		again.init.Config = s.config
		code, out := again.run()
		if want := "osk-dns-watcher is set up already: " + s.config + " exists. Nothing to ask.\n"; code != 0 || out != want {
			t.Errorf("exit code %d, output %q; want 0 and %q", code, out, want)
		}
		if changed := iniChanged(before, iniTree(s.folder)); len(changed) > 0 {
			t.Errorf("the second run changed %q", changed)
		}
	})
}

// A check right after init, as "osk-dns-watcher check --expect" makes it for each file
// of the config, finds nothing and gets an answer from every server.
func TestInitSetupChecksWithoutFindings(t *testing.T) {
	n := iniLab(t)
	url, _ := iniLabURL()
	s := iniLabNew(t, n, n+"2", "corp.test", url, "yes")
	if code, out := s.run(); code != 0 {
		t.Fatalf("exit code %d; want 0; output:\n%s", code, out)
	}
	c, problems := config.Read(s.config)
	if len(problems) != 0 {
		t.Fatalf("config.Read: %v", problems)
	}
	o, err := observe.New(observe.Config{RootServers: c.RootServers, ExtraRanges: c.ExtraRanges})
	if err != nil {
		t.Fatal(err)
	}
	for _, dom := range c.Domains {
		f, problems := dom.Read()
		if len(problems) != 0 {
			t.Fatalf("%s: %v", dom.Expect, problems)
		}
		keys := []obs.Key{obs.DelegationKey(f.Domain), obs.DSKey(f.Domain)}
		for _, e := range f.Expectations {
			if e.Type != dnswire.TypeDS || !e.Name.Equal(f.Domain) {
				keys = append(keys, obs.RecordsKey(f.Domain, e.Name, e.Type))
			}
		}
		// The delegation, DS, and the 12 sets of the apex and under it, then
		// the A and AAAA sets of the two nameservers.
		if len(keys) != 18 {
			t.Errorf("%s gives %d checks; want 18", dom.Expect, len(keys))
		}
		for _, k := range keys {
			ob, err := o.Run(t.Context(), observe.Check{Key: k, Interval: time.Minute})
			if err != nil {
				t.Fatalf("check %s: %v", k, err)
			}
			if found := decide.Findings(f, ob); len(found) != 0 {
				t.Errorf("check %s finds %s: %s", k, found[0].Rule, found[0].Value)
			}
			for _, a := range ob.Answers {
				if r, failed := iniFailure(a); failed {
					t.Errorf("check %s: %v gave no answer: %s", k, a.Server.Addr, r)
				}
			}
		}
	}
}

func iniFailure(a obs.Answer) (obs.Reason, bool) {
	var reason obs.Reason
	failed := obs.Match(a.Result,
		func(obs.Records) bool { return false },
		func(obs.NoData) bool { return false },
		func(obs.NoName) bool { return false },
		func(f obs.Failure) bool { reason = f.Reason; return true })
	return reason, failed
}

// One real nameserver gives another address for www.corp.test. during the
// setup: init shows the set as not watched and does not write it.
func TestInitShowsAServerThatDisagreesInTheLab(t *testing.T) {
	n := iniLab(t)
	iniLabctl(t, "set", "ns2", "www.corp.test.", "300", "A", n+"99")
	url, _ := iniLabURL()
	d := "corp.test."
	lines := iniLabLines(n)
	lines = slices.DeleteFunc(lines, func(l string) bool { return strings.HasPrefix(l, "www.corp.test. ") })
	skip := "www.corp.test. A: servers disagree: " + n + "11:53 ns1.corp.test. gives " + n + "81; " + n + "12:53 ns2.corp.test. gives " + n + "99"
	s := iniLabNew(t, n, n+"2", "corp.test", url, "yes")
	code, out := s.run()
	if code != 0 {
		t.Errorf("exit code %d; want 0", code)
	}
	iniSame(t, "the dialogue", out, s.shown("corp.test", iniBlock(d, lines, skip))+"yes\n"+s.wrote(d))
	iniSame(t, "corp.test.expect", s.written(d)["corp.test.expect"], iniStamp+strings.Join(lines, "\n")+"\n")
}
