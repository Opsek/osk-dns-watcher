package mtasts

import (
	"strings"
	"testing"

	"github.com/Opsek/osk-dns-watcher/internal/dnswire"
	"github.com/Opsek/osk-dns-watcher/internal/httpclient"
)

func FuzzHost(f *testing.F) {
	for _, s := range []string{
		"example.com", "EXAMPLE.com.", "a_b.test", "a-b.test", "x", ".", "", "..", "a..b", `a\.b.test`, `a\/b.test`, `a\:b.test`, `a\#b.test`,
		`a\@b.test`, `a\ b.test`, `a\000b.test`, `\255.test`, "é.test", "xn--e1afmkfd.test", "a*.test", "*.test", "a%2fb.test",
		strings.Repeat("a", 63) + ".test", strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 53),
		strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 54),
		strings.Repeat("a.", 120), strings.Repeat("a.", 127) + "a", "\x00", "\xff", "a\x00b.test", "0",
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		domain, err := dnswire.ParseName(s)
		if err != nil {
			return
		}
		host, ok := Host(domain)
		if !ok {
			if host != "" {
				t.Fatalf("Host(%q) = %q, false; want no host", s, host)
			}
			return
		}
		name, found := strings.CutSuffix(host, ":443")
		if !found || !strings.HasPrefix(name, "mta-sts.") || len(name) > 253 {
			t.Fatalf("Host(%q) = %q; want mta-sts.<name>:443 with a name of at most 253 octets", s, host)
		}
		if strings.Trim(name, "abcdefghijklmnopqrstuvwxyz0123456789-_.") != "" {
			t.Fatalf("Host(%q) = %q holds an octet that is not a-z, 0-9, - _ or .", s, host)
		}
		for _, label := range strings.Split(name, ".") {
			if label == "" || len(label) > 63 {
				t.Fatalf("Host(%q) = %q holds the label %q", s, host, label)
			}
		}
		if got, err := httpclient.HostOf(policyURL(host)); err != nil || got != host {
			t.Fatalf("Host(%q) = %q, but HostOf of its URL gives %q, %v", s, host, got, err)
		}
	})
}
