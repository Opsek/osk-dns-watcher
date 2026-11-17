package certlog_test

import (
	"regexp"
	"strings"
	"testing"

	"github.com/Opsek/dns-monitoring/internal/sources/certlog"
)

func TestName(t *testing.T) {
	l63 := strings.Repeat("a", 63)
	long253 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 61)
	long254 := l63 + "." + l63 + "." + l63 + "." + strings.Repeat("b", 62)
	cases := []struct {
		in   string
		want string // "" : not read
	}{
		{"example.com", "example.com."},
		{"EXAMPLE.Com", "example.com."},
		{"example.com.", "example.com."},
		{"Example.COM.", "example.com."},
		{"*.example.com", "*.example.com."},
		{"*.EXAMPLE.com.", "*.example.com."},
		{"*", "*."},
		{"a", "a."},
		{"A", "a."},
		{"Z.example.com", "z.example.com."},
		{"AZ.Example.Com", "az.example.com."},
		{"zZ.ZZ", "zz.zz."},
		{"a.b", "a.b."},
		{"xn--bcher-kva.example", "xn--bcher-kva.example."},
		{"-a.test", "-a.test."},
		{"a-.test", "a-.test."},
		{"a--b.test", "a--b.test."},
		{"1.2.3.4", "1.2.3.4."},
		{"0.test", "0.test."},
		{l63 + ".test", l63 + ".test."},
		{long253, long253 + "."},
		{long253 + ".", long253 + "."},
		{"", ""},
		{".", ""},
		{"..", ""},
		{".a.test", ""},
		{"a.test..", ""},
		{"a..test", ""},
		{l63 + "a.test", ""},
		{long254, ""},
		{long254 + ".", ""},
		{"a.*.test", ""},
		{"*.*.test", ""},
		{"**.test", ""},
		{"*a.test", ""},
		{"a*.test", ""},
		{"x*", ""},
		{"a_b.test", ""},
		{"_dmarc.a.test", ""},
		{"ü.test", ""},
		{"bücher.example", ""},
		{"ａ.test", ""},
		{"K.test", ""},
		{"a b.test", ""},
		{" a.test", ""},
		{"a.test ", ""},
		{"a.test\n", ""},
		{"a\x00b.test", ""},
		{"a\\.b.test", ""},
		{"a\\097.test", ""},
		{"a:b.test", ""},
		{"a/b.test", ""},
		{"a@b.test", ""},
		{"a$b.test", ""},
		{"a;b.test", ""},
		{"a\"b.test", ""},
		{"a\xffb.test", ""},
	}
	for _, tc := range cases {
		got, ok := certlog.Name(tc.in)
		switch {
		case tc.want == "" && ok:
			t.Errorf("Name(%q) = %q; want it not read", tc.in, got)
		case tc.want != "" && (!ok || got.String() != tc.want):
			t.Errorf("Name(%q) = %q, %v; want %q", tc.in, got, ok, tc.want)
		}
	}
}

var crtNameRE = regexp.MustCompile(`^(\*|[a-z0-9-]{1,63})(\.[a-z0-9-]{1,63})*$`)

func crtASCIILower(s string) string {
	b := []byte(s)
	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + 32
		}
	}
	return string(b)
}

// crtNameRead is the rule of Name, written again in the simplest way.
func crtNameRead(s string) bool {
	s = strings.TrimSuffix(crtASCIILower(s), ".")
	if len(s) < 1 || len(s) > 253 || !crtNameRE.MatchString(s) {
		return false
	}
	return true
}

func FuzzName(f *testing.F) {
	for _, s := range []string{"example.com", "EXAMPLE.com.", "*.a.test", "a_b", "ü", "", ".", "a..b", "*", "*.*", strings.Repeat("a", 64), "a-.b-"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		n, ok := certlog.Name(s)
		if ok != crtNameRead(s) {
			t.Fatalf("Name(%q) read: %v, want %v", s, ok, !ok)
		}
		if !ok {
			return
		}
		text := n.String()
		if text != crtASCIILower(text) || !strings.HasSuffix(text, ".") {
			t.Fatalf("Name(%q) = %q", s, text)
		}
		if want := crtASCIILower(strings.TrimSuffix(s, ".")) + "."; text != want {
			t.Fatalf("Name(%q) = %q, want %q", s, text, want)
		}
		if back, ok := certlog.Name(text); !ok || !back.Equal(n) {
			t.Fatalf("Name(%q) = %q does not read back", s, text)
		}
	})
}
