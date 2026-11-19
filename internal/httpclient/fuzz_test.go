package httpclient

import (
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"
)

func FuzzHostOf(f *testing.F) {
	for _, s := range []string{
		"https://example.com", "https://Example.COM:8443/hook?x=1#f", "HTTPS://EXAMPLE.com/", "https://[::1]/", "https://[2001:DB8::1]:444/",
		"https://[fe80::1%25eth0]/", "https://127.0.0.1:1", "https://example.com:", "https://example.com:99999",
		"http://example.com", "ftp://example.com", "https://user@example.com", "https://user:pass@example.com/", "https://@example.com",
		"https://éxample.com", "https://EXAMPLE.K.com", "https://xn--e1afmkfd.example", "https:example.com", "https:///path",
		"https://]", "https://a]", "https://[a", "https://a[b", "https://[", "https://", "https:", "", "h", "\x00", "https://exa\x00mple.com", "https://exa mple.com", "https://a\\b.com", "https://a.com\\@b.com",
		"https://a.com#@b.com", "https://a.com?@b.com", "//example.com", "https://" + strings.Repeat("a", 5000), "https://" + strings.Repeat(".", 300),
		"https://a.com:" + strings.Repeat("9", 200), "https://\xff\xfe", strings.Repeat("https://", 100),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		got, err := HostOf(raw)
		if err != nil {
			if !errors.Is(err, ErrURL) || got != "" {
				t.Fatalf("HostOf(%q) = %q, %v; want ErrURL and nothing", raw, got, err)
			}
			return
		}
		host, port, serr := net.SplitHostPort(got)
		if serr != nil || host == "" || port == "" || strings.Trim(port, "0123456789") != "" {
			t.Fatalf("HostOf(%q) = %q, not host:port with a number", raw, got)
		}
		for i := 0; i < len(host); i++ {
			if c := host[i]; c >= 0x80 || 'A' <= c && c <= 'Z' || c <= ' ' || c == 0x7f {
				t.Fatalf("HostOf(%q) = %q, host holds %q", raw, got, c)
			}
		}
		if !strings.EqualFold(raw[:strings.Index(raw, ":")], "https") {
			t.Fatalf("HostOf(%q) = %q, but the scheme is not https", raw, got)
		}
		if again, err := HostOf("https://" + got); err != nil || again != got {
			t.Fatalf("HostOf(%q) = %q, but HostOf of that gives %q, %v", raw, got, again, err)
		}
		for _, other := range []string{"http://" + got, "https://user@" + got, "https://user:pw@" + got, "ftp://" + got, "https://é" + got} {
			if h, err := HostOf(other); err == nil {
				t.Fatalf("HostOf(%q) = %q; want a refusal (derived from %q)", other, h, raw)
			}
		}
	})
}

func FuzzRetryAfter(f *testing.F) {
	for _, s := range []string{
		"0", "1", "120", "86400", "86401", "999999", "1000000", "000001", "0000000", "-1", "+1", "1.5", "1e3", " 1", "1 ", "",
		"Wed, 21 Oct 2026 07:28:00 GMT", "\x00", "1\x00", "\xff", "١٢", "9223372036854775807", strings.Repeat("9", 100000),
		strings.Repeat("0", 6), strings.Repeat("\x00", 7),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		d := retryAfter(v)
		if d < 0 || d > 24*time.Hour || d%time.Second != 0 {
			t.Fatalf("retryAfter(%q) = %v; want 0 to 24h in whole seconds", v, d)
		}
		n, err := strconv.Atoi(v)
		digits := v != "" && len(v) <= 6 && strings.Trim(v, "0123456789") == ""
		switch {
		case digits && err == nil && n <= 86400:
			if d != time.Duration(n)*time.Second {
				t.Fatalf("retryAfter(%q) = %v; want %ds", v, d, n)
			}
		case d != 0:
			t.Fatalf("retryAfter(%q) = %v; want 0 for a value that is not seconds up to a day", v, d)
		}
	})
}

func FuzzDate(f *testing.F) {
	for _, s := range []string{
		"Mon, 16 Nov 2026 10:04:05 GMT", "Monday, 16-Nov-26 10:04:05 GMT", "Mon Nov 16 10:04:05 2026", "Mon Nov  6 10:04:05 2026",
		"Mon, 32 Nov 2026 10:04:05 GMT", "Mon, 16 Nov 2026 10:04:05", "Mon, 16 Nov 2026 24:00:00 GMT", "Mon, 16 Nov 2026 10:04:60 GMT",
		"Thu, 01 Jan 0001 00:00:00 GMT", "Fri, 31 Dec 9999 23:59:59 GMT", "Mon, 16 Nov 99999 10:04:05 GMT", "Sun, 06-Nov-94 08:49:37 GMT",
		"2026-11-16T10:04:05Z", "1794823445", "", " ", "\x00", "\xff\xfe", "Mon, \x00 Nov 2026 10:04:05 GMT", "GMT", strings.Repeat("GMT", 30000),
		strings.Repeat("Mon, ", 5000),
	} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, v string) {
		got := date(v)
		if got.IsZero() {
			return
		}
		if again, err := http.ParseTime(got.UTC().Format(http.TimeFormat)); err != nil || !again.Equal(got) {
			t.Fatalf("date(%q) = %v, which does not read back as an HTTP date: %v, %v", v, got, again, err)
		}
	})
}
