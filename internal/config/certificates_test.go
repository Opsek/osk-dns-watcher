package config

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/schedule"
	"github.com/Opsek/dns-monitoring/internal/sources/certlog"
)

const (
	crtWantURL = "want an https URL with a host and no query"
	crtWantKey = "the key holds an octet that is not printable ASCII, or a space"
	crtEnvKey  = `{"env": "CERT_KEY"}`
	crtDefHost = "api.certspotter.com:443"
)

// crtWith is the smallest valid config with a certificates object, on line 5.
func crtWith(members string) string {
	return cfgWith(`"certificates": {` + members + `}`)
}

// crtVars are the variables of cfgVars and a good key.
func crtVars(key string) map[string]string {
	vars := cfgVars()
	vars["CERT_KEY"] = key
	return vars
}

func crtDefaultIntervals(every time.Duration) schedule.Intervals {
	iv := schedule.Defaults()
	iv.Certificates = every
	return iv
}

func TestCertificatesAbsentMeansTheSourceIsOff(t *testing.T) {
	c := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack))
	if c.Certificates != nil {
		t.Errorf("Certificates = %+v; want nil when the object is absent", *c.Certificates)
	}
	if c.Intervals.Certificates != 0 || c.Intervals != schedule.Defaults() {
		t.Errorf("Intervals = %+v; want the defaults with Certificates 0", c.Intervals)
	}
	for _, w := range c.Warnings() {
		if strings.Contains(w, "certificates") {
			t.Errorf("Warnings() holds %q with the object absent", w)
		}
	}
	v, problems := c.Secrets(cfgEnv(cfgVars()))
	if len(problems) > 0 || v.CertificatesURL != "" || v.CertificatesKey != "" {
		t.Errorf("Secrets gave URL %q, key %q, problems %v; want empty values", v.CertificatesURL, v.CertificatesKey, problems)
	}
	if want := []string{"hooks.slack.example:443"}; !slices.Equal(v.Hosts(), want) {
		t.Errorf("Hosts() = %q; want %q", v.Hosts(), want)
	}
}

func TestCertificatesEmptyObjectGivesTheDefaults(t *testing.T) {
	c := cfgOK(t, crtWith(``))
	want := Certificates{URL: certlog.DefaultURL, Key: nil, Interval: 10 * time.Minute}
	if c.Certificates == nil || *c.Certificates != want {
		t.Fatalf("Certificates = %+v; want %+v", c.Certificates, want)
	}
	if want := crtDefaultIntervals(10 * time.Minute); c.Intervals != want {
		t.Errorf("Intervals = %+v; want %+v", c.Intervals, want)
	}
	if certlog.DefaultURL != "https://api.certspotter.com/v1/issuances" {
		t.Errorf("DefaultURL = %q", certlog.DefaultURL)
	}
	v, problems := c.Secrets(cfgEnv(cfgVars()))
	if len(problems) > 0 || v.CertificatesURL != certlog.DefaultURL || v.CertificatesKey != "" {
		t.Errorf("Secrets gave URL %q, key %q, problems %v", v.CertificatesURL, v.CertificatesKey, problems)
	}
}

func TestCertificatesEachKeyParsesToItsValue(t *testing.T) {
	c := cfgOK(t, crtWith(`"url": "https://ct.example:8443/v1/issuances", "key": `+crtEnvKey+`, "interval": "90s"`))
	want := Certificates{URL: "https://ct.example:8443/v1/issuances", Key: &Secret{Env: "CERT_KEY", Path: "certificates.key", Line: 5},
		Interval: 90 * time.Second}
	got := c.Certificates
	if got == nil || got.URL != want.URL || got.Interval != want.Interval || got.Key == nil || *got.Key != *want.Key {
		t.Fatalf("Certificates = %+v; want %+v", got, want)
	}
	if want := crtDefaultIntervals(90 * time.Second); c.Intervals != want {
		t.Errorf("Intervals = %+v; want %+v", c.Intervals, want)
	}

	// Each key alone leaves the others at their defaults.
	c = cfgOK(t, crtWith(`"url": "https://ct.example/x"`))
	if c.Certificates.URL != "https://ct.example/x" || c.Certificates.Interval != 10*time.Minute || c.Certificates.Key != nil {
		t.Errorf("url alone: %+v", *c.Certificates)
	}
	c = cfgOK(t, crtWith(`"interval": "1h"`))
	if c.Certificates.URL != certlog.DefaultURL || c.Certificates.Interval != time.Hour || c.Certificates.Key != nil || c.Intervals.Certificates != time.Hour {
		t.Errorf("interval alone: %+v, intervals %+v", *c.Certificates, c.Intervals)
	}
	c = cfgOK(t, crtWith(`"key": `+crtEnvKey))
	if c.Certificates.URL != certlog.DefaultURL || c.Certificates.Interval != 10*time.Minute || c.Certificates.Key == nil {
		t.Errorf("key alone: %+v", *c.Certificates)
	}

	// The key is a file: its path is absolute, and relative to the config folder.
	c = cfgOK(t, crtWith(`"key": {"file": "cert.key"}`))
	if k := c.Certificates.Key; k == nil || *k != (Secret{File: cfgDir + "/cert.key", Path: "certificates.key", Line: 5}) {
		t.Errorf("file key: %+v", k)
	}
}

func TestCertificatesIntervalGoesFromTheFloorToTheCeiling(t *testing.T) {
	for _, v := range []struct {
		text string
		want time.Duration
	}{{"5s", schedule.Floor}, {"5000ms", schedule.Floor}, {"10m", 10 * time.Minute}, {"24h", schedule.Ceiling}} {
		c := cfgOK(t, crtWith(`"interval": "`+v.text+`"`))
		if c.Certificates.Interval != v.want || c.Intervals.Certificates != v.want {
			t.Errorf("interval %q gave %v and %v; want %v", v.text, c.Certificates.Interval, c.Intervals.Certificates, v.want)
		}
	}
	for _, v := range []struct{ value, text string }{
		{`"4999ms"`, cfgBelow(4999 * time.Millisecond)},
		{`"4s"`, cfgBelow(4 * time.Second)},
		{`"0s"`, cfgBelow(0)},
		{`"-5s"`, cfgBelow(-5 * time.Second)},
		{`"24h0m0.000000001s"`, cfgAbove(schedule.Ceiling+1, schedule.Ceiling)},
		{`"25h"`, cfgAbove(25*time.Hour, schedule.Ceiling)},
		{`"1d"`, `"1d" is not a duration`},
		{`""`, `"" is not a duration`},
		{`600`, "want a string"},
		{`null`, "want a string"},
	} {
		cfgRefused(t, crtWith(`"interval": `+v.value), cfgAt(5, "certificates.interval", v.text))
	}
}

func TestCertificatesURLIsHTTPSWithAHostAndNoQueryFragmentOrUserName(t *testing.T) {
	for _, u := range []string{
		"https://ct.example/v1/issuances", "https://ct.example", "https://ct.example:8443/x", "https://[fd00::1]/x",
		"https://CT.example/a/b/c",
	} {
		if c := cfgOK(t, crtWith(`"url": "`+u+`"`)); c.Certificates.URL != u {
			t.Errorf("URL %q gave %q", u, c.Certificates.URL)
		}
	}
	for _, u := range []string{
		"https://ct.example/x?a=b", "https://ct.example/x?after=1", "https://ct.example/x#frag", "https://ct.example/x?a=b#frag",
		"https://user@ct.example/x", "https://user:pw@ct.example/x", "http://ct.example/x", "https:///x",
		"ct.example/x", "ftp://ct.example/x", "", "https://ct.ex%zzample/x",
	} {
		cfgRefused(t, crtWith(`"url": "`+u+`"`), cfgAt(5, "certificates.url", crtWantURL))
	}
	cfgRefused(t, crtWith(`"url": 5`), cfgAt(5, "certificates.url", "want a string"))
	// The problem text does not repeat the URL.
	_, problems := Parse(cfgFile, []byte(crtWith(`"url": "https://ct.example/pastedtoken?k=1"`)))
	for _, p := range problems {
		if strings.Contains(p.Text, "pastedtoken") {
			t.Errorf("problem %q repeats the URL", p.Text)
		}
	}
}

func TestCertificatesObjectIsStrict(t *testing.T) {
	cfgRefused(t, crtWith(`"token": "x"`), cfgUnknown(5, "certificates", "token"))
	cfgRefused(t, crtWith(`"URL": "https://ct.example/x"`), cfgUnknown(5, "certificates", "URL"))
	cfgRefused(t, crtWith(`"interval": "10m", "interval": "20m"`), cfgTwice(5, "certificates", "interval"))
	cfgRefused(t, cfgWith(`"certificates": ["https://ct.example/x"]`), cfgAt(5, "certificates", "want an object"))
	cfgRefused(t, cfgWith(`"certificates": "on"`), cfgAt(5, "certificates", "want an object"))
	cfgRefused(t, cfgWith(`"certificates": null`), cfgAt(5, "certificates", "want an object"))
	// The interval belongs to the object, not to the intervals of the tiers.
	cfgRefused(t, cfgWith(`"intervals": {"certificates": "10m"}`), cfgUnknown(5, "intervals", "certificates"))
	cfgRefused(t, crtWith(`"key": "abc"`), cfgAt(5, "certificates.key", cfgWantSecret))
	cfgRefused(t, crtWith(`"key": {}`), cfgAt(5, "certificates.key", cfgWantSecret))
	cfgRefused(t, crtWith(`"key": {"env": "lower"}`), cfgAt(5, "certificates.key.env", cfgWantEnvName))
	// Every problem is reported, each at its own path.
	cfgRefused(t, crtWith(`"url": "http://ct.example/", "interval": "1s", "extra": 1`),
		cfgAt(5, "certificates.url", crtWantURL), cfgAt(5, "certificates.interval", cfgBelow(time.Second)),
		cfgUnknown(5, "certificates", "extra"))
}

func TestCertificatesKeyComesFromTheEnvironmentAndFromAFile(t *testing.T) {
	text := crtWith(`"key": ` + crtEnvKey)
	key := "Abc123-_.~!"
	v, problems := cfgSecretProblems(t, text, crtVars(key))
	if len(problems) > 0 || v.CertificatesKey != key {
		t.Fatalf("env key: CertificatesKey %q, problems %v; want %q", v.CertificatesKey, problems, key)
	}
	// The real environment is not read.
	t.Setenv("CERT_KEY", "from-the-real-environment")
	if v, _ := cfgSecretProblems(t, text, crtVars(key)); v.CertificatesKey != key {
		t.Errorf("CertificatesKey = %q; want the value of the lookup", v.CertificatesKey)
	}

	file := filepath.Join(t.TempDir(), "cert.key")
	for _, data := range []string{key, key + "\n", key + "\r\n"} {
		cfgWrite(t, file, data)
		v, problems := cfgSecretProblems(t, crtWith(`"key": {"file": `+cfgQuote(t, file)+`}`), cfgVars())
		if len(problems) > 0 || v.CertificatesKey != key {
			t.Errorf("file %q: CertificatesKey %q, problems %v; want %q", data, v.CertificatesKey, problems, key)
		}
	}

	// A missing variable and an empty one are named at the key.
	cfgSecretRefused(t, text, cfgVars(), cfgAt(5, "certificates.key", "the environment variable is not set"))
	cfgSecretRefused(t, text, crtVars(""), cfgAt(5, "certificates.key", "the environment variable is not set"))
	cfgSecretRefused(t, crtWith(`"key": {"file": `+cfgQuote(t, file+".none")+`}`), cfgVars(),
		cfgAt(5, "certificates.key", "the secret file cannot be read: it does not exist"))
}

func TestCertificatesKeyIsOneTo256PrintableOctets(t *testing.T) {
	text := crtWith(`"key": ` + crtEnvKey)
	for name, key := range map[string]string{
		"one octet":     "k",
		"0x21":          "!",
		"0x7E":          "~",
		"256 octets":    strings.Repeat("k", 256),
		"all printable": "!\"#$%&'()*+,-./0123456789:;<=>?@ABCDEFGHIJKLMNOPQRSTUVWXYZ[\\]^_`abcdefghijklmnopqrstuvwxyz{|}~",
	} {
		if v, problems := cfgSecretProblems(t, text, crtVars(key)); len(problems) > 0 || v.CertificatesKey != key {
			t.Errorf("%s: CertificatesKey %q, problems %v", name, v.CertificatesKey, problems)
		}
	}
	for name, key := range map[string]string{
		"a space inside":       "ab cd",
		"a space at the start": " abcd",
		"a space at the end":   "abcd ",
		"a tab":                "ab\tcd",
		"a line feed inside":   "ab\ncd",
		"a NUL":                "ab\x00cd",
		"0x1F":                 "ab\x1fcd",
		"0x7F":                 "ab\x7fcd",
		"0x80":                 "ab\x80cd",
		"0xFF":                 "ab\xffcd",
		"a letter with accent": "café",
		"257 octets":           strings.Repeat("k", 257),
		"4096 octets":          strings.Repeat("k", 4096),
	} {
		cfgSecretRefused(t, text, crtVars(key), cfgAt(5, "certificates.key", crtWantKey))
		if _, problems := cfgSecretProblems(t, text, crtVars(key)); len(problems) == 1 && strings.Contains(problems[0].Text, "kkkk") {
			t.Errorf("%s: the problem repeats the key", name)
		}
	}
	// A file loses one line end; a space before it stays and is refused.
	file := filepath.Join(t.TempDir(), "cert.key")
	cfgWrite(t, file, "abcd \n")
	cfgSecretRefused(t, crtWith(`"key": {"file": `+cfgQuote(t, file)+`}`), cfgVars(), cfgAt(5, "certificates.key", crtWantKey))
	cfgWrite(t, file, strings.Repeat("k", 257)+"\n")
	cfgSecretRefused(t, crtWith(`"key": {"file": `+cfgQuote(t, file)+`}`), cfgVars(), cfgAt(5, "certificates.key", crtWantKey))
}

func TestCertificatesKeyProblemDoesNotHideAnotherSecretProblem(t *testing.T) {
	vars := crtVars("bad key")
	vars["OSK_SLACK_URL"] = "http://hooks.slack.example/x"
	cfgSecretRefused(t, crtWith(`"key": `+crtEnvKey), vars,
		cfgAt(4, "slack.url", cfgWantURL), cfgAt(5, "certificates.key", crtWantKey))
}

func TestCertificatesValuesGiveTheURLAndTheHostIsListed(t *testing.T) {
	for _, c := range []struct {
		members, url, host string
	}{
		{``, certlog.DefaultURL, crtDefHost},
		{`"url": "https://ct.example/v1/issuances"`, "https://ct.example/v1/issuances", "ct.example:443"},
		{`"url": "https://CT.Example:8443/x"`, "https://CT.Example:8443/x", "ct.example:8443"},
	} {
		v, problems := cfgSecretProblems(t, crtWith(c.members), cfgVars())
		if len(problems) > 0 || v.CertificatesURL != c.url {
			t.Errorf("%s: CertificatesURL %q, problems %v; want %q", c.members, v.CertificatesURL, problems, c.url)
		}
		want := []string{"hooks.slack.example:443", c.host}
		if got := slices.Sorted(slices.Values(v.Hosts())); !slices.Equal(got, slices.Sorted(slices.Values(want))) {
			t.Errorf("%s: Hosts() = %q; want %q", c.members, v.Hosts(), want)
		}
	}
	// A host that another channel has is listed once.
	vars := cfgVars()
	vars["OSK_SLACK_URL"] = "https://ct.example/slack"
	v, problems := cfgSecretProblems(t, crtWith(`"url": "https://ct.example/v1/issuances"`), vars)
	if len(problems) > 0 || !slices.Equal(v.Hosts(), []string{"ct.example:443"}) {
		t.Errorf("Hosts() = %q, problems %v; want ct.example:443 once", v.Hosts(), problems)
	}
	// The key never leaves Values in text.
	v, _ = cfgSecretProblems(t, crtWith(`"key": `+crtEnvKey), crtVars("secretkeymark"))
	if s := fmt.Sprintf("%v %+v %#v %s", v, v, v, v); strings.Contains(s, "secretkeymark") {
		t.Errorf("Values prints the key: %s", s)
	}
}

// The host is written either as osk keeps it for the HTTPS client or without
// the default port 443; the text of the warning holds no interval.
func crtWarnings(hosts ...string) []string {
	var texts []string
	for _, h := range hosts {
		texts = append(texts, "certificates is set: osk sends the name of each watched domain to "+h+
			", which learns which domains you watch.")
	}
	return texts
}

func TestCertificatesWarningNamesTheHostAndNoInterval(t *testing.T) {
	for _, c := range []struct {
		text  string
		hosts []string
	}{
		{crtWith(``), []string{"api.certspotter.com", crtDefHost}},
		{crtWith(`"interval": "90s"`), []string{"api.certspotter.com", crtDefHost}},
		{crtWith(`"interval": "24h", "key": ` + crtEnvKey), []string{"api.certspotter.com", crtDefHost}},
		{crtWith(`"url": "https://ct.example:8443/x", "interval": "5s"`), []string{"ct.example:8443"}},
		{crtWith(`"url": "https://ct.example/x"`), []string{"ct.example", "ct.example:443"}},
	} {
		got := cfgOK(t, c.text).Warnings()
		if len(got) != 1 || !slices.Contains(crtWarnings(c.hosts...), got[0]) {
			t.Errorf("Warnings() of %s = %q; want one of %q", c.text, got, crtWarnings(c.hosts...))
		}
	}
	// Two different intervals give the same text.
	a := cfgOK(t, crtWith(`"interval": "5s"`)).Warnings()
	b := cfgOK(t, crtWith(`"interval": "24h"`)).Warnings()
	if len(a) != 1 || !slices.Equal(a, b) || strings.Contains(a[0], "5s") || strings.Contains(a[0], "24h") {
		t.Errorf("Warnings() for 5s %q and for 24h %q; want the same text with no interval", a, b)
	}
	// The warning of the network keys stays when both are set.
	got := cfgOK(t, cfgDoc(cfgState, cfgDomains, cfgSlack, `"network": {`+cfgRoots+`}`, `"certificates": {}`)).Warnings()
	if len(got) != 2 || !slices.Contains(got, cfgRootWarning) {
		t.Errorf("Warnings() = %q; want the root warning and the certificates warning", got)
	}
}
