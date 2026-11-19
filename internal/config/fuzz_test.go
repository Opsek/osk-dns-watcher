package config

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/Opsek/dns-monitoring/internal/schedule"
)

// fzMarker stands for a secret value: no fixed problem text holds it, so
// finding it in a problem means that a pasted value came back.
const fzMarker = "zq7kx9secretvalue"

const fzFull = `{
  "state": "/var/lib/osk",
  "domains": [
    {"name": "corp.test.", "expect": "corp.test.expect", "fast": ["www.corp.test.", "api.corp.test."]},
    {"name": "Other.TEST.", "expect": "/etc/osk/other.expect"}
  ],
  "intervals": {"serial": "15s", "parent": "1m", "fast": "30s", "other": "5m"},
  "slack": {"url": {"env": "OSK_SLACK_URL"}, "min_severity": "high"},
  "webhooks": [{"name": "siem", "url": {"file": "siem.url"}, "key": {"env": "HOOK_KEY"}, "min_severity": "critical"}],
  "heartbeat": {"url": {"env": "BEAT"}, "interval": "1m"},
  "certificates": {"url": "https://ct.example/search", "key": {"env": "CT_KEY"}, "interval": "10m"},
  "history_days": 30,
  "remind": "24h",
  "network": {"root_servers": ["192.0.2.1", "192.0.2.2:5353", "[2001:db8::1]:53"], "extra_ranges": ["10.0.0.0/8", "fd00::/8"]}
}
`

func fzSecretSlots(form int, x string) string {
	q, _ := json.Marshal(x)
	var secret string
	switch form {
	case 0:
		secret = `{"env": ` + string(q) + `}`
	case 1:
		secret = `{"file": ` + string(q) + `}`
	case 2:
		secret = string(q)
	default:
		secret = `{"env": ` + string(q) + `, "file": ` + string(q) + `}`
	}
	return `{"state": "/s", "domains": [{"name": "a.test.", "expect": "/e"}],
	  "slack": {"url": ` + secret + `},
	  "webhooks": [{"name": "h", "url": ` + secret + `, "key": ` + secret + `}],
	  "heartbeat": {"url": ` + secret + `},
	  "certificates": {"url": ` + string(q) + `, "key": ` + secret + `}}`
}

func FuzzParse(f *testing.F) {
	for _, s := range []string{
		fzFull,
		cfgDoc(cfgState, cfgDomains, cfgSlack),
		cfgWith(cfgHooks("a", "b")),
		cfgWith(`"history_days": 3650`),
		cfgWith(`"remind": "0s"`),
		cfgWith(`"intervals": {"serial": "5s", "other": "24h"}`),
		cfgWith(`"network": {"root_servers": ["::1"], "extra_ranges": ["0.0.0.0/0"]}`),
		cfgDoc(cfgState, cfgDomains),
		cfgWith(`"slack": {"url": "https://hooks.example/T0/B0/token"}`),
		cfgWith(`"slack": {"url": {"env": "https://hooks.example/T0/B0/token"}}`),
		"", "{", "}", "{}", "[]", "null", "0", `""`, "\x00", "\xff\xfe", "{\x00}", `{"state":`,
		"{{{{{{{{", "[[[[[[[[", strings.Repeat("[", 5000), strings.Repeat(`{"a":`, 2000),
		`{"state": "/s", "state": "/t"}`, `{"domains": [` + strings.Repeat(`{},`, 200) + `{}]}`,
		`{"state": "\u0000", "domains": [], "slack": {"url": {"env": "A"}}}`,
		"\xef\xbb\xbf" + cfgDoc(cfgState, cfgDomains, cfgSlack),
		strings.Repeat(" ", 4096) + "{}", strings.Repeat("\n", 4096) + "{",
	} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		c, problems := Parse(cfgFile, data)
		again, problemsAgain := Parse(cfgFile, data)
		if !reflect.DeepEqual(c, again) || !reflect.DeepEqual(problems, problemsAgain) {
			t.Fatalf("Parse of %q gives another result the second time", data)
		}
		if c == nil {
			fzCheckProblems(t, data, problems)
		} else {
			if len(problems) != 0 {
				t.Fatalf("Parse of %q gives a config and problems %v", data, problems)
			}
			fzCheckLimits(t, data, c)
		}
		fzCheckNoPastedValue(t, data)
	})
}

func fzCheckProblems(t *testing.T, data []byte, problems []Problem) {
	t.Helper()
	if len(problems) < 1 || len(problems) > maxProblems {
		t.Fatalf("Parse of %q gives no config and %d problems", data, len(problems))
	}
	for _, p := range problems {
		if p.File != cfgFile || p.Line < 0 || p.Text == "" || p.String() == "" {
			t.Fatalf("Parse of %q gives the odd problem %+v", data, p)
		}
	}
}

func fzCheckLimits(t *testing.T, data []byte, c *Config) {
	t.Helper()
	bad := func(format string, args ...any) {
		t.Fatalf("Parse of %q gives a config where "+format, append([]any{data}, args...)...)
	}
	if len(data) > maxFileSize {
		bad("the file is larger than %d octets", maxFileSize)
	}
	if !filepath.IsAbs(c.State) {
		bad("the state %q is not absolute", c.State)
	}
	if n := len(c.Domains); n < 1 || n > maxDomains {
		bad("there are %d domains", n)
	}
	keys := map[string]bool{}
	for _, d := range c.Domains {
		if d.Name.LabelCount() == 0 || keys[d.Name.Key()] || !filepath.IsAbs(d.Expect) || len(d.Fast) > maxFast || d.Line < 1 {
			bad("the domain %+v is not allowed", d)
		}
		keys[d.Name.Key()] = true
	}
	iv := c.Intervals
	bounded := []time.Duration{iv.Serial, iv.Parent, iv.Fast, iv.Other}
	if c.Certificates != nil {
		bounded = append(bounded, c.Certificates.Interval, iv.Certificates)
	}
	for _, d := range bounded {
		if d < schedule.Floor || d > schedule.Ceiling {
			bad("the intervals %+v leave their bounds", iv)
		}
	}
	if c.HistoryDays < 1 || c.HistoryDays > maxHistoryDays {
		bad("history_days is %d", c.HistoryDays)
	}
	if c.Remind != 0 && (c.Remind < minRemind || c.Remind > maxRemind) {
		bad("remind is %v", c.Remind)
	}
	fzCheckChannels(t, data, c, bad)
	if len(c.RootServers) > maxRootServers || len(c.ExtraRanges) > maxRanges {
		bad("there are %d root servers and %d ranges", len(c.RootServers), len(c.ExtraRanges))
	}
	for _, p := range c.ExtraRanges {
		if p != p.Masked() {
			bad("the range %v has bits after its length", p)
		}
	}
	_ = c.Warnings()
}

func fzCheckChannels(t *testing.T, data []byte, c *Config, bad func(string, ...any)) {
	t.Helper()
	if c.Slack == nil && len(c.Webhooks) == 0 {
		bad("there is no channel")
	}
	if len(c.Webhooks) > maxWebhooks {
		bad("there are %d webhooks", len(c.Webhooks))
	}
	names := map[string]bool{}
	for _, h := range c.Webhooks {
		if !validWebhookName(h.Name) || h.Name == "slack" || names[h.Name] {
			bad("the webhook name %q is not allowed", h.Name)
		}
		names[h.Name] = true
	}
	if h := c.Heartbeat; h != nil && (h.Interval < minBeat || h.Interval > maxBeat) {
		bad("the heartbeat interval is %v", h.Interval)
	}
	for _, s := range fzSecrets(c) {
		if (s.Env == "") == (s.File == "") || s.Env != "" && !validEnvName(s.Env) || s.File != "" && !filepath.IsAbs(s.File) {
			bad("the secret %+v is not one env name or one absolute file", s)
		}
	}
}

func fzSecrets(c *Config) []Secret {
	var all []Secret
	if c.Slack != nil {
		all = append(all, c.Slack.URL)
	}
	for _, h := range c.Webhooks {
		all = append(all, h.URL, h.Key)
	}
	if c.Heartbeat != nil {
		all = append(all, c.Heartbeat.URL)
	}
	if c.Certificates != nil && c.Certificates.Key != nil {
		all = append(all, *c.Certificates.Key)
	}
	return all
}

// A value pasted where a secret, or the certificates URL, is read must not
// come back in a problem, whatever else the text holds.
func fzCheckNoPastedValue(t *testing.T, data []byte) {
	t.Helper()
	x := fzMarker + string(data)
	for form := 0; form < 4; form++ {
		doc := fzSecretSlots(form, x)
		_, problems := Parse(cfgFile, []byte(doc))
		for _, p := range problems {
			if strings.Contains(p.String(), fzMarker) {
				t.Fatalf("form %d: the problem %q repeats the pasted value %.60q", form, p.String(), x)
			}
		}
	}
}

// fzVar names the environment of a secret: the lookup knows only these.
type fzVars map[string]string

func (v fzVars) lookup(name string) (string, bool) {
	s, ok := v[name]
	return s, ok
}

func FuzzSecrets(f *testing.F) {
	f.Add("")
	f.Add("a")
	f.Add("/hook/token")
	f.Add("\r")
	f.Add("\n\n")
	f.Add("\x00")
	f.Add("\xff\xfe\xfd")
	f.Add(" with spaces and é")
	f.Add(strings.Repeat("k", 32))
	f.Add(strings.Repeat("k", 4096))
	f.Add(strings.Repeat("k", 5000))
	f.Add(strings.Repeat("/", 300))
	f.Add("@user:pass@")
	f.Fuzz(func(t *testing.T, v string) {
		// A file loses one line end, so a value that ends in one cannot
		// come back from a file as it is.
		v = strings.TrimRight(v, "\r\n")
		dir := t.TempDir()
		urlValue := "https://" + fzMarker + ".example/" + v
		keyValue := fzMarker + v
		write := func(name, data string) string {
			path := filepath.Join(dir, name)
			cfgWrite(t, path, data+"\n")
			return path
		}
		vars := fzVars{"SLACK": urlValue, "HOOK_KEY": keyValue, "BEAT": urlValue, "CT_KEY": keyValue}
		ct := keyValue
		c := &Config{
			Path:  cfgFile,
			Slack: &Slack{URL: Secret{Env: "SLACK", Path: "slack.url", Line: 3}},
			Webhooks: []Webhook{{
				Name: "h",
				URL:  Secret{File: write("hook.url", urlValue), Path: "webhooks[0].url", Line: 4},
				Key:  Secret{Env: "HOOK_KEY", Path: "webhooks[0].key", Line: 4},
			}},
			Heartbeat:    &Heartbeat{URL: Secret{Env: "BEAT", Path: "heartbeat.url", Line: 5}},
			Certificates: &Certificates{URL: "https://ct.example/search", Key: &Secret{File: write("ct.key", ct), Path: "certificates.key", Line: 6}},
		}
		values, problems := c.Secrets(vars.lookup)
		if len(problems) > 0 {
			if !reflect.DeepEqual(values, Values{}) {
				t.Fatalf("problems %v and values %v together", problems, values)
			}
			for _, p := range problems {
				if strings.Contains(p.String(), fzMarker) || p.Text == "" {
					t.Fatalf("the problem %q repeats a value or is empty", p.String())
				}
			}
			return
		}
		if values.SlackURL != urlValue || !reflect.DeepEqual(values.WebhookURLs, []string{urlValue}) ||
			string(values.WebhookKeys[0]) != keyValue || values.HeartbeatURL != urlValue || values.CertificatesKey != ct {
			t.Fatalf("Secrets changed a value: %+v from %q", values, v)
		}
		if got := fmt.Sprintf("%v %+v %#v %s", values, values, values, values); strings.Contains(got, fzMarker) {
			t.Fatalf("a print of the values shows a secret: %s", got)
		}
	})
}
