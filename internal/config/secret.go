package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"slices"

	"github.com/Opsek/dns-monitoring/internal/httpclient"
)

const (
	maxSecretFile = 4096
	maxEnvName    = 64
	// RFC 2104 asks for an HMAC key at least as long as the hash: 32
	// octets for SHA-256.
	minKey = 32
	maxKey = 4096
)

const secretShape = `want {"env": "<NAME>"} or {"file": "<path>"}`

// secret reads where a secret is: an environment variable or a file, never
// the value, so that the config can be shown and kept without harm. keyAt
// is where its key starts; the problems of its value point there.
func (w *walker) secret(path string, keyAt int64) Secret {
	s := Secret{Path: path, Line: w.lines.at(keyAt)}
	t, at := w.next()
	if t != json.Delim('{') {
		w.refuse(t, at, path, secretShape)
		return s
	}
	seen := w.members(path, at, fields{
		"env":  func(p string, _ int64) { s.Env = w.envName(p) },
		"file": func(p string, _ int64) { s.File, _, _ = w.filePath(p) },
	}, nil)
	if len(seen) != 1 {
		w.add(at, path, secretShape)
	}
	return s
}

// envName reads the name of a variable. The problem text does not repeat
// it: a value pasted here by mistake must not reach a log.
func (w *walker) envName(path string) string {
	s, at, ok := w.str(path)
	if ok && !validEnvName(s) {
		w.add(at, path, "the name of an environment variable holds only A to Z, 0 to 9 and _, and does not start with a digit")
	}
	return s
}

// validEnvName allows [A-Z_][A-Z0-9_]*, the names that every shell can set.
func validEnvName(s string) bool {
	if s == "" || len(s) > maxEnvName || '0' <= s[0] && s[0] <= '9' {
		return false
	}
	for _, c := range []byte(s) {
		if !('A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// Values are the secrets of a config. They go only to the channels and the
// HTTPS client, never to a printed text.
type Values struct {
	SlackURL     string
	WebhookURLs  []string // config order
	WebhookKeys  [][]byte
	HeartbeatURL string
}

func (v Values) String() string { return "[hidden]" }

// Format hides the values from every verb of package fmt: String alone
// leaves %#v and %d to print the fields.
func (v Values) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, v.String())
}

// Secrets reads the value of each secret: lookup is os.LookupEnv in the
// service. A problem names the variable or the file, never a value. When
// there is a problem, Values is empty.
func (c *Config) Secrets(lookup func(string) (string, bool)) (Values, []Problem) {
	var v Values
	var problems []Problem
	read := func(s Secret, check func(string) string) string {
		value, text := s.value(lookup)
		if text == "" {
			text = check(value)
		}
		if text != "" {
			problems = append(problems, Problem{File: c.Path, Line: s.Line, Path: s.Path, Text: text})
		}
		return value
	}
	if c.Slack != nil {
		v.SlackURL = read(c.Slack.URL, checkURL)
	}
	for _, h := range c.Webhooks {
		v.WebhookURLs = append(v.WebhookURLs, read(h.URL, checkURL))
		v.WebhookKeys = append(v.WebhookKeys, []byte(read(h.Key, checkKey)))
	}
	if c.Heartbeat != nil {
		v.HeartbeatURL = read(c.Heartbeat.URL, checkURL)
	}
	if len(problems) > 0 {
		return Values{}, problems
	}
	return v, nil
}

// value reads the secret and gives it, or the text of its problem.
func (s Secret) value(lookup func(string) (string, bool)) (string, string) {
	if s.Env != "" {
		v, ok := lookup(s.Env)
		// The text names no variable: a token pasted as the name must not
		// come back; the key path and the line say which.
		if !ok || v == "" {
			return "", "the environment variable is not set"
		}
		return v, ""
	}
	data, err := ReadRegular(s.File, maxSecretFile)
	switch {
	case err != nil:
		return "", "the secret file cannot be read: " + readWhy(err)
	case len(data) > maxSecretFile:
		return "", fmt.Sprintf("the file %s is larger than %d octets", s.File, maxSecretFile)
	}
	// The line end that an editor or echo leaves is no part of the value.
	data = bytes.TrimSuffix(data, []byte("\n"))
	data = bytes.TrimSuffix(data, []byte("\r"))
	if len(data) == 0 {
		return "", fmt.Sprintf("the file %s is empty", s.File)
	}
	return string(data), ""
}

// readWhy names why a secret file cannot be read, without its path or the
// text of the system: the key path and the line of the problem name the
// file, and a secret pasted as the path must not come back.
func readWhy(err error) string {
	switch {
	case errors.Is(err, fs.ErrNotExist):
		return "it does not exist"
	case errors.Is(err, fs.ErrPermission):
		return "permission denied"
	case errors.Is(err, ErrNotRegular):
		return "it is not a regular file"
	}
	return "read error"
}

// checkURL refuses a URL that the HTTPS client would refuse. The text holds
// no part of the URL, which may carry a token in its path.
func checkURL(value string) string {
	if _, err := httpclient.HostOf(value); err != nil {
		return "the value is not an https URL with a host and no user name"
	}
	return ""
}

func checkKey(value string) string {
	switch {
	case len(value) < minKey:
		return fmt.Sprintf("the key is shorter than %d octets", minKey)
	case len(value) > maxKey:
		return fmt.Sprintf("the key is longer than %d octets", maxKey)
	}
	return ""
}

// Hosts gives the host of each URL in the form that httpclient.New takes,
// without repeats: the only hosts that osk may post to.
func (v Values) Hosts() []string {
	urls := append([]string{v.SlackURL}, v.WebhookURLs...)
	urls = append(urls, v.HeartbeatURL)
	var hosts []string
	for _, u := range urls {
		// The URL of a channel that is not set is empty and has no host.
		if h, err := httpclient.HostOf(u); err == nil && !slices.Contains(hosts, h) {
			hosts = append(hosts, h)
		}
	}
	return hosts
}
