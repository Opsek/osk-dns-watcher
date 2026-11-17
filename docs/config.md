# Configuration

osk reads one config file. In the Docker setup of the [README](../README.md) it is `/data/osk.json` in the volume `osk_data`, and `osk init` writes it. Run the commands on this page in the folder `dns-monitoring/deploy`.

## The file

- Strict JSON in UTF-8, at most 1 MiB (1048576 octets). JSON has no comments, and osk accepts none.
- A key that osk does not know, a key given twice and a key in the wrong case are refused. `null` is refused everywhere.
- A relative path is read from the folder of the config file: `/data` in the Docker setup.
- osk reads the config only when it starts. After a change, check it and restart the service:

```sh
docker compose exec osk osk validate --config osk.json
docker compose restart osk
```

`osk validate` names each problem as `<file>:<line>: <key>: <text>`, for example `osk.json:<line>: intervals.fast: 4s is below the floor of 5s`. When osk did not run for a minute or more, the restart sends a DOWN notice that says how long.

## What `osk init` writes

```json
{
  "state": "state",
  "domains": [
    {
      "name": "example.com.",
      "expect": "example.com.expect"
    }
  ],
  "slack": {
    "url": {
      "file": "slack-url"
    }
  }
}
```

The Slack webhook URL is in the file `slack-url` (mode 600) and in no other file.

## A larger example

Two domains, Slack, one signed webhook and a heartbeat:

```json
{
  "state": "/data/state",
  "domains": [
    {"name": "example.com.", "expect": "example.com.expect", "fast": ["login.example.com."]},
    {"name": "example.org.", "expect": "example.org.expect"}
  ],
  "slack": {"url": {"env": "OSK_SLACK_URL"}, "min_severity": "medium"},
  "webhooks": [
    {"name": "siem", "url": {"file": "/data/siem-url"}, "key": {"file": "/data/siem-key"}, "min_severity": "high"}
  ],
  "heartbeat": {"url": {"env": "OSK_HEARTBEAT_URL"}, "interval": "60s"},
  "intervals": {"serial": "15s", "parent": "60s", "fast": "60s", "other": "5m"},
  "history_days": 90,
  "remind": "0s"
}
```

An `env` secret needs the variable in the environment of `osk run`. The Compose file of the Docker setup sets no variable, so use `file` secrets there.

## Keys

| Key | Type | Default | Limits and meaning |
|---|---|---|---|
| `state` | string | required | The folder that holds the history. Not empty; no `?` or `#`. osk refuses a folder that other users can open: it must be mode 700. |
| `domains` | list of objects | required | 1 to 100 domains. |
| `domains[i].name` | string | required | The domain, with its trailing dot. Not the root. Each domain once, ignoring case. |
| `domains[i].expect` | string | required | The expectations file of the domain. Its `domain` line must equal `name`. |
| `domains[i].fast` | list of strings | `[]` | At most 100 names, each with its trailing dot. Every line of these names is checked at the `fast` interval. |
| `intervals.serial` | duration | `15s` | The zone serial at each nameserver. 5s to 24h. |
| `intervals.parent` | duration | `60s` | The NS and DS sets at the parent zone. 5s to 24h. |
| `intervals.fast` | duration | `60s` | The A, AAAA, CAA and MX sets of the domain, every line of `_acme-challenge.<domain>`, and the `fast` names. 5s to 24h. |
| `intervals.other` | duration | `5m` | Every other line. 5s to 24h. |
| `slack.url` | secret | required in `slack` | An https URL with a host and no user name. |
| `slack.min_severity` | string | `low` | `low`, `medium`, `high` or `critical`. |
| `webhooks` | list of objects | `[]` | 0 to 8 webhooks. |
| `webhooks[i].name` | string | required | 1 to 32 octets of `a` to `z`, `0` to `9` and `-`. Not `slack`. Each name once. |
| `webhooks[i].url` | secret | required | As `slack.url`. |
| `webhooks[i].key` | secret | required | The signing key: 32 to 4096 octets. |
| `webhooks[i].min_severity` | string | `low` | As `slack.min_severity`. |
| `heartbeat.url` | secret | required in `heartbeat` | As `slack.url`. |
| `heartbeat.interval` | duration | `60s` | 5s to 1h. |
| `history_days` | integer | `90` | 1 to 3650, with no fraction and no exponent. Resolved alerts and notices older than this are deleted; an open alert and a message that is not sent yet are never deleted. |
| `remind` | duration | `0s` (off) | `0s`, or 1h to 720h. When set, an alert that stays open is sent again, marked "still open", when this time has passed since its last message. |
| `network.root_servers` | list of strings | `[]` | At most 16 IP addresses, each with an optional port (53 when none is given). See [Labs and private networks](#labs-and-private-networks). |
| `network.extra_ranges` | list of strings | `[]` | At most 64 address prefixes, with no bits set after the prefix length. |

- A duration is written as Go writes it: `90s`, `5m`, `1h`.
- `slack`, `heartbeat`, `intervals` and `network` are optional objects. The config needs at least one channel: `slack` or one webhook.
- A check that gets no usable answer from any server opens a medium `check-failing` alert after 5 times its interval (`parent` and `fast`), 3 times (`other`) or 60 times (`serial`). At the default intervals that is 5, 15 and 15 minutes.
- A channel gets the messages of an alert when the highest severity of that alert reaches the channel's `min_severity`. Notices (TEST, DOWN, and a change of the expectations) go to every channel.

## Secrets

A secret is an object with one key:

- `{"env": "<NAME>"}`: the value of an environment variable. The name holds only `A` to `Z`, `0` to `9` and `_`, does not start with a digit, and has at most 64 octets. A variable that is not set or is empty is a problem.
- `{"file": "<path>"}`: the content of a file, at most 4096 octets. One line end at the end of the file is removed. An empty file is a problem.

A secret file must be readable only by its owner (mode 600); `osk doctor` reports one that is not, with the `chmod` command to run. No secret value appears in the config, the history, a log line or the output of a command. `osk validate` reads the secrets from its own environment, which can differ from the environment of the service.

## Delivery

osk sends each message to each channel as an HTTPS POST, and keeps it in its history until it is delivered or given up.

- A 2xx status means delivered.
- Status 408, 429 or 5xx, or no answer: osk tries again after 10 seconds, then waits twice as long each time, up to 1 hour (after a 429, at least its `Retry-After`, up to 1 hour). It gives up after 30 attempts.
- Any other 3xx or 4xx status: osk gives up at once, because a refused URL or body does not change.

`osk status` shows a channel that fails, and the log of `osk run` has a line for each attempt.

## Webhooks

A webhook gets a POST with `Content-Type: application/json` and a body with `"schema": 1`. The body is one line; here it is spread over several lines. An alert:

```json
{
  "schema": 1,
  "type": "alert",
  "id": "4f0c2a9e7b1d36584e2a0c9f1b7d3e65",
  "at": "2026-11-15T14:02:07Z",
  "event": "open",
  "severity": "high",
  "was": "high",
  "rule": "record-set",
  "check": {"kind": "records", "domain": "example.com.", "name": "www.example.com.", "rtype": "A"},
  "expected": "192.0.2.10",
  "seen": [{"server": "ns1.example.net.", "address": "198.51.100.53:53", "text": "203.0.113.7", "ttl": 300}],
  "more": 0,
  "value": ["198.51.100.53:53 ns1.example.net. 203.0.113.7"],
  "first_seen": "2026-11-15T14:02:07Z",
  "last_clean": "2026-11-15T14:01:07Z",
  "resolved": "",
  "text": ":red_circle: *HIGH* · `www.example.com. A` changed\n\n```\nexpected   192.0.2.10\n\nnow        203.0.113.7\nseen at    ns1.example.net. (198.51.100.53)   TTL 300\n```\n\n:clock3: First seen 14:02:07 · last OK 14:01:07 · 15 Nov 2026 UTC\n\n:point_right: If you did not make this change, check your DNS provider account now."
}
```

- `event`: `open`, `update`, `escalate`, `reminder` or `resolve`. `severity` is the severity after the event, `was` the one before.
- `rule`: `nameservers`, `record-set`, `zone`, `not-covered`, `invalid-file`, `check-failing` or `zone-changed`.
- `check.kind` is empty for an alert about the whole domain (`invalid-file`, `zone-changed`).
- `seen` lists each server whose answer differs, at most 6; `more` counts the servers left out. A resolve has an empty `seen`.
- `value` holds at most 6 lines. Times are UTC; an empty string means none.
- `text` is the Slack text, so a receiver that shows Slack text can show it as it is.

A notice has `schema`, `type` (`"notice"`), `id`, `at`, `notice` (`test`, `down` or `expectations`), `domain` (empty when the notice is about no domain), `lines` (at most 200) and `text`.

### Signature

Each POST to a webhook carries two headers:

- `Osk-Timestamp`: the Unix time of the attempt, in seconds.
- `Osk-Signature`: `sha256=` and 64 lowercase hex digits of HMAC-SHA256 with the key, over the timestamp, one `.`, and the body exactly as sent.

A receiver in Go checks them like this (with the packages `crypto/hmac`, `crypto/sha256`, `encoding/hex`, `net/http`, `strconv` and `time`):

```go
func verify(key, body []byte, h http.Header, now time.Time) bool {
	ts := h.Get("Osk-Timestamp")
	sec, err := strconv.ParseInt(ts, 10, 64)
	if err != nil || sec < now.Unix()-300 || sec > now.Unix()+300 {
		return false // not fresh: a replay or a wrong clock
	}
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(ts + "."))
	mac.Write(body)
	return hmac.Equal([]byte("sha256="+hex.EncodeToString(mac.Sum(nil))), []byte(h.Get("Osk-Signature")))
}
```

The window is 300 seconds each way. Then drop a body whose `id` you saw in the last 10 minutes: it is a replay inside the window, or a message that osk sent again because it saw no answer. A message that osk sends again keeps its body and `id`, with a new timestamp and signature.

## Heartbeat

With `heartbeat` set, `osk run` POSTs `{"schema":1,"type":"heartbeat","at":"2026-11-15T14:00:00Z"}` to `heartbeat.url` every `heartbeat.interval`, but only while `osk status` would say healthy: the service stored its own beat in the last 30 seconds, no check is late, and no channel fails. The heartbeat is not signed, not stored and not sent again: a missing beat is the signal. Point it at a service that alerts you when the beats stop.

## Labs and private networks

By default osk starts every lookup at the root servers of the internet and sends queries only to public addresses. Two keys change that, for a lab or a private network. `osk init`, `osk check` and `osk snapshot` take the same settings as the flags `--root-server <address>` and `--extra-range <prefix>`.

When a key is set, `osk run`, `osk status`, `osk validate` and `osk doctor` print its warning:

- `network.root_servers is set: osk starts its walk at <a, b> instead of the root servers of the internet, so these servers decide every answer. Use it only in a lab or a private network.`
- `network.extra_ranges is set: data from DNS can now make osk send queries to <p, q>. Use it only in a lab or a private network.`

## Adding a domain

`osk init` runs only once, so add a second domain by hand. Write its expectations from what its servers give now:

```sh
docker compose exec osk sh -c 'osk snapshot example.net. example.net. A example.net. AAAA example.net. MX example.net. TXT example.net. CAA www.example.net. A > example.net.expect'
```

This asks for the same sets that `osk init` writes. A set that osk could not take gets a `# not written:` comment line with the reason, and the command then exits with 1. Read every line before you trust it, and add or change lines:

```sh
docker compose exec osk vi example.net.expect
```

Add `{"name": "example.net.", "expect": "example.net.expect"}` to `domains` in `osk.json`, then check the config and restart:

```sh
docker compose exec osk vi osk.json
docker compose exec osk osk validate --config osk.json
docker compose restart osk
```

## Commands and flags

```
osk run --config <file>
osk validate --config <file> [--json]
osk status --config <file> [--json]
osk watch --config <file> [--json]
osk accept --config <file> [--write <code>] [--json] <alert id>
osk test-alert --config <file> [--json]
osk init --config <file> [--root-server <address>]... [--extra-range <prefix>]...
osk doctor --config <file> [--json]
osk snapshot [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
osk check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] --expect <file>
osk query [--rd] [--do] [--cd] [--tcp] [--timeout <duration>] [--json] @<server> <name> [<type>]
osk version [--json]
```

Flags come before the other arguments. With `--json`, each line of output is one JSON object, and its first key is `type`. Exit codes: 0 done, 1 a problem (for `status`: not healthy), 2 wrong use. Every command except `version` refuses to run as root.
