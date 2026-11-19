# Configuration

The service reads one config file. In the Docker setup it is `/data/config.json` in the volume `osk-dns-watcher_data`, and `init` writes it. Run the commands on this page in `osk-dns-watcher/deploy`: `./osk-dns-watcher` there runs the program inside the service ([The command in deploy](#the-command-in-deploy)).

## The file

- Strict JSON in UTF-8, at most 1 MiB (1048576 octets). No comments.
- An unknown key, a key given twice and a key in the wrong case are refused. `null` is refused everywhere.
- A relative path is read from the folder of the config file: `/data` in the Docker setup.
- The service reads the config only when it starts. After a change, check it and restart:

```sh
./osk-dns-watcher validate
docker compose restart watcher
```

`validate` names each problem as `<file>:<line>: <key>: <text>`, for example `/data/config.json:12: intervals.fast: 4s is below the floor of 5s`.

`init` writes this, and puts the Slack webhook URL in the file `slack-url` (mode 600) and in no other file:

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

A larger example, with two domains, Slack, one signed webhook and a heartbeat:

```json
{
  "state": "/data/state",
  "domains": [
    {"name": "example.com.", "expect": "example.com.expect", "fast": ["login.example.com."]},
    {"name": "example.org.", "expect": "example.org.expect"}
  ],
  "slack": {"url": {"file": "/data/slack-url"}, "min_severity": "medium"},
  "webhooks": [
    {"name": "siem", "url": {"file": "/data/siem-url"}, "key": {"file": "/data/siem-key"}, "min_severity": "high"}
  ],
  "heartbeat": {"url": {"file": "/data/heartbeat-url"}, "interval": "60s"},
  "intervals": {"serial": "15s", "parent": "60s", "fast": "60s", "other": "5m"},
  "history_days": 90,
  "remind": "0s"
}
```

## Settings

`slack`, `webhooks`, `heartbeat`, `intervals`, `network` and `certificates` are optional. The config needs at least one channel: `slack` or one webhook. A duration is written as Go writes it: `90s`, `5m`, `1h`. A secret is a file or an environment variable ([Secrets](#secrets)).

### Domains

| Setting | What it does | Default | Limits |
|---|---|---|---|
| `state` | The folder of the history, which is kept in `state.db` there. | required | Not empty; no `?` or `#`. Mode 700: a folder that other users can open is refused. |
| `domains` | The domains to watch. | required | 1 to 100. |
| `domains[i].name` | The domain, with its trailing dot. | required | Not the root. Each domain once, ignoring case. |
| `domains[i].expect` | The [expectations file](expectations.md) of the domain. | required | Its `domain` line must equal `name`. |
| `domains[i].fast` | Names whose every line is checked at the `fast` interval. | `[]` | At most 100 names, each with its trailing dot. |

### Intervals

| Setting | What it checks | Default | Limits |
|---|---|---|---|
| `intervals.serial` | The zone serial at each nameserver. | `15s` | 5s to 24h |
| `intervals.parent` | The NS and DS sets and the glue at the parent zone. | `60s` | 5s to 24h |
| `intervals.fast` | The A, AAAA, CAA and MX sets of the domain itself, every line whose first label is `_acme-challenge`, and the `fast` names. | `60s` | 5s to 24h |
| `intervals.other` | Every other line; each name outside the domain's own zone that a line points at; each wildcard check; the MTA-STS policy fetch; and the CAA policy of each name of the file that has no CAA line of its own. | `5m` | 5s to 24h |

A moved serial also starts at once the checks of every name in the domain's own zone. A check whose servers give no usable answer opens an alert after 5 times its interval (`parent`, `fast`), 3 times (`other`) or 60 times (`serial`): 5, 15 and 15 minutes at the defaults. The alert about nameservers that give different answers needs the split for 2 times `other` and 11 checks in a row: 10 minutes for a set checked every 60 seconds, up to 50 minutes for one checked every 5 minutes.

### Channels

| Setting | What it does | Default | Limits |
|---|---|---|---|
| `slack.url` | The Slack incoming webhook URL. | required in `slack` | A secret: an https URL with a host and no user name. |
| `slack.min_severity` | The lowest severity of the alerts that this channel gets. | `low` | `low`, `medium`, `high` or `critical` |
| `webhooks` | Your own receivers of signed JSON ([Webhooks](#webhooks)). | `[]` | 0 to 8 |
| `webhooks[i].name` | The name of the channel in `status` and the log. | required | 1 to 32 octets of `a` to `z`, `0` to `9` and `-`. Not `slack`. Each name once. |
| `webhooks[i].url` | Where the service posts. | required | A secret, as `slack.url`. |
| `webhooks[i].key` | The signing key. | required | A secret of 32 to 4096 octets. |
| `webhooks[i].min_severity` | As `slack.min_severity`. | `low` | As `slack.min_severity`. |

A channel gets the messages of an alert when the highest severity of that alert reaches its `min_severity`. Notices (`TEST`, `DOWN`, `CHANGED`) go to every channel.

### Heartbeat, history and reminders

| Setting | What it does | Default | Limits |
|---|---|---|---|
| `heartbeat.url` | Where the service posts its heartbeat ([Heartbeat](#heartbeat)). | required in `heartbeat` | A secret, as `slack.url`. |
| `heartbeat.interval` | The time between two beats. | `60s` | 5s to 1h |
| `history_days` | Resolved alerts and notices older than this are deleted. An open alert and a message that is not sent yet are never deleted. | `90` | 1 to 3650; an integer with no fraction and no exponent |
| `remind` | An alert that stays open is sent again, marked `still open`, when this time has passed since its last message. | `0s` (off) | `0s`, or 1h to 720h |

### Network

For a lab or a private network only. The commands `init`, `check` and `snapshot` take the same settings as the flags `--root-server <address>` and `--extra-range <prefix>`.

| Setting | What it does | Default | Limits |
|---|---|---|---|
| `network.root_servers` | Servers at which every lookup starts, in place of the root servers of the internet. | `[]` | At most 16 IP addresses, each with an optional port (53 when none is given). |
| `network.extra_ranges` | Address ranges that DNS queries and policy fetches may also go to. By default they go only to public addresses. | `[]` | At most 64 prefixes, with no bits set after the prefix length. |

When one is set, `run`, `status`, `validate`, `doctor` and `init` print its warning:

```
network.root_servers is set: osk-dns-watcher starts its walk at <a, b> instead of the root servers of the internet, so these servers decide every answer. Use it only in a lab or a private network.
network.extra_ranges is set: data from DNS can now make osk-dns-watcher send queries and HTTPS requests for MTA-STS policy files to <p, q>. Use it only in a lab or a private network.
```

### Certificate logs

| Setting | What it does | Default | Limits |
|---|---|---|---|
| `certificates.url` | The source of the certificate logs. | `https://api.certspotter.com/v1/issuances` | An https URL with a host, and no query, fragment or user name. The service adds its own query. |
| `certificates.key` | An API key for the source, sent as `Authorization: Bearer <key>`. | none | A secret of 1 to 256 octets of printable ASCII, with no space. |
| `certificates.interval` | The gap between two reads of the source for a domain, when the source asks for less. | `10m` | 5s to 24h |

See [Certificates](#certificates) below.

## Secrets

A secret is an object with one key:

- `{"file": "<path>"}`: the content of a file, at most 4096 octets. One line end at its end is removed. An empty file is a problem. The file must be readable only by its owner (mode 600); `doctor` reports one that is not, with the `chmod` command to run.
- `{"env": "<NAME>"}`: the value of an environment variable of `run`. The name holds only `A` to `Z`, `0` to `9` and `_`, does not start with a digit, and has at most 64 octets. A variable that is not set or is empty is a problem. The Compose files set no variable, so use `file` secrets there.

No secret value appears in the config, the history, a log line or the output of a command. `validate` reads the secrets from its own environment, which can differ from that of the service.

To correct the Slack webhook URL, edit the file and restart the service, which reads it only when it starts:

```sh
docker compose exec watcher vi slack-url
docker compose restart watcher
```

## Environment variables

| Variable | Read by | What it does |
|---|---|---|
| a name in an `env` secret | `run`, `validate` | The value of that secret. |
| `OSK_SLACK_URL` | `check --expect … --state` | The Slack webhook URL for the alerts of that command. |
| `OSK_UNVERIFIED=1` | `start.sh` | Builds the folder as it is, with no check of the signature, to work on the code. `start.sh update` ignores it. `start.sh` prints a line when it is set. |
| `OSK_COMPOSE_EXTRA` | `start.sh` | One more Compose file, for a lab. `start.sh` prints a line when it is set. |

## Delivery

The service sends each message to each channel as an HTTPS POST, and keeps it in its history until it is delivered or given up.

- A 2xx status means delivered.
- Status 408, 429 or 5xx, or no answer: it tries again after 10 seconds, then waits twice as long each time, up to 1 hour (after a 429, at least its `Retry-After`, up to 1 hour). It gives up after 30 attempts.
- Any other 3xx or 4xx status: it gives up at once, because a refused URL or body does not change.

`status` shows a channel that fails, and the log of the service has a line for each attempt.

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

- `event`: `open`, `update`, `escalate`, `reminder` or `resolve`. `severity` is the severity after the event, `was` the one before. The end of the three dangling-name alerts is a `resolve` too, with the `CHECK` text ([alerts.md](alerts.md#how-an-alert-ends)).
- `rule`: `nameservers`, `record-set`, `zone`, `not-covered`, `glue`, `ds`, `gone`, `invalid-file`, `check-failing`, `zone-changed`, `disagree`, `alias-target`, `nameserver-host`, `mail-target`, `challenge`, `wildcard`, `caa`, `issuer`, `certname`, `hostnames`, `spf`, `dmarc`, `dkim` or `mta-sts`.
- `check.kind` is `delegation`, `ds`, `records`, `serial`, `wildcard`, `certificates` or `policy`; it is empty for an alert about the whole domain (`invalid-file`, `zone-changed`). A `wildcard` check asks a random name directly under `check.name`, and its `rtype` is `A`. A `policy` check fetches the MTA-STS policy file from the host `check.name`; its `rtype` is `TXT`. A `certificates` check has an empty `rtype`.
- `seen` lists each server whose answer differs, at most 6; `more` counts the servers left out. A resolve has an empty `seen`.
- `value` holds at most 6 server lines; for `issuer`, `certname` and `hostnames` it holds every line, up to 200. For `spf`, `dmarc`, `dkim` and `mta-sts`, the server lines are followed by one line `weaker <word>` for each way in which the record permits more than the file (or, for `mta-sts`, protects less), for example `weaker p=none in place of p=reject`. A word is a fixed English phrase, at most 240 characters, that holds no text of the record beyond an address, a name or a key. There are at most 12 words; when there are more, the twelfth is `weaker and <k> more`.
- Times are UTC; an empty string means none.
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

The window is 300 seconds each way. Then drop a body whose `id` you saw in the last 10 minutes: it is a replay inside the window, or a message sent again because no answer came. A message sent again keeps its body and `id`, with a new timestamp and signature.

## Heartbeat

The service cannot report its own crash. With `heartbeat` set, it posts `{"schema":1,"type":"heartbeat","at":"2026-11-15T14:00:00Z"}` to `heartbeat.url` every `heartbeat.interval`, but only while `status` would say healthy: the service stored its own beat in the last 30 seconds, no check is late, and no channel fails. A beat is not signed, not stored and not sent again: a missing beat is the signal. Point it at a service that alerts you when the beats stop.

## Certificates

By default no certificate log is read. This object turns the reading on; every key is optional, so `"certificates": {}` turns it on with the defaults:

```json
"certificates": {
  "key": {"env": "CERTSPOTTER_KEY"},
  "interval": "10m"
}
```

The source is the Cert Spotter API of SSLMate. When `certificates` is set, `run`, `status`, `validate` and `doctor` print:

```
certificates is set: osk-dns-watcher sends the name of each watched domain to <host>, which learns which domains you watch.
```

The `issuer` and `certname` lines of the expectations files count only when `certificates` is set. Otherwise `run` and `validate` print `warning <domain>: the issuer and certname lines are not judged: certificates is not set in the config`.

How often the source is asked:

- The source sets the gap between reads. On 17 Nov 2026, without a key, it allowed 10 requests an hour, and after a list with nothing new it asked for a wait of one hour. The service waits as asked (a wait of more than one hour after an empty list is cut to one hour) and asks again at its first check after the wait. A check inside a wait sends nothing.
- `interval` is the gap used only when the source asks for less. A wait after a `429` is kept whole; a `Retry-After` of more than 24 hours is not read, and the next check asks again.
- One domain costs one request an hour once the service runs, and at least two when it starts, because a start lists every valid certificate again. A longer list needs one request for each page, at most 10 in one read. Once in 24 hours the list is read again from the beginning, beside the normal work; when that fails, it is tried again one hour later. At most two certificate checks run at one time.
- More than 10000 valid certificates for a domain, or more than 100000 names on them, make the check fail with "too many". It is tried again after one hour; the open alerts stay judged by the certificates already read.
- A read that fails (no answer, a timeout, status `429` or another status that is not 200, an answer that is too large or cannot be read) never means "no certificates": only the certificates already read are judged. After 3 times `interval` of failing reads, an alert of a failing check opens.

The terms of the source said on 17 Nov 2026 that use without a key is for personal or evaluation purposes; get a key for any other use. The limits of the certificate checks are in [limits.md](limits.md#certificates).

## The MTA-STS policy fetch

The MTA-STS policy file of a domain is fetched exactly when its expectations file has an `mta-sts` line; no setting turns it on. Each fetch is one HTTPS GET of `https://mta-sts.<domain>/.well-known/mta-sts.txt`, every `other` interval (5 minutes), to that host only. It sends no secret and no data of yours.

- The service looks up `mta-sts.<domain>` through the resolver of the machine, and connects only to a public address of it, or one in `network.extra_ranges`. The certificate of the host, checked against those that the system trusts, shows that the answer is the domain's.
- It uses no proxy and follows no redirect. It waits at most 30 seconds, and takes a body of at most 64 kilobytes with status 200.
- A body that arrives but cannot be read as a policy is a difference from the line: senders act as if there were no policy.
- A fetch that fails never means "no policy". After 15 minutes of failing fetches, an alert of a failing check opens. The log line of each failed fetch names the cause in parentheses, for example `failed bad-answer (HTTP status 404)`. The other causes are `timeout`, `network: name lookup failed`, `network: certificate not trusted`, `network: cannot connect`, `network: no usable answer`, `network: no permitted address` and `the policy file is larger than 65536 octets`.

## The command in deploy

`deploy/osk-dns-watcher` runs the program inside the running service of the Compose file beside it, from any folder:

```sh
./osk-dns-watcher status
./osk-dns-watcher accept --write <code> 42
```

- For `run`, `validate`, `status`, `watch`, `accept`, `test-alert`, `init` and `doctor`, it adds `--config /data/config.json`, the config that `start.sh` writes, unless the arguments name a config. Every argument passes unchanged.
- A file name is a path inside the container, whose working folder is `/data`: `check --expect example.com.expect` reads `/data/example.com.expect`.
- When both its input and its output are a terminal, the command gets a terminal too, so that it can ask questions and Ctrl-C reaches it. Its output can be piped.
- The long form still works, and is the one to use with the image, whose folder has no such script: `docker compose exec watcher osk-dns-watcher status --config /data/config.json`.

## Commands and flags

```
osk-dns-watcher version [--json]
osk-dns-watcher query [--rd] [--do] [--cd] [--tcp] [--timeout <duration>] [--json] @<server> <name> [<type>]
osk-dns-watcher check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
osk-dns-watcher snapshot [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] [--json] <domain> [<name> <type>]...
osk-dns-watcher check [--root-server <address>]... [--extra-range <prefix>]... [--timeout <duration>] --expect <file> [--state <folder> [--slack-min-severity <severity>]]
osk-dns-watcher run --config <file>
osk-dns-watcher validate --config <file> [--json]
osk-dns-watcher status --config <file> [--json]
osk-dns-watcher watch --config <file> [--json]
osk-dns-watcher accept --config <file> [--write <code>] [--json] <alert id>
osk-dns-watcher test-alert --config <file> [--json]
osk-dns-watcher init --config <file> [--root-server <address>]... [--extra-range <prefix>]...
osk-dns-watcher doctor --config <file> [--json]
```

Run them as `./osk-dns-watcher <command>` in `osk-dns-watcher/deploy` ([above](#the-command-in-deploy)).

| Command | What it does |
|---|---|
| `version` | Prints the versions of osk-dns-watcher, Go and SQLite. |
| `query` | Sends one DNS query to one server and prints the answer. `--timeout` is for the whole exchange (default 5s). |
| `check <domain>` | Asks the servers once, from the root down, and prints what the walk asked and every answer. `--timeout` is for one query (default 2s). |
| `snapshot` | Prints the expectation lines of what the servers give now ([expectations.md](expectations.md#snapshot)). |
| `check --expect` | Runs the checks of an expectations file once and prints what differs. `--json` works here too. With `--state`, it also keeps the alerts in that folder and sends them to the Slack URL in `OSK_SLACK_URL`, from `--slack-min-severity` up (default `low`). |
| `run` | The service; the container runs it. Its log has one JSON object per line, with the keys `time`, `level`, `event`, `domain` and `text`: `docker compose logs -f watcher`. Its history is `state.db` in the `state` folder. |
| `validate` | Checks the config, its secrets as this process sees them, the expectations files and the state folder. |
| `status` | Says if the service is healthy (exit 0) or not (exit 1), and lists the open alerts with their ids. |
| `watch` | Prints alerts and notices as they happen. |
| `accept` | Prints the line that makes the value of an open alert expected; with `--write <code>`, writes it ([expectations.md](expectations.md#accept)). |
| `test-alert` | Asks the running service to send a test message to every channel, and prints what each did. |
| `init` | Asks the setup questions and writes the config ([expectations.md](expectations.md#what-init-asks-and-writes)); `start.sh` runs it. |
| `doctor` | Checks the network path to the root servers, the config, the rights of the files, DNS, each channel (it sends a test message) and the clock, and says what to fix. |

Flags come before the other arguments. With `--json`, each line of output is one JSON object, and its first key is `type`. Exit codes: 0 done, 1 a problem (for `status`: not healthy), 2 wrong use. Every command except `version` refuses to run as root.
