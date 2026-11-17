# osk

osk watches the DNS of your domains from the outside: it asks each domain's own servers, starting from the root servers, and compares their answers with a file of expectations that you own. When an answer differs, it sends an alert to Slack or to any webhook.

## Quick start

You need git and Docker with the Compose plugin, on Linux or macOS (on Windows, in WSL 2), and the URL of a Slack incoming webhook.

osk must reach the DNS root servers directly on port 53, over UDP and TCP; a network whose VPN, router or provider answers DNS queries itself cannot run osk.

```sh quickstart
git clone https://github.com/Opsek/dns-monitoring.git
dns-monitoring/deploy/start.sh
```

`start.sh` builds osk, which takes a few minutes the first time, and asks for the domains to watch and the webhook URL. It shows what osk sees now for each domain and writes nothing until you type `yes`. When this machine cannot reach some nameserver addresses over IPv6, one "Not asked" line says how many, and the expectations come from the servers that answered. Then it starts osk as a service and sends a test message to your channel.

Run every other command in the folder `dns-monitoring/deploy`.

## What an alert looks like

In Slack the `:codes:` show as emoji.

~~~
:red_circle: *HIGH* · `www.example.com. A` changed

```
expected   192.0.2.10

now        203.0.113.7
seen at    ns1.example.net. (198.51.100.53)   TTL 300
```

:clock3: First seen 14:02:07 · last OK 14:01:07 · 15 Nov 2026 UTC

:point_right: If you did not make this change, check your DNS provider account now.
~~~

When the answer is as expected again, a RESOLVED message follows. Other webhooks get the same text in signed JSON; see [docs/config.md](docs/config.md).

## The expectations file

One file per domain, one line per record set: the name, the type, and what is expected. `osk init` writes the first version from what the servers give, for the NS, DS, A, AAAA, MX, TXT and CAA sets of the domain and the A set of `www`. Edit it to change what osk trusts or to watch more names:

```
domain example.com.
example.com. NS ns1.example.net. | ns2.example.net.
example.com. DS none
example.com. A 192.0.2.10
example.com. MX 10 mail.example.com.
www.example.com. A in 192.0.2.0/24
cdn.example.com. CNAME like *.cdn.example.net.
mail.example.com. A 192.0.2.25 | 192.0.2.26 || 192.0.2.27
_acme-challenge.example.com. TXT none
```

- `|` separates the records of one set; `||` separates sets that are each allowed.
- `in <prefix>` allows any address in the range; `like *.<name>` allows any name under that name.
- `none`: the set must not exist.
- Names end with a dot. A line that starts with `#` is a comment.
- A `DS` line is accepted, but its data is not compared yet: a changed DS record gives no alert.

To accept the value that an alert reports, run `docker compose exec osk osk accept --config osk.json <alert id>`: it prints the change and a code; add `--write <code>` before the id to make it. To edit a file by hand: `docker compose exec osk vi example.com.expect`. osk reads the files again every 5 seconds, keeps the last valid file when one is not valid (and alerts), and sends a notice with the changed lines.

## Commands

Run them as `docker compose exec osk osk <command>`. All but the last four take `--config osk.json`. All but `init` and `run` take `--json`.

| Command | What it does |
|---|---|
| `status` | Says if osk is healthy (exit 0) or not (exit 1), and lists the open alerts with their ids. |
| `watch` | Prints alerts and notices as they happen. |
| `accept <alert id>` | Prints the line that makes the reported value expected; with `--write <code>`, writes it. |
| `test-alert` | Sends a test message through the running service to every channel. |
| `doctor` | Checks DNS, the webhooks, the clock and the file rights, and says what to fix. It sends a test message to each channel. |
| `validate` | Checks the config and the expectations files. |
| `init` | Asks the setup questions and writes the config; `start.sh` runs it. |
| `run` | The service; the container runs it. Its log has one JSON object per line: `docker compose logs -f osk`. |
| `snapshot <domain> [<name> <type>]...` | Prints the expectation lines of what the servers give now. |
| `check <domain> [<name> <type>]...` | Asks the servers once and prints each answer; `check --expect <file>` compares them with a file. |
| `query @<server> <name> [<type>]` | Sends one DNS query to one server and prints the answer. |
| `version` | Prints the versions of osk, Go and SQLite. |

## What osk detects

- The nameservers of a domain at its parent zone differ from the file: critical.
- A record set at any nameserver of the domain differs from the file: high for A, AAAA, CNAME, MX and NS, medium for the other types.
- A name is answered from a zone that the file does not expect.
- The file has no line for the NS or the DS set of a domain.
- The zone serial moved and no watched record differs: low. This is a change to a record you do not watch, or one that was undone.
- A check gets no usable answer for 5 minutes, or 15 minutes for the checks that run every 5 minutes and for the serial.
- The expectations file changed, or is not valid.
- osk was not running for a minute or more: at its next start, a notice says for how long.

How often osk asks: the zone serial at each nameserver every 15 seconds, and a moved serial starts the checks of the zone at once; the nameservers and DS at the parent every 60 seconds; the A, AAAA, CAA and MX sets of each domain and its `_acme-challenge` names every 60 seconds; every other set every 5 minutes. An alert is sent within 5 seconds of the check that sees the change, unless older messages to that channel are still waiting. These intervals are what osk is built for and were tested in a lab; detection times on real domains are not measured yet. The intervals can be changed in the config.

## What osk does not detect yet

- A change that is made and undone between two checks can be missed. If the DNS provider moves the zone serial, the serial check reports that the zone changed, but not which record.
- DS records are not compared, and glue addresses at the parent are not checked.
- Nameserver addresses that this machine cannot reach are not checked. Docker's default network has no IPv6, so with it no IPv6 address of a nameserver is checked.
- Registry data (locks, expiry), certificates, names that point at something gone, email policy, DNSSEC validation and the answers of public resolvers.

## Update, stop, data

```sh update
./start.sh update
```

This pulls the new code, rebuilds osk and starts it again with the same config, expectations and history. The restart sends a test message, and a DOWN notice when osk did not run for a minute or more.

- Stop osk: `docker compose stop`. Start it again: `docker compose start`.
- Everything osk keeps is in the Docker volume `osk_data`, at `/data` in the container: `osk.json`, one `.expect` file for each domain, `slack-url` and the history in `state/`. `docker compose down` keeps it; `docker compose down --volumes` deletes it.
- To correct a wrong webhook URL: `docker compose exec osk vi slack-url`, then `docker compose restart osk`. osk reads the URL only when it starts.
- Config keys, other webhooks and the heartbeat: [docs/config.md](docs/config.md).

## Build and check

`make build` builds osk as one static Linux file for amd64 and one for arm64, which need nothing else to run. `make check` runs every check of the code in containers. See [docs/development.md](docs/development.md).

## License

Source-available under the PolyForm Noncommercial License 1.0.0. See [LICENSE.md](LICENSE.md).
