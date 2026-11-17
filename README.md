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

One file per domain, one line per record set: the name, the type, and what is expected. `osk init` writes the first version from what the servers give, for the NS, DS, A, AAAA, MX, TXT and CAA sets of the domain and the A set of `www`. It also writes `_acme-challenge.<domain>. TXT none`, `_acme-challenge.www.<domain>. TXT none` and `*.<domain>. A none` where nothing is there. If you use DNS challenges to get certificates, remove the two `_acme-challenge` lines: the challenge alert fires at each certificate request. Edit it to change what osk trusts or to watch more names:

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
- `*.<name>. A none`: no wildcard answers under that name; osk asks a random name under it every 5 minutes; for a name in the domain's own zone, also at once when the serial of the zone moves. Only this line is the wildcard line: any other line with a `*` name is checked at that literal name.
- `osk snapshot` writes no line for a certificate-challenge record that is there now, because its token changes with each request. Write `none` once it is gone, or no line if you use DNS challenges.
- Names end with a dot. A line that starts with `#` is a comment.
- A `DS` line is compared at the parent: a changed DS record gives an alert. The address line of a nameserver host also checks its glue at the parent, the address that the parent gives with the delegation. Ask for the host pairs in `osk snapshot` to get those lines, for example `osk snapshot example.com. ns1.example.com. A ns1.example.com. AAAA`. Ask for both types: a host with no AAAA gets the line `AAAA none`, and glue of a type with no line is a difference.
- `issuer <name>` and `certname <name>` lines tell the certificate check (see [Certificates](#certificates)) what is expected. `issuer letsencrypt.org` names a certificate authority as it appears in CAA records (no trailing dot); with at least one such line, a valid certificate from any other authority gives an alert. `certname *.example.com.` allows a wildcard certificate name; it ends with a dot and must be at or under the domain. Write one name on each line.

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
- A glue address that the parent gives for a watched nameserver host differs from the file: critical.
- The DS set at the parent differs from the file or is gone: high; critical when the nameservers alert of the domain is open, and it stays critical until it resolves.
- The parent says that the domain does not exist: critical.
- A record set at any nameserver of the domain differs from the file: high for A, AAAA, CNAME, MX and NS, medium for the other types.
- A name is answered from a zone that the file does not expect.
- The file has no line for the NS or the DS set of a domain.
- The zone serial moved and no watched record differs: low. This is a change to a record you do not watch, or one that was undone.
- The nameservers of a domain give different answers for a watched set, each one steadily, for 10 minutes and 11 checks in a row (up to 50 minutes for a set that is checked every 5 minutes), while the file allows each answer: medium. The alert ends when the split has been absent for 11 checks in a row.
- A certificate-challenge record (`_acme-challenge`) appears where the file says `none`: high.
- The CAA policy that applies to a name of the file permits more than the CAA lines of the file allow (another certificate authority, any account or validation method, wildcards, or the policy is gone): high. A change of the CAA set that permits nothing more is an ordinary change of the set: medium. A certificate authority can read each of three things strictly or permissively: a critical record with a tag that osk does not know, a repeated or empty `accounturi`, and a repeated or faulty `validationmethods`. osk tries each combination and alerts when one of them permits more than the file allows.
- A name outside the domain's own zone that an alias, an MX record, an SPF include or a nameserver in the file points at does not exist: high, critical for a nameserver. When the domain above that name is gone, the alert names the zone that no longer delegates it. A nameserver that answers "no such name" for a name that only has records of another type (against RFC 8020) gives a false alert for such a target.
- A random name under `<name>` gets an answer although the file has `*.<name>. A none`: medium.
- Only when `certificates` is set in the config: a valid certificate for a name of the domain comes from a certificate authority that the CAA lines or the `issuer` lines of the file do not permit: high.
- Only when `certificates` is set: a valid wildcard certificate for a name of the domain is not listed by a `certname` line: high.
- Only when `certificates` is set: valid certificates name hosts under the domain that the file does not list: low. One alert holds the list.
- A check gets no usable answer for 5 minutes, or 15 minutes for the checks that run every 5 minutes and for the serial.
- The expectations file changed, or is not valid.
- osk was not running for a minute or more: at its next start, a notice says for how long.

How often osk asks: the zone serial at each nameserver every 15 seconds, and a moved serial starts the checks of the zone at once; the nameservers and DS at the parent every 60 seconds; the A, AAAA, CAA and MX sets of each domain and its `_acme-challenge` names every 60 seconds; every other set every 5 minutes, and so are the address check of each name that a line points at, the wildcard check, and the CAA set of each other name of the file, which is also checked at once when the serial of the zone moves. The wildcard check of a name in the domain's own zone also starts at once when the serial of the zone moves. An alert is sent within 5 seconds of the check that sees the change, unless older messages to that channel are still waiting. These intervals are what osk is built for and were tested in a lab; detection times on real domains are not measured yet. The intervals can be changed in the config.

## Certificates

osk can also read the public certificate logs, to see certificates that were issued for your domains. This is off until the config has a `certificates` object (see [docs/config.md](docs/config.md)). The source is the Cert Spotter API of SSLMate, `https://api.certspotter.com/v1/issuances`; it works without a key, and a key can be set.

- osk sends the name of each watched domain to that source, which then learns which domains you watch. A check that falls inside a wait that the source asked for sends nothing.
- A certificate is judged only while it is valid. It leaves the list when it expires, and an alert about it ends then.
- The source sets the pace. Without a key, on 17 Nov 2026, it allowed 10 requests an hour and, after a list with nothing new, asked for a wait of one hour. osk obeys: it asks again at its first check after that wait, so a new certificate is seen about one hour after the source has it (a little later when `interval` does not divide the hour; when `interval` is longer than the wait, the next read comes one `interval` later), plus the delay of the source behind the issuance, which is not measured yet. `interval` is the gap that osk uses only when the source asks for less. A wait that the source asks for after a `429` is kept whole; a `Retry-After` of more than 24 hours is not read, and osk then asks again at its next check. The limits with a key were not measured.
- The terms of the source said on 17 Nov 2026 that use without a key is for personal or evaluation purposes. Get a key for any other use.
- One domain costs one request an hour once osk is running, and at least two when osk starts: the first list, then one more request that finds the end of it. A domain with many certificates needs one request for each page. Once in 24 hours, in one run, osk reads the list again from the beginning, beside its normal work; this never stops the certificate alerts. For a domain whose list does not fit one run (more than 9 pages: 10 pages need 11 requests), the list is not read again until osk starts again, so a fault of the source's position marker is not healed before that. When the daily listing fails, osk tries it again one hour later, and the normal reading of new certificates goes on in between. At most two certificate checks run at one time.
- More than 10000 valid certificates for a domain, or more than 100000 names on them, make the check fail with "too many". osk asks again after one hour, and the alerts that are open stay judged by the certificates that osk has. A domain that is truly that large fails every hour, which the `check-failing` alert tells.
- When the source cannot be read (no answer, a rate limit, a status that is not 200, or an answer that osk cannot read), osk never takes it as "no certificates": it judges only the certificates that it has read. An alert can still open from pages read before the failure, and it ends when its certificate expires. After the fail limit, 3 times `interval`, a `check-failing` alert opens.
- A source that wrongly answers with an empty list right after osk starts ends the open certificate alerts until its next true answer.

## What osk does not detect yet

- A change that is made and undone between two checks can be missed. If the DNS provider moves the zone serial, the serial check reports that the zone changed, but not which record.
- Nameserver addresses that this machine cannot reach are not checked. Docker's default network has no IPv6, so with it no IPv6 address of a nameserver is checked.
- A nameserver that does not answer while another one does.
- A nameserver that gives another allowed answer only now and then, a steady difference beside a nameserver whose answers change from query to query, and names whose answers change from query to query: a line with `in`, `like` or `||` trusts every answer that it allows. Nameservers that each keep another allowed answer for some minutes can get the alert above again and again.
- A wildcard that holds no A or CNAME record, for example one with only AAAA, TXT or MX records.
- A CAA set at the target of an alias: the certificate authority follows the alias, osk does not. When an alias stands at a name that has no line in the file, above a name of the file, the CAA policy of the names below it comes from the alias target; osk sees only that the zone serial moved.
- A CAA policy above the watched domain, at its TLD: osk reads it as none.
- A CAA record at a name with a `_` label: osk compares it as an ordinary set, not as a policy.
- A CAA line with more than 64 different grants in a class reads as no policy for that class: no CAA alert for it. A method list of more than 16 labels reads as "any method" for its grant.
- When your own CAA line holds an unusual value (a critical record with a tag that osk does not know, or a repeated or faulty `accounturi` or `validationmethods`), a change to another unusual value of the same kind is not ranked: it gives only the medium alert at that name and none at a name below it.
- A CAA record whose tag is `issue` with a blank or another odd character added is an unknown tag for osk. A certificate authority that reads such a tag as `issue` would not be seen; none is known.
- A wildcard CAA record (`*.name`) that permits more than the policy above it gives the CAA alert at each name of the file under it that does not exist.
- A deleted name inside the domain's own zone that an alias or MX record points at, unless it has a line of its own.
- A name that an alias, MX record or SPF include points at, at a provider that answers for every name: it still exists when nobody owns it.
- A missing name whose zone answers 'no data' and not 'no such name'.
- A certificate that was revoked: its alert ends when the certificate expires.
- A certificate from an expected authority for a name of the file, for example one that someone obtained by changing DNS for a moment: the logs cannot tell it from your own renewal. The DNS checks and the CAA lines are the defence.
- A wildcard certificate for a name that is one label above a watched domain.
- Certificates that were issued before osk started are all new to it: the first run lists every valid certificate, and what the file does not cover gives up to three alerts for each domain.
- Registry data (locks, expiry), email policy, DNSSEC validation and the answers of public resolvers.

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
