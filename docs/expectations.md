# The expectations file

Each domain has one file that says what its DNS must look like, for example `example.com.expect`. It lies beside the config, in `/data` in the container. The service alerts when a server gives anything that the file does not allow.

The commands on this page run in `osk-dns-watcher/deploy`. `./osk-dns-watcher` runs the program inside the running service, so a file name such as `example.com.expect` is read in `/data` there. With the image, use the long form that [config.md](config.md#the-command-in-deploy) gives.

## The one idea: what you confirm is trusted

`init` asks the servers of your domain and writes what they give now. When you type `yes`, those answers become what the service expects. If the domain is already wrong at that moment, for example a record that someone else changed, the wrong state becomes the expected one, and no alert comes.

So read every line before you type `yes`. Do the same for every line that `accept` or `snapshot` gives you.

## What `init` asks and writes

`start.sh` runs `init`. It asks two questions:

```
Domains to watch, separated by spaces:
Slack incoming webhook URL (hidden):
```

Then it asks the servers, shows the lines it would write for each domain, lists under `Not watched, and why:` each set that it leaves out, and asks `Trust these lines and write the setup to /data? Type yes:`. Any other answer writes nothing. Once the config exists, `init` asks nothing again.

For each domain it writes:

- the `domain` line;
- the NS set of the domain. When the parent zone and the domain's servers give different sets (at most four), the line accepts each one, and `init` shows which server gave which set;
- the DS set at the parent zone;
- the A, AAAA, MX, TXT and CAA sets of the domain itself;
- the A set of `www.<domain>`, and the TXT sets of `_dmarc.<domain>` and `_mta-sts.<domain>`;
- the TXT sets of `_acme-challenge.<domain>` and `_acme-challenge.www.<domain>`, but only when no record is there;
- the A set of `*.<domain>`: `none` when no wildcard answers, else its records;
- the A and AAAA sets of each nameserver host inside the domain, when the NS line names at most eight such hosts. These lines make the service compare the glue at the parent zone;
- the `mta-sts` line, when `_mta-sts.<domain>` holds an MTA-STS record and the policy file can be read.

A set gets a line only when every server answered and all agree; an empty set gets a `none` line. IPv6 addresses that this machine cannot reach are left out, and `init` says how many. A file for `example.com.` can look like this:

```
# Written by osk-dns-watcher init at 2026-11-15 14:00:00 UTC from what the servers gave. Edit a line to change what osk-dns-watcher trusts.
domain example.com.
mta-sts enforce 604800 mail.example.com.
example.com. A 192.0.2.10
example.com. NS ns1.example.com. | ns2.example.net.
example.com. MX 10 mail.example.com.
example.com. TXT "v=spf1 mx -all"
example.com. AAAA none
example.com. DS none
example.com. CAA 0 issue "letsencrypt.org"
*.example.com. A none
_acme-challenge.example.com. TXT none
_dmarc.example.com. TXT "v=DMARC1; p=reject"
_mta-sts.example.com. TXT "v=STSv1; id=20261115"
ns1.example.com. A 192.0.2.53
ns1.example.com. AAAA none
www.example.com. A 192.0.2.10
_acme-challenge.www.example.com. TXT none
```

If you get certificates through DNS challenges, remove the two `_acme-challenge` lines: else each certificate request gives an alert.

## Line forms

A line is `<name> <type> <what is expected>`. Every name ends with a dot. There is no TTL and no class field, and TTLs are not compared. A file has one line for each name and type.

- **Exact records.** `example.com. A 192.0.2.10`: the set holds exactly these records, written as in a zone file.
- **Several records.** `mail.example.com. A 192.0.2.25 | 192.0.2.26`: `|` separates the records of one set.
- **Alternatives.** `example.com. NS ns1.example.net. | ns2.example.net. || ns1.example.org. | ns2.example.org.`: `||` separates sets that are each allowed, at most 16.
- **None.** `example.com. DS none`: the set must not exist.
- **Address ranges.** `www.example.com. A in 192.0.2.0/24 198.51.100.0/24`: each address lies in one of the ranges. A and AAAA only; a range has no bits set after its length.
- **Name patterns.** `cdn.example.com. CNAME like *.cdn.example.net.`: each target matches a pattern. `*.<name>` matches any name under `<name>`, but not `<name>` itself; a plain name matches only itself. NS, CNAME, DNAME and MX only.
- **No wildcard.** `*.example.com. A none`: no wildcard answers under `example.com.`. The service asks a random name under it every 5 minutes and, for a name in the domain's own zone, at once when the zone serial moves. Only this line is a wildcard line: any other line with a `*` name is checked at that literal name.
- **The domain.** `domain example.com.`: once, before every other line that is not a comment.
- **Issuer.** `issuer letsencrypt.org`: a certificate authority, as CAA records name it, with no trailing dot. With at least one such line, a valid certificate from any other authority gives an alert.
- **Certificate name.** `certname *.example.com.`: a name that certificates may hold besides the names of your lines. It ends with a dot, lies at or under the domain, and has `*` only as its first label.
- **MTA-STS policy.** `mta-sts enforce 604800 mail.example.com. *.mail.example.net.`: the policy that the domain must serve: the mode (`enforce`, `testing` or `none`), `max_age` in seconds (0 to 31557600), and the mx patterns, each with a trailing dot and with `*` only as its first label. At most one such line. It turns on the fetch of the policy file: see [config.md](config.md#the-mta-sts-policy-fetch).
- **Comment.** A line that starts with `#`.

`issuer` and `certname` lines count only when the config turns on the certificate logs ([config.md](config.md#certificates)).

More rules:

- A `DS` line is allowed only for the domain itself. It is compared at the parent zone.
- The A and AAAA lines of a nameserver host also check the glue that the parent zone gives for that host. Glue of a type that has no line is a difference. A host with no address line has no glue check.
- An NS line for a name under the domain declares a subzone: the names under it are then expected to be answered from that zone. An answer from a subzone that the file does not declare gives an alert.
- Each name outside the domain's own zone that an alias, an MX record, an SPF include or redirect, or a nameserver of an exact line points at is also checked: it must still exist.
- A line holds only printable ASCII and tabs. A file holds at most 4 MiB, and at most 10000 lines besides the `domain` line and the comments.

### Mail records

These TXT lines are read as mail policies, not only as text:

| Line at | Policy |
|---|---|
| a name whose line holds an SPF record | SPF |
| `_dmarc.<name>.` | DMARC |
| `<selector>._domainkey.<name>.` | DKIM |
| `_mta-sts.<name>.` | the MTA-STS record |

When such a record changes, the alert names the policy. When the record now permits more than the line, the alert says how, for example `p=none in place of p=reject`. Any change gives an alert, also one that permits nothing more. A TXT line with `||` gives the plain record alert, without words.

DKIM selectors cannot be listed from DNS, so `init` does not guess them. Add the line of each selector with `snapshot` (below).

## How to change the file

### `accept`

When an alert reports a change that you made, `accept` writes the line for you. It needs the id that `status` shows:

```sh
./osk-dns-watcher accept 42
```

It prints the change and the command that writes it:

```
/data/example.com.expect:4
- example.com. A 192.0.2.10
+ example.com. A 192.0.2.20
To write this change: osk-dns-watcher accept --config /data/config.json --write <code> 42
```

Run that command with `./` in front: `./osk-dns-watcher accept --config /data/config.json --write <code> 42`. The code covers this exact change, so if the alert or the file changes in between, `accept` refuses and you look again. It also refuses when the servers give different sets, and for the alerts in [alerts.md](alerts.md) whose "What to do" does not name it.

### `snapshot`

`snapshot` prints the lines of what the servers give now. It writes no file:

```sh
./osk-dns-watcher snapshot example.com. s1._domainkey.example.com. TXT
```

With only the domain, it prints the NS and DS lines and the address lines of the nameserver hosts inside the domain. Each set that it cannot take gets a line `# not written: <name> <type>: <reason>`, and the command then exits with 1. Copy the lines that you trust into the file.

### By hand

```sh
docker compose exec watcher vi example.com.expect
./osk-dns-watcher validate
```

The service reads the files every 5 seconds and takes a change within about 10 seconds. Each change sends a `CHANGED` notice with the removed (`- `) and the added (`+ `) lines to every channel. A file that is not valid is not used: the service keeps the last valid file, and when the file stays not valid for 30 seconds, it opens an alert.

To check a name every minute, list it in `fast` in the config ([config.md](config.md#domains)).

## Add a domain

`init` runs only once, so add a domain by hand. Write its file from what its servers give now; this asks for the same sets as `init`, and writes the file inside the container:

```sh
docker compose exec watcher sh -c 'osk-dns-watcher snapshot example.net. example.net. A example.net. AAAA example.net. MX example.net. TXT example.net. CAA www.example.net. A _dmarc.example.net. TXT _mta-sts.example.net. TXT _acme-challenge.example.net. TXT _acme-challenge.www.example.net. TXT "*.example.net." A > example.net.expect'
docker compose exec watcher vi example.net.expect
```

Read every line. Then add `{"name": "example.net.", "expect": "example.net.expect"}` to `domains` in the config, check it, and restart the service, which reads the config only when it starts:

```sh
docker compose exec watcher vi config.json
./osk-dns-watcher validate
docker compose restart watcher
```
