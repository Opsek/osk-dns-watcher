# The expectations file

Each domain has one file, for example `example.com.expect`, that says what its DNS must look like. The file is beside the config, in `/data` in the container. The service alerts when a server gives anything that the file does not allow.

Run the commands on this page in `osk-dns-watcher/deploy`. `./osk-dns-watcher` runs the program inside the running service, so the program looks for a file name such as `example.com.expect` in `/data`. With the image, use the long form that [The command in deploy](config.md#the-command-in-deploy) in config.md gives.

## The service trusts what you confirm

`init` asks the servers of your domain and writes what they give now. When you type `yes`, those answers become what the service expects. The domain may already be wrong at that moment, for example because someone else changed a record. Then the wrong state becomes the expected one, and no alert comes.

So read every line before you type `yes`. Do the same for every line that `accept` or `snapshot` gives you.

## What `init` asks and writes

`start.sh` runs `init`. `init` asks two questions:

```
Domains to watch, separated by spaces:
Slack incoming webhook URL (hidden):
```

Then `init` asks the servers and shows the lines that it would write for each domain. Under `Not watched, and why:`, it lists each set that it leaves out. Last, it asks `Trust these lines and write the setup to /data? Type yes:`. An answer other than `yes` writes nothing. Once the config exists, `init` asks nothing again.

For each domain, `init` writes these lines:

- The `domain` line.
- The NS set of the domain. When the parent zone and the domain's servers give two to four different sets, the line accepts each one, and `init` shows which server gave which set.
- The DS set at the parent zone.
- The A, AAAA, MX, TXT, and CAA sets of the domain itself.
- The A set of `www.<domain>`, or its CNAME when `www.<domain>` is an alias, and the TXT sets of `_dmarc.<domain>` and `_mta-sts.<domain>`.
- The TXT sets of `_acme-challenge.<domain>` and `_acme-challenge.www.<domain>`, but only when no record is there.
- The A set of `*.<domain>`, or `none` when no wildcard answers.
- The A and AAAA sets of each nameserver host inside the domain, when the NS line names at most eight such hosts. With these lines, the service compares the glue at the parent zone.
- The `mta-sts` line, when `_mta-sts.<domain>` holds an MTA-STS record and `init` can read the policy file.

A set gets a line only when every server answered and all servers agree. An empty set gets a `none` line. `init` does not ask a server at an address that this machine has no route to, and it says how many such addresses there are. The service does the same at every check. A file for `example.com.` can look like this:

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

If you get certificates through DNS challenges, remove the two `_acme-challenge` lines. Otherwise each certificate request gives an alert.

## Line forms

A line is `<name> <type> <what is expected>`. Every name ends with a dot. A line has no TTL and no class field, and the service does not compare TTLs. A file has one line for each name and type.

- **Exact records.** `example.com. A 192.0.2.10`: the set holds exactly these records, written as in a zone file.
- **Several records.** `mail.example.com. A 192.0.2.25 | 192.0.2.26`: `|` separates the records of one set.
- **Alternatives.** `example.com. NS ns1.example.net. | ns2.example.net. || ns1.example.org. | ns2.example.org.`: `||` separates sets that are each allowed. A line has at most 16 such sets.
- **None.** `example.com. DS none`: the set must not exist.
- **Address ranges.** `www.example.com. A in 192.0.2.0/24 198.51.100.0/24`: each address lies in one of the ranges. Only A and AAAA lines take this form. A range has no bits set after its length.
- **Name patterns.** `cdn.example.com. CNAME like *.cdn.example.net.`: each target matches a pattern. `*.<name>` matches any name under `<name>`, but not `<name>` itself. A plain name matches only itself. Only NS, CNAME, DNAME, and MX lines take this form.
- **No wildcard.** `*.example.com. A none`: no wildcard answers under `example.com.`. The service asks a random name under it every 5 minutes. For a name in the domain's own zone, it also asks at once when the zone serial moves. Only this form is a wildcard line. The service checks any other line with a `*` name at that literal name.
- **The domain.** `domain example.com.`: the file has this line once, before every other line that is not a comment.
- **Issuer.** `issuer letsencrypt.org`: a certificate authority, as CAA records name it, with no trailing dot. With at least one such line, a valid certificate from any other authority gives an alert.
- **Certificate name.** `certname *.example.com.`: a name that certificates may hold besides the names of your lines. It ends with a dot, lies at or under the domain, and has `*` only as its first label.
- **MTA-STS policy.** `mta-sts enforce 604800 mail.example.com. *.mail.example.net.`: the policy that the domain must serve. The line gives the mode, then `max_age` in seconds, then the mx patterns. The mode is `enforce`, `testing`, or `none`. `max_age` is 0 to 31557600. Each mx pattern ends with a dot and has `*` only as its first label. A file has at most one such line. The line turns on the fetch of the policy file, as [The MTA-STS policy fetch](config.md#the-mta-sts-policy-fetch) in config.md describes.
- **Comment.** A line that starts with `#`.

`issuer` and `certname` lines count only when the config turns on the certificate logs. See [Certificates](config.md#certificates) in config.md.

These rules also apply:

- A `DS` line is allowed only for the domain itself. The service compares it at the parent zone.
- The A and AAAA lines of a nameserver host also check the glue that the parent zone gives for that host. Glue of a type that has no line is a difference. A host with no address line has no glue check.
- An NS line for a name under the domain declares a subzone. The service then expects that subzone to answer for the names under it. An answer from a subzone that the file does not declare gives an alert.
- The service also checks the names outside the domain's own zone that exact lines point at. Each such name must still exist. A line points at a name through an alias, an MX record, an SPF include or redirect, or a nameserver.
- A line holds only printable ASCII and tabs. A file holds at most 4 MiB, and at most 10000 lines besides the `domain` line and the comments.

### Mail records

The service reads these TXT lines as mail policies, not only as text:

| Line at | Policy |
|---|---|
| a name whose line holds an SPF record | SPF |
| `_dmarc.<name>.` | DMARC |
| `<selector>._domainkey.<name>.` | DKIM |
| `_mta-sts.<name>.` | the MTA-STS record |

[Mail](alerts.md#mail) in alerts.md lists the alerts of these records. A TXT line with `||` gives the plain record alert instead, which does not name the policy or say how it is weaker.

DNS gives no list of DKIM selectors, so `init` does not guess them. Add the line of each selector with [`snapshot`](#snapshot).

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

Run that command with `./` in front: `./osk-dns-watcher accept --config /data/config.json --write <code> 42`. The code covers this exact change. If the alert or the file changes in between, `accept` refuses, and you must look at the change again. `accept` also refuses when the servers give different sets. It refuses too for each alert whose "What to do" in [alerts.md](alerts.md) does not name `accept`.

### `snapshot`

`snapshot` prints the lines of what the servers give now. It writes no file:

```sh
./osk-dns-watcher snapshot example.com. s1._domainkey.example.com. TXT
```

With only the domain, `snapshot` prints the NS and DS lines and the address lines of the nameserver hosts inside the domain. For each set that it cannot take, it prints a line `# not written: <name> <type>: <reason>`, and the command then exits with 1. Copy the lines that you trust into the file.

### By hand

```sh
docker compose exec watcher vi example.com.expect
./osk-dns-watcher validate
```

The service reads the files every 5 seconds and takes a change within about 10 seconds. Each change of a line sends a `CHANGED` notice to every channel. An edit that changes only comments or blank lines sends none. The notice shows the removed lines with `- ` and the added lines with `+ `. The service does not use a file that is not valid, and keeps the last valid file. When the file stays not valid for 30 seconds, the service opens an alert.

To check a name every minute, list it in `fast` in the config. See [Domains](config.md#domains) in config.md.

## Add a domain

`init` runs only once, so add a domain by hand. First write its file from what its servers give now. The first command below asks for the same sets as `init`, and writes the file inside the container:

```sh
docker compose exec watcher sh -c 'osk-dns-watcher snapshot example.net. example.net. A example.net. AAAA example.net. MX example.net. TXT example.net. CAA www.example.net. A _dmarc.example.net. TXT _mta-sts.example.net. TXT _acme-challenge.example.net. TXT _acme-challenge.www.example.net. TXT "*.example.net." A > example.net.expect'
docker compose exec watcher vi example.net.expect
```

Read every line. Then add `{"name": "example.net.", "expect": "example.net.expect"}` to `domains` in the config. Check the config, and restart the service, which reads the config only when it starts:

```sh
docker compose exec watcher vi config.json
./osk-dns-watcher validate
docker compose restart watcher
```
