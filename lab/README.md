# The DNS lab

The lab is a small, closed copy of the DNS that runs in Docker on your
machine: a root, a parent zone `test.`, two authoritative nameservers, two
resolvers and a webhook receiver. It uses real DNS software (BIND and
Unbound). It is made for tests that change zones, delegations and answers the
way an attacker or a careless operator would.

The lab network is internal: no port is published on the host, and no
container reaches the internet.

## Start, stop, reset

From the root of the repository:

```sh
lab/bin/lab up       # build the image if needed, start the lab, wait until every server answers
lab/bin/lab status   # print each host and whether it answers; exit 0 only if all do
lab/bin/lab reset    # put the lab back into its base state, without a restart
lab/bin/lab down     # stop the lab and remove its containers, network and volume
```

`make lab-up` and `make lab-down` do the same as `up` and `down`. The settings
`DOCKER` and `BUILD_FLAGS` work as for `make check` (see
[docs/development.md](../docs/development.md)).

`lab/bin/lab run <command...>` runs a command in the runner container and
exits with its exit code:

```sh
$ lab/bin/lab run dig +short @10.53.0.11 www.corp.test. A
10.53.0.81
```

The runner sees the repository read-only at `/src`. Its `/tmp` is writable.

## Hosts

`N` is the lab number, `LAB_ID` (default 0).

| Host | Address | Role |
|---|---|---|
| root | 10.53.N.2 | The root zone `.`. Delegates `test.` to tld. |
| tld | 10.53.N.3 | The zone `test.`, parent of every test domain. |
| ns1 | 10.53.N.11 | The zones `corp.test.`, `dnshost.test.` and `shop.test.`. |
| ns2 | 10.53.N.12 | The same zones, as its own copy: there is no zone transfer between ns1 and ns2, so they can differ. |
| resolver | 10.53.N.20 | Recursive resolver that starts at the lab root. It does not validate DNSSEC. |
| liar | 10.53.N.21 | Like resolver, but `labctl lie` makes it give false answers. |
| receiver | 10.53.N.30 | HTTPS webhook receiver for `hooks.lab.test`. It stores every request. Containers on the lab network find `hooks.lab.test` through Docker's DNS. |
| mta-sts.corp.test | 10.53.N.30 | The policy host of `corp.test.`: the receiver again, under a second name. See [The MTA-STS policy host](#the-mta-sts-policy-host). |
| runner | 10.53.N.100 | Runs tests and `labctl`. It has `dig`, `delv`, `nsupdate`, `dnssec-keygen`, `dnssec-signzone` and `curl`. |

No host uses 10.53.N.99: delegate to it to get a server that does not answer.

In the runner, `/lab/ca.pem` is the lab CA, which the runner trusts. The
folder `/lab/ca/` holds only a copy of it, `ca.pem`, for a container that must
trust the lab CA and nothing else. `/lab/xfr.key` is the TSIG key that zone
transfers need (`dig -k /lab/xfr.key @10.53.0.11 corp.test. AXFR`).

The base zones are in `lab/image/zones/`, where `@N@` stands for the lab
number. Every zone starts with serial 1, and there is no DS record.

## labctl

`labctl` changes the lab. It runs in the runner:

```sh
lab/bin/lab run labctl serial ns1 corp.test.
```

Every change is served before `labctl` returns. Every name ends with a dot.
Each `<rdata>` is one record in zone-file form, so TXT and CAA data keep their
quotes: `'"v=spf1 mx -all"'`. `<server>` is `ns1`, `ns2` or `both`. Exit codes:
0 done, 1 the lab refused the change, 2 wrong use.

The examples are for lab 0 and run in the runner.

| Command | Example | Does |
|---|---|---|
| `set <server> <name> <ttl> <type> <rdata>...` | `labctl set both www.corp.test. 300 A 10.53.0.66` | Replaces the record set and adds 1 to the zone serial. |
| `del <server> <name> <type>` | `labctl del ns2 www.corp.test. A` | Removes the record set and adds 1 to the serial. |
| `serial ns1\|ns2 <zone>` | `labctl serial ns1 corp.test.` | Prints the serial of the zone. |
| `delegate <zone> <ns-name>...` | `labctl delegate corp.test. ns1.dnshost.test. ns2.dnshost.test.` | Replaces the NS set of the delegation in `test.`. |
| `glue <ns-name> [<address>...]` | `labctl glue ns1.corp.test. 10.53.0.99` | Replaces the glue of the name in `test.`; no address removes it. |
| `ds <zone> <ds-rdata>...\|none` | `labctl ds corp.test. none` | Replaces or removes the DS set in `test.`. |
| `undelegate <zone>` | `labctl undelegate shop.test.` | Removes the delegation and its glue, so `test.` answers "no such name". |
| `load-zone <server>\|root\|tld <zone> <file>` | `labctl load-zone ns1 corp.test. /tmp/corp.zone.signed` | Serves the zone file as it is, with its serial and signatures. `set` and `del` are refused on a zone loaded this way (exit 1). |
| `drop-zone <server>\|root\|tld <zone>` | `labctl drop-zone ns2 shop.test.` | Removes the zone; the server then answers REFUSED for it. |
| `lie <name> <type> <rdata>...` | `labctl lie www.corp.test. A 192.0.2.1` | Makes liar give this answer. |
| `lie clear` | `labctl lie clear` | Removes every false answer. |
| `hooks list` | `labctl hooks list` | Prints the stored requests as JSON lines: `time`, `method`, `path`, `headers`, `body`, `status`. |
| `hooks clear` | `labctl hooks clear` | Deletes the stored requests. |
| `hooks fail <status> <count>` | `labctl hooks fail 503 2` | Answers the next `<count>` requests with this status. |
| `hooks reply <status> <count> [--header '<Name>: <value>']... [--delay <seconds>] [--body <text>]` | `labctl hooks reply 429 1 --header 'Retry-After: 30' --body 'slow down'` | Answers the next `<count>` requests like this. |
| `certs set` | `labctl certs set < issuances.json` | Replaces the set that stands in for a certificate source; the JSON array comes on standard input. `GET https://hooks.lab.test/v1/issuances?domain=<name>&after=<id>` answers with the issuances of the set that name the domain or a name below it, at most 2 in a page, in id order; none left gives `[]` with `Retry-After: 1`. These requests are not listed by `hooks list`. |
| `certs fail <status> <count> [<retry>]` | `labctl certs fail 429 1 30` | Answers the next `<count>` lookups with this status and, when `<retry>` is above 0, `Retry-After: <retry>`. |
| `certs count` | `labctl certs count` | Prints the number of lookups that the source got since the last `certs clear` (or lab reset), failed ones included. |
| `certs clear` | `labctl certs clear` | Empties the set and the failures, and sets the lookup count to 0. |
| `policy <host> <status> [<body>]` | `labctl policy mta-sts.corp.test. 200 "$(printf 'version: STSv1\nmode: enforce\nmx: mail.corp.test\nmax_age: 604800\n')"` | Sets the status and body that the policy host serves for `<host>`, which replaces what was set for it. The body is one argument and keeps its line feeds; without it the body is empty. The status is 200 to 599. |
| `policy clear` | `labctl policy clear` | Removes every policy, so that every host answers 404. |
| `reset` | `labctl reset` | Puts the lab back into its base state, which includes `policy clear`; `lab/bin/lab reset` runs it. |
| `status` | `labctl status` | Prints each host and whether it answers; `lab/bin/lab status` runs it. |

A DS record is one argument: `labctl ds corp.test. '11111 13 2 <64 hex digits>'`.

`load-zone` reads a file in the runner. This makes a signed copy of
`corp.test.` and serves it on ns1:

```sh
lab/bin/lab run sh -c 'cd /tmp &&
  sed "s/@N@/$LAB_ID/g" /src/lab/image/zones/db.corp.test > corp.zone &&
  dnssec-keygen -q -a ECDSAP256SHA256 -f KSK corp.test. &&
  dnssec-keygen -q -a ECDSAP256SHA256 corp.test. &&
  dnssec-signzone -q -S -o corp.test. -f corp.zone.signed corp.zone &&
  labctl load-zone ns1 corp.test. /tmp/corp.zone.signed'
```

The receiver answers any request with status 200 unless `hooks fail` or
`hooks reply` says otherwise:

```sh
$ lab/bin/lab run curl -s -o /dev/null -w '%{http_code}\n' --data hello https://hooks.lab.test/alert
200
```

## The MTA-STS policy host

The receiver also serves the policy file of `corp.test.` for a client that
checks MTA-STS:

- Name and address: `mta-sts.corp.test`, 10.53.N.30. The runner finds it
  through its hosts file, and other containers on the lab network through the
  Docker alias of the receiver. The lab zones hold no record for it, so a
  query to the lab resolvers for this name gets no answer.
- Certificate: the lab CA signs it; it is the certificate of the receiver,
  which names both `hooks.lab.test` and `mta-sts.corp.test`. The runner trusts
  the CA. A lab made before this name was added keeps its old certificate until
  `lab/bin/lab down`.
- Path: only a GET of `/.well-known/mta-sts.txt` returns a policy. It answers
  with the status and body that `labctl policy` set for the host of the
  request (lowercase, without port or final dot), and with 404 and an empty
  body when none is set. It sends no redirect of its own, but `labctl policy
  <host> 302` makes it answer 302.
- These requests are not stored: `labctl hooks list` shows none of them.

```sh
$ lab/bin/lab run labctl policy mta-sts.corp.test. 200 'version: STSv1'
$ lab/bin/lab run curl -s https://mta-sts.corp.test/.well-known/mta-sts.txt
version: STSv1
$ lab/bin/lab run labctl policy mta-sts.corp.test. 404     # break the policy
$ lab/bin/lab run labctl policy clear                      # no policy at all
```

The base zones have no `_mta-sts` record; add one with `labctl set`, for
example `labctl set both _mta-sts.corp.test. 300 TXT '"v=STSv1; id=1"'`.

## Acceptance checks

The checks of the lab itself. `run.sh` runs in the runner of a started lab
and leaves the lab in its base state; `host.sh` runs on the host and starts
and stops two labs of its own (`HOST_LAB_A` and `HOST_LAB_B`, default 8 and
9, which must not be in use):

```sh
lab/bin/lab up && lab/bin/lab run /src/lab/accept/run.sh; lab/bin/lab down
lab/accept/host.sh
```

`policy-served` sets a policy, fetches it over HTTPS with the lab CA, checks
that the certificate names the host and that `hooks list` stays empty;
`policy-reset` checks that `labctl reset` leaves the host answering 404.

Each prints `ok <name>` or `FAIL <name>: <reason>` for each check and exits
with 0 only if all passed. `make check` runs both.

## Several labs at once

Each lab has its own number, `LAB_ID`, from 0 to 9. Lab `N` is the Compose
project `osklabN` on the subnet 10.53.N.0/24, and every container, network
and volume of it carries the label `osk.lab=N`. Labs with different numbers
run at the same time and cannot reach each other:

```sh
LAB_ID=3 lab/bin/lab up
LAB_ID=3 lab/bin/lab run dig +short @10.53.3.11 www.corp.test. A
LAB_ID=3 lab/bin/lab down
```
