# What it does not detect

osk-dns-watcher compares what the servers of your domains answer with your expectations file. It also reads the certificate logs if you turn them on.

## Not built yet

**Registry data.** The registry (RDAP) is not read. A removed transfer lock, a new registrar, a domain in redemption or pending deletion, or an expiry date that comes near gives no alert. A deleted domain is seen only when the parent zone no longer delegates it.

**DNSSEC validity.** The DS records at the parent zone are compared with your file, but signatures are not checked. An expired signature or a broken chain of trust gives no alert.

**Public resolvers.** The service asks the servers of your domain, not the public resolvers that your users ask. An answer that public resolvers give and your servers do not, such as one from a poisoned cache, is not seen.

**An audit.** The service compares answers with your file. It does not judge whether the file is safe. It does not say that a domain lacks a registry lock, DNSSEC, a CAA record bound to your account, or a strict DMARC policy. Nor does it say that your SPF record has `+all` or that your MTA-STS mode is `testing`.

**Zone transfers.** The service asks for the sets that your file lists. It does not copy the zone. A change that is made and undone between two checks can be missed. When the change moves the zone serial, a low alert says that the zone changed, but not which record. While an alert of a watched record of the zone is open, the low alert waits for the next check of that record. That can take one interval of the check. It does not come when the new serial equals one that was reported before, for example when a zone is restored with its old serial.

**Routes.** The routes to your nameservers and hosts are not watched. A route hijack is not seen.

**Grouping.** Each check that finds a difference sends its own alert. One cause, such as replaced nameservers, sends one alert for each watched set that now differs.

## Setup and trust

- The service trusts what you confirm at `init`, at `accept`, and when you edit the file. If the domain is already wrong at that moment, the wrong state becomes the expected one.
- The service watches only the sets that your file lists and the names that its lines point at. `init` writes a [fixed list of sets](expectations.md#what-init-asks-and-writes). Add the others yourself.
- A server that lies while `init` runs gets its NS set into the NS line. `init` shows each set and which server gave it.
- When the parent zone gives no NS set, or the servers give more than four different NS sets, `init` writes no NS line and warns. Until you add the line, a change of the nameservers gives only an update of the medium alert about the missing line.
- `init` writes the address lines of nameserver hosts inside the domain only when the NS line names at most eight of them. The glue of a host without an address line is not compared.
- `init` writes no CAA line for `www`, and no `issuer` or `certname` line.

## Timing

- The intervals were tested in a lab. They were also measured on one real domain at one DNS provider: an alert came 2 to 20 seconds after the provider took a change, an edit of the expectations file took effect in 6 to 10 seconds, and an alert ended 5 to 18 seconds after the record was put back, or at the next run of its check. A long run on real domains is not done yet.
- On the real internet, a provider can limit the rate of the frequent serial queries, anycast servers can differ for a moment, and EDNS answers can be odd. Each can cause alerts of failing checks or of different answers that the lab never showed.
- A zone delegated below your domain has no serial check. A change there is seen only at the interval of its lines.
- Names outside the domain's own zone and the CAA policies of names below the domain are checked every 5 minutes. The CAA policies are also checked at once when the serial moves.
- Sometimes the nameservers and the DS change together, and the nameservers are put back before the next check of the parent zone. In that case, the DS alert stays high and is not raised to critical.
- `check --expect` shows a DS difference as high. Only the service raises it to critical.

## Nameservers and answers

- Some DNS providers have many machines behind one nameserver address. For up to about a minute after a change, some of them still give the old answer. While one of them does, the alert stays open. The `RESOLVED` message can then wait for the next run of the check: 1 minute for the fast tier, 5 minutes for the others. It does not come 15 seconds after the change.
- One more server that gives a value that the alert already shows sends no `changed again` message. Only a new value, a new severity, or a new expected line does. The `seen at` list of a later message names the servers of the first message or of the last update.
- A new subzone whose nameservers do not answer gives no zone alert, only the alert of a failing check after its limit.
- A nameserver that gives no answer while another one answers gives no alert. The alert of a failing check opens only when no nameserver answers. Such a check does not count as OK. The `last OK` time of an alert comes from an earlier check.
- The service does not ask a nameserver address that this machine has no route to. A check counts as OK when the other nameservers answer. Docker's default network has no IPv6, so on that network the service asks no IPv6 address of a nameserver. A nameserver that gives false answers only over IPv6 is then not seen.
- The log says once that this machine has no route to some nameserver addresses, and once that the route is back. `doctor` shows a warning. `status` does not show it.
- A line with `in`, `like`, or `||` trusts every answer that it allows. A nameserver that gives another allowed answer only at times is not reported.
- The alert about nameservers that give different answers needs a steady split. A nameserver whose answers rotate hides a stale one beside it. Nameservers that each keep another allowed answer for some minutes can cause this alert again and again. No line turns it off.
- TTLs are not compared.
- A removed NS or DS line ends its open alert with a `RESOLVED` message that says "as expected again", and the alert about the missing line opens. The `delegation` and `ds` checks stay, so no `CHANGED` line closes that alert.

## Dangling names

- An alias or MX record can point at a deleted name inside the domain's own zone. The deletion is seen only when that name has a line of its own.
- A name at a provider that answers for every name still exists when nobody owns it.
- A missing name whose zone answers "no data" and not "no such name" is not seen.
- A nameserver that answers "no such name" for a name that has only records of another type gives a false alert. Such an answer breaks RFC 8020.
- The `CHECK` end message does not show what the name answers now.
- A removed line that pointed at a missing name ends its alert inside the `CHANGED` message, which lists it with a line that starts with `closed `. No `RESOLVED` and no `CHECK` message comes, and a webhook gets no `resolve` event. See [How an alert ends](alerts.md#how-an-alert-ends).
- A nameserver that alternates between two zones when it signs "no such name" gives an update at each check.

## Wildcards

- A wildcard that holds no A or CNAME record, for example one with only AAAA, TXT, or MX records, is not seen.
- Only a `*.<name>. A none` line starts a wildcard check. Any other line with a `*` name is checked at that literal name.

## CAA

- The service does not follow an alias to read the CAA set at its target, but a certificate authority does.
- An alias can stand at a name that has no line, above a name in the file. The names below that alias then take their CAA policy from the alias target. The service sees only that the zone serial moved.
- A CAA policy above the watched domain, at its TLD, reads as none.
- A CAA record at a name with a `_` label is compared as an ordinary set, not as a policy.
- A CAA line with more than 64 different grants in a class reads as no policy for that class. That class then gives no CAA alert. A method list of more than 16 labels reads as "any method" for its grant.
- Your own CAA line can hold an unusual value: a critical record with an unknown tag, or a repeated or faulty `accounturi` or `validationmethods`. A change to another unusual value of the same kind then gives only the medium alert at that name, and no alert at a name below it.
- A tag that is `issue` with a blank or another odd character added counts as an unknown tag. No known certificate authority reads such a tag as `issue`.
- A wildcard CAA record at `*.name` can permit more than the policy above it. Such a record gives the CAA alert at each name under it that the file lists and that does not exist.
- `accept` refuses an alert whose set holds a record with an odd tag. No line can state such a set.

## Certificates

These limits hold when the config turns on the certificate logs.

- The service sends the name of each watched domain to the source, Cert Spotter of SSLMate. The source then learns which domains you watch.
- A certificate from an authority that your file allows gives no alert. Someone can get such a certificate by changing your DNS for a few minutes. The logs cannot tell it from your own renewal. Your defences are the DNS alerts and, where your authority supports it, a CAA record bound to your account. The binding uses `accounturi` and `validationmethods` from RFC 8657.
- An alert about a certificate from an authority that the file does not allow ends only when the certificate expires. Revocations are not read. `accept` refuses this alert. After you move to a new authority, the old authority's valid certificates open this alert once. With `remind` set, it repeats.
- A wildcard certificate for a name one label above a watched domain is not seen.
- Certificates issued before the service started are all new to it. Its first run lists every valid certificate. The certificates that the file does not cover give up to three alerts for each domain.
- The source sets the pace. On 17 Nov 2026, without a key, it allowed 10 requests an hour and asked for one hour between reads. As a result, the service sees a new certificate about one hour after the source has it. The delay of the source behind the issuance adds to that hour and is not measured. The limits with a key were not measured.
- The terms of the source said on 17 Nov 2026 that use without a key is for personal or evaluation purposes.
- The service does not read a list longer than 9 pages from the start again until it restarts. Until then, a fault of the source's position marker stays.
- A source that wrongly answers with an empty list right after the service starts ends the open certificate alerts until its next true answer. A source that lies in a form that looks right is believed. Only Cert Spotter's form of answer is read.
- A renewal after the source maps more CAA names to the authority sends one "changed again" message.
- A certificate check that waits behind two running checks can make `status` report late checks.

## Mail

- A change inside a record that an SPF include or redirect names is not seen. The record of the line is compared, not the records that it points at. Watch such a record with a line of its own.
- The limit of 10 DNS lookups of an SPF record counts only the terms of that record, not those of the records that its includes name.
- A name that an SPF macro builds is not checked.
- Three cases give the plain alert, with no `weaker` lines: an SPF record that appears where the file has `TXT none`, a TXT line that holds no SPF record, and a TXT line with `||`.
- A DKIM key added at a selector that no line names is not seen. Selectors cannot be listed from DNS.
- The size of a DKIM key is not judged. A DKIM record that does not follow the strict form does not count as a key, though a lenient verifier may use it. For example, its `v` tag is not first, or it has an odd tag.
- The service does not work out which DMARC record governs a subdomain that has no record of its own. Add the line of the record that governs it. Any change of a DMARC `psd` tag counts as weaker.
- A mail record that a provider hosts through a CNAME is watched as a CNAME. A change of the target gives an alert, but the record behind it is not read. When `_mta-sts.<domain>` is a CNAME, `init` and `snapshot` write no `mta-sts` line, so no policy file is fetched.
- A mail record rewritten with the same policy, but with other string breaks or spaces, still gives an alert. Accept the new text.
- In the MTA-STS policy file, a key can appear twice with other values. The first value counts, as the standard says. A sender that keeps the last value reads another policy. The media type of the file is not checked.
- A policy fetch that fails gives no alert about the policy, only the alert of a failing check after 15 minutes. A host that fails two fetches in three never reaches that limit.
- Each fetch sends one request, so a host can tell the service from a mail server and serve it another policy.
- On an IPv6-only machine, DNS64 can use its own prefix. The address check of the policy fetch then sees a public IPv6 address and not the IPv4 address behind it. That IPv4 address may be private, and the harm is a TLS connection attempt to it. Do not add the NAT64 prefix, such as `64:ff9b::/96`, to `network.extra_ranges`. That entry would permit every IPv4 address in the prefix.

## Alerts and delivery

- The service cannot report its own crash. Docker starts it again. If the service was down for a minute or more, the next start sends a `DOWN` notice. A crash loop shorter than the limit of a failing check gives no alert. Docker does not restart a container that is only unhealthy. Set a [`heartbeat`](config.md#heartbeat) to an outside service that alerts when the beats stop.
- After a restart, the count toward the alert of a failing check starts again.
- If the service stops after it sends a message and before the answer comes, the next start sends that message again. A webhook gets the same `id`.
- Slack shows a bounded view. A `CHANGED` message shows 12 lines and then `and N more lines`. A record set shows 6 records and then `and N more records`. A long line ends with ` [cut]`. A webhook body holds up to 200 lines of a `CHANGED` notice and the `value` of an alert, as [Webhooks](config.md#webhooks) describes. `check` shows what the servers give now.
- When you raise a channel's `min_severity` above the highest severity of an open alert, that channel misses the end of the alert.
- The service gives up a message after 30 failed attempts, which take about 21 hours. It gives up at once on a 3xx or 4xx status other than 408 and 429.
- After a give-up, the channel counts as failing, also when no message is pending. `status` exits with 1, and the heartbeat stops. This holds until the service delivers the next message to that channel. After you fix the cause, run `osk-dns-watcher test-alert` to prove the channel.
- A changed expectations file that is not valid opens an alert only when it stays not valid for 30 seconds. Until then, and after, the service uses the last valid file.

## Install and update

- Your config, expectations, and history live in a Docker volume, not in a folder under version control. Copy them out. [Your files](install.md#your-files) shows how.
- The Docker log of the service has no size limit unless the Docker daemon sets one.
- An update needs the network. Git fetches the tags, and the build pulls the base images.
- The image holds Alpine and its CA certificates as of the release. The program holds the SQLite of the release. A fix in any of them needs a new release. The vulnerability scan of the release covers only Go code, not SQLite's own C code.
- The first release has one signing key. If the owner loses it, installed copies cannot verify a later release, as [Keys](install.md#keys) explains.
- Old Compose versions without `up --wait`, Windows with WSL 2, rootless Docker, and Podman are not tested.
- The service sends many small queries to each nameserver address. How providers treat that load is not measured.
