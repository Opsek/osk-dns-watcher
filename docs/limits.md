# What it does not detect

osk-dns-watcher compares what the servers of your domains answer with your expectations file, and reads certificate logs when you turn that on. This page lists what it does not see: first what is not built yet, then the limits of what is built.

## Not built yet

**Registry data.** The registry (RDAP) is not read. A removed transfer lock, a new registrar, a domain in redemption or pending deletion, or an expiry date that comes near gives no alert. A deleted domain is seen only when the parent zone stops delegating it.

**DNSSEC validity.** The DS records at the parent zone are compared with your file, but signatures are not checked. An expired signature or a broken chain of trust gives no alert.

**Public resolvers.** The service asks the servers of your domain, not the public resolvers that your users ask. An answer that resolvers give and your servers do not, such as a poisoned cache, is not seen.

**An audit.** The service compares with your file; it does not judge whether the file is safe. It does not say that a domain lacks a registry lock, DNSSEC, a CAA record bound to your account, or a strict DMARC policy, nor that your SPF has `+all` or your MTA-STS mode is `testing`.

**Zone transfers.** The service asks for the sets of your file; it does not copy the zone. A change that is made and undone between two checks can be missed. When the change moves the zone serial, a low alert says that the zone changed, but not which record.

**Routes.** The routes to your nameservers and hosts are not watched. A route hijack is not seen.

**Grouping.** Each check that differs sends its own alert. One cause, such as replaced nameservers, sends one alert for each watched set that now differs.

## Setup and trust

- What you confirm at `init`, at `accept` and when you edit the file is trusted. If the domain is already wrong at that moment, the wrong state becomes the expected one.
- Only the sets that your file lists, and the names that those lines point at, are watched. `init` writes a fixed list of sets ([expectations.md](expectations.md#what-init-asks-and-writes)); add the others yourself.
- A server that lies while `init` runs gets its NS set into the line. `init` shows each set and which server gave it.
- When the parent zone gives no NS set, or the servers give more than four, `init` writes no NS line and warns. Until you add the line, a change of the nameservers gives only an update of the medium alert about the missing line.
- `init` writes the address lines of nameserver hosts inside the domain only when the NS line names at most eight of them. The glue of a host without an address line is not compared.
- `init` writes no CAA line for `www`, and no `issuer` or `certname` line.

## Timing

- The intervals were tested in a lab. A drill on a real test domain and a long run on real domains are not done yet.
- On the real internet, a provider that limits the rate of the frequent serial queries, anycast servers that differ for a moment, or odd EDNS answers can cause alerts of failing checks or of different answers that the lab never showed.
- A zone delegated below your domain has no serial check: a change there is seen only at the interval of its lines.
- Names outside the domain's own zone, and CAA policies of names below the domain, are checked every 5 minutes (and the latter at once when the serial moves).
- When nameservers and DS change together and the nameservers are put back before the next check of the parent zone, the DS alert stays high and is not raised to critical.
- `check --expect` shows a DS difference as high: only the service raises it to critical.

## Nameservers and answers

- A nameserver that gives no answer while another one answers gives no alert. The alert of a failing check opens only when no server answers.
- Nameserver addresses that this machine cannot reach are not checked. Docker's default network has no IPv6, so with it no IPv6 address of a nameserver is checked.
- A line with `in`, `like` or `||` trusts every answer that it allows. A nameserver that gives another allowed answer only now and then is not reported.
- The alert about nameservers that give different answers needs a steady split. A nameserver whose answers rotate hides a stale one beside it. Nameservers that each keep another allowed answer for some minutes can get this alert again and again; no line turns it off.
- TTLs are not compared.
- A removed NS or DS line ends its open alert with "as expected again", while the alert about the missing line opens.

## Dangling names

- A deleted name inside the domain's own zone that an alias or MX record points at is not seen, unless it has a line of its own.
- A name at a provider that answers for every name still exists when nobody owns it.
- A missing name whose zone answers "no data" and not "no such name" is not seen.
- A nameserver that answers "no such name" for a name that only has records of another type (against RFC 8020) gives a false alert.
- The `CHECK` end message does not show what the name answers now.
- A removed line that pointed at a missing name ends its alert with a `CHECK` message too.
- A server that signs "no such name" with two different zones in turn gives an update at each check.

## Wildcards

- A wildcard that holds no A or CNAME record, for example one with only AAAA, TXT or MX records, is not seen.
- Only a `*.<name>. A none` line starts a wildcard check. Any other line with a `*` name is checked at that literal name.

## CAA

- An alias is not followed to read the CAA set at its target; a certificate authority follows it. When an alias stands at a name that has no line, above a name of the file, the names below it take their CAA policy from the alias target, and only the move of the zone serial is seen.
- A CAA policy above the watched domain, at its TLD, reads as none.
- A CAA record at a name with a `_` label is compared as an ordinary set, not as a policy.
- A CAA line with more than 64 different grants in a class reads as no policy for that class: no CAA alert for it. A method list of more than 16 labels reads as "any method" for its grant.
- When your own CAA line holds an unusual value (a critical record with an unknown tag, or a repeated or faulty `accounturi` or `validationmethods`), a change to another unusual value of the same kind gives only the medium alert at that name, and none at a name below it.
- A tag that is `issue` with a blank or another odd character added counts as an unknown tag. No certificate authority is known that reads such a tag as `issue`.
- A wildcard CAA record (`*.name`) that permits more than the policy above it gives the CAA alert at each name of the file under it that does not exist.
- `accept` refuses an alert whose set holds a record with an odd tag, and no line can state such a set.

## Certificates

These hold when the config turns on the certificate logs.

- The name of each watched domain goes to the source, Cert Spotter of SSLMate, which then learns which domains you watch.
- A certificate from an authority that your file allows gives no alert, for example one that someone obtained by changing your DNS for a few minutes: the logs cannot tell it from your own renewal. Your defence is a CAA record bound to your account (`accounturi`, and `validationmethods`, RFC 8657) where your authority supports it, and the DNS alerts.
- An alert about a certificate from an authority that the file does not permit ends only when the certificate expires. Revocations are not read, and `accept` refuses this alert. After you move to a new authority, the old authority's valid certificates open this alert once; with `remind` set, it repeats.
- A wildcard certificate for a name one label above a watched domain is not seen.
- Certificates issued before the service started are all new to it: its first run lists every valid certificate, and what the file does not cover gives up to three alerts for each domain.
- The source sets the pace. Without a key, on 17 Nov 2026, it allowed 10 requests an hour and asked for one hour between reads, so a new certificate is seen about one hour after the source has it, plus the delay of the source behind the issuance, which is not measured. The limits with a key were not measured.
- The terms of the source said on 17 Nov 2026 that use without a key is for personal or evaluation purposes.
- A list longer than 9 pages is not read again from the start until the service starts again, so a fault of the source's position marker is not healed before that.
- A source that wrongly answers with an empty list right after a start ends the open certificate alerts until its next true answer. A source that lies in a form that looks right is believed. Only Cert Spotter's form of answer is read.
- A renewal after the source maps more CAA names to the authority sends one "changed again" message.
- A certificate check that waits behind two running ones can make `status` report checks that are late.

## Mail

- A change inside a record that an SPF include or redirect names is not seen: the record of the line is compared, not the records that it points at. Watch such a record with a line of its own.
- The limit of 10 DNS lookups of an SPF record counts the terms of that record only, not those of the records that its includes name.
- A name that an SPF macro builds is not checked.
- An SPF record that appears where the file has `TXT none`, or a TXT line that holds no SPF record, gives the alert with no words.
- A TXT line with `||` gives the plain alert, with no words.
- A DKIM key added at a selector that no line names is not seen: selectors cannot be listed from DNS.
- The size of a DKIM key is not judged. A DKIM record that does not follow the strict form (the `v` tag not first, an odd tag) does not count as a key, though a lenient verifier may use it.
- Which DMARC record governs a subdomain that has none of its own is not worked out: add the line of the record that governs it. Any change of a DMARC `psd` tag counts as weaker.
- A mail record that a provider hosts through a CNAME is watched as a CNAME: a change of the target gives an alert, but the record behind it is not read. When `_mta-sts.<domain>` is a CNAME, `init` and `snapshot` write no `mta-sts` line, so no policy file is fetched.
- A mail record rewritten with the same policy (other string breaks or spaces) still gives an alert: accept the new text.
- In the MTA-STS policy file, a key given twice with other values: the first counts, as the standard says, and a sender that keeps the last one reads another policy. The media type of the file is not checked.
- A policy fetch that fails gives no alert about the policy, only the alert of a failing check after 15 minutes. A host that fails two fetches in three never reaches that limit.
- Each fetch sends one request, so a host can tell the service from a mail server and serve it another policy.
- On an IPv6-only machine whose DNS64 uses its own prefix, the address check of the policy fetch sees a public IPv6 address and cannot see the IPv4 address behind it, which may be private. The harm is a TLS connection attempt to that address. Do not add the NAT64 prefix (such as `64:ff9b::/96`) to `network.extra_ranges`: that permits every IPv4 address it holds.

## Alerts and delivery

- The service cannot report its own crash. Docker starts it again, and the next start sends a `DOWN` notice when it was down for a minute or more. A crash loop shorter than the limit of a failing check gives no alert, and Docker does not restart a container that is only unhealthy. Set a `heartbeat` ([config.md](config.md#heartbeat)) to an outside service that alerts when the beats stop.
- After a restart, the count toward the alert of a failing check starts again.
- A stop that cuts a send whose answer never came lets the next start send that message again. A webhook gets the same `id`.
- When you raise a channel's `min_severity` above the highest severity of an open alert, that channel misses the end of the alert.
- A message is given up after 30 failed attempts, about 21 hours, and at once on a 3xx or 4xx status other than 408 and 429.
- A changed expectations file that is not valid counts only after 30 seconds; until then, and after, the last valid file is used.

## Install and update

- Your config, expectations and history live in a Docker volume, not in a folder under version control. Copy them out ([install.md](install.md#your-files)).
- The Docker log of the service has no size limit unless the Docker daemon sets one.
- An update needs the network: git fetches the tags, and the build pulls the base images.
- The image holds Alpine and its CA certificates as of the release, and the program holds the SQLite of the release. A fix there needs a new release. The vulnerability scan of the release covers Go code only, not SQLite's own C code.
- The first release has one signing key. If the owner loses it, installed copies cannot verify a later release ([install.md](install.md#keys)).
- Old Compose versions without `up --wait`, Windows with WSL 2, rootless Docker and Podman are not tested.
- The service sends many small queries to each nameserver address. How providers treat this load is not measured.
