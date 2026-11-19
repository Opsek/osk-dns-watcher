# Alerts

Every alert that the service can send, as Slack shows its headline, what it means and what to do. The names in the headlines are examples. The commands, such as `accept` and `validate`, run as `./osk-dns-watcher accept <alert id>` in `osk-dns-watcher/deploy` ([config.md](config.md#the-command-in-deploy)).

## How an alert looks

A message has four parts: the headline; a block with what the file expects (`expected`), what the servers give (`now`) and which server gave it (`seen at`); the times; and what to do. The [README](../README.md) shows one.

The headline starts with an emoji and the severity:

| Start of the headline | Severity |
|---|---|
| `:rotating_light: *CRITICAL*` | critical |
| `:red_circle: *HIGH*` | high |
| `:large_orange_circle: *MEDIUM*` | medium |
| `:large_yellow_circle: *LOW*` | low |

Later messages of the same alert add a few words after the severity: `, changed again` when the servers show something new, `, raised from <severity>` when the severity goes up, and `, still open` for a reminder (only when `remind` is set in the config). The last message starts with `:white_check_mark: *RESOLVED*`, or with `:warning: *CHECK*` (see [How an alert ends](#how-an-alert-ends)).

A channel gets the messages of an alert when the highest severity of the alert reaches the channel's `min_severity`. A webhook gets the same text in signed JSON: see [config.md](config.md#webhooks).

## How fast a change is seen

At the default intervals, plus the time to ask:

| What changes | Seen within |
|---|---|
| Nameservers, glue, DS and the domain itself, at the parent zone | 1 min |
| The A, AAAA, MX and CAA sets of the domain itself, `_acme-challenge` names, and names listed in `fast` | 1 min |
| Every other line, wildcards, the MTA-STS policy file, and the CAA policy of names below the domain | 5 min |
| Names that your lines point at, outside the domain's own zone | 5 min |
| A change inside the domain's own zone that moves the zone serial | about 15 s |
| Nameservers that give different answers | 10 to 50 min |
| A check with no usable answer | 5 to 15 min; 30 min for the certificate source |
| Certificates in the public logs | about 1 h after the source has them |

These times were tested in a lab. A drill on a real test domain and a long run on real domains are not done yet.

## Delegation and nameservers

| Headline | What it means | What to do |
|---|---|---|
| **CRITICAL** · nameservers of `example.com.` changed at the parent zone | The parent zone delegates your domain to nameservers that the NS line does not allow. | If you did not change them, contact your registrar now. If you did, run `accept`. |
| **CRITICAL** · nameserver addresses of `example.com.` changed at the parent zone | The glue address that the parent zone gives for one of your nameserver hosts differs from its address line. | If you did not change it, contact your registrar now. If you did, edit the address line. |
| **HIGH** · DS of `example.com.` changed at the parent zone | The DS set at the parent zone differs from the DS line, or is gone. It is raised to **CRITICAL** when the nameservers alert of the domain is open, and stays so. | If you did not change your DNSSEC keys, contact your registrar now. If you did, run `accept`. |
| **CRITICAL** · `example.com.` does not exist at the parent zone | The parent zone says that the domain does not exist. | Contact your registrar now: the registration may have expired, been deleted or been transferred. |
| **MEDIUM** · `example.com. NS` has no expectation and is not checked | The file has no NS line, or no DS line, so that set cannot be judged. | Run `accept` to add the line. |
| **HIGH** · `shop.example.com.` is answered from an unexpected zone | A name of the file is answered from another zone than the file declares, for example a new subzone. | If you did not create this zone, check the delegations under your domain at your DNS provider. If you did, add its NS line by hand. |
| **MEDIUM** · the nameservers of `example.com.` give different answers for `www.example.com. A` | Each nameserver has given its own answer, steadily, for 10 to 50 minutes; the file allows each one. | Find out why one nameserver answers otherwise: it may be out of date, or not yours. |

## Records

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · `www.example.com. A` changed | A server gives a set that the line does not allow. **HIGH** for A, AAAA, CNAME, MX and NS; **MEDIUM** for the other types. | If you did not make this change, check your DNS provider account now. If you did, run `accept`. |
| **MEDIUM** · a wildcard answers for names under `example.com.` that do not exist | A random name under `example.com.` gets an answer, and the file says `*.example.com. A none`. | If you did not add a wildcard, remove it at your DNS provider and find out who added it. If you did, write its lines by hand. |

## Dangling names

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · `old.example.net.` does not exist, and an alias in `example.com.` points at it | A CNAME or DNAME of the file points at a name that does not exist. Whoever creates it receives its traffic. | Change or remove the alias now. |
| **CRITICAL** · nameserver `ns2.example.net.` of `example.com.` does not exist | The NS line names a host that does not exist. Whoever creates it can answer for your domain. | Replace it at your registrar now, or restore it. |
| **HIGH** · `mx.example.net.` does not exist, and the mail records of `example.com.` point at it | An MX record, or an SPF include or redirect, names a name that does not exist. Whoever creates it can receive or send mail as your domain. | Change the MX or SPF record now. |

Only names outside the domain's own zone are checked, every 5 minutes.

## Mail

Each mail record has two headlines, both **MEDIUM**: one for any change, and one when the record now permits more than the line.

| Record | Any change | When it permits more |
|---|---|---|
| SPF | the SPF record at `example.com.` changed | the SPF record at `example.com.` lets more senders pass than the file |
| DMARC | the DMARC record `_dmarc.example.com.` changed | the DMARC record `_dmarc.example.com.` asks receivers to do less than the file |
| DKIM | the DKIM key `s1._domainkey.example.com.` changed | the DKIM key `s1._domainkey.example.com.` lets another key sign mail |
| MTA-STS record | MTA-STS at `_mta-sts.example.com.` changed | MTA-STS at `_mta-sts.example.com.` protects less than the file |
| MTA-STS policy file | MTA-STS at `mta-sts.example.com.` changed | MTA-STS at `mta-sts.example.com.` protects less than the file |

In the second form, `weaker` lines say how, for example `p=none in place of p=reject` or `mode testing in place of enforce: senders deliver mail even when the TLS check fails`. A policy file that cannot be read counts as a change: senders act as if there were no policy.

What to do: if you did not make the change, restore the record, or the policy file, now. If you did, run `accept`.

## Certificates and CAA

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · a certificate-challenge record appeared at `_acme-challenge.example.com. TXT` | A record or an alias stands at a challenge name where the file says `none`. It lets whoever controls it get a certificate for the name. | If you did not ask for a certificate for this name, find out who changed your DNS, and look for the certificate in the certificate logs. |
| **HIGH** · the CAA policy for `example.com.` is weaker than expected | The CAA records that apply to this name permit more than the file: another authority, any account or validation method, wildcards, or no policy at all. A CAA change that permits nothing more gives the plain `changed` alert (**MEDIUM**). | If you did not change them, restore them now, then look for certificates that you did not ask for. If you did, run `accept`. |
| **HIGH** · a certificate for a name of `example.com.` comes from an authority that the expectations do not permit | A valid certificate in the public logs comes from an authority that the CAA lines or the `issuer` lines do not permit. | If you did not ask for it, ask its authority to revoke it, and check your CAA records and your DNS provider account. If you did, allow the authority in those lines by hand. |
| **HIGH** · a wildcard certificate for `example.com.` holds a name that the expectations do not list | A valid wildcard certificate holds a name that no `certname` line lists. | If you did not ask for it, ask its authority to revoke it. If it is yours, run `accept`. |
| **LOW** · certificates name hosts under `example.com.` that the expectations do not list | Valid certificates name hosts that no line lists. One alert holds the list. | Check that each host is yours. Run `accept` to list them, or add a line for each host that the service should watch. |

The last three come only when the config turns on the certificate logs ([config.md](config.md#certificates)).

## The watch itself

| Headline | What it means | What to do |
|---|---|---|
| **MEDIUM** · the records check of `www.example.com. A` has had no usable answer for too long | No server gave a usable answer for too long: at the default intervals, 5 minutes for the `parent` and `fast` checks, 15 minutes for the `other` and `serial` checks, 30 minutes for the certificate source. Until one does, a change there is not seen. | Find out why no server answers this machine. For the policy file or the certificate source, the log of the service names the reason. |
| **LOW** · the zone `example.com.` changed, and no watched record differs | The zone serial moved and no line differs: a change of a record that the file does not watch, or a change that was undone. | If you did not change the zone, find out who did. The alert cannot say which record changed. |
| **MEDIUM** · the expectations file of `example.com.` is not valid | The file has a fault. The service goes on with the last valid file. | Fix the file. `validate` names each problem. |

The word after "the" in the first headline is the kind of check: `delegation`, `ds`, `records`, `serial`, `wildcard`, `policy` or `certificates`.

### Notices

Notices go to every channel, whatever its `min_severity`. They have no severity and no end. Their headlines start with `:test_tube: *TEST*`, `:warning: *DOWN*` and `:memo: *CHANGED*`.

| Headline | What it means | What to do |
|---|---|---|
| **TEST** · osk-dns-watcher can send to this channel | `test-alert` or `doctor` asked for it. `start.sh` sends one at its end. | Nothing. |
| **DOWN** · osk-dns-watcher did not run for 7 min 34 s | At its start, the service saw that it had not run for a minute or more. Changes in that time were not seen when they happened. | If you did not stop it, find out who did. |
| **CHANGED** · the expectations of `example.com.` changed | The file changed. The lines show what was removed (`- `) and added (`+ `). | If you did not make this change, find out who did and restore the file. |

## How an alert ends

Most alerts end when the servers give what the file allows again, or when you change the file so that it allows what they give, for example with `accept`. The end message is `:white_check_mark: *RESOLVED*`. An alert stays open while a server that showed the problem gives no answer.

Some alerts end in their own way:

| Alert | Ends when |
|---|---|
| has no expectation and is not checked | the file has the line |
| the expectations file is not valid | the file is valid again |
| has had no usable answer for too long | a server gives a usable answer |
| the zone changed | the serial has not moved for 5 minutes (the `other` interval) |
| the nameservers give different answers | the split has been gone for 11 checks in a row |
| the three certificate alerts | no valid certificate shows the problem any more: the certificate expires, or the file allows it. A revoked certificate counts until it expires. |
| the three dangling-name alerts | the name exists again: the end message is `:warning: *CHECK*` |

The three dangling-name alerts end with a `CHECK` warning, not a green `RESOLVED`: the name can exist again because you fixed it, or because someone else registered it to take its traffic, and the service cannot tell which. The message asks you to find out who holds the name now. A webhook gets `"event": "resolve"` for both.
