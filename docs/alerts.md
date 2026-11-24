# Alerts

The tables below list every alert that the service can send, with its headline as Slack shows it, what it means, and what to do. The names in the headlines are examples.

Run the commands on this page, such as `accept` and `validate`, in `osk-dns-watcher/deploy`, as in `./osk-dns-watcher accept <alert id>`. See [The command in deploy](config.md#the-command-in-deploy) in config.md.

## How an alert looks

A message has four parts, in this order:

1. The headline.
2. A block that shows what the file expects under `expected`, what the servers give under `now`, and which server gave it under `seen at`.
3. The times.
4. What to do.

The [README](../README.md) shows a full message.

The headline starts with an emoji and the severity:

| Start of the headline | Severity |
|---|---|
| 🚨 **CRITICAL** | critical |
| 🔴 **HIGH** | high |
| 🟠 **MEDIUM** | medium |
| 🟡 **LOW** | low |

Later messages of the same alert add words after the severity:

- `, changed again` when the servers show something new.
- `, raised from <severity>` when the severity goes up.
- `, still open` for a reminder. Reminders come only when the config sets `remind`.

The end message of an alert starts with ✅ **RESOLVED** or ⚠️ **CHECK**. See [How an alert ends](#how-an-alert-ends).

A channel gets the messages of an alert when the highest severity of the alert reaches the channel's `min_severity`. A webhook gets the same text in signed JSON, as [Webhooks](config.md#webhooks) in config.md describes. The service sends each emoji as a Slack emoji code, such as `:rotating_light:`, which Slack shows as the emoji.

## Delegation and nameservers

| Headline | What it means | What to do |
|---|---|---|
| **CRITICAL** · nameservers of `example.com.` changed at the parent zone | The parent zone delegates your domain to nameservers that the NS line does not allow. | If you did not change them, contact your registrar now. If you did, run `accept`. |
| **CRITICAL** · nameserver addresses of `example.com.` changed at the parent zone | The glue address that the parent zone gives for one of your nameserver hosts differs from its address line. | If you did not change it, contact your registrar now. If you did, edit the address line. |
| **HIGH** · DS of `example.com.` changed at the parent zone | The DS set at the parent zone differs from the DS line, or is gone. The service raises it to **CRITICAL** when the nameservers alert of the domain is open. It then stays **CRITICAL**. | If you did not change your DNSSEC keys, contact your registrar now. If you did, run `accept`. |
| **CRITICAL** · `example.com.` does not exist at the parent zone | The parent zone says that the domain does not exist. | Contact your registrar now. The registration may have expired, been deleted, or been transferred. |
| **MEDIUM** · `example.com. NS` has no expectation and is not checked | The file has no NS line or no DS line, so the service cannot judge that set. | Run `accept` to add the line. |
| **HIGH** · `shop.example.com.` is answered from an unexpected zone | A name of the file is answered from a zone other than the one that the file declares, for example a new subzone. | If you did not create this zone, check the delegations under your domain at your DNS provider. If you did, add its NS line by hand. |
| **MEDIUM** · the nameservers of `example.com.` give different answers for `www.example.com. A` | Each nameserver has given its own answer, steadily, for 10 to 50 minutes. The file allows each answer. | Find out why one nameserver answers otherwise. It may be out of date or not yours. |

## Records

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · `www.example.com. A` changed | A server gives a set that the line does not allow. The alert is **HIGH** for A, AAAA, CNAME, MX, and NS, and **MEDIUM** for the other types. | If you did not make this change, check your DNS provider account now. If you did, run `accept`. |
| **MEDIUM** · a wildcard answers for names under `example.com.` that do not exist | A random name under `example.com.` gets an answer, and the file says `*.example.com. A none`. | If you did not add a wildcard, remove it at your DNS provider and find out who added it. If you did, write its lines by hand. |

## Dangling names

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · `old.example.net.` does not exist, and an alias in `example.com.` points at it | A CNAME or DNAME of the file points at a name that does not exist. Whoever creates that name receives the traffic of the alias. | Change or remove the alias now. |
| **CRITICAL** · nameserver `ns2.example.net.` of `example.com.` does not exist | The NS line names a host that does not exist. Whoever creates that host can answer for your domain. | Replace the host at your registrar now, or restore it. |
| **HIGH** · `mx.example.net.` does not exist, and the mail records of `example.com.` point at it | An MX record, or an SPF include or redirect, names a name that does not exist. Whoever creates that name can receive or send mail as your domain. | Change the MX or SPF record now. |

The service checks only the names outside the domain's own zone, every 5 minutes.

## Mail

Each mail record has two headlines, both **MEDIUM**. The first comes for any change, and the second when the record now permits more than the line.

| Record | Any change | When it permits more |
|---|---|---|
| SPF | the SPF record at `example.com.` changed | the SPF record at `example.com.` lets more senders pass than the file |
| DMARC | the DMARC record `_dmarc.example.com.` changed | the DMARC record `_dmarc.example.com.` asks receivers to do less than the file |
| DKIM | the DKIM key `s1._domainkey.example.com.` changed | the DKIM key `s1._domainkey.example.com.` lets another key sign mail |
| MTA-STS record | MTA-STS at `_mta-sts.example.com.` changed | MTA-STS at `_mta-sts.example.com.` protects less than the file |
| MTA-STS policy file | MTA-STS at `mta-sts.example.com.` changed | MTA-STS at `mta-sts.example.com.` protects less than the file |

A message with the second headline has `weaker` lines that say how, for example `p=none in place of p=reject` or `mode testing in place of enforce: senders deliver mail even when the TLS check fails`.

A policy file that arrives but cannot be read as a policy counts as a change. Senders then act as if there were no policy.

For each mail alert, if you did not make the change, restore the record or the policy file now. If you did, run `accept`.

## Certificates and CAA

| Headline | What it means | What to do |
|---|---|---|
| **HIGH** · a certificate-challenge record appeared at `_acme-challenge.example.com. TXT` | A record or an alias stands at a challenge name where the file says `none`. Whoever controls that record can get a certificate for the name. | If you did not ask for a certificate for this name, find out who changed your DNS. Also look for the certificate in the certificate logs. |
| **HIGH** · the CAA policy for `example.com.` is weaker than expected | The CAA records that apply to this name permit more than the file: another authority, any account or validation method, wildcards, or no policy at all. A CAA change that permits nothing more gives the plain **MEDIUM** `changed` alert. | If you did not change them, restore them now, then look for certificates that you did not ask for. If you did, run `accept`. |
| **HIGH** · a certificate for a name of `example.com.` comes from an authority that the expectations do not permit | A valid certificate in the public logs comes from an authority that the CAA lines or the `issuer` lines do not permit. | If you did not ask for it, ask its authority to revoke it. Also check your CAA records and your DNS provider account. If you asked for it, allow the authority in those lines by hand. |
| **HIGH** · a wildcard certificate for `example.com.` holds a name that the expectations do not list | A valid wildcard certificate holds a name that no `certname` line lists. | If you did not ask for it, ask its authority to revoke it. If it is yours, run `accept`. |
| **LOW** · certificates name hosts under `example.com.` that the expectations do not list | Valid certificates name hosts that no line lists. One alert holds the list. | Check that each host is yours. Run `accept` to list them, or add a line for each host that the service should watch. |

The last three alerts come only when the config turns on the certificate logs. See [Certificates](config.md#certificates) in config.md.

## The watch itself

| Headline | What it means | What to do |
|---|---|---|
| **MEDIUM** · the records check of `www.example.com. A` has had no usable answer for too long | No server gave a usable answer for too long. At the default intervals, too long is 5 minutes for the `parent` and `fast` checks, 15 minutes for the `other` and `serial` checks, and 30 minutes for the certificate source. Until a server answers, the service does not see a change there. | Find out why no server answers this machine. For the policy file or the certificate source, the log of the service names the reason. |
| **LOW** · the zone `example.com.` changed, and no watched record differs | The zone serial moved, and no line differs. The cause is a change of a record that the file does not watch, or a change that was undone. | If you did not change the zone, find out who did. The alert cannot say which record changed. |
| **MEDIUM** · the expectations file of `example.com.` is not valid | The file has a fault. The service goes on with the last valid file. | Fix the file. `validate` names each fault. |

In the first headline, the word after "the" is the kind of check: `delegation`, `ds`, `records`, `serial`, `wildcard`, `policy`, or `certificates`.

### Notices

Notices go to every channel, whatever its `min_severity`. They have no severity and no end. A notice headline starts with 🧪 **TEST**, ⚠️ **DOWN**, or 📝 **CHANGED**.

| Headline | What it means | What to do |
|---|---|---|
| **TEST** · osk-dns-watcher can send to this channel | `test-alert` or `doctor` asked for it. `start.sh` sends one at its end. | Nothing. |
| **DOWN** · osk-dns-watcher did not run for 7 min 34 s | At its start, the service found that it had not run for a minute or more. It did not see the changes of that time when they happened. | If you did not stop it, find out who did. |
| **CHANGED** · the expectations of `example.com.` changed | The file changed. Lines that start with `- ` show what was removed, and lines that start with `+ ` show what was added. | If you did not make this change, find out who did and restore the file. |

## How an alert ends

Most alerts end when the servers give what the file allows again. They also end when you change the file so that it allows what the servers give, for example with `accept`. The end message starts with ✅ **RESOLVED**. An alert stays open while a server that showed the problem gives no answer.

Some alerts end in their own way:

| Alert | Ends when |
|---|---|
| has no expectation and is not checked | the file has the line |
| the expectations file is not valid | the file is valid again |
| has had no usable answer for too long | a server gives a usable answer |
| the zone changed | the serial has not moved for 5 minutes, the `other` interval |
| the nameservers give different answers | the split has been gone for 11 checks in a row |
| the three certificate alerts | no valid certificate shows the problem any more. Each certificate that showed it has expired, or the file now allows it. A revoked certificate counts until it expires. |
| the three dangling-name alerts | the name exists again. The end message starts with ⚠️ **CHECK**. |

The three dangling-name alerts end with a `CHECK` warning, not a green `RESOLVED`. The name can exist again because you fixed it, or because someone else registered it to take its traffic. The service cannot tell which. The end message asks you to find out who holds the name now. A webhook gets `"event": "resolve"` for both kinds of end.

## How fast a change is seen

At the default intervals, the service sees a change within these times, plus the time that its queries take:

| What changes | Seen within |
|---|---|
| Nameservers, glue, DS, and the domain itself, at the parent zone | 1 min |
| The A, AAAA, MX, and CAA sets of the domain itself, `_acme-challenge` names, and the names listed in `fast` | 1 min |
| Every other line, wildcards, the MTA-STS policy file, and the CAA policy of names below the domain | 5 min |
| Names that your lines point at, outside the domain's own zone | 5 min |
| A change inside the domain's own zone that moves the zone serial | about 15 s |
| Nameservers that give different answers | 10 to 50 min |
| A check with no usable answer | 5 to 15 min, and 30 min for the certificate source |
| Certificates in the public logs | about 1 h after the source has them |

These times were tested in a lab. A drill on a real test domain and a long run on real domains are not done yet.
