# osk-dns-watcher

osk-dns-watcher watches the DNS of your domains from the outside and alerts you on Slack or a webhook when an answer is not what you confirmed.

> 🚨 **CRITICAL** · nameservers of `example.com.` changed at the parent zone
>
> ```
> expected   ns1.example.net.
>            ns2.example.net.
>
> now        ns1.example.org.
>            ns2.example.org.
> seen at    a.gtld-servers.net. (192.5.6.30)   TTL 172800
> ```
>
> 🕒 First seen 14:02:07 · last OK 14:01:07 · 15 Nov 2026 UTC
>
> 👉 If you did not change the nameservers, contact your registrar now.

## Quick start

You need:

- git 2.34 or later
- OpenSSH 8.2 or later
- Docker with Compose
- the address of a Slack incoming webhook
- a network that reaches the DNS root servers directly (VPNs and some office networks do not; the setup says so)

```sh quickstart
git clone https://github.com/Opsek/osk-dns-watcher.git
osk-dns-watcher/deploy/start.sh
```

`start.sh` checks the release signature, builds the program and asks for your domains and the webhook.
It shows what your servers answer now; when you type `yes`, the service trusts that, starts and sends a test message.

To run the ready-made image without a build, or to check the release key first, see [docs/install.md](docs/install.md).

## What it watches

| What changes | How serious | Seen within |
|---|---|---|
| Who answers for your domain: nameservers, glue, DS, the delegation | up to critical | 1 min |
| Your records: any set in your file (A, AAAA, CNAME, MX, NS count as high) | up to high | 5 min |
| Certificate challenges and CAA policy | high | 5 min |
| Mail policy: SPF, DMARC, DKIM, MTA-STS | medium | 5 min |
| Names your records point at that no longer exist | up to critical | 5 min |
| Wildcards, and names served from an unexpected zone | up to high | 5 min |
| Certificates in the public logs (off by default) | up to high | 1 h |
| The watch itself: servers that disagree, a failing check, an unexplained zone change | up to medium | 50 min |

Every alert, with its severity and time: [docs/alerts.md](docs/alerts.md).
Times were tested in a lab; a drill and a long run on real domains are not done yet.

## What it does not watch yet

- Registry data: transfer locks, a new registrar, an expiry date.
- DNSSEC validity: signatures and the chain of trust.
- Public resolvers: a poisoned cache is not seen.
- Missing protections: no audit for a registry lock, DNSSEC, CAA `accounturi` or a strict DMARC policy.
- Zone transfers: a change made and undone between two checks can be missed.
- Routes: a route hijack of your nameservers or hosts is not seen.
- Grouping: one cause sends one alert for each set that it changes.

[docs/limits.md](docs/limits.md) explains these and every limit of what is built.

## Every day

Run these in `osk-dns-watcher/deploy`:

```sh
./osk-dns-watcher status                              # healthy? which alerts are open, with their ids
./osk-dns-watcher check --expect example.com.expect   # what differs from the file now
./osk-dns-watcher accept <alert id>                   # the line that makes an alert's value expected
./osk-dns-watcher test-alert                          # a test message to every channel
```

To move to the newest signed release:

```sh update
./start.sh update
```

## More

- [Install, update, uninstall and verify a release](docs/install.md)
- [The expectations file](docs/expectations.md)
- [Every alert, and what to do](docs/alerts.md)
- [What it does not detect](docs/limits.md)
- [Settings, webhooks, the heartbeat and every command](docs/config.md)
- [Work on the code](docs/development.md)
- [Report a security fault](SECURITY.md)

Issues are welcome. Pull requests are not taken yet.
