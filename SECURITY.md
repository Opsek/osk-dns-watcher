# Security

## Report a fault

Report a security fault in private: on the page of the repository, open **Security**, then **Report a vulnerability**. Please do not open a public issue for it.

## What osk-dns-watcher promises about itself

- It listens on no port.
- It holds no credential of a DNS provider or registrar, and cannot change your DNS.
- It sends HTTPS requests only to the hosts of its config, to the certificate source when you turn it on, and to `mta-sts.<domain>` of a watched domain.
- It sends DNS queries and policy fetches only to public addresses, unless the `network` settings for a lab permit more.
- It starts no other program, and refuses to run as root.
- It uses one outside module, the SQLite driver `github.com/mattn/go-sqlite3`, pinned in `go.sum` and stored in `vendor/`.

`make check` fails when the code listens on a socket, starts a process or uses another module ([docs/development.md](docs/development.md#the-rule-of-the-code)).

## Verify a release

Releases are signed. [docs/install.md](docs/install.md#verify-a-release) shows how to check the tag, the files and the image.
