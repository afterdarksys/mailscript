# Filtering gateway qualification

Validated on 2026-09-07 using disposable containers and synthetic local mail.
These fixtures are test configurations, not production deployment templates.

| Backend | Tested build | Result |
|---|---|---|
| go-emailservice-ads | `mailhub:qualification-2.7` cached platform image | PASS |
| Postfix | Debian Bookworm 3.7.11 | PASS |
| Exim | Debian Bookworm 4.96 | PASS |
| Sendmail | Debian Bookworm 8.17.1.9 with sensible-mda/procmail | PASS |
| qmail family | notqmail 1.09, commit `9f2f76e4f5b92f92f3e0e175dc01ab5144da0efc` | PASS |

The qmail fixture uses the [upstream notqmail release](https://notqmail.org/releases/1.09/),
not an unmodified qmail 1.03 build. Every MTA fixture verifies backend relay denial,
a null envelope sender, a policy-added header, dot transparency, and actual local
mailbox contents after delivery.

The platform fixture additionally verifies required backend STARTTLS with a
trusted test certificate, unknown-recipient rejection during RCPT, IMAP INBOX
contents, removal of a forged quarantine marker, a durable quarantine entry,
scanner-required release refusal, SIGHUP reload, invalid-reload retention, and
SIGTERM while an active SMTP transaction finishes.

The platform's trusted quarantine marker puts mail into its administrative held
queue. It does not immediately create an IMAP Junk message. The test asserts that
actual behavior rather than assuming folder delivery. The test deliberately has
no scanner; release must fail with the platform's scanner-required response.

## Reproduce

Requires Docker, Go, Python 3, and OpenSSL. Build or supply the platform image
first. The default platform image name is `mailhub:qualification-2.7`; override it
with `MAILHUB_IMAGE`.

```sh
# From the MailScript repository root:
./tests/integration/run.sh
```

For an individual backend:

```sh
go build -o /tmp/mailscript-check ./cmd/mailscript
docker build --build-arg MTA=postfix -t mailscript-mta:postfix tests/integration/mta
python3 tests/integration/mta.py --mailscript /tmp/mailscript-check --mta postfix

# Platform, using an existing local build:
python3 tests/integration/platform.py --mailscript /tmp/mailscript-check --image mailhub:qualification-2.7
```

Use `MTA=exim` or `MTA=sendmail` for the other Debian fixtures. qmail uses its own
Dockerfile, pinned to the upstream source commit:

```sh
docker build -f tests/integration/mta/Dockerfile.qmail -t mailscript-mta:qmail tests/integration/mta
python3 tests/integration/mta.py --mailscript /tmp/mailscript-check --mta qmail
```

Each runner creates unique container names and temporary directories, publishes
only loopback ports, checks delivery, then stops its proxy and removes its backend
container even after failure. Test images remain cached. External recipients are
used only for RCPT rejection checks; no external DATA is submitted.

## Automated regressions

```sh
go test -race ./...
go vet ./...
```

Go tests cover backend TLS and certificate failures, submission authentication,
recipient transactions, API partial-recipient failures, routing, adapter
capabilities/receipts/retry IDs, malformed SMTP framing, immutable module snapshots,
reload retention and drain deadlines. Live tests validate the shared SMTP contract
on the named configurations; deployments still configure their own authentication,
relay rules, certificates, scanners and host-adapter capabilities.
