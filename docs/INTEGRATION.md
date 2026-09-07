# MailScript integration

MailScript owns filtering. The mail server owns relay authorization, its durable
queue, mailbox delivery, and user authentication. The common integration is SMTP;
Postfix, Sendmail, qmail, Exim, and go-emailservice-ads can sit behind the same
MailScript gateway. No platform-specific protocol is required for ordinary mail.

## SMTP gateway

```sh
mailscript proxy --script=examples/gateway.star \
  --listen=127.0.0.1 --port=3025 --upstream=127.0.0.1:2525
```

Route inbound mail to MailScript and configure the backend on a separate private
listener. For a public perimeter, explicitly select the public bind address with
`--listen`. Avoid routing the backend back through MailScript. Keep the backend's
recipient and relay checks enabled; trusting a filter connection must not grant
permission to relay to arbitrary domains.

MailScript returns success only after the backend accepts end-of-DATA. It has no
local queue. Backend connection failures and script failures are temporary errors.
Permanent backend rejections retain their status. SMTP recipients are validated
against the same open backend transaction during the client's RCPT exchange, so
an invalid recipient does not prevent delivery to a valid one. API submissions
and policy redirects have one outcome for their complete recipient list; mixed
backend results defer those submissions before DATA, preventing partial delivery.

The gateway supports null envelope senders, SMTP dot transparency, 8BITMIME, and
messages up to 50 MiB. It requires CRLF DATA line endings and bounds connections,
recipients, line lengths, and network waits. SMTPUTF8 is not advertised.

## TLS and authenticated submission

`--upstream-tls=plain` is for a local/private transport. Use
`--upstream-tls=starttls` to require STARTTLS, or `--upstream-tls=tls` for implicit
TLS. Both encrypted modes verify the certificate and hostname and require TLS
1.2 or newer. `--upstream-ca` adds private CA certificates;
`--upstream-tls-name` overrides the certificate hostname. There is no insecure
certificate bypass or opportunistic downgrade.

For a backend service account, configure `--upstream-user` and set
`MAILSCRIPT_UPSTREAM_PASSWORD`. Credentials require encrypted backend transport.

For end-user submission, run a separate instance:

```sh
mailscript proxy --script=examples/gateway.star --port=3587 \
  --upstream=mail.internal:587 --upstream-tls=starttls \
  --enable-tls --cert=cert.pem --key=key.pem --submission
```

Submission requires client STARTTLS and AUTH PLAIN before MAIL. The backend
verifies each client's credentials over encrypted transport; those credentials
are used for that client's backend transactions. This preserves the backend's
per-user relay rules. The default perimeter mode does not expose AUTH. The two
default ports do not imply distinct authentication modes within one instance.

## Shutdown and policy reload

Startup validates the complete root policy and loaded module graph before binding
listeners. SIGHUP reads and validates a new immutable snapshot and atomically
publishes it. In-flight evaluations keep their existing snapshot. Invalid syntax,
unknown builtins, load cycles, missing files, and escaping module paths reject the
reload and retain the previous policy. Runtime errors that depend on message data
remain temporary per-message failures.

SIGTERM/SIGINT stop accepting new connections and drain SMTP sessions and gRPC
requests for up to 30 seconds. At the deadline, remaining connections are closed;
unacknowledged SMTP submissions remain the sender's responsibility.

## go-emailservice-ads quarantine

The platform's `content_filter` configuration already implements the marker
contract used by MailScript. Merge this into the platform configuration, using
only the actual private proxy source addresses:

```yaml
content_filter:
  enabled: true
  trusted_proxy_networks:
    - 127.0.0.1/32
  quarantine_header: X-MailScript-Quarantine
  quarantine_folder: Junk
```

Run MailScript with the backend's actual private SMTP port:

```sh
mailscript proxy --script=examples/gateway.star \
  --listen=127.0.0.1 --port=3025 --upstream=127.0.0.1:2525 \
  --forward-quarantine
```

Client-supplied `X-MailScript-Quarantine` fields are removed. A policy quarantine
adds a fresh marker; the platform recognizes it only from a trusted filter peer,
removes it, and durably holds the mail in its administrative quarantine queue.
The configured folder is retained as quarantine metadata; immediate IMAP delivery
to that folder must not be assumed. The platform's `/api/v1/quarantine` API lists
held messages. Its release operation requires a configured scanner and a clear
rescan. Other servers need an equivalent trusted handler before enabling this flag.
Without the flag, quarantine returns 550 and does not deliver the message.

## Policy actions

| Action | Gateway behavior |
|---|---|
| `accept()` | Forward; return 250 after upstream acceptance |
| `reject()`, `bounce()`, `drop()`, `discard()` | Return 550 without forwarding (legacy drop/discard behavior retained) |
| `defer()` | Return 451 without forwarding |
| `reply_with_smtp_error(code, text)` | Return the policy's 4xx/5xx response, with single-line text |
| `quarantine()`, `fileinto("Spam")` | Trusted quarantine forwarding when enabled; otherwise 550 |
| Header additions/removals | Apply to the forwarded message after evaluation |
| `redirect`, `divert_to` | Replace the envelope recipient list with the policy destinations |
| `screen_to` | Add policy destinations as envelope recipients |
| Other folder/reply/digest/DLP actions | Execute through a configured host delivery adapter; otherwise return 451 |

Actions accumulate. An `accept()` does not override a blocking action. The first
blocking action determines the SMTP failure. Logs, scoring, and tags remain
available as policy output. Evaluate-only gRPC calls return actions for the host
application to implement, including actions the generic SMTP gateway cannot run.

## Host delivery adapter

Configure `--delivery-adapter=https://host.internal/filter-delivery` and optionally
`MAILSCRIPT_DELIVERY_TOKEN`. HTTPS is required except for loopback HTTP. Startup
fetches `GET /v1/capabilities` from that base URL:

```json
{"version":1,"actions":["accept","quarantine","fileinto","redirect","auto_reply","add_to_digest","set_dlp"]}
```

The configured host must advertise `accept` and every delivery action it can
execute. If a policy asks for an unadvertised action, MailScript defers without
submitting the plan. Header edits and log actions are already applied locally;
other actions, including tags and scanner/DLP controls, require host support.

MailScript posts one JSON delivery plan to `POST /v1/deliver`:

```json
{"version":1,"id":"sha256-delivery-key","from":"sender@example.com","to":["user@example.com"],"message":"base64-rfc5322-bytes","actions":["fileinto:Inbox","auto_reply:Away"],"client_ip":"192.0.2.1","helo":"sender.example"}
```

The host owns delivery of the entire plan, including the original message. It
must validate action arguments, durably commit all work or nothing, and persist
receipts keyed by `id` so a retry cannot duplicate replies, copies, or digests.
The key derives from the envelope, processed message, and actions; connecting
IP and HELO do not change it. The response must echo the ID and include a durable
receipt before MailScript acknowledges success:

```json
{"id":"sha256-delivery-key","smtp_code":250,"receipt":"durable-job-123","reason":"Queued"}
```

A 4xx/5xx `smtp_code` denies the complete plan. Timeouts, HTTP errors, redirects,
malformed responses, missing receipts, and mismatched IDs defer delivery. HTTP
requests have a 30-second deadline and responses are bounded to 64 KiB. The SMTP
backend still validates sender/recipient admission; accepted DATA goes exclusively
to the adapter when one is configured. This contract is the integration point for
platform-specific mailbox and workflow operations; the host implements their
semantics. SMTP-only installations can use filtering, header edits, quarantine
markers and native redirects without an adapter.

## Programmatic integration

The checked-in `pkg/proto` Go bindings support `raw_message` on `ProcessRequest`.
Use original RFC 5322 bytes for real mail: a header map cannot preserve duplicate
headers or DKIM wire representation. `raw_message` cannot be combined with
`headers`/`body`; the original map/body format remains supported for constructed
messages. `from` and `to` are envelope identities, and an empty `from` is valid.
Supply `client_ip` and `helo` from trusted connection metadata for SPF evaluation.

`ProcessResponse` includes `smtp_code`, `actions`, `removed_headers`,
`modified_headers`, and `processed_message`. `forwarded` is true only after a
requested backend delivery succeeds. With `forward_to_upstream=false`, the caller
still owns delivery and must implement returned actions. Existing field numbers
and RPC methods are unchanged. The default gRPC receive limit is 4 MiB.

The API binds to loopback by default. Non-loopback binding requires a bearer token
via `MAILSCRIPT_GRPC_TOKEN` or `--grpc-auth-token`; use a protected transport because
the gRPC listener does not terminate TLS. SMTP submission through this API is
privileged access to the configured backend.
