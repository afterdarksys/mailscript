# MailScript

Starlark-based email filtering that runs anywhere: offline against sample
messages, over mailboxes, or as an SMTP proxy in front of any mail server.

```bash
git clone https://github.com/afterdarksys/mailscript.git
cd mailscript
./build.sh

./mailscript inspect --eml=suspicious.eml
```

## What it does

- **Rules in Starlark**, a Python-like language, with 234 mail-aware builtins.
- **Header validation** covering RFC 5322 conformance, spoofing, and header
  injection.
- **Real cryptographic verification** of SPF, DKIM, DMARC and DANE, computed
  from the message bytes rather than read from a header a sender can forge.
- **Human versus machine classification**, separating correspondence from
  bulk, transactional, list and automated mail.
- **TF-IDF classification** with optional BERT tokenization and GoLearn.
- **mbox and Maildir processing**, JSON output, an SMTP proxy, and a gRPC
  interface.

See [SPEC.md](SPEC.md) for the complete language and builtin reference.

## Why verification matters

`Authentication-Results` is an ordinary header. Any sender can write:

```
Authentication-Results: mx.google.com; spf=pass; dkim=pass; dmarc=pass
```

A filter that reads it and believes it is bypassed by anyone who can send
mail, and spammers do exactly this. MailScript handles it two ways:

```bash
# Recompute every verdict locally from the message and DNS.
mailscript verify --eml=message.eml --client-ip=203.0.113.10

# Or, when reading the header, know who wrote it.
mailscript inspect --eml=message.eml --trusted-authserv=mx.yourcompany.com
```

In a rule:

```python
def evaluate():
    if forged_auth_results():
        log_entry("message forged an authentication header")
        quarantine()
        return

    if dns_available() and not is_verified():
        add_score(4.0, "sender did not prove control of " + from_domain())

    accept()
```

`is_verified()` performs the SPF evaluation, DKIM signature check and DMARC
alignment itself. `spf_result()` and friends report what an upstream claimed,
and are only meaningful once `auth_results_trusted()` is true.

## Commands

### `inspect` — everything known about a message

```bash
mailscript inspect --eml=message.eml --verify --client-ip=203.0.113.10
```

Reports validation findings, authentication state, sender classification,
URLs and attachments. Runs no rule script; use it to understand a message or
to work out why a rule fired.

### `verify` — authentication only

```bash
mailscript verify --eml=message.eml --client-ip=203.0.113.10 --mail-from=sender@example.com
mailscript verify --eml=message.eml --dane --dns-server=1.1.1.1:53
```

Exits non-zero when the message does not authenticate, so it can gate a
pipeline.

### `test` — run a rule

```bash
mailscript test --script=filter.star --from=spam@evil.example --subject="Buy now" -v
mailscript test --script=filter.star --eml=message.eml --verify --json
```

### `process` — mailboxes

```bash
mailscript process --script=filter.star --mbox=/var/mail/user -v
mailscript process --script=filter.star --maildir=~/Maildir --json
```

### `train` — build a classifier

```bash
mailscript train --spam=spam.mbox --ham=ham.mbox --out=spam.json.gz
mailscript test --script=filter.star --model=spam.json.gz --eml=message.eml
```

Reports per-class precision and recall on a held-out split, because a single
accuracy figure hides the failure that matters: misclassified legitimate mail.

### `lint` — check a script

```bash
mailscript lint --script=filter.star
```

Parses and executes the script against a benign probe, reporting syntax
errors, unknown builtins, and rules that reach no delivery decision. Run it in
CI: a script that fails to parse takes the filter offline.

### `builtins` — list the API

```bash
mailscript builtins --filter=dkim
```

### `repl` — interactive development

```bash
mailscript repl --script=filter.star
```

### `proxy` — SMTP gateway

```bash
mailscript proxy --script=filter.star --upstream=mail.example.com:25
mailscript proxy --script=filter.star --enable-tls --cert=cert.pem --key=key.pem
```

Listens on 3025 and 3587 by default, so no root and no conflict with an
existing mail server.

```
[clients] -> [mailscript:3025/3587] -> [mail server:25/587]
                      |
               [gRPC apps:50051]
```

## Writing rules

```python
def evaluate():
    # Headers, case-insensitively, duplicates preserved.
    subject = get_header("Subject")

    # A second From is a spoofing technique, not a typo.
    if header_count("From") > 1:
        quarantine()
        return

    # Accumulate evidence rather than deciding on the first hit.
    if regex_match("(?i)(verify your account|suspended)", subject):
        add_score(2.5, "urgency language")

    if has_url_display_mismatch():
        add_score(5.0, "link text disagrees with its destination")

    if has_executable_attachment():
        drop()
        return

    apply_validation_score(min_severity="medium")

    if get_score() >= 10.0:
        quarantine()
        return

    accept()
```

Complete examples in [`examples/`](examples/):

| File | Purpose |
|---|---|
| `phishing-defense.star` | layered phishing detection with scoring |
| `human-mail.star` | route by sender class |
| `spam-filter.star` | keyword and score filtering |
| `corporate-policy.star` | DLP and content policy |

## DNS

DNS is off by default so rules stay deterministic and offline. Pass `--dns` to
enable it, or `--verify`, which implies it. Answers are cached for five
minutes with a three-second per-query timeout.

DANE additionally needs a DNSSEC-validating resolver: TLSA records that arrive
without the Authenticated Data bit are reported as `insecure`, never `pass`,
because an attacker who can forge the answer can also strip it.

## Building

```bash
./build.sh                                    # current platform
./build-all.sh                                # all platforms
go build -tags golearn ./cmd/mailscript       # with GoLearn algorithms
go test ./...
```

Requires Go 1.21 or later.

## Security notes

- Rules are sandboxed: no filesystem, no imports, no network beyond the DNS
  builtins.
- Execution is bounded by a step limit and a wall-clock timeout, so a runaway
  rule fails one message rather than wedging a worker.
- Patterns use RE2, which has no backtracking and therefore no catastrophic
  cases. RE2 also has no backreferences.
- Digest and certificate comparisons are constant-time.
- Verification fails closed: a missing key, an unreachable resolver, or a
  deprecated algorithm produces an error result, never a pass.
- `add_header` refuses CR, LF and NUL, so the engine cannot construct the
  injection its own validator flags.

DKIM specifically rejects `rsa-sha1` (RFC 8301), RSA keys under 1024 bits,
signatures that do not cover `From`, and any message carrying two `From`
fields. Signatures using the `l=` body-length tag verify but are flagged: the
unsigned remainder of the body can be replaced by an attacker.

## Library use

```go
import (
    "github.com/afterdarksys/mailscript/pkg/dnsx"
    "github.com/afterdarksys/mailscript/pkg/rules"
)

ctx, err := rules.ParseMessage(raw)
if err != nil {
    return err
}
ctx.Resolver = dnsx.NewResolver()

if err := rules.ExecuteEngine(script, ctx); err != nil {
    return err
}
// ctx.Actions, ctx.Score, ctx.LogEntries
```

Packages:

| Package | Contents |
|---|---|
| `pkg/rules` | message model, validation, classification, Starlark engine |
| `pkg/authverify` | SPF, DKIM, DMARC and DANE verification |
| `pkg/dnsx` | caching DNS client with DNSBL and TLSA support |
| `pkg/ml` | analyzer, TF-IDF, Naive Bayes, WordPiece tokenizer |

## gRPC

The proxy exposes a gRPC service on port 50051 so any application can submit
messages for filtering. See `pkg/proto/mailscript.proto`. Generate bindings
with:

```bash
protoc --go_out=. --go-grpc_out=. pkg/proto/mailscript.proto
```

## Related projects

- **AfterMail**: email client with MailScript integration
- **AfterSMTP**: next-generation email protocol with DID-based identity
- **Mailblocks**: proof-of-stake spam prevention

## License

MIT. See LICENSE.

## Support

- Issues: https://github.com/afterdarksys/mailscript/issues
- Email: support@afterdarksys.com
