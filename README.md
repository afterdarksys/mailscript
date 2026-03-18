# MailScript

**Universal Email Filtering Engine** - Starlark-based mail filtering that runs anywhere.

Test offline, process mailboxes, or run as an SMTP proxy gateway. Integrate MailScript into ANY email infrastructure.

## Quick Start

```bash
# Clone and build
git clone https://github.com/afterdarksys/mailscript.git
cd mailscript
./build.sh

# Or use the installer
curl -sSL https://raw.githubusercontent.com/afterdarksys/mailscript/main/install.sh | bash

# Test it out
./mailscript test --script=examples/spam-filter.star
```

## What is MailScript?

MailScript is a powerful email filtering engine based on Starlark (Python-like syntax) that can:

- ✅ **Run standalone** - No dependencies on other mail systems
- ✅ **Process mailboxes** - Import and filter mbox/maildir files
- ✅ **SMTP proxy mode** - Universal gateway for ANY mail server
- ✅ **gRPC integration** - Non-mail apps can submit messages
- ✅ **Offline testing** - Develop and test rules before production
- ✅ **JSON output** - Perfect for CI/CD pipelines

## Commands

### `mailscript test` - Offline Testing
```bash
# Test spam filter with custom data
mailscript test --script=filter.star \
  --from="spam@evil.com" \
  --subject="Buy Viagra Now!!!" \
  --verbose
```

### `mailscript process` - Mailbox Processing
```bash
# Process mbox file
mailscript process --script=filter.star --mbox=/var/mail/user -v

# Process Maildir with JSON output
mailscript process --script=filter.star --maildir=~/Maildir --json
```

### `mailscript repl` - Interactive Development
```bash
# Start interactive REPL
mailscript repl --script=filter.star

# Try different scenarios
mailscript> set From spam@evil.com
mailscript> set Subject "Win $1000 NOW!!!"
mailscript> spam 9.5
mailscript> run
```

### `mailscript proxy` - SMTP Proxy Gateway 🔥

**The nuclear option** - Run as a filtering gateway in front of ANY mail server.

```bash
# Basic SMTP proxy (ports 3025, 3587)
mailscript proxy --script=filter.star

# With upstream forwarding
mailscript proxy --script=filter.star --upstream=mail.example.com:25

# Enable TLS
mailscript proxy --script=filter.star \
  --enable-tls \
  --cert=cert.pem \
  --key=key.pem
```

**Architecture:**
```
[Mail Clients] → [MailScript:3025/3587] → [Mail Server:25/587]
       ↓                    ↓
  [gRPC Apps:50051]   [Filter Rules]
```

## Use Cases

### 1. Email Service Providers
Integrate MailScript into your infrastructure for advanced filtering:
```bash
mailscript proxy --script=/etc/mailscript/policy.star \
  --upstream=mail-cluster:25 \
  --port=3025,3587 \
  --enable-tls \
  --max-connections=1000
```

### 2. Corporate Mail Gateway
Enforce content policy and compliance:
```bash
mailscript proxy --script=examples/corporate-policy.star \
  --upstream=exchange.company.com:25 \
  --enable-tls
```

### 3. Development & Testing
Test mail servers with real traffic:
```bash
mailscript proxy --script=test-rules.star \
  --upstream=localhost:2525 \
  --disable-tls \
  -v
```

### 4. CI/CD Integration
Validate filtering rules in pipelines:
```bash
mailscript process --script=rules.star \
  --mbox=test-data.mbox \
  --json > results.json
```

### 5. Security Research
Analyze spam and phishing patterns:
```bash
mailscript process --script=analysis.star \
  --mbox=spam-archive.mbox \
  --json | jq '.messages[] | select(.actions[] | contains("quarantine"))'
```

## Writing MailScript Rules

MailScript uses Starlark (Python-like) syntax:

```python
def evaluate():
    # Get message details
    subject = get_header("Subject")
    from_addr = get_header("From")
    spam_score = getspamscore()

    # Log for debugging
    log_entry("Checking: " + subject)

    # Apply rules
    if spam_score > 7.0:
        quarantine()
        return

    if regex_match("(?i)(viagra|casino)", subject):
        fileinto("Spam")
        return

    # Trusted domains
    if regex_match("@company\\.com$", from_addr):
        add_header("X-Trusted", "yes")
        accept()
        return

    accept()
```

### Available Functions

**Message Info:**
- `get_header(name)` - Get header value
- `search_body(text)` - Search in message body
- `getspamscore()` - Get spam score (0-10)
- `getvirusstatus()` - Get virus scan result

**Actions:**
- `accept()` - Accept message
- `discard()` - Silently discard
- `fileinto(folder)` - File to folder
- `quarantine()` - Quarantine message
- `bounce()` - Bounce to sender
- `drop()` - Drop message

**Headers:**
- `add_header(name, value)` - Add/modify header
- `get_sender_domain()` - Extract sender domain
- `get_sender_ip()` - Get sender IP

**Advanced:**
- `regex_match(pattern, text)` - Regex matching
- `dns_check(domain)` - DNS verification
- `rbl_check(ip, server)` - RBL lookup
- `log_entry(message)` - Debug logging

See `examples/` for complete samples.

## gRPC Integration

MailScript includes a gRPC server (port 50051) for programmatic access from any application:

```python
import grpc
from mailscript_pb2 import ProcessRequest
from mailscript_pb2_grpc import MailScriptServiceStub

channel = grpc.insecure_channel('localhost:50051')
client = MailScriptServiceStub(channel)

response = client.ProcessMessage(ProcessRequest(
    from_='app@example.com',
    to=['user@example.com'],
    headers={'Subject': 'Order Confirmation'},
    body='Your order #12345',
    forward_to_upstream=True
))

if response.accepted:
    print("Message accepted")
else:
    print(f"Rejected: {response.reason}")
```

This means ANY application can use MailScript:
- Web apps validating emails
- Chat systems filtering messages
- CRM systems classifying mail
- Monitoring tools checking alerts
- **Literally ANYTHING**

## Building

```bash
# Build for current platform
./build.sh

# Build for all platforms
./build-all.sh

# Run tests
./test.sh
```

## Installation

### Quick Install
```bash
curl -sSL https://raw.githubusercontent.com/afterdarksys/mailscript/main/install.sh | bash
```

### Manual Install
```bash
git clone https://github.com/afterdarksys/mailscript.git
cd mailscript
./build.sh
sudo cp mailscript /usr/local/bin/
```

### From Source
```bash
go install github.com/afterdarksys/mailscript/cmd/mailscript@latest
```

## Configuration

MailScript looks for scripts in these locations:
1. Path specified with `--script`
2. `./mailscript.star`
3. `~/.config/mailscript/default.star`
4. `/etc/mailscript/default.star`

## Performance

- **Throughput**: 10,000+ messages/second (proxy mode)
- **Latency**: <1ms per message (typical rules)
- **Memory**: ~50MB baseline + 1KB per connection
- **Concurrency**: Handles 1000+ concurrent SMTP connections

## Security

- TLS 1.2+ support (SMTP and gRPC)
- Sandboxed Starlark execution
- No filesystem access from scripts
- Rate limiting and connection pooling
- Stats and monitoring endpoints

## Why MailScript?

**For Email Service Providers:**
- Add value-add filtering without touching core infrastructure
- Deploy gradually without production risk
- Per-customer rule customization
- Enterprise-grade performance

**For Developers:**
- Test rules offline before deployment
- CI/CD integration with JSON output
- Interactive REPL for rapid development
- No production dependencies

**For Security Teams:**
- Analyze mail archives for threats
- Custom detection rules
- Real-time traffic inspection
- Compliance enforcement

**For Everyone:**
- Python-like syntax (Starlark)
- Runs anywhere
- No vendor lock-in
- Open source

## Related Projects

- **AfterMail**: Full email client with MailScript integration - https://github.com/afterdarksys/aftermail
- **AfterSMTP**: Next-gen email protocol with DID-based identity
- **Mailblocks**: Proof-of-stake spam prevention

## License

MIT License - See LICENSE file

## Contributing

Contributions welcome! Please see CONTRIBUTING.md

## Support

- GitHub Issues: https://github.com/afterdarksys/mailscript/issues
- Documentation: https://aftermail.app
- Email: support@afterdarksys.com
