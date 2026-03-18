# MailScript - Standalone Email Filtering Engine

Powerful Starlark-based email filtering that runs anywhere. Test offline, process mailboxes, or run as an SMTP proxy gateway.

## Commands

### `mailscript test` - Offline Rule Testing
Test MailScript rules with sample data:
```bash
# Test with default sample message
mailscript test --script=filter.star

# Test with custom headers
mailscript test --script=filter.star --from=spam@evil.com --subject="Buy Now!" -v
```

### `mailscript process` - Mailbox Processing
Apply rules to mbox/maildir mailboxes:
```bash
# Process an mbox file
mailscript process --script=filter.star --mbox=/var/mail/ryan -v

# Process Maildir with JSON output
mailscript process --script=filter.star --maildir=~/Maildir --json

# Limit processing
mailscript process --script=filter.star --mbox=inbox.mbox --max=100
```

### `mailscript repl` - Interactive Development
Interactive REPL for rule development:
```bash
# Start REPL with a script
mailscript repl --script=filter.star

# REPL commands
mailscript> set From spam@evil.com
mailscript> set Subject "Buy Viagra Now!!!"
mailscript> spam 8.5
mailscript> run
```

### `mailscript daemon` - Live Daemon Integration
Connect to aftermaild for live testing:
```bash
# Check daemon status
mailscript daemon status

# Test against live messages
mailscript daemon test --script=filter.star --limit=10

# Monitor in real-time
mailscript daemon monitor --script=filter.star --interval=5
```

### `mailscript proxy` - SMTP Proxy Gateway 🔥

**The Nuclear Option**: Run MailScript as a full SMTP filtering proxy that sits in front of ANY mail server.

```bash
# Basic SMTP proxy (ports 3025, 3587)
mailscript proxy --script=filter.star

# With upstream forwarding
mailscript proxy --script=filter.star --upstream=mail.example.com:25

# Enable TLS
mailscript proxy --script=filter.star --enable-tls --cert=cert.pem --key=key.pem

# Custom ports
mailscript proxy --script=filter.star --port=3025,3465,3587
```

#### Why This Is Brilliant (and Dangerous)

**The ports are cheeky**: 3025, 3587 reference standard SMTP ports (25, 587) but prefixed with "3":
- No root required
- No conflicts with existing mail servers
- Easy to remember
- Instantly recognizable as "SMTP but filtered"

**Architecture:**
```
[Mail Client]
    ↓ SMTP (3025/3587)
[MailScript Proxy] ← Apply filtering rules
    ↓ SMTP (25/587)
[Your Mail Server]
```

**What You Can Do:**
1. **Filter ALL Incoming Mail**: Sit in front of your mail server
2. **Re-inject to Upstream**: Apply rules, modify headers, forward to real server
3. **gRPC Integration**: Non-mail apps can submit messages via gRPC (port 50051)
4. **TLS/STARTTLS**: Full encryption support
5. **Real-time Processing**: Filter messages as they flow through
6. **Metrics & Stats**: Track what's being filtered

**Use Cases:**
- **Email Service Providers**: Add enterprise filtering to existing infrastructure
- **Corporate Gateways**: Compliance and content policy enforcement
- **Development/Testing**: Test mail servers with real SMTP traffic
- **Migration**: Gradually roll out new filtering without touching production
- **Security Research**: Analyze malicious mail in real-time
- **Multi-tenant Systems**: Different filtering rules per customer

#### gRPC Interface for Non-Mail Apps

The proxy includes a gRPC server (default port 50051) so ANY application can submit messages programmatically:

```protobuf
service MailScriptService {
    // Process a message through MailScript rules
    rpc ProcessMessage(ProcessRequest) returns (ProcessResponse);

    // Get proxy statistics
    rpc GetStats(StatsRequest) returns (StatsResponse);

    // Stream processing for high throughput
    rpc ProcessMessageStream(stream ProcessRequest) returns (stream ProcessResponse);
}
```

This means:
- Web apps can validate emails before sending
- Chat apps can filter messages
- CRM systems can classify incoming mail
- Monitoring systems can check for alerts
- **Literally ANYTHING can use MailScript filtering**

## Integration Examples

### Corporate Mail Gateway
```bash
# Run as filtering gateway in front of Exchange/Gmail
mailscript proxy \
  --script=/etc/mailscript/corporate-policy.star \
  --upstream=exchange.company.com:25 \
  --port=3025,3587 \
  --enable-tls \
  --cert=/etc/ssl/mail.crt \
  --key=/etc/ssl/mail.key \
  --max-connections=500
```

### Development Testing
```bash
# Test your mail server with real traffic
mailscript proxy \
  --script=test-rules.star \
  --upstream=localhost:2525 \
  --port=3025 \
  --disable-tls \
  -v
```

### gRPC Application Integration
```python
import grpc
from mailscript_pb2 import ProcessRequest
from mailscript_pb2_grpc import MailScriptServiceStub

channel = grpc.insecure_channel('localhost:50051')
client = MailScriptServiceStub(channel)

response = client.ProcessMessage(ProcessRequest(
    from_='user@example.com',
    to=['recipient@example.com'],
    headers={'Subject': 'Test Message'},
    body='This is a test',
    forward_to_upstream=True
))

if response.accepted:
    print(f"Message accepted: {response.reason}")
else:
    print(f"Message rejected: {response.reason}")
```

## Building

```bash
# Build standalone binary
go build -o mailscript ./cmd/mailscript

# Generate gRPC code (optional, for full gRPC support)
protoc --go_out=. --go-grpc_out=. pkg/proto/mailscript.proto
```

## Why This Matters

MailScript is now a **universal email filtering engine** that can:

1. ✅ Run standalone without AfterMail
2. ✅ Integrate into ANY email infrastructure
3. ✅ Process messages via SMTP proxy
4. ✅ Accept messages via gRPC from ANY app
5. ✅ Test offline before production
6. ✅ Monitor live systems
7. ✅ Export results as JSON for automation

You can literally drop MailScript in front of Gmail, Exchange, Postfix, SendGrid, Mailgun, or your custom mail server and add enterprise-grade filtering **without touching their code**.

## The "Going to Hell" Part

The proxy mode turns MailScript from "a nice filtering tool" into **a weaponized email gateway** that can:
- Intercept ALL mail traffic
- Apply arbitrary rules
- Modify messages in flight
- Re-inject to upstream
- Integrate with non-mail apps
- Track everything

And it's so easy to deploy that anyone can do it. Hence: going to hell. 😈

But it's also **incredibly useful** for legitimate use cases like compliance, security, testing, and integration.
