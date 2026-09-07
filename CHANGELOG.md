# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-09-07

First numbered release. Everything below was previously shipped only as
`mailscript:latest` builds reporting version `dev`.

### Added
- Starlark rule engine with mail-aware builtins, mbox/Maildir processing, JSON output and a gRPC interface that preserves original message bytes.
- Cryptographic SPF, DKIM, DMARC, ARC and DANE verification computed from message bytes; DNSSEC, MTA-STS and TLS-RPT transport policy discovery.
- RFC 5322 header validation, spoofing and header-injection checks, and trusted `Authentication-Results` handling.
- Human-versus-machine classification and Fisher/Robinson/TF-IDF scorers with an unsure band, chi-square feature selection and optional OSB features.
- ClamAV (native clamd protocol) and YARA policy scanning, plus external analyzer sidecars for executable, document, OCR/QR and sandbox findings.
- SMTP gateway with backend recipient validation, required STARTTLS or implicit TLS, private CAs, delegated submission authentication, native redirect/divert/copy routing and a capability-checked host delivery adapter.
- Gateway routing and filtering primitives, silent diversion and envelope BCC screening, and a portable `examples/gateway.star` policy.
- Atomic policy reload on SIGHUP with previous-generation retention, and bounded drain on shutdown.
- Real-MTA integration harness covering Postfix, Exim and qmail, and a go-emailservice-ads platform harness.
- Production Dockerfile.

### Fixed
- Upstream SMTP rejections are surfaced with their real response code.
- gRPC open relay, hard-coded scan status and AI-header quarantine bypass.
- DKIM fold canonicalisation; cryptographic tag parsing rejects uppercase and duplicate tag names.
- Mixed upstream recipient outcomes are rejected before DATA so no message is partially delivered.

### Known gaps
- See `docs/ENTERPRISE-GAPS.md`: structured MIME editing, complete inspection status, durable evidence capture, retention and legal hold, auditable policy decisions and policy governance are not implemented.
