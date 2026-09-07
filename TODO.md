# TODO

## Enterprise filtering work

See `docs/ENTERPRISE-GAPS.md` for the assessed capabilities, platform reuse,
prioritized gaps and proposed Starlark interfaces. Silent diversion and envelope
BCC screening are implemented and explicitly tested. Structured MIME mutation,
complete inspection status, durable evidence primitives and the platform
compliance adapter remain outstanding; existing action names alone do not
implement those capabilities.

## Filtering-layer integration status (2026-09-07)

The SMTP gateway and gRPC delivery contract now have regression coverage for
policy rejections/defer, null envelope senders, command injection, raw messages,
quarantine forwarding, SMTP transparency, transaction resets, and partial
recipient failures. See `docs/INTEGRATION.md` for deployment and limitations.

## Completed in the delivery and operations pass

- Validate SMTP recipients in the same backend transaction before accepting RCPT.
- Support required STARTTLS, implicit TLS, private CAs, backend service accounts,
  and client submission authentication delegated to the encrypted backend.
- Execute native redirect/divert/copy routing and support atomic host delivery
  through a capability-checked, idempotent HTTP adapter contract.
- Snapshot root policy and modules, atomically reload on SIGHUP, and retain the
  previous generation when a reload is invalid.
- Stop admission and drain active SMTP/gRPC work on shutdown, with a deadline.
- Add isolated real-MTA and platform integration harnesses. See
  `tests/integration/README.md` for tested versions and reproduction commands.

Host-specific folder, reply, digest and DLP implementations belong to the host
adapter. Deployments must implement the advertised capabilities; MailScript
refuses unsupported plans and does not silently simulate those operations.

## Completed in the gateway integration pass

- Share blocking policy decisions across SMTP and gRPC; expose SMTP response
  codes, processed bytes, removed headers, and confirmed forwarding in gRPC.
- Preserve original RFC message bytes and connection metadata in the API.
- Require an upstream and bind all listeners before reporting readiness.
- Bound SMTP connections, message/line sizes, recipients, and network waits;
  reset envelope state across DATA, HELO/EHLO, RSET, and STARTTLS.
- Reject mixed upstream recipient outcomes before DATA to prevent silent loss.
- Document the existing go-emailservice-ads trusted quarantine contract and add
  a portable gateway policy.

## Completed in the security and policy pass

- Generated and registered the protobuf/gRPC service; API-requested upstream
  delivery now uses the real SMTP relay path and reports failures.
- Added selectable Fisher, Robinson, and legacy Bayes scorers backed by raw
  token counts, an unsure band, chi-square feature selection, and optional
  OSB sparse order features.
- Distinguished DANE discovery (`available`) from certificate verification
  (`pass`) and added matching/mismatch certificate fixtures.
- Made DKIM cryptographic tag parsing reject uppercase and duplicate tag names.
- Added SPF macro expansion, including `%{s}`, `%{d}`, `%{i}`, transformers,
  and explicit `permerror` for unsupported DNS-dependent macros.
- Added cryptographic ARC chain validation and generated-chain tests.
- Added an SMTP-proxy policy-path test for duplicate `From` rejection.
- Documented that inbound DANE is transport hygiene, not authentication.
- Added composable policy modules, transport policy checks, metadata
  minimization, and explicit AI provenance filtering.
- Added a bounded, concurrent external-analyzer contract with normalized
  verdicts and explainable findings for open-source capa, oletools, OCR/QR,
  and sandbox sidecars.

The former `code-review-graph` server `torch` note was an external MCP server
environment issue, not part of this repository. It has been removed from the
MailScript work queue; MailScript does not import or require PyTorch.
