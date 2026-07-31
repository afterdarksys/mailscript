# TODO

There are no known outstanding repository items as of 2026-07-31.

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

The former `code-review-graph` server `torch` note was an external MCP server
environment issue, not part of this repository. It has been removed from the
MailScript work queue; MailScript does not import or require PyTorch.
