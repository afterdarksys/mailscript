"""Compose typed policy modules into one administrative policy.

Run with:
  mailscript test --script=examples/policy-bundle.star --eml=message.eml --verify
  mailscript proxy --script=examples/policy-bundle.star --dns --upstream=127.0.0.1:25

load() paths are relative to this root policy and cannot escape its directory.
Each module exports a normal function. The root evaluate() controls ordering
and can stop after a terminal content or routing decision.
"""

load("policies/authentication.star", "apply_authentication")
load("policies/ai-mail.star", "apply_ai_policy")
load("policies/content.star", "apply_content_safety")
load("policies/privacy.star", "apply_privacy")

def evaluate():
    apply_authentication()

    if apply_content_safety():
        return

    # apply_ai_policy() files the message into an AI-review folder when
    # is_ai_generated() matches, but that classification is driven entirely
    # by sender-supplied headers (see ai-mail.star / pkg/rules/ai.go) — it is
    # not a verified trust signal the way authentication or content-safety
    # results are. Record the classification but do NOT let it short-circuit
    # past the authentication-score gate or privacy stripping below: doing so
    # let a single spoofed "X-AI-Agent" header bypass quarantine for a
    # message that otherwise failed SPF/DKIM/ARC badly enough to score >= 5,
    # and skip stripping internal headers (X-Internal-Trace etc.) entirely.
    ai_classified = apply_ai_policy()

    # Apply privacy at the trust-boundary handoff, after checks that need the
    # original headers have completed.
    apply_privacy()

    if get_score() >= 5:
        quarantine()
        return
    if ai_classified:
        return
    accept()

