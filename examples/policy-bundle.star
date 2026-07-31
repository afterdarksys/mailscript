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
    if apply_ai_policy():
        return

    # Apply privacy at the trust-boundary handoff, after checks that need the
    # original headers have completed.
    apply_privacy()

    if get_score() >= 5:
        quarantine()
        return
    accept()

