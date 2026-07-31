"""Select metadata protection on demand from message policy signals."""

def evaluate():
    # Strict mode removes Received and Return-Path too. Reserve it for an
    # intentional external handoff where loss of internal trace data is okay.
    if has_header("X-Privacy-Sensitive"):
        protect_metadata("strict", extra=["X-Tenant-ID", "X-Case-ID"])
    else:
        protect_metadata("standard")
    accept()

