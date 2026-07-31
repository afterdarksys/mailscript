# Policy gates for optional open-source analysis sidecars such as capa,
# oletools, and OCR/QR inspection. Stable finding codes keep the policy
# independent of the implementation behind each sidecar.

def quarantine_with_reason(reason):
    log_entry(reason)
    quarantine()

def evaluate():
    if analysis_pending():
        quarantine_with_reason("deeper attachment analysis is pending")
        return

    if threat_verdict() == "malicious":
        quarantine_with_reason("external analyzer detected malicious content")
        return

    if has_finding("office/autoexec-macro"):
        quarantine_with_reason("Office document contains an auto-run macro")
        return

    if has_capability("process/create-powershell"):
        quarantine_with_reason("attachment can launch PowerShell")
        return

    if threat_verdict() == "suspicious" and threat_score() >= 0.8:
        quarantine_with_reason("high-confidence suspicious attachment")
        return

    accept()
