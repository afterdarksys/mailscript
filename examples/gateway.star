# Portable gateway policy. Enable --forward-quarantine only with a trusted
# backend quarantine handler; go-emailservice-ads provides one.
def evaluate():
    if has_finding("HDR_INJECTION") or has_finding("HDR_DUP_FROM"):
        reject()
        return
    if getvirusstatus() == "infected" or threat_verdict() == "malicious":
        quarantine()
        return
    if has_executable_attachment() or has_macro_attachment():
        quarantine()
        return
    if has_url_display_mismatch():
        add_score(5.0, "link text disagrees with destination")
    if ml_available() and ml_score("spam") > 0.95:
        add_score(5.0, "classifier identified spam")
    if get_score() >= 5.0:
        quarantine()
        return
    accept()
