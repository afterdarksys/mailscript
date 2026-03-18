def evaluate():
    """
    Corporate email policy enforcement
    - Block large attachments
    - Enforce DLP rules
    - Log all external emails
    """
    from_addr = get_header("From")
    to_addr = get_header("To")
    subject = get_header("Subject")

    # Check if external email
    is_external = not regex_match("@company\\.com$", from_addr)

    if is_external:
        log_entry("External email from: " + from_addr)
        add_header("X-External-Mail", "yes")

    # Block large attachments (>50MB)
    body_bytes = body_size()
    if body_bytes > 52428800:
        log_entry("Large attachment blocked: " + str(body_bytes) + " bytes")
        bounce()
        return

    # DLP: Check for credit card patterns
    if regex_match("\\b\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}[\\s-]?\\d{4}\\b", get_header("Body")):
        log_entry("Credit card pattern detected")
        set_dlp("quarantine", "compliance@company.com")
        return

    # DLP: Check for SSN patterns
    if regex_match("\\b\\d{3}-\\d{2}-\\d{4}\\b", get_header("Body")):
        log_entry("SSN pattern detected")
        set_dlp("quarantine", "compliance@company.com")
        return

    # External emails require extra scrutiny
    if is_external:
        # Check for phishing indicators
        if regex_match("(?i)(verify your account|suspended|urgent|act now)", subject):
            log_entry("Potential phishing email")
            fileinto("Quarantine")
            return

    accept()
