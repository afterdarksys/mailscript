def evaluate():
    """
    Example spam filter using MailScript
    """
    # Get spam score
    score = getspamscore()

    # Get headers
    subject = get_header("Subject")
    from_addr = get_header("From")

    # Log what we're checking
    log_entry("Checking message from: " + from_addr)

    # High spam score -> quarantine
    if score > 7.0:
        log_entry("High spam score: " + str(score))
        quarantine()
        return

    # Spam keywords in subject
    if regex_match("(?i)(viagra|cialis|casino|lottery|winner|prize)", subject):
        log_entry("Spam keywords detected in subject")
        fileinto("Spam")
        return

    # Check for suspicious patterns in body
    if search_body("click here now") or search_body("limited time offer"):
        log_entry("Suspicious content in body")
        fileinto("Spam")
        return

    # Trusted sender domains
    if regex_match("@(example\\.com|trusted\\.org)$", from_addr):
        log_entry("Trusted sender domain")
        add_header("X-Trusted", "yes")
        accept()
        return

    # Default action
    accept()
