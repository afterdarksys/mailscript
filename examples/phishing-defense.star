# Layered phishing defence.
#
# Combines header validation, verified sender authentication, brand
# impersonation checks, link analysis and attachment inspection into a single
# score, then decides once at the end.
#
# Run with:
#   mailscript test --script=examples/phishing-defense.star \
#     --eml=message.eml --verify --client-ip=203.0.113.10
#
# The brands list should name the organisations your users are impersonated
# as, not every brand in existence: each entry widens the lookalike net.

BRANDS = [
    "paypal.com", "microsoft.com", "google.com", "apple.com",
    "amazon.com", "netflix.com", "docusign.com", "dropbox.com",
]

# Attachment types that execute on open, directly or through a script host.
BLOCKED_EXTENSIONS = ["exe", "scr", "js", "vbs", "jar", "hta", "iso", "lnk"]


def evaluate():
    # -- Hard blocks: conditions with no legitimate explanation -------------

    if has_finding("HDR_INJECTION"):
        log_entry("header injection attempt")
        drop()
        return

    if has_attachment_ext(BLOCKED_EXTENSIONS):
        log_entry("executable attachment: " + str(attachment_names()))
        quarantine()
        return

    if len(double_extension_attachments()) > 0:
        log_entry("disguised extension: " + str(double_extension_attachments()))
        quarantine()
        return

    if len(rtl_override_attachments()) > 0:
        log_entry("bidi override hides the real extension")
        quarantine()
        return

    # -- Authentication ----------------------------------------------------
    #
    # Only judge authentication when it could actually be evaluated. Treating
    # "DNS is down" as "sender failed" turns an outage into mass rejection.

    if dns_available():
        if not is_verified():
            add_score(4.0, "sender did not prove control of " + from_domain())

        if auth_disposition() == "reject":
            log_entry("domain owner asks for reject: " + auth_summary())
            quarantine()
            return

        for warning in auth_warnings():
            log_entry("auth warning: " + warning)

    # A pass claimed by an authority we do not operate is a deliberate
    # forgery, not a misconfiguration.
    if forged_auth_results():
        log_entry("forged Authentication-Results from " + str(untrusted_authservs()))
        add_score(6.0, "forged authentication header")

    # -- Identity ----------------------------------------------------------

    impersonated = looks_like_any(from_domain(), BRANDS)
    if impersonated:
        log_entry("domain resembles " + impersonated)
        add_score(7.0, "lookalike of " + impersonated)

    if display_name_spoofed():
        add_score(5.0, "display name claims a different address")

    # A display name naming a brand while the domain is unrelated is the
    # most common form of impersonation and needs no lookalike domain.
    display = from_display_name().lower()
    for brand in BRANDS:
        label = brand.split(".")[0]
        if label in display and not same_org_domain(from_domain(), brand):
            add_score(6.0, "display name claims " + brand)
            break

    # -- Links -------------------------------------------------------------

    if has_url_display_mismatch():
        for mismatch in url_display_mismatches():
            log_entry("link text says " + mismatch["display_host"] +
                      " but points to " + mismatch["href_host"])
        add_score(5.0, "link text disagrees with destination")

    if has_url_shortener():
        add_score(2.0, "shortened link hides its destination")

    if url_count() > 15:
        add_score(1.5, str(url_count()) + " links")

    # -- Language ----------------------------------------------------------

    if regex_match("(?i)(verify your account|suspended|act now|urgent|" +
                   "confirm your identity|unusual activity|password expire)",
                   get_header("Subject")):
        add_score(2.5, "urgency language in the subject")

    if subject_shouting():
        add_score(1.0, "subject is shouting")

    # -- Statistical -------------------------------------------------------

    if ml_available():
        spam = ml_score("spam")
        if spam > 0.95:
            add_score(4.0, "classifier: spam at " + str(int(spam * 100)) + "%")
        elif spam > 0.80:
            add_score(2.0, "classifier: likely spam")

    # -- Structural findings -----------------------------------------------

    apply_validation_score(min_severity="medium")

    # -- Decide once -------------------------------------------------------

    score = get_score()

    if score >= 12.0:
        log_entry("quarantined, score " + str(int(score)))
        for reason in get_score_reasons():
            log_entry("  " + reason)
        quarantine()
        return

    if score >= 6.0:
        add_header("X-MailScript-Suspicious", "score=" + str(int(score)))
        fileinto("Suspicious")
        return

    if score > 0:
        add_header("X-MailScript-Score", str(int(score)))

    accept()
