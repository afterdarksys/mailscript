# gomeow.media gateway baseline
#
# This policy protects inbound mail and constrains the transactional stream.
# It intentionally quarantines suspicious attachments rather than silently
# deleting them. A malware scanner must set `virus_status` before production
# enforcement is enabled.

GOMEOW_DOMAIN = "gomeow.media"
BLOCKED_EXTENSIONS = [
    "ade", "adp", "apk", "app", "bat", "cab", "cmd", "com", "cpl",
    "dll", "exe", "hta", "img", "ins", "iso", "jar", "js", "jse",
    "lnk", "mht", "mhtml", "msi", "msp", "pif", "ps1", "reg", "scr",
    "sct", "vbe", "vbs", "wsc", "wsf", "wsh",
]


def quarantine_with_reason(reason):
    add_header("X-MailScript-Quarantine", "true")
    add_header("X-MailScript-Quarantine-Reason", reason)
    log_entry("gomeow quarantine: " + reason)
    quarantine()


def evaluate():
    sender_domain = envelope_from_domain()
    is_gomeow_transactional = sender_domain == GOMEOW_DOMAIN and is_automated()

    # Transactional mail is account/security mail, not a file-transfer path.
    # Media delivery must use an authenticated, expiring HTTPS link instead.
    if is_gomeow_transactional and has_attachment():
        quarantine_with_reason("transactional-mail-with-attachment")
        return

    # Structural attachment checks are safe to enforce without an AV engine.
    if has_executable_attachment() or has_attachment_ext(BLOCKED_EXTENSIONS):
        quarantine_with_reason("executable-attachment")
        return
    if len(double_extension_attachments()) > 0:
        quarantine_with_reason("double-extension-attachment")
        return
    if len(rtl_override_attachments()) > 0:
        quarantine_with_reason("rtl-override-attachment")
        return

    # Archives and macros are review-worthy until a scanner can recursively
    # inspect them. Never fail open based on an unavailable scanner.
    if has_macro_attachment() or has_archive_attachment():
        quarantine_with_reason("macro-or-archive-attachment")
        return
    if total_attachment_size() > 20 * 1024 * 1024:
        quarantine_with_reason("attachment-size-limit")
        return
	if getvirusstatus() == "infected":
		quarantine_with_reason("clamav-malware-detected")
		return
	if len(yara_matches()) > 0:
		quarantine_with_reason("yara-rule-match:" + yara_matches()[0])
		return
	if has_attachment() and (not av_available() or not yara_available()):
		quarantine_with_reason("attachment-scanner-unavailable")
		return

    # Preserve a clear classification for downstream auditing and delivery.
    if is_gomeow_transactional:
        add_header("X-Gomeow-Mail-Class", "transactional")
    accept()
