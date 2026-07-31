"""Attachment and content safety policy module."""

def apply_content_safety():
    if has_executable_attachment() or has_macro_attachment():
        quarantine()
        return True
    if has_url_display_mismatch() and not is_verified():
        quarantine()
        return True
    return False

