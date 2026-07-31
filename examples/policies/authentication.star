"""Authentication and path-integrity policy module."""

def apply_authentication():
    result = verify_auth()
    if result["arc"] not in ("none", "pass"):
        add_score(3.0, "ARC chain did not verify: " + result["arc"])
    if not result["authenticated"]:
        add_score(4.0, "sender failed aligned SPF/DKIM authentication")
    if forged_auth_results():
        add_score(5.0, "forged Authentication-Results header")

