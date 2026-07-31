"""AI-agent provenance policy module."""

def apply_ai_policy():
    if is_ai_generated(threshold=95):
        add_header("X-Mail-Class", "ai-declared")
        fileinto("AI/Declared")
        return True
    if is_ai_generated(threshold=70):
        add_header("X-Mail-Class", "ai-likely")
        fileinto("AI/Review")
        return True
    return False

