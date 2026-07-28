# Route mail by who, or what, wrote it.
#
# Separates person-to-person correspondence from the machine-generated mail
# that dominates most mailboxes, so the inbox holds only messages that expect
# a reply.
#
# Run with:
#   mailscript test --script=examples/human-mail.star --eml=message.eml -v

# Senders whose automated mail still belongs in the inbox: alerts you act on.
URGENT_AUTOMATED = ["pagerduty.com", "opsgenie.com", "statuspage.io"]


def evaluate():
    sender_type = sender_class()
    log_entry("class=" + sender_type + " human_score=" + str(int(human_score())))

    # A reply to a thread you are already in is correspondence regardless of
    # what generated it, so this check comes before any bulk filtering.
    if is_threaded() and not is_bulk():
        add_header("X-Mail-Class", "conversation")
        accept()
        return

    # Operational alerts are automated but time-critical.
    for domain in URGENT_AUTOMATED:
        if same_org_domain(from_domain(), domain):
            add_header("X-Mail-Class", "alert")
            fileinto("Alerts")
            return

    if sender_type == "human":
        add_header("X-Mail-Class", "human")
        accept()
        return

    if sender_type == "transactional":
        # Receipts, password resets, shipping notices: wanted, but not
        # conversation.
        add_header("X-Mail-Class", "transactional")
        fileinto("Receipts")
        return

    if sender_type == "list":
        add_header("X-Mail-Class", "list")
        fileinto("Lists")
        return

    if sender_type == "bulk":
        add_header("X-Mail-Class", "bulk")

        # Bulk mail that cannot be unsubscribed from is not a newsletter.
        if not has_unsubscribe():
            log_entry("bulk mail with no unsubscribe mechanism")
            fileinto("Junk")
            return

        fileinto("Bulk")
        return

    if sender_type == "automated":
        add_header("X-Mail-Class", "automated")
        fileinto("Notifications")
        return

    # Unclear. Record the evidence so the classification can be tuned, and
    # deliver rather than guess.
    for reason in human_reasons():
        log_entry("  " + reason)
    add_header("X-Mail-Class", "unknown")
    accept()
