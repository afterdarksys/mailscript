"""Audit destination transport-security publication.

Use this for policy/audit decisions. DANE and MTA-STS describe delivery *to*
a domain; they do not authenticate mail received *from* that domain.
"""

def evaluate():
    domain = from_domain()
    dane = verify_dane(domain)
    tlsrpt = check_tlsrpt(domain)
    sts = check_mta_sts(domain)

    log_entry("transport domain=" + domain + " dane=" + dane["result"] +
              " mta_sts=" + sts["result"] + " tlsrpt=" + tlsrpt["result"])

    if dane["result"] == "insecure":
        add_header("X-Transport-Audit", "dane-downgrade-risk")
    elif sts["result"] == "valid" and sts["mode"] == "enforce":
        add_header("X-Transport-Audit", "mta-sts-enforce")
    accept()

