"""Outbound metadata-minimization policy module."""

def apply_privacy():
    protect_metadata("standard", extra=[
        "X-Internal-Trace",
        "X-Backend-Server",
        "X-Employee-ID",
    ])

