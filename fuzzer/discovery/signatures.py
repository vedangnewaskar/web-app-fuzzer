"""
Module 4 support — centralized sensitive-content signatures.

Used to auto-confirm path traversal findings: a response body that
contains one of these is very unlikely to be a coincidence, unlike a
mere HTTP 200. Kept as a single small, easily-audited mapping rather
than scattered string checks, so it's easy to review exactly what
counts as "confirmed" and to extend without touching classification
logic elsewhere.
"""
from typing import Dict, List, Optional

# Centralized. Each entry should be specific enough that it would
# essentially never appear in an ordinary web response by coincidence.
SENSITIVE_SIGNATURES: Dict[str, List[str]] = {
    "linux_passwd": ["root:x:0:0:"],
    "linux_shadow": ["root:$1$", "root:$6$", "root:!:"],
    "windows_boot_ini": ["[boot loader]"],
    "windows_hosts_file": ["# Copyright (c) 1993-2009 Microsoft Corp"],
}


def find_matching_signature(body_snippet: str) -> Optional[str]:
    """
    Return the name of the first signature category found in
    `body_snippet`, or None if nothing matches. Categories are checked
    in the (deterministic) order they're defined in
    SENSITIVE_SIGNATURES.
    """
    for category, signatures in SENSITIVE_SIGNATURES.items():
        for signature in signatures:
            if signature in body_snippet:
                return category
    return None
