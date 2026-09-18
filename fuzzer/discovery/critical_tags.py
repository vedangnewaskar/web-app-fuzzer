"""
Module 7 — Critical-Exposure Auto-Tagging.

Centralized rule list for resources that are high-risk *if* they turn
out to be real -- finding a path matching one of these rules is never
treated as proof anything is actually exposed (that's what
`confidence`/`confirmation` are for). This module only answers "is this
the *kind* of resource that would be a serious problem to have
exposed", independent of how confident the scan is that it's really
there.

`severity` grades how bad a confirmed exposure of that resource would
be; `critical` is a simpler boolean (True for any rule match at all,
regardless of grade) so a frontend/report can filter "did Module 7
flag this" without inspecting the severity string.
"""
import re
from typing import List, NamedTuple, Optional

from fuzzer.core.models import FuzzResult


class CriticalRule(NamedTuple):
    pattern: "re.Pattern"
    category: str
    severity: str  # "critical" | "high" | "medium" | "low"
    note: str


def _rule(pattern: str, category: str, severity: str, note: str) -> CriticalRule:
    return CriticalRule(re.compile(pattern, re.IGNORECASE), category, severity, note)


# Centralized so the rule set can be reviewed/extended in one place.
# Patterns match against the path with any leading slash stripped, so
# `(^|/)` anchors "at the start, or right after a directory separator"
# -- i.e. matches both "/.env" and "/some/dir/.env".
CRITICAL_EXPOSURE_RULES: List[CriticalRule] = [
    _rule(r"(^|/)\.git/config$", "vcs_exposure", "critical",
          "Exposed .git/config can reveal repository remotes and, in some setups, embedded credentials."),
    _rule(r"(^|/)\.git/HEAD$", "vcs_exposure", "high",
          "Exposed .git/HEAD suggests the full .git directory may be browsable, risking source code disclosure."),
    _rule(r"(^|/)\.env$", "config_exposure", "critical",
          "Potential exposure of application configuration or secrets -- .env files commonly hold API keys and credentials."),
    _rule(r"(^|/)id_rsa$", "credential_exposure", "critical",
          "Potential exposure of an SSH private key -- would allow impersonation if the key is valid and unencrypted."),
    _rule(r"(^|/)id_rsa\.pub$", "credential_exposure", "low",
          "An exposed public key alone is low risk, but signals a matching private key may exist nearby."),
    _rule(r"wp-config\.php(\.bak|\.old|~)?$", "config_exposure", "critical",
          "WordPress configuration (or a backup of it) commonly contains database credentials and secret keys."),
    _rule(r"(^|/)\.htpasswd$", "credential_exposure", "high",
          "Potential exposure of hashed credentials for a protected area."),
    _rule(r"(^|/)\.aws/credentials$", "credential_exposure", "critical",
          "Potential exposure of AWS credentials -- could grant access to cloud infrastructure if valid."),
    _rule(r"(^|/)docker-compose\.ya?ml$", "config_exposure", "medium",
          "docker-compose files sometimes embed environment variables or credentials."),
    _rule(r"\.sql(\.gz|\.bak)?$", "data_exposure", "high",
          "Potential exposure of a database dump, which could contain application data."),
    _rule(r"(^|/)\.DS_Store$", "info_disclosure", "low",
          ".DS_Store can leak directory/file naming information, though it's rarely sensitive on its own."),
]


def find_critical_rule(path: str) -> Optional[CriticalRule]:
    """Return the first matching rule for `path`, or None. Deterministic
    (rules checked in the order defined above)."""
    normalized = path.lstrip("/")
    for rule in CRITICAL_EXPOSURE_RULES:
        if rule.pattern.search(normalized):
            return rule
    return None


def tag_critical_exposure(result: FuzzResult) -> FuzzResult:
    """
    Mutate `result` in place if its path matches a critical-exposure
    rule: sets `severity`, `critical`, and appends the rule's
    explanation to `note` (without clobbering a note already set by an
    earlier stage, e.g. a calibration-baseline match). Never touches
    `confidence`/`confirmation` -- severity is independent of how sure
    the scan is that the resource is really there. Returns `result`
    for convenient chaining.
    """
    rule = find_critical_rule(result.path)
    if rule is None:
        return result

    result.severity = rule.severity
    result.critical = True
    result.note = f"{result.note} | {rule.note}" if result.note else rule.note

    return result
