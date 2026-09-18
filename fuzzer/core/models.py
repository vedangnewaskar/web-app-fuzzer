from dataclasses import dataclass, field
from typing import Dict, Optional


BODY_SNIPPET_LIMIT = 4096  # chars kept for keyword/signature inspection, not the full body


@dataclass
class HTTPResult:
    """Raw result of a single HTTP request. Fields from Phase 0 are unchanged;
    body_snippet is additive (default "") so existing callers/tests aren't affected."""
    url: str
    method: str  # get or post
    status_code: int
    response_length: int
    response_time: float
    headers: Dict[str, str]  # {"Content-Type": "text/html"}
    body_snippet: str = ""  # first BODY_SNIPPET_LIMIT chars of the decoded body
    body: str = ""
    resolved_url: str = ""  # final URL after aiohttp follows redirects (== url if none followed)
    location_header: Optional[str] = None  # raw Location header, present even when redirects aren't followed


@dataclass
class FuzzResult:
    """
    A single fuzzing finding, built on top of an HTTPResult.

    This is intentionally a superset of HTTPResult's fields (rather than
    wrapping it) so existing code / JSON consumers that only look for
    status_code / response_length keep working, while new Tier 1 fields
    default to values that mean "not yet analyzed" until later modules
    (calibration, scoring, etc.) populate them.
    """
    path: str
    url: str
    status_code: int
    length: int
    response_time: float = 0.0
    type: str = "unknown"  # "file" | "directory" | "traversal" | "unknown"
    resolved_url: str = ""  # final URL after redirects, when different from `url`

    # Populated by Tier 1 modules; safe defaults keep this usable standalone.
    confidence: Optional[int] = None          # 0-100, Module 2
    signals: Dict[str, float] = field(default_factory=dict)  # Module 2
    severity: Optional[str] = None            # Module 7
    critical: bool = False                    # Module 7
    confirmation: Optional[str] = None        # "candidate"|"suspected"|"confirmed"
    note: str = ""

    @classmethod
    def from_http_result(cls, result: HTTPResult, path: str, type_: str = "unknown") -> "FuzzResult":
        return cls(
            path=path,
            url=result.url,
            status_code=result.status_code,
            length=result.response_length,
            response_time=result.response_time,
            type=type_,
            resolved_url=result.resolved_url,
        )
