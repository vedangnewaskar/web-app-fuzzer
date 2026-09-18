"""
Path traversal scan.

Base scan (send payloads, record raw results) extended by Tier 1
Module 4: rather than treating any HTTP 200 as "possible
vulnerability", each response body is checked against a centralized
set of known sensitive-content signatures
(fuzzer.discovery.signatures). A signature match sets
confirmation="confirmed"; a response that merely succeeded (2xx)
without a recognizable signature is downgraded to "suspected" rather
than treated as proof; a response that looks like the payload was
simply rejected (4xx/5xx, no signature) is left unclassified
(confirmation=None) rather than reported as a finding at all.
"""
import asyncio
from typing import List, Optional

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import FuzzResult
from fuzzer.discovery.signatures import find_matching_signature

# Small, conservative default payload set. Kept centralized and short by
# design — this is a controlled-testing tool, not an exhaustive traversal
# fuzzer with thousands of encodings.
DEFAULT_TRAVERSAL_PAYLOADS: List[str] = [
    "../../../../etc/passwd",
    "..%2f..%2f..%2f..%2fetc%2fpasswd",
    "..\\..\\..\\..\\windows\\win.ini",
    "....//....//....//etc/passwd",
]

# Traversal isn't run through Module 2's general weighted scorer --
# there's no soft-404 baseline concept for a query-string payload the
# way there is for a directory path. Confidence here is instead
# derived directly from the (far more specific) signature-based
# confirmation below. Centralized rather than inlined so it's
# configurable like every other threshold in this project.
DEFAULT_CONFIDENCE_BY_CONFIRMATION = {
    "confirmed": 95,
    "suspected": 40,
}


async def _fetch_one(
    client: HTTPClient,
    base_url: str,
    param: str,
    payload: str,
    semaphore: asyncio.Semaphore,
    confidence_by_confirmation: dict,
) -> FuzzResult:
    url = f"{base_url.rstrip('/')}/?{param}={payload}"
    async with semaphore:
        http_result = await client.request("GET", url)
    result = FuzzResult.from_http_result(http_result, path=f"/?{param}={payload}", type_="traversal")

    matched_category = find_matching_signature(http_result.body_snippet)
    if matched_category:
        result.confirmation = "confirmed"
        result.note = f"response matches known sensitive-content signature ({matched_category})"
    elif 200 <= http_result.status_code < 300:
        # Do NOT auto-classify every 200 as a vulnerability -- it's a
        # candidate for human review, nothing more, until/unless a
        # signature actually confirms it.
        result.confirmation = "suspected"
        result.note = (
            f"traversal payload against '{param}' returned {http_result.status_code} "
            "but no known signature was found in the response"
        )
    else:
        result.note = (
            f"traversal payload against '{param}' returned {http_result.status_code}; "
            "no evidence the payload succeeded"
        )

    if result.confirmation:
        result.confidence = confidence_by_confirmation.get(result.confirmation)

    return result


async def run_traversal_scan(
    base_url: str,
    param: str = "file",
    payloads: Optional[List[str]] = None,
    client: Optional[HTTPClient] = None,
    concurrency: int = 5,
    confidence_by_confirmation: Optional[dict] = None,
) -> List[FuzzResult]:
    """Send traversal payloads at `param` on `base_url` and return FuzzResults,
    each with confirmation ("confirmed"/"suspected"/None) set by signature
    matching rather than status code alone."""
    client = client or HTTPClient()
    payloads = payloads or DEFAULT_TRAVERSAL_PAYLOADS
    confidence_by_confirmation = confidence_by_confirmation or DEFAULT_CONFIDENCE_BY_CONFIRMATION
    semaphore = asyncio.Semaphore(max(1, concurrency))

    tasks = [
        _fetch_one(client, base_url, param, payload, semaphore, confidence_by_confirmation)
        for payload in payloads
    ]
    return await asyncio.gather(*tasks)
