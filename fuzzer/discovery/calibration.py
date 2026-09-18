"""
Module 1 — Soft-404 / Wildcard Calibration.

Before trusting any scan result, probe the target with a few random,
almost-certainly-nonexistent paths and record how it responds. Many
targets don't return a clean 404 for missing resources: they return
200 with a custom error page, a wildcard/catch-all page, or an SPA's
index.html for every unknown route. Treating every 200 as "found"
against such a target produces near-100% false positives.

`calibrate()` builds a CalibrationBaseline once per scan; `matches()`
lets any later result be checked against it. This module only produces
the baseline and the match check — deciding what to do with a match
(penalize confidence, suppress, etc.) belongs to Module 2.
"""
import random
import string
from dataclasses import dataclass, field
from typing import List, Optional

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import HTTPResult

DEFAULT_PROBE_COUNT = 3
DEFAULT_LENGTH_TOLERANCE = 25  # bytes of allowed spread before responses count as "different"
RANDOM_PATH_LENGTH = 10

# Kept centralized (not scattered through classification logic) so the
# heuristics can be tuned in one place.
_SPA_MARKERS = ('id="root"', "id='root'", 'id="app"', "id='app'", 'id="__next"')
_ERROR_KEYWORDS = ("not found", "404", "page not found", "does not exist", "page you requested")


def _random_nonsense_path(length: int = RANDOM_PATH_LENGTH) -> str:
    charset = string.ascii_lowercase + string.digits
    return "/" + "".join(random.choice(charset) for _ in range(length))


@dataclass
class CalibrationBaseline:
    """What "nothing is really there" looks like on this target."""

    classification: str  # "normal_404"|"soft_404"|"wildcard"|"spa_fallback"|"custom_error"|"inconsistent"
    is_consistent: bool  # did the probes agree with each other at all?
    status_code: Optional[int]
    length: Optional[int]  # average length across probes, when consistent
    length_tolerance: int
    samples: List[HTTPResult] = field(default_factory=list)

    def matches(self, result: HTTPResult) -> bool:
        """True if `result` is indistinguishable from this target's known fake response."""
        if not self.is_consistent or self.status_code is None or self.length is None:
            return False
        if result.status_code != self.status_code:
            return False
        return abs(result.response_length - self.length) <= self.length_tolerance

    def length_delta(self, result: HTTPResult) -> Optional[int]:
        """Byte distance from the baseline length, or None if there's no baseline to compare to."""
        if self.length is None:
            return None
        return abs(result.response_length - self.length)


def _classify(status_code: int, body_snippet: str) -> str:
    lowered = body_snippet.lower()
    if status_code == 404:
        return "normal_404"
    if status_code >= 400:
        return "custom_error"
    if any(marker in lowered for marker in _SPA_MARKERS):
        return "spa_fallback"
    if any(keyword in lowered for keyword in _ERROR_KEYWORDS):
        return "soft_404"
    return "wildcard"


async def calibrate(
    base_url: str,
    client: Optional[HTTPClient] = None,
    probe_count: int = DEFAULT_PROBE_COUNT,
    length_tolerance: int = DEFAULT_LENGTH_TOLERANCE,
) -> CalibrationBaseline:
    """
    Probe `base_url` with `probe_count` random nonexistent paths and
    return a CalibrationBaseline describing how the target behaves for
    resources that don't exist. Does not assume 200 == real, and does
    not hard-code any particular site's response shape.
    """
    client = client or HTTPClient()
    samples: List[HTTPResult] = []
    for _ in range(max(1, probe_count)):
        url = base_url.rstrip("/") + _random_nonsense_path()
        samples.append(await client.request("GET", url))

    statuses = {s.status_code for s in samples}
    lengths = [s.response_length for s in samples]
    length_spread = (max(lengths) - min(lengths)) if lengths else 0
    is_consistent = len(statuses) == 1 and length_spread <= length_tolerance

    if not is_consistent:
        # Probes disagreed with each other (e.g. random 404/200 mix, or
        # wildly different body sizes) — there's no single reliable
        # baseline to compare real scan results against.
        return CalibrationBaseline(
            classification="inconsistent",
            is_consistent=False,
            status_code=None,
            length=None,
            length_tolerance=length_tolerance,
            samples=samples,
        )

    status_code = samples[0].status_code
    avg_length = round(sum(lengths) / len(lengths))
    classification = _classify(status_code, samples[0].body_snippet)

    return CalibrationBaseline(
        classification=classification,
        is_consistent=True,
        status_code=status_code,
        length=avg_length,
        length_tolerance=length_tolerance,
        samples=samples,
    )
