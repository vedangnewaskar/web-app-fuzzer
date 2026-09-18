"""
Directory / file discovery scan.

Base Phase 0 scanner (load a wordlist, request each candidate path)
extended by Tier 1: each result is calibrated against the target's
soft-404 baseline (Module 1) and given a 0-100 confidence score
(Module 2). Recursion (Module 6) and mutation follow-up (Module 3)
wrap `run_directory_scan` rather than duplicating it.

Module 11 adds differential structural response parsing:
responses are compared against the calibration response structure
to detect meaningful changes in HTML/JSON response shape.
"""

import asyncio
from typing import List, Optional
from urllib.parse import urlsplit

from fuzzer.discovery.structural import (
    structural_fingerprint,
    compare_structures,
)

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import CalibrationBaseline
from fuzzer.discovery.calibration import calibrate as calibrate_target
from fuzzer.discovery.critical_tags import tag_critical_exposure
from fuzzer.discovery.scoring import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    score_result,
)


def load_wordlist(path: str) -> List[str]:
    """Read a newline-delimited wordlist, skipping blanks and comments."""
    words: List[str] = []

    with open(path, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()

            if line and not line.startswith("#"):
                words.append(line)

    return words


def _has_file_extension(word: str) -> bool:
    """True if the last path segment looks like it names a file."""
    last_segment = word.rstrip("/").rsplit("/", 1)[-1]

    return "." in last_segment.lstrip(".")


def _classify_type(word: str, http_result) -> str:
    """
    Directory vs. file classification.

    A wordlist entry with a file extension is classified as a file.
    Everything else is treated as a directory candidate.
    """

    if _has_file_extension(word):
        return "file"

    return "directory"


def _redirected_to_directory(http_result) -> bool:
    """
    True if the response shows evidence of a redirect onto a
    slash-terminated URL.
    """

    if http_result.status_code in (301, 302, 307, 308):
        return True

    requested = http_result.url.split("?")[0]
    resolved = (http_result.resolved_url or "").split("?")[0]

    if resolved and resolved != requested and resolved.endswith("/"):
        return True

    if (
        http_result.location_header
        and http_result.location_header.split("?")[0].endswith("/")
    ):
        return True

    return False


def _baseline_structural_fingerprint(
    baseline: Optional[CalibrationBaseline],
) -> Optional[dict]:
    """
    Build a structural fingerprint from the first calibration response.

    The calibration samples already contain the complete HTTPResult,
    including the full response body captured by HTTPClient.
    """

    if baseline is None or not baseline.samples:
        return None

    sample = baseline.samples[0]

    content_type = sample.headers.get("Content-Type", "")

    return structural_fingerprint(
        sample.body,
        content_type,
    )


async def _fetch_one(
    client: HTTPClient,
    base_url: str,
    word: str,
    semaphore: asyncio.Semaphore,
    baseline: Optional[CalibrationBaseline],
    baseline_structure: Optional[dict],
    weights: dict,
    thresholds: dict,
) -> FuzzResult:

    path = "/" + word.lstrip("/")

    url = base_url.rstrip("/") + path

    async with semaphore:
        http_result = await client.request("GET", url)

    result_type = _classify_type(
        word,
        http_result,
    )

    # Derived from the full request URL.
    # This preserves the complete hierarchy during recursive scanning.
    full_path = urlsplit(url).path or "/"

    fuzz_result = FuzzResult.from_http_result(
        http_result,
        path=full_path,
        type_=result_type,
    )

    # Redirect information.
    if _redirected_to_directory(http_result):
        fuzz_result.signals["redirected_to_directory"] = 1.0

    # ------------------------------------------------------------------
    # Module 11 — Differential structural response parsing
    # ------------------------------------------------------------------

    if baseline_structure is not None:

        content_type = http_result.headers.get(
            "Content-Type",
            "",
        )

        payload_structure = structural_fingerprint(
            http_result.body,
            content_type,
        )

        structural_comparison = compare_structures(
            baseline_structure,
            payload_structure,
        )

        fuzz_result.signals["structural_change"] = (
            1.0
            if structural_comparison["changed"]
            else 0.0
        )

        if structural_comparison["changed"]:

            fuzz_result.note = (
                fuzz_result.note + "; "
                if fuzz_result.note
                else ""
            ) + (
                "response structure differs "
                "from calibration baseline"
            )

    # ------------------------------------------------------------------
    # Module 1 — Soft-404 / wildcard calibration
    # ------------------------------------------------------------------

    if baseline is not None:

        delta = baseline.length_delta(
            http_result,
        )

        fuzz_result.signals["soft_404_match"] = (
            1.0
            if baseline.matches(http_result)
            else 0.0
        )

        if delta is not None:
            fuzz_result.signals[
                "baseline_length_delta"
            ] = float(delta)

        if baseline.matches(http_result):

            fuzz_result.note = (
                f"matches calibration baseline "
                f"({baseline.classification}); "
                f"likely false positive"
            )

    # ------------------------------------------------------------------
    # Module 2 — Confidence scoring
    # ------------------------------------------------------------------

    score_result(
        fuzz_result,
        http_result,
        baseline=baseline,
        weights=weights,
        thresholds=thresholds,
    )

    # ------------------------------------------------------------------
    # Module 7 — Critical exposure tagging
    # ------------------------------------------------------------------

    tag_critical_exposure(
        fuzz_result,
    )

    return fuzz_result


async def run_directory_scan(
    base_url: str,
    wordlist_path: Optional[str] = None,
    client: Optional[HTTPClient] = None,
    concurrency: int = 10,
    baseline: Optional[CalibrationBaseline] = None,
    auto_calibrate: bool = True,
    weights: Optional[dict] = None,
    thresholds: Optional[dict] = None,
    words: Optional[List[str]] = None,
) -> List[FuzzResult]:
    """
    Fuzz `base_url` with every entry in the wordlist at `wordlist_path`
    or with `words` directly.

    Exactly one of `wordlist_path` / `words` must be provided.

    `client` can be passed in so callers such as recursion and mutation
    follow-up reuse the same HTTPClient.

    `baseline` can be passed in to reuse a CalibrationBaseline already
    computed for this target.

    If omitted and `auto_calibrate` is True, this function calibrates
    against `base_url` before scanning.

    Module 11 derives a structural baseline from the calibration
    response and compares every fuzz response against it.
    """

    client = client or HTTPClient()

    # --------------------------------------------------------------
    # Module 1 — Calibration
    # --------------------------------------------------------------

    if baseline is None and auto_calibrate:
        baseline = await calibrate_target(
            base_url,
            client=client,
        )

    # --------------------------------------------------------------
    # Module 11 — Build structural baseline
    # --------------------------------------------------------------

    baseline_structure = _baseline_structural_fingerprint(
        baseline,
    )

    # --------------------------------------------------------------
    # Module 2 — Scoring configuration
    # --------------------------------------------------------------

    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS

    # --------------------------------------------------------------
    # Load scan targets
    # --------------------------------------------------------------

    if words is None:

        if not wordlist_path:
            raise ValueError(
                "run_directory_scan requires either "
                "wordlist_path or words"
            )

        words = load_wordlist(
            wordlist_path,
        )

    semaphore = asyncio.Semaphore(
        max(1, concurrency),
    )

    # --------------------------------------------------------------
    # Execute requests
    # --------------------------------------------------------------

    tasks = [
        _fetch_one(
            client,
            base_url,
            word,
            semaphore,
            baseline,
            baseline_structure,
            weights,
            thresholds,
        )
        for word in words
    ]

    return await asyncio.gather(
        *tasks,
    )