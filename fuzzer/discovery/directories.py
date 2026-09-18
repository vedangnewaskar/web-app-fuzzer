"""
Directory / file discovery scan.

Base Phase 0 scanner (load a wordlist, request each candidate path)
extended by Tier 1: each result is calibrated against the target's
soft-404 baseline (Module 1) and given a 0-100 confidence score
(Module 2). Recursion (Module 6) and mutation follow-up (Module 3)
wrap `run_directory_scan` rather than duplicating it.
"""
import asyncio
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlsplit

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import CalibrationBaseline
from fuzzer.discovery.calibration import calibrate as calibrate_target
from fuzzer.discovery.critical_tags import tag_critical_exposure
from fuzzer.discovery.scoring import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS, score_result


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
    """True if the last path segment looks like it names a file (has a dot
    after any leading dots, so hidden files like `.env` don't count)."""
    last_segment = word.rstrip("/").rsplit("/", 1)[-1]
    return "." in last_segment.lstrip(".")


def _classify_type(word: str, http_result) -> str:
    """
    Directory vs. file classification.

    Primary signal: a wordlist entry with a file extension (backup.zip,
    config.php) is always a file -- Module 6 relies on this to avoid
    ever recursing into a file. Everything else (no extension) is
    treated as a directory candidate, matching the convention most
    fuzzing wordlists already follow (extensionless entries are routes
    or directories) -- this deliberately does NOT require an explicit
    redirect or trailing slash, since plenty of real servers serve
    `/admin` directly with a 200 and no redirect at all. An observed
    redirect onto a slash-terminated URL, or an explicit 3xx status
    (only visible when follow_redirects=False), is treated as
    additional confirmation but isn't required.
    """
    if _has_file_extension(word):
        return "file"
    return "directory"


def _redirected_to_directory(http_result) -> bool:
    """True if the response shows evidence of a redirect onto a
    slash-terminated URL -- informational only, not used to gate
    directory classification (see _classify_type)."""
    if http_result.status_code in (301, 302, 307, 308):
        return True
    requested = http_result.url.split("?")[0]
    resolved = (http_result.resolved_url or "").split("?")[0]
    if resolved and resolved != requested and resolved.endswith("/"):
        return True
    if http_result.location_header and http_result.location_header.split("?")[0].endswith("/"):
        return True
    return False


async def _fetch_one(
    client: HTTPClient,
    base_url: str,
    word: str,
    semaphore: asyncio.Semaphore,
    baseline: Optional[CalibrationBaseline],
    weights: dict,
    thresholds: dict,
) -> FuzzResult:
    path = "/" + word.lstrip("/")
    url = base_url.rstrip("/") + path
    async with semaphore:
        http_result = await client.request("GET", url)

    result_type = _classify_type(word, http_result)
    # Derived from the full request URL, not the local `path` above --
    # `path` is only relative to whatever level is being scanned right
    # now, but during recursion (Module 6) `base_url` is itself a
    # sub-directory, so the URL's path component is what actually
    # carries the full hierarchy (e.g. "/admin/login", not just
    # "/login"). Matters for Module 5's sitemap tree and for de-duping.
    full_path = urlsplit(url).path or "/"
    fuzz_result = FuzzResult.from_http_result(http_result, path=full_path, type_=result_type)
    if _redirected_to_directory(http_result):
        fuzz_result.signals["redirected_to_directory"] = 1.0

    # Module 1: raw diagnostics against the calibration baseline. Kept
    # distinct from Module 2's weighted breakdown below (different key
    # names) so both are visible for debugging.
    if baseline is not None:
        delta = baseline.length_delta(http_result)
        fuzz_result.signals["soft_404_match"] = 1.0 if baseline.matches(http_result) else 0.0
        if delta is not None:
            fuzz_result.signals["baseline_length_delta"] = float(delta)
        if baseline.matches(http_result):
            fuzz_result.note = (
                f"matches calibration baseline ({baseline.classification}); likely false positive"
            )

    # Module 2: 0-100 confidence score, with the weighted breakdown
    # merged into signals and confirmation set to candidate/suspected.
    # Never assumes 200 == valid -- a baseline match drives confidence
    # toward 0 via soft_404_penalty regardless of status code.
    score_result(fuzz_result, http_result, baseline=baseline, weights=weights, thresholds=thresholds)

    # Module 7: severity/critical tagging is independent of confidence
    # -- a path matching a high-risk rule gets tagged whether the scan
    # is very sure it's there or not (that distinction stays in
    # confidence/confirmation, untouched here).
    tag_critical_exposure(fuzz_result)

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
    (or with `words` directly, when the caller already has an in-memory
    list -- e.g. Module 3's generated mutations -- so it doesn't have
    to round-trip through a temp file just to reuse this function).
    Exactly one of `wordlist_path`/`words` must be given.

    `client` can be passed in so callers (recursion, mutation follow-up)
    reuse the same HTTPClient/config rather than constructing a new one
    per call.

    `baseline` can be passed in to reuse a CalibrationBaseline already
    computed for this target (e.g. by a recursive sub-scan, Module 6).
    If omitted and `auto_calibrate` is True (default), this function
    calibrates against `base_url` itself before scanning.

    `weights`/`thresholds` override the confidence-scoring defaults
    (see fuzzer.discovery.scoring) -- typically sourced from config
    rather than hard-coded per call site.
    """
    client = client or HTTPClient()
    if baseline is None and auto_calibrate:
        baseline = await calibrate_target(base_url, client=client)

    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS

    if words is None:
        if not wordlist_path:
            raise ValueError("run_directory_scan requires either wordlist_path or words")
        words = load_wordlist(wordlist_path)

    semaphore = asyncio.Semaphore(max(1, concurrency))

    tasks = [
        _fetch_one(client, base_url, word, semaphore, baseline, weights, thresholds)
        for word in words
    ]
    return await asyncio.gather(*tasks)
