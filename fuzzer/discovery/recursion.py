"""
Module 6 — Recursive Auto-Fuzzing.

Wraps `run_directory_scan` (never duplicates it): when a discovered
path looks like a directory and scored confidently enough, fuzz inside
it too, up to a configurable max depth. Guards against infinite
recursion, duplicate/cyclic scans, and excessive request generation.
"""
from typing import Dict, List, Optional, Set

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import calibrate as calibrate_target
from fuzzer.discovery.directories import load_wordlist, run_directory_scan
from fuzzer.discovery.scoring import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS

DEFAULT_MAX_DEPTH = 2
DEFAULT_RECURSE_CONFIDENCE_THRESHOLD = 70  # only descend into "high" confidence (spec's 70-84 band) or above
DEFAULT_MAX_TOTAL_REQUESTS = 2000  # hard ceiling across the entire recursive scan


def looks_like_directory(result: FuzzResult) -> bool:
    """
    Whether a discovered result is worth recursing into. Trusts the
    `type` classification `run_directory_scan` already computed (it had
    full response info -- redirect target, Location header -- that
    isn't retained on FuzzResult), and separately refuses to recurse
    into anything with a file extension even if `type` somehow said
    otherwise, as a second, independent guard against fuzzing files.
    """
    if result.type != "directory":
        return False
    last_segment = result.path.rstrip("/").rsplit("/", 1)[-1]
    if "." in last_segment.lstrip("."):
        return False
    return True


async def run_recursive_scan(
    base_url: str,
    wordlist_path: str,
    client: Optional[HTTPClient] = None,
    concurrency: int = 10,
    max_depth: int = DEFAULT_MAX_DEPTH,
    recurse_confidence_threshold: int = DEFAULT_RECURSE_CONFIDENCE_THRESHOLD,
    max_total_requests: int = DEFAULT_MAX_TOTAL_REQUESTS,
    weights: Optional[dict] = None,
    thresholds: Optional[dict] = None,
) -> List[FuzzResult]:
    """
    Recursively fuzz `base_url`, descending into confidently-discovered
    directories up to `max_depth` (root scan = depth 1). Reuses
    `run_directory_scan` for every level instead of a second scanning
    implementation.

    Protections:
      - `max_depth` caps how many levels deep recursion can go.
      - a visited-URL set means no directory is ever scanned twice,
        even if reached via a different parent or a redirect cycle.
      - `max_total_requests` is a hard budget on requests across the
        whole recursive scan; once a level would exceed it, that level
        (and anything below it) is skipped, but results already
        collected are still returned.
      - only results classified as directories (see looks_like_directory)
        with confidence >= recurse_confidence_threshold are recursed
        into; low-confidence directories and any file are never fuzzed.
    """
    client = client or HTTPClient()
    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS
    word_count = len(load_wordlist(wordlist_path))

    visited_urls: Set[str] = set()
    all_results: List[FuzzResult] = []
    requests_used = 0

    async def _scan_level(target_url: str, depth: int) -> None:
        nonlocal requests_used

        normalized = target_url.rstrip("/")
        if normalized in visited_urls:
            return  # duplicate / cyclic-redirect protection
        visited_urls.add(normalized)

        if requests_used + word_count > max_total_requests:
            return  # request-budget protection: stop expanding, keep what's already collected

        # Module 1 says calibrate before every directory scan -- a
        # soft-404 page scoped to /admin/* can differ from the one at
        # the root, so each level gets its own baseline rather than
        # reusing the root's.
        baseline = await calibrate_target(target_url, client=client)

        level_results = await run_directory_scan(
            target_url, wordlist_path, client=client, concurrency=concurrency,
            baseline=baseline, auto_calibrate=False,
            weights=weights, thresholds=thresholds,
        )
        requests_used += len(level_results)
        all_results.extend(level_results)

        if depth >= max_depth:
            return

        for result in level_results:
            if not looks_like_directory(result):
                continue
            if result.confidence is None or result.confidence < recurse_confidence_threshold:
                continue
            await _scan_level(result.resolved_url or result.url, depth + 1)

    await _scan_level(base_url, depth=1)
    return all_results
