"""
Module 2 — Confidence Scoring.

Replaces binary found/not-found logic with a transparent 0-100
confidence score built from a small, fixed set of independently
weighted signals. This is deliberately NOT a black-box model: every
point in the final score traces back to exactly one signal below, and
the full breakdown is kept on FuzzResult.signals so a person can see
why a score is what it is.

Confidence is never treated as proof — see `confirmation_for()`.
"""
from typing import Dict, Optional

from fuzzer.core.models import FuzzResult, HTTPResult
from fuzzer.discovery.calibration import CalibrationBaseline

# Max points each signal can contribute. Positive weights sum to 100 so a
# "perfect" result reads as confidence=100; soft_404_penalty is a ceiling
# on how much a baseline match can subtract, not a positive weight.
# Centralized here (not scattered through the scoring logic) so tuning
# doesn't require touching the functions themselves.
DEFAULT_WEIGHTS: Dict[str, int] = {
    "status": 40,
    "length_delta": 35,
    "keyword": 15,
    "response_time": 10,
    "soft_404_penalty": -100,
}

# Suggested interpretation bands from the spec, kept configurable rather
# than hard-coded into classify_confidence()/confirmation_for().
DEFAULT_THRESHOLDS: Dict[str, int] = {
    "very_low": 0,
    "low": 30,
    "medium": 50,
    "high": 70,
    "very_high": 85,
}

# How "sure" each status code is, relative to the max "status" weight.
# 404/410 score 0 outright; everything else is scaled down from a clean
# 200. Centralized mapping instead of magic numbers inline.
_STATUS_SCORE_RATIO: Dict[int, float] = {
    200: 1.0,
    201: 1.0,
    204: 0.9,
    301: 0.7,
    302: 0.7,
    307: 0.7,
    308: 0.7,
    401: 0.6,  # gated, but "something is there" is still a real signal
    403: 0.6,
    405: 0.5,  # method not allowed still implies the route exists
    500: 0.3,  # errors on access -- weak, could also be noise
    502: 0.15,
    503: 0.15,
    404: 0.0,
    410: 0.0,
}

# Small, centralized keyword list. Not exhaustive by design -- this is
# one signal among several, not the sole basis for a finding.
INTERESTING_KEYWORDS = (
    "index of", "login", "admin", "dashboard", "unauthorized", "forbidden",
    "welcome", "password", "config", "backup", "api", "root:x:0:0",
)


def _status_score(status_code: int, max_points: int) -> float:
    ratio = _STATUS_SCORE_RATIO.get(status_code)
    if ratio is None:
        ratio = 0.4 if 200 <= status_code < 400 else 0.1
    return round(ratio * max_points, 2)


def _length_delta_score(
    http_result: HTTPResult, baseline: Optional[CalibrationBaseline], max_points: int
) -> float:
    if baseline is None or baseline.length is None:
        return 0.0
    delta = abs(http_result.response_length - baseline.length)
    if delta <= baseline.length_tolerance:
        return 0.0
    # Scale to full points once delta is well past the tolerance band, so
    # a difference of a few bytes over tolerance doesn't overclaim.
    scale_at = max(baseline.length_tolerance * 10, 100)
    ratio = min(delta / scale_at, 1.0)
    return round(ratio * max_points, 2)


def _keyword_score(body_snippet: str, max_points: int) -> float:
    lowered = body_snippet.lower()
    hits = sum(1 for kw in INTERESTING_KEYWORDS if kw in lowered)
    if hits == 0:
        return 0.0
    ratio = min(hits / 3, 1.0)  # 3+ distinct keyword hits = full points
    return round(ratio * max_points, 2)


def _response_time_score(
    http_result: HTTPResult, baseline: Optional[CalibrationBaseline], max_points: int
) -> float:
    if baseline is None or not baseline.samples:
        return 0.0
    baseline_times = [s.response_time for s in baseline.samples]
    avg_baseline_time = sum(baseline_times) / len(baseline_times)
    if avg_baseline_time <= 0:
        return 0.0
    delta_ratio = abs(http_result.response_time - avg_baseline_time) / avg_baseline_time
    ratio = min(delta_ratio, 1.0)
    return round(ratio * max_points, 2)


def _soft_404_penalty(
    baseline: Optional[CalibrationBaseline], http_result: HTTPResult, max_penalty: int
) -> float:
    if baseline is None or not baseline.matches(http_result):
        return 0.0
    return float(max_penalty)  # max_penalty is <= 0


def classify_confidence(confidence: int, thresholds: Dict[str, int]) -> str:
    """Maps a 0-100 score onto the suggested bands: very_low..very_high."""
    if confidence >= thresholds["very_high"]:
        return "very_high"
    if confidence >= thresholds["high"]:
        return "high"
    if confidence >= thresholds["medium"]:
        return "medium"
    if confidence >= thresholds["low"]:
        return "low"
    return "very_low"


def confirmation_for(confidence: int, thresholds: Dict[str, int]) -> str:
    """
    A score is never proof by itself. Below the "low" threshold a result
    is a "candidate" (barely worth a human's time); at or above it,
    "suspected". "confirmed" is reserved for findings independently
    verified by other means (e.g. Module 4's traversal signature match)
    -- never assigned from confidence alone, however high.
    """
    if confidence < thresholds["low"]:
        return "candidate"
    return "suspected"


def score_result(
    fuzz_result: FuzzResult,
    http_result: HTTPResult,
    baseline: Optional[CalibrationBaseline] = None,
    weights: Optional[Dict[str, int]] = None,
    thresholds: Optional[Dict[str, int]] = None,
) -> FuzzResult:
    """
    Compute a 0-100 confidence score for `fuzz_result` and mutate it in
    place: sets `confidence`, merges the signal breakdown into
    `signals`, and sets `confirmation`. Returns `fuzz_result` for
    convenient chaining.
    """
    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS

    status = _status_score(http_result.status_code, weights["status"])
    length_delta = _length_delta_score(http_result, baseline, weights["length_delta"])
    keyword = _keyword_score(http_result.body_snippet, weights["keyword"])
    response_time = _response_time_score(http_result, baseline, weights["response_time"])
    soft_404_penalty = _soft_404_penalty(baseline, http_result, weights["soft_404_penalty"])

    raw_total = status + length_delta + keyword + response_time + soft_404_penalty
    confidence = int(round(max(0.0, min(100.0, raw_total))))

    fuzz_result.confidence = confidence
    fuzz_result.signals.update({
        "status": status,
        "length_delta": length_delta,
        "keyword": keyword,
        "response_time": response_time,
        "soft_404_penalty": soft_404_penalty,
    })
    fuzz_result.confirmation = confirmation_for(confidence, thresholds)

    return fuzz_result
