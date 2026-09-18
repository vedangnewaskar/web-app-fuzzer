"""
Module 2 tests — Confidence Scoring.

Covers exactly the scenarios called out in the spec: 200, 301/302, 404,
large vs small length differences, a keyword match, and a soft-404
match -- plus a sweep asserting every score stays within 0-100.
"""
import unittest

from fuzzer.core.models import FuzzResult, HTTPResult
from fuzzer.discovery.calibration import DEFAULT_LENGTH_TOLERANCE, CalibrationBaseline
from fuzzer.discovery.scoring import (
    DEFAULT_THRESHOLDS,
    DEFAULT_WEIGHTS,
    classify_confidence,
    score_result,
)


def _http(status=200, length=1000, body="", time=0.05):
    return HTTPResult(
        url="http://example.test/x", method="GET", status_code=status,
        response_length=length, response_time=time, headers={}, body_snippet=body,
    )


def _fuzz():
    return FuzzResult(path="/x", url="http://example.test/x", status_code=0, length=0)


def _baseline(status=404, length=9, tolerance=DEFAULT_LENGTH_TOLERANCE, consistent=True, samples=None):
    return CalibrationBaseline(
        classification="normal_404" if status == 404 else "wildcard",
        is_consistent=consistent, status_code=status, length=length,
        length_tolerance=tolerance, samples=samples or [],
    )


class ScoringTests(unittest.TestCase):
    def test_200_response_scores_higher_than_404(self):
        baseline = _baseline()
        r200 = score_result(_fuzz(), _http(status=200, length=8000), baseline=baseline)
        r404 = score_result(_fuzz(), _http(status=404, length=9), baseline=baseline)
        self.assertGreater(r200.confidence, r404.confidence)
        self.assertEqual(r404.confidence, 0)  # exact baseline match -> fully suppressed

    def test_redirect_scores_lower_than_200_but_above_zero(self):
        baseline = _baseline()
        r301 = score_result(_fuzz(), _http(status=301, length=500), baseline=baseline)
        self.assertGreater(r301.confidence, 0)
        self.assertLess(r301.signals["status"], DEFAULT_WEIGHTS["status"])

    def test_404_response_is_zero_or_near_zero(self):
        baseline = _baseline()
        result = score_result(_fuzz(), _http(status=404, length=9), baseline=baseline)
        self.assertEqual(result.confidence, 0)

    def test_large_length_difference_scores_higher_than_small(self):
        baseline = _baseline(status=200, length=15234)
        small_diff = score_result(_fuzz(), _http(status=200, length=15260), baseline=baseline)
        large_diff = score_result(_fuzz(), _http(status=200, length=800), baseline=baseline)
        self.assertGreater(large_diff.signals["length_delta"], small_diff.signals["length_delta"])

    def test_keyword_match_adds_points(self):
        baseline = _baseline()
        with_keyword = score_result(
            _fuzz(), _http(status=200, length=500, body="Admin Dashboard Login"), baseline=baseline
        )
        without_keyword = score_result(
            _fuzz(), _http(status=200, length=500, body="hello world"), baseline=baseline
        )
        self.assertGreater(with_keyword.signals["keyword"], 0)
        self.assertEqual(without_keyword.signals["keyword"], 0)
        self.assertGreater(with_keyword.confidence, without_keyword.confidence)

    def test_soft_404_match_suppresses_confidence_even_with_keywords(self):
        # The spec's core example: baseline is 200/15234 bytes; a real path
        # that happens to land exactly on that baseline must not score high,
        # even if it happens to contain an interesting keyword.
        baseline = _baseline(status=200, length=15234)
        result = score_result(
            _fuzz(), _http(status=200, length=15234, body="Welcome admin"), baseline=baseline
        )
        self.assertEqual(result.signals["soft_404_penalty"], DEFAULT_WEIGHTS["soft_404_penalty"])
        self.assertEqual(result.confidence, 0)

    def test_confidence_always_within_bounds(self):
        baseline = _baseline(status=200, length=15234)
        scenarios = [
            (200, 15234, ""), (200, 1, "admin login password backup"),
            (404, 9, ""), (301, 0, ""), (500, 999999, "root:x:0:0"),
            (403, 15234, "forbidden"),
        ]
        for status, length, body in scenarios:
            result = score_result(_fuzz(), _http(status=status, length=length, body=body), baseline=baseline)
            self.assertGreaterEqual(result.confidence, 0)
            self.assertLessEqual(result.confidence, 100)

    def test_no_baseline_still_produces_a_bounded_score(self):
        result = score_result(_fuzz(), _http(status=200, length=5000, body="admin"), baseline=None)
        self.assertGreaterEqual(result.confidence, 0)
        self.assertLessEqual(result.confidence, 100)
        self.assertEqual(result.signals["soft_404_penalty"], 0.0)

    def test_confirmation_is_candidate_below_low_threshold_else_suspected(self):
        self.assertEqual(classify_confidence(10, DEFAULT_THRESHOLDS), "very_low")
        self.assertEqual(classify_confidence(95, DEFAULT_THRESHOLDS), "very_high")
        low_conf = score_result(_fuzz(), _http(status=404, length=9), baseline=_baseline())
        self.assertEqual(low_conf.confirmation, "candidate")

    def test_confirmation_is_never_set_to_confirmed_by_scoring_alone(self):
        # "confirmed" is reserved for Module 4's independent signature check.
        baseline = _baseline(status=200, length=15234)
        result = score_result(
            _fuzz(), _http(status=200, length=200, body="admin login dashboard password"), baseline=baseline
        )
        self.assertIn(result.confirmation, ("candidate", "suspected"))
        self.assertNotEqual(result.confirmation, "confirmed")


if __name__ == "__main__":
    unittest.main()
