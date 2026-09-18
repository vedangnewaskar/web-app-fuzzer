"""
Module 1 tests — Soft-404 / Wildcard Calibration.

Uses a scripted fake HTTPClient (no real network / aiohttp needed) so
these tests run anywhere, and cover exactly the four scenarios called
out in the spec:
  1. Normal 404 server
  2. Soft-404 server
  3. Wildcard / SPA-style server
  4. A real resource that differs from the fake baseline is not suppressed
"""
import asyncio
import unittest

from fuzzer.core.models import HTTPResult
from fuzzer.discovery.calibration import (
    DEFAULT_LENGTH_TOLERANCE,
    CalibrationBaseline,
    calibrate,
)


class FakeClient:
    """Test double for HTTPClient. `responder(url)` returns a canned HTTPResult."""

    def __init__(self, responder):
        self._responder = responder

    async def request(self, method, url):
        return self._responder(url)


def _run(coro):
    return asyncio.run(coro)


class CalibrationTests(unittest.TestCase):
    def test_normal_404_server(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=404, response_length=9,
                response_time=0.01, headers={}, body_snippet="Not Found",
            )

        baseline = _run(calibrate("http://example.test", client=FakeClient(responder)))
        self.assertEqual(baseline.classification, "normal_404")
        self.assertTrue(baseline.is_consistent)
        self.assertEqual(baseline.status_code, 404)

    def test_soft_404_server(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=512,
                response_time=0.01, headers={}, body_snippet="<html>Sorry, page not found</html>",
            )

        baseline = _run(calibrate("http://example.test", client=FakeClient(responder)))
        self.assertEqual(baseline.classification, "soft_404")
        self.assertTrue(baseline.is_consistent)
        self.assertEqual(baseline.status_code, 200)

    def test_spa_fallback_server(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=1500,
                response_time=0.01, headers={}, body_snippet='<div id="root"></div>',
            )

        baseline = _run(calibrate("http://example.test", client=FakeClient(responder)))
        self.assertEqual(baseline.classification, "spa_fallback")

    def test_wildcard_server(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=15234,
                response_time=0.01, headers={}, body_snippet="<html>Welcome to our site</html>",
            )

        baseline = _run(calibrate("http://example.test", client=FakeClient(responder)))
        self.assertEqual(baseline.classification, "wildcard")

    def test_inconsistent_server_has_no_usable_baseline(self):
        lengths = iter([100, 900, 50])

        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=next(lengths),
                response_time=0.01, headers={}, body_snippet="",
            )

        baseline = _run(calibrate("http://example.test", client=FakeClient(responder)))
        self.assertFalse(baseline.is_consistent)
        self.assertEqual(baseline.classification, "inconsistent")
        self.assertIsNone(baseline.status_code)
        self.assertIsNone(baseline.length)

    def test_fake_response_suppressed_real_resource_is_not(self):
        # Example from the spec: /random1..3 -> 200, 15234 bytes every time.
        baseline = CalibrationBaseline(
            classification="wildcard", is_consistent=True, status_code=200,
            length=15234, length_tolerance=DEFAULT_LENGTH_TOLERANCE, samples=[],
        )

        fake_admin = HTTPResult(
            url="http://example.test/admin", method="GET", status_code=200,
            response_length=15234, response_time=0.01, headers={}, body_snippet="",
        )
        real_admin = HTTPResult(
            url="http://example.test/admin", method="GET", status_code=200,
            response_length=842, response_time=0.01, headers={}, body_snippet="",
        )

        self.assertTrue(baseline.matches(fake_admin))   # should be flagged as noise
        self.assertFalse(baseline.matches(real_admin))  # genuinely differs -> not suppressed

    def test_status_code_alone_does_not_trigger_a_match(self):
        # A 200 with a wildly different length from the baseline must not match,
        # even though the status code matches — "do not assume 200 == valid" cuts
        # both ways: it also must not treat *every* 200 as noise.
        baseline = CalibrationBaseline(
            classification="wildcard", is_consistent=True, status_code=200,
            length=15234, length_tolerance=DEFAULT_LENGTH_TOLERANCE, samples=[],
        )
        different_length = HTTPResult(
            url="http://example.test/backup.zip", method="GET", status_code=200,
            response_length=99, response_time=0.01, headers={}, body_snippet="",
        )
        self.assertFalse(baseline.matches(different_length))


if __name__ == "__main__":
    unittest.main()
