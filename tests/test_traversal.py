"""
Module 4 tests — Traversal Hit Auto-Confirmation.

Covers exactly what the spec asks for: a response containing a known
signature ("root:x:0:0:") is confirmed, a response without one is not
auto-classified as confirmed just because it returned 200.
"""
import asyncio
import unittest
from unittest.mock import patch

from fuzzer.core.models import HTTPResult
from fuzzer.discovery import traversal
from fuzzer.discovery.signatures import find_matching_signature


class SignatureTests(unittest.TestCase):
    def test_linux_passwd_signature_is_detected(self):
        body = "root:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin"
        self.assertEqual(find_matching_signature(body), "linux_passwd")

    def test_windows_boot_ini_signature_is_detected(self):
        body = "[boot loader]\ntimeout=30\ndefault=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS"
        self.assertEqual(find_matching_signature(body), "windows_boot_ini")

    def test_ordinary_response_has_no_signature_match(self):
        body = "<html><body><h1>Welcome to our site</h1></body></html>"
        self.assertIsNone(find_matching_signature(body))


class FakeClient:
    def __init__(self, responder):
        self._responder = responder

    async def request(self, method, url):
        return self._responder(url)


def _run(coro):
    return asyncio.run(coro)


class TraversalConfirmationTests(unittest.TestCase):
    def test_signature_present_is_confirmed(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=500,
                response_time=0.02, headers={}, body_snippet="root:x:0:0:root:/root:/bin/bash",
            )

        results = _run(traversal.run_traversal_scan(
            "http://example.test", payloads=["../../../etc/passwd"], client=FakeClient(responder),
        ))
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0].type, "traversal")
        self.assertEqual(results[0].confirmation, "confirmed")
        self.assertEqual(results[0].confidence, traversal.DEFAULT_CONFIDENCE_BY_CONFIRMATION["confirmed"])

    def test_signature_absent_on_200_is_suspected_not_confirmed(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=200,
                response_time=0.02, headers={}, body_snippet="<html>just a normal page</html>",
            )

        results = _run(traversal.run_traversal_scan(
            "http://example.test", payloads=["../../../etc/passwd"], client=FakeClient(responder),
        ))
        self.assertEqual(results[0].confirmation, "suspected")
        self.assertNotEqual(results[0].confirmation, "confirmed")
        self.assertEqual(results[0].confidence, traversal.DEFAULT_CONFIDENCE_BY_CONFIRMATION["suspected"])

    def test_404_response_is_left_unclassified(self):
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=404, response_length=9,
                response_time=0.02, headers={}, body_snippet="Not Found",
            )

        results = _run(traversal.run_traversal_scan(
            "http://example.test", payloads=["../../../etc/passwd"], client=FakeClient(responder),
        ))
        self.assertIsNone(results[0].confirmation)
        self.assertIsNone(results[0].confidence)

    def test_200_with_signature_is_confirmed_even_though_a_plain_200_is_only_suspected(self):
        # Direct regression test for the spec's core complaint: HTTP 200
        # alone must never be enough for "confirmed".
        def signature_responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=900,
                response_time=0.02, headers={}, body_snippet="...root:x:0:0:root:/root:/bin/bash...",
            )

        def plain_responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=200, response_length=900,
                response_time=0.02, headers={}, body_snippet="<html>ordinary 200 response</html>",
            )

        confirmed = _run(traversal.run_traversal_scan(
            "http://example.test", payloads=["p"], client=FakeClient(signature_responder),
        ))[0]
        suspected = _run(traversal.run_traversal_scan(
            "http://example.test", payloads=["p"], client=FakeClient(plain_responder),
        ))[0]

        self.assertEqual(confirmed.status_code, suspected.status_code)  # same status code...
        self.assertNotEqual(confirmed.confirmation, suspected.confirmation)  # ...different classification

    def test_existing_traversal_scan_still_returns_one_result_per_payload(self):
        # Regression: Phase-0-era behavior (one FuzzResult per payload,
        # type="traversal") must still hold after Module 4's changes.
        def responder(url):
            return HTTPResult(
                url=url, method="GET", status_code=404, response_length=9,
                response_time=0.01, headers={}, body_snippet="",
            )

        results = _run(traversal.run_traversal_scan("http://example.test", client=FakeClient(responder)))
        self.assertEqual(len(results), len(traversal.DEFAULT_TRAVERSAL_PAYLOADS))
        self.assertTrue(all(r.type == "traversal" for r in results))


if __name__ == "__main__":
    unittest.main()
