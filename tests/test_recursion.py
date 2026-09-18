"""
Module 6 tests — Recursive Auto-Fuzzing.

Uses a scripted fake `run_directory_scan`/`calibrate_target` (patched
onto the recursion module) so these tests exercise the real recursion
control-flow -- depth limiting, duplicate/cyclic protection, request
budget, confidence gating, file-vs-directory gating -- without needing
real network access or aiohttp.
"""
import asyncio
import unittest
from unittest.mock import patch

from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import CalibrationBaseline
from fuzzer.discovery import recursion


def _fr(path, url, type_, confidence):
    return FuzzResult(
        path=path, url=url, status_code=200, length=100,
        type=type_, confidence=confidence, resolved_url=url,
    )


async def _fake_calibrate(target_url, client=None, probe_count=3, length_tolerance=25):
    return CalibrationBaseline(
        classification="normal_404", is_consistent=True,
        status_code=404, length=9, length_tolerance=25, samples=[],
    )


def _scan_map_backed_fetcher(scan_map, calls):
    async def fake_scan(target_url, wordlist_path, client=None, concurrency=10,
                         baseline=None, auto_calibrate=True, weights=None, thresholds=None):
        calls.append(target_url)
        return list(scan_map.get(target_url.rstrip("/"), []))
    return fake_scan


class RecursionTests(unittest.TestCase):
    def test_recursion_respects_max_depth(self):
        calls = []
        scan_map = {
            "http://x": [
                _fr("/admin", "http://x/admin", "directory", 90),
                _fr("/api", "http://x/api", "directory", 40),
                _fr("/backup.zip", "http://x/backup.zip", "file", 95),
            ],
            "http://x/admin": [
                _fr("/admin/login", "http://x/admin/login", "file", 80),
                _fr("/admin/users", "http://x/admin/users", "directory", 95),
            ],
            "http://x/admin/users": [
                _fr("/admin/users/1", "http://x/admin/users/1", "file", 60),
            ],
        }

        with patch.object(recursion, "run_directory_scan", side_effect=_scan_map_backed_fetcher(scan_map, calls)), \
             patch.object(recursion, "calibrate_target", side_effect=_fake_calibrate), \
             patch.object(recursion, "load_wordlist", return_value=["a", "b", "c"]):
            results = asyncio.run(recursion.run_recursive_scan(
                "http://x", "irrelevant.txt", max_depth=2, recurse_confidence_threshold=70,
            ))

        # depth 1 (root) and depth 2 (admin/) scanned; depth 3 (admin/users/) must NOT be
        self.assertIn("http://x", calls)
        self.assertIn("http://x/admin", calls)
        self.assertNotIn("http://x/admin/users", calls)
        # low-confidence /api (40 < 70) is never recursed into
        self.assertNotIn("http://x/api", calls)

        paths = {r.path for r in results}
        self.assertIn("/admin/users", paths)          # discovered, just not descended into
        self.assertNotIn("/admin/users/1", paths)      # would only exist if depth 3 ran

    def test_duplicate_and_cyclic_urls_are_not_rescanned(self):
        calls = []
        # /a and /b both lead to the same canonical /shared URL -- must scan it once.
        scan_map = {
            "http://x": [
                _fr("/a", "http://x/a", "directory", 90),
                _fr("/b", "http://x/b", "directory", 90),
            ],
            "http://x/a": [_fr("/a/shared", "http://x/shared", "directory", 90)],
            "http://x/b": [_fr("/b/shared", "http://x/shared", "directory", 90)],
            "http://x/shared": [_fr("/shared/thing", "http://x/shared/thing", "file", 50)],
        }

        with patch.object(recursion, "run_directory_scan", side_effect=_scan_map_backed_fetcher(scan_map, calls)), \
             patch.object(recursion, "calibrate_target", side_effect=_fake_calibrate), \
             patch.object(recursion, "load_wordlist", return_value=["a", "b", "c"]):
            asyncio.run(recursion.run_recursive_scan(
                "http://x", "irrelevant.txt", max_depth=3, recurse_confidence_threshold=70,
            ))

        self.assertEqual(calls.count("http://x/shared"), 1)

    def test_request_budget_stops_further_expansion(self):
        calls = []
        scan_map = {
            "http://x": [
                _fr("/a", "http://x/a", "directory", 90),
                _fr("/b", "http://x/b", "file", 10),
                _fr("/c", "http://x/c", "file", 10),
            ],
            "http://x/a": [
                _fr("/a/x", "http://x/a/x", "file", 10),
                _fr("/a/y", "http://x/a/y", "file", 10),
                _fr("/a/z", "http://x/a/z", "file", 10),
            ],
        }

        with patch.object(recursion, "run_directory_scan", side_effect=_scan_map_backed_fetcher(scan_map, calls)), \
             patch.object(recursion, "calibrate_target", side_effect=_fake_calibrate), \
             patch.object(recursion, "load_wordlist", return_value=["w1", "w2", "w3"]):
            asyncio.run(recursion.run_recursive_scan(
                "http://x", "irrelevant.txt", max_depth=5, recurse_confidence_threshold=70,
                max_total_requests=4,  # root costs 3; next level's pre-check (3+3=6 > 4) must block it
            ))

        self.assertIn("http://x", calls)
        self.assertNotIn("http://x/a", calls)

    def test_low_confidence_directory_is_not_recursed_into(self):
        calls = []
        scan_map = {
            "http://x": [_fr("/low", "http://x/low", "directory", 20)],
            "http://x/low": [_fr("/low/secret", "http://x/low/secret", "file", 90)],
        }

        with patch.object(recursion, "run_directory_scan", side_effect=_scan_map_backed_fetcher(scan_map, calls)), \
             patch.object(recursion, "calibrate_target", side_effect=_fake_calibrate), \
             patch.object(recursion, "load_wordlist", return_value=["a"]):
            asyncio.run(recursion.run_recursive_scan(
                "http://x", "irrelevant.txt", max_depth=5, recurse_confidence_threshold=70,
            ))

        self.assertEqual(calls, ["http://x"])

    def test_files_are_never_recursed_into(self):
        calls = []
        scan_map = {"http://x": [_fr("/backup.zip", "http://x/backup.zip", "file", 99)]}

        with patch.object(recursion, "run_directory_scan", side_effect=_scan_map_backed_fetcher(scan_map, calls)), \
             patch.object(recursion, "calibrate_target", side_effect=_fake_calibrate), \
             patch.object(recursion, "load_wordlist", return_value=["a"]):
            asyncio.run(recursion.run_recursive_scan(
                "http://x", "irrelevant.txt", max_depth=5, recurse_confidence_threshold=70,
            ))

        self.assertEqual(calls, ["http://x"])

    def test_looks_like_directory_rejects_paths_with_extensions(self):
        directory_typed_but_has_extension = _fr("/weird.zip", "http://x/weird.zip", "directory", 90)
        self.assertFalse(recursion.looks_like_directory(directory_typed_but_has_extension))

        genuine_directory = _fr("/admin", "http://x/admin", "directory", 90)
        self.assertTrue(recursion.looks_like_directory(genuine_directory))

        file_type = _fr("/notes", "http://x/notes", "file", 90)
        self.assertFalse(recursion.looks_like_directory(file_type))


if __name__ == "__main__":
    unittest.main()
