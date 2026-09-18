"""
Module 3 tests — Mutation-Based Wordlist Expansion.

Covers exactly what the spec asks for: given `backup.zip`, mutations
are generated and deduplicated, and request counts stay bounded --
plus the second-wave gating (confidence threshold, files only, no
duplicate/already-scanned requests) via a scripted fake
`run_directory_scan`/`calibrate_target`.
"""
import asyncio
import unittest
from unittest.mock import patch

from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import CalibrationBaseline
from fuzzer.discovery import mutations


def _fr(path, type_="file", confidence=90):
    return FuzzResult(path=path, url=f"http://x{path}", status_code=200, length=100, type=type_, confidence=confidence)


class GenerateMutationsTests(unittest.TestCase):
    def test_backup_zip_mutations_are_generated_and_deduplicated(self):
        result = mutations.generate_mutations("backup.zip")
        self.assertGreater(len(result), 0)
        self.assertEqual(len(result), len(set(result)))  # no duplicates
        self.assertNotIn("backup.zip", result)  # never includes the original

        # spot-check the exact examples from the spec
        for expected in ("backup.zip.bak", "backup.zip.old", "backup.zip~",
                          "backup_old.zip", "backup1.zip", "backup2.zip",
                          "old_backup.zip", "backup_2025.zip", "backup_2026.zip"):
            self.assertIn(expected, result)

    def test_config_php_mutations_match_spec_examples(self):
        result = mutations.generate_mutations("config.php")
        for expected in ("config.php.bak", "config.php.old", "config.php~",
                          "config_old.php", "config_backup.php", "config.php.save"):
            self.assertIn(expected, result)

    def test_generation_is_deterministic(self):
        first = mutations.generate_mutations("backup.zip")
        second = mutations.generate_mutations("backup.zip")
        self.assertEqual(first, second)

    def test_max_mutations_caps_output(self):
        result = mutations.generate_mutations("backup.zip", max_mutations=3)
        self.assertEqual(len(result), 3)

    def test_hidden_file_without_extension_still_produces_suffix_variants(self):
        result = mutations.generate_mutations(".env")
        self.assertIn(".env.bak", result)
        self.assertIn("old_.env", result)
        # rules requiring an extension (numeric/year/stem-old) should not fire
        self.assertNotIn(".env1", result)


def _fake_calibrate(*args, **kwargs):
    async def _inner(*a, **kw):
        return CalibrationBaseline(
            classification="normal_404", is_consistent=True,
            status_code=404, length=9, length_tolerance=25, samples=[],
        )
    return _inner()


class RunMutationScanTests(unittest.TestCase):
    def test_only_confident_files_are_mutated_and_requests_are_bounded(self):
        results = [
            _fr("/backup.zip", type_="file", confidence=90),   # qualifies
            _fr("/lowconf.zip", type_="file", confidence=10),  # too low confidence -- skipped
            _fr("/admin", type_="directory", confidence=95),   # directory -- never mutated
        ]

        calls = []

        async def fake_run_directory_scan(base_url, wordlist_path=None, client=None, concurrency=10,
                                           baseline=None, auto_calibrate=True, weights=None,
                                           thresholds=None, words=None):
            calls.append((base_url, list(words or [])))
            return [
                FuzzResult(path=f"/{w}", url=f"{base_url}/{w}", status_code=404, length=9,
                           type="file", confidence=0)
                for w in (words or [])
            ]

        async def fake_calibrate_target(target_url, client=None, probe_count=3, length_tolerance=25):
            return CalibrationBaseline(
                classification="normal_404", is_consistent=True,
                status_code=404, length=9, length_tolerance=25, samples=[],
            )

        with patch.object(mutations, "run_directory_scan", side_effect=fake_run_directory_scan), \
             patch.object(mutations, "calibrate_target", side_effect=fake_calibrate_target):
            mutated = asyncio.run(mutations.run_mutation_scan(
                "http://x", results, max_mutations_per_result=15, max_total_requests=500,
            ))

        # exactly one group scanned (only backup.zip qualified)
        self.assertEqual(len(calls), 1)
        base_url, words = calls[0]
        self.assertEqual(base_url, "http://x")  # backup.zip is at the root
        self.assertTrue(all(w.startswith("backup") or w.startswith("old_backup") for w in words))
        self.assertEqual(len(words), len(set(words)))  # deduplicated

    def test_max_total_requests_bounds_the_whole_second_wave(self):
        results = [_fr(f"/f{i}.zip", type_="file", confidence=90) for i in range(5)]

        async def fake_run_directory_scan(base_url, wordlist_path=None, client=None, concurrency=10,
                                           baseline=None, auto_calibrate=True, weights=None,
                                           thresholds=None, words=None):
            return [
                FuzzResult(path=f"/{w}", url=f"{base_url}/{w}", status_code=404, length=9,
                           type="file", confidence=0)
                for w in (words or [])
            ]

        async def fake_calibrate_target(target_url, client=None, probe_count=3, length_tolerance=25):
            return CalibrationBaseline(
                classification="normal_404", is_consistent=True,
                status_code=404, length=9, length_tolerance=25, samples=[],
            )

        with patch.object(mutations, "run_directory_scan", side_effect=fake_run_directory_scan), \
             patch.object(mutations, "calibrate_target", side_effect=fake_calibrate_target):
            mutated = asyncio.run(mutations.run_mutation_scan(
                "http://x", results, max_mutations_per_result=15, max_total_requests=10,
            ))

        # 5 files x up to 14 mutations each (15 cap minus the original) would be
        # ~70 candidate requests; the budget must cap it at 10.
        self.assertLessEqual(len(mutated), 10)

    def test_directories_are_never_mutated(self):
        results = [_fr("/admin", type_="directory", confidence=99)]

        async def fake_run_directory_scan(*a, **kw):
            raise AssertionError("run_directory_scan should never be called -- nothing to mutate")

        with patch.object(mutations, "run_directory_scan", side_effect=fake_run_directory_scan):
            mutated = asyncio.run(mutations.run_mutation_scan("http://x", results))

        self.assertEqual(mutated, [])

    def test_already_scanned_paths_are_not_requeued(self):
        # backup_old.zip was somehow already found in the original scan --
        # the mutation of backup.zip that would produce it must be skipped.
        results = [
            _fr("/backup.zip", type_="file", confidence=90),
            _fr("/backup_old.zip", type_="file", confidence=90),
        ]

        async def fake_run_directory_scan(base_url, wordlist_path=None, client=None, concurrency=10,
                                           baseline=None, auto_calibrate=True, weights=None,
                                           thresholds=None, words=None):
            self.assertNotIn("backup_old.zip", words or [])
            return []

        async def fake_calibrate_target(target_url, client=None, probe_count=3, length_tolerance=25):
            return CalibrationBaseline(
                classification="normal_404", is_consistent=True,
                status_code=404, length=9, length_tolerance=25, samples=[],
            )

        with patch.object(mutations, "run_directory_scan", side_effect=fake_run_directory_scan), \
             patch.object(mutations, "calibrate_target", side_effect=fake_calibrate_target):
            asyncio.run(mutations.run_mutation_scan("http://x", results))


if __name__ == "__main__":
    unittest.main()
