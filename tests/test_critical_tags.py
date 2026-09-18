"""
Module 7 tests — Critical-Exposure Auto-Tagging.

Verifies known sensitive paths receive the right severity/tag, and
that ordinary paths are never incorrectly marked critical -- plus that
severity stays independent of confidence/confirmation.
"""
import unittest

from fuzzer.core.models import FuzzResult
from fuzzer.discovery.critical_tags import find_critical_rule, tag_critical_exposure


def _fr(path, confidence=None, confirmation=None, note=""):
    return FuzzResult(
        path=path, url=f"http://x{path}", status_code=200, length=100,
        confidence=confidence, confirmation=confirmation, note=note,
    )


class CriticalTagTests(unittest.TestCase):
    def test_known_sensitive_paths_are_tagged(self):
        cases = {
            "/.git/config": "critical",
            "/.git/HEAD": "high",
            "/.env": "critical",
            "/id_rsa": "critical",
            "/wp-config.php.bak": "critical",
        }
        for path, expected_severity in cases.items():
            result = tag_critical_exposure(_fr(path))
            self.assertEqual(result.severity, expected_severity, msg=f"path={path}")
            self.assertTrue(result.critical, msg=f"path={path}")
            self.assertTrue(result.note)  # human-readable explanation present

    def test_nested_sensitive_paths_are_still_matched(self):
        # A .git/config found under a recursed subdirectory must still match.
        result = tag_critical_exposure(_fr("/backend/.git/config"))
        self.assertEqual(result.severity, "critical")
        self.assertTrue(result.critical)

    def test_ordinary_paths_are_never_marked_critical(self):
        for path in ("/admin", "/login", "/api/users", "/dashboard", "/index.html", "/about-us"):
            result = tag_critical_exposure(_fr(path))
            self.assertFalse(result.critical, msg=f"path={path}")
            self.assertIsNone(result.severity, msg=f"path={path}")

    def test_env_lookalike_is_not_falsely_matched(self):
        # ".env" should match the *file* .env, not something that merely
        # contains "env" as a substring elsewhere in the path.
        result = tag_critical_exposure(_fr("/environment-settings"))
        self.assertFalse(result.critical)
        result2 = tag_critical_exposure(_fr("/env/config"))
        self.assertFalse(result2.critical)

    def test_existing_note_is_preserved_and_extended_not_overwritten(self):
        result = _fr("/.env", note="matches calibration baseline (soft_404); likely false positive")
        tag_critical_exposure(result)
        self.assertIn("calibration baseline", result.note)
        self.assertIn("secrets", result.note.lower())

    def test_severity_is_independent_of_confidence_and_confirmation(self):
        # Spec's explicit example: severity=critical, confidence=96,
        # confirmation=suspected is a valid combination -- tagging must
        # never touch confidence/confirmation.
        result = _fr("/.env", confidence=96, confirmation="suspected")
        tag_critical_exposure(result)
        self.assertEqual(result.severity, "critical")
        self.assertEqual(result.confidence, 96)
        self.assertEqual(result.confirmation, "suspected")

    def test_low_confidence_finding_can_still_be_tagged_critical(self):
        # Tagging is about the *kind* of resource, not how sure the scan
        # is it's really there -- a low-confidence .env hit is still tagged.
        result = _fr("/.env", confidence=5, confirmation="candidate")
        tag_critical_exposure(result)
        self.assertEqual(result.severity, "critical")
        self.assertTrue(result.critical)

    def test_find_critical_rule_returns_none_for_unmatched_paths(self):
        self.assertIsNone(find_critical_rule("/admin/dashboard"))

    def test_does_not_claim_confirmation_of_exposure(self):
        # The tag alone must never claim proof -- confirmation stays
        # whatever it was (or None), never forced to "confirmed" by tagging.
        result = _fr("/.env")
        tag_critical_exposure(result)
        self.assertIsNone(result.confirmation)


if __name__ == "__main__":
    unittest.main()
