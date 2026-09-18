"""
Module 3 — Mutation-Based Wordlist Expansion.

A deterministic, rule-based mutator: given a discovered filename,
produces a small bounded set of plausible variants (backup copies,
old versions, numbered/dated duplicates). This is a second-wave
process only -- `run_mutation_scan` takes already-scored results from
a prior scan and only mutates the sufficiently confident FILE findings
among them, rather than expanding the original wordlist wholesale.

Directories are intentionally not mutated here: Module 6 (recursion)
already handles exploring into confident directories, and a directory
name doesn't map onto a single follow-up request the way a filename's
suffix/prefix variants do.
"""
from typing import Callable, Dict, List, Optional, Tuple

from fuzzer.core.http_client import HTTPClient
from fuzzer.core.models import FuzzResult
from fuzzer.discovery.calibration import calibrate as calibrate_target
from fuzzer.discovery.directories import run_directory_scan
from fuzzer.discovery.scoring import DEFAULT_THRESHOLDS, DEFAULT_WEIGHTS

# Only mutate findings at least this confident -- spec's "medium" band
# and above. Deliberately lower than Module 6's recursion threshold:
# a file worth trying backup/old variants of doesn't need to be as
# certain as a directory worth spending a whole sub-scan on.
DEFAULT_CONFIDENCE_THRESHOLD = 50

# Per-finding and whole-run caps, so a handful of confident findings
# can never balloon into an unbounded number of extra requests.
DEFAULT_MAX_MUTATIONS_PER_RESULT = 15
DEFAULT_MAX_TOTAL_REQUESTS = 500

DEFAULT_YEARS = [2023, 2024, 2025, 2026]

RuleFn = Callable[[str, str, str], List[str]]

# Suffixes appended to the whole filename (config.php -> config.php.bak).
_APPEND_SUFFIXES = (".bak", ".old", ".save", ".backup", "~")


def _split_name(name: str) -> Tuple[str, str]:
    """Split into (stem, ext). Hidden files like `.env` have no `ext`
    (stem=".env") -- a leading dot alone doesn't count as an extension."""
    stripped = name.lstrip(".")
    if "." in stripped:
        idx = name.rindex(".")
        return name[:idx], name[idx:]
    return name, ""


def _rule_append_suffix(stem: str, ext: str, full: str) -> List[str]:
    """config.php -> config.php.bak, config.php.old, config.php~, ..."""
    return [full + suffix for suffix in _APPEND_SUFFIXES]


def _rule_stem_old_backup(stem: str, ext: str, full: str) -> List[str]:
    """config.php -> config_old.php, config_backup.php"""
    if not ext:
        return []
    return [f"{stem}_old{ext}", f"{stem}_backup{ext}"]


def _rule_old_prefix(stem: str, ext: str, full: str) -> List[str]:
    """backup.zip -> old_backup.zip"""
    return [f"old_{full}"]


def _rule_numeric_suffix(stem: str, ext: str, full: str) -> List[str]:
    """backup.zip -> backup1.zip, backup2.zip"""
    if not ext:
        return []
    return [f"{stem}1{ext}", f"{stem}2{ext}"]


def _make_year_suffix_rule(years: List[int]) -> RuleFn:
    def _rule(stem: str, ext: str, full: str) -> List[str]:
        """backup.zip -> backup_2025.zip, backup_2026.zip, ..."""
        if not ext:
            return []
        return [f"{stem}_{year}{ext}" for year in years]
    return _rule


# Centralized so the rule set can be tuned/extended in one place rather
# than scattered through the scanning logic.
DEFAULT_RULES: List[RuleFn] = [
    _rule_append_suffix,
    _rule_stem_old_backup,
    _rule_old_prefix,
    _rule_numeric_suffix,
]


def generate_mutations(
    name: str,
    rules: Optional[List[RuleFn]] = None,
    years: Optional[List[int]] = None,
    max_mutations: int = DEFAULT_MAX_MUTATIONS_PER_RESULT,
) -> List[str]:
    """
    Deterministic filename variants of `name`. Same input always
    produces the same output in the same order (rule order, then
    within-rule order) -- no randomness. Deduplicated, capped at
    `max_mutations`, and never includes `name` itself.
    """
    active_rules = list(rules) if rules is not None else list(DEFAULT_RULES)
    active_rules = active_rules + [_make_year_suffix_rule(years or DEFAULT_YEARS)]

    stem, ext = _split_name(name)
    seen: Dict[str, None] = {}
    for rule in active_rules:
        for candidate in rule(stem, ext, name):
            if candidate and candidate != name:
                seen.setdefault(candidate, None)

    return list(seen.keys())[:max_mutations]


def _parent_and_name(path: str) -> Tuple[str, str]:
    """"/admin/backup.zip" -> ("/admin", "backup.zip"); "/backup.zip" -> ("", "backup.zip")."""
    trimmed = path.rstrip("/") or "/"
    parent, _, name = trimmed.rpartition("/")
    return parent, name


async def run_mutation_scan(
    base_url: str,
    results: List[FuzzResult],
    client: Optional[HTTPClient] = None,
    confidence_threshold: int = DEFAULT_CONFIDENCE_THRESHOLD,
    max_mutations_per_result: int = DEFAULT_MAX_MUTATIONS_PER_RESULT,
    max_total_requests: int = DEFAULT_MAX_TOTAL_REQUESTS,
    concurrency: int = 10,
    weights: Optional[dict] = None,
    thresholds: Optional[dict] = None,
    years: Optional[List[int]] = None,
    rules: Optional[List[RuleFn]] = None,
) -> List[FuzzResult]:
    """
    Second-wave scan: for every sufficiently confident FILE in
    `results`, generate filename mutations and fuzz those too.
    Reuses `run_directory_scan` for the actual requests (via its
    `words=` parameter) rather than a second HTTP mechanism.

    Mutations are grouped by parent directory and each group is
    calibrated (Module 1) against that specific directory before being
    scanned -- a subdirectory discovered via recursion can have a
    different soft-404 baseline than the root, so a single baseline
    isn't reused across groups.

    `max_total_requests` bounds the whole second wave regardless of
    how many qualifying originals or rules produced candidates.
    Mutations that duplicate an already-scanned path, or that were
    already queued by another finding's mutation set, are skipped.
    """
    client = client or HTTPClient()
    weights = weights or DEFAULT_WEIGHTS
    thresholds = thresholds or DEFAULT_THRESHOLDS

    already_scanned_paths = {(r.path.rstrip("/") or "/") for r in results}

    groups: Dict[str, List[str]] = {}
    queued_paths = set()
    total_queued = 0

    for result in results:
        if total_queued >= max_total_requests:
            break
        if result.type != "file":
            continue
        if result.confidence is None or result.confidence < confidence_threshold:
            continue

        parent, name = _parent_and_name(result.path)
        parent_url = base_url.rstrip("/") + parent

        for mutated_name in generate_mutations(name, rules=rules, years=years, max_mutations=max_mutations_per_result):
            if total_queued >= max_total_requests:
                break
            mutated_path = f"{parent}/{mutated_name}" if parent else f"/{mutated_name}"
            if mutated_path in already_scanned_paths or mutated_path in queued_paths:
                continue
            queued_paths.add(mutated_path)
            groups.setdefault(parent_url, []).append(mutated_name)
            total_queued += 1

    if not groups:
        return []

    all_results: List[FuzzResult] = []
    for parent_url, words in groups.items():
        baseline = await calibrate_target(parent_url, client=client)
        level_results = await run_directory_scan(
            parent_url, client=client, concurrency=concurrency,
            baseline=baseline, auto_calibrate=False,
            weights=weights, thresholds=thresholds, words=words,
        )
        all_results.extend(level_results)

    return all_results
