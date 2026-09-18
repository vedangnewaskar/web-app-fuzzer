"""Result output: JSON file writer + console summary. No new dependency."""
import json
from dataclasses import asdict
from pathlib import Path
from typing import List

from fuzzer.core.models import FuzzResult


def results_to_dict(results: List[FuzzResult]) -> dict:
    """Shape matches the API response: {"results": [...]}."""
    return {"results": [asdict(r) for r in results]}


def save_results(results: List[FuzzResult], output_path: str) -> None:
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(results_to_dict(results), f, indent=2)


def print_summary(results: List[FuzzResult]) -> None:
    for r in results:
        conf = f" conf={r.confidence}" if r.confidence is not None else ""
        # Module 7 tags severity purely from path pattern, independent of
        # confidence (by design -- see fuzzer.discovery.critical_tags), so
        # a plain 404 for a well-known sensitive filename is still tagged
        # in the saved JSON. The console summary is display-only and
        # suppresses that tag when confidence is 0/unset, so a report
        # reader isn't shown "[CRITICAL]" next to something that plainly
        # wasn't found -- the full annotation is always in the JSON output.
        show_severity = r.severity and (r.confidence or 0) > 0
        sev = f" [{r.severity.upper()}]" if show_severity else ""
        print(f"{r.status_code:>3}  {r.length:>8}  {r.path}{conf}{sev}")
    print(f"\n{len(results)} results")
