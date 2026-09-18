"""
Config loader for configs/default.yaml (and any override file passed on
the CLI). Kept intentionally small: it reads YAML into a plain dict and
applies a few defaults, rather than introducing a config framework.
"""
from pathlib import Path
from typing import Any, Dict

import yaml

DEFAULT_CONFIG_PATH = Path(__file__).resolve().parents[2] / "configs" / "default.yaml"

# Minimal defaults so a missing/partial config file doesn't crash the scan.
_DEFAULTS: Dict[str, Any] = {
    "target": {"url": "http://127.0.0.1:8000"},
    "scan": {
        "mode": "dirs",
        "threads": 10,
        "timeout": 10,
        "follow_redirects": True,
    },
    "calibration": {"probe_count": 3, "length_tolerance": 25},
    "scoring": {
        "weights": {
            "status": 40,
            "length_delta": 35,
            "keyword": 15,
            "response_time": 10,
            "soft_404_penalty": -100,
        },
        "thresholds": {
            "very_low": 0,
            "low": 30,
            "medium": 50,
            "high": 70,
            "very_high": 85,
        },
    },
    "recursion": {
        "max_depth": 2,
        "recurse_confidence_threshold": 70,
        "max_total_requests": 2000,
    },
    "mutation": {
        "confidence_threshold": 50,
        "max_mutations_per_result": 15,
        "max_total_requests": 500,
        "years": [2023, 2024, 2025, 2026],
    },
    "traversal": {
        "confidence_by_confirmation": {"confirmed": 95, "suspected": 40},
    },
    "wordlists": {
        "directories": "fuzzer/wordlists/directories.txt",
        "subdomains": "fuzzer/wordlists/subdomains.txt",
    },
    "output": {"format": "json", "file": "output/results.json"},
}


def _deep_merge(base: Dict[str, Any], override: Dict[str, Any]) -> Dict[str, Any]:
    merged = dict(base)
    for key, value in override.items():
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _deep_merge(merged[key], value)
        else:
            merged[key] = value
    return merged


def load_config(path: str | Path | None = None) -> Dict[str, Any]:
    """Load YAML config from `path` (or configs/default.yaml), merged over defaults."""
    config_path = Path(path) if path else DEFAULT_CONFIG_PATH

    if not config_path.exists():
        return dict(_DEFAULTS)

    with open(config_path, "r", encoding="utf-8") as f:
        loaded = yaml.safe_load(f) or {}

    return _deep_merge(_DEFAULTS, loaded)
