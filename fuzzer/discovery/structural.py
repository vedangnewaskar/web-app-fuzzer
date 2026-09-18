import json
from typing import Any

from bs4 import BeautifulSoup


def _max_depth_html(soup: BeautifulSoup) -> int:
    """Return the maximum nesting depth of HTML tags."""

    def depth(tag) -> int:
        parent = tag.parent

        if parent is None or getattr(parent, "name", None) is None:
            return 1

        return 1 + depth(parent)

    depths = [
        depth(tag)
        for tag in soup.find_all()
    ]

    return max(depths, default=0)


def structural_fingerprint_html(body: str) -> dict:
    """
    Create a structural fingerprint of an HTML response.

    Text content is ignored.
    The fingerprint records:
    - total number of tags
    - tag sequence
    - maximum nesting depth
    - attribute count for each tag
    """

    soup = BeautifulSoup(body, "html.parser")

    tags = soup.find_all()

    return {
        "tag_count": len(tags),
        "tag_sequence": [tag.name for tag in tags],
        "max_depth": _max_depth_html(soup),
        "attribute_counts": [
            len(tag.attrs)
            for tag in tags
        ],
    }


def _extract_schema(value: Any) -> Any:
    """Recursively extract a JSON key/type schema."""

    if isinstance(value, dict):
        return {
            key: _extract_schema(child)
            for key, child in sorted(value.items())
        }

    if isinstance(value, list):
        if not value:
            return ["empty"]

        return [
            _extract_schema(value[0])
        ]

    if value is None:
        return "null"

    if isinstance(value, bool):
        return "boolean"

    if isinstance(value, int):
        return "integer"

    if isinstance(value, float):
        return "number"

    if isinstance(value, str):
        return "string"

    return type(value).__name__


def structural_fingerprint_json(body: str) -> dict:
    """
    Create a structural fingerprint of a JSON response.

    JSON values are ignored.
    Keys and value types are preserved recursively.
    """

    data = json.loads(body)

    return {
        "schema": _extract_schema(data)
    }


def structural_fingerprint(
    body: str,
    content_type: str = "",
) -> dict:
    """
    Automatically select the appropriate structural fingerprint.

    Returns:
        {
            "type": "html" | "json",
            "fingerprint": ...
        }
    """

    content_type = content_type.lower()

    if "json" in content_type:
        return {
            "type": "json",
            "fingerprint": structural_fingerprint_json(body),
        }

    if "html" in content_type:
        return {
            "type": "html",
            "fingerprint": structural_fingerprint_html(body),
        }

    # Fallback: try JSON first, then HTML.
    try:
        return {
            "type": "json",
            "fingerprint": structural_fingerprint_json(body),
        }
    except (json.JSONDecodeError, TypeError):
        return {
            "type": "html",
            "fingerprint": structural_fingerprint_html(body),
        }
    
def compare_structures(
    baseline: dict,
    payload: dict,
) -> dict:
    """
    Compare two structural fingerprints.

    Returns a simple, explainable anomaly report.
    """

    if baseline["type"] != payload["type"]:
        return {
            "changed": True,
            "reason": (
                f"response type changed from "
                f"{baseline['type']} to {payload['type']}"
            ),
        }

    baseline_fp = baseline["fingerprint"]
    payload_fp = payload["fingerprint"]

    if baseline["type"] == "html":
        differences = {}

        if baseline_fp["tag_count"] != payload_fp["tag_count"]:
            differences["tag_count"] = {
                "baseline": baseline_fp["tag_count"],
                "payload": payload_fp["tag_count"],
            }

        if baseline_fp["tag_sequence"] != payload_fp["tag_sequence"]:
            differences["tag_sequence"] = {
                "baseline": baseline_fp["tag_sequence"],
                "payload": payload_fp["tag_sequence"],
            }

        if baseline_fp["max_depth"] != payload_fp["max_depth"]:
            differences["max_depth"] = {
                "baseline": baseline_fp["max_depth"],
                "payload": payload_fp["max_depth"],
            }

        if (
            baseline_fp["attribute_counts"]
            != payload_fp["attribute_counts"]
        ):
            differences["attribute_counts"] = {
                "baseline": baseline_fp["attribute_counts"],
                "payload": payload_fp["attribute_counts"],
            }

        return {
            "changed": bool(differences),
            "differences": differences,
        }

    if baseline["type"] == "json":
        changed = (
            baseline_fp["schema"]
            != payload_fp["schema"]
        )

        return {
            "changed": changed,
            "differences": {
                "schema": {
                    "baseline": baseline_fp["schema"],
                    "payload": payload_fp["schema"],
                }
            } if changed else {},
        }

    return {
        "changed": baseline_fp != payload_fp,
        "differences": {
            "baseline": baseline_fp,
            "payload": payload_fp,
        } if baseline_fp != payload_fp else {},
    }