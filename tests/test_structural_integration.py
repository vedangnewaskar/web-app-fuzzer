from fuzzer.core.models import HTTPResult
from fuzzer.discovery.calibration import CalibrationBaseline
from fuzzer.discovery.directories import _baseline_structural_fingerprint
from fuzzer.discovery.structural import (
    structural_fingerprint,
    compare_structures,
)


def test_structural_baseline_from_calibration():
    sample = HTTPResult(
        url="http://test/random",
        method="GET",
        status_code=404,
        response_length=50,
        response_time=0.1,
        headers={"Content-Type": "text/html"},
        body_snippet="<html><body><h1>Not Found</h1></body></html>",
        body="<html><body><h1>Not Found</h1></body></html>",
    )

    baseline = CalibrationBaseline(
        classification="normal_404",
        is_consistent=True,
        status_code=404,
        length=50,
        length_tolerance=25,
        samples=[sample],
    )

    fingerprint = _baseline_structural_fingerprint(baseline)

    assert fingerprint is not None
    assert fingerprint["type"] == "html"


def test_structural_change_detected():
    baseline = structural_fingerprint(
        "<html><body><h1>Not Found</h1></body></html>",
        "text/html",
    )

    payload = structural_fingerprint(
        "<html><body><h1>Found</h1><script>alert(1)</script></body></html>",
        "text/html",
    )

    comparison = compare_structures(
        baseline,
        payload,
    )

    assert comparison["changed"] is True