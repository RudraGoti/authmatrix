from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmatrix.comparison import compare_results, write_comparison
from authmatrix.errors import ScanError


def make_finding(
    operation_id: str,
    resource_id: str,
    title: str = "Unauthorized object access",
) -> dict:
    return {
        "id": f"{operation_id}:alice:{resource_id}",
        "category": "BOLA",
        "severity": "high",
        "title": title,
        "operation_id": operation_id,
        "evidence": {"http_status": 200},
        "reproduction": {
            "method": "GET",
            "path": f"/items/{resource_id}",
            "identity": "alice",
            "resource_id": resource_id,
        },
        "remediation": "Enforce object-level authorization.",
    }


def make_report(findings: list[dict], target: str = "http://127.0.0.1:8000") -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target": target,
        "summary": {
            "requests": 1,
            "passed": 0,
            "failed": len(findings),
            "inconclusive": 0,
            "findings": len(findings),
        },
        "findings": findings,
        "checks": [],
    }


def write_report(path: Path, report: dict) -> None:
    path.write_text(json.dumps(report), encoding="utf-8")


def test_classifies_new_fixed_and_recurring_findings(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    write_report(
        baseline,
        make_report(
            [
                make_finding("read_item", "1"),
                make_finding("read_item", "2"),
            ]
        ),
    )
    write_report(
        current,
        make_report(
            [
                make_finding("read_item", "2"),
                make_finding("read_item", "3"),
            ]
        ),
    )

    result = compare_results(str(baseline), str(current))

    assert result["summary"] == {
        "new": 1,
        "fixed": 1,
        "recurring": 1,
    }
    assert result["new_findings"][0]["reproduction"]["resource_id"] == "3"
    assert result["fixed_findings"][0]["reproduction"]["resource_id"] == "1"
    assert result["recurring_findings"][0]["reproduction"]["resource_id"] == "2"


def test_title_and_severity_changes_do_not_create_new_finding(
    tmp_path: Path,
) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    old_finding = make_finding("read_item", "1")
    new_finding = make_finding(
        "read_item",
        "1",
        title="Updated finding title",
    )
    new_finding["severity"] = "critical"

    write_report(baseline, make_report([old_finding]))
    write_report(current, make_report([new_finding]))

    result = compare_results(str(baseline), str(current))

    assert result["summary"] == {
        "new": 0,
        "fixed": 0,
        "recurring": 1,
    }


def test_rejects_different_targets(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    write_report(baseline, make_report([]))
    write_report(
        current,
        make_report([], target="http://127.0.0.1:9000"),
    )

    with pytest.raises(ScanError, match="different targets"):
        compare_results(str(baseline), str(current))


def test_rejects_missing_baseline(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    write_report(current, make_report([]))

    with pytest.raises(ScanError, match="Cannot read scan results"):
        compare_results(
            str(tmp_path / "missing.json"),
            str(current),
        )


def test_rejects_invalid_finding_structure(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    write_report(baseline, make_report([{"category": "BOLA"}]))
    write_report(current, make_report([]))

    with pytest.raises(ScanError, match="Finding is missing"):
        compare_results(str(baseline), str(current))


def test_write_comparison_creates_directory_and_json_file(
    tmp_path: Path,
) -> None:
    output = tmp_path / "reports" / "comparison.json"
    results = {"schema_version": 1, "summary": {"new": 1}}

    write_comparison(results, output)

    assert output.exists()
    assert json.loads(output.read_text(encoding="utf-8")) == results


def test_write_comparison_rejects_unwritable_path(
    tmp_path: Path,
) -> None:
    blocked = tmp_path / "blocked"
    blocked.write_text("not a directory", encoding="utf-8")

    with pytest.raises(ScanError, match="Cannot write comparison results"):
        write_comparison(
            {"schema_version": 1},
            blocked / "comparison.json",
        )


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("target", ""),
        ("target", None),
        ("generated_at", ""),
        ("generated_at", None),
    ],
)
def test_rejects_invalid_report_metadata(
    tmp_path: Path,
    field: str,
    value: str | None,
) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    report = make_report([])
    report[field] = value

    write_report(baseline, report)
    write_report(current, make_report([]))

    with pytest.raises(ScanError, match=f"invalid {field}"):
        compare_results(str(baseline), str(current))


def test_rejects_malformed_json(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    baseline.write_text("{invalid json", encoding="utf-8")
    write_report(current, make_report([]))

    with pytest.raises(ScanError, match="not valid JSON"):
        compare_results(str(baseline), str(current))


def test_duplicate_findings_are_counted_once(tmp_path: Path) -> None:
    baseline = tmp_path / "baseline.json"
    current = tmp_path / "current.json"

    finding = make_finding("read_item", "1")

    write_report(
        baseline,
        make_report([finding, finding.copy()]),
    )
    write_report(
        current,
        make_report([finding, finding.copy()]),
    )

    result = compare_results(str(baseline), str(current))

    assert result["summary"] == {
        "new": 0,
        "fixed": 0,
        "recurring": 1,
    }
