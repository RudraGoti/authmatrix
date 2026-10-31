from __future__ import annotations

import json
from pathlib import Path

import pytest

from authmatrix.errors import ScanError
from authmatrix.reporting import load_results, render_html, write_report


def sample_results() -> dict:
    return {
        "schema_version": 1,
        "generated_at": "2026-01-01T00:00:00+00:00",
        "target": "http://127.0.0.1:8000",
        "summary": {
            "requests": 1,
            "passed": 0,
            "failed": 1,
            "inconclusive": 2,
            "findings": 1,
        },
        "findings": [
            {
                "id": "test",
                "category": "BOLA",
                "severity": "high",
                "title": "<script>alert(1)</script>",
                "operation_id": "read",
                "evidence": {"http_status": 200},
                "reproduction": {
                    "method": "GET",
                    "path": "/items/1",
                    "identity": "alice",
                },
                "remediation": "Enforce object-level authorization.",
            }
        ],
        "checks": [],
    }


def test_html_report_escapes_untrusted_text() -> None:
    report = render_html(sample_results())
    assert "<script>" not in report
    assert "&lt;script&gt;" in report


def test_writes_json_and_html_reports(tmp_path: Path) -> None:
    source = tmp_path / "results.json"
    source.write_text(json.dumps(sample_results()), encoding="utf-8")
    json_output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"
    write_report(source, json_output, "json")
    write_report(source, html_output, "html")
    assert load_results(json_output)["summary"]["findings"] == 1
    assert "AuthMatrix authorization report" in html_output.read_text(encoding="utf-8")


def test_rejects_invalid_report_json(tmp_path: Path) -> None:
    source = tmp_path / "broken.json"
    source.write_text("{", encoding="utf-8")
    with pytest.raises(ScanError, match="not valid JSON"):
        load_results(source)

def test_html_report_displays_inconclusive_count() -> None:
    report = render_html(sample_results())
    assert "Inconclusive: 2" in report


def test_html_report_supports_older_summary_without_inconclusive() -> None:
    results = sample_results()
    results["summary"].pop("inconclusive")

    report = render_html(results)

    assert "Inconclusive: 0" in report
