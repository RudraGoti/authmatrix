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


def test_report_refuses_overwrite_without_explicit_force(tmp_path: Path) -> None:
    source = tmp_path / "results.json"
    source.write_text(json.dumps(sample_results()), encoding="utf-8")
    destination = tmp_path / "report.html"
    destination.write_text("keep this file", encoding="utf-8")

    with pytest.raises(ScanError, match="already exists"):
        write_report(source, destination, "html")

    assert destination.read_text(encoding="utf-8") == "keep this file"

    write_report(source, destination, "html", overwrite=True)
    assert "AuthMatrix authorization report" in destination.read_text(
        encoding="utf-8"
    )


def test_reports_redact_nested_authentication_material(tmp_path: Path) -> None:
    source = tmp_path / "results.json"
    results = sample_results()
    results["checks"] = [
        {
            "request_headers": {
                "Authorization": "Bearer secret-bearer-value",
                "X-Api-Key": "secret-api-key",
            },
            "password": "secret-password",
            "note": "token=secret-inline-token",
            "target_hint": "https://user:secret-url-password@127.0.0.1",
        }
    ]
    source.write_text(json.dumps(results), encoding="utf-8")

    json_output = tmp_path / "report.json"
    html_output = tmp_path / "report.html"
    write_report(source, json_output, "json")
    write_report(source, html_output, "html")

    json_report = json_output.read_text(encoding="utf-8")
    html_report = html_output.read_text(encoding="utf-8")
    for secret in (
        "secret-bearer-value",
        "secret-api-key",
        "secret-password",
        "secret-inline-token",
        "user:secret-url-password",
    ):
        assert secret not in json_report
        assert secret not in html_report
    assert "[REDACTED]" in json_report


def test_rejects_invalid_report_json(tmp_path: Path) -> None:
    source = tmp_path / "broken.json"
    source.write_text("{", encoding="utf-8")
    with pytest.raises(ScanError, match="not valid JSON"):
        load_results(source)

def test_html_report_displays_inconclusive_count() -> None:
    report = render_html(sample_results())
    assert "Inconclusive: 2" in report


def test_html_report_displays_and_escapes_skipped_openapi_operations() -> None:
    results = sample_results()
    results["summary"]["skipped"] = 1
    results["skipped_operations"] = [
        {
            "operation_id": "<unmapped>",
            "method": "GET",
            "path": "/items/{id}",
            "reason": "<required value missing>",
        }
    ]

    report = render_html(results)

    assert "Skipped operations: 1" in report
    assert "&lt;unmapped&gt;" in report
    assert "&lt;required value missing&gt;" in report


def test_html_report_includes_policy_identities_checks_and_limitations() -> None:
    results = sample_results()
    results["scan_id"] = "scan-123"
    results["policy"] = "<policy>"
    results["identities"] = [{"name": "<admin>", "role": "operator"}]
    results["limitations"] = ["<configured checks only>"]
    results["checks"] = [
        {
            "operation_id": "read",
            "identity": "alice",
            "expected": "deny",
            "actual": "allow",
            "status_code": 200,
            "passed": False,
        }
    ]

    report = render_html(results)

    assert "scan-123" in report
    assert "&lt;policy&gt;" in report
    assert "&lt;admin&gt;" in report
    assert "expected deny, observed allow" in report
    assert "&lt;configured checks only&gt;" in report


def test_html_report_supports_older_summary_without_inconclusive() -> None:
    results = sample_results()
    results["summary"].pop("inconclusive")

    report = render_html(results)

    assert "Inconclusive: 0" in report


def test_rejects_malformed_report_summary(tmp_path: Path) -> None:
    source = tmp_path / "malformed.json"
    results = sample_results()
    results["summary"]["requests"] = "one"
    source.write_text(json.dumps(results), encoding="utf-8")

    with pytest.raises(ScanError, match="valid summary"):
        load_results(source)
