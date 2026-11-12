"""Sanitized JSON and HTML report rendering."""

from __future__ import annotations

import html
import json
import re
from pathlib import Path
from typing import Any

from authmatrix.errors import ScanError

_SENSITIVE_FIELD = re.compile(
    r"(?:authorization|cookie|credential|password|secret|token|api[_-]?key)",
    re.IGNORECASE,
)
_SENSITIVE_TEXT = (
    re.compile(r"\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/-]+=*", re.IGNORECASE),
    re.compile(
        r"\b(password|token|secret|api[_-]?key)\s*[:=]\s*[^\s,;]+",
        re.IGNORECASE,
    ),
    re.compile(r"(https?://)[^/@\s:]+:[^/@\s]+@", re.IGNORECASE),
)


def _redact(value: Any, *, field_name: str = "") -> Any:
    if _SENSITIVE_FIELD.search(field_name):
        return "[REDACTED]"
    if isinstance(value, dict):
        return {
            key: _redact(item, field_name=str(key))
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, str):
        for pattern in _SENSITIVE_TEXT[:2]:
            value = pattern.sub(
                lambda match: (
                    match.group(1) + "[REDACTED]"
                    if match.lastindex
                    else "[REDACTED]"
                ),
                value,
            )
        value = _SENSITIVE_TEXT[2].sub(
            lambda match: f"{match.group(1)}[REDACTED]@",
            value,
        )
        return value
    return value


def sanitize_results(results: dict) -> dict:
    """Return a redacted copy of a scan result document."""
    sanitized = _redact(results)
    if not isinstance(sanitized, dict):
        raise ScanError("Scan results must be a mapping.")
    return sanitized


def load_results(path: str | Path) -> dict:
    source = Path(path)
    try:
        results = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScanError(f"Cannot read scan results: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ScanError(f"Scan results are not valid JSON: {source}") from exc
    return validate_results(results)


def validate_results(results: object) -> dict:
    """Validate the scan-result schema before rendering or comparison."""
    if not isinstance(results, dict) or results.get("schema_version") != 1:
        raise ScanError("Unsupported or invalid scan results document.")
    for field in ("target", "generated_at"):
        value = results.get(field)
        if not isinstance(value, str) or not value.strip():
            raise ScanError(f"Scan results have invalid {field}.")
    summary = results.get("summary")
    if not isinstance(summary, dict) or any(
        isinstance(summary.get(key), bool)
        or not isinstance(summary.get(key), int)
        or summary[key] < 0
        for key in ("requests", "passed", "failed", "findings")
    ):
        raise ScanError("Scan results must contain a valid summary.")
    if any(
        key in summary
        and (
            isinstance(summary[key], bool)
            or not isinstance(summary[key], int)
            or summary[key] < 0
        )
        for key in ("inconclusive", "skipped")
    ):
        raise ScanError("Scan results must contain a valid summary.")
    if (
        not isinstance(results.get("findings"), list)
        or not isinstance(results.get("checks"), list)
        or any(not isinstance(item, dict) for item in results["findings"])
        or any(not isinstance(item, dict) for item in results["checks"])
    ):
        raise ScanError("Scan results must contain findings and checks lists.")
    skipped_operations = results.get("skipped_operations", [])
    if not isinstance(skipped_operations, list) or any(
        not isinstance(item, dict)
        or any(
            not isinstance(item.get(key), str)
            for key in ("operation_id", "method", "path", "reason")
        )
        for item in skipped_operations
    ):
        raise ScanError("Scan results contain invalid skipped-operation metadata.")
    for finding in results["findings"]:
        if any(
            not isinstance(finding.get(key), str)
            for key in (
                "title",
                "severity",
                "category",
                "operation_id",
                "remediation",
            )
        ) or not isinstance(finding.get("evidence"), dict) or not isinstance(
            finding.get("reproduction"), dict
        ) or any(
            not isinstance(finding["reproduction"].get(key), str)
            for key in ("method", "path", "identity")
        ):
            raise ScanError("Finding is missing required or valid fields.")
    identities = results.get("identities", [])
    if not isinstance(identities, list) or any(
        not isinstance(identity, dict)
        or not isinstance(identity.get("name"), str)
        or not isinstance(identity.get("role", "unspecified role"), str)
        for identity in identities
    ):
        raise ScanError("Scan results contain invalid identity metadata.")
    limitations = results.get("limitations", [])
    if not isinstance(limitations, list) or any(
        not isinstance(limitation, str) for limitation in limitations
    ):
        raise ScanError("Scan results contain invalid limitation metadata.")
    return results


def render_html(results: dict) -> str:
    results = sanitize_results(results)
    summary = results["summary"]
    scan_id = html.escape(str(results.get("scan_id", "unavailable")))
    policy = html.escape(str(results.get("policy", "unavailable")))
    identities = results.get("identities", [])
    identity_rows = [
        html.escape(
            f"{identity['name']} ({identity.get('role', 'unspecified role')})"
        )
        for identity in identities
        if isinstance(identity, dict) and isinstance(identity.get("name"), str)
    ]
    finding_rows = []
    for finding in results["findings"]:
        evidence = finding["evidence"]
        finding_rows.append(
            "<article class='finding'>"
            f"<h3>{html.escape(finding['title'])} "
            f"<span class='severity'>"
            f"{html.escape(finding['severity'].upper())}</span></h3>"
            f"<p><strong>Category:</strong> {html.escape(finding['category'])} · "
            f"<strong>Operation:</strong> {html.escape(finding['operation_id'])}</p>"
            "<p><strong>Evidence:</strong> "
            f"{html.escape(json.dumps(evidence, sort_keys=True))}</p>"
            "<p><strong>Reproduction:</strong> "
            f"{html.escape(finding['reproduction']['method'])} "
            f"{html.escape(finding['reproduction']['path'])} as "
            f"{html.escape(finding['reproduction']['identity'])}</p>"
            "<p><strong>Remediation:</strong> "
            f"{html.escape(finding['remediation'])}</p>"
            "</article>"
        )
    if not finding_rows:
        finding_rows.append("<p>No unauthorized access was observed.</p>")
    check_rows = []
    for check in results["checks"]:
        if not isinstance(check, dict):
            continue
        check_rows.append(
            "<li>"
            f"{html.escape(str(check.get('operation_id', 'unknown operation')))} · "
            f"{html.escape(str(check.get('identity', 'unknown identity')))} · "
            f"expected {html.escape(str(check.get('expected', 'unknown')))}, "
            f"observed {html.escape(str(check.get('actual', 'unknown')))} "
            f"(HTTP {html.escape(str(check.get('status_code', 'unknown')))}), "
            f"{'passed' if check.get('passed') is True else 'not passed'}"
            "</li>"
        )
    if not check_rows:
        check_rows.append("<li>No check details are available.</li>")
    skipped_rows = [
        "<li>"
        f"{html.escape(item['operation_id'])} · "
        f"{html.escape(item['method'])} {html.escape(item['path'])}: "
        f"{html.escape(item['reason'])}</li>"
        for item in results.get("skipped_operations", [])
    ]
    if not skipped_rows:
        skipped_rows.append("<li>No OpenAPI operations were skipped.</li>")
    limitations = results.get("limitations", [])
    limitation_rows = [
        f"<li>{html.escape(item)}</li>"
        for item in limitations
        if isinstance(item, str)
    ]
    return (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>AuthMatrix report</title><style>"
        "body{font:16px/1.5 system-ui,sans-serif;max-width:960px;"
        "margin:2rem auto;padding:0 1rem;color:#17212b}"
        "header,.finding{border:1px solid #d5dde5;border-radius:8px;"
        "padding:1rem;margin:1rem 0}"
        ".severity{color:#9b1c1c;font-size:.8em}code{overflow-wrap:anywhere}"
        "</style></head><body>"
        "<h1>AuthMatrix authorization report</h1>"
        f"<p><strong>Scan ID:</strong> {scan_id}<br>"
        f"<strong>Policy:</strong> {policy}<br>"
        f"<strong>Target:</strong> {html.escape(results['target'])}<br>"
        f"<strong>Generated:</strong> {html.escape(results['generated_at'])}</p>"
        "<header><h2>Summary</h2>"
        f"<p>Requests: {summary['requests']} · Passed: {summary['passed']} · "
        f"Failed: {summary['failed']} · "
        f"Inconclusive: {summary.get('inconclusive', 0)} · "
        f"Skipped operations: {summary.get('skipped', 0)} · "
        f"Findings: {summary['findings']}</p></header>"
        f"<h2>Tested identities</h2><p>{', '.join(identity_rows) or 'Not recorded'}</p>"
        "<h2>Checks</h2><ul>" + "".join(check_rows) + "</ul>"
        "<h2>Skipped OpenAPI operations</h2><ul>"
        + "".join(skipped_rows)
        + "</ul>"
        "<h2>Findings</h2>" + "".join(finding_rows)
        + "<h2>Limitations</h2><ul>"
        + "".join(limitation_rows)
        + "</ul></body></html>\n"
    )


def write_report(
    results_path: str | Path,
    output_path: str | Path,
    report_format: str,
    *,
    overwrite: bool = False,
) -> None:
    results = load_results(results_path)
    destination = Path(output_path)
    if report_format not in {"json", "html"}:
        raise ScanError("Report format must be json or html.")
    if destination.is_symlink():
        raise ScanError("Report output must not be a symbolic link.")
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if report_format == "json":
            content = (
                json.dumps(sanitize_results(results), indent=2, ensure_ascii=False)
                + "\n"
            )
        elif report_format == "html":
            content = render_html(results)
        if overwrite:
            destination.write_text(content, encoding="utf-8")
        else:
            with destination.open("x", encoding="utf-8") as output:
                output.write(content)
    except FileExistsError as exc:
        raise ScanError(
            "Report output already exists; choose a new path or use --force."
        ) from exc
    except OSError as exc:
        raise ScanError(f"Cannot write report: {destination}") from exc
