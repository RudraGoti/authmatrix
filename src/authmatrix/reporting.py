"""Sanitized JSON and HTML report rendering."""

from __future__ import annotations

import html
import json
from pathlib import Path

from authmatrix.errors import ScanError


def load_results(path: str | Path) -> dict:
    source = Path(path)
    try:
        results = json.loads(source.read_text(encoding="utf-8"))
    except OSError as exc:
        raise ScanError(f"Cannot read scan results: {source}") from exc
    except json.JSONDecodeError as exc:
        raise ScanError(f"Scan results are not valid JSON: {source}") from exc
    if not isinstance(results, dict) or results.get("schema_version") != 1:
        raise ScanError("Unsupported or invalid scan results document.")
    if not isinstance(results.get("findings"), list) or not isinstance(
        results.get("checks"), list
    ):
        raise ScanError("Scan results must contain findings and checks lists.")
    return results


def render_html(results: dict) -> str:
    summary = results["summary"]
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
        f"<p><strong>Target:</strong> {html.escape(results['target'])}<br>"
        f"<strong>Generated:</strong> {html.escape(results['generated_at'])}</p>"
        "<header><h2>Summary</h2>"
        f"<p>Requests: {summary['requests']} · Passed: {summary['passed']} · "
        f"Failed: {summary['failed']} · "
        f"Inconclusive: {summary.get('inconclusive', 0)} · "
        f"Findings: {summary['findings']}</p></header>"
        "<h2>Findings</h2>" + "".join(finding_rows) + "</body></html>\n"
    )


def write_report(
    results_path: str | Path, output_path: str | Path, report_format: str
) -> None:
    results = load_results(results_path)
    destination = Path(output_path)
    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        if report_format == "json":
            content = json.dumps(results, indent=2, ensure_ascii=False) + "\n"
        elif report_format == "html":
            content = render_html(results)
        else:
            raise ScanError("Report format must be json or html.")
        destination.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"Cannot write report: {destination}") from exc
