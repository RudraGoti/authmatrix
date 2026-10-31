"""Compare AuthMatrix scan results against a saved baseline."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

from authmatrix.errors import ScanError
from authmatrix.reporting import load_results


def _finding_fingerprint(finding: Mapping[str, Any]) -> str:
    """Build a stable identifier from a finding's security-relevant fields."""
    try:
        reproduction = finding["reproduction"]
        identity = {
            "category": finding["category"],
            "operation_id": finding["operation_id"],
            "method": reproduction["method"],
            "path": reproduction["path"],
            "identity": reproduction["identity"],
            "resource_id": reproduction.get("resource_id"),
        }
    except (KeyError, TypeError) as exc:
        raise ScanError("Finding is missing required comparison fields.") from exc

    required_fields = (
        "category",
        "operation_id",
        "method",
        "path",
        "identity",
    )

    if not all(
        isinstance(identity[key], str) and identity[key] for key in required_fields
    ):
        raise ScanError("Finding contains invalid comparison fields.")

    if identity["resource_id"] is not None and not isinstance(
        identity["resource_id"], str
    ):
        raise ScanError("Finding contains an invalid resource ID.")

    canonical = json.dumps(
        identity,
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _validate_comparison_report(results: dict[str, Any]) -> None:
    """Validate metadata required for a reliable comparison."""
    for field in ("target", "generated_at"):
        value = results.get(field)

        if not isinstance(value, str) or not value.strip():
            raise ScanError(f"Scan results contain an invalid {field} value.")


def compare_results(
    baseline_path: str,
    current_path: str,
) -> dict[str, Any]:
    """Compare two compatible scan reports and classify their findings."""
    baseline = load_results(baseline_path)
    current = load_results(current_path)
    _validate_comparison_report(baseline)
    _validate_comparison_report(current)

    if baseline["target"] != current["target"]:
        raise ScanError("Cannot compare scan results from different targets.")

    def index_findings(
        results: dict[str, Any],
    ) -> dict[str, dict[str, Any]]:
        indexed: dict[str, dict[str, Any]] = {}

        for finding in results["findings"]:
            if not isinstance(finding, dict):
                raise ScanError("Scan results contain an invalid finding.")

            fingerprint = _finding_fingerprint(finding)
            indexed.setdefault(fingerprint, finding)

        return indexed

    baseline_findings = index_findings(baseline)
    current_findings = index_findings(current)

    baseline_ids = set(baseline_findings)
    current_ids = set(current_findings)

    new_ids = current_ids - baseline_ids
    fixed_ids = baseline_ids - current_ids
    recurring_ids = baseline_ids & current_ids

    return {
        "schema_version": 1,
        "target": current["target"],
        "baseline_generated_at": baseline["generated_at"],
        "current_generated_at": current["generated_at"],
        "summary": {
            "new": len(new_ids),
            "fixed": len(fixed_ids),
            "recurring": len(recurring_ids),
        },
        "new_findings": [current_findings[key] for key in sorted(new_ids)],
        "fixed_findings": [baseline_findings[key] for key in sorted(fixed_ids)],
        "recurring_findings": [current_findings[key] for key in sorted(recurring_ids)],
    }


def write_comparison(
    results: dict[str, Any],
    output_path: str | Path,
) -> None:
    """Write comparison results as formatted JSON."""
    destination = Path(output_path)

    try:
        destination.parent.mkdir(parents=True, exist_ok=True)
        content = json.dumps(results, indent=2, ensure_ascii=False) + "\n"
        destination.write_text(content, encoding="utf-8")
    except OSError as exc:
        raise ScanError(f"Cannot write comparison results: {destination}") from exc
