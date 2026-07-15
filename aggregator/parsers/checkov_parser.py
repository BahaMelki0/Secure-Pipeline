"""Convert Checkov JSON output into normalized findings."""

from __future__ import annotations

from typing import Any

from aggregator.models import Finding, Severity


def parse_checkov(payload: Any) -> list[Finding]:
    documents = payload if isinstance(payload, list) else [payload]
    findings: list[Finding] = []
    for document in documents:
        if not isinstance(document, dict):
            raise TypeError("expected an object or array of framework objects")
        failed = (document.get("results") or {}).get("failed_checks") or []
        for check in failed:
            path = str(check.get("file_path") or check.get("file_abs_path") or "unknown")
            line_range = check.get("file_line_range") or []
            line = line_range[0] if line_range else None
            location = f"{path}:{line}" if line is not None else path
            rule_id = str(check.get("check_id") or "checkov.unknown")
            title = str(check.get("check_name") or rule_id)
            findings.append(Finding(
                tool="checkov", severity=Severity.parse(check.get("severity"), Severity.MEDIUM),
                rule_id=rule_id, title=title, location=location,
                description=str(check.get("guideline") or title),
                metadata={
                    "resource": check.get("resource"), "framework": check.get("check_type"),
                    "guideline": check.get("guideline"),
                },
            ))
    return findings
