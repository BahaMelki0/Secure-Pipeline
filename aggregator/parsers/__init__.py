"""Scanner JSON parsers."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from aggregator.models import Finding
from aggregator.parsers.checkov_parser import parse_checkov
from aggregator.parsers.gitleaks_parser import parse_gitleaks
from aggregator.parsers.semgrep_parser import parse_semgrep
from aggregator.parsers.trivy_parser import parse_trivy

PARSERS: dict[str, Callable[[Any], list[Finding]]] = {
    "semgrep": parse_semgrep,
    "trivy": parse_trivy,
    "trivy-fs": parse_trivy,
    "trivy-container": parse_trivy,
    "gitleaks": parse_gitleaks,
    "checkov": parse_checkov,
}


class ReportParseError(ValueError):
    pass


def parse_file(tool: str, path: str | Path) -> list[Finding]:
    normalized_tool = tool.strip().lower()
    if normalized_tool not in PARSERS:
        raise ReportParseError(f"Unsupported scanner '{tool}'")
    report_path = Path(path)
    if not report_path.is_file():
        raise ReportParseError(f"{tool}: report not found: {report_path}")
    try:
        payload = json.loads(report_path.read_text(encoding="utf-8-sig"))
    except json.JSONDecodeError as exc:
        raise ReportParseError(f"{tool}: invalid JSON in {report_path}: {exc.msg}") from exc
    try:
        findings = PARSERS[normalized_tool](payload)
    except (KeyError, TypeError, ValueError) as exc:
        raise ReportParseError(f"{tool}: unsupported report structure in {report_path}: {exc}") from exc
    # Preserve the stage name so filesystem and container Trivy remain distinguishable.
    if normalized_tool in {"trivy-fs", "trivy-container"}:
        findings = [
            Finding(
                tool=normalized_tool, severity=item.severity, rule_id=item.rule_id,
                title=item.title, location=item.location, description=item.description,
                fingerprint=item.fingerprint, metadata=item.metadata,
            )
            for item in findings
        ]
    return findings

