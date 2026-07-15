"""Convert Semgrep JSON output into normalized findings."""

from __future__ import annotations

from typing import Any

from aggregator.models import Finding, Severity


def parse_semgrep(payload: Any) -> list[Finding]:
    if not isinstance(payload, dict):
        raise TypeError("expected an object with a results array")
    findings: list[Finding] = []
    for result in payload.get("results", []):
        extra = result.get("extra") or {}
        metadata = extra.get("metadata") or {}
        path = str(result.get("path") or "unknown")
        line = (result.get("start") or {}).get("line")
        location = f"{path}:{line}" if line is not None else path
        rule_id = str(result.get("check_id") or "semgrep.unknown")
        message = str(extra.get("message") or rule_id)
        findings.append(Finding(
            tool="semgrep",
            severity=Severity.parse(extra.get("severity"), Severity.MEDIUM),
            rule_id=rule_id,
            title=str(metadata.get("shortlink") or message).splitlines()[0][:160],
            location=location,
            description=message,
            metadata={"confidence": metadata.get("confidence"), "category": metadata.get("category")},
        ))
    return findings

