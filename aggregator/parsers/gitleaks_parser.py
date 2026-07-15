"""Convert Gitleaks JSON output into normalized findings."""

from __future__ import annotations

from typing import Any

from aggregator.models import Finding, Severity


def parse_gitleaks(payload: Any) -> list[Finding]:
    if payload is None:
        return []
    if not isinstance(payload, list):
        raise TypeError("expected an array of leaks")
    findings: list[Finding] = []
    for leak in payload:
        path = str(leak.get("File") or leak.get("file") or "unknown")
        line = leak.get("StartLine", leak.get("startLine"))
        location = f"{path}:{line}" if line is not None else path
        rule_id = str(leak.get("RuleID") or leak.get("ruleID") or "gitleaks.unknown")
        description = str(leak.get("Description") or leak.get("description") or "Potential secret detected")
        findings.append(Finding(
            tool="gitleaks", severity=Severity.HIGH, rule_id=rule_id,
            title=description, location=location,
            description="A credential-like value was detected. Rotate the secret and remove it from repository history.",
            fingerprint=str(leak.get("Fingerprint") or leak.get("fingerprint") or ""),
            metadata={"commit": leak.get("Commit"), "tags": leak.get("Tags") or []},
        ))
    return findings

