"""Convert Trivy filesystem or container JSON into normalized findings."""

from __future__ import annotations

from typing import Any

from aggregator.models import Finding, Severity


def parse_trivy(payload: Any) -> list[Finding]:
    if not isinstance(payload, dict):
        raise TypeError("expected a Trivy JSON object")
    if "Results" not in payload and "SchemaVersion" not in payload:
        raise TypeError("missing Trivy results/schema metadata")
    if payload.get("Results") is not None and not isinstance(payload["Results"], list):
        raise TypeError("Results must be an array or null")
    findings: list[Finding] = []
    for result in payload.get("Results") or []:
        target = str(result.get("Target") or payload.get("ArtifactName") or "unknown")
        for vulnerability in result.get("Vulnerabilities") or []:
            package = str(vulnerability.get("PkgName") or "package")
            installed = str(vulnerability.get("InstalledVersion") or "unknown")
            rule_id = str(vulnerability.get("VulnerabilityID") or "trivy.unknown")
            title = str(vulnerability.get("Title") or rule_id)
            description = str(vulnerability.get("Description") or title)
            findings.append(Finding(
                tool="trivy", severity=Severity.parse(vulnerability.get("Severity")),
                rule_id=rule_id, title=title,
                location=f"{target} :: {package}@{installed}", description=description,
                metadata={
                    "package": package, "installed_version": installed,
                    "fixed_version": vulnerability.get("FixedVersion"),
                    "primary_url": vulnerability.get("PrimaryURL"),
                },
            ))
        for misconfiguration in result.get("Misconfigurations") or []:
            rule_id = str(misconfiguration.get("ID") or "trivy.misconfig.unknown")
            title = str(misconfiguration.get("Title") or rule_id)
            message = str(misconfiguration.get("Message") or misconfiguration.get("Description") or title)
            findings.append(Finding(
                tool="trivy", severity=Severity.parse(misconfiguration.get("Severity"), Severity.MEDIUM),
                rule_id=rule_id, title=title, location=target, description=message,
                metadata={"resolution": misconfiguration.get("Resolution")},
            ))
    return findings
