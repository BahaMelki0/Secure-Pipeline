"""Configurable security gate, allowlist, and score calculation."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

import yaml

from aggregator.models import Finding, Severity


class PolicyError(ValueError):
    pass


@dataclass(frozen=True, slots=True)
class AllowlistEntry:
    tool: str = "*"
    rule_id: str = "*"
    location: str = "*"
    fingerprint: str = "*"
    reason: str = "Accepted risk"
    expires: date | None = None

    def matches(self, finding: Finding) -> bool:
        if self.expires and datetime.now(timezone.utc).date() > self.expires:
            return False
        return (
            fnmatch(finding.tool, self.tool.lower())
            and fnmatch(finding.rule_id, self.rule_id)
            and fnmatch(finding.location, self.location)
            and fnmatch(finding.fingerprint, self.fingerprint)
        )


@dataclass(frozen=True, slots=True)
class Policy:
    fail_on_severity: Severity | None
    max_findings: dict[Severity, int]
    minimum_score: int
    score_weights: dict[Severity, int]
    required_tools: tuple[str, ...]
    allowlist: tuple[AllowlistEntry, ...]

    @classmethod
    def from_file(cls, path: str | Path) -> "Policy":
        policy_path = Path(path)
        if not policy_path.is_file():
            raise PolicyError(f"Policy file not found: {policy_path}")
        try:
            value = yaml.safe_load(policy_path.read_text(encoding="utf-8")) or {}
        except yaml.YAMLError as exc:
            raise PolicyError(f"Invalid policy YAML: {exc}") from exc
        if not isinstance(value, dict):
            raise PolicyError("Policy root must be a YAML mapping")
        if type(value.get("version", 1)) is not int or value.get("version", 1) != 1:
            raise PolicyError("Only security policy version 1 is supported")
        gate = _mapping(value.get("gate"), "gate")
        scoring = _mapping(value.get("scoring"), "scoring")
        threshold_value = str(gate.get("fail_on_severity", "critical")).lower()
        fail_on = None if threshold_value in {"none", "off", "disabled"} else Severity.parse(threshold_value)
        if fail_on and threshold_value not in {item.value for item in Severity}:
            raise PolicyError(f"Unsupported fail_on_severity: {threshold_value}")
        max_findings: dict[Severity, int] = {}
        for severity, limit in _mapping(gate.get("max_findings"), "gate.max_findings").items():
            parsed_severity = Severity.parse(severity)
            if str(severity).lower() not in {item.value for item in Severity}:
                raise PolicyError(f"Unsupported max_findings severity: {severity}")
            if type(limit) is not int or limit < 0:
                raise PolicyError(f"max_findings.{severity} must be a non-negative integer")
            max_findings[parsed_severity] = limit
        minimum_score = scoring.get("minimum_score", 0)
        if type(minimum_score) is not int or not 0 <= minimum_score <= 100:
            raise PolicyError("scoring.minimum_score must be an integer from 0 to 100")
        default_weights = {
            Severity.CRITICAL: 30, Severity.HIGH: 12, Severity.MEDIUM: 5,
            Severity.LOW: 1, Severity.INFO: 0,
        }
        for severity, weight in _mapping(scoring.get("weights"), "scoring.weights").items():
            parsed = Severity.parse(severity)
            if str(severity).lower() not in {item.value for item in Severity}:
                raise PolicyError(f"Unsupported score severity: {severity}")
            if type(weight) is not int or weight < 0:
                raise PolicyError(f"scoring.weights.{severity} must be a non-negative integer")
            default_weights[parsed] = weight
        raw_allowlist = value.get("allowlist")
        if raw_allowlist is None:
            raw_allowlist = []
        if not isinstance(raw_allowlist, list):
            raise PolicyError("allowlist must be a YAML list")
        allowlist = []
        for index, entry in enumerate(raw_allowlist, start=1):
            if not isinstance(entry, dict):
                raise PolicyError(f"allowlist entry {index} must be a mapping")
            if not isinstance(entry.get("reason"), str) or not entry["reason"].strip():
                raise PolicyError(f"allowlist entry {index} requires an explicit reason")
            if all(str(entry.get(key, '*')) == '*' for key in ('rule_id', 'fingerprint')):
                raise PolicyError(f"allowlist entry {index} requires a rule_id or fingerprint scope")
            expires = None
            if entry.get('expires') is not None:
                try:
                    expires = date.fromisoformat(str(entry['expires']))
                except ValueError as exc:
                    raise PolicyError(f"allowlist entry {index} has an invalid expiry date") from exc
            allowlist.append(AllowlistEntry(
                tool=str(entry.get("tool", "*")), rule_id=str(entry.get("rule_id", "*")),
                location=str(entry.get("location", "*")), fingerprint=str(entry.get("fingerprint", "*")),
                reason=str(entry.get("reason", "Accepted risk")),
                expires=expires,
            ))
        required_tools = value.get("required_tools")
        if required_tools is None:
            required_tools = []
        if not isinstance(required_tools, list) or not all(
            isinstance(tool, str) and tool.strip() for tool in required_tools
        ):
            raise PolicyError("required_tools must be a list of non-empty scanner names")
        return cls(
            fail_on_severity=fail_on, max_findings=max_findings,
            minimum_score=minimum_score, score_weights=default_weights,
            required_tools=tuple(tool.strip().lower() for tool in required_tools),
            allowlist=tuple(allowlist),
        )


def _mapping(value: Any, name: str) -> dict[str, Any]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise PolicyError(f"{name} must be a YAML mapping")
    return value


@dataclass(frozen=True, slots=True)
class SuppressedFinding:
    finding: Finding
    reason: str


@dataclass(slots=True)
class PolicyResult:
    passed: bool
    score: int
    findings: list[Finding]
    suppressed: list[SuppressedFinding]
    violations: list[str]
    severity_counts: dict[str, int] = field(default_factory=dict)
    tool_counts: dict[str, int] = field(default_factory=dict)


def evaluate_policy(findings: list[Finding], policy: Policy, seen_tools: set[str]) -> PolicyResult:
    active: list[Finding] = []
    suppressed: list[SuppressedFinding] = []
    for finding in findings:
        match = next((entry for entry in policy.allowlist if entry.matches(finding)), None)
        if match:
            suppressed.append(SuppressedFinding(finding, match.reason))
        else:
            active.append(finding)
    severity_counter = Counter(finding.severity for finding in active)
    tool_counter = Counter(finding.tool for finding in active)
    score = max(0, 100 - sum(policy.score_weights[finding.severity] for finding in active))
    violations: list[str] = []
    if policy.fail_on_severity:
        blocking = [finding for finding in active if finding.severity.rank >= policy.fail_on_severity.rank]
        if blocking:
            violations.append(
                f"{len(blocking)} finding(s) meet or exceed the {policy.fail_on_severity.value} fail threshold"
            )
    for severity, limit in policy.max_findings.items():
        count = severity_counter[severity]
        if count > limit:
            violations.append(f"{severity.value} finding budget exceeded: {count} > {limit}")
    if score < policy.minimum_score:
        violations.append(f"security score below minimum: {score} < {policy.minimum_score}")
    missing_tools = sorted(set(policy.required_tools) - {tool.lower() for tool in seen_tools})
    if missing_tools:
        violations.append(f"required scanner reports missing: {', '.join(missing_tools)}")
    return PolicyResult(
        passed=not violations, score=score, findings=active, suppressed=suppressed,
        violations=violations,
        severity_counts={severity.value: severity_counter[severity] for severity in Severity},
        tool_counts={tool: tool_counter[tool] for tool in sorted(set(seen_tools) | set(tool_counter))},
    )
