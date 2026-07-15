from __future__ import annotations

import json
from pathlib import Path

import pytest

from aggregator.__main__ import main
from aggregator.models import Finding, Severity
from aggregator.parsers import ReportParseError, parse_file
from aggregator.parsers.checkov_parser import parse_checkov
from aggregator.parsers.gitleaks_parser import parse_gitleaks
from aggregator.parsers.semgrep_parser import parse_semgrep
from aggregator.parsers.trivy_parser import parse_trivy
from aggregator.policy_engine import Policy, PolicyError, evaluate_policy
from aggregator.reporter import render_html, render_markdown


def finding(severity: Severity = Severity.MEDIUM, **overrides: object) -> Finding:
    values = {
        "tool": "semgrep",
        "severity": severity,
        "rule_id": "python.lang.security.audit.eval-detected",
        "title": "Dynamic code execution",
        "location": "src/app.py:12",
        "description": "User input reaches eval.",
    }
    values.update(overrides)
    return Finding(**values)


def write_policy(path: Path, body: str = "") -> Path:
    path.write_text(
        body
        or """version: 1
gate:
  fail_on_severity: critical
  max_findings: {high: 2}
scoring:
  minimum_score: 50
  weights: {critical: 30, high: 12, medium: 5, low: 1, info: 0}
required_tools: [semgrep, gitleaks]
allowlist: []
""",
        encoding="utf-8",
    )
    return path


def test_finding_normalizes_severity_and_has_stable_fingerprint() -> None:
    first = finding(severity="HIGH", tool="Semgrep")
    second = finding(severity=Severity.HIGH)
    assert first.severity is Severity.HIGH
    assert first.tool == "semgrep"
    assert first.fingerprint == second.fingerprint
    assert first.to_dict()["severity"] == "high"


def test_semgrep_parser() -> None:
    result = parse_semgrep(
        {
            "results": [
                {
                    "check_id": "python.flask.security.xss",
                    "path": "app.py",
                    "start": {"line": 7},
                    "extra": {
                        "severity": "ERROR",
                        "message": "Unescaped response",
                        "metadata": {"confidence": "HIGH", "category": "security"},
                    },
                }
            ]
        }
    )[0]
    assert result.severity is Severity.HIGH
    assert result.location == "app.py:7"
    assert result.rule_id == "python.flask.security.xss"


def test_gitleaks_parser_never_copies_secret_value() -> None:
    result = parse_gitleaks(
        [
            {
                "RuleID": "generic-api-key",
                "Description": "Generic API key",
                "File": "settings.py",
                "StartLine": 4,
                "Secret": "do-not-leak-this",
                "Fingerprint": "abc:settings.py:generic-api-key:4",
            }
        ]
    )[0]
    assert result.severity is Severity.HIGH
    assert result.location == "settings.py:4"
    assert "do-not-leak-this" not in json.dumps(result.to_dict())


def test_trivy_parser_handles_vulnerabilities_and_misconfigurations() -> None:
    results = parse_trivy(
        {
            "ArtifactName": "demo:latest",
            "Results": [
                {
                    "Target": "requirements.txt",
                    "Vulnerabilities": [
                        {
                            "VulnerabilityID": "CVE-2026-0001",
                            "PkgName": "demo-lib",
                            "InstalledVersion": "1.0",
                            "FixedVersion": "1.1",
                            "Severity": "CRITICAL",
                            "Title": "Example vulnerability",
                        }
                    ],
                    "Misconfigurations": [
                        {"ID": "DS001", "Title": "Unsafe image", "Severity": "MEDIUM"}
                    ],
                }
            ],
        }
    )
    assert [item.severity for item in results] == [Severity.CRITICAL, Severity.MEDIUM]
    assert results[0].location == "requirements.txt :: demo-lib@1.0"


def test_checkov_parser_accepts_multi_framework_array() -> None:
    results = parse_checkov(
        [
            {
                "check_type": "dockerfile",
                "results": {
                    "failed_checks": [
                        {
                            "check_id": "CKV_DOCKER_3",
                            "check_name": "Run as non-root",
                            "file_path": "/Dockerfile",
                            "file_line_range": [8, 8],
                            "severity": "HIGH",
                            "resource": "Dockerfile",
                        }
                    ]
                },
            }
        ]
    )
    assert len(results) == 1
    assert results[0].rule_id == "CKV_DOCKER_3"
    assert results[0].location == "/Dockerfile:8"


def test_trivy_input_preserves_scan_stage(tmp_path: Path) -> None:
    report = tmp_path / "trivy.json"
    report.write_text(
        json.dumps(
            {
                "Results": [
                    {
                        "Target": "requirements.txt",
                        "Vulnerabilities": [
                            {"VulnerabilityID": "CVE-1", "PkgName": "x", "Severity": "LOW"}
                        ],
                    }
                ]
            }
        ),
        encoding="utf-8",
    )
    assert parse_file("trivy-fs", report)[0].tool == "trivy-fs"


def test_policy_gate_threshold_score_budgets_and_coverage(tmp_path: Path) -> None:
    policy = Policy.from_file(write_policy(tmp_path / "policy.yml"))
    result = evaluate_policy(
        [finding(Severity.CRITICAL), finding(Severity.HIGH, rule_id="rule.two")],
        policy,
        {"semgrep"},
    )
    assert result.passed is False
    assert result.score == 58
    assert result.tool_counts == {"semgrep": 2}
    assert any("critical fail threshold" in item for item in result.violations)
    assert any("gitleaks" in item for item in result.violations)


def test_allowlist_suppresses_exact_finding(tmp_path: Path) -> None:
    target = finding(Severity.CRITICAL)
    policy = Policy.from_file(
        write_policy(
            tmp_path / "policy.yml",
            f"""version: 1
gate: {{fail_on_severity: critical}}
scoring: {{minimum_score: 100}}
required_tools: [semgrep]
allowlist:
  - tool: semgrep
    rule_id: "{target.rule_id}"
    location: "{target.location}"
    fingerprint: "{target.fingerprint}"
    reason: reviewed test exception
""",
        )
    )
    result = evaluate_policy([target], policy, {"semgrep"})
    assert result.passed is True
    assert result.score == 100
    assert not result.findings
    assert result.suppressed[0].reason == "reviewed test exception"


def test_reporters_escape_untrusted_scanner_content(tmp_path: Path) -> None:
    policy = Policy.from_file(write_policy(tmp_path / "policy.yml"))
    result = evaluate_policy(
        [finding(title="<script>alert(1)</script>", description="a | b")],
        policy,
        {"semgrep", "gitleaks"},
    )
    html = render_html(result)
    markdown = render_markdown(result)
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html
    assert "a \\| b" not in markdown  # descriptions are intentionally omitted from the compact table


def test_cli_writes_reports_and_returns_policy_status(tmp_path: Path) -> None:
    policy = write_policy(tmp_path / "policy.yml")
    semgrep = tmp_path / "semgrep.json"
    gitleaks = tmp_path / "gitleaks.json"
    semgrep.write_text(json.dumps({"results": []}), encoding="utf-8")
    gitleaks.write_text("[]", encoding="utf-8")
    output = tmp_path / "out"
    status = main(
        [
            "--policy", str(policy),
            "--input", f"semgrep={semgrep}",
            "--input", f"gitleaks={gitleaks}",
            "--markdown", str(output / "report.md"),
            "--html", str(output / "report.html"),
            "--json", str(output / "findings.json"),
        ]
    )
    assert status == 0
    assert (output / "report.md").is_file()
    assert json.loads((output / "findings.json").read_text(encoding="utf-8"))["passed"] is True


def test_bad_json_is_a_configuration_error(tmp_path: Path) -> None:
    report = tmp_path / "bad.json"
    report.write_text("{", encoding="utf-8")
    with pytest.raises(ReportParseError, match="invalid JSON"):
        parse_file("semgrep", report)


@pytest.mark.parametrize(
    "body, message",
    [
        ("version: 2", "version 1"),
        ("version: 1\ngate: []", "gate must be"),
        ("version: 1\nrequired_tools: semgrep", "required_tools must be"),
        ("version: 1\nallowlist: {}", "allowlist must be"),
    ],
)
def test_policy_rejects_ambiguous_shapes(tmp_path: Path, body: str, message: str) -> None:
    with pytest.raises(PolicyError, match=message):
        Policy.from_file(write_policy(tmp_path / "policy.yml", body))


def test_workflows_pin_third_party_actions_and_demo_calls_reusable_workflow() -> None:
    root = Path(__file__).parents[1]
    reusable = (root / ".github/workflows/reusable-security.yml").read_text(encoding="utf-8")
    main_workflow = (root / ".github/workflows/security-pipeline.yml").read_text(encoding="utf-8")
    assert "actions/checkout@de0fac2e4500dabe0009e67214ff5f5447ce83dd" in reusable
    assert "actions/upload-artifact@bbbca2ddaa5d8feaa63e36b76fdaad77386f024f" in reusable
    assert "uses: ./.github/workflows/reusable-security.yml" in main_workflow
    assert "@v" not in "\n".join(line for line in reusable.splitlines() if "uses:" in line)
