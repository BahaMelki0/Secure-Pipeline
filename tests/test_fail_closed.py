import json
from pathlib import Path
import pytest
from aggregator.parsers import parse_file, ReportParseError
from aggregator.policy_engine import Policy, PolicyError
from aggregator.workflow_paths import target_path
from aggregator.models import Finding, Severity


@pytest.mark.parametrize('tool,payload', [
    ('semgrep', {}), ('semgrep', {'results': [], 'errors': [{'message': 'scan failed'}]}),
    ('trivy-fs', {}), ('trivy-fs', {'Results': 'invalid'}),
    ('checkov', {}), ('checkov', {'results': {'failed_checks': []}, 'summary': {'parsing_errors': 1}}),
    ('semgrep', {'results': [None]}),
])
def test_invalid_or_incomplete_scan_is_never_a_clean_report(tmp_path, tool, payload):
    report = tmp_path / 'report.json'
    report.write_text(json.dumps(payload), encoding='utf-8')
    with pytest.raises(ReportParseError): parse_file(tool, report)


@pytest.mark.parametrize('body', ['scoring: {minimum_score: true}', 'gate: {max_findings: {high: false}}', 'scoring: {weights: {high: true}}'])
def test_boolean_cannot_silently_change_numeric_policy(tmp_path, body):
    path = tmp_path / 'policy.yml'
    path.write_text('version: 1\n' + body, encoding='utf-8')
    with pytest.raises(PolicyError): Policy.from_file(path)


def test_workflow_paths_reject_escape_and_control_characters(tmp_path):
    assert target_path(tmp_path, 'src') == tmp_path / 'src'
    for invalid in ['../outside', str(tmp_path.parent.resolve()), 'src\nINJECTED=true', '']:
        with pytest.raises(ValueError): target_path(tmp_path, invalid)
    # Shell punctuation is harmless data, never interpolated into the command body.
    assert target_path(tmp_path, '$(echo test)') == tmp_path / '$(echo test)'


def test_expired_exception_cannot_hide_a_finding(tmp_path):
    path = tmp_path / 'policy.yml'
    path.write_text('version: 1\nallowlist:\n  - rule_id: DEMO\n    reason: time limited review\n    expires: 2000-01-01\n', encoding='utf-8')
    policy = Policy.from_file(path)
    item = Finding(tool='semgrep', severity=Severity.HIGH, rule_id='DEMO', title='Demo', location='app.py', description='Demo')
    assert not policy.allowlist[0].matches(item)


@pytest.mark.parametrize('entry', ['rule_id: DEMO', 'reason: suppress everything', 'rule_id: DEMO\n    reason: reviewed\n    expires: invalid'])
def test_exception_requires_scope_reason_and_valid_expiry(tmp_path, entry):
    path = tmp_path / 'policy.yml'
    path.write_text('version: 1\nallowlist:\n  - ' + entry + '\n', encoding='utf-8')
    with pytest.raises(PolicyError): Policy.from_file(path)
