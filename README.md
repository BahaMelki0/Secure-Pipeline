# SecurePipeline

SecurePipeline is a reusable security-as-code CI/CD gate. It runs SAST, secret, dependency, container, IaC, and SBOM tooling, then converts every scanner's JSON into one schema and makes one explainable pass/fail decision.

The useful part is not the list of scanners. It is the Python aggregation layer: scanner output stays evidence, policy stays versioned configuration, and the same gate behaves consistently in every consuming repository.

## What runs on every push and pull request

| Stage | Tool | Output |
|---|---|---|
| SAST | Semgrep | JSON findings |
| Secrets | Gitleaks | redacted JSON findings |
| SCA | Trivy filesystem | JSON vulnerabilities |
| Container | Docker + Trivy image | JSON vulnerabilities |
| IaC | Checkov | JSON misconfigurations |
| SBOM | Syft | CycloneDX JSON |
| Gate | SecurePipeline aggregator | Markdown, HTML, normalized JSON, exit code |

All raw evidence and consolidated reports are uploaded as one workflow artifact. The Markdown report is also written to the GitHub Actions job summary.

```text
scanner JSON ──> parser adapters ──> Finding[] ──> allowlist ──> policy gate
 Semgrep             common fields                    │          │
 Gitleaks     tool, severity, rule, location          │          ├─ exit 0/1
 Trivy        title, description, fingerprint         │          └─ score
 Checkov                                             └─ suppressed audit trail
```

## Repository layout

```text
secure-pipeline/
├── .github/workflows/
│   ├── security-pipeline.yml
│   └── reusable-security.yml
├── aggregator/
│   ├── parsers/
│   ├── models.py
│   ├── policy_engine.py
│   └── reporter.py
├── policy/security-policy.yml
├── examples/sample-reports/
└── tests/test_aggregator.py
```

## Use it from another repository

Create `.github/workflows/security.yml` in the consuming repository:

```yaml
name: Application security

on:
  push:
  pull_request:

permissions:
  contents: read

jobs:
  security:
    uses: BahaMelki0/Secure-Pipeline/.github/workflows/reusable-security.yml@main
    with:
      policy-path: .github/security-policy.yml
      enable-container-scan: true
```

Copy `policy/security-policy.yml` to `.github/security-policy.yml` and tune it for the application. For a stable production consumer, replace `@main` with a release tag or commit SHA.

The reusable workflow accepts these inputs:

| Input | Default | Purpose |
|---|---|---|
| `scan-path` | `.` | Subdirectory to scan |
| `policy-path` | `.github/security-policy.yml` | Policy in the target repository |
| `dockerfile` | `Dockerfile` | Dockerfile relative to the repository root |
| `enable-container-scan` | `true` | Build and scan when that Dockerfile exists |
| `toolkit-repository` | `BahaMelki0/Secure-Pipeline` | Aggregator repository |
| `toolkit-ref` | `main` | Aggregator tag, branch, or commit |

If the consuming repository has no policy at the requested path, the workflow uses SecurePipeline's default policy. Container scanning is skipped cleanly when disabled or when no Dockerfile exists.

## Policy

```yaml
version: 1
gate:
  fail_on_severity: critical
  max_findings:
    high: 5
    medium: 20
scoring:
  minimum_score: 60
  weights:
    critical: 30
    high: 12
    medium: 5
    low: 1
    info: 0
required_tools: [semgrep, gitleaks, trivy-fs, checkov]
allowlist: []
```

The gate fails when any active finding meets `fail_on_severity`, a severity budget is exceeded, the score falls below `minimum_score`, or a required report is missing. Set `fail_on_severity: off` to rely only on budgets and score.

The score starts at 100 and subtracts the configured weight for every active finding, with a floor of zero. It is intentionally transparent rather than statistical: reviewers can reproduce the result from the report.

Exceptions are narrow, documented, and remain visible in the suppressed-finding audit trail:

```yaml
allowlist:
  - tool: checkov
    rule_id: CKV_DOCKER_3
    location: "*/Dockerfile:*"
    fingerprint: "*"
    reason: "Platform injects a non-root UID; reviewed in APPSEC-1234"
```

Patterns use shell-style wildcards. Prefer an exact fingerprint when accepting one concrete finding. Never put a secret value in an allowlist; the Gitleaks parser deliberately does not ingest secret material.

## Run the aggregator locally

Python 3.11 or newer is required.

```bash
python -m venv .venv
python -m pip install -r requirements.txt
python -m aggregator \
  --policy policy/security-policy.yml \
  --input semgrep=reports/semgrep.json \
  --input gitleaks=reports/gitleaks.json \
  --input trivy-fs=reports/trivy-fs.json \
  --input trivy-container=reports/trivy-container.json \
  --input checkov=reports/checkov.json
```

Exit codes are part of the interface:

- `0`: policy passed
- `1`: reports were valid, but policy failed
- `2`: invalid policy, missing report, malformed JSON, or unsupported scanner

The command always writes Markdown, HTML, and normalized JSON when inputs are valid—even when the security policy fails.

## Demonstration: APK Sentinel

The pipeline is applied to the real `Apk-sentinel` project through its own `.github/workflows/security-pipeline.yml` and `.github/security-policy.yml`. That consumer proves the template is usable outside this repository; it disables only the container stage because APK Sentinel currently has no Dockerfile.

Publish this repository at `BahaMelki0/Secure-Pipeline` before enabling the APK Sentinel workflow. The reusable-workflow reference cannot resolve until that repository and ref exist on GitHub.

## Example report and tests

Synthetic raw scanner fixtures and generated consolidated reports live in `examples/sample-reports/`. Regenerate them from the repository root:

```bash
python -m aggregator \
  --policy examples/sample-reports/demo-policy.yml \
  --input semgrep=examples/sample-reports/raw/semgrep.json \
  --input gitleaks=examples/sample-reports/raw/gitleaks.json \
  --input trivy-fs=examples/sample-reports/raw/trivy-fs.json \
  --input trivy-container=examples/sample-reports/raw/trivy-container.json \
  --input checkov=examples/sample-reports/raw/checkov.json \
  --markdown examples/sample-reports/security-report.md \
  --html examples/sample-reports/security-report.html \
  --json examples/sample-reports/normalized-findings.json
```

Run the test suite with `python -m pytest -q`. It covers all parser contracts, severity normalization, de-duplication inputs, allowlisting, score and threshold behavior, scanner coverage, HTML escaping, CLI outputs, and pinned workflow actions.

## Security and maintenance notes

- GitHub Actions are pinned to full commit SHAs; tag comments keep updates readable.
- Scanner runtimes are pinned. Vulnerability databases and remote rule packs still update by design, so reports retain the raw evidence used for each decision.
- Scanner findings do not directly fail their steps. JSON is collected first, then one centralized gate decides the result.
- Gitleaks scans full Git history because checkout uses `fetch-depth: 0`, and reports are redacted.
- The workflow uses read-only repository permissions and disables persisted checkout credentials.
- SBOM creation is evidence generation; it is not included in the finding score.

Scanner schemas evolve. Update a parser and its fixture test together, then update the pinned tool version. The project intentionally supports only the JSON shapes it tests.

## Tool references

- [Semgrep CLI](https://semgrep.dev/docs/cli-reference)
- [Gitleaks](https://github.com/gitleaks/gitleaks)
- [Trivy Action](https://github.com/aquasecurity/trivy-action)
- [Checkov](https://www.checkov.io/2.Basics/CLI%20Command%20Reference.html)
- [Anchore SBOM Action](https://github.com/anchore/sbom-action)
