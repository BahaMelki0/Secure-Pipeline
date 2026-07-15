# SecurePipeline Security Report

> ✅ **Policy PASS** · Security score **78/100** · 3 active · 0 suppressed

## Severity summary

| Critical | High | Medium | Low | Info |
|---:|---:|---:|---:|---:|
| 0 | 1 | 2 | 0 | 0 |

## Per-tool breakdown

| Tool | Active findings |
|---|---:|
| `checkov` | 1 |
| `gitleaks` | 0 |
| `semgrep` | 1 |
| `trivy-container` | 0 |
| `trivy-fs` | 1 |

## Policy decision

- ✅ All configured policy checks passed.

## Active findings

| Severity | Tool | Rule | Title | Location |
|---|---|---|---|---|
| **HIGH** | `trivy-fs` | `CVE-2026-DEMO` | Synthetic dependency vulnerability | `requirements.txt :: example-library@1.0.0` |
| **MEDIUM** | `checkov` | `CKV_DOCKER_3` | Ensure that a user for the container has been created | `/Dockerfile:1` |
| **MEDIUM** | `semgrep` | `python.lang.security.audit.subprocess-shell-true` | Subprocess call uses shell=True with a potentially dynamic command. | `src/runner.py:31` |

_Generated 2026-07-15T20:50:50.654912+00:00_
