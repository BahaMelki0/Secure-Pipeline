"""Consolidated Markdown and standalone HTML security reporting."""

from __future__ import annotations

from datetime import datetime, timezone
from html import escape
from pathlib import Path

from aggregator.models import Finding, Severity
from aggregator.policy_engine import PolicyResult


def write_reports(result: PolicyResult, markdown_path: Path, html_path: Path) -> None:
    markdown_path.parent.mkdir(parents=True, exist_ok=True)
    html_path.parent.mkdir(parents=True, exist_ok=True)
    markdown_path.write_text(render_markdown(result), encoding="utf-8")
    html_path.write_text(render_html(result), encoding="utf-8")


def render_markdown(result: PolicyResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    icon = "✅" if result.passed else "❌"
    lines = [
        "# SecurePipeline Security Report", "",
        f"> {icon} **Policy {status}** · Security score **{result.score}/100** · "
        f"{len(result.findings)} active · {len(result.suppressed)} suppressed", "",
        "## Severity summary", "",
        "| Critical | High | Medium | Low | Info |", "|---:|---:|---:|---:|---:|",
        "| " + " | ".join(str(result.severity_counts.get(item.value, 0)) for item in Severity) + " |", "",
        "## Per-tool breakdown", "", "| Tool | Active findings |", "|---|---:|",
    ]
    if result.tool_counts:
        lines.extend(f"| `{tool}` | {count} |" for tool, count in result.tool_counts.items())
    else:
        lines.append("| _No findings_ | 0 |")
    lines.extend(["", "## Policy decision", ""])
    if result.violations:
        lines.extend(f"- ❌ {violation}" for violation in result.violations)
    else:
        lines.append("- ✅ All configured policy checks passed.")
    lines.extend(["", "## Active findings", ""])
    if result.findings:
        lines.extend(["| Severity | Tool | Rule | Title | Location |", "|---|---|---|---|---|"])
        for finding in _sorted(result.findings):
            lines.append(
                f"| **{finding.severity.value.upper()}** | `{_md(finding.tool)}` | `{_md(finding.rule_id)}` | "
                f"{_md(finding.title)} | `{_md(finding.location)}` |"
            )
    else:
        lines.append("No active findings.")
    if result.suppressed:
        lines.extend(["", "## Suppressed findings", "", "| Tool | Rule | Location | Reason |", "|---|---|---|---|"])
        for item in result.suppressed:
            finding = item.finding
            lines.append(f"| `{_md(finding.tool)}` | `{_md(finding.rule_id)}` | `{_md(finding.location)}` | {_md(item.reason)} |")
    lines.extend(["", f"_Generated {datetime.now(timezone.utc).isoformat()}_", ""])
    return "\n".join(lines)


def render_html(result: PolicyResult) -> str:
    status = "PASS" if result.passed else "FAIL"
    status_class = "pass" if result.passed else "fail"
    severity_cards = "".join(
        f'<div><span>{item.value}</span><strong class="{item.value}">{result.severity_counts.get(item.value, 0)}</strong></div>'
        for item in Severity
    )
    tool_rows = "".join(
        f"<tr><td>{escape(tool)}</td><td>{count}</td></tr>" for tool, count in result.tool_counts.items()
    ) or '<tr><td class="muted">No scanner reports</td><td>0</td></tr>'
    violation_items = "".join(f"<li>{escape(value)}</li>" for value in result.violations) or "<li>All configured policy checks passed.</li>"
    finding_rows = "".join(
        f'<tr><td><span class="badge {finding.severity.value}">{finding.severity.value}</span></td>'
        f"<td>{escape(finding.tool)}</td><td><code>{escape(finding.rule_id)}</code></td>"
        f"<td><strong>{escape(finding.title)}</strong><small>{escape(finding.description)}</small></td>"
        f"<td><code>{escape(finding.location)}</code></td></tr>"
        for finding in _sorted(result.findings)
    ) or '<tr><td colspan="5" class="empty">No active findings.</td></tr>'
    suppressed_rows = "".join(
        f"<tr><td>{escape(item.finding.tool)}</td><td><code>{escape(item.finding.rule_id)}</code></td>"
        f"<td><code>{escape(item.finding.location)}</code></td><td>{escape(item.reason)}</td></tr>"
        for item in result.suppressed
    ) or '<tr><td colspan="4" class="empty">No suppressed findings.</td></tr>'
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>SecurePipeline Security Report</title><style>
:root{{--bg:#0b1017;--panel:#111923;--line:#243241;--text:#e7eef5;--muted:#8293a3;--accent:#42d8ca;--critical:#ff5d69;--high:#ff9b52;--medium:#edc65e;--low:#6db4ef}}*{{box-sizing:border-box}}body{{max-width:1280px;margin:0 auto;padding:38px 24px;background:var(--bg);color:var(--text);font:14px/1.5 system-ui,sans-serif}}header{{display:flex;justify-content:space-between;align-items:flex-end;border-bottom:1px solid var(--line);padding-bottom:22px}}h1{{margin:0;font-size:28px}}header p{{margin:5px 0 0;color:var(--muted)}}.decision{{padding:8px 13px;border:1px solid;font:700 12px ui-monospace,monospace}}.decision.pass{{color:#72e3ad;border-color:#2f7655}}.decision.fail{{color:var(--critical);border-color:#7b3239}}.score{{display:grid;grid-template-columns:1.2fr repeat(5,1fr);gap:10px;margin:20px 0}}.score>div{{padding:15px;border:1px solid var(--line);background:var(--panel)}}.score span,.finding small{{display:block;color:var(--muted)}}.score strong{{font-size:25px}}.score .critical,.badge.critical{{color:var(--critical)}}.score .high,.badge.high{{color:var(--high)}}.score .medium,.badge.medium{{color:var(--medium)}}.score .low,.badge.low{{color:var(--low)}}section{{margin-top:18px;padding:18px;border:1px solid var(--line);background:var(--panel)}}h2{{margin:0 0 13px;font-size:16px}}table{{width:100%;border-collapse:collapse}}th,td{{padding:10px;border-bottom:1px solid var(--line);text-align:left;vertical-align:top}}th{{color:var(--muted);font-size:10px;text-transform:uppercase}}code{{font:11px ui-monospace,monospace}}.badge{{text-transform:uppercase;font:700 10px ui-monospace,monospace}}.finding small{{margin-top:4px;max-width:550px}}.muted,.empty{{color:var(--muted)}}ul{{margin:0;padding-left:20px}}@media(max-width:800px){{.score{{grid-template-columns:repeat(2,1fr)}}header{{align-items:flex-start;gap:15px;flex-direction:column}}.table-wrap{{overflow:auto}}table{{min-width:760px}}}}
</style></head><body><header><div><h1>SecurePipeline</h1><p>Consolidated application security report</p></div><div class="decision {status_class}">POLICY {status}</div></header><div class="score"><div><span>Security score</span><strong>{result.score}/100</strong></div>{severity_cards}</div><section><h2>Policy decision</h2><ul>{violation_items}</ul></section><section><h2>Per-tool breakdown</h2><table><thead><tr><th>Tool</th><th>Active findings</th></tr></thead><tbody>{tool_rows}</tbody></table></section><section><h2>Active findings</h2><div class="table-wrap"><table class="finding"><thead><tr><th>Severity</th><th>Tool</th><th>Rule</th><th>Finding</th><th>Location</th></tr></thead><tbody>{finding_rows}</tbody></table></div></section><section><h2>Suppressed findings</h2><div class="table-wrap"><table><thead><tr><th>Tool</th><th>Rule</th><th>Location</th><th>Reason</th></tr></thead><tbody>{suppressed_rows}</tbody></table></div></section></body></html>"""


def _sorted(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda item: (-item.severity.rank, item.tool, item.rule_id, item.location))


def _md(value: str) -> str:
    return (
        escape(str(value), quote=False)
        .replace("`", "&#96;")
        .replace("|", "\\|")
        .replace("\n", " ")
        .replace("\r", " ")
    )
