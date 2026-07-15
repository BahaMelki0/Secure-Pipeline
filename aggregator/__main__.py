"""Command-line entry point for aggregation, reporting, and policy gating."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

from aggregator.parsers import ReportParseError, parse_file
from aggregator.policy_engine import Policy, PolicyError, evaluate_policy
from aggregator.reporter import write_reports


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Normalize scanner JSON, apply policy, and generate consolidated reports.")
    parser.add_argument("--policy", type=Path, required=True, help="Security policy YAML file.")
    parser.add_argument(
        "--input", action="append", required=True, metavar="TOOL=REPORT.json",
        help="Scanner report; repeat per tool.",
    )
    parser.add_argument("--markdown", type=Path, default=Path("reports/security-report.md"))
    parser.add_argument("--html", type=Path, default=Path("reports/security-report.html"))
    parser.add_argument("--json", dest="json_output", type=Path, default=Path("reports/normalized-findings.json"))
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        policy = Policy.from_file(args.policy)
        findings = []
        seen_tools: set[str] = set()
        for raw_input in args.input:
            if "=" not in raw_input:
                raise ReportParseError(f"Invalid --input '{raw_input}'; expected TOOL=PATH")
            tool, raw_path = raw_input.split("=", 1)
            tool = tool.strip().lower()
            if not tool or not raw_path.strip():
                raise ReportParseError(f"Invalid --input '{raw_input}'; expected TOOL=PATH")
            findings.extend(parse_file(tool, Path(raw_path)))
            seen_tools.add(tool)
        # Stable de-duplication prevents a repeated input from inflating the gate.
        unique = {f"{finding.tool}:{finding.fingerprint}": finding for finding in findings}
        result = evaluate_policy(list(unique.values()), policy, seen_tools)
        write_reports(result, args.markdown, args.html)
        args.json_output.parent.mkdir(parents=True, exist_ok=True)
        args.json_output.write_text(json.dumps({
            "schema_version": 1,
            "passed": result.passed, "score": result.score,
            "violations": result.violations,
            "summary": {
                "active": len(result.findings),
                "suppressed": len(result.suppressed),
                "by_severity": result.severity_counts,
                "by_tool": result.tool_counts,
            },
            "findings": [finding.to_dict() for finding in result.findings],
            "suppressed": [
                {"finding": item.finding.to_dict(), "reason": item.reason} for item in result.suppressed
            ],
        }, indent=2), encoding="utf-8")
    except (OSError, PolicyError, ReportParseError) as exc:
        print(f"SecurePipeline error: {exc}", file=sys.stderr)
        return 2
    print(
        f"Policy {'PASS' if result.passed else 'FAIL'} | score={result.score}/100 | "
        f"active={len(result.findings)} | suppressed={len(result.suppressed)}"
    )
    for violation in result.violations:
        print(f" - {violation}")
    return 0 if result.passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
