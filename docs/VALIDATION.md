# Validation and current limits

The October 6, 2026 review added regression coverage for incomplete scanner reports, malformed structures, boolean policy values, expired/unscoped exceptions and workflow path escapes.

Run `python -m pytest -q`. Exit codes from the aggregator are 0 (policy pass), 1 (policy failure), and 2 (report/policy/configuration error). A configuration error must never be interpreted as a clean scan.

## Fail-safe collection

Semgrep requires a results array and rejects scanner-reported errors. Checkov requires framework results and failed_checks arrays, and rejects parsing errors. Trivy requires recognizable results/schema metadata. These contracts distinguish supported clean reports from arbitrary empty JSON, but do not establish that every relevant source file was scanned.

Scanner findings are centralized in the policy gate; scanner execution errors remain failures. Paths are passed as environment data and validated against the target repository, including symlink resolution. Container scan inputs participate in aggregation only when the container target exists; requiring trivy-container while skipping it fails coverage.

Exceptions require a reason and rule/fingerprint scope. Optional `expires: YYYY-MM-DD` is inclusive through that UTC date; expired entries cannot suppress findings. Tool version/data feeds and rule packs affect reproducibility; raw artifacts remain necessary.

## Manual smoke checks

1. Aggregate the bundled sample reports: expect the documented demo decision and generated HTML/Markdown/JSON.
2. Replace a Semgrep sample with an error-only object: expect exit 2, never PASS.
3. Add an expired exception: the matching finding must stay active.
4. Call the workflow with a path outside the target checkout: validation must fail before tools scan it.
5. In a test consumer, introduce a controlled vulnerable fixture: verify policy failure and raw artifacts; remove it and rerun.

Unit tests validate the aggregator and input contracts, not the entire hosted scanner ecosystem. Full scanner installation/remote rule access, Docker execution and hosted workflow results are separate integration checks. HTML reports use the shared Obsidian Signal red/black palette; severity colors preserve meaning.
