# Changelog

## v0.1.0

First public release.

### Checks

- `broad-token-permissions`: `permissions: write-all` at workflow or job scope.
- `workflow-wide-write-permission`: workflow-level write grants inherited by jobs that do not override permissions.
- `privileged-checkout-of-untrusted-code`: `actions/checkout` of contributor-controlled refs or fork repositories in workflows triggered by `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`, or `discussion_comment`.
- `untrusted-expression-in-run`: known attacker-controlled event fields interpolated into `run:` scripts; high severity under the privileged triggers above.
- `unpinned-third-party-action`: third-party actions and reusable workflows not pinned to a full commit SHA.

### CLI

- Text and JSON output with file, line, evidence, rationale, and remediation for each finding.
- `--fail-on high|medium` for CI gating; exit status `0`, `1` (threshold reached), or `2` (errors).
- `--recursive` to scan subdirectories; by default only files directly inside a directory are scanned.
- Per-file error reporting: files that cannot be analyzed are reported and do not stop the scan.
- Unsupported input (anchors, aliases, tags, duplicate keys, multiple documents, non-workflow YAML) is reported as an error rather than a clean result.

### Distribution

- Prebuilt binaries for Linux x86_64, Windows x86_64, and macOS (Apple silicon and Intel), with SHA-256 checksums and third-party license notices.
- Minimum supported Rust version: 1.88.
