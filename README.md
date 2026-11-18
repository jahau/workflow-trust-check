# workflow-trust-check

A read-only, offline explainer for a small set of GitHub Actions trust-boundary risks. It parses YAML and reports source lines, evidence, severity rationale, and cautious remediation guidance. It never executes a workflow, downloads actions, contacts GitHub, or edits files.

This is an explanatory supplement, not a workflow validator, complete security audit, or proof of safety.

## What it checks

- **Broad token permissions**: `write-all` at workflow or job scope, and explicit workflow-level write grants that apply more broadly than job-scoped grants.
- **Privileged checkout of untrusted code**: in workflows triggered by `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`, or `discussion_comment` (which run with the base repository's token and secrets), `actions/checkout` steps whose `ref` points at contributor-controlled code (`github.event.pull_request.head.*`, `github.head_ref`, `merge_commit_sha`, `refs/pull/...`, `github.event.workflow_run.head_*`) or whose `repository` points at the fork.
- **Shell interpolation**: a deliberately short allowlist of common attacker-controlled event fields in inline scripts, reported as high severity under the privileged triggers above and medium otherwise. It does not try to evaluate shell quoting, expression semantics, custom actions, or data flow.
- **Unpinned third-party actions**: step-level `uses:` actions and job-level reusable-workflow references that are not full 40-character commit SHAs. `actions/*`, `github/*`, local actions and workflows, Docker references, and SHA-pinned references are excluded.

Unrecognized constructs are not declared safe. YAML anchors and aliases are not supported by the selected marked parser; files using them fail with a visible parse error rather than being silently interpreted differently. Findings are heuristics and require human review.

## Usage

```console
cargo run -- --help
cargo run -- .github/workflows
cargo run -- --format json .github/workflows
cargo run -- examples/basic.yml
cargo run -- --fail-on high .github/workflows
```

Paths may be workflow YAML files or directories. For a directory, only the `.yml` and `.yaml` files directly inside it are scanned, matching how GitHub loads workflows; pass `--recursive` to include subdirectories. No input defaults to `.github/workflows`.

A file that cannot be read or parsed is reported on stderr and in the JSON `errors` array, and the remaining files are still analyzed.

Exit status:

- `0`: every file was analyzed, and no finding reached the `--fail-on` threshold (findings alone never fail without `--fail-on`).
- `1`: `--fail-on high|medium` was given and at least one finding has that severity or higher.
- `2`: a path was missing or invalid, or at least one file could not be analyzed. This takes precedence over `1`.

Untrusted-field matching recognizes dotted, bracketed (`github.event['issue']['title']`), indexed (`commits[0].message`), and wildcard (`commits.*.message`) property access, case-insensitively.

Example:

```console
Scanned 1 workflow file(s); 0 finding(s).

Findings are limited heuristics, not proof that a workflow is safe or unsafe.
```

JSON output has `scanned_files` (files analyzed successfully), a `findings` array (`rule`, `severity`, `file`, `line`, `evidence`, `rationale`, `remediation`), an `errors` array (`file`, `message`), and the same disclaimer.

## Relationship to existing tools

This project intentionally does not reimplement comprehensive workflow linting or automatic hardening:

- [actionlint](https://github.com/rhysd/actionlint) validates GitHub Actions syntax and expressions, checks action inputs, integrates shellcheck/pyflakes, and already detects script injection, hard-coded credentials, and permissions-related issues. Use it for correctness and broader workflow linting.
- [zizmor](https://github.com/zizmorcore/zizmor) is a dedicated CI/CD security analyzer with a broader set of offline audits, including dangerous triggers, template injection, excessive permissions, and unsafe action references. Prefer it for a fuller security audit.
- [StepSecurity Secure Workflow](https://docs.stepsecurity.io/github/orchestrate-security/secure-workflow) applies suggested workflow changes in an interactive hosted workflow. Its guidance includes restricting token permissions, pinning actions to full commit SHAs, and adding Harden-Runner. [Harden-Runner](https://github.com/step-security/harden-runner) provides runtime monitoring and network controls; it is not a local static YAML explainer.

The narrow purpose here is to explain a few high-signal trust boundaries from local files, with no network dependency or workflow execution. These capabilities overlap by design; this tool is not a replacement for the projects above.

## Build and test

```console
cargo test --locked
cargo fmt --all -- --check
cargo clippy --locked --all-targets -- -D warnings
```

Fixture-based tests cover positive detections and negative cases such as local actions, first-party actions, SHA pins, trusted metadata, permission overrides, and multiline source locations. The CLI itself has no runtime network requirement.

## License review

The project is distributed under the MIT License. Direct dependencies were selected with permissive licensing: `marked-yaml` (MIT), `clap` (MIT OR Apache-2.0), `serde`/`serde_json` (MIT OR Apache-2.0), and `walkdir` (Unlicense OR MIT). This is a project-level review, not legal advice; review transitive dependencies and license obligations before redistribution.
