# workflow-trust-check

A read-only, offline explainer for a small set of GitHub Actions trust-boundary risks. It parses YAML and reports source lines, evidence, severity rationale, and cautious remediation guidance. It never executes a workflow, downloads actions, contacts GitHub, or edits files.

This is an explanatory supplement, not a workflow validator, complete security audit, or proof of safety.

## What it checks

- **Broad token permissions**: `write-all` at workflow or job scope, and explicit workflow-level write grants that apply more broadly than job-scoped grants.
- **Risky `pull_request_target` combinations**: checking out the contributor-controlled pull request head, and known untrusted event values interpolated directly into `run:` scripts.
- **Shell interpolation**: a deliberately short allowlist of common attacker-controlled event fields in inline scripts. It does not try to evaluate shell quoting, expression semantics, custom actions, or data flow.
- **Unpinned third-party actions**: remote action/reusable-workflow references that are not full 40-character commit SHAs. `actions/*`, `github/*`, local actions, Docker references, and SHA-pinned references are excluded.

Unrecognized constructs are not declared safe. YAML anchors and aliases are not supported by the selected marked parser; files using them fail with a visible parse error rather than being silently interpreted differently. Findings are heuristics and require human review.

## Usage

```console
cargo run -- --help
cargo run -- .github/workflows
cargo run -- --format json .github/workflows
cargo run -- examples/basic.yml
```

Paths may be workflow YAML files or directories. Directories are searched recursively for `.yml` and `.yaml` files. No input defaults to `.github/workflows`. Findings do not cause a non-zero exit; I/O and YAML errors do.

Example:

```console
Scanned 1 workflow file(s); 0 finding(s).

Findings are limited heuristics, not proof that a workflow is safe or unsafe.
```

JSON output has `scanned_files`, a `findings` array (`rule`, `severity`, `file`, `line`, `evidence`, `rationale`, `remediation`), and the same disclaimer.

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

The integration fixtures cover positive detections and negative cases such as local actions, first-party actions, SHA pins, and trusted metadata. The CLI itself has no runtime network requirement.

## License review

The project is distributed under the MIT License. Direct dependencies were selected with permissive licensing: `marked-yaml` (MIT), `clap` (MIT OR Apache-2.0), `serde`/`serde_json` (MIT OR Apache-2.0), and `walkdir` (Unlicense OR MIT). This is a project-level review, not legal advice; review transitive dependencies and license obligations before redistribution.
