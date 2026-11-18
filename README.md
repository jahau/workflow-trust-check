# workflow-trust-check

A read-only, offline explainer for a small set of GitHub Actions trust-boundary risks. It parses YAML and reports source lines, evidence, severity rationale, and cautious remediation guidance. It never executes a workflow, downloads actions, contacts GitHub, or edits files.

This is an explanatory supplement, not a workflow validator, complete security audit, or proof of safety. It complements comprehensive scanners such as zizmor and actionlint (see [Relationship to existing tools](#relationship-to-existing-tools)); it does not replace them.

## Example

[`examples/risky.yml`](examples/risky.yml):

```yaml
name: Label pull request
on:
  pull_request_target:
    types: [opened, synchronize]
permissions: write-all
jobs:
  triage:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: acme/labeler@v2
      - name: Announce
        run: echo "Triaging ${{ github.event.pull_request.title }}"
```

```console
$ workflow-trust-check examples/risky.yml
Scanned 1 workflow file(s); 4 finding(s).
examples/risky.yml:5: High [broad-token-permissions]
  Evidence: workflow: permissions: write-all
  Why: The workflow token is granted write access across all permission scopes, increasing the impact of a compromised step.
  Guidance: Replace `write-all` with only the required permission scopes and grant write access at the narrowest job level.
examples/risky.yml:12: High [privileged-checkout-of-untrusted-code]
  Evidence: ${{ github.event.pull_request.head.sha }}
  Why: This workflow is triggered by `pull_request_target`, which runs with the base repository's token and secrets, and it checks out contributor-controlled code. Subsequent steps may execute that code with those privileges.
  Guidance: Avoid checking out or executing contributor-controlled code in a privileged run. If validation is needed, use an isolated `pull_request` workflow without secrets or write permissions, and pass results to privileged steps only as data.
examples/risky.yml:13: Medium [unpinned-third-party-action]
  Evidence: acme/labeler@v2
  Why: A tag or branch can move, so the action code used by a future run may change without a workflow edit.
  Guidance: Pin the action to a reviewed, full 40-character commit SHA; keep a version comment and update it deliberately.
examples/risky.yml:15: High [untrusted-expression-in-run]
  Evidence: ${{ github.event.pull_request.title }}
  Why: An event-controlled value is interpolated directly into a shell script in a workflow triggered by `pull_request_target`. Shell metacharacters in attacker-controlled text can become shell syntax, and these events run with the base repository's token and secrets.
  Guidance: Pass the value through an `env:` entry and quote/validate the environment variable in the script, or handle it in an action rather than interpolating it into `run:`.

Findings are limited heuristics, not proof that a workflow is safe or unsafe.
```

This output is checked by the test suite against [`examples/risky.txt`](examples/risky.txt), so it stays reproducible.

## What it checks

- **Broad token permissions**: `write-all` at workflow or job scope, and explicit workflow-level write grants that apply more broadly than job-scoped grants.
- **Privileged checkout of untrusted code**: in workflows triggered by `pull_request_target`, `workflow_run`, `issue_comment`, `issues`, `discussion`, or `discussion_comment` (which run with the base repository's token and secrets), `actions/checkout` steps whose `ref` points at contributor-controlled code (`github.event.pull_request.head.*`, `github.head_ref`, `merge_commit_sha`, `refs/pull/...`, `github.event.workflow_run.head_*`) or whose `repository` points at the fork.
- **Shell interpolation**: a deliberately short allowlist of common attacker-controlled event fields in inline scripts, reported as high severity under the privileged triggers above and medium otherwise. It does not try to evaluate shell quoting, expression semantics, custom actions, or data flow.
- **Unpinned third-party actions**: step-level `uses:` actions and job-level reusable-workflow references that are not full 40-character commit SHAs. `actions/*`, `github/*`, local actions and workflows, Docker references, and SHA-pinned references are excluded.

Unrecognized constructs are not declared safe. Input the tool cannot analyze faithfully is reported as an error instead of producing a clean result: YAML anchors, aliases and tags, duplicate mapping keys, files with more than one YAML document, and YAML files without top-level `on` and `jobs` keys. Findings are heuristics and require human review.

## Installation

Prebuilt binaries for each release are attached to the [GitHub Releases](https://github.com/jahau/workflow-trust-check/releases) page, each with a `.sha256` checksum file and a `THIRD-PARTY-LICENSES.md` notice. Verify the checksum, extract the archive, and put `workflow-trust-check` (or `workflow-trust-check.exe`) on your `PATH`.

To build from source (Rust 1.88 or newer):

```console
cargo install --locked --git https://github.com/jahau/workflow-trust-check --tag v0.1.0
```

### Supported platforms

| Platform | Prebuilt binary | CI tested |
| --- | --- | --- |
| Linux x86_64 (`x86_64-unknown-linux-gnu`) | yes | yes |
| Windows x86_64 (`x86_64-pc-windows-msvc`) | yes | yes |
| macOS Apple silicon (`aarch64-apple-darwin`) | yes | yes |
| macOS Intel (`x86_64-apple-darwin`) | yes | build only |

Other platforms supported by Rust should work when built from source but are not tested.

## Usage

```console
workflow-trust-check --help
workflow-trust-check .github/workflows
workflow-trust-check --format json .github/workflows
workflow-trust-check --fail-on high .github/workflows
```

Paths may be workflow YAML files or directories. For a directory, only the `.yml` and `.yaml` files directly inside it are scanned, matching how GitHub loads workflows; pass `--recursive` to include subdirectories. No input defaults to `.github/workflows`.

A file that cannot be read or parsed is reported on stderr and in the JSON `errors` array, and the remaining files are still analyzed.

Exit status:

- `0`: every file was analyzed, and no finding reached the `--fail-on` threshold (findings alone never fail without `--fail-on`).
- `1`: `--fail-on high|medium` was given and at least one finding has that severity or higher.
- `2`: a path was missing or invalid, or at least one file could not be analyzed. This takes precedence over `1`.

Untrusted-field matching recognizes dotted, bracketed (`github.event['issue']['title']`), indexed (`commits[0].message`), and wildcard (`commits.*.message`) property access, case-insensitively.

JSON output has `scanned_files` (files analyzed successfully), a `findings` array (`rule`, `severity`, `file`, `line`, `evidence`, `rationale`, `remediation`), an `errors` array (`file`, `message`), and the same disclaimer.

## Known limitations

- **Narrow rule set.** Only the four checks above exist. No finding means none of these heuristics matched, not that the workflow is safe.
- **No data-flow analysis.** Values passed through `env:`, step outputs, artifacts, `GITHUB_ENV`, or custom actions are not followed. Untrusted fields used in `with:` inputs, `if:` conditions, or `env:` are not reported.
- **Short allowlist of untrusted fields.** Event fields outside the built-in list, and whole-object expressions such as `toJSON(github.event)`, are not flagged.
- **Checkout detection is pattern-based.** Only `actions/checkout` with recognized `ref`/`repository` expressions is detected; checking out code with `git`, `gh`, or other actions is not.
- **No knowledge of repository settings.** Default token permissions, environment protections, fork approval rules, and branch protections are not visible from YAML and are not taken into account.
- **First-party actions are trusted.** `actions/*` and `github/*` references are not reported even when unpinned.
- **Composite actions and called reusable workflows are not analyzed**; only the local workflow files passed in are read.
- **Restricted YAML subset.** Anchors, aliases, tags, duplicate keys, and multi-document files are rejected with an error (GitHub also rejects several of these).

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

Fixture-based tests cover positive detections and negative cases such as local actions, first-party actions, SHA pins, trusted metadata, permission overrides, multiline source locations, and rejected YAML constructs. CLI tests cover exit codes, error reporting, directory scanning, and the documented example output. CI runs these on Linux, Windows, and macOS, checks the minimum supported Rust version, and runs the tool on this repository's own workflows.

The CLI has no runtime network requirement. Its only side effects are reading the given paths and writing the report to stdout and errors to stderr.

## License review

The project is distributed under the MIT License. Direct dependencies use permissive licenses: `marked-yaml` (MIT), `yaml-rust2` (MIT OR Apache-2.0), `clap` (MIT OR Apache-2.0), `serde`/`serde_json` (MIT OR Apache-2.0), and `walkdir` (Unlicense OR MIT). Transitive dependencies in `Cargo.lock` are also permissive, including MIT, Apache-2.0, Unlicense, Zlib (`foldhash`), BSD-3-Clause (`encoding_rs`), and Unicode-3.0 (`unicode-ident`). Release archives include `THIRD-PARTY-LICENSES.md`, generated by [`scripts/third_party_licenses.py`](scripts/third_party_licenses.py) from the locked dependency set for each target. This is a project-level review, not legal advice.
