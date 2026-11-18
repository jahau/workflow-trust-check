use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use marked_yaml::{Spanned, from_yaml};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use walkdir::WalkDir;

#[derive(Debug, Parser)]
#[command(
    name = "workflow-trust-check",
    version,
    about = "Explain selected GitHub Actions trust-boundary risks without running workflows"
)]
struct Args {
    #[arg(value_name = "PATH", default_value = ".github/workflows")]
    paths: Vec<PathBuf>,

    #[arg(long, value_enum, default_value_t = OutputFormat::Text)]
    format: OutputFormat,
}

#[derive(Clone, Copy, Debug, Default, ValueEnum)]
enum OutputFormat {
    #[default]
    Text,
    Json,
}

#[derive(Debug, Deserialize)]
struct Workflow {
    #[serde(rename = "on")]
    on: Option<Spanned<Value>>,
    permissions: Option<Spanned<Value>>,
    #[serde(default)]
    jobs: BTreeMap<String, Job>,
}

#[derive(Debug, Deserialize)]
struct Job {
    permissions: Option<Spanned<Value>>,
    #[serde(default)]
    steps: Vec<Step>,
}

#[derive(Debug, Deserialize)]
struct Step {
    uses: Option<Spanned<String>>,
    run: Option<Spanned<String>>,
    #[serde(default)]
    with: BTreeMap<String, Spanned<String>>,
}

#[derive(Clone, Copy, Debug, Serialize)]
#[serde(rename_all = "lowercase")]
enum Severity {
    High,
    Medium,
}

#[derive(Debug, Serialize)]
struct Finding {
    rule: &'static str,
    severity: Severity,
    file: String,
    line: usize,
    evidence: String,
    rationale: String,
    remediation: String,
}

#[derive(Debug, Serialize)]
struct Report {
    scanned_files: usize,
    findings: Vec<Finding>,
    disclaimer: &'static str,
}

const DISCLAIMER: &str =
    "Findings are limited heuristics, not proof that a workflow is safe or unsafe.";

fn main() {
    if let Err(error) = run() {
        eprintln!("workflow-trust-check: {error}");
        std::process::exit(2);
    }
}

fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();
    let files = collect_workflows(&args.paths)?;
    let mut findings = Vec::new();

    for path in &files {
        findings.extend(analyze_file(path)?);
    }
    findings.sort_by(|left, right| {
        (&left.file, left.line, left.rule).cmp(&(&right.file, right.line, right.rule))
    });

    let report = Report {
        scanned_files: files.len(),
        findings,
        disclaimer: DISCLAIMER,
    };
    let stdout = io::stdout();
    let mut output = stdout.lock();
    match args.format {
        OutputFormat::Text => write_text(&mut output, &report)?,
        OutputFormat::Json => {
            writeln!(output, "{}", serde_json::to_string_pretty(&report)?)?;
        }
    }
    Ok(())
}

fn collect_workflows(paths: &[PathBuf]) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
    let mut files = Vec::new();
    for path in paths {
        if !path.exists() {
            return Err(format!("path does not exist: {}", path.display()).into());
        }
        if path.is_file() {
            if is_yaml(path) {
                files.push(path.clone());
            } else {
                return Err(format!("expected a .yml or .yaml file: {}", path.display()).into());
            }
            continue;
        }
        for entry in WalkDir::new(path).follow_links(false) {
            let entry = entry?;
            if entry.file_type().is_file() && is_yaml(entry.path()) {
                files.push(entry.into_path());
            }
        }
    }
    files.sort();
    files.dedup();
    Ok(files)
}

fn is_yaml(path: &Path) -> bool {
    path.extension()
        .and_then(|extension| extension.to_str())
        .is_some_and(|extension| {
            extension.eq_ignore_ascii_case("yml") || extension.eq_ignore_ascii_case("yaml")
        })
}

fn analyze_file(path: &Path) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let source = fs::read_to_string(path)?;
    let workflow: Workflow = from_yaml(0, &source).map_err(|error| {
        format!(
            "{}: invalid or unsupported workflow YAML: {error}",
            path.display()
        )
    })?;
    let file = path.display().to_string();
    let mut findings = Vec::new();
    let pull_request_target = workflow
        .on
        .as_ref()
        .is_some_and(|events| contains_key_or_scalar(events, "pull_request_target"));

    if let Some(permissions) = &workflow.permissions {
        check_permissions(
            &mut findings,
            &file,
            line(permissions),
            permissions,
            "workflow",
        );
    }

    for (job_name, job) in &workflow.jobs {
        if let Some(permissions) = &job.permissions {
            check_permissions(
                &mut findings,
                &file,
                line(permissions),
                permissions,
                &format!("job `{job_name}`"),
            );
        }
        for step in &job.steps {
            if let Some(uses) = &step.uses {
                let reference = uses.as_str();
                if is_unpinned_third_party_action(reference) {
                    findings.push(Finding {
                        rule: "unpinned-third-party-action",
                        severity: Severity::Medium,
                        file: file.clone(),
                        line: line(uses),
                        evidence: reference.to_owned(),
                        rationale: "A tag or branch can move, so the action code used by a future run may change without a workflow edit.".to_owned(),
                        remediation: "Pin the action to a reviewed, full 40-character commit SHA; keep a version comment and update it deliberately.".to_owned(),
                    });
                }
                if pull_request_target
                    && reference.starts_with("actions/checkout@")
                    && step.with.get("ref").is_some_and(|checkout_ref| {
                        contains_pull_request_head(checkout_ref.as_str())
                    })
                {
                    let checkout_ref = &step.with["ref"];
                    findings.push(Finding {
                        rule: "pull-request-target-checks-out-head",
                        severity: Severity::High,
                        file: file.clone(),
                        line: line(checkout_ref),
                        evidence: checkout_ref.as_str().to_owned(),
                        rationale: "This workflow is triggered by `pull_request_target` and checks out the contributor-controlled pull request head. Subsequent steps may execute that code with the target event's elevated token or secrets.".to_owned(),
                        remediation: "Avoid checking out or executing the pull request head in a privileged `pull_request_target` run. If validation is needed, use an isolated `pull_request` workflow without secrets or write permissions.".to_owned(),
                    });
                }
            }
            if let Some(run) = &step.run {
                for expression in untrusted_expressions(run.as_str()) {
                    findings.push(Finding {
                        rule: "untrusted-expression-in-run",
                        severity: if pull_request_target {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        file: file.clone(),
                        line: line(run),
                        evidence: expression,
                        rationale: if pull_request_target {
                            "An event-controlled value is interpolated directly into a shell script in a `pull_request_target` workflow. Shell metacharacters in attacker-controlled text can become shell syntax, and the event may have privileged access.".to_owned()
                        } else {
                            "An event-controlled value is inserted into a generated shell script before execution, which can turn attacker-controlled text into shell syntax.".to_owned()
                        },
                        remediation: "Pass the value through an `env:` entry and quote/validate the environment variable in the script, or handle it in an action rather than interpolating it into `run:`.".to_owned(),
                    });
                }
            }
        }
    }
    Ok(findings)
}

fn check_permissions(
    findings: &mut Vec<Finding>,
    file: &str,
    line: usize,
    permissions: &Value,
    scope: &str,
) {
    if permissions.as_str() == Some("write-all") {
        findings.push(Finding {
            rule: "broad-token-permissions",
            severity: Severity::High,
            file: file.to_owned(),
            line,
            evidence: format!("{scope}: permissions: write-all"),
            rationale: "The workflow token is granted write access across all permission scopes, increasing the impact of a compromised step.".to_owned(),
            remediation: "Replace `write-all` with only the required permission scopes and grant write access at the narrowest job level.".to_owned(),
        });
        return;
    }
    if scope == "workflow"
        && permissions.as_object().is_some_and(|scopes| {
            scopes.values().any(|value| {
                value
                    .as_str()
                    .is_some_and(|value| value.eq_ignore_ascii_case("write"))
            })
        })
    {
        findings.push(Finding {
            rule: "workflow-wide-write-permission",
            severity: Severity::Medium,
            file: file.to_owned(),
            line,
            evidence: "workflow-level permissions include write access".to_owned(),
            rationale: "A workflow-level write grant applies to jobs that do not override the permission map, broader than granting a capability only to the job that needs it.".to_owned(),
            remediation: "Move write scopes to the specific job that requires them and keep other jobs read-only.".to_owned(),
        });
    }
}

fn is_unpinned_third_party_action(reference: &str) -> bool {
    if reference.starts_with("./") || reference.starts_with("docker://") {
        return false;
    }
    let Some((repository, revision)) = reference.split_once('@') else {
        return false;
    };
    let Some((owner, _)) = repository.split_once('/') else {
        return false;
    };
    if owner.eq_ignore_ascii_case("actions") || owner.eq_ignore_ascii_case("github") {
        return false;
    }
    !(revision.len() == 40 && revision.bytes().all(|byte| byte.is_ascii_hexdigit()))
}

const UNTRUSTED_FIELDS: &[&str] = &[
    "github.event.pull_request.title",
    "github.event.pull_request.body",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.head.label",
    "github.event.issue.title",
    "github.event.issue.body",
    "github.event.comment.body",
    "github.event.review.body",
    "github.event.head_commit.message",
    "github.head_ref",
];

fn untrusted_expressions(script: &str) -> Vec<String> {
    let mut found = Vec::new();
    let mut remaining = script;
    while let Some(start) = remaining.find("${{") {
        let expression_start = start + 3;
        let Some(end) = remaining[expression_start..].find("}}") else {
            break;
        };
        let expression = remaining[expression_start..expression_start + end].trim();
        if UNTRUSTED_FIELDS
            .iter()
            .any(|field| contains_field_reference(expression, field))
        {
            let full = format!("${{{{ {} }}}}", expression);
            if !found.contains(&full) {
                found.push(full);
            }
        }
        remaining = &remaining[expression_start + end + 2..];
    }
    found
}

fn contains_field_reference(expression: &str, field: &str) -> bool {
    let mut in_string = false;
    let mut chars = expression.char_indices().peekable();
    while let Some((index, character)) = chars.next() {
        if character == '\'' {
            if in_string && chars.peek().is_some_and(|(_, next)| *next == '\'') {
                chars.next();
                continue;
            }
            in_string = !in_string;
            continue;
        }
        if in_string || !expression[index..].starts_with(field) {
            continue;
        }
        let previous_is_identifier = expression[..index]
            .chars()
            .next_back()
            .is_some_and(is_expression_path_character);
        let end = index + field.len();
        let next_is_identifier = expression[end..]
            .chars()
            .next()
            .is_some_and(is_expression_path_character);
        if !previous_is_identifier && !next_is_identifier {
            return true;
        }
    }
    false
}

fn is_expression_path_character(character: char) -> bool {
    character.is_ascii_alphanumeric() || character == '_' || character == '.'
}

fn contains_pull_request_head(value: &str) -> bool {
    value.contains("github.event.pull_request.head.sha")
        || value.contains("github.event.pull_request.head.ref")
}

fn contains_key_or_scalar(value: &Value, expected: &str) -> bool {
    match value {
        Value::String(scalar) => scalar == expected,
        Value::Array(values) => values
            .iter()
            .any(|value| contains_key_or_scalar(value, expected)),
        Value::Object(mapping) => mapping.contains_key(expected),
        _ => false,
    }
}

fn line<T>(value: &Spanned<T>) -> usize {
    value
        .span()
        .start()
        .map(|marker| marker.line())
        .unwrap_or(1)
}

fn write_text(output: &mut impl Write, report: &Report) -> io::Result<()> {
    writeln!(
        output,
        "Scanned {} workflow file(s); {} finding(s).",
        report.scanned_files,
        report.findings.len()
    )?;
    for finding in &report.findings {
        writeln!(
            output,
            "{}:{}: {:?} [{}]",
            finding.file, finding.line, finding.severity, finding.rule
        )?;
        writeln!(output, "  Evidence: {}", finding.evidence)?;
        writeln!(output, "  Why: {}", finding.rationale)?;
        writeln!(output, "  Guidance: {}", finding.remediation)?;
    }
    writeln!(output, "\n{}", report.disclaimer)?;
    output.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures")
            .join(name)
    }

    #[test]
    fn reports_expected_trust_boundaries_with_source_lines() {
        let findings = analyze_file(&fixture("risky.yml")).unwrap();
        let rules: Vec<_> = findings.iter().map(|finding| finding.rule).collect();
        assert!(rules.contains(&"broad-token-permissions"));
        assert!(rules.contains(&"pull-request-target-checks-out-head"));
        assert!(rules.contains(&"untrusted-expression-in-run"));
        assert!(rules.contains(&"unpinned-third-party-action"));
        assert!(findings.iter().all(|finding| finding.line > 0));
        assert!(findings.iter().any(|finding| {
            finding.rule == "untrusted-expression-in-run"
                && finding.evidence.contains("github.event.pull_request.title")
                && matches!(finding.severity, Severity::High)
        }));
    }

    #[test]
    fn clean_fixture_does_not_trigger_narrow_rules() {
        assert!(analyze_file(&fixture("clean.yml")).unwrap().is_empty());
        assert!(
            analyze_file(&fixture("low-false-positive.yml"))
                .unwrap()
                .is_empty()
        );
    }

    #[test]
    fn excludes_first_party_and_sha_pinned_actions() {
        assert!(!is_unpinned_third_party_action("actions/checkout@v4"));
        assert!(!is_unpinned_third_party_action(
            "acme/action@0123456789abcdef0123456789abcdef01234567"
        ));
        assert!(!is_unpinned_third_party_action("./.github/actions/local"));
        assert!(is_unpinned_third_party_action("acme/action@v2"));
    }

    #[test]
    fn only_flags_known_untrusted_fields_inside_expressions() {
        assert_eq!(
            untrusted_expressions("echo '${{ github.event.pull_request.title }}'"),
            vec!["${{ github.event.pull_request.title }}"]
        );
        assert!(untrusted_expressions("echo '${{ github.sha }}'").is_empty());
        assert!(
            untrusted_expressions("echo \"${{ 'github.event.pull_request.title' }}\"").is_empty()
        );
        assert!(
            untrusted_expressions("echo '${{ github.event.pull_request.title_suffix }}'")
                .is_empty()
        );
        assert!(untrusted_expressions(
            "echo '${{ github.event.pull_request.title }}' '${{ github.event.pull_request.title }}'"
        )
        .len()
            == 1);
    }

    #[test]
    fn json_report_keeps_evidence_and_disclaimer_fields() {
        let report = Report {
            scanned_files: 0,
            findings: Vec::new(),
            disclaimer: DISCLAIMER,
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["scanned_files"], 0);
        assert!(json["findings"].as_array().unwrap().is_empty());
        assert!(json["disclaimer"].as_str().unwrap().contains("not proof"));
    }
}
