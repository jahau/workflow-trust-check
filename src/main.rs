use std::collections::BTreeMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use clap::{Parser, ValueEnum};
use marked_yaml::{LoaderOptions, Spanned, from_yaml_with_options};
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

    /// Exit with status 1 when a finding of at least this severity is reported.
    #[arg(long, value_enum, value_name = "SEVERITY")]
    fail_on: Option<Severity>,

    /// Search directories recursively. By default only the files directly
    /// inside a directory are scanned, matching how GitHub loads workflows.
    #[arg(long)]
    recursive: bool,
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
    jobs: Option<BTreeMap<String, Job>>,
}

#[derive(Debug, Deserialize)]
struct Job {
    permissions: Option<Spanned<Value>>,
    uses: Option<Spanned<String>>,
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

#[derive(Clone, Copy, Debug, Serialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
enum Severity {
    High,
    Medium,
}

impl Severity {
    fn rank(self) -> u8 {
        match self {
            Severity::High => 2,
            Severity::Medium => 1,
        }
    }
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
struct FileError {
    file: String,
    message: String,
}

#[derive(Debug, Serialize)]
struct Report {
    scanned_files: usize,
    findings: Vec<Finding>,
    errors: Vec<FileError>,
    disclaimer: &'static str,
}

const DISCLAIMER: &str =
    "Findings are limited heuristics, not proof that a workflow is safe or unsafe.";

const EXIT_FINDINGS: i32 = 1;
const EXIT_ERROR: i32 = 2;

fn main() {
    match run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            eprintln!("workflow-trust-check: {error}");
            std::process::exit(EXIT_ERROR);
        }
    }
}

fn run() -> Result<i32, Box<dyn std::error::Error>> {
    let args = Args::parse();
    let files = collect_workflows(&args.paths, args.recursive)?;
    let mut findings = Vec::new();
    let mut errors = Vec::new();

    for path in &files {
        match analyze_file(path) {
            Ok(file_findings) => findings.extend(file_findings),
            Err(error) => errors.push(FileError {
                file: path.display().to_string(),
                message: error.to_string(),
            }),
        }
    }
    findings.sort_by(|left, right| {
        (&left.file, left.line, left.rule).cmp(&(&right.file, right.line, right.rule))
    });

    let report = Report {
        scanned_files: files.len() - errors.len(),
        findings,
        errors,
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
    for error in &report.errors {
        eprintln!("workflow-trust-check: {}: {}", error.file, error.message);
    }
    Ok(exit_code(&report, args.fail_on))
}

fn exit_code(report: &Report, fail_on: Option<Severity>) -> i32 {
    if !report.errors.is_empty() {
        return EXIT_ERROR;
    }
    let threshold_reached = fail_on.is_some_and(|threshold| {
        report
            .findings
            .iter()
            .any(|finding| finding.severity.rank() >= threshold.rank())
    });
    if threshold_reached { EXIT_FINDINGS } else { 0 }
}

fn collect_workflows(
    paths: &[PathBuf],
    recursive: bool,
) -> Result<Vec<PathBuf>, Box<dyn std::error::Error>> {
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
        let walker = WalkDir::new(path).follow_links(false);
        let walker = if recursive {
            walker
        } else {
            walker.max_depth(1)
        };
        for entry in walker {
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

type Jobs = BTreeMap<String, Job>;

/// Parses a workflow strictly enough that unsupported input is reported
/// instead of being analyzed partially and looking clean.
fn parse_workflow(raw: &str) -> Result<(Workflow, Jobs, &str), String> {
    // Spans are relative to the text after the BOM; GitHub ignores the BOM too.
    let source = raw.strip_prefix('\u{feff}').unwrap_or(raw);
    let options = LoaderOptions::default().error_on_duplicate_keys(true);
    let mut workflow: Workflow = from_yaml_with_options(0, source, options)
        .map_err(|error| format!("invalid or unsupported workflow YAML: {error}"))?;
    let documents = count_yaml_documents(source)
        .map_err(|error| format!("invalid or unsupported workflow YAML: {error}"))?;
    if documents > 1 {
        return Err(format!(
            "unsupported workflow YAML: found {documents} YAML documents; a workflow file must contain exactly one"
        ));
    }
    if workflow.on.is_none() {
        return Err("not a GitHub Actions workflow: missing top-level `on` key".to_owned());
    }
    let jobs = workflow
        .jobs
        .take()
        .ok_or("not a GitHub Actions workflow: missing top-level `jobs` key")?;
    Ok((workflow, jobs, source))
}

fn count_yaml_documents(source: &str) -> Result<usize, yaml_rust2::ScanError> {
    let mut parser = yaml_rust2::parser::Parser::new_from_str(source);
    let mut documents = 0;
    loop {
        match parser.next_token()?.0 {
            yaml_rust2::Event::DocumentStart => documents += 1,
            yaml_rust2::Event::StreamEnd => return Ok(documents),
            _ => {}
        }
    }
}

fn analyze_file(path: &Path) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(path).map_err(|error| format!("cannot read file: {error}"))?;
    let (workflow, jobs, source) = parse_workflow(&raw)?;
    let file = path.display().to_string();
    let mut findings = Vec::new();
    let privileged_triggers: Vec<&str> = workflow.on.as_ref().map_or_else(Vec::new, |events| {
        PRIVILEGED_TRIGGERS
            .iter()
            .copied()
            .filter(|trigger| contains_key_or_scalar(events, trigger))
            .collect()
    });
    let privileged = !privileged_triggers.is_empty();
    let trigger_list = privileged_triggers
        .iter()
        .map(|trigger| format!("`{trigger}`"))
        .collect::<Vec<_>>()
        .join(", ");

    if jobs.values().any(|job| job.permissions.is_none())
        && let Some(permissions) = &workflow.permissions
    {
        check_permissions(
            &mut findings,
            &file,
            line(permissions),
            permissions,
            "workflow",
        );
    }

    for (job_name, job) in &jobs {
        if let Some(permissions) = &job.permissions {
            check_permissions(
                &mut findings,
                &file,
                line(permissions),
                permissions,
                &format!("job `{job_name}`"),
            );
        }
        if let Some(uses) = &job.uses {
            check_unpinned(&mut findings, &file, uses, "reusable workflow");
        }
        for step in &job.steps {
            if let Some(uses) = &step.uses {
                let reference = uses.as_str();
                check_unpinned(&mut findings, &file, uses, "action");
                if privileged
                    && reference.starts_with("actions/checkout@")
                    && let Some(untrusted) = untrusted_checkout_input(&step.with)
                {
                    findings.push(Finding {
                        rule: "privileged-checkout-of-untrusted-code",
                        severity: Severity::High,
                        file: file.clone(),
                        line: line(untrusted),
                        evidence: untrusted.as_str().to_owned(),
                        rationale: format!("This workflow is triggered by {trigger_list}, which runs with the base repository's token and secrets, and it checks out contributor-controlled code. Subsequent steps may execute that code with those privileges."),
                        remediation: "Avoid checking out or executing contributor-controlled code in a privileged run. If validation is needed, use an isolated `pull_request` workflow without secrets or write permissions, and pass results to privileged steps only as data.".to_owned(),
                    });
                }
            }
            if let Some(run) = &step.run {
                for (expression, line_offset, expression_index) in
                    untrusted_expressions(run.as_str())
                {
                    let line_offset =
                        source_line_offset(source, run, expression_index).unwrap_or(line_offset);
                    findings.push(Finding {
                        rule: "untrusted-expression-in-run",
                        severity: if privileged {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        file: file.clone(),
                        line: line(run) + line_offset,
                        evidence: expression,
                        rationale: if privileged {
                            format!("An event-controlled value is interpolated directly into a shell script in a workflow triggered by {trigger_list}. Shell metacharacters in attacker-controlled text can become shell syntax, and these events run with the base repository's token and secrets.")
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

fn check_unpinned(findings: &mut Vec<Finding>, file: &str, uses: &Spanned<String>, kind: &str) {
    if !is_unpinned_third_party_action(uses.as_str()) {
        return;
    }
    findings.push(Finding {
        rule: "unpinned-third-party-action",
        severity: Severity::Medium,
        file: file.to_owned(),
        line: line(uses),
        evidence: uses.as_str().to_owned(),
        rationale: format!("A tag or branch can move, so the {kind} code used by a future run may change without a workflow edit."),
        remediation: format!("Pin the {kind} to a reviewed, full 40-character commit SHA; keep a version comment and update it deliberately."),
    });
}

/// Triggers that run in the base repository's context with access to secrets
/// and a potentially write-scoped token, while carrying attacker-influenced data.
const PRIVILEGED_TRIGGERS: &[&str] = &[
    "pull_request_target",
    "workflow_run",
    "issue_comment",
    "issues",
    "discussion",
    "discussion_comment",
];

const UNTRUSTED_CHECKOUT_REFS: &[&str] = &[
    "github.event.pull_request.head.sha",
    "github.event.pull_request.head.ref",
    "github.event.pull_request.merge_commit_sha",
    "github.event.workflow_run.head_sha",
    "github.event.workflow_run.head_branch",
    "github.head_ref",
    "refs/pull/",
];

const UNTRUSTED_CHECKOUT_REPOSITORIES: &[&str] = &[
    "github.event.pull_request.head.repo",
    "github.event.workflow_run.head_repository",
];

fn untrusted_checkout_input(with: &BTreeMap<String, Spanned<String>>) -> Option<&Spanned<String>> {
    let matches = |key: &str, patterns: &[&str]| {
        with.get(key)
            .filter(|value| patterns.iter().any(|pattern| value.contains(pattern)))
    };
    matches("ref", UNTRUSTED_CHECKOUT_REFS)
        .or_else(|| matches("repository", UNTRUSTED_CHECKOUT_REPOSITORIES))
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
    "github.event.pull_request.head.repo.default_branch",
    "github.event.review_comment.body",
    "github.event.discussion.title",
    "github.event.discussion.body",
    "github.event.head_commit.message",
    "github.event.head_commit.author.name",
    "github.event.head_commit.author.email",
    "github.event.commits.*.message",
    "github.event.commits.*.author.name",
    "github.event.commits.*.author.email",
    "github.event.pages.*.page_name",
    "github.event.workflow_run.head_branch",
    "github.event.workflow_run.display_title",
    "github.event.workflow_run.head_commit.message",
    "github.event.workflow_run.head_commit.author.name",
    "github.event.workflow_run.head_commit.author.email",
    "github.head_ref",
];

/// Rewrites property access into the dotted form used by `UNTRUSTED_FIELDS`:
/// `a['b']` becomes `a.b`, and `a[0]` / `a[*]` become `a.*`. Context names
/// are case-insensitive in GitHub expressions, so the result is lowercased.
/// String literals outside brackets are kept so they can still be ignored.
fn normalize_expression(expression: &str) -> String {
    let mut normalized = String::with_capacity(expression.len());
    let mut in_string = false;
    let mut rest = expression;
    while let Some(character) = rest.chars().next() {
        if character == '\'' {
            in_string = !in_string;
        } else if !in_string
            && character == '['
            && let Some(close) = rest.find(']')
        {
            let inner = rest[1..close].trim();
            let property = inner
                .strip_prefix('\'')
                .and_then(|name| name.strip_suffix('\''))
                .filter(|name| !name.contains('\''));
            if let Some(name) = property {
                normalized.push('.');
                normalized.push_str(name);
                rest = &rest[close + 1..];
                continue;
            }
            if inner == "*" || (!inner.is_empty() && inner.bytes().all(|b| b.is_ascii_digit())) {
                normalized.push_str(".*");
                rest = &rest[close + 1..];
                continue;
            }
        }
        normalized.push(character);
        rest = &rest[character.len_utf8()..];
    }
    normalized.to_ascii_lowercase()
}

fn untrusted_expressions(script: &str) -> Vec<(String, usize, usize)> {
    let mut found = Vec::new();
    let mut search_from = 0;
    let mut expression_index = 0;
    while let Some(relative_start) = script[search_from..].find("${{") {
        let start = search_from + relative_start;
        let expression_start = start + 3;
        let Some(relative_end) = script[expression_start..].find("}}") else {
            break;
        };
        let expression_end = expression_start + relative_end;
        let expression = script[expression_start..expression_end].trim();
        let normalized = normalize_expression(expression);
        if UNTRUSTED_FIELDS
            .iter()
            .any(|field| contains_field_reference(&normalized, field))
        {
            let full = format!("${{{{ {} }}}}", expression);
            if !found.iter().any(|(existing, _, _)| existing == &full) {
                let line_offset = script[..start]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count();
                found.push((full, line_offset, expression_index));
            }
        }
        search_from = expression_end + 2;
        expression_index += 1;
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
    character.is_ascii_alphanumeric() || matches!(character, '_' | '.' | '*' | '-')
}

fn source_line_offset(
    source: &str,
    run: &Spanned<String>,
    expression_index: usize,
) -> Option<usize> {
    let span = run.span();
    let start = span.start()?.character();
    let end = span
        .end()
        .map(|marker| marker.character())
        .unwrap_or_else(|| source.chars().count());
    let byte_offset = |character_offset| {
        source
            .char_indices()
            .nth(character_offset)
            .map_or(source.len(), |(offset, _)| offset)
    };
    let start = byte_offset(start);
    let end = byte_offset(end);
    let scalar_source = source.get(start..end)?;
    let mut search_from = 0;
    let mut current_index = 0;
    while let Some(relative_start) = scalar_source[search_from..].find("${{") {
        let start = search_from + relative_start;
        if current_index == expression_index {
            return Some(
                scalar_source[..start]
                    .bytes()
                    .filter(|byte| *byte == b'\n')
                    .count(),
            );
        }
        let expression_start = start + 3;
        let expression_end = expression_start + scalar_source[expression_start..].find("}}")?;
        search_from = expression_end + 2;
        current_index += 1;
    }
    None
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
    if !report.errors.is_empty() {
        writeln!(
            output,
            "{} file(s) could not be analyzed; see errors on stderr.",
            report.errors.len()
        )?;
    }
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
        assert!(rules.contains(&"privileged-checkout-of-untrusted-code"));
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
            vec![("${{ github.event.pull_request.title }}".to_owned(), 0, 0)]
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
    fn multiline_expression_reports_its_own_yaml_line() {
        let findings = analyze_file(&fixture("multiline-expression.yml")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 10);
        let folded_findings = analyze_file(&fixture("folded-expression.yml")).unwrap();
        assert_eq!(folded_findings.len(), 1);
        assert_eq!(folded_findings[0].line, 10);
        let multiple_findings = analyze_file(&fixture("multiple-expression-lines.yml")).unwrap();
        assert_eq!(multiple_findings.len(), 2);
        assert_eq!(
            multiple_findings
                .iter()
                .map(|finding| finding.line)
                .collect::<Vec<_>>(),
            vec![9, 10]
        );
    }

    #[test]
    fn workflow_write_is_not_reported_when_every_job_overrides_it() {
        assert!(
            analyze_file(&fixture("permissions-overridden.yml"))
                .unwrap()
                .iter()
                .all(|finding| finding.rule != "workflow-wide-write-permission")
        );
        assert!(
            analyze_file(&fixture("permissions-inherited.yml"))
                .unwrap()
                .iter()
                .any(|finding| finding.rule == "workflow-wide-write-permission")
        );
    }

    #[test]
    fn flags_unpinned_remote_reusable_workflows_only() {
        let findings = analyze_file(&fixture("reusable-workflow.yml")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "unpinned-third-party-action");
        assert_eq!(findings[0].line, 7);
        assert!(findings[0].rationale.contains("reusable workflow"));
    }

    #[test]
    fn flags_privileged_checkout_variants() {
        let findings = analyze_file(&fixture("privileged-checkout-variants.yml")).unwrap();
        let mut lines: Vec<_> = findings
            .iter()
            .filter(|finding| finding.rule == "privileged-checkout-of-untrusted-code")
            .map(|finding| finding.line)
            .collect();
        lines.sort_unstable();
        assert_eq!(lines, vec![11, 17, 23]);

        let findings = analyze_file(&fixture("workflow-run-checkout.yml")).unwrap();
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].rule, "privileged-checkout-of-untrusted-code");
        assert!(findings[0].rationale.contains("`workflow_run`"));
    }

    #[test]
    fn injection_in_other_privileged_triggers_is_high() {
        let findings = analyze_file(&fixture("issue-comment-injection.yml")).unwrap();
        assert_eq!(findings.len(), 1);
        assert!(matches!(findings[0].severity, Severity::High));
        assert!(findings[0].rationale.contains("`issue_comment`"));
    }

    #[test]
    fn matches_bracket_index_and_case_variants_of_untrusted_fields() {
        for expression in [
            "echo ${{ github.event['pull_request']['title'] }}",
            "echo ${{ github.event.commits[0].message }}",
            "echo ${{ github.event.commits.*.author.email }}",
            "echo ${{ GitHub.Event.Issue.Title }}",
            "echo ${{ github.event.workflow_run.head_branch }}",
            "echo ${{ github.event.review_comment.body }}",
        ] {
            assert_eq!(untrusted_expressions(expression).len(), 1, "{expression}");
        }
        assert!(
            untrusted_expressions("echo ${{ github.event['pull_request']['number'] }}").is_empty()
        );
        assert!(untrusted_expressions("echo ${{ 'github.event[0].commits' }}").is_empty());
        assert_eq!(
            normalize_expression("github.event['pull_request'].commits[12]"),
            "github.event.pull_request.commits.*"
        );
    }

    #[test]
    fn exit_code_reflects_errors_and_fail_on_threshold() {
        let finding = |severity| Finding {
            rule: "test",
            severity,
            file: String::new(),
            line: 1,
            evidence: String::new(),
            rationale: String::new(),
            remediation: String::new(),
        };
        let report = |findings, errors| Report {
            scanned_files: 1,
            findings,
            errors,
            disclaimer: DISCLAIMER,
        };
        let medium = report(vec![finding(Severity::Medium)], Vec::new());
        assert_eq!(exit_code(&medium, None), 0);
        assert_eq!(exit_code(&medium, Some(Severity::High)), 0);
        assert_eq!(exit_code(&medium, Some(Severity::Medium)), EXIT_FINDINGS);
        let high = report(vec![finding(Severity::High)], Vec::new());
        assert_eq!(exit_code(&high, Some(Severity::Medium)), EXIT_FINDINGS);
        let failed = report(
            Vec::new(),
            vec![FileError {
                file: "x.yml".to_owned(),
                message: "bad".to_owned(),
            }],
        );
        assert_eq!(exit_code(&failed, Some(Severity::High)), EXIT_ERROR);
    }

    #[test]
    fn unsupported_or_non_workflow_yaml_is_an_error_not_a_clean_result() {
        let error = |source: &str| parse_workflow(source).err().unwrap_or_default();
        assert!(error("").contains("missing top-level `on`"));
        assert!(error("version: 2\nupdates: []\n").contains("missing top-level `on`"));
        assert!(error("on: push\n").contains("missing top-level `jobs`"));
        assert!(
            error("on: push\njobs: {}\n---\non: pull_request_target\njobs: {}\n")
                .contains("2 YAML documents")
        );
        assert!(
            error("on: push\njobs:\n  a: {}\n  a: {}\n").contains("Duplicate key"),
            "duplicate keys hide earlier definitions"
        );
        assert!(error("a: &x 1\nb: *x\n").contains("anchor"));
        assert!(parse_workflow("---\non: push\njobs: {}\n...\n").is_ok());
    }

    #[test]
    fn byte_order_mark_does_not_hide_the_trigger() {
        let source = "\u{feff}on: pull_request_target\njobs:\n  b:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n";
        let (workflow, _, stripped) = parse_workflow(source).unwrap();
        assert!(!stripped.starts_with('\u{feff}'));
        assert!(contains_key_or_scalar(
            workflow.on.as_ref().unwrap(),
            "pull_request_target"
        ));
    }

    #[test]
    fn json_report_keeps_evidence_and_disclaimer_fields() {
        let report = Report {
            scanned_files: 0,
            findings: Vec::new(),
            errors: Vec::new(),
            disclaimer: DISCLAIMER,
        };
        let json = serde_json::to_value(report).unwrap();
        assert_eq!(json["scanned_files"], 0);
        assert!(json["errors"].as_array().unwrap().is_empty());
        assert!(json["findings"].as_array().unwrap().is_empty());
        assert!(json["disclaimer"].as_str().unwrap().contains("not proof"));
    }
}
