use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const RISKY: &str = "on: pull_request_target\njobs:\n  t:\n    steps:\n      - run: echo ${{ github.event.pull_request.title }}\n";
const MEDIUM: &str = "on: push\njobs:\n  t:\n    steps:\n      - uses: acme/action@v1\n";

struct TempDir(PathBuf);

impl TempDir {
    fn new(name: &str) -> Self {
        let path = std::env::temp_dir().join(format!(
            "workflow-trust-check-{name}-{}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&path);
        fs::create_dir_all(&path).unwrap();
        Self(path)
    }

    fn write(&self, relative: &str, contents: &str) {
        let path = self.0.join(relative);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, contents).unwrap();
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

fn run(args: &[&str], dir: &Path) -> Output {
    Command::new(env!("CARGO_BIN_EXE_workflow-trust-check"))
        .args(args)
        .arg(dir)
        .output()
        .unwrap()
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn findings_exit_zero_unless_fail_on_threshold_is_reached() {
    let dir = TempDir::new("fail-on");
    dir.write("medium.yml", MEDIUM);

    assert_eq!(run(&[], &dir.0).status.code(), Some(0));
    assert_eq!(run(&["--fail-on", "high"], &dir.0).status.code(), Some(0));
    assert_eq!(run(&["--fail-on", "medium"], &dir.0).status.code(), Some(1));

    dir.write("risky.yml", RISKY);
    assert_eq!(run(&["--fail-on", "high"], &dir.0).status.code(), Some(1));
}

#[test]
fn invalid_file_is_reported_without_hiding_other_results() {
    let dir = TempDir::new("errors");
    dir.write("risky.yml", RISKY);
    dir.write("anchors.yml", "a: &x 1\nb: *x\n");

    let output = run(&["--format", "json"], &dir.0);
    assert_eq!(output.status.code(), Some(2));
    let report = json(&output);
    assert_eq!(report["scanned_files"], 1);
    assert_eq!(report["findings"].as_array().unwrap().len(), 1);
    let errors = report["errors"].as_array().unwrap();
    assert_eq!(errors.len(), 1);
    assert!(errors[0]["file"].as_str().unwrap().ends_with("anchors.yml"));
    assert!(String::from_utf8_lossy(&output.stderr).contains("anchors.yml"));
}

#[test]
fn subdirectories_are_only_scanned_with_recursive() {
    let dir = TempDir::new("recursive");
    dir.write("top.yml", MEDIUM);
    dir.write("nested/inner.yml", MEDIUM);

    assert_eq!(
        json(&run(&["--format", "json"], &dir.0))["scanned_files"],
        1
    );
    assert_eq!(
        json(&run(&["--format", "json", "--recursive"], &dir.0))["scanned_files"],
        2
    );
}
