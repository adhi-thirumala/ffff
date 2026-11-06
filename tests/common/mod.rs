//! Shared harness for GNU-differential conformance tests.
//!
//! Runs the same argv, stdin bytes, and environment against `/usr/bin/grep`
//! (invoked with `argv[0] = "grep"` so error prefixes read `grep: ...`) and
//! against `ffff::Grep::search_with_environment`, then compares raw
//! `Output { stdout, stderr, status }` byte for byte.

use std::ffi::{OsStr, OsString};
use std::io::Write;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use ffff::{Environment, Grep, Output};

/// The oracle binary. The shell `grep` is a harness shim and must never be
/// used; this absolute path bypasses PATH entirely.
pub const GNU: &str = "/usr/bin/grep";

/// Byte-string argv entry for case tables.
pub fn s(bytes: &'static [u8]) -> OsString {
    use std::os::unix::ffi::OsStringExt;
    OsString::from_vec(bytes.to_vec())
}

#[derive(Clone, Copy)]
pub enum FileSpec {
    /// Regular file content (arbitrary bytes: NUL, invalid UTF-8, no EOL).
    Text(&'static [u8]),
    /// Symlink whose target is the given byte string (relative to its dir).
    Symlink(&'static [u8]),
}

use FileSpec::{Symlink, Text};

pub struct Case {
    pub name: &'static str,
    pub files: Vec<(&'static [u8], FileSpec)>,
    /// Owned argv: `s()` is a non-const constructor, so &'static arrays of
    /// its results don't get static promotion; a Vec keeps arbitrary bytes.
    pub args: Vec<OsString>,
    pub stdin: &'static [u8],
    pub env: &'static [(&'static str, Option<&'static str>)],
}

impl Case {
    pub fn new(
        name: &'static str,
        files: &[(&'static [u8], FileSpec)],
        args: Vec<OsString>,
        stdin: &'static [u8],
        env: &'static [(&'static str, Option<&'static str>)],
    ) -> Self {
        Self {
            name,
            files: files.to_vec(),
            args,
            stdin,
            env,
        }
    }
    pub fn env_of(&self, name: &str) -> Option<&'static str> {
        self.env
            .iter()
            .find(|(k, _)| *k == name)
            .and_then(|(_, v)| *v)
    }
}

macro_rules! case {
    ($name:expr, $files:expr, $args:expr) => {
        crate::common::Case::new($name, $files, $args.to_vec(), b"", &[])
    };
    ($name:expr, $files:expr, $args:expr, stdin $stdin:expr) => {
        crate::common::Case::new($name, $files, $args.to_vec(), $stdin, &[])
    };
    ($name:expr, $files:expr, $args:expr, env $env:expr) => {
        crate::common::Case::new($name, $files, $args.to_vec(), b"", $env)
    };
    ($name:expr, $files:expr, $args:expr, stdin $stdin:expr, env $env:expr) => {
        crate::common::Case::new($name, $files, $args.to_vec(), $stdin, $env)
    };
}
/// Populate a fresh tempdir with the case fixtures.
pub fn populate(root: &Path, case: &Case) {
    for (rel, spec) in &case.files {
        let path = root.join(PathBuf::from(OsStr::from_bytes(rel)));
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).unwrap();
        }
        match *spec {
            Text(bytes) => std::fs::write(&path, bytes).unwrap(),
            Symlink(target) => {
                std::os::unix::fs::symlink(OsStr::from_bytes(target), &path).unwrap();
            }
        }
    }
}

/// Request-local wrapper environment mirroring the process env GNU gets.
/// Empty TERM/GREP_COLORS strings mean "unset" for GNU and are normalized.
pub fn wrapper_env(case: &Case) -> Environment {
    Environment {
        locale: case.env_of("LC_ALL").unwrap_or("C").into(),
        grep_colors: case
            .env_of("GREP_COLORS")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
        posixly_correct: case.env_of("POSIXLY_CORRECT").is_some(),
        stdout_is_terminal: false,
        term: case
            .env_of("TERM")
            .filter(|v| !v.is_empty())
            .map(str::to_string),
    }
}

/// Run /usr/bin/grep in `root` with the case's argv, stdin, and env.
pub fn run_gnu(root: &Path, case: &Case) -> (Vec<u8>, Vec<u8>, i32) {
    let mut cmd = Command::new(GNU);
    cmd.arg0("grep");
    cmd.args(&case.args);
    cmd.current_dir(root);
    cmd.stdin(Stdio::piped());
    cmd.stdout(Stdio::piped());
    cmd.stderr(Stdio::piped());
    cmd.env_clear();
    cmd.env("LC_ALL", "C");
    cmd.env("PATH", "/usr/bin:/bin");
    for (key, value) in case.env {
        cmd.env(key, value.unwrap_or(""));
    }
    let mut child = cmd.spawn().expect("failed to spawn /usr/bin/grep");
    if let Err(error) = child.stdin.take().unwrap().write_all(case.stdin) {
        assert_eq!(
            error.kind(),
            std::io::ErrorKind::BrokenPipe,
            "failed to write oracle stdin"
        );
    }
    let out = child
        .wait_with_output()
        .expect("failed to read oracle output");
    let status = out.status.code().expect("oracle died from a signal");
    (out.stdout, out.stderr, status)
}
pub async fn run_ffff(grep: &Grep, case: &Case) -> Result<Output, ffff::Error> {
    grep.search_with_environment(case.args.clone(), case.stdin.to_vec(), wrapper_env(case))
        .await
}

/// Compare wrapper output byte-for-byte with the GNU oracle.
#[track_caller]
pub fn assert_outputs(case: &Case, gnu: &(Vec<u8>, Vec<u8>, i32), got: &Output) {
    let (gnu_out, gnu_err, gnu_status) = gnu;
    assert_eq!(
        &got.stdout, gnu_out,
        "stdout mismatch in case {}",
        case.name
    );
    assert_eq!(
        &got.stderr, gnu_err,
        "stderr mismatch in case {}",
        case.name
    );
    assert_eq!(
        got.status, *gnu_status,
        "status mismatch in case {}",
        case.name
    );
}

/// Run every case in the table against a fresh root+Grep and the oracle.
pub async fn assert_cases(cases: &[Case]) {
    assert!(
        Path::new(GNU).exists(),
        "differential conformance tests require {GNU}"
    );
    for case in cases {
        let root = tempfile::tempdir().unwrap();
        populate(root.path(), case);
        let grep = Grep::new(root.path())
            .await
            .unwrap_or_else(|e| panic!("Grep::new failed in case {}: {e}", case.name));
        let gnu = run_gnu(root.path(), case);
        let got = run_ffff(&grep, case)
            .await
            .unwrap_or_else(|e| panic!("search failed in case {}: {e}", case.name));
        assert_outputs(case, &gnu, &got);
    }
}
