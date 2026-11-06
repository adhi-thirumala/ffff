//! Contract tests for the raw-Output API itself: unsupported options become
//! status-2 outputs, the search helper chain is equivalent, stdin consumption
//! is accounted, and one `Grep` session reflects fresh filesystem state and
//! serves concurrent searches. GNU-differential comparisons live in
//! `compat.rs`; nothing here spawns a subprocess.

use ffff::{Environment, Grep, Output};

/// Request-local environment mirroring what GNU gets in the differential
/// suite: C locale, no terminal, no colors.
fn c_env() -> Environment {
    Environment {
        locale: "C".into(),
        grep_colors: None,
        posixly_correct: false,
        stdout_is_terminal: false,
        term: None,
    }
}

#[tokio::test]
async fn unsupported_options_yield_status_two_output() {
    let root = tempfile::tempdir().unwrap();
    let grep = Grep::new(root.path()).await.unwrap();
    // Help and version are intentionally outside this adapter's contract.
    // Unknown options and a missing pattern are usage errors on stderr.
    for (args, status, stdout_start) in [
        (vec!["--help".to_string()], 2, &b""[..]),
        (vec!["--version".to_string()], 2, &b""[..]),
        (vec!["--color=banana".to_string()], 0, &b"Usage: grep"[..]),
        (vec!["--bogus-flag".to_string()], 2, &b""[..]),
        (vec![], 2, &b""[..]),
    ] {
        let out: Output = grep
            .search(&args)
            .await
            .expect("argument processing must be reported as Output");
        assert_eq!(out.status, status, "args {args:?} status");
        assert!(out.stdout.starts_with(stdout_start), "args {args:?} stdout");
        if status == 2 {
            assert!(!out.stderr.is_empty(), "args {args:?} stderr");
        } else {
            assert!(
                out.stderr.is_empty(),
                "args {args:?} must not err on stdout paths"
            );
        }
    }
}

#[tokio::test]
async fn search_helpers_are_equivalent() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("f"), "foo\n").unwrap();
    let grep = Grep::new(root.path()).await.unwrap();

    let plain = grep.search(["foo", "f"]).await.unwrap();
    let with_input = grep
        .search_with_input(["foo", "f"], Vec::new())
        .await
        .unwrap();
    let with_env = grep
        .search_with_environment(["foo", "f"], Vec::new(), Environment::default())
        .await
        .unwrap();
    assert_eq!(
        plain, with_input,
        "search must equal search_with_input(empty stdin)"
    );
    assert_eq!(
        plain, with_env,
        "search must equal search_with_environment with the process environment"
    );
    assert_eq!(plain.stdout, b"foo\n");
    assert_eq!(plain.status, 0);
    assert_eq!(plain.stdin_consumed, 0);
}

#[tokio::test]
async fn stdin_consumed_accounting() {
    let root = tempfile::tempdir().unwrap();
    let grep = Grep::new(root.path()).await.unwrap();

    // -m1: GNU stops after the first matching record; bytes through its end
    // are the reported consumption.
    let out = grep
        .search_with_input(["-m1", "foo"], b"bar\nfoo\nfoo\n".to_vec())
        .await
        .unwrap();
    assert_eq!(out.stdout, b"foo\n");
    assert_eq!(out.status, 0);
    assert_eq!(out.stdin_consumed, 8);

    // -q exits at the first match, same consumed prefix.
    let out = grep
        .search_with_input(["-q", "foo"], b"bar\nfoo\nfoo\n".to_vec())
        .await
        .unwrap();
    assert!(out.stdout.is_empty());
    assert_eq!(out.status, 0);
    assert_eq!(out.stdin_consumed, 8);

    // No match: the whole input is consumed.
    let out = grep
        .search_with_input(["zzz"], b"bar\nfoo\nfoo\n".to_vec())
        .await
        .unwrap();
    assert_eq!(out.status, 1);
    assert_eq!(out.stdin_consumed, 12);

    // -m0 short-circuits before reading anything.
    let out = grep
        .search_with_input(["-m0", "foo"], b"foo\n".to_vec())
        .await
        .unwrap();
    assert_eq!(out.status, 1);
    assert_eq!(out.stdin_consumed, 0);

    // -z: records are NUL-terminated; -m1 consumes one record.
    let out = grep
        .search_with_input(["-z", "-m1", "foo"], b"foo\0bar\0bar\0".to_vec())
        .await
        .unwrap();
    assert_eq!(out.stdout, b"foo\0");
    assert_eq!(out.stdin_consumed, 4);

    // -c reads everything.
    let out = grep
        .search_with_input(["-c", "foo"], b"bar\nfoo\nfoo\n".to_vec())
        .await
        .unwrap();
    assert_eq!(out.stdout, b"2\n");
    assert_eq!(out.stdin_consumed, 12);
}

#[tokio::test]
async fn new_rejects_invalid_roots() {
    assert!(Grep::new("/nonexistent-ffff-root-xyz").await.is_err());

    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("plain-file");
    std::fs::write(&file, "x").unwrap();
    assert!(Grep::new(&file).await.is_err());
}

#[tokio::test]
async fn devices_skip_does_not_open_a_fifo() {
    use std::os::unix::ffi::OsStrExt;

    let root = tempfile::tempdir().unwrap();
    let pipe = root.path().join("pipe");
    let c_pipe = std::ffi::CString::new(pipe.as_os_str().as_bytes()).unwrap();
    // SAFETY: c_pipe is NUL-terminated, points to writable parent storage,
    // and remains alive for the duration of this call.
    assert_eq!(unsafe { libc::mkfifo(c_pipe.as_ptr(), 0o600) }, 0);
    let grep = Grep::new(root.path()).await.unwrap();

    let out = tokio::time::timeout(
        std::time::Duration::from_secs(2),
        grep.search(["-D", "skip", "foo", "pipe"]),
    )
    .await
    .expect("-D skip tried to open the FIFO")
    .unwrap();
    assert_eq!(
        out,
        Output {
            status: 1,
            ..Output::default()
        }
    );
}

#[tokio::test]
async fn session_reflects_fresh_filesystem_state() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("f1"), "alpha\n").unwrap();
    let grep = Grep::new(root.path()).await.unwrap();

    let hit = grep.search(["-F", "alpha", "f1"]).await.unwrap();
    assert_eq!(hit.status, 0);
    assert_eq!(hit.stdout, b"alpha\n");

    // Modify: the next search sees the new content without any watcher wait.
    std::fs::write(root.path().join("f1"), "beta\n").unwrap();
    let miss = grep.search(["-F", "alpha", "f1"]).await.unwrap();
    assert_eq!(miss.status, 1);
    assert!(miss.stdout.is_empty());
    assert_eq!(
        grep.search(["-F", "beta", "f1"]).await.unwrap().stdout,
        b"beta\n"
    );

    // Truncate.
    std::fs::write(root.path().join("f1"), "").unwrap();
    assert_eq!(grep.search(["-F", "beta", "f1"]).await.unwrap().status, 1);

    // Delete: GNU-compatible diagnostic and status.
    std::fs::remove_file(root.path().join("f1")).unwrap();
    let gone = grep.search(["-F", "beta", "f1"]).await.unwrap();
    assert_eq!(gone.status, 2);
    assert_eq!(gone.stderr, b"grep: f1: No such file or directory\n");

    // Recreate.
    std::fs::write(root.path().join("f1"), "gamma\n").unwrap();
    assert_eq!(grep.search(["-F", "gamma", "f1"]).await.unwrap().status, 0);

    // A file created after indexing must be found by traversal immediately;
    // the persistent index may not gate visibility behind watcher events.
    std::fs::write(root.path().join("new2.txt"), "needle\n").unwrap();
    let rec = grep.search(["-r", "-F", "needle", "."]).await.unwrap();
    assert_eq!(rec.status, 0);
    assert_eq!(rec.stdout, b"./new2.txt:needle\n");
}

#[tokio::test]
async fn cached_binary_detection_preserves_gnu_read_boundaries() {
    const CHUNK_BYTES: usize = 96 * 1024;
    let root = tempfile::tempdir().unwrap();
    let mut bytes = b"foo\n".to_vec();
    bytes.resize(CHUNK_BYTES + 16, b'x');
    bytes.extend_from_slice(b"\0tail\n");
    std::fs::write(root.path().join("f"), bytes).unwrap();
    let grep = Grep::new(root.path()).await.unwrap();

    for _ in 0..2 {
        let out = grep.search(["foo", "f"]).await.unwrap();
        assert_eq!(out.stdout, b"foo\n");
        assert!(out.stderr.is_empty());
        assert_eq!(out.status, 0);
    }
}

#[tokio::test]
async fn concurrent_searches_on_one_clone() {
    let root = tempfile::tempdir().unwrap();
    for i in 0..8 {
        std::fs::write(root.path().join(format!("f{i}.txt")), format!("item{i}\n")).unwrap();
    }
    let grep = Grep::new(root.path()).await.unwrap();

    let handles: Vec<_> = (0..8)
        .map(|i| {
            let grep = grep.clone();
            tokio::spawn(async move {
                let args = ["-F".to_string(), format!("item{i}"), format!("f{i}.txt")];
                grep.search(args).await.unwrap()
            })
        })
        .collect();
    for (i, handle) in handles.into_iter().enumerate() {
        let out = handle.await.unwrap();
        assert_eq!(out.status, 0);
        assert_eq!(out.stdout, format!("item{i}\n").into_bytes());
    }
}

#[tokio::test]
async fn color_auto_follows_terminal_and_term() {
    let root = tempfile::tempdir().unwrap();
    std::fs::write(root.path().join("f"), "foo\n").unwrap();
    let grep = Grep::new(root.path()).await.unwrap();
    let env = |tty: bool, term: Option<&str>| Environment {
        locale: "C".into(),
        grep_colors: None,
        posixly_correct: false,
        stdout_is_terminal: tty,
        term: term.map(str::to_string),
    };

    // Auto on a color-capable terminal colorizes the match.
    let out = grep
        .search_with_environment(["-Hn", "foo", "f"], Vec::new(), env(true, Some("xterm")))
        .await
        .unwrap();
    assert_eq!(out.status, 0);
    assert!(
        out.stdout.windows(7).any(|w| w == b"\x1b[01;31"),
        "auto+tty+xterm must colorize matches"
    );

    // Auto over a pipe stays plain.
    let out = grep
        .search_with_environment(["-Hn", "foo", "f"], Vec::new(), env(false, Some("xterm")))
        .await
        .unwrap();
    assert!(!out.stdout.contains(&0x1b), "auto+pipe must stay plain");

    // GNU refuses color when TERM is "dumb" even on a terminal.
    let out = grep
        .search_with_environment(["-Hn", "foo", "f"], Vec::new(), env(true, Some("dumb")))
        .await
        .unwrap();
    assert!(!out.stdout.contains(&0x1b), "dumb TERM must suppress color");

    // ... and when TERM is unset.
    let out = grep
        .search_with_environment(["-Hn", "foo", "f"], Vec::new(), env(true, None))
        .await
        .unwrap();
    assert!(
        !out.stdout.contains(&0x1b),
        "unset TERM must suppress color"
    );

    // Sanity: explicit C locale environment still works end to end.
    let out = grep
        .search_with_environment(["-n", "foo", "f"], Vec::new(), c_env())
        .await
        .unwrap();
    assert_eq!(out.stdout, b"1:foo\n");
}
