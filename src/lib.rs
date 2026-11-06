//! Persistent, in-process GNU grep-style queries for an async server.
//!
//! `ffff` parses argv; the vendored FFF engine owns native BRE/ERE/PCRE
//! matching, byte-oriented input/output, traversal and persistent indexing.
//! Production queries never spawn grep or another process.
//!
//! Create one [`Grep`] per working directory and clone it for concurrent
//! requests. The index builds in the background; searches are usable immediately.
//! Files absent from the index are searched normally. Byte snapshots are checked
//! against inode/size/nanosecond mtime/ctime on each access, rather than waiting
//! for the watcher before observing a changed file.
//!
//! # Interface
//! Arguments are argv entries **after** `grep`, including patterns and file
//! operands. [`Grep::search_options`] parses shell quoting, not expansions,
//! redirects, substitutions or pipelines. Prefer argv for untrusted input.
//! Paths are relative to the instance's root, which is a working directory,
//! **not** a sandbox. Absolute paths and `..` have normal grep semantics.
//!
//! Output is raw bytes with grep's 0/1/2 status. Parse and search failures are
//! returned as status 2 with diagnostics; [`Error`] is reserved for session or
//! Tokio worker failures. Help and version are intentionally excluded.
//!
//! Like `Command::output`, this API buffers output. `--line-buffered` does not
//! expose intermediate records through a completed-buffer interface. Color
//! `auto` treats output as redirected unless an explicit [`Environment`] says
//! otherwise. Standard input is request-local; [`Grep::search`] supplies EOF.
//! Dropping a search future does not stop an already-running blocking worker.
//! Device/FIFO reads requested by the caller can block just as they do in grep.
//!
//! # Native prerequisites
//! Linux with glibc, a C compiler at build time, and PCRE2 (the `pcre2-sys`
//! dependency can build its bundled copy). Native matcher state and locale are
//! isolated to each blocking worker; no process-global cwd or descriptors change.
//!
//! ```no_run
//! # async fn example() -> Result<(), ffff::Error> {
//! let grep = ffff::Grep::new("/srv/project").await?; // Once at startup.
//! let result = grep.search(["-Pin", "(?<=prefix)word", "src/lib.rs"]).await?;
//! // Send result.stdout, result.stderr, result.status to your client.
//! let result = grep.search_options("-Fn -C2 'some text' src/lib.rs").await?;
//! let result = grep.search_with_input(["-zF", "needle"], b"needle\0other\0".to_vec()).await?;
//! # Ok(())
//! # }
//! ```

#[cfg(not(all(target_os = "linux", target_env = "gnu")))]
compile_error!("ffff's native GNU regex backend requires Linux with glibc");

mod args;

use fff_search::grep_compat::Session;
pub use fff_search::grep_compat::{Environment, Output};
use std::ffi::OsString;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

#[derive(Debug)]
pub struct Error(String);
impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Error {}

/// Cloneable handle to one persistent FFF session.
#[derive(Clone)]
pub struct Grep {
    session: Arc<Session>,
}

impl Grep {
    /// Starts FFF indexing in the background; queries need not wait for it.
    pub async fn new(root: impl AsRef<Path>) -> Result<Self, Error> {
        let root = root.as_ref().to_owned();
        tokio::task::spawn_blocking(move || {
            Session::new(root)
                .map(|session| Self {
                    session: Arc::new(session),
                })
                .map_err(|e| Error(e.to_string()))
        })
        .await
        .map_err(|e| Error(e.to_string()))?
    }

    /// Optional index warm-up barrier. False means it timed out or FFF cannot
    /// index the root's encoding; searches remain complete in either case.
    pub async fn wait_for_index(&self, timeout: Duration) -> Result<bool, Error> {
        let session = self.session.clone();
        tokio::task::spawn_blocking(move || session.wait_for_index(timeout))
            .await
            .map_err(|e| Error(e.to_string()))
    }

    pub async fn search<I, S>(&self, args: I) -> Result<Output, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.search_with_input(args, Vec::new()).await
    }

    pub async fn search_with_input<I, S>(&self, args: I, stdin: Vec<u8>) -> Result<Output, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        self.search_with_environment(args, stdin, Environment::default())
            .await
    }

    /// Explicit request-local environment, useful for deterministic locale and
    /// color behavior. Never calls setlocale/setenv or redirects server stdio.
    pub async fn search_with_environment<I, S>(
        &self,
        args: I,
        stdin: Vec<u8>,
        environment: Environment,
    ) -> Result<Output, Error>
    where
        I: IntoIterator<Item = S>,
        S: Into<OsString>,
    {
        let args = args.into_iter().map(Into::into).collect::<Vec<_>>();
        let session = self.session.clone();
        tokio::task::spawn_blocking(move || {
            match args::parse(&args, environment.posixly_correct) {
                Ok(options) => session.search(options, &stdin, &environment),
                // GNU emits bare usage errors (missing pattern, bare `--`,
                // unknown option after no-args) without a "grep: " prefix;
                // everything else is a "grep: "-prefixed diagnostic.
                Err(text) if text == args::parser::HELP_TEXT => Output {
                    stdout: text.into_bytes(),
                    stderr: Vec::new(),
                    status: 0,
                    stdin_consumed: 0,
                },
                Err(usage) if usage.starts_with("Usage:") => {
                    let mut stderr = usage.into_bytes();
                    stderr.push(b'\n');
                    Output {
                        stdout: Vec::new(),
                        stderr,
                        status: 2,
                        stdin_consumed: 0,
                    }
                }
                Err(error) => Output::error(error),
            }
        })
        .await
        .map_err(|e| Error(e.to_string()))
    }

    pub async fn search_options(&self, options: &str) -> Result<Output, Error> {
        match shell_words::split(options) {
            Ok(args) => self.search(args).await,
            Err(error) => Ok(Output::error(error.to_string())),
        }
    }
}
