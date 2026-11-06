//! GNU grep-compatible execution over the persistent FFF session.
//!
//! The native FFF index is a conservative accelerator. Record selection and
//! output are byte-oriented and do not use FFF's truncated display strings.

mod engine;
mod matcher;
mod session;
pub use session::Session;

use std::ffi::OsString;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Mode {
    #[default]
    Basic,
    Extended,
    Awk,
    GnuAwk,
    PosixAwk,
    Fixed,
    Perl,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Binary {
    #[default]
    Binary,
    Text,
    WithoutMatch,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Directories {
    #[default]
    Read,
    Skip,
    Recurse,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum DeviceMode {
    /// GNU's default: read command-line devices, skip recursively found ones.
    #[default]
    ReadCommandLine,
    Read,
    Skip,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum Color {
    #[default]
    Auto,
    Never,
    Always,
}
#[derive(Clone, Debug)]
pub enum PatternSource {
    Inline(Vec<u8>),
    File(PathBuf),
}
#[derive(Clone, Debug)]
pub enum FileFilter {
    Include(OsString),
    Exclude(OsString),
    ExcludeFrom(PathBuf),
}

#[derive(Clone, Debug)]
pub struct Options {
    pub mode: Mode,
    pub patterns: Vec<PatternSource>,
    pub files: Vec<PathBuf>,
    pub ignore_case: bool,
    pub invert: bool,
    pub word: bool,
    pub whole_line: bool,
    pub count: bool,
    pub list_files: Option<bool>,
    pub max_count: Option<u64>,
    pub only_matching: bool,
    pub quiet: bool,
    pub no_messages: bool,
    pub byte_offset: bool,
    pub filename: Option<bool>,
    pub label: OsString,
    pub line_number: bool,
    pub initial_tab: bool,
    pub null_filename: bool,
    /// Distinguishes explicit zero context (-A0) from no context request.
    pub context: bool,
    pub before: usize,
    pub after: usize,
    pub group_separator: Option<Vec<u8>>,
    pub binary: Binary,
    pub directories: Directories,
    pub devices: DeviceMode,
    pub dereference: bool,
    pub filters: Vec<FileFilter>,
    pub exclude_dirs: Vec<OsString>,
    pub line_buffered: bool,
    pub null_data: bool,
    pub color: Color,
}
impl Default for Options {
    fn default() -> Self {
        Self {
            mode: Mode::Basic,
            patterns: Vec::new(),
            files: Vec::new(),
            ignore_case: false,
            invert: false,
            word: false,
            whole_line: false,
            count: false,
            list_files: None,
            max_count: None,
            only_matching: false,
            quiet: false,
            no_messages: false,
            byte_offset: false,
            filename: None,
            label: "(standard input)".into(),
            line_number: false,
            initial_tab: false,
            null_filename: false,
            context: false,
            before: 0,
            after: 0,
            group_separator: Some(b"--".to_vec()),
            binary: Binary::Binary,
            directories: Directories::Read,
            devices: DeviceMode::ReadCommandLine,
            dereference: false,
            filters: Vec::new(),
            exclude_dirs: Vec::new(),
            line_buffered: false,
            null_data: false,
            color: Color::Auto,
        }
    }
}

/// Request-local environment; no global cwd, locale, or descriptors are changed.
#[derive(Clone, Debug)]
pub struct Environment {
    /// Empty inherits per-category environment settings. A name such as "C"
    /// overrides all locale categories for this request only.
    pub locale: OsString,
    pub grep_colors: Option<String>,
    pub posixly_correct: bool,
    pub stdout_is_terminal: bool,
    pub term: Option<String>,
}
impl Default for Environment {
    fn default() -> Self {
        let locale = OsString::new();
        Self {
            locale,
            grep_colors: std::env::var("GREP_COLORS").ok(),
            posixly_correct: std::env::var_os("POSIXLY_CORRECT").is_some(),
            stdout_is_terminal: false,
            term: std::env::var("TERM").ok(),
        }
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Output {
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    pub status: i32,
    /// Offset after the last consumed stdin record; accounts for `-m` seeking.
    pub stdin_consumed: usize,
}
impl Output {
    pub fn error(message: impl AsRef<str>) -> Self {
        Self {
            stderr: format!("grep: {}\n", message.as_ref()).into_bytes(),
            status: 2,
            ..Self::default()
        }
    }
}

pub(crate) trait ContentSource {
    fn prepare(&mut self, patterns: &[Vec<u8>], options: &Options);
    fn open(&mut self, path: &Path) -> io::Result<Box<dyn BufRead + Send>>;
}
