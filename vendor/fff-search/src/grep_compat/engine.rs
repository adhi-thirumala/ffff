//! GNU grep-compatible synchronous execution: file traversal, record stream
//! processing, and byte-exact output over the native [`Matcher`] and the
//! session's [`ContentSource`].
//!
//! The reference behavior is GNU grep 3.12 (`/usr/bin/grep`).  Matching is
//! delegated entirely to [`Matcher`]; this module owns pattern loading,
//! operand/traversal semantics, binary detection, context groups, `-m`/`-q`
//! early termination, exit-status aggregation and all output formatting.

use std::collections::{HashSet, VecDeque};
use std::ffi::{CString, OsStr, OsString};
use std::fs;
use std::io::{self, BufRead};
use std::path::{Path, PathBuf};

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use super::matcher::Matcher;
use super::{
    Binary, Color, ContentSource, DeviceMode, Directories, Environment, FileFilter, Options,
    Output, PatternSource,
};

/// Separator between filename/line/byte prefix and record content.
const SEP_SELECTED: u8 = b':';
const SEP_REJECTED: u8 = b'-';

/// GNU reads input in ~96 KiB chunks; binary detection and the `-I` abort
/// are chunk-aligned, so mirror that chunk size.
pub(crate) const CHUNK_BYTES: usize = 96 * 1024;

/// `-T` padding width for non-regular inputs: digit count of INTMAX_MAX.
const WIDE_OFFSET_WIDTH: usize = 19;

const SGR_START: &[u8] = b"\x1b[";
const SGR_END: &[u8] = b"\x1b[m";
const SGR_EL: &[u8] = b"\x1b[K";

// ---------------------------------------------------------------------------
// GREP_COLORS
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
struct Colors {
    selected_match: Vec<u8>,
    context_match: Vec<u8>,
    filename: Vec<u8>,
    line_num: Vec<u8>,
    byte_num: Vec<u8>,
    sep: Vec<u8>,
    selected_line: Vec<u8>,
    context_line: Vec<u8>,
    /// `rv`: with `-v`, selected and context line colors swap.
    reverse: bool,
    /// `ne`: omit the erase-in-line (`ESC[K`) suffix on SGR sequences.
    no_el: bool,
}

impl Default for Colors {
    fn default() -> Self {
        Self {
            selected_match: b"01;31".to_vec(),
            context_match: b"01;31".to_vec(),
            filename: b"35".to_vec(),
            line_num: b"32".to_vec(),
            byte_num: b"32".to_vec(),
            sep: b"36".to_vec(),
            selected_line: Vec::new(),
            context_line: Vec::new(),
            reverse: false,
            no_el: false,
        }
    }
}

/// Port of GNU `parse_grep_colors`.  Malformed input stops parsing at the
/// offending point; unknown capability names are ignored.
fn parse_grep_colors(spec: &str) -> Colors {
    let mut c = Colors::default();
    let bytes = spec.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        let name_start = i;
        while i < bytes.len() && bytes[i] != b'=' && bytes[i] != b':' {
            i += 1;
        }
        let name = &bytes[name_start..i];
        let mut val: Option<&[u8]> = None;
        if i < bytes.len() && bytes[i] == b'=' {
            i += 1;
            let val_start = i;
            while i < bytes.len() && (bytes[i] == b';' || bytes[i].is_ascii_digit()) {
                i += 1;
            }
            if i < bytes.len() && bytes[i] != b':' {
                // Unacceptable character in a value: be well-formed or be gone.
                return c;
            }
            val = Some(&bytes[val_start..i]);
        }
        if !name.is_empty() {
            match name {
                b"mt" => {
                    if let Some(v) = val {
                        c.selected_match = v.to_vec();
                        c.context_match = v.to_vec();
                    }
                }
                b"ms" => {
                    if let Some(v) = val {
                        c.selected_match = v.to_vec();
                    }
                }
                b"mc" => {
                    if let Some(v) = val {
                        c.context_match = v.to_vec();
                    }
                }
                b"fn" => {
                    if let Some(v) = val {
                        c.filename = v.to_vec();
                    }
                }
                b"ln" => {
                    if let Some(v) = val {
                        c.line_num = v.to_vec();
                    }
                }
                b"bn" => {
                    if let Some(v) = val {
                        c.byte_num = v.to_vec();
                    }
                }
                b"se" => {
                    if let Some(v) = val {
                        c.sep = v.to_vec();
                    }
                }
                b"sl" => {
                    if let Some(v) = val {
                        c.selected_line = v.to_vec();
                    }
                }
                b"cx" => {
                    if let Some(v) = val {
                        c.context_line = v.to_vec();
                    }
                }
                b"rv" => c.reverse = true,
                b"ne" => c.no_el = true,
                _ => {}
            }
        }
        if i >= bytes.len() {
            break;
        }
        // Skip the ':' separator (or a malformed '=' position, per GNU).
        i += 1;
    }
    c
}

fn sgr_start(out: &mut Vec<u8>, c: &Colors, s: &[u8]) {
    if s.is_empty() {
        return;
    }
    out.extend_from_slice(SGR_START);
    out.extend_from_slice(s);
    out.extend_from_slice(b"m");
    if !c.no_el {
        out.extend_from_slice(SGR_EL);
    }
}

fn sgr_end(out: &mut Vec<u8>, c: &Colors, s: &[u8]) {
    if s.is_empty() {
        return;
    }
    out.extend_from_slice(SGR_END);
    if !c.no_el {
        out.extend_from_slice(SGR_EL);
    }
}

// ---------------------------------------------------------------------------
// Include/exclude rules (gnulib exclude.c semantics as used by grep)
// ---------------------------------------------------------------------------

struct Rule {
    glob: Vec<u8>,
    include: bool,
}

/// Last matching rule in command-line order wins; when nothing matches, the
/// default is the opposite of the FIRST rule's kind.  Returns true when the
/// file should be skipped.
fn file_is_skipped(rules: &[Rule], name: &[u8], anchored: bool) -> bool {
    if rules.is_empty() {
        return false;
    }
    for rule in rules.iter().rev() {
        if rule_matches(&rule.glob, name, anchored) {
            return !rule.include;
        }
    }
    rules[0].include
}

/// fnmatch with no FNM_ flags, plus slash-suffix probing when not anchored.
/// Must run under the request locale; callers route through `with_locale`.
fn rule_matches(glob: &[u8], name: &[u8], anchored: bool) -> bool {
    let pat = bytes_to_cstring(glob);
    if unsafe { libc::fnmatch(pat.as_ptr(), bytes_to_cstring(name).as_ptr(), 0) } == 0 {
        return true;
    }
    if !anchored {
        for (i, &c) in name.iter().enumerate() {
            if c == b'/' && name.get(i + 1) != Some(&b'/') {
                let suffix = bytes_to_cstring(&name[i + 1..]);
                if unsafe { libc::fnmatch(pat.as_ptr(), suffix.as_ptr(), 0) } == 0 {
                    return true;
                }
            }
        }
    }
    false
}

fn bytes_to_cstring(bytes: &[u8]) -> CString {
    match CString::new(bytes) {
        Ok(c) => c,
        // Interior NUL bytes truncate the string, as in C.
        Err(e) => CString::new(&bytes[..e.nul_position()]).expect("prefix is NUL-free"),
    }
}

#[cfg(unix)]
fn os_bytes(os: &OsStr) -> &[u8] {
    use std::os::unix::ffi::OsStrExt;
    os.as_bytes()
}

#[cfg(not(unix))]
fn os_bytes(os: &OsStr) -> &[u8] {
    os.to_string_lossy().as_bytes().as_ref()
}

fn path_bytes(path: &Path) -> &[u8] {
    os_bytes(path.as_os_str())
}

/// Byte-wise trailing-slash trim used by fts on operand display paths:
/// strips while the path is longer than one byte.
fn trim_trailing_slashes(path: &Path) -> PathBuf {
    use std::os::unix::ffi::OsStringExt;

    let bytes = path_bytes(path);
    let mut len = bytes.len();
    while len > 1 && bytes[len - 1] == b'/' {
        len -= 1;
    }
    if len == bytes.len() {
        path.to_path_buf()
    } else {
        PathBuf::from(OsString::from_vec(bytes[..len].to_vec()))
    }
}

// ---------------------------------------------------------------------------
// Pattern loading
// ---------------------------------------------------------------------------

type Provenance = Option<(PathBuf, u64)>;

struct LoadedPattern {
    bytes: Vec<u8>,
    origin: Provenance,
}

/// Read the bytes of a `-f` pattern file (or stdin for `-f -`), producing
/// `grep: ...` diagnostics on failure.  `-f -` consumes the whole stdin
/// cursor, like GNU.
fn read_pattern_bytes(
    path: &Path,
    root: &Path,
    stdin: &[u8],
    cursor: &mut usize,
    out: &mut Output,
) -> Option<Vec<u8>> {
    if path == Path::new("-") {
        let bytes = stdin[*cursor..].to_vec();
        *cursor = stdin.len();
        return Some(bytes);
    }
    match fs::read(root.join(path)) {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            out.stderr.extend_from_slice(b"grep: ");
            out.stderr.extend_from_slice(path_bytes(path));
            out.stderr.extend_from_slice(b": ");
            out.stderr.extend_from_slice(err_text(&e).as_bytes());
            out.stderr.push(b'\n');
            out.status = 2;
            None
        }
    }
}

/// Load patterns in command-line order.  Inline and `-f` pattern bytes alike
/// are split on `\n` (always, even with `-z`, matching GNU's
/// update_patterns), deduplicated preserving first occurrence and
/// provenance.  Returns false on a fatal error.
fn load_patterns(
    options: &Options,
    root: &Path,
    stdin: &[u8],
    cursor: &mut usize,
    out: &mut Output,
) -> Option<Vec<LoadedPattern>> {
    let mut seen: HashSet<Vec<u8>> = HashSet::new();
    let mut patterns: Vec<LoadedPattern> = Vec::new();
    for source in &options.patterns {
        let (bytes, origin_file) = match source {
            // GNU stores each -e pattern with an appended '\n' delimiter
            // before update_patterns splits, so a pattern ending in '\n'
            // yields a trailing empty pattern.
            PatternSource::Inline(bytes) => {
                let mut b = bytes.clone();
                b.push(b'\n');
                (b, None)
            }
            PatternSource::File(path) => {
                let bytes = read_pattern_bytes(path, root, stdin, cursor, out)?;
                (bytes, Some(path.clone()))
            }
        };
        let mut off = 0usize;
        let mut line = 1u64;
        while off < bytes.len() {
            let rest = &bytes[off..];
            match rest.iter().position(|&b| b == b'\n') {
                Some(pos) => {
                    push_pattern(
                        &mut patterns,
                        &mut seen,
                        rest[..pos].to_vec(),
                        origin_file.as_ref(),
                        line,
                    );
                    off += pos + 1;
                    line += 1;
                }
                None => {
                    push_pattern(
                        &mut patterns,
                        &mut seen,
                        rest.to_vec(),
                        origin_file.as_ref(),
                        line,
                    );
                    break;
                }
            }
        }
    }
    Some(patterns)
}

fn push_pattern(
    patterns: &mut Vec<LoadedPattern>,
    seen: &mut HashSet<Vec<u8>>,
    bytes: Vec<u8>,
    origin_file: Option<&PathBuf>,
    line: u64,
) {
    if !seen.insert(bytes.clone()) {
        return;
    }
    patterns.push(LoadedPattern {
        bytes,
        origin: origin_file.map(|f| (f.clone(), line)),
    });
}

/// Flatten `--include`/`--exclude`/`--exclude-from` into one ordered rule
/// list.  Returns false on a fatal `--exclude-from` read error.
fn load_file_rules(
    options: &Options,
    root: &Path,
    stdin: &[u8],
    cursor: &mut usize,
    out: &mut Output,
) -> Option<Vec<Rule>> {
    let mut rules = Vec::new();
    for filter in &options.filters {
        match filter {
            FileFilter::Include(glob) => rules.push(Rule {
                glob: os_bytes(glob).to_vec(),
                include: true,
            }),
            FileFilter::Exclude(glob) => rules.push(Rule {
                glob: os_bytes(glob).to_vec(),
                include: false,
            }),
            FileFilter::ExcludeFrom(path) => {
                let bytes = read_pattern_bytes(path, root, stdin, cursor, out)?;
                // One glob per line; whitespace-only lines are ignored and
                // trailing whitespace is stripped (gnulib add_exclude_file).
                for raw in bytes.split(|&b| b == b'\n') {
                    let line = strip_trailing_whitespace(raw);
                    if line.is_empty() {
                        continue;
                    }
                    rules.push(Rule {
                        glob: line.to_vec(),
                        include: false,
                    });
                }
            }
        }
    }
    Some(rules)
}

fn strip_trailing_whitespace(mut line: &[u8]) -> &[u8] {
    while let Some((&last, rest)) = line.split_last() {
        if is_c_space(last) {
            line = rest;
        } else {
            break;
        }
    }
    line
}

fn is_c_space(b: u8) -> bool {
    matches!(b, b' ' | b'\t' | b'\n' | b'\x0b' | b'\x0c' | b'\r')
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

/// English (C-locale) strerror text, deterministic regardless of the
/// process locale; Rust's io::Error messages match the C locale on Linux.
fn err_text(e: &io::Error) -> String {
    let mut text = e.to_string();
    if let Some(pos) = text.rfind(" (os error ") {
        if text.ends_with(')') {
            text.truncate(pos);
        }
    }
    text
}

/// A suppressible per-file diagnostic: `grep: NAME: message`.  `-s` silences
/// the message but never the exit status.
fn suppressible_error(
    out: &mut Output,
    errseen: &mut bool,
    no_messages: bool,
    name: &[u8],
    code: i32,
) {
    *errseen = true;
    if no_messages {
        return;
    }
    out.stderr.extend_from_slice(b"grep: ");
    out.stderr.extend_from_slice(name);
    out.stderr.extend_from_slice(b": ");
    out.stderr
        .extend_from_slice(err_text(&io::Error::from_raw_os_error(code)).as_bytes());
    out.stderr.push(b'\n');
}

/// Format the matcher's compile error with provenance: `grep: FILE:LINE: msg`
/// for `-f` patterns, `grep: msg` for command-line patterns.
fn matcher_error_output(patterns: &[LoadedPattern], err: &str) -> Output {
    let mut out = Output::default();
    out.status = 2;
    out.stderr.extend_from_slice(b"grep: ");
    if let Some(pos) = err.strip_prefix("pattern ")
        && let Some((idx, msg)) = pos.split_once(':')
        && let Ok(idx) = idx.trim().parse::<usize>()
    {
        let msg = msg.trim_start();
        if let Some(origin) = patterns.get(idx).and_then(|p| p.origin.as_ref()) {
            out.stderr.extend_from_slice(path_bytes(&origin.0));
            out.stderr
                .extend_from_slice(format!(":{}: ", origin.1).as_bytes());
        }
        out.stderr.extend_from_slice(msg.as_bytes());
        out.stderr.push(b'\n');
        return out;
    }
    out.stderr.extend_from_slice(err.as_bytes());
    out.stderr.push(b'\n');
    out
}

// ---------------------------------------------------------------------------
// File state
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq)]
enum FShow {
    Yes,
    No,
    /// Resolve per operand: show iff the operand is a directory (GNU's
    /// `out_file < 0` deferred resolution).
    ResolveDir,
}

enum BinState {
    Clean,
    Detected { nlines_at: u64 },
}

#[derive(Clone)]
struct ContextRecord {
    content: Vec<u8>,
    term: u8,
    start: u64,
    end: u64,
    line: u64,
}

struct FileState {
    name: Vec<u8>,
    show: FShow,
    offset_base: u64,
    offset_width: usize,
    /// Selected records counted so far.
    nlines: u64,
    /// Records still selectable (`-m`); `u64::MAX` without `-m`.
    outleft: u64,
    /// Trailing-context records owed.
    pending: usize,
    /// Byte position just past the last printed record (None until first
    /// print); drives group-separator adjacency.
    lastout: Option<u64>,
    /// Leading-context window.
    ring: VecDeque<ContextRecord>,
    /// Stream offset just past the last selected record (`-m` cursor).
    after_last_match: u64,
    /// True while inside a `-v` selected run.
    in_run: bool,
    binary: BinState,
    encoding_error: bool,
    /// Local `out_quiet`/`done_on_match` installed by binary detection.
    quiet_local: bool,
    done_local: bool,
    /// Stream stopped early (`-m`, `-l`, binary).
    stopped: bool,
    /// EOF (or I/O error) reached.
    eof: bool,
    /// Bytes read so far (stream-relative).
    consumed: u64,
}

impl FileState {
    fn new(
        name: Vec<u8>,
        show: FShow,
        offset_base: u64,
        offset_width: usize,
        max_count: Option<u64>,
    ) -> Self {
        Self {
            name,
            show,
            offset_base,
            offset_width,
            nlines: 0,
            outleft: max_count.unwrap_or(u64::MAX),
            pending: 0,
            lastout: None,
            ring: VecDeque::new(),
            after_last_match: 0,
            in_run: false,
            binary: BinState::Clean,
            encoding_error: false,
            quiet_local: false,
            done_local: false,
            stopped: false,
            eof: false,
            consumed: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Execution driver
// ---------------------------------------------------------------------------

struct Exec<'a> {
    matcher: &'a Matcher,
    options: &'a Options,
    colors: Colors,
    colorize: bool,
    /// Resolved modes after precedence: -q > -l/-L > -c.
    quiet: bool,
    list: Option<bool>,
    count: bool,
    /// `-c`, `-l`/`-L`, or `-q`: suppress all line output.
    out_quiet_mode: bool,
    /// GNU suppresses binary diagnostics for -q/-c and unlimited -l/-L,
    /// but finite -m combined with list mode leaves them enabled.
    binary_diagnostics: bool,
    file_rules: Vec<Rule>,
    dir_rules: Vec<Rule>,
    group_sep: Option<Vec<u8>>,
    delimiter: u8,
    status_all: bool,
    errseen: bool,
    /// True once any group output has occurred (GNU's static `used`).
    used: bool,
    /// `-q` found a match: success status overrides earlier errors.
    quiet_matched: bool,
    /// Stop everything (matcher error or -q exit).
    quit: bool,
    out: Output,
}

pub fn run(
    options: Options,
    root: &Path,
    stdin: &[u8],
    env: &Environment,
    source: &mut impl ContentSource,
) -> Output {
    // GNU argument-processing order: pattern files are read (and any `-f -`
    // consumes stdin) before any matching begins.
    let mut out = Output::default();
    let mut cursor = 0usize;

    let Some(patterns) = load_patterns(&options, root, stdin, &mut cursor, &mut out) else {
        return out;
    };
    let Some(file_rules) = load_file_rules(&options, root, stdin, &mut cursor, &mut out) else {
        return out;
    };

    // --exclude-dir forms its own ordered rule list (all excludes).
    let dir_rules: Vec<Rule> = options
        .exclude_dirs
        .iter()
        .map(|g| Rule {
            glob: os_bytes(g).to_vec(),
            include: false,
        })
        .collect();

    // Fast paths evaluated before pattern compilation, as in GNU main().
    let zero_patterns = patterns.is_empty();
    // Zero patterns: GNU flips -v and clears -w/-x so that nothing matches;
    // without -v this short-circuits to exit 1 without reading anything.
    let flipped_invert = if zero_patterns {
        !options.invert
    } else {
        options.invert
    };
    let key_bytes_empty = zero_patterns || (patterns.len() == 1 && patterns[0].bytes.is_empty());
    if (options.max_count == Some(0)
        || (key_bytes_empty && flipped_invert && !options.whole_line && !options.word))
        && options.list_files != Some(false)
    {
        out.status = 1;
        return out;
    }

    // Effective options after the zero-pattern flip.
    let mut effective = options.clone();
    if zero_patterns {
        effective.invert = flipped_invert;
        effective.word = false;
        effective.whole_line = false;
    }

    let pattern_bytes: Vec<Vec<u8>> = if zero_patterns {
        vec![Vec::new()]
    } else {
        patterns.iter().map(|p| p.bytes.clone()).collect()
    };

    let matcher = match Matcher::new(&pattern_bytes, &effective, env) {
        Ok(m) => m,
        Err(e) => return matcher_error_output(&patterns, &e),
    };

    source.prepare(&pattern_bytes, &options);

    // Mode precedence: -q > -l/-L > -c > normal (GNU main()).
    let quiet = effective.quiet;
    let list = if quiet { None } else { effective.list_files };
    let count = !quiet && list.is_none() && effective.count;
    let out_quiet_mode = quiet || list.is_some() || count;
    let max_is_unlimited = effective
        .max_count
        .is_none_or(|limit| limit == i64::MAX as u64);
    let binary_diagnostics = !quiet && !count && !(list.is_some() && max_is_unlimited);

    let colorize = match effective.color {
        Color::Always => true,
        Color::Never => false,
        Color::Auto => {
            env.stdout_is_terminal
                && env
                    .term
                    .as_deref()
                    .is_some_and(|t| !t.eq_ignore_ascii_case("dumb"))
        }
    };
    let colors = match effective.color {
        Color::Never => Colors::default(),
        _ => env
            .grep_colors
            .as_deref()
            .map(parse_grep_colors)
            .unwrap_or_default(),
    };

    let mut exec = Exec {
        matcher: &matcher,
        options: &effective,
        colors,
        colorize,
        quiet,
        list,
        count,
        out_quiet_mode,
        binary_diagnostics,
        file_rules,
        dir_rules,
        group_sep: effective.group_separator.clone(),
        delimiter: if effective.null_data { 0 } else { b'\n' },
        status_all: true,
        errseen: false,
        used: false,
        quiet_matched: false,
        quit: false,
        out,
    };

    // The request locale applies to libc fnmatch character classes in the
    // include/exclude machinery; the matcher owns the same thread-local
    // mechanism for native matching.
    matcher.with_locale(|| {
        exec.run_operands(root, stdin, &mut cursor, source);
    });

    let mut out = exec.out;
    if exec.quiet_matched {
        out.status = 0;
    } else if out.status == 0 {
        out.status = if exec.errseen {
            2
        } else if exec.status_all {
            1
        } else {
            0
        };
    }
    out.stdin_consumed = cursor;
    out
}

impl<'a> Exec<'a> {
    fn run_operands(
        &mut self,
        root: &Path,
        stdin: &[u8],
        cursor: &mut usize,
        source: &mut impl ContentSource,
    ) {
        // Default operand when none given: "." for -r/-R, else stdin.
        let explicit: Vec<PathBuf> = self.options.files.clone();
        let (operands, omit_dot_slash): (Vec<PathBuf>, bool) = if explicit.is_empty() {
            if self.options.directories == Directories::Recurse {
                (vec![PathBuf::from(".")], true)
            } else {
                (vec![PathBuf::from("-")], false)
            }
        } else {
            (explicit, false)
        };

        for operand in &operands {
            if self.quit {
                break;
            }
            if operand == Path::new("-") {
                self.search_stdin_operand(stdin, cursor);
            } else {
                self.process_operand(root, operand, omit_dot_slash, source);
            }
        }
    }

    // -- command-line operands -------------------------------------------------

    fn process_operand(
        &mut self,
        root: &Path,
        operand: &Path,
        omit_dot_slash: bool,
        source: &mut impl ContentSource,
    ) {
        let io_path = root.join(operand);
        let metadata = match fs::metadata(&io_path) {
            Ok(m) => m,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                suppressible_error(
                    &mut self.out,
                    &mut self.errseen,
                    self.options.no_messages,
                    path_bytes(operand),
                    code,
                );
                return;
            }
        };

        let name = path_bytes(operand);
        let is_dir = metadata.is_dir();
        let is_device = is_device_mode(&metadata);

        // Order per GNU grepdesc: device skip, then exclude rules.
        if is_device && self.skip_devices(true) {
            return;
        }
        let rules = if is_dir {
            &self.dir_rules
        } else {
            &self.file_rules
        };
        if file_is_skipped(rules, name, false) {
            return;
        }

        let show = match self.show_for(operand) {
            FShow::ResolveDir => {
                if is_dir {
                    FShow::Yes
                } else {
                    FShow::No
                }
            }
            other => other,
        };
        // Command-line operands keep their exact spelling (fts strips only
        // trailing slashes from display paths).
        let display = trim_trailing_slashes(operand);

        if is_dir {
            match self.options.directories {
                Directories::Recurse => {
                    // Cycle detection applies only on dereference paths:
                    // -R follows all symlinks; -r follows command-line
                    // symlink operands (FTS_COMFOLLOW) and their target is
                    // a dereference root too.
                    let mut stack: Vec<(u64, u64)> = Vec::new();
                    let deref_root = self.options.dereference
                        || fs::symlink_metadata(&io_path).is_ok_and(|m| m.file_type().is_symlink());
                    if deref_root {
                        stack.push((metadata.dev(), metadata.ino()));
                    }
                    self.walk(
                        root,
                        &io_path,
                        &display,
                        omit_dot_slash,
                        &mut stack,
                        source,
                        show,
                    );
                    return;
                }
                Directories::Skip => return,
                Directories::Read => {}
            }
        }
        let mut reader = match source.open(&io_path) {
            Ok(reader) => reader,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                suppressible_error(
                    &mut self.out,
                    &mut self.errseen,
                    self.options.no_messages,
                    path_bytes(operand),
                    code,
                );
                return;
            }
        };

        let width = self.width_for(&metadata);
        let mut fs = FileState::new(name.to_vec(), show, 0, width, self.options.max_count);
        self.search_stream(&mut *reader, &mut fs);
        self.finish_file(&mut fs);
    }

    fn show_for(&self, _operand: &Path) -> FShow {
        match self.options.filename {
            Some(true) => FShow::Yes,
            Some(false) => FShow::No,
            None => {
                let n = self.options.files.len();
                if n > 1 || self.options.directories == Directories::Recurse {
                    if n <= 1 {
                        FShow::ResolveDir
                    } else {
                        FShow::Yes
                    }
                } else {
                    FShow::No
                }
            }
        }
    }

    fn search_stdin_operand(&mut self, stdin: &[u8], cursor: &mut usize) {
        let base = *cursor;
        let remaining = &stdin[base..];
        let mut reader = SliceReader::new(remaining);
        let name: Vec<u8> = os_bytes(&self.options.label).to_vec();
        let show = match self.show_for(Path::new("-")) {
            FShow::ResolveDir => FShow::No,
            other => other,
        };
        let mut fs = FileState::new(
            name.clone(),
            show,
            base as u64,
            WIDE_OFFSET_WIDTH,
            self.options.max_count,
        );
        self.search_stream(&mut reader, &mut fs);
        // stdin cursor: GNU drains for -l/-L/-I, seeks back after -m, and
        // stops just past the triggering record for -q.
        let advance: u64 = if self.quit || fs.outleft == 0 {
            fs.after_last_match
        } else if fs.eof {
            remaining.len() as u64
        } else {
            remaining.len() as u64
        };
        *cursor = base + advance as usize;
        self.finish_file(&mut fs);
    }

    fn width_for(&self, metadata: &fs::Metadata) -> usize {
        // GNU pads line/byte numbers only under -T (offset_width stays 0
        // otherwise); non-regular inputs use the INTMAX_MAX width.
        if !self.options.initial_tab {
            return 0;
        }
        if metadata.is_file() {
            let mut num = metadata.len();
            if self.options.line_number && num < u64::MAX {
                num += 1;
            }
            digits(num)
        } else {
            WIDE_OFFSET_WIDTH
        }
    }

    // -- recursive traversal ---------------------------------------------------

    #[allow(clippy::too_many_arguments)]
    fn walk(
        &mut self,
        root: &Path,
        dir: &Path,
        display_dir: &Path,
        omit_dot_slash: bool,
        stack: &mut Vec<(u64, u64)>,
        source: &mut impl ContentSource,
        show: FShow,
    ) {
        if self.quit {
            return;
        }
        let entries = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                suppressible_error(
                    &mut self.out,
                    &mut self.errseen,
                    self.options.no_messages,
                    path_bytes(display_dir),
                    code,
                );
                return;
            }
        };
        for entry in entries {
            if self.quit {
                return;
            }
            let entry = match entry {
                Ok(e) => e,
                Err(e) => {
                    let code = e.raw_os_error().unwrap_or(0);
                    suppressible_error(
                        &mut self.out,
                        &mut self.errseen,
                        self.options.no_messages,
                        path_bytes(display_dir),
                        code,
                    );
                    continue;
                }
            };
            let name = entry.file_name();
            let child = dir.join(&name);
            let display_child = self.join_display(display_dir, &name, omit_dot_slash);
            let lt = match fs::symlink_metadata(&child) {
                Ok(m) => m,
                Err(e) => {
                    let code = e.raw_os_error().unwrap_or(0);
                    suppressible_error(
                        &mut self.out,
                        &mut self.errseen,
                        self.options.no_messages,
                        path_bytes(&display_child),
                        code,
                    );
                    continue;
                }
            };
            if lt.file_type().is_symlink() {
                if !self.options.dereference {
                    continue; // FTS_SL: silently skipped under -r
                }
                match fs::metadata(&child) {
                    Ok(m) => {
                        if m.is_dir() {
                            self.walk_dir_entry(
                                root,
                                &child,
                                &display_child,
                                &m,
                                stack,
                                source,
                                show,
                            );
                        } else {
                            self.search_entry(&child, &display_child, &m, source, show);
                        }
                    }
                    Err(_) => {
                        // FTS_SLNONE: dangling symlink, still subject to
                        // --exclude; otherwise an open error.
                        let base = display_child.file_name();
                        let base = base.map(os_bytes).unwrap_or(b"");
                        if file_is_skipped(&self.file_rules, base, true) {
                            continue;
                        }
                        match source.open(&child) {
                            Ok(_) => unreachable!("dangling symlink cannot open"),
                            Err(e) => {
                                let code = e.raw_os_error().unwrap_or(0);
                                suppressible_error(
                                    &mut self.out,
                                    &mut self.errseen,
                                    self.options.no_messages,
                                    path_bytes(&display_child),
                                    code,
                                );
                            }
                        }
                    }
                }
                continue;
            }
            if lt.is_dir() {
                self.walk_dir_entry(root, &child, &display_child, &lt, stack, source, show);
            } else {
                self.search_entry(&child, &display_child, &lt, source, show);
            }
        }
    }

    fn join_display(&self, display_dir: &Path, name: &OsStr, omit_dot_slash: bool) -> PathBuf {
        if omit_dot_slash {
            // Implied "." operand: GNU strips the "./" prefix.
            PathBuf::from(name)
        } else {
            display_dir.join(name)
        }
    }

    #[allow(clippy::too_many_arguments)]
    fn walk_dir_entry(
        &mut self,
        root: &Path,
        child: &Path,
        display_child: &Path,
        metadata: &fs::Metadata,
        stack: &mut Vec<(u64, u64)>,
        source: &mut impl ContentSource,
        show: FShow,
    ) {
        let base = display_child.file_name();
        let base = base.map(os_bytes).unwrap_or(b"");
        if file_is_skipped(&self.dir_rules, base, true) {
            return; // FTS_SKIP: prune the subtree
        }
        if self.options.dereference {
            let key = (metadata.dev(), metadata.ino());
            if stack.contains(&key) {
                // FTS_DC: recursive directory loop.
                if !self.options.no_messages {
                    self.out.stderr.extend_from_slice(b"grep: ");
                    self.out.stderr.extend_from_slice(path_bytes(display_child));
                    self.out
                        .stderr
                        .extend_from_slice(b": warning: recursive directory loop\n");
                }
                return;
            }
            stack.push(key);
            self.walk(root, child, display_child, false, stack, source, show);
            stack.pop();
        } else {
            self.walk(root, child, display_child, false, stack, source, show);
        }
    }

    fn search_entry(
        &mut self,
        child: &Path,
        display_child: &Path,
        metadata: &fs::Metadata,
        source: &mut impl ContentSource,
        show: FShow,
    ) {
        let base = display_child.file_name();
        let base = base.map(os_bytes).unwrap_or(b"");
        if file_is_skipped(&self.file_rules, base, true) {
            return;
        }
        if is_device_mode(metadata) && self.skip_devices(false) {
            return;
        }
        let mut reader = match source.open(child) {
            Ok(r) => r,
            Err(e) => {
                let code = e.raw_os_error().unwrap_or(0);
                suppressible_error(
                    &mut self.out,
                    &mut self.errseen,
                    self.options.no_messages,
                    path_bytes(display_child),
                    code,
                );
                return;
            }
        };
        let width = self.width_for(metadata);
        let name = path_bytes(display_child).to_vec();
        let mut fs = FileState::new(name, show, 0, width, self.options.max_count);
        self.search_stream(&mut *reader, &mut fs);
        self.finish_file(&mut fs);
    }

    // -- shared helpers --------------------------------------------------------

    fn skip_devices(&self, command_line: bool) -> bool {
        match self.options.devices {
            DeviceMode::ReadCommandLine => !command_line && !self.options.dereference,
            DeviceMode::Read => false,
            DeviceMode::Skip => true,
        }
    }

    // -- per-file completion ---------------------------------------------------

    fn finish_file(&mut self, fs: &mut FileState) {
        // Binary diagnostic: `grep: NAME: binary file matches`.
        let binary_message = matches!(self.options.binary, Binary::Binary)
            && self.binary_diagnostics
            && (fs.encoding_error
                || matches!(fs.binary, BinState::Detected { nlines_at } if fs.nlines > nlines_at));
        if binary_message {
            self.out.stderr.extend_from_slice(b"grep: ");
            self.out.stderr.extend_from_slice(&fs.name);
            self.out
                .stderr
                .extend_from_slice(b": binary file matches\n");
        }

        if self.count && !self.quit {
            if fs.show == FShow::Yes {
                self.print_filename(&fs.name);
                if self.options.null_filename {
                    self.out.stdout.push(0);
                } else {
                    self.print_sep(SEP_SELECTED);
                }
            }
            self.out
                .stdout
                .extend_from_slice(format!("{}\n", fs.nlines).as_bytes());
        }

        if let Some(list) = self.list {
            let wanted = if list { fs.nlines > 0 } else { fs.nlines == 0 };
            if wanted && !self.quit {
                self.print_filename(&fs.name);
                self.out
                    .stdout
                    .push(if self.options.null_filename { 0 } else { b'\n' });
            }
        }

        // GNU status aggregation: grepdesc returns true when the file had no
        // selected lines; main() ANDs across operands.
        self.status_all &= fs.nlines == 0;
    }

    // -- the record stream ------------------------------------------------------

    fn search_stream(&mut self, reader: &mut dyn BufRead, fs: &mut FileState) {
        let delim = self.delimiter;
        let mut partial: Vec<u8> = Vec::new();
        let mut partial_start: u64 = 0;
        let mut line_no: u64 = 1;
        let mut record_buf: Vec<u8> = Vec::new();

        loop {
            let chunk_len = match reader.fill_buf() {
                Ok(c) => c.len(),
                Err(e) => {
                    let code = e.raw_os_error().unwrap_or(0);
                    suppressible_error(
                        &mut self.out,
                        &mut self.errseen,
                        self.options.no_messages,
                        &fs.name,
                        code,
                    );
                    break;
                }
            };
            if chunk_len == 0 {
                break;
            }
            let chunk_start = fs.consumed;

            // Binary detection is chunk-aligned: GNU scans each buffer once,
            // before matching any of its records.
            if self.options.binary != Binary::Text && !self.options.null_data {
                let chunk = reader.fill_buf().expect("refilled");
                if chunk.contains(&0) {
                    match self.options.binary {
                        Binary::WithoutMatch => {
                            // -I: the file is treated as unmatched, even for
                            // records matched in earlier chunks.
                            fs.nlines = 0;
                            fs.stopped = true;
                            fs.consumed += chunk_len as u64;
                            reader.consume(chunk_len);
                            fs.eof = false;
                            return;
                        }
                        _ => {
                            if let BinState::Clean = fs.binary {
                                fs.binary = BinState::Detected {
                                    nlines_at: fs.nlines,
                                };
                                if !self.options.count {
                                    fs.quiet_local = true;
                                    if self.options.max_count.is_none() {
                                        fs.done_local = true;
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // GNU replaces NUL bytes with the record delimiter after
            // detecting binary input. This bounds binary "lines" and keeps a
            // literal NUL pattern from matching in default binary mode.
            let zap_nuls = matches!(fs.binary, BinState::Detected { .. });
            // Walk records within the chunk.
            let chunk = reader.fill_buf().expect("refilled");
            let mut off = 0usize;
            while off < chunk.len() {
                let pos = chunk[off..]
                    .iter()
                    .position(|&b| b == delim || (zap_nuls && b == 0));
                match pos {
                    Some(p) => {
                        let record_start = if partial.is_empty() {
                            chunk_start + off as u64
                        } else {
                            partial_start
                        };
                        let record_end = chunk_start + (off + p + 1) as u64;
                        record_buf.clear();
                        if !partial.is_empty() {
                            record_buf.extend_from_slice(&partial);
                        }
                        record_buf.extend_from_slice(&chunk[off..off + p]);
                        record_buf.push(delim);

                        self.process_record(&record_buf, record_start, record_end, line_no, fs);
                        partial.clear();
                        off += p + 1;
                        line_no += 1;
                        if self.quit || fs.stopped {
                            fs.consumed = record_end;
                            return;
                        }
                    }
                    None => {
                        if partial.is_empty() {
                            partial_start = chunk_start + off as u64;
                        }
                        partial.extend_from_slice(&chunk[off..]);
                        off = chunk.len();
                    }
                }
            }
            fs.consumed += chunk_len as u64;
            reader.consume(chunk_len);
        }

        // Final unterminated record (GNU residue): processed with a virtual
        // terminator, which is also printed.
        if !partial.is_empty() {
            record_buf.clear();
            record_buf.extend_from_slice(&partial);
            record_buf.push(delim);
            self.process_record(&record_buf, partial_start, fs.consumed, line_no, fs);
        }
        fs.eof = true;
    }

    fn process_record(
        &mut self,
        record: &[u8],
        start: u64,
        end: u64,
        line: u64,
        fs: &mut FileState,
    ) {
        let content = &record[..record.len() - 1];
        let term = record[record.len() - 1];

        // Selection is gated on outleft: GNU skips matching entirely once
        // -m is exhausted (trailing context printing continues).
        let mut spans: Vec<(usize, usize)> = Vec::new();
        let selected = if fs.outleft == 0 {
            false
        } else {
            let need_spans = !self.out_quiet_mode
                && !fs.quiet_local
                && (self.options.only_matching || self.colorize)
                && (!self.options.invert || self.options.only_matching);
            let matched = if need_spans {
                match self.matcher.find_all(record) {
                    Ok(s) => {
                        spans = s;
                        !spans.is_empty()
                    }
                    Err(e) => {
                        self.out = matcher_error_output(&[], &e);
                        self.quit = true;
                        return;
                    }
                }
            } else {
                match self.matcher.is_match(record) {
                    Ok(m) => m,
                    Err(e) => {
                        self.out = matcher_error_output(&[], &e);
                        self.quit = true;
                        return;
                    }
                }
            };
            matched ^ self.options.invert
        };

        if selected {
            fs.nlines += 1;
            fs.after_last_match = end;
            if self.list.is_some() {
                // GNU stops -l/-L at the first selected record.
                fs.stopped = true;
                return;
            }
            if self.quiet {
                self.quiet_matched = true;
                self.quit = true;
                return;
            }
            if self.out_quiet_mode {
                // Count mode (list/quiet returned above): only -m can stop.
                if fs.outleft != u64::MAX {
                    fs.outleft -= 1;
                    if fs.outleft == 0 {
                        fs.stopped = true;
                    }
                }
                return;
            }
            // Normal line-output mode.
            if self.options.invert {
                if !fs.in_run {
                    self.emit_group_header(fs, start);
                    fs.in_run = true;
                }
                if !fs.quiet_local {
                    self.print_line(fs, content, term, start, end, line, SEP_SELECTED, None);
                }
            } else {
                self.emit_group_header(fs, start);
                if !fs.quiet_local {
                    self.print_line(
                        fs,
                        content,
                        term,
                        start,
                        end,
                        line,
                        SEP_SELECTED,
                        Some(&spans),
                    );
                }
            }
            if fs.outleft != u64::MAX {
                fs.outleft -= 1;
            }
            fs.pending = if self.out_quiet_mode || fs.quiet_local {
                0
            } else {
                self.options.after
            };
            if (fs.outleft == 0 && fs.pending == 0) || fs.done_local {
                fs.stopped = true;
            }
            return;
        }

        // Not selected.
        fs.in_run = false;
        if !self.out_quiet_mode && fs.pending > 0 {
            self.print_context_record(fs, content, term, start, end, line);
            fs.pending -= 1;
        }
        if self.options.before > 0 {
            fs.ring.push_back(ContextRecord {
                content: content.to_vec(),
                term,
                start,
                end,
                line,
            });
            if fs.ring.len() > self.options.before {
                fs.ring.pop_front();
            }
        }
        if fs.outleft == 0 && fs.pending == 0 {
            fs.stopped = true;
        }
    }

    fn quiet_effective(&self, fs: &FileState) -> bool {
        self.out_quiet_mode || fs.quiet_local
    }

    /// Group prologue: group separator and leading context.  Sets `used`
    /// like GNU's prtext, even when output is suppressed.
    fn emit_group_header(&mut self, fs: &mut FileState, group_first: u64) {
        if self.quiet_effective(fs) {
            self.used = true;
            return;
        }
        let was_used = self.used;
        let mut ctx: Vec<ContextRecord> = fs
            .ring
            .iter()
            .rev()
            .filter(|r| fs.lastout.is_none_or(|lo| r.start >= lo))
            .take(self.options.before)
            .cloned()
            .collect();
        ctx.reverse();
        let first = ctx.first().map(|r| r.start).unwrap_or(group_first);
        if self.options.context
            && was_used
            && self.group_sep.is_some()
            && fs.lastout.is_none_or(|lo| first != lo)
        {
            if let Some(sep) = self.group_sep.clone() {
                self.print_group_separator(&sep);
            }
        }
        for r in ctx {
            self.print_context_record(fs, &r.content, r.term, r.start, r.end, r.line);
        }
        self.used = true;
    }

    fn print_group_separator(&mut self, sep: &[u8]) {
        if self.colorize {
            sgr_start(&mut self.out.stdout, &self.colors, &self.colors.sep);
            self.out.stdout.extend_from_slice(sep);
            sgr_end(&mut self.out.stdout, &self.colors, &self.colors.sep);
        } else {
            self.out.stdout.extend_from_slice(sep);
        }
        self.out.stdout.push(b'\n');
    }

    #[allow(clippy::too_many_arguments)]
    fn print_context_record(
        &mut self,
        fs: &mut FileState,
        content: &[u8],
        term: u8,
        start: u64,
        end: u64,
        line: u64,
    ) {
        let want_spans = self.options.invert
            && (self.options.only_matching || self.colorize)
            && !self.quiet_effective(fs);
        let spans: Option<Vec<(usize, usize)>> = if want_spans {
            let mut record = Vec::with_capacity(content.len() + 1);
            record.extend_from_slice(content);
            record.push(term);
            match self.matcher.find_all(&record) {
                Ok(s) => Some(s),
                Err(_) => None,
            }
        } else {
            None
        };
        self.print_line(
            fs,
            content,
            term,
            start,
            end,
            line,
            SEP_REJECTED,
            spans.as_deref(),
        );
    }

    /// Print one record (or its matches under -o).  `spans` is the record's
    /// match list when computed, or None.
    #[allow(clippy::too_many_arguments)]
    fn print_line(
        &mut self,
        fs: &mut FileState,
        content: &[u8],
        term: u8,
        start: u64,
        end: u64,
        line: u64,
        sep: u8,
        spans: Option<&[(usize, usize)]>,
    ) {
        let matching = (sep == SEP_SELECTED) ^ self.options.invert;

        if self.options.only_matching {
            if !matching {
                // GNU prline still advances lastout when -o prints nothing.
                fs.lastout = Some(end);
                return;
            }
            let Some(spans) = spans else {
                fs.lastout = Some(end);
                return;
            };
            for &(s, e) in spans {
                if s == e || e > content.len() {
                    continue; // zero-length matches are never printed by -o
                }
                let head_ok = self.print_line_head(fs, &content[s..e], line, start + s as u64, sep);
                if !head_ok {
                    return; // encoding error suppresses the rest of the line
                }
                let match_color = if sep == SEP_SELECTED {
                    self.colors.selected_match.clone()
                } else {
                    self.colors.context_match.clone()
                };
                if self.colorize {
                    sgr_start(&mut self.out.stdout, &self.colors, &match_color);
                }
                self.out.stdout.extend_from_slice(&content[s..e]);
                if self.colorize {
                    sgr_end(&mut self.out.stdout, &self.colors, &match_color);
                }
                self.out.stdout.push(term);
            }
            fs.lastout = Some(end);
            return;
        }

        // Whole-record printing.
        if !self.print_line_head(fs, content, line, start, sep) {
            return; // encoding error suppresses the record; lastout untouched
        }

        let line_color = if (sep == SEP_SELECTED) ^ (self.options.invert && self.colors.reverse) {
            self.colors.selected_line.clone()
        } else {
            self.colors.context_line.clone()
        };
        let match_color = if sep == SEP_SELECTED {
            self.colors.selected_match.clone()
        } else {
            self.colors.context_match.clone()
        };

        if self.colorize && matching && !match_color.is_empty() {
            // Colorize match spans and the segments between them (GNU
            // print_line_middle); the line color stays open across matches.
            let mut pos = 0usize;
            for &(s, e) in spans.unwrap_or(&[]) {
                if s == e || e > content.len() {
                    continue;
                }
                sgr_start(&mut self.out.stdout, &self.colors, &line_color);
                if s > pos {
                    self.out.stdout.extend_from_slice(&content[pos..s]);
                }
                sgr_start(&mut self.out.stdout, &self.colors, &match_color);
                self.out.stdout.extend_from_slice(&content[s..e]);
                sgr_end(&mut self.out.stdout, &self.colors, &match_color);
                pos = e;
            }
            // Tail after the last match, excluding the terminator and a
            // preceding CR, is colored with the line color (GNU
            // print_line_tail); the CR and terminator are written raw.
            let mut tail_end = content.len();
            if content.last() == Some(&b'\r') {
                tail_end -= 1;
            }
            if tail_end > pos {
                sgr_start(&mut self.out.stdout, &self.colors, &line_color);
                self.out.stdout.extend_from_slice(&content[pos..tail_end]);
                sgr_end(&mut self.out.stdout, &self.colors, &line_color);
                pos = tail_end;
            }
            self.out.stdout.extend_from_slice(&content[pos..]);
        } else if self.colorize && !line_color.is_empty() {
            // Match color disabled: the whole line body gets the line color.
            let mut tail_end = content.len();
            if content.last() == Some(&b'\r') {
                tail_end -= 1;
            }
            if tail_end > 0 {
                sgr_start(&mut self.out.stdout, &self.colors, &line_color);
                self.out.stdout.extend_from_slice(&content[..tail_end]);
                sgr_end(&mut self.out.stdout, &self.colors, &line_color);
                self.out.stdout.extend_from_slice(&content[tail_end..]);
            } else {
                self.out.stdout.extend_from_slice(content);
            }
        } else {
            self.out.stdout.extend_from_slice(content);
        }
        self.out.stdout.push(term);
        fs.lastout = Some(end);
    }

    /// Print the filename/line/byte prefix.  Returns false when the checked
    /// bytes are invalid in the request locale while binary mode is active,
    /// in which case nothing is printed.
    fn print_line_head(
        &mut self,
        fs: &mut FileState,
        checked: &[u8],
        line: u64,
        byte_off: u64,
        sep: u8,
    ) -> bool {
        if self.options.binary != Binary::Text && !self.matcher.valid_text(checked) {
            fs.encoding_error = true;
            return false;
        }
        if fs.show == FShow::Yes {
            if self.colorize {
                sgr_start(&mut self.out.stdout, &self.colors, &self.colors.filename);
            }
            self.out.stdout.extend_from_slice(&fs.name);
            if self.colorize {
                sgr_end(&mut self.out.stdout, &self.colors, &self.colors.filename);
            }
            if self.options.null_filename {
                self.out.stdout.push(0);
            } else {
                self.print_sep(sep);
            }
        }
        if self.options.line_number {
            if self.colorize {
                sgr_start(&mut self.out.stdout, &self.colors, &self.colors.line_num);
            }
            self.out
                .stdout
                .extend_from_slice(format!("{:>width$}", line, width = fs.offset_width).as_bytes());
            if self.colorize {
                sgr_end(&mut self.out.stdout, &self.colors, &self.colors.line_num);
            }
            self.print_sep(sep);
        }
        if self.options.byte_offset {
            if self.colorize {
                sgr_start(&mut self.out.stdout, &self.colors, &self.colors.byte_num);
            }
            let off = byte_off - fs.offset_base;
            self.out
                .stdout
                .extend_from_slice(format!("{:>width$}", off, width = fs.offset_width).as_bytes());
            if self.colorize {
                sgr_end(&mut self.out.stdout, &self.colors, &self.colors.byte_num);
            }
            self.print_sep(sep);
        }
        if self.options.initial_tab
            && (fs.show == FShow::Yes || self.options.line_number || self.options.byte_offset)
            && !checked.is_empty()
        {
            self.out.stdout.push(b'\t');
        }
        true
    }

    fn print_sep(&mut self, sep: u8) {
        if self.colorize {
            sgr_start(&mut self.out.stdout, &self.colors, &self.colors.sep);
            self.out.stdout.push(sep);
            sgr_end(&mut self.out.stdout, &self.colors, &self.colors.sep);
        } else {
            self.out.stdout.push(sep);
        }
    }

    fn print_filename(&mut self, name: &[u8]) {
        if self.colorize {
            sgr_start(&mut self.out.stdout, &self.colors, &self.colors.filename);
        }
        self.out.stdout.extend_from_slice(name);
        if self.colorize {
            sgr_end(&mut self.out.stdout, &self.colors, &self.colors.filename);
        }
    }
}

// ---------------------------------------------------------------------------
// Stdin reader
// ---------------------------------------------------------------------------

struct SliceReader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> SliceReader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
    }
}

impl io::Read for SliceReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let avail = self.fill_buf()?;
        let n = avail.len().min(buf.len());
        buf[..n].copy_from_slice(&avail[..n]);
        self.consume(n);
        Ok(n)
    }
}

impl BufRead for SliceReader<'_> {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        // Chunk like GNU's 96 KiB reads so binary detection is aligned.
        let end = (self.pos + CHUNK_BYTES).min(self.data.len());
        Ok(&self.data[self.pos..end])
    }

    fn consume(&mut self, amt: usize) {
        self.pos += amt;
    }
}

fn is_device_mode(m: &fs::Metadata) -> bool {
    use std::os::unix::fs::FileTypeExt;
    let ft = m.file_type();
    ft.is_char_device() || ft.is_block_device() || ft.is_socket() || ft.is_fifo()
}

fn digits(mut num: u64) -> usize {
    let mut n = 0usize;
    loop {
        n += 1;
        num /= 10;
        if num == 0 {
            return n;
        }
    }
}
