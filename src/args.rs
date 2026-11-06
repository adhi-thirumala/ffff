//! GNU grep 3.12-compatible command-line parser.
//!
//! Implements the complete option grammar of GNU grep 3.12 (glibc
//! `getopt_long` semantics) over raw `OsString` bytes: clustered short
//! options, attached or separate values, long options with `=` or
//! unambiguous abbreviations, `--`-terminated option scanning, options
//! after operands (unless POSIXLY_CORRECT), `-NUM` context options,
//! repeated `-e`/`-f` pattern options, and the default first-operand
//! pattern. All search and output flags listed in `grep --help` are
//! supported; informational `--help`, `--version`, and `-V` are intentionally
//! rejected by the library wrapper.
//!
//! Pattern-file and exclude-file contents are not read here; the engine
//! loads them via [`PatternSource`] and [`FileFilter`].  Arguments are
//! never converted through UTF-8: patterns, file names, labels and globs
//! are preserved as raw bytes.
//!
//! Errors are GNU-shaped diagnostic bodies: getopt-style parse errors
//! carry the two-line usage trailer, value errors (`die`) do not.

pub use parser::parse;
pub mod parser {
    use std::ffi::OsString;
    use std::os::unix::ffi::{OsStrExt, OsStringExt};
    use std::path::PathBuf;

    use fff_search::grep_compat::{
        Binary, Color, DeviceMode, Directories, FileFilter, Mode, Options, PatternSource,
    };

    /// GNU's usage trailer, printed after getopt diagnostics.
    const USAGE: &str =
        "Usage: grep [OPTION]... PATTERNS [FILE]...\nTry 'grep --help' for more information.";

    /// Full `grep --help` text (usage(EXIT_SUCCESS) in grep.c v3.12).
    pub const HELP_TEXT: &str = r#"Usage: grep [OPTION]... PATTERNS [FILE]...
Search for PATTERNS in each FILE.
Example: grep -i 'hello world' menu.h main.c
PATTERNS can contain multiple patterns separated by newlines.

Pattern selection and interpretation:
  -E, --extended-regexp     PATTERNS are extended regular expressions
  -F, --fixed-strings       PATTERNS are strings
  -G, --basic-regexp        PATTERNS are basic regular expressions
  -P, --perl-regexp         PATTERNS are Perl regular expressions
  -e, --regexp=PATTERNS     use PATTERNS for matching
  -f, --file=FILE           take PATTERNS from FILE
  -i, --ignore-case         ignore case distinctions in patterns and data
      --no-ignore-case      do not ignore case distinctions (default)
  -w, --word-regexp         match only whole words
  -x, --line-regexp         match only whole lines
  -z, --null-data           a data line ends in 0 byte, not newline

Miscellaneous:
  -s, --no-messages         suppress error messages
  -v, --invert-match        select non-matching lines
  -V, --version             display version information and exit
      --help                display this help text and exit

Output control:
  -m, --max-count=NUM       stop after NUM selected lines
  -b, --byte-offset         print the byte offset with output lines
  -n, --line-number         print line number with output lines
      --line-buffered       flush output on every line
  -H, --with-filename       print file name with output lines
  -h, --no-filename         suppress the file name prefix on output
      --label=LABEL         use LABEL as the standard input file name prefix
  -o, --only-matching       show only nonempty parts of lines that match
  -q, --quiet, --silent     suppress all normal output
      --binary-files=TYPE   assume that binary files are TYPE;
                            TYPE is 'binary', 'text', or 'without-match'
  -a, --text                equivalent to --binary-files=text
  -I                        equivalent to --binary-files=without-match
  -d, --directories=ACTION  how to handle directories;
                            ACTION is 'read', 'recurse', or 'skip'
  -D, --devices=ACTION      how to handle devices, FIFOs and sockets;
                            ACTION is 'read' or 'skip'
  -r, --recursive           like --directories=recurse
  -R, --dereference-recursive  likewise, but follow all symlinks
      --include=GLOB        search only files that match GLOB (a file pattern)
      --exclude=GLOB        skip files that match GLOB
      --exclude-from=FILE   skip files that match any file pattern from FILE
      --exclude-dir=GLOB    skip directories that match GLOB
  -L, --files-without-match  print only names of FILEs with no selected lines
  -l, --files-with-matches  print only names of FILEs with selected lines
  -c, --count               print only a count of selected lines per FILE
  -T, --initial-tab         make tabs line up (if needed)
  -Z, --null                print 0 byte after FILE name

Context control:
  -B, --before-context=NUM  print NUM lines of leading context
  -A, --after-context=NUM   print NUM lines of trailing context
  -C, --context=NUM         print NUM lines of output context
  -NUM                      same as --context=NUM
      --group-separator=SEP  print SEP on line between matches with context
      --no-group-separator  do not print separator for matches with context
      --color[=WHEN],
      --colour[=WHEN]       use markers to highlight the matching strings;
                            WHEN is 'always', 'never', or 'auto'
  -U, --binary              do not strip CR characters at EOL (MSDOS/Windows)

When FILE is '-', read standard input.  If no FILE is given, read standard
input, but with -r, recursively search the working directory instead.  With
fewer than two FILEs, assume -h.  Exit status is 0 if any line is selected,
1 otherwise; if any error occurs and -q is not given, the exit status is 2.

Report bugs to: bug-grep@gnu.org
GNU grep home page: <https://www.gnu.org/software/grep/>
General help using GNU software: <https://www.gnu.org/gethelp/>
"#;

    /// Append GNU's usage trailer to a getopt-style diagnostic.
    fn with_usage(msg: String) -> String {
        format!("{msg}\n{USAGE}")
    }

    /// Display raw bytes in diagnostics, lossily for non-UTF-8.
    fn show(bytes: &[u8]) -> String {
        String::from_utf8_lossy(bytes).into_owned()
    }

    /// How a long option takes its argument (identity component).
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Kind {
        No,
        Req,
        Opt,
    }

    /// Option action tags; long and short options share them.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Tag {
        After,
        Before,
        Context,
        Devices,
        Ext,
        Fixed,
        Basic,
        WithFilename,
        BinarySkip,
        Perl,
        InitialTab,
        BinaryIO,
        Version,
        MatcherName,
        Text,
        ByteOffset,
        Count,
        DirAction,
        Regexp,
        PatternFile,
        NoFilename,
        IgnoreCase,
        FilesWithout,
        FilesWith,
        MaxCount,
        LineNumber,
        OnlyMatching,
        Quiet,
        DerefRecursive,
        Recursive,
        NoMessages,
        ObsoleteUnix,
        Invert,
        Word,
        WholeLine,
        LegacyIgnoreCase,
        NullFilename,
        NullData,
        BinaryFiles,
        ColorOpt,
        Exclude,
        ExcludeFrom,
        ExcludeDir,
        GroupSep,
        Help,
        Include,
        Label,
        LineBuffered,
        NoIgnoreCase,
    }

    /// The long-option table, in the exact order of grep.c v3.12
    /// `long_options` (ambiguity listings follow this order).
    const LONG_OPTS: &[(&[u8], Kind, Tag)] = &[
        (b"basic-regexp", Kind::No, Tag::Basic),
        (b"extended-regexp", Kind::No, Tag::Ext),
        (b"fixed-regexp", Kind::No, Tag::Fixed),
        (b"fixed-strings", Kind::No, Tag::Fixed),
        (b"perl-regexp", Kind::No, Tag::Perl),
        (b"after-context", Kind::Req, Tag::After),
        (b"before-context", Kind::Req, Tag::Before),
        (b"binary-files", Kind::Req, Tag::BinaryFiles),
        (b"byte-offset", Kind::No, Tag::ByteOffset),
        (b"context", Kind::Req, Tag::Context),
        (b"color", Kind::Opt, Tag::ColorOpt),
        (b"colour", Kind::Opt, Tag::ColorOpt),
        (b"count", Kind::No, Tag::Count),
        (b"devices", Kind::Req, Tag::Devices),
        (b"directories", Kind::Req, Tag::DirAction),
        (b"exclude", Kind::Req, Tag::Exclude),
        (b"exclude-from", Kind::Req, Tag::ExcludeFrom),
        (b"exclude-dir", Kind::Req, Tag::ExcludeDir),
        (b"file", Kind::Req, Tag::PatternFile),
        (b"files-with-matches", Kind::No, Tag::FilesWith),
        (b"files-without-match", Kind::No, Tag::FilesWithout),
        (b"group-separator", Kind::Req, Tag::GroupSep),
        (b"help", Kind::No, Tag::Help),
        (b"include", Kind::Req, Tag::Include),
        (b"ignore-case", Kind::No, Tag::IgnoreCase),
        (b"no-ignore-case", Kind::No, Tag::NoIgnoreCase),
        (b"initial-tab", Kind::No, Tag::InitialTab),
        (b"label", Kind::Req, Tag::Label),
        (b"line-buffered", Kind::No, Tag::LineBuffered),
        (b"line-number", Kind::No, Tag::LineNumber),
        (b"line-regexp", Kind::No, Tag::WholeLine),
        (b"max-count", Kind::Req, Tag::MaxCount),
        (b"no-filename", Kind::No, Tag::NoFilename),
        (b"no-group-separator", Kind::No, Tag::GroupSep),
        (b"no-messages", Kind::No, Tag::NoMessages),
        (b"null", Kind::No, Tag::NullFilename),
        (b"null-data", Kind::No, Tag::NullData),
        (b"only-matching", Kind::No, Tag::OnlyMatching),
        (b"quiet", Kind::No, Tag::Quiet),
        (b"recursive", Kind::No, Tag::Recursive),
        (b"dereference-recursive", Kind::No, Tag::DerefRecursive),
        (b"regexp", Kind::Req, Tag::Regexp),
        (b"invert-match", Kind::No, Tag::Invert),
        (b"silent", Kind::No, Tag::Quiet),
        (b"text", Kind::No, Tag::Text),
        (b"binary", Kind::No, Tag::BinaryIO),
        (b"version", Kind::No, Tag::Version),
        (b"with-filename", Kind::No, Tag::WithFilename),
        (b"word-regexp", Kind::No, Tag::Word),
    ];

    /// Look up a short option: `(has_argument, tag)`; digits handled by
    /// the caller, unknown characters return `None`.
    fn short_opt(c: u8) -> Option<(bool, Tag)> {
        use Tag::*;
        let (req, tag) = match c {
            b'A' => (true, After),
            b'B' => (true, Before),
            b'C' => (true, Context),
            b'D' => (true, Devices),
            b'E' => (false, Ext),
            b'F' => (false, Fixed),
            b'G' => (false, Basic),
            b'H' => (false, WithFilename),
            b'I' => (false, BinarySkip),
            b'P' => (false, Perl),
            b'T' => (false, InitialTab),
            b'U' => (false, BinaryIO),
            b'V' => (false, Version),
            b'X' => (true, MatcherName),
            b'a' => (false, Text),
            b'b' => (false, ByteOffset),
            b'c' => (false, Count),
            b'd' => (true, DirAction),
            b'e' => (true, Regexp),
            b'f' => (true, PatternFile),
            b'h' => (false, NoFilename),
            b'i' => (false, IgnoreCase),
            b'L' => (false, FilesWithout),
            b'l' => (false, FilesWith),
            b'm' => (true, MaxCount),
            b'n' => (false, LineNumber),
            b'o' => (false, OnlyMatching),
            b'q' => (false, Quiet),
            b'R' => (false, DerefRecursive),
            b'r' => (false, Recursive),
            b's' => (false, NoMessages),
            b'u' => (false, ObsoleteUnix),
            b'v' => (false, Invert),
            b'w' => (false, Word),
            b'x' => (false, WholeLine),
            b'y' => (false, LegacyIgnoreCase),
            b'Z' => (false, NullFilename),
            b'z' => (false, NullData),
            _ => return None,
        };
        Some((req, tag))
    }

    /// Result of parsing an integer the way gnulib `xstrtoimax(str, 0,
    /// 10, ...)` does: leading `isspace` skipped by `strtoimax`, optional
    /// sign, base-10 digits, and the whole string must be consumed.
    enum Intmax {
        Val(i64),
        PosOverflow,
        NegOverflow,
        Invalid,
    }

    fn parse_intmax(bytes: &[u8]) -> Intmax {
        // C-locale isspace: space, \t, \n, \v, \f, \r (strtoimax skips these).
        let mut i = 0;
        while i < bytes.len() && matches!(bytes[i], b' ' | b'\t' | b'\n' | 0x0B | 0x0C | b'\r') {
            i += 1;
        }
        let mut neg = false;
        if i < bytes.len() && (bytes[i] == b'+' || bytes[i] == b'-') {
            neg = bytes[i] == b'-';
            i += 1;
        }
        let start = i;
        let mut acc: i128 = 0;
        let mut overflow = false;
        while i < bytes.len() && bytes[i].is_ascii_digit() {
            if !overflow {
                acc = acc * 10 + (bytes[i] - b'0') as i128;
                if acc > i64::MAX as i128 + 1 {
                    overflow = true;
                }
            }
            i += 1;
        }
        if i == start || i != bytes.len() {
            return Intmax::Invalid;
        }
        if overflow {
            return if neg {
                Intmax::NegOverflow
            } else {
                Intmax::PosOverflow
            };
        }
        if neg {
            if acc > i64::MAX as i128 + 1 {
                Intmax::NegOverflow
            } else if acc == i64::MAX as i128 + 1 {
                Intmax::Val(i64::MIN)
            } else {
                Intmax::Val(-(acc as i64))
            }
        } else if acc > i64::MAX as i128 {
            Intmax::PosOverflow
        } else {
            Intmax::Val(acc as i64)
        }
    }

    /// `context_length_arg`: accepts zero and positive values, ceilings
    /// overflow at INTMAX_MAX, rejects everything else with GNU's message.
    fn parse_context(value: &[u8]) -> Result<i64, String> {
        match parse_intmax(value) {
            Intmax::Val(n) if n >= 0 => Ok(n),
            Intmax::PosOverflow => Ok(i64::MAX),
            _ => Err(format!("{}: invalid context length argument", show(value))),
        }
    }

    /// Append one digit to a `-NUM` run with GNU's leading-zero
    /// suppression and its 21-digit buffer cap.
    fn push_digit(digits: &mut Vec<u8>, digit: u8) -> Result<(), String> {
        if digits.len() == 21 {
            let mut too_long = digits.clone();
            too_long.extend_from_slice(b"...");
            return Err(format!(
                "{}: invalid context length argument",
                show(&too_long)
            ));
        }
        if digits.as_slice() == b"0" {
            digits[0] = digit;
        } else {
            digits.push(digit);
        }
        Ok(())
    }

    /// Apply a finished `-NUM` digit run as the default context.
    fn flush_digits(digits: &mut Vec<u8>, st: &mut St) -> Result<(), String> {
        if digits.is_empty() {
            return Ok(());
        }
        let value = match parse_intmax(digits) {
            Intmax::Val(n) if n >= 0 => n,
            Intmax::PosOverflow => i64::MAX,
            _ => return Err(format!("{}: invalid context length argument", show(digits))),
        };
        st.default_context = value;
        st.context_seen = true;
        digits.clear();
        Ok(())
    }

    /// `setmatcher` from grep.c: matchers are indexed as in GNU's
    /// matchers table so conflicts match GNU exactly.
    fn set_matcher(index: usize, st: &mut St) -> Result<(), String> {
        if let Some(current) = st.matcher
            && current != index
        {
            return Err("conflicting matchers specified".into());
        }
        st.matcher = Some(index);
        Ok(())
    }

    /// `--directories` uses gnulib argmatch: exact match first, then
    /// unambiguous prefixes, then GNU's two error shapes.
    fn argmatch_directories(value: &[u8], st: &mut St) -> Result<(), String> {
        const ARGS: [&[u8]; 3] = [b"read", b"recurse", b"skip"];
        const TYPES: [Directories; 3] =
            [Directories::Read, Directories::Recurse, Directories::Skip];
        if let Some(i) = ARGS.iter().position(|a| *a == value) {
            st.opts.directories = TYPES[i];
            return Ok(());
        }
        let matches: Vec<usize> = (0..ARGS.len())
            .filter(|&i| ARGS[i].starts_with(value))
            .collect();
        if matches.len() == 1 {
            st.opts.directories = TYPES[matches[0]];
            return Ok(());
        }
        let what = if matches.is_empty() {
            "invalid"
        } else {
            "ambiguous"
        };
        Err(with_usage(format!(
            "{what} argument '{}' for '--directories'\n\
Valid arguments are:\n  - 'read'\n  - 'recurse'\n  - 'skip'",
            show(value)
        )))
    }

    /// Mutable parse state.
    struct St {
        opts: Options,
        matcher: Option<usize>,
        explicit_pattern: bool,
        default_context: i64,
        out_before: i64,
        out_after: i64,
        context_seen: bool,
    }

    /// ASCII case-insensitive equality (c_strcasecmp).
    fn eq_ascii_ci(value: &[u8], word: &[u8]) -> bool {
        value.len() == word.len()
            && value
                .iter()
                .zip(word)
                .all(|(&v, &w)| v.eq_ignore_ascii_case(&w))
    }

    /// Apply one option (long or short) with its value, if any.
    fn apply(tag: Tag, value: Option<&[u8]>, st: &mut St) -> Result<(), String> {
        use Tag::*;
        let v = || value.unwrap();
        match tag {
            Basic => set_matcher(0, st),
            Ext => set_matcher(1, st),
            Fixed => set_matcher(2, st),
            Perl => set_matcher(6, st),
            MatcherName => {
                let index = match v() {
                    b"grep" => 0,
                    b"egrep" => 1,
                    b"fgrep" => 2,
                    b"awk" => 3,
                    b"gawk" => 4,
                    b"posixawk" => 5,
                    b"perl" => 6,
                    other => return Err(format!("invalid matcher {}", show(other))),
                };
                set_matcher(index, st)
            }
            After => {
                st.out_after = parse_context(v())?;
                st.context_seen = true;
                Ok(())
            }
            Before => {
                st.out_before = parse_context(v())?;
                st.context_seen = true;
                Ok(())
            }
            Context => {
                st.default_context = parse_context(v())?;
                st.context_seen = true;
                Ok(())
            }
            Devices => {
                if v() == b"read" {
                    st.opts.devices = DeviceMode::Read;
                    Ok(())
                } else if v() == b"skip" {
                    st.opts.devices = DeviceMode::Skip;
                    Ok(())
                } else {
                    Err("unknown devices method".into())
                }
            }
            DirAction => argmatch_directories(v(), st),
            WithFilename => {
                st.opts.filename = Some(true);
                Ok(())
            }
            NoFilename => {
                st.opts.filename = Some(false);
                Ok(())
            }
            BinarySkip => {
                st.opts.binary = Binary::WithoutMatch;
                Ok(())
            }
            Text => {
                st.opts.binary = Binary::Text;
                Ok(())
            }
            BinaryFiles => {
                st.opts.binary = if v() == b"binary" {
                    Binary::Binary
                } else if v() == b"text" {
                    Binary::Text
                } else if v() == b"without-match" {
                    Binary::WithoutMatch
                } else {
                    return Err("unknown binary-files type".into());
                };
                Ok(())
            }
            InitialTab => {
                st.opts.initial_tab = true;
                Ok(())
            }
            BinaryIO => Ok(()), // -U/--binary: no-op off MSDOS/Windows
            ObsoleteUnix => Err(USAGE.to_string()), // -u removed in grep 3.12
            Version => Err("version output is intentionally unsupported".into()),
            Help => Err("help output is intentionally unsupported".into()),
            ByteOffset => {
                st.opts.byte_offset = true;
                Ok(())
            }
            Count => {
                st.opts.count = true;
                Ok(())
            }
            Regexp => {
                st.opts.patterns.push(PatternSource::Inline(v().to_vec()));
                st.explicit_pattern = true;
                Ok(())
            }
            PatternFile => {
                st.opts
                    .patterns
                    .push(PatternSource::File(PathBuf::from(OsString::from_vec(
                        v().to_vec(),
                    ))));
                st.explicit_pattern = true;
                Ok(())
            }
            IgnoreCase | LegacyIgnoreCase => {
                st.opts.ignore_case = true;
                Ok(())
            }
            NoIgnoreCase => {
                st.opts.ignore_case = false;
                Ok(())
            }
            FilesWithout => {
                st.opts.list_files = Some(false);
                Ok(())
            }
            FilesWith => {
                st.opts.list_files = Some(true);
                Ok(())
            }
            MaxCount => {
                st.opts.max_count = match parse_intmax(v()) {
                    Intmax::Val(n) => {
                        if n < 0 {
                            None // negative is unlimited in GNU
                        } else {
                            Some(n as u64)
                        }
                    }
                    Intmax::PosOverflow => Some(i64::MAX as u64),
                    Intmax::NegOverflow | Intmax::Invalid => return Err("invalid max count".into()),
                };
                Ok(())
            }
            LineNumber => {
                st.opts.line_number = true;
                Ok(())
            }
            OnlyMatching => {
                st.opts.only_matching = true;
                Ok(())
            }
            Quiet => {
                st.opts.quiet = true;
                Ok(())
            }
            DerefRecursive => {
                st.opts.directories = Directories::Recurse;
                st.opts.dereference = true;
                Ok(())
            }
            Recursive => {
                st.opts.directories = Directories::Recurse;
                Ok(())
            }
            NoMessages => {
                st.opts.no_messages = true;
                Ok(())
            }
            Invert => {
                st.opts.invert = true;
                Ok(())
            }
            Word => {
                st.opts.word = true;
                Ok(())
            }
            WholeLine => {
                st.opts.whole_line = true;
                Ok(())
            }
            NullFilename => {
                st.opts.null_filename = true;
                Ok(())
            }
            NullData => {
                st.opts.null_data = true;
                Ok(())
            }
            ColorOpt => {
                let setting = match value {
                    None => Color::Auto,
                    Some(arg)
                        if eq_ascii_ci(arg, b"always")
                            || eq_ascii_ci(arg, b"yes")
                            || eq_ascii_ci(arg, b"force") =>
                    {
                        Color::Always
                    }
                    Some(arg)
                        if eq_ascii_ci(arg, b"never")
                            || eq_ascii_ci(arg, b"no")
                            || eq_ascii_ci(arg, b"none") =>
                    {
                        Color::Never
                    }
                    Some(arg)
                        if eq_ascii_ci(arg, b"auto")
                            || eq_ascii_ci(arg, b"tty")
                            || eq_ascii_ci(arg, b"if-tty") =>
                    {
                        Color::Auto
                    }
                    // GNU prints the help text (exit 0) for unknown settings.
                    Some(_) => return Err(HELP_TEXT.to_string()),
                };
                st.opts.color = setting;
                Ok(())
            }
            Exclude => {
                st.opts
                    .filters
                    .push(FileFilter::Exclude(OsString::from_vec(v().to_vec())));
                Ok(())
            }
            Include => {
                st.opts
                    .filters
                    .push(FileFilter::Include(OsString::from_vec(v().to_vec())));
                Ok(())
            }
            ExcludeFrom => {
                st.opts
                    .filters
                    .push(FileFilter::ExcludeFrom(PathBuf::from(OsString::from_vec(
                        v().to_vec(),
                    ))));
                Ok(())
            }
            ExcludeDir => {
                let mut dir = v().to_vec();
                while dir.last() == Some(&b'/') {
                    dir.pop();
                }
                st.opts.exclude_dirs.push(OsString::from_vec(dir));
                Ok(())
            }
            GroupSep => match value {
                Some(sep) => {
                    st.opts.group_separator = Some(sep.to_vec());
                    Ok(())
                }
                None => {
                    st.opts.group_separator = None;
                    Ok(())
                }
            },
            Label => {
                st.opts.label = OsString::from_vec(v().to_vec());
                Ok(())
            }
            LineBuffered => {
                st.opts.line_buffered = true;
                Ok(())
            }
        }
    }

    /// Parse GNU grep 3.12 arguments.  `posixly_correct` stops option
    /// scanning at the first operand, like the `POSIXLY_CORRECT`
    /// environment variable does for glibc getopt.
    pub fn parse(args: &[OsString], posixly_correct: bool) -> Result<Options, String> {
        let argv: Vec<&[u8]> = args.iter().map(|a| a.as_bytes()).collect();
        let mut st = St {
            opts: Options::default(),
            matcher: None,
            explicit_pattern: false,
            default_context: -1,
            out_before: -1,
            out_after: -1,
            context_seen: false,
        };
        let mut operands: Vec<Vec<u8>> = Vec::new();
        let mut options_on = true;
        let mut i = 0;
        while i < argv.len() {
            let arg = argv[i];
            if !options_on || arg == b"-" || !arg.starts_with(b"-") {
                operands.push(arg.to_vec());
                if posixly_correct {
                    options_on = false;
                }
                i += 1;
                continue;
            }
            if arg == b"--" {
                options_on = false;
                i += 1;
                continue;
            }
            if let Some(body) = arg.strip_prefix(b"--") {
                // Long option.
                let (name, attached) = match body.iter().position(|&b| b == b'=') {
                    Some(p) => (&body[..p], Some(&body[p + 1..])),
                    None => (body, None),
                };
                let chosen = if let Some(exact) = LONG_OPTS.iter().find(|(n, _, _)| *n == name) {
                    Some(exact)
                } else {
                    let matches: Vec<&(&[u8], Kind, Tag)> = LONG_OPTS
                        .iter()
                        .filter(|(n, _, _)| n.starts_with(name))
                        .collect();
                    if matches.is_empty() {
                        None
                    } else if matches.len() == 1
                        || matches
                            .iter()
                            .all(|m| (m.1, m.2) == (matches[0].1, matches[0].2))
                    {
                        Some(matches[0])
                    } else {
                        let list = matches
                            .iter()
                            .map(|(n, _, _)| format!(" '--{}'", show(n)))
                            .collect::<String>();
                        return Err(with_usage(format!(
                            "option '{}' is ambiguous; possibilities:{list}",
                            show(arg)
                        )));
                    }
                };
                let Some((long_name, kind, tag)) = chosen else {
                    return Err(with_usage(format!("unrecognized option '{}'", show(arg))));
                };
                let value: Option<&[u8]> = match kind {
                    Kind::No => {
                        if attached.is_some() {
                            return Err(with_usage(format!(
                                "option '--{}' doesn't allow an argument",
                                show(long_name)
                            )));
                        }
                        None
                    }
                    Kind::Req => match attached {
                        Some(v) => Some(v),
                        None => match argv.get(i + 1) {
                            Some(v) => {
                                i += 1;
                                Some(v)
                            }
                            None => {
                                return Err(with_usage(format!(
                                    "option '--{}' requires an argument",
                                    show(long_name)
                                )));
                            }
                        },
                    },
                    Kind::Opt => attached,
                };
                apply(*tag, value, &mut st)?;
                i += 1;
                continue;
            }
            // Short option cluster.
            let cluster = &arg[1..];
            let mut pos = 0;
            let mut digits: Vec<u8> = Vec::new();
            'cluster: loop {
                if pos == cluster.len() {
                    flush_digits(&mut digits, &mut st)?;
                    i += 1;
                    break 'cluster;
                }
                let c = cluster[pos];
                if c.is_ascii_digit() {
                    push_digit(&mut digits, c)?;
                    pos += 1;
                    continue;
                }
                flush_digits(&mut digits, &mut st)?;
                let Some((has_arg, tag)) = short_opt(c) else {
                    return Err(with_usage(format!("invalid option -- '{}'", show(&[c]))));
                };
                if !has_arg {
                    apply(tag, None, &mut st)?;
                    pos += 1;
                    continue;
                }
                // Required argument: rest of cluster, else next element.
                let mut consumed = 1;
                let value: &[u8] = if pos + 1 < cluster.len() {
                    &cluster[pos + 1..]
                } else {
                    match argv.get(i + 1) {
                        Some(v) => {
                            consumed = 2;
                            v
                        }
                        None => {
                            return Err(with_usage(format!(
                                "option requires an argument -- '{}'",
                                show(&[c])
                            )));
                        }
                    }
                };
                apply(tag, Some(value), &mut st)?;
                i += consumed;
                break 'cluster;
            }
        }

        // Default first-operand pattern, unless -e/-f were given.
        if !st.explicit_pattern {
            if operands.is_empty() {
                return Err(USAGE.to_string());
            }
            let mut pattern = operands.remove(0);
            // Non-fgrep matchers unescape a leading "\-".
            if st.matcher != Some(2) && pattern.starts_with(b"\\-") {
                pattern.remove(0);
            }
            st.opts.patterns.push(PatternSource::Inline(pattern));
        }
        st.opts.files = operands
            .into_iter()
            .map(|bytes| PathBuf::from(OsString::from_vec(bytes)))
            .collect();

        // Resolve context: explicit -A/-B beat -C/-NUM regardless of order.
        if st.out_after < 0 {
            st.out_after = st.default_context;
        }
        if st.out_before < 0 {
            st.out_before = st.default_context;
        }
        st.opts.after = if st.out_after < 0 {
            0
        } else {
            st.out_after as usize
        };
        st.opts.before = if st.out_before < 0 {
            0
        } else {
            st.out_before as usize
        };
        st.opts.context = st.context_seen;

        st.opts.mode = match st.matcher {
            None | Some(0) => Mode::Basic,
            Some(1) => Mode::Extended,
            Some(2) => Mode::Fixed,
            Some(3) => Mode::Awk,
            Some(4) => Mode::GnuAwk,
            Some(5) => Mode::PosixAwk,
            Some(6) => Mode::Perl,
            _ => unreachable!(),
        };
        Ok(st.opts)
    }
}
