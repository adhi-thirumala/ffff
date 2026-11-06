//! GNU grep-compatible matchers.
//!
//! BRE/ERE/AWK and fixed strings run through the C bridge in `native.c`
//! (glibc GNU regex with `re_compile_pattern`/`re_search`/`re_match`, the
//! corresponding `RE_SYNTAX_*` mode, `RE_ICASE`, plus byte-literal -F
//! matching with GNU's `toupper` folding). `-P` uses `pcre2-sys` directly
//! because the high-level
//! `pcre2` crate cannot express GNU's compile flags (DOLLAR_ENDONLY,
//! EXTRA_ASCII_BSD, EXTRA_MATCH_LINE, MATCH_INVALID_UTF) nor match-time
//! NOTBOL.  Semantics mirror GNU grep 3.12's EGexecute/Fexecute exact path
//! and `print_line_middle` iteration; there is no DFA/KWset prefilter, so
//! the `-w`/`-x` acceptance checks run in the search loop itself.
//!
//! One `Matcher` is used on one blocking thread at a time and may move
//! between threads (it is `Send`, not `Sync`).  Locale state is per-matcher
//! (`newlocale`) and entered/restored around every call via `uselocale`;
//! `setlocale` is never called and no other process-global state is touched.
//!
//! Record framing: one record per call, including its terminator byte
//! (`\n`, or `\0` with `-z`); a final record may lack it.  Matches never
//! include the terminator.  Record start is always a line start (BOL).
//! Reported spans are byte offsets into the record as passed.

use std::borrow::Cow;
use std::collections::HashSet;
use std::ffi::{CStr, c_char, c_void};
use std::os::unix::ffi::OsStrExt;
use std::ptr;

use super::{Environment, Mode, Options};

const ERR_TOO_LARGE: i32 = -1;
const ERR_INTERNAL: i32 = -2;

// ---------------------------------------------------------------------
// C bridge declarations (implemented in native.c)
// ---------------------------------------------------------------------

#[repr(C)]
struct FffLocale {
    _opaque: [u8; 0],
}
#[repr(C)]
struct FffMatcher {
    _opaque: [u8; 0],
}

unsafe extern "C" {
    // glibc: thread-local locale swap; the only locale mechanism used.
    fn uselocale(loc: *mut c_void) -> *mut c_void;

    fn fff_locale_new(name: *const c_char, name_len: usize) -> *mut FffLocale;
    fn fff_locale_free(loc: *mut FffLocale);
    fn fff_locale_get(loc: *const FffLocale) -> *mut c_void;
    fn fff_locale_info(loc: *const FffLocale, mb_cur_max: *mut i32, is_utf8: *mut i32);
    fn fff_valid_text(loc: *const FffLocale, s: *const u8, len: usize) -> i32;
    /// GNU grep.c try_fgrep_pattern: with 2+ patterns, -E/-G switch to -F
    /// byte matching when every pattern is a literal (observable with -x -w,
    /// where the regex engine reports a doubled terminator and kwset does not).
    fn fff_try_fgrep(
        pats: *const *const u8,
        lens: *const usize,
        pcount: i32,
        is_ere: i32,
        icase: i32,
        loc: *const FffLocale,
    ) -> i32;

    fn fff_matcher_compile(
        pats: *const *const u8,
        lens: *const usize,
        pcount: i32,
        mode: i32, // 0 = BRE, 1 = ERE, 2 = fixed, 3/4/5 = AWK variants
        icase: i32,
        word: i32,
        whole: i32,
        eol_nl: i32,
        loc: *const FffLocale,
        err_pat: *mut i32,
        errbuf: *mut c_char,
        errlen: usize,
    ) -> *mut FffMatcher;
    fn fff_matcher_free(m: *mut FffMatcher);
    fn fff_matcher_find(
        m: *mut FffMatcher,
        s: *const u8,
        len: usize,
        start: usize,
        ms: *mut usize,
        me: *mut usize,
    ) -> i32;
    fn fff_matcher_is_match(m: *mut FffMatcher, s: *const u8, len: usize) -> i32;
}

// ---------------------------------------------------------------------
// Locale ownership and RAII
// ---------------------------------------------------------------------

struct Locale {
    ptr: *mut FffLocale,
}

impl Locale {
    fn new(name: &std::ffi::OsStr) -> Result<Locale, String> {
        let bytes = name.as_bytes();
        // An empty name resolves all categories from the environment, as
        // glibc documents; the bridge falls back to "C" on failure.
        let ptr = unsafe { fff_locale_new(bytes.as_ptr().cast(), bytes.len()) };
        if ptr.is_null() {
            return Err("cannot allocate locale".into());
        }
        Ok(Locale { ptr })
    }

    fn get(&self) -> *mut c_void {
        unsafe { fff_locale_get(self.ptr) }
    }
}

impl Drop for Locale {
    fn drop(&mut self) {
        unsafe { fff_locale_free(self.ptr) };
    }
}

/// Enter `locale` on this thread until dropped.  `uselocale` returns the
/// previous locale and only touches thread-local state, so guards nest.
struct LocaleGuard {
    prev: *mut c_void,
}

impl LocaleGuard {
    fn enter(locale: *mut c_void) -> LocaleGuard {
        LocaleGuard {
            prev: unsafe { uselocale(locale) },
        }
    }
}

impl Drop for LocaleGuard {
    fn drop(&mut self) {
        unsafe { uselocale(self.prev) };
    }
}

// ---------------------------------------------------------------------
// Native backend (BRE/ERE/AWK/fixed)
// ---------------------------------------------------------------------

struct NativeMatcher {
    ptr: *mut FffMatcher,
}

impl Drop for NativeMatcher {
    fn drop(&mut self) {
        unsafe { fff_matcher_free(self.ptr) };
    }
}

impl NativeMatcher {
    fn new(
        patterns: &[&[u8]],
        mode: i32,
        options: &Options,
        locale: &Locale,
    ) -> Result<NativeMatcher, String> {
        let pts: Vec<*const u8> = patterns.iter().map(|p| p.as_ptr()).collect();
        let lens: Vec<usize> = patterns.iter().map(|p| p.len()).collect();
        let mut err_pat: i32 = -1;
        let mut errbuf = [0i8; 256];
        let ptr = unsafe {
            fff_matcher_compile(
                pts.as_ptr(),
                lens.as_ptr(),
                patterns.len() as i32,
                mode,
                options.ignore_case as i32,
                options.word as i32,
                options.whole_line as i32,
                (!options.null_data) as i32,
                locale.ptr,
                &mut err_pat,
                errbuf.as_mut_ptr(),
                errbuf.len(),
            )
        };
        if ptr.is_null() {
            let msg = unsafe { CStr::from_ptr(errbuf.as_ptr()) }
                .to_string_lossy()
                .into_owned();
            // The engine owns GNU's "grep: FILE:LINE: msg" formatting; the
            // index is into the deduplicated pattern sequence.
            return Err(if err_pat >= 0 {
                format!("pattern {}: {}", err_pat, msg)
            } else {
                msg
            });
        }
        Ok(NativeMatcher { ptr })
    }

    fn find(
        &self,
        record: &[u8],
        clen: usize,
        cur: usize,
    ) -> Result<Option<(usize, usize)>, String> {
        let mut ms = 0usize;
        let mut me = 0usize;
        let r = unsafe { fff_matcher_find(self.ptr, record.as_ptr(), clen, cur, &mut ms, &mut me) };
        match r {
            1 => Ok(Some((ms, me))),
            0 => Ok(None),
            ERR_TOO_LARGE | ERR_INTERNAL => Err("memory exhausted".into()),
            other => Err(format!("internal regex error: {}", other)),
        }
    }

    fn is_match(&self, record: &[u8], clen: usize) -> Result<bool, String> {
        let r = unsafe { fff_matcher_is_match(self.ptr, record.as_ptr(), clen) };
        match r {
            1 => Ok(true),
            0 => Ok(false),
            ERR_TOO_LARGE | ERR_INTERNAL => Err("memory exhausted".into()),
            other => Err(format!("internal regex error: {}", other)),
        }
    }
}

// ---------------------------------------------------------------------
// PCRE2 backend (-P)
// ---------------------------------------------------------------------

use pcre2_sys::*;

/// Raw pointers are not `Send`; the backend owns non-thread-bound PCRE2
/// state confined to one blocking worker at a time, so moving it across
/// threads is safe (see `unsafe impl Send for Matcher`).
#[derive(Clone, Copy)]
struct SendPtr<T>(*mut T);
unsafe impl<T> Send for SendPtr<T> {}

struct PcreMatcher {
    code: SendPtr<pcre2_code_8>,
    match_data: SendPtr<pcre2_match_data_8>,
    mcontext: std::cell::Cell<SendPtr<pcre2_match_context_8>>,
    jit_stack: std::cell::Cell<SendPtr<pcre2_jit_stack_8>>,
    jit_stack_size: std::cell::Cell<usize>,
}

impl Drop for PcreMatcher {
    fn drop(&mut self) {
        unsafe {
            if !self.jit_stack.get().0.is_null() {
                pcre2_jit_stack_free_8(self.jit_stack.get().0);
            }
            if !self.mcontext.get().0.is_null() {
                pcre2_match_context_free_8(self.mcontext.get().0);
            }
            pcre2_match_data_free_8(self.match_data.0);
            pcre2_code_free_8(self.code.0);
        }
    }
}

impl PcreMatcher {
    /// Compile with GNU grep 3.12 pcresearch.c flags: DOLLAR_ENDONLY always,
    /// CASELESS for -i; in a multibyte (UTF-8) locale also UTF,
    /// MATCH_INVALID_UTF, UCP plus EXTRA_ASCII_BSD so \d \s \w stay ASCII
    /// while -i folds per Unicode; -x uses EXTRA_MATCH_LINE; -w wraps the
    /// pattern in (?<!\w)(?:...)(?!\w).
    fn new(pattern: &[u8], options: &Options, locale: &Locale) -> Result<PcreMatcher, String> {
        let mut mb = 0i32;
        let mut utf8 = 0i32;
        unsafe { fff_locale_info(locale.ptr, &mut mb, &mut utf8) };
        let mut flags: u32 = PCRE2_DOLLAR_ENDONLY
            | if options.ignore_case {
                PCRE2_CASELESS
            } else {
                0
            };
        let mut extra: u32 = 0;
        if mb > 1 {
            if utf8 == 0 {
                return Err("-P supports only unibyte and UTF-8 locales".into());
            }
            flags |= PCRE2_UTF | PCRE2_MATCH_INVALID_UTF | PCRE2_UCP;
            extra |= PCRE2_EXTRA_ASCII_BSD;
        }
        if options.whole_line {
            extra |= PCRE2_EXTRA_MATCH_LINE;
        }
        let pat: Cow<'_, [u8]> = if options.word && !options.whole_line {
            const PREFIX: &[u8] = b"(?<!\\w)(?:";
            const SUFFIX: &[u8] = b")(?!\\w)";
            let mut v = Vec::with_capacity(pattern.len() + PREFIX.len() + SUFFIX.len());
            v.extend_from_slice(PREFIX);
            v.extend_from_slice(pattern);
            v.extend_from_slice(SUFFIX);
            Cow::Owned(v)
        } else {
            Cow::Borrowed(pattern)
        };
        // SAFETY: pattern/length are valid; ccontext is freed after compile.
        let cctx = unsafe { pcre2_compile_context_create_8(ptr::null_mut()) };
        if cctx.is_null() {
            return Err("memory exhausted".into());
        }
        if extra != 0 {
            // Extra options exist since PCRE2 10.43; pcre2-sys bindings are
            // generated from 10.46 and the linked library is at least that.
            if unsafe { pcre2_set_compile_extra_options_8(cctx, extra) } != 0 {
                unsafe { pcre2_compile_context_free_8(cctx) };
                return Err("internal PCRE error: bad compile option".into());
            }
        }
        let mut ec: i32 = 0;
        let mut eo: usize = 0;
        let code =
            unsafe { pcre2_compile_8(pat.as_ptr(), pat.len(), flags, &mut ec, &mut eo, cctx) };
        unsafe { pcre2_compile_context_free_8(cctx) };
        if code.is_null() {
            let mut buf = vec![0u8; 256];
            unsafe { pcre2_get_error_message_8(ec, buf.as_mut_ptr(), buf.len()) };
            let msg = CStr::from_bytes_until_nul(&buf)
                .map(|c| c.to_string_lossy().into_owned())
                .unwrap_or_default();
            return Err(msg);
        }
        let match_data = unsafe { pcre2_match_data_create_from_pattern_8(code, ptr::null_mut()) };
        if match_data.is_null() {
            unsafe { pcre2_code_free_8(code) };
            return Err("memory exhausted".into());
        }
        // Best effort, like GNU (matching falls back to the interpreter).
        unsafe { pcre2_jit_compile_8(code, PCRE2_JIT_COMPLETE) };
        Ok(PcreMatcher {
            code: SendPtr(code),
            match_data: SendPtr(match_data),
            mcontext: std::cell::Cell::new(SendPtr(ptr::null_mut())),
            jit_stack: std::cell::Cell::new(SendPtr(ptr::null_mut())),
            jit_stack_size: std::cell::Cell::new(32 << 10),
        })
    }

    /// Mirror GNU's jit_exec: one pcre2_match, growing the JIT stack and
    /// depth limit on the corresponding errors.
    fn exec(&self, record: &[u8], clen: usize, cur: usize, options: u32) -> Result<i32, String> {
        loop {
            let e = unsafe {
                pcre2_match_8(
                    self.code.0,
                    record.as_ptr(),
                    clen,
                    cur,
                    options,
                    self.match_data.0,
                    self.mcontext.get().0,
                )
            };
            if e == PCRE2_ERROR_JIT_STACKLIMIT && self.jit_stack_size.get() <= usize::MAX / 2 {
                let old = self.jit_stack_size.get();
                let new = old * 2;
                self.jit_stack_size.set(new);
                if !self.jit_stack.get().0.is_null() {
                    unsafe { pcre2_jit_stack_free_8(self.jit_stack.get().0) };
                }
                let stack = unsafe { pcre2_jit_stack_create_8(old, new, ptr::null_mut()) };
                if stack.is_null() {
                    return Err("memory exhausted".into());
                }
                self.jit_stack.set(SendPtr(stack));
                self.ensure_mcontext()?;
                // SAFETY: mcontext non-null; default callback, no user data.
                unsafe { pcre2_jit_stack_assign_8(self.mcontext.get().0, None, ptr::null_mut()) };
                continue;
            }
            if e == PCRE2_ERROR_DEPTHLIMIT {
                let mut lim: u32 = 0;
                // SAFETY: valid output pointer for PCRE2_CONFIG_DEPTHLIMIT.
                unsafe {
                    pcre2_config_8(PCRE2_CONFIG_DEPTHLIMIT, (&mut lim as *mut u32).cast());
                }
                if lim > u32::MAX / 2 {
                    return Err("exceeded PCRE's nested backtracking limit".into());
                }
                self.ensure_mcontext()?;
                unsafe { pcre2_set_depth_limit_8(self.mcontext.get().0, lim * 2) };
                continue;
            }
            return Ok(e);
        }
    }

    fn ensure_mcontext(&self) -> Result<(), String> {
        if self.mcontext.get().0.is_null() {
            let mc = unsafe { pcre2_match_context_create_8(ptr::null_mut()) };
            if mc.is_null() {
                return Err("memory exhausted".into());
            }
            self.mcontext.set(SendPtr(mc));
        }
        Ok(())
    }

    fn find(
        &self,
        record: &[u8],
        clen: usize,
        cur: usize,
    ) -> Result<Option<(usize, usize)>, String> {
        // Record start is a line start (BOL); GNU sets NOTBOL once the
        // search position moves off it (bol = p[-1] == eolbyte).
        let options = if cur > 0 { PCRE2_NOTBOL } else { 0 };
        let e = self.exec(record, clen, cur, options)?;
        match e {
            PCRE2_ERROR_NOMATCH => Ok(None),
            PCRE2_ERROR_NOMEMORY => Err("memory exhausted".into()),
            PCRE2_ERROR_JIT_STACKLIMIT => Err("exhausted PCRE JIT stack".into()),
            PCRE2_ERROR_MATCHLIMIT => Err("exceeded PCRE's backtracking limit".into()),
            PCRE2_ERROR_DEPTHLIMIT => Err("exceeded PCRE's nested backtracking limit".into()),
            PCRE2_ERROR_RECURSELOOP => Err("PCRE detected recurse loop".into()),
            e if e == PCRE2_ERROR_HEAPLIMIT => Err("exceeded PCRE's heap limit".into()),
            e if e >= 0 => {
                // SAFETY: match succeeded; ovector[0..2] is the whole match.
                let ov = unsafe {
                    std::slice::from_raw_parts(pcre2_get_ovector_pointer_8(self.match_data.0), 2)
                };
                Ok(Some((ov[0], ov[1])))
            }
            e => Err(format!("internal PCRE error: {}", e)),
        }
    }

    fn is_match(&self, record: &[u8], clen: usize) -> Result<bool, String> {
        Ok(self.find(record, clen, 0)?.is_some())
    }
}

// ---------------------------------------------------------------------
// Matcher
// ---------------------------------------------------------------------

enum Backend {
    Native(NativeMatcher),
    Pcre(PcreMatcher),
    /// No patterns at all (-f /dev/null): nothing matches; the engine owns
    /// -v inversion, which selects every record in that case.
    Never,
}

impl Backend {
    fn find(
        &self,
        record: &[u8],
        clen: usize,
        cur: usize,
    ) -> Result<Option<(usize, usize)>, String> {
        match self {
            Backend::Native(n) => n.find(record, clen, cur),
            Backend::Pcre(p) => p.find(record, clen, cur),
            Backend::Never => Ok(None),
        }
    }

    fn is_match(&self, record: &[u8], clen: usize) -> Result<bool, String> {
        match self {
            Backend::Native(n) => n.is_match(record, clen),
            Backend::Pcre(p) => p.is_match(record, clen),
            Backend::Never => Ok(false),
        }
    }
}

pub struct Matcher {
    backend: Backend,
    locale: Locale,
    null_data: bool,
}

// The matcher carries no thread-bound state: locale_t objects are shared
// per-thread on use and the backend is never used concurrently.  Moving the
// whole Matcher across threads (one blocking worker at a time) is safe.
unsafe impl Send for Matcher {}

impl Matcher {
    pub fn new(
        patterns: &[Vec<u8>],
        options: &Options,
        env: &Environment,
    ) -> Result<Matcher, String> {
        // GNU deduplicates patterns as they are added (grep.c
        // update_patterns); errors later refer to indices in the deduplicated
        // sequence, and -P accepts repeated identical patterns.
        let pats = dedup(patterns);
        let locale = Locale::new(&env.locale)?;
        let backend = match options.mode {
            Mode::Perl => {
                if pats.len() > 1 {
                    return Err("the -P option only supports a single pattern".into());
                }
                if let Some(pat) = pats.first() {
                    Backend::Pcre(PcreMatcher::new(pat, options, &locale)?)
                } else {
                    Backend::Never
                }
            }
            Mode::Basic
            | Mode::Extended
            | Mode::Fixed
            | Mode::Awk
            | Mode::GnuAwk
            | Mode::PosixAwk => {
                let mode = match options.mode {
                    Mode::Basic => 0,
                    Mode::Extended => 1,
                    Mode::Fixed => 2,
                    Mode::Awk => 3,
                    Mode::GnuAwk => 4,
                    Mode::PosixAwk => 5,
                    Mode::Perl => unreachable!(),
                };
                if pats.is_empty() {
                    Backend::Never
                } else {
                    // GNU's try_fgrep_pattern conversion (grep.c main):
                    // 2+ literal-safe patterns under -E/-G run as -F.
                    let pts: Vec<*const u8> = pats.iter().map(|p| p.as_ptr()).collect();
                    let lens: Vec<usize> = pats.iter().map(|p| p.len()).collect();
                    let can_try_fixed = matches!(options.mode, Mode::Basic | Mode::Extended);
                    let mode = if can_try_fixed
                        && pats.len() > 1
                        && unsafe {
                            fff_try_fgrep(
                                pts.as_ptr(),
                                lens.as_ptr(),
                                pats.len() as i32,
                                (mode == 1) as i32,
                                options.ignore_case as i32,
                                locale.ptr,
                            ) == 1
                        } {
                        2
                    } else {
                        mode
                    };
                    Backend::Native(NativeMatcher::new(&pats, mode, options, &locale)?)
                }
            }
        };
        Ok(Matcher {
            backend,
            locale,
            null_data: options.null_data,
        })
    }

    /// All matches GNU's `-o`/`--color` loop visits, left to right,
    /// non-overlapping, as (start, end) byte spans into the record as
    /// passed, including zero-length matches (which signal selection and
    /// advance the scan by one byte but print nothing).  With `-x -w` the
    /// regex engine may report a span running one byte past an unterminated
    /// final record: GNU's buffer sentinel, printed as the terminator byte.
    pub fn find_all(&self, record: &[u8]) -> Result<Vec<(usize, usize)>, String> {
        let clen = content_len(record, self.null_data);
        let mut spans = Vec::new();
        let mut cur = 0usize;
        while cur < record.len() {
            let Some((b, e)) = self.backend.find(record, clen, cur)? else {
                break;
            };
            spans.push((b, e));
            // GNU print_line_middle: advance by the match, at least one byte.
            cur = if e > b { e } else { b + 1 };
        }
        Ok(spans)
    }

    pub fn is_match(&self, record: &[u8]) -> Result<bool, String> {
        let clen = content_len(record, self.null_data);
        self.backend.is_match(record, clen)
    }

    /// True if BYTES are valid text in the matcher's locale (always true in
    /// single-byte locales).  The engine passes record content without the
    /// terminator, mirroring GNU's line checks.
    pub fn valid_text(&self, bytes: &[u8]) -> bool {
        unsafe { fff_valid_text(self.locale.ptr, bytes.as_ptr(), bytes.len()) == 1 }
    }

    /// Run F under this matcher's locale on the current thread.  For the
    /// engine's own locale-dependent work (e.g. libc fnmatch for excludes).
    /// Nests safely with the backend's internal guards.
    pub(crate) fn with_locale<T>(&self, f: impl FnOnce() -> T) -> T {
        let _guard = LocaleGuard::enter(self.locale.get());
        f()
    }
}

fn content_len(record: &[u8], null_data: bool) -> usize {
    let term = if null_data { b'\0' } else { b'\n' };
    match record.last() {
        Some(&b) if b == term => record.len() - 1,
        _ => record.len(),
    }
}

fn dedup(patterns: &[Vec<u8>]) -> Vec<&[u8]> {
    let mut seen = HashSet::new();
    patterns
        .iter()
        .filter(|p| seen.insert(p.as_slice()))
        .map(|p| p.as_slice())
        .collect()
}
