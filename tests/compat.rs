//! GNU-differential conformance cases: identical argv, stdin bytes, and
//! environment are fed to `/usr/bin/grep` and to `ffff::Grep`, and the raw
//! `Output` (stdout, stderr, status) must match byte for byte.

#[macro_use]
mod common;

use common::FileSpec::{Symlink, Text};
use common::{Case, FileSpec, assert_cases, s};
use std::sync::LazyLock;

// ---------------------------------------------------------------------------
// Matcher modes: BRE (default/-G), ERE, AWK variants, PCRE, fixed strings,
// and byte patterns.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn matcher_modes_match_gnu() {
    let cases: &[Case] = &[
        case!(
            "bre_interval",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"a\\{2\\}"), s(b"f")]
        ),
        case!(
            "bre_backref",
            &[(b"f", Text(b"aa\na\n"))],
            &[s(b"\\(a\\)\\1"), s(b"f")]
        ),
        case!(
            "bre_alternation",
            &[(b"f", Text(b"foo\nbar\nbaz\n"))],
            &[s(b"foo\\|bar"), s(b"f")]
        ),
        case!(
            "bre_plus_literal",
            &[(b"f", Text(b"a+\naa\n"))],
            &[s(b"a\\+"), s(b"f")]
        ),
        case!(
            "bre_anchors_class",
            &[(b"f", Text(b"cat\ncot\ncoat\n"))],
            &[s(b"^c[ao]t$"), s(b"f")]
        ),
        case!(
            "bre_star_greed",
            &[(b"f", Text(b"ba\nbaa\nbb\n"))],
            &[s(b"ba*"), s(b"f")]
        ),
        case!(
            "mode_g_explicit",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"-G"), s(b"a\\{2\\}"), s(b"f")]
        ),
        case!(
            "mode_X_awk_interval_is_literal",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"-X"), s(b"awk"), s(b"a{2}"), s(b"f")]
        ),
        case!(
            "mode_X_gawk_leading_star_is_literal",
            &[(b"f", Text(b"*a\na\naa\n"))],
            &[s(b"-X"), s(b"gawk"), s(b"*a"), s(b"f")]
        ),
        case!(
            "mode_X_posixawk_rejects_leading_star",
            &[(b"f", Text(b"*a\na\n"))],
            &[s(b"-X"), s(b"posixawk"), s(b"*a"), s(b"f")]
        ),
        case!(
            "mode_X_grep_attached",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"-Xgrep"), s(b"a\\{2\\}"), s(b"f")]
        ),
        case!(
            "mode_X_egrep",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"-X"), s(b"egrep"), s(b"a{2}"), s(b"f")]
        ),
        case!(
            "mode_X_fgrep",
            &[(b"f", Text(b"aa\na{2}\n"))],
            &[s(b"-X"), s(b"fgrep"), s(b"a{2}"), s(b"f")]
        ),
        case!(
            "mode_X_perl",
            &[(b"f", Text(b"ab\nac\n"))],
            &[s(b"-X"), s(b"perl"), s(b"a(?=b)"), s(b"f")]
        ),
        case!(
            "ere_backref",
            &[(b"f", Text(b"aa a\n"))],
            &[s(b"-E"), s(b"(a)\\1"), s(b"f")]
        ),
        case!(
            "ere_plus_question",
            &[(b"f", Text(b"ab\nabb\na\n"))],
            &[s(b"-E"), s(b"ab+?"), s(b"f")]
        ),
        case!(
            "ere_leftmost_longest",
            &[(b"f", Text(b"ab\n"))],
            &[s(b"-E"), s(b"-o"), s(b"a|ab"), s(b"f")]
        ),
        case!(
            "pcre_leftmost_shortest",
            &[(b"f", Text(b"ab\n"))],
            &[s(b"-P"), s(b"-o"), s(b"a|ab"), s(b"f")]
        ),
        case!(
            "pcre_lookahead",
            &[(b"f", Text(b"ab ac\n"))],
            &[s(b"-P"), s(b"a(?=b)"), s(b"f")]
        ),
        case!(
            "pcre_lookbehind",
            &[(b"f", Text(b"xa ya\n"))],
            &[s(b"-P"), s(b"-o"), s(b"(?<=x)a"), s(b"f")]
        ),
        case!(
            "pcre_backref",
            &[(b"f", Text(b"aa a\n"))],
            &[s(b"-P"), s(b"(a)\\1"), s(b"f")]
        ),
        case!(
            "pcre_word_long_forms",
            &[(b"f", Text(b"ab\nac\n"))],
            &[
                s(b"--perl-regexp"),
                s(b"--word-regexp"),
                s(b"a(?=b)"),
                s(b"f")
            ]
        ),
        case!(
            "pcre_eol_anchor",
            &[(b"f", Text(b"ab\na\n"))],
            &[s(b"-P"), s(b"b$"), s(b"f")]
        ),
        case!(
            "fixed_literal_metachars",
            &[(b"f", Text(b"x a[1],b y\nnope\n"))],
            &[s(b"-F"), s(b"a[1],b"), s(b"f")]
        ),
        case!(
            "fixed_dash_pattern",
            &[(b"f", Text(b"a-b\nc\n"))],
            &[s(b"-F"), s(b"-"), s(b"f")]
        ),
        case!(
            "fixed_glob_chars",
            &[(b"f", Text(b"*.rs != \\n\n"))],
            &[s(b"-F"), s(b"*.rs !="), s(b"f")]
        ),
        case!(
            "empty_pattern_default",
            &[(b"f", Text(b"a\n\nb\n"))],
            &[s(b""), s(b"f")]
        ),
        case!(
            "empty_pattern_fixed",
            &[(b"f", Text(b"a\n\nb\n"))],
            &[s(b"-F"), s(b""), s(b"f")]
        ),
        case!(
            "empty_pattern_ere",
            &[(b"f", Text(b"a\n\nb\n"))],
            &[s(b"-E"), s(b""), s(b"f")]
        ),
        case!(
            "dot_does_not_match_newline",
            &[(b"f", Text(b"a\nb\nacb\n"))],
            &[s(b"a.b"), s(b"f")]
        ),
        case!(
            "eol_anchor",
            &[(b"f", Text(b"ab\na\n"))],
            &[s(b"b$"), s(b"f")]
        ),
        case!(
            "byte_pattern_ff",
            &[(b"f", Text(b"a\xffb\nnope\n"))],
            &[s(b"\xff"), s(b"f")]
        ),
        case!(
            "byte_pattern_ff_fixed",
            &[(b"f", Text(b"a\xffb\nnope\n"))],
            &[s(b"-F"), s(b"\xff"), s(b"f")]
        ),
        case!(
            "byte_pattern_ff_o",
            &[(b"f", Text(b"a\xffb\nnope\n"))],
            &[s(b"-o"), s(b"\xff"), s(b"f")]
        ),
        case!(
            "multibyte_pattern_plain",
            &[(b"f", Text(b"x\xc3\xa9y\nnope\n"))],
            &[s(b"\xc3\xa9"), s(b"f")]
        ),
        case!(
            "multibyte_pattern_o",
            &[(b"f", Text(b"x\xc3\xa9y\nnope\n"))],
            &[s(b"-o"), s(b"\xc3\xa9"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

#[tokio::test]
async fn utf8_locale_matching_matches_gnu() {
    let utf8: &[(&str, Option<&str>)] = &[("LC_ALL", Some("C.UTF-8"))];
    let cases: &[Case] = &[
        case!("utf8_fixed_icase", &[(b"f", Text(b"CAF\xc3\x89\ncaf\xc3\xa9\ncafe\n"))], &[s(b"-Fi"), s(b"caf\xc3\xa9"), s(b"f")], env utf8),
        case!("utf8_bre_icase", &[(b"f", Text(b"CAF\xc3\x89\ncaf\xc3\xa9\ncafe\n"))], &[s(b"-Gi"), s(b"caf\xc3\xa9"), s(b"f")], env utf8),
        case!("utf8_ere_icase", &[(b"f", Text(b"\xce\x91\n\xce\xb1\nA\n"))], &[s(b"-Ei"), s(b"\xce\xb1"), s(b"f")], env utf8),
        case!("utf8_pcre_icase", &[(b"f", Text(b"\xce\x91\n\xce\xb1\nA\n"))], &[s(b"-Pi"), s(b"\xce\xb1"), s(b"f")], env utf8),
        case!("utf8_fixed_word", &[(b"f", Text(b"x\xc3\xa9\n\xc3\xa9\n\xc3\xa9z\n"))], &[s(b"-Fw"), s(b"\xc3\xa9"), s(b"f")], env utf8),
        case!("utf8_bre_word", &[(b"f", Text(b"x\xce\xb1\n\xce\xb1\n\xce\xb1z\n"))], &[s(b"-Gw"), s(b"\xce\xb1"), s(b"f")], env utf8),
        case!("utf8_pcre_word", &[(b"f", Text(b"x\xce\xb1\n\xce\xb1\n\xce\xb1z\n"))], &[s(b"-Pw"), s(b"\xce\xb1"), s(b"f")], env utf8),
        case!("utf8_fixed_icase_only_matching", &[(b"f", Text(b"xCAF\xc3\x89y\n"))], &[s(b"-Fio"), s(b"caf\xc3\xa9"), s(b"f")], env utf8),
        case!("utf8_invalid_pattern_fixed", &[(b"f", Text(b"a\xffb\n"))], &[s(b"-F"), s(b"\xff"), s(b"f")], env utf8),
        case!("utf8_invalid_output_reports_binary", &[(b"f", Text(b"foo\xff\n"))], &[s(b"foo"), s(b"f")], env utf8),
        case!("utf8_invalid_output_text_mode", &[(b"f", Text(b"foo\xff\n"))], &[s(b"-a"), s(b"foo"), s(b"f")], env utf8),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Selection flags: -v, -o, -x, -w, -i, --no-ignore-case and precedence.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn selection_flags_match_gnu() {
    // é = U+00E9. `const` (not `static`) so the byte arrays inline into the
    // case tables and get 'static promotion like b"..." literals do.
    const ACCENT_BYTES: &[u8] = b"\xc3\xa9\nx\xc3\xa9x\n\xc3\xa9 x\ncaf\xc3\xa9\n";
    const ACCENT_PAT: &[u8] = b"\xc3\xa9";
    const CAFE_BYTES: &[u8] = b"caf\xc3\xa9\nCAF\xc3\x89\nCAFE\ncafe\n";
    const CAFE_PAT: &[u8] = b"caf\xc3\xa9";
    let cases: &[Case] = &[
        case!(
            "invert",
            &[(b"f", Text(b"foo\nbar\n"))],
            &[s(b"-v"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invert_o_prints_nothing",
            &[(b"f", Text(b"a foo b\nbar\n"))],
            &[s(b"-v"), s(b"-o"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invert_o_all_match",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-v"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invert_x",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-v"), s(b"-x"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invert_w",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-v"), s(b"-w"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invert_empty_pattern",
            &[(b"f", Text(b"a\n\nb\n"))],
            &[s(b"-v"), s(b""), s(b"f")]
        ),
        case!(
            "invert_empty_x",
            &[(b"f", Text(b"\na\n\n"))],
            &[s(b"-v"), s(b"-x"), s(b""), s(b"f")]
        ),
        case!(
            "invert_empty_w",
            &[(b"f", Text(b"\na\n\n"))],
            &[s(b"-v"), s(b"-w"), s(b""), s(b"f")]
        ),
        case!(
            "only_matching",
            &[(b"f", Text(b"foo foo\n"))],
            &[s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "only_matching_multi_pattern",
            &[(b"f", Text(b"foo bar\nbar foo\n"))],
            &[s(b"-o"), s(b"-e"), s(b"foo"), s(b"-e"), s(b"bar"), s(b"f")]
        ),
        case!(
            "only_matching_empty",
            &[(b"f", Text(b"ab\n"))],
            &[s(b"-o"), s(b""), s(b"f")]
        ),
        case!(
            "only_matching_e_empty",
            &[(b"f", Text(b"ab\n"))],
            &[s(b"-e"), s(b""), s(b"-o"), s(b"f")]
        ),
        case!(
            "only_matching_x",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-x"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "only_matching_w",
            &[(b"f", Text(b"foo foobar\n"))],
            &[s(b"-w"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "word_boundaries",
            &[(b"f", Text(b"foo\nfoobar\nbar foo baz\n_foo\nfoo_bar\n"))],
            &[s(b"-w"), s(b"foo"), s(b"f")]
        ),
        case!(
            "word_boundaries_unicode",
            &[(b"f", Text(ACCENT_BYTES))],
            &[s(b"-w"), s(ACCENT_PAT), s(b"f")]
        ),
        case!(
            "word_boundaries_unicode_pcre",
            &[(b"f", Text(ACCENT_BYTES))],
            &[s(b"-P"), s(b"-w"), s(ACCENT_PAT), s(b"f")]
        ),
        case!(
            "word_empty_pattern",
            &[(b"f", Text(b"a\n\nb\n"))],
            &[s(b"-w"), s(b""), s(b"f")]
        ),
        case!(
            "word_fixed",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-w"), s(b"-F"), s(b"foo"), s(b"f")]
        ),
        case!(
            "word_fixed_punctuation",
            &[(b"f", Text(b"a.b\naxb\n"))],
            &[s(b"-F"), s(b"-w"), s(b"a.b"), s(b"f")]
        ),
        case!(
            "whole_line",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-x"), s(b"foo"), s(b"f")]
        ),
        case!(
            "whole_line_unicode",
            &[(b"f", Text(ACCENT_BYTES))],
            &[s(b"-x"), s(ACCENT_PAT), s(b"f")]
        ),
        case!(
            "whole_line_fixed_punct",
            &[(b"f", Text(b"a.b\naxb\n"))],
            &[s(b"-F"), s(b"-x"), s(b"a.b"), s(b"f")]
        ),
        case!(
            "whole_line_word_combo",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-x"), s(b"-w"), s(b"foo"), s(b"f")]
        ),
        case!(
            "word_line_combo",
            &[(b"f", Text(b"foo\nfoobar\n"))],
            &[s(b"-w"), s(b"-x"), s(b"foo"), s(b"f")]
        ),
        case!(
            "ignore_case",
            &[(b"f", Text(b"foo\nFOO\n"))],
            &[s(b"-i"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "legacy_y_ignore_case",
            &[(b"f", Text(b"foo\nFOO\n"))],
            &[s(b"-y"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "ignore_case_ascii_only_c_locale",
            &[(b"f", Text(CAFE_BYTES))],
            &[s(b"-i"), s(CAFE_PAT), s(b"f")]
        ),
        case!(
            "ignore_case_unicode_pcre",
            &[(b"f", Text(CAFE_BYTES))],
            &[s(b"-P"), s(b"-i"), s(CAFE_PAT), s(b"f")]
        ),
        case!(
            "ignore_case_fixed",
            &[(b"f", Text(b"foo\nFOO\n"))],
            &[s(b"-i"), s(b"-F"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "ignore_case_whole_line",
            &[(b"f", Text(b"foo\nFOO\nfoobar\n"))],
            &[s(b"-x"), s(b"-i"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "no_ignore_case_wins_first",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-i"), s(b"--no-ignore-case"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "ignore_case_wins_last",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--no-ignore-case"), s(b"-i"), s(b"FOO"), s(b"f")]
        ),
        case!(
            "ignore_case_duplicate_patterns",
            &[(b"f", Text(b"foo\nFOO\nbar\n"))],
            &[s(b"-i"), s(b"-e"), s(b"foo"), s(b"-e"), s(b"FOO"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// -c, -m, -l, -L, -q: per-file counts, caps, and selection precedence.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn counts_and_limits_match_gnu() {
    static MANY_HITS: LazyLock<Vec<u8>> = LazyLock::new(|| "hit\n".repeat(260).into_bytes());
    let many_files: Vec<(&'static [u8], FileSpec)> =
        vec![(b"many".as_slice(), FileSpec::Text(&MANY_HITS))];
    let many: &[(&'static [u8], FileSpec)] = &many_files;
    let cases: &[Case] = &[
        case!(
            "count",
            &[(b"f", Text(b"foo\nfoo\nbar\n"))],
            &[s(b"-c"), s(b"foo"), s(b"f")]
        ),
        case!(
            "count_no_match",
            &[(b"f", Text(b"bar\n"))],
            &[s(b"-c"), s(b"foo"), s(b"f")]
        ),
        case!(
            "count_empty_file",
            &[(b"e", Text(b""))],
            &[s(b"-c"), s(b"foo"), s(b"e")]
        ),
        case!(
            "count_multiple_files",
            &[(b"f", Text(b"foo\nfoo\n")), (b"g", Text(b"bar\n"))],
            &[s(b"-c"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "count_h",
            &[(b"f", Text(b"foo\nfoo\n")), (b"g", Text(b"bar\n"))],
            &[s(b"-c"), s(b"-h"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "count_ignores_n",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-c"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "count_o_counts_lines",
            &[(b"f", Text(b"foo foo\n"))],
            &[s(b"-c"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "count_v",
            &[(b"f", Text(b"foo\nbar\n"))],
            &[s(b"-c"), s(b"-v"), s(b"foo"), s(b"f")]
        ),
        case!(
            "count_inverted_empty_pattern_short_circuits",
            &[(b"f", Text(b"foo\nbar\n"))],
            &[s(b"-c"), s(b"-v"), s(b""), s(b"f")]
        ),
        case!(
            "count_z_records",
            &[(b"f", Text(b"foo\0foo\0bar\0"))],
            &[s(b"-c"), s(b"-z"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count",
            &[(b"f", Text(b"foo\nfoo\nfoo\n"))],
            &[s(b"-m1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_per_file",
            &[(b"f", Text(b"foo\nfoo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"-m1"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "max_count_v",
            &[(b"f", Text(b"y\ny\ny\n"))],
            &[s(b"-v"), s(b"-m1"), s(b"x"), s(b"f")]
        ),
        case!("max_count_v_stdin", &[], &[s(b"-m2"), s(b"-v"), s(b"foo")], stdin b"foo\nbar\nbar\nbar\n"),
        case!(
            "max_count_c",
            &[(b"f", Text(b"foo\nfoo\nfoo\n"))],
            &[s(b"-c"), s(b"-m2"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_v_c",
            &[(b"f", Text(b"bar\nbar\nfoo\n"))],
            &[s(b"-m1"), s(b"-v"), s(b"-c"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_o_prints_all_in_line",
            &[(b"f", Text(b"foo foo\n"))],
            &[s(b"-o"), s(b"-m1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_o_z_b",
            &[(b"f", Text(b"a foo\0foo\0foo\0"))],
            &[s(b"-m2"), s(b"-o"), s(b"-z"), s(b"-b"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_last_wins",
            &[(b"f", Text(b"foo\nfoo\nfoo\n"))],
            &[s(b"-m2"), s(b"-m1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_zero",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-m0"), s(b"foo"), s(b"f")]
        ),
        case!("max_count_zero_stdin", &[], &[s(b"-m0"), s(b"foo")], stdin b"foo\nbar\n"),
        case!(
            "max_count_zero_skips_missing",
            &[],
            &[s(b"-m0"), s(b"foo"), s(b"/nonexistent_m0")]
        ),
        case!(
            "max_count_zero_c_silent",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-m0"), s(b"-c"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_zero_L",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-m0"), s(b"-L"), s(b"foo"), s(b"f")]
        ),
        case!(
            "max_count_zero_c_L",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-m0"), s(b"-c"), s(b"-L"), s(b"foo"), s(b"f")]
        ),
        case!(
            "files_with_matches",
            &[(b"a", Text(b"foo\n")), (b"b", Text(b"bar\n"))],
            &[s(b"-l"), s(b"foo"), s(b"a"), s(b"b")]
        ),
        case!(
            "files_without_matches",
            &[(b"a", Text(b"foo\n")), (b"b", Text(b"bar\n"))],
            &[s(b"-L"), s(b"foo"), s(b"a"), s(b"b")]
        ),
        case!(
            "files_without_all_match",
            &[(b"a", Text(b"foo\n")), (b"d", Text(b"foo\n"))],
            &[s(b"-L"), s(b"foo"), s(b"a"), s(b"d")]
        ),
        case!(
            "files_without_none_match",
            &[(b"b", Text(b"bar\n")), (b"c", Text(b"baz\n"))],
            &[s(b"-L"), s(b"foo"), s(b"b"), s(b"c")]
        ),
        case!(
            "files_without_single_miss",
            &[(b"b", Text(b"bar\n"))],
            &[s(b"-L"), s(b"foo"), s(b"b")]
        ),
        case!(
            "files_without_binary_miss",
            &[(b"f", Text(b"bar\0baz\n"))],
            &[s(b"-L"), s(b"foo"), s(b"f")]
        ),
        case!(
            "files_with_binary_match",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-l"), s(b"foo"), s(b"f")]
        ),
        case!(
            "files_without_invert",
            &[(b"a", Text(b"foo\n")), (b"b", Text(b"bar\n"))],
            &[s(b"-L"), s(b"-v"), s(b"foo"), s(b"a"), s(b"b")]
        ),
        case!(
            "l_overrides_c",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"bar\n"))],
            &[s(b"-l"), s(b"-c"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "c_yields_to_l",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"bar\n"))],
            &[s(b"-c"), s(b"-l"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "quiet_hit",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-q"), s(b"foo"), s(b"f")]
        ),
        case!(
            "quiet_miss",
            &[(b"g", Text(b"bar\n"))],
            &[s(b"-q"), s(b"foo"), s(b"g")]
        ),
        case!(
            "quiet_overrides_L",
            &[(b"a", Text(b"foo\n")), (b"b", Text(b"bar\n"))],
            &[s(b"-q"), s(b"-L"), s(b"foo"), s(b"a"), s(b"b")]
        ),
        case!(
            "quiet_overrides_l",
            &[(b"a", Text(b"foo\n")), (b"b", Text(b"bar\n"))],
            &[s(b"-q"), s(b"-l"), s(b"foo"), s(b"a"), s(b"b")]
        ),
        case!(
            "quiet_overrides_c",
            &[(b"a", Text(b"foo\n"))],
            &[s(b"-q"), s(b"-c"), s(b"foo"), s(b"a")]
        ),
        case!(
            "quiet_missing_file",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-q"), s(b"foo"), s(b"/nope"), s(b"f")]
        ),
        case!(
            "quiet_binary",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-q"), s(b"foo"), s(b"f")]
        ),
        case!(
            "quiet_recursive",
            &[(b"a", Text(b"foo\n"))],
            &[s(b"-q"), s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "over_two_hundred_matches",
            many,
            &[s(b"-n"), s(b"hit"), s(b"many")]
        ),
        case!(
            "over_two_hundred_count",
            many,
            &[s(b"-c"), s(b"hit"), s(b"many")]
        ),
        case!(
            "over_two_hundred_m3",
            many,
            &[s(b"-m3"), s(b"hit"), s(b"many")]
        ),
        case!(
            "empty_pattern_list",
            &[(b"pat", Text(b"")), (b"f", Text(b"foo\nbar\n"))],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "empty_pattern_list_L",
            &[
                (b"pat", Text(b"")),
                (b"a", Text(b"foo\n")),
                (b"b", Text(b"bar\n"))
            ],
            &[s(b"-L"), s(b"-f"), s(b"pat"), s(b"a"), s(b"b")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Context: -A/-B/-C/-NUM precedence, grouping, separators, -m interplay.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn context_flags_match_gnu() {
    let l5: &[u8] = b"L0\nL1\nfoo\nL3\nL4\nL5\n";
    let cases: &[Case] = &[
        case!(
            "context_ab",
            &[(b"f", Text(b"x\nfoo\ny\n"))],
            &[s(b"-A1"), s(b"-B1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_C",
            &[(b"f", Text(b"x\nfoo\ny\n"))],
            &[s(b"-C1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_C0",
            &[(b"f", Text(b"x\nfoo\ny\n"))],
            &[s(b"-C0"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_dash_num",
            &[(b"f", Text(l5))],
            &[s(b"-2"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_a_b_override_c1",
            &[(b"f", Text(l5))],
            &[s(b"-A1"), s(b"-C2"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_a_b_override_c2",
            &[(b"f", Text(l5))],
            &[s(b"-C2"), s(b"-A1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_b_overrides_c1",
            &[(b"f", Text(l5))],
            &[s(b"-B1"), s(b"-C2"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_b_overrides_c2",
            &[(b"f", Text(l5))],
            &[s(b"-C2"), s(b"-B1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_three_way",
            &[(b"f", Text(l5))],
            &[s(b"-C1"), s(b"-B2"), s(b"-A3"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_C_last_wins",
            &[(b"f", Text(l5))],
            &[s(b"-C2"), s(b"-C1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_A_last_wins",
            &[(b"f", Text(l5))],
            &[s(b"-A2"), s(b"-A1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_num_yields_to_A",
            &[(b"f", Text(l5))],
            &[s(b"-2"), s(b"-A1"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_equal_ab",
            &[(b"f", Text(l5))],
            &[s(b"-A2"), s(b"-B2"), s(b"foo"), s(b"f")]
        ),
        case!(
            "group_separator_on_gap",
            &[(b"f", Text(b"foo\nx\ny\nfoo\n"))],
            &[s(b"-A1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "group_adjacent_no_separator",
            &[(b"f", Text(b"foo\nx\nfoo\n"))],
            &[s(b"-A1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "group_separator_custom",
            &[(b"f", Text(b"foo\nx\ny\nfoo\n"))],
            &[
                s(b"--group-separator=SEP"),
                s(b"-A1"),
                s(b"-n"),
                s(b"foo"),
                s(b"f")
            ]
        ),
        case!(
            "group_separator_empty",
            &[(b"f", Text(b"foo\nx\ny\nfoo\n"))],
            &[
                s(b"--group-separator="),
                s(b"-A1"),
                s(b"-n"),
                s(b"foo"),
                s(b"f")
            ]
        ),
        case!(
            "no_group_separator",
            &[(b"f", Text(b"foo\nx\ny\nfoo\n"))],
            &[
                s(b"--no-group-separator"),
                s(b"-A1"),
                s(b"-n"),
                s(b"foo"),
                s(b"f")
            ]
        ),
        case!(
            "context_m1_caps_group",
            &[(b"f", Text(b"foo\nx\nfoo\ny\n"))],
            &[s(b"-m1"), s(b"-A1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_m2_two_groups",
            &[(b"f", Text(b"foo\nx\nfoo\ny\nfoo\nz\n"))],
            &[s(b"-m2"), s(b"-A1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_multi_file_groups",
            &[(b"f", Text(b"foo\nx\n")), (b"g", Text(b"foo\n"))],
            &[s(b"-A1"), s(b"-H"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "only_matching_ignores_context",
            &[(b"f", Text(b"a foo b\nc\n"))],
            &[s(b"-o"), s(b"-A1"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "context_long_form",
            &[(b"f", Text(b"x\nfoo\ny\n"))],
            &[s(b"--context=1"), s(b"--line-number"), s(b"foo"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Presentation: -n, -b, -H/-h precedence, -T, -Z, -z, --label, long forms.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn presentation_flags_match_gnu() {
    let cases: &[Case] = &[
        case!(
            "line_number",
            &[(b"f", Text(b"bar\nfoo\n"))],
            &[s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "line_number_no_final_eol",
            &[(b"f", Text(b"bar\nfoo"))],
            &[s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset",
            &[(b"f", Text(b"x foo\nfoo\n"))],
            &[s(b"-b"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset_o",
            &[(b"f", Text(b"x foo\nfoo\n"))],
            &[s(b"-b"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset_n",
            &[(b"f", Text(b"x foo\n"))],
            &[s(b"-n"), s(b"-b"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset_Hn",
            &[(b"f", Text(b"x foo\n"))],
            &[s(b"-H"), s(b"-n"), s(b"-b"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset_z",
            &[(b"f", Text(b"foo\0bar foo\0"))],
            &[s(b"-b"), s(b"-z"), s(b"foo"), s(b"f")]
        ),
        case!(
            "byte_offset_o_z",
            &[(b"f", Text(b"a foo b\0"))],
            &[s(b"-b"), s(b"-o"), s(b"-z"), s(b"foo"), s(b"f")]
        ),
        case!(
            "H_then_h_last_wins",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-H"), s(b"-h"), s(b"foo"), s(b"f")]
        ),
        case!(
            "h_then_H_last_wins",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-h"), s(b"-H"), s(b"foo"), s(b"f")]
        ),
        case!(
            "H_single_file",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-H"), s(b"foo"), s(b"f")]
        ),
        case!(
            "h_single_file",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-h"), s(b"foo"), s(b"f")]
        ),
        case!(
            "two_files_default_H",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "long_no_filename",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"--no-filename"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "long_with_filename",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--with-filename"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_n",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-T"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_needs_prefix",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-T"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_b",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-T"), s(b"-b"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_Hn",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-T"), s(b"-H"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_o",
            &[(b"f", Text(b"x foo\n"))],
            &[s(b"-T"), s(b"-n"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "initial_tab_Z",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-T"), s(b"-Z"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "null_filename_Z",
            &[(b"f", Text(b"foo\nbar foo\n"))],
            &[s(b"-Z"), s(b"-H"), s(b"foo"), s(b"f")]
        ),
        case!(
            "null_filename_multi",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"-Z"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "null_long_form",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"--null"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "null_data_z",
            &[(b"f", Text(b"foo\0bar foo\0"))],
            &[s(b"-z"), s(b"foo"), s(b"f")]
        ),
        case!(
            "null_data_z_n",
            &[(b"f", Text(b"foo\0bar foo\0"))],
            &[s(b"-z"), s(b"-n"), s(b"foo"), s(b"f")]
        ),
        case!(
            "null_data_z_Z",
            &[(b"f", Text(b"foo\0bar foo\0"))],
            &[s(b"-z"), s(b"-Z"), s(b"-H"), s(b"foo"), s(b"f")]
        ),
        case!(
            "null_data_long",
            &[(b"f", Text(b"foo\0bar foo\0"))],
            &[s(b"--null-data"), s(b"-H"), s(b"foo"), s(b"f")]
        ),
        case!("label_stdin", &[], &[s(b"--label=LBL"), s(b"-H"), s(b"foo")], stdin b"foo\n"),
        case!("default_stdin_label", &[], &[s(b"-H"), s(b"foo")], stdin b"foo\nbar foo\n"),
        case!("label_L_stdin", &[], &[s(b"-L"), s(b"--label=LBL"), s(b"foo")], stdin b"foo\nbar\n"),
        case!(
            "line_buffered",
            &[(b"f", Text(b"foo\nbar\n"))],
            &[s(b"--line-buffered"), s(b"foo"), s(b"f")]
        ),
        case!(
            "cr_is_line_content",
            &[(b"f", Text(b"foo\r\nbar\r\n"))],
            &[s(b"-F"), s(b"foo"), s(b"f")]
        ),
        case!(
            "cr_is_line_content_o",
            &[(b"f", Text(b"foo\r\n"))],
            &[s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "trailing_no_newline",
            &[(b"f", Text(b"bar\nfoo"))],
            &[s(b"foo"), s(b"f")]
        ),
        case!(
            "trailing_no_newline_o",
            &[(b"f", Text(b"bar foo"))],
            &[s(b"-o"), s(b"foo"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Binary data: NUL detection, -a/-I/--binary-files, -z suppression.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn binary_handling_matches_gnu() {
    static LATE_NUL: LazyLock<Vec<u8>> = LazyLock::new(|| {
        let mut bytes = b"foo\n".to_vec();
        bytes.resize(16 * 1024, b'x');
        bytes.extend_from_slice(b"\0tail\n");
        bytes
    });
    let late_nul_files: Vec<(&'static [u8], FileSpec)> =
        vec![(b"late".as_slice(), FileSpec::Text(&LATE_NUL))];
    let late_nul: &[(&'static [u8], FileSpec)] = &late_nul_files;
    let cases: &[Case] = &[
        case!(
            "binary_file_matches",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_late_nul_same_read",
            late_nul,
            &[s(b"foo"), s(b"late")]
        ),
        case!(
            "binary_file_matches_Hn",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-Hn"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_continues_other_files",
            &[(b"f", Text(b"foo\0bar\n")), (b"g", Text(b"foo\n"))],
            &[s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "binary_q",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-q"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_c_counts",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-c"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_l_lists",
            &[(b"f", Text(b"foo\0bar\n")), (b"g", Text(b"nope\n"))],
            &[s(b"-l"), s(b"foo"), s(b"f"), s(b"g")]
        ),
        case!(
            "binary_l_no_match",
            &[(b"f", Text(b"bar\0\n"))],
            &[s(b"-l"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_L_finite_max_count_reports_match",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-L"), s(b"-m3"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_I",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-I"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_without_match_long",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"--binary-files=without-match"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_a_prints_raw",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-a"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_text_long",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"--binary-files=text"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_a_o",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-a"), s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!(
            "binary_o_default",
            &[(b"f", Text(b"foo\0bar\n"))],
            &[s(b"-o"), s(b"foo"), s(b"f")]
        ),
        case!("binary_stdin_message", &[], &[s(b"foo")], stdin b"foo\0bar\n"),
        case!(
            "invalid_utf8_is_text_in_c_locale",
            &[(b"f", Text(b"foo\xff\xfe\n"))],
            &[s(b"foo"), s(b"f")]
        ),
        case!(
            "nul_pattern_matches_binary_with_a",
            &[(b"pat", Text(b"a\0b\n")), (b"f", Text(b"x a\0b y\nnope\n"))],
            &[s(b"-a"), s(b"-F"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "nul_pattern_no_trailing_nl",
            &[(b"pat", Text(b"a\0b")), (b"f", Text(b"x a\0b y\n"))],
            &[s(b"-a"), s(b"-F"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "nul_pattern_binary_zapped",
            &[(b"pat", Text(b"a\0b\n")), (b"f", Text(b"x a\0b y\n"))],
            &[s(b"-F"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "nul_pattern_text_miss",
            &[(b"pat", Text(b"a\0b\n")), (b"f", Text(b"ab\n"))],
            &[s(b"-a"), s(b"-F"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "nul_pattern_bre_miss",
            &[(b"pat", Text(b"a\0b\n")), (b"f", Text(b"ab\n"))],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "z_disables_binary_detection",
            &[(b"f", Text(b"foo\0bar\0"))],
            &[s(b"-z"), s(b"foo"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Pattern sources: -e, -f, operand pattern, --, empty and NUL patterns.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn pattern_sources_match_gnu() {
    let cases: &[Case] = &[
        case!(
            "e_patterns_or",
            &[(b"f", Text(b"foo\nbar\nbaz\n"))],
            &[s(b"-e"), s(b"foo"), s(b"-e"), s(b"bar"), s(b"f")]
        ),
        case!(
            "e_demotes_operand_pattern",
            &[(b"f", Text(b"foo\nbar\nbaz\n"))],
            &[s(b"foo"), s(b"-e"), s(b"bar"), s(b"f")]
        ),
        case!("e_only_reads_stdin", &[], &[s(b"-e"), s(b"foo")], stdin b"foo\nbar\n"),
        case!(
            "f_multiple_patterns",
            &[
                (b"pat", Text(b"foo\nbar\n")),
                (b"f", Text(b"foo\nbar\nbaz\n"))
            ],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "f_plus_e_or",
            &[(b"pat", Text(b"bar\n")), (b"f", Text(b"foo\nbar\nbaz\n"))],
            &[s(b"-e"), s(b"foo"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "f_last_line_no_nl",
            &[(b"pat", Text(b"foo")), (b"f", Text(b"foo\nbar\n"))],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "f_keeps_cr",
            &[
                (b"pat", Text(b"foo\r\nbar\r\n")),
                (b"f", Text(b"foo\nbar\n"))
            ],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "f_missing_file",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-f"), s(b"/nope_pat"), s(b"f")]
        ),
        case!(
            "f_missing_aborts_all",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-e"), s(b"foo"), s(b"-f"), s(b"/nope_pat"), s(b"f")]
        ),
        case!(
            "dash_pattern_operand",
            &[(b"f", Text(b"a-b\nc\n"))],
            &[s(b"-F"), s(b"-"), s(b"f")]
        ),
        case!(
            "double_dash_terminator",
            &[(b"f", Text(b"x\n-n\ny\n"))],
            &[s(b"--"), s(b"-n"), s(b"f")]
        ),
        case!(
            "e_empty_matches_all",
            &[(b"f", Text(b"ab\n\ncd\n"))],
            &[s(b"-e"), s(b""), s(b"f")]
        ),
        case!(
            "regexp_long_form",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--regexp=foo"), s(b"--with-filename"), s(b"f")]
        ),
        case!(
            "f_byte_pattern",
            &[(b"pat", Text(b"\xff\n")), (b"f", Text(b"a\xffb\nnope\n"))],
            &[s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "f_byte_pattern_fixed",
            &[(b"pat", Text(b"\xff\n")), (b"f", Text(b"a\xffb\nnope\n"))],
            &[s(b"-F"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Traversal: -r/-R, directories, symlinks, glob filters and their order.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn traversal_matches_gnu() {
    let cases: &[Case] = &[
        case!(
            "r_two_dir_operands",
            &[
                (b"dir1/x.txt", Text(b"foo\n")),
                (b"dir2/x.txt", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"-H"), s(b"foo"), s(b"dir1"), s(b"dir2")]
        ),
        case!(
            "r_dot_operand",
            &[(b"a.txt", Text(b"foo\n")), (b"sub/b.txt", Text(b"foo\n"))],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "r_no_operands_walks_cwd",
            &[(b"a.txt", Text(b"foo\n")), (b"sub/b.txt", Text(b"foo\n"))],
            &[s(b"-r"), s(b"foo")]
        ),
        case!(
            "r_file_operand_no_prefix",
            &[(b"x.txt", Text(b"foo\n"))],
            &[s(b"-r"), s(b"foo"), s(b"x.txt")]
        ),
        case!(
            "r_mixed_operands",
            &[(b"d/sub", Text(b"foo\n")), (b"x.txt", Text(b"foo\n"))],
            &[s(b"-r"), s(b"foo"), s(b"d"), s(b"x.txt")]
        ),
        case!(
            "r_h_suppresses_names",
            &[(b"a", Text(b"foo\n"))],
            &[s(b"-r"), s(b"-h"), s(b"foo"), s(b".")]
        ),
        case!(
            "directories_recurse_long",
            &[(b"d/sub", Text(b"foo\n"))],
            &[s(b"--directories=recurse"), s(b"foo"), s(b"d")]
        ),
        case!(
            "directory_operand_error",
            &[(b"d/sub", Text(b"foo\n")), (b"f", Text(b"foo\n"))],
            &[s(b"foo"), s(b"d"), s(b"f")]
        ),
        case!(
            "directories_skip",
            &[(b"d/sub", Text(b"foo\n"))],
            &[s(b"--directories=skip"), s(b"foo"), s(b"d")]
        ),
        case!(
            "R_follows_dir_symlinks",
            &[
                (b"top/real/a.txt", Text(b"foo\n")),
                (b"top/link", Symlink(b"real"))
            ],
            &[s(b"-R"), s(b"foo"), s(b"top")]
        ),
        case!(
            "r_skips_dir_symlinks",
            &[
                (b"top/real/a.txt", Text(b"foo\n")),
                (b"top/link", Symlink(b"real"))
            ],
            &[s(b"-r"), s(b"foo"), s(b"top")]
        ),
        case!(
            "r_skips_file_symlinks",
            &[(b"real", Text(b"foo\n")), (b"ln", Symlink(b"real"))],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "R_follows_file_symlinks",
            &[(b"real", Text(b"foo\n")), (b"ln", Symlink(b"real"))],
            &[s(b"-R"), s(b"foo"), s(b".")]
        ),
        case!(
            "R_default_reads_devices",
            &[(b"null", Symlink(b"/dev/null"))],
            &[s(b"-R"), s(b"-L"), s(b"foo"), s(b".")]
        ),
        case!(
            "devices_read_recursive",
            &[(b"null", Symlink(b"/dev/null"))],
            &[s(b"-R"), s(b"-L"), s(b"-D"), s(b"read"), s(b"foo"), s(b".")]
        ),
        case!(
            "devices_skip_recursive",
            &[(b"null", Symlink(b"/dev/null"))],
            &[s(b"-R"), s(b"-L"), s(b"-D"), s(b"skip"), s(b"foo"), s(b".")]
        ),
        case!(
            "symlink_file_operand",
            &[(b"real.txt", Text(b"foo\n")), (b"ln", Symlink(b"real.txt"))],
            &[s(b"foo"), s(b"ln")]
        ),
        case!(
            "symlink_dir_operand_r",
            &[(b"real/a", Text(b"foo\n")), (b"lnk", Symlink(b"real"))],
            &[s(b"-r"), s(b"foo"), s(b"lnk")]
        ),
        case!(
            "symlink_loop_R",
            &[(b"a", Text(b"foo\n")), (b"loop", Symlink(b"."))],
            &[s(b"-R"), s(b"foo"), s(b".")]
        ),
        case!(
            "symlink_loop_R_no_match",
            &[(b"loop", Symlink(b"."))],
            &[s(b"-R"), s(b"foo"), s(b".")]
        ),
        case!(
            "symlink_loop_r_silent",
            &[(b"a", Text(b"foo\n")), (b"loop", Symlink(b"."))],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "dangling_symlink_R",
            &[(b"dang", Symlink(b"missing"))],
            &[s(b"-R"), s(b"foo"), s(b".")]
        ),
        case!(
            "dangling_symlink_r",
            &[(b"dang", Symlink(b"missing"))],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "r_searches_dotfiles_and_ignored",
            &[
                (b".gitignore", Text(b"*\n")),
                (b".hidden", Text(b"foo\n")),
                (b"sub/.deep", Text(b"foo\n")),
                (b"keep.txt", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "include_filters",
            &[
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n")),
                (b"sub/c.txt", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"--include=*.txt"), s(b"foo"), s(b".")]
        ),
        case!(
            "include_or_accumulates",
            &[
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n")),
                (b"c.rs", Text(b"foo\n"))
            ],
            &[
                s(b"-r"),
                s(b"--include=*.txt"),
                s(b"--include=*.md"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_filters",
            &[(b"a.txt", Text(b"foo\n")), (b"b.md", Text(b"foo\n"))],
            &[s(b"-r"), s(b"--exclude=*.txt"), s(b"foo"), s(b".")]
        ),
        case!(
            "exclude_or_accumulates",
            &[
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n")),
                (b"c.rs", Text(b"foo\n"))
            ],
            &[
                s(b"-r"),
                s(b"--exclude=*.txt"),
                s(b"--exclude=*.md"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "include_then_exclude_order1",
            &[(b"a.txt", Text(b"foo\n")), (b"b.md", Text(b"foo\n"))],
            &[
                s(b"-r"),
                s(b"--include=*.txt"),
                s(b"--exclude=*.txt"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_then_include_order2",
            &[(b"a.txt", Text(b"foo\n")), (b"b.md", Text(b"foo\n"))],
            &[
                s(b"-r"),
                s(b"--exclude=*.txt"),
                s(b"--include=*.txt"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "include_exclude_distinct",
            &[(b"a.txt", Text(b"foo\n")), (b"b.md", Text(b"foo\n"))],
            &[
                s(b"-r"),
                s(b"--include=*.md"),
                s(b"--exclude=*.txt"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "include_star_exclude_md",
            &[(b"a.txt", Text(b"foo\n")), (b"b.md", Text(b"foo\n"))],
            &[
                s(b"-r"),
                s(b"--include=*"),
                s(b"--exclude=*.md"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_from_file",
            &[
                (b"xf", Text(b"*.txt\n")),
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"--exclude-from=xf"), s(b"foo"), s(b".")]
        ),
        case!(
            "exclude_from_multiple",
            &[
                (b"xf", Text(b"*.txt\n*.md\n")),
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n")),
                (b"c.rs", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"--exclude-from=xf"), s(b"foo"), s(b".")]
        ),
        case!(
            "include_plus_exclude_from",
            &[
                (b"xf", Text(b"*.txt\n")),
                (b"a.txt", Text(b"foo\n")),
                (b"b.md", Text(b"foo\n"))
            ],
            &[
                s(b"-r"),
                s(b"--include=*.txt"),
                s(b"--exclude-from=xf"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_dir",
            &[
                (b"skip/a.txt", Text(b"foo\n")),
                (b"keep/b.txt", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"--exclude-dir=skip"), s(b"foo"), s(b".")]
        ),
        case!(
            "exclude_dir_multiple",
            &[
                (b"a/x", Text(b"foo\n")),
                (b"b/x", Text(b"foo\n")),
                (b"c/x", Text(b"foo\n"))
            ],
            &[
                s(b"-r"),
                s(b"--exclude-dir=a"),
                s(b"--exclude-dir=b"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_dir_operand",
            &[(b"skip/x", Text(b"foo\n")), (b"keep/x", Text(b"foo\n"))],
            &[
                s(b"-r"),
                s(b"--exclude-dir=skip"),
                s(b"foo"),
                s(b"skip"),
                s(b"keep")
            ]
        ),
        case!(
            "exclude_dir_long_forms",
            &[(b"sub/a", Text(b"foo\n")), (b"b", Text(b"foo\n"))],
            &[
                s(b"--directories=recurse"),
                s(b"--exclude-dir=sub"),
                s(b"foo"),
                s(b".")
            ]
        ),
        case!(
            "exclude_filters_command_line",
            &[(b"a.txt", Text(b"foo\n")), (b"b.txt", Text(b"foo\n"))],
            &[s(b"--exclude=a.txt"), s(b"foo"), s(b"a.txt"), s(b"b.txt")]
        ),
        case!(
            "include_filters_command_line",
            &[(b"a.txt", Text(b"foo\n")), (b"b.txt", Text(b"foo\n"))],
            &[s(b"--include=*.md"), s(b"foo"), s(b"a.txt"), s(b"b.txt")]
        ),
        case!(
            "non_utf8_name_operand",
            &[(b"caf\xe9.txt", Text(b"foo\n"))],
            &[s(b"foo"), s(b"caf\xe9.txt")]
        ),
        case!(
            "non_utf8_name_recursive",
            &[
                (b"caf\xe9.txt", Text(b"foo\n")),
                (b"ok.txt", Text(b"foo\n"))
            ],
            &[s(b"-r"), s(b"foo"), s(b".")]
        ),
        case!(
            "non_utf8_directory_trailing_slash",
            &[(b"caf\xe9/a", Text(b"foo\n"))],
            &[s(b"-r"), s(b"foo"), s(b"caf\xe9/")]
        ),
        case!("r_empty_tree", &[], &[s(b"-r"), s(b"foo"), s(b".")]),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Errors: exact diagnostics, output suppression, and exit status.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn error_reporting_matches_gnu() {
    let cases: &[Case] = &[
        case!("missing_operand", &[], &[s(b"foo"), s(b"/nope_missing")]),
        case!(
            "missing_after_hit",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"foo"), s(b"f"), s(b"/nope_missing")]
        ),
        case!(
            "missing_pattern_file",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-f"), s(b"/nope_pat"), s(b"f")]
        ),
        case!(
            "no_messages_suppresses_errors",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-s"), s(b"foo"), s(b"/missing_xyz"), s(b"f")]
        ),
        case!(
            "no_messages_only_missing",
            &[],
            &[s(b"-s"), s(b"foo"), s(b"/missing_xyz")]
        ),
        case!(
            "quiet_still_reports_errors",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-q"), s(b"foo"), s(b"/missing_xyz"), s(b"f")]
        ),
        case!(
            "invalid_ere",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-E"), s(b"("), s(b"f")]
        ),
        case!(
            "invalid_ere_pattern_file_line",
            &[(b"pat", Text(b"foo\n(\n")), (b"f", Text(b"foo\n"))],
            &[s(b"-E"), s(b"-f"), s(b"pat"), s(b"f")]
        ),
        case!(
            "invalid_pcre",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-P"), s(b"(?<"), s(b"f")]
        ),
        case!(
            "invalid_bre_backref",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"\\2"), s(b"f")]
        ),
        case!(
            "invalid_bre_unmatched",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"a\\("), s(b"f")]
        ),
        case!(
            "invalid_regex_aborts_all_output",
            &[(b"f", Text(b"foo\n")), (b"g", Text(b"foo\n"))],
            &[s(b"-E"), s(b"("), s(b"f"), s(b"g")]
        ),
        case!(
            "unknown_long_option",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--bogus-option"), s(b"foo"), s(b"f")]
        ),
        case!(
            "invalid_matcher_name",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-X"), s(b"nope"), s(b"foo"), s(b"f")]
        ),
        case!(
            "obsolete_u_is_usage_error",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"-u"), s(b"foo"), s(b"f")]
        ),
        case!("no_args_usage_error", &[(b"f", Text(b"foo\n"))], &[]),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Stdin operands: default stdin, "-", repetition, labels, -m/-q interplay.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn stdin_operands_match_gnu() {
    let cases: &[Case] = &[
        case!("stdin_default", &[], &[s(b"foo")], stdin b"foo\nbar\n"),
        case!("stdin_dash_operand", &[(b"f", Text(b"foo\n"))], &[s(b"-H"), s(b"foo"), s(b"-"), s(b"f")], stdin b"foo\nbar\n"),
        case!("stdin_repeated_operands", &[(b"f", Text(b"foo\n"))], &[s(b"-H"), s(b"foo"), s(b"-"), s(b"f"), s(b"-")], stdin b"foo\nbar\n"),
        case!("stdin_after_files", &[(b"f", Text(b"foo\n"))], &[s(b"-H"), s(b"foo"), s(b"f"), s(b"-"), s(b"-")], stdin b"foo\nbar\n"),
        case!("stdin_two_dashes", &[], &[s(b"-H"), s(b"foo"), s(b"-"), s(b"-")], stdin b"foo\nbar\n"),
        case!("stdin_label", &[], &[s(b"--label=LBL"), s(b"-H"), s(b"foo")], stdin b"foo\n"),
        case!("stdin_binary_message", &[], &[s(b"foo")], stdin b"foo\0bar\n"),
        case!("stdin_m1_stops", &[], &[s(b"-m1"), s(b"foo")], stdin b"bar\nfoo\nfoo\n"),
        case!("stdin_q", &[], &[s(b"-q"), s(b"foo")], stdin b"bar\nfoo\nfoo\n"),
        case!("stdin_z", &[], &[s(b"-z"), s(b"foo")], stdin b"foo\0bar\0"),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// POSIXLY_CORRECT: option parsing stops at the first operand.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn posixly_correct_matches_gnu() {
    let env: &[(&str, Option<&str>)] = &[("POSIXLY_CORRECT", Some("1"))];
    let cases: &[Case] = &[
        case!("posixly_flag_after_operand_is_file", &[(b"f", Text(b"foo\n"))], &[s(b"foo"), s(b"-n"), s(b"f")], env env),
        case!("posixly_flags_before_operand_ok", &[(b"f", Text(b"foo\n"))], &[s(b"-n"), s(b"foo"), s(b"f")], env env),
        case!("posixly_e_still_consumes", &[(b"f", Text(b"foo\n"))], &[s(b"-e"), s(b"foo"), s(b"-n"), s(b"f")], env env),
    ];
    assert_cases(cases).await;
}

// ---------------------------------------------------------------------------
// Colors: --color=always with default and custom GREP_COLORS, and every
// colorable output element; --color=auto/never over a pipe.
// ---------------------------------------------------------------------------
#[tokio::test]
async fn colors_match_gnu() {
    let default: &[(&str, Option<&str>)] = &[("TERM", Some("xterm"))];
    let custom: &[(&str, Option<&str>)] = &[
        ("TERM", Some("xterm")),
        (
            "GREP_COLORS",
            Some("ms=1;33:mc=1;33:fn=4;32:ln=1;36:bn=36:se=36"),
        ),
    ];
    let sl_cx: &[(&str, Option<&str>)] = &[
        ("TERM", Some("xterm")),
        ("GREP_COLORS", Some("sl=4;33:cx=4;36")),
    ];
    let mc_custom: &[(&str, Option<&str>)] = &[
        ("TERM", Some("xterm")),
        ("GREP_COLORS", Some("ms=01;31:mc=1;34:fn=35:ln=32:se=36")),
    ];
    let cases: &[Case] = &[
        case!("color_selected_line", &[(b"f", Text(b"foo\n"))], &[s(b"--color=always"), s(b"-Hn"), s(b"foo"), s(b"f")], env default),
        case!("color_custom_colors", &[(b"f", Text(b"foo\n"))], &[s(b"--color=always"), s(b"-Hn"), s(b"foo"), s(b"f")], env custom),
        case!(
            "color_ignores_dumb_term",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--color=always"), s(b"foo"), s(b"f")],
            env & [("TERM", Some("dumb"))]
        ),
        case!(
            "color_ignores_unset_term",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--color=always"), s(b"foo"), s(b"f")],
            env & [("TERM", None)]
        ),
        case!("color_context_lines", &[(b"f", Text(b"x\nfoo\ny\n"))], &[s(b"--color=always"), s(b"-Hn"), s(b"-C1"), s(b"foo"), s(b"f")], env default),
        case!("color_group_separator", &[(b"f", Text(b"foo\nx\ny\nfoo\n"))], &[s(b"--color=always"), s(b"-Hn"), s(b"-A1"), s(b"foo"), s(b"f")], env default),
        case!("color_only_matching", &[(b"f", Text(b"x foo\n"))], &[s(b"--color=always"), s(b"-o"), s(b"-Hn"), s(b"foo"), s(b"f")], env default),
        case!("color_byte_offset", &[(b"f", Text(b"x foo\n"))], &[s(b"--color=always"), s(b"-b"), s(b"foo"), s(b"f")], env default),
        case!("color_inverted_line", &[(b"f", Text(b"foo\nbar\n"))], &[s(b"--color=always"), s(b"-v"), s(b"-Hn"), s(b"foo"), s(b"f")], env default),
        case!("color_sl_cx_custom", &[(b"f", Text(b"foo\nbar\n"))], &[s(b"--color=always"), s(b"-v"), s(b"-Hn"), s(b"foo"), s(b"f")], env sl_cx),
        case!("color_count", &[(b"f", Text(b"foo\nfoo\n"))], &[s(b"--color=always"), s(b"-c"), s(b"-H"), s(b"foo"), s(b"f")], env default),
        case!("color_files_with_matches", &[(b"f", Text(b"foo\n")), (b"g", Text(b"bar\n"))], &[s(b"--color=always"), s(b"-l"), s(b"foo"), s(b"f"), s(b"g")], env default),
        case!("color_label_stdin", &[], &[s(b"--color=always"), s(b"-H"), s(b"--label=LBL"), s(b"foo")], stdin b"foo\n", env default),
        case!("color_context_match_uncapped", &[(b"f", Text(b"foo\nbar foo\n"))], &[s(b"--color=always"), s(b"-A1"), s(b"-Hn"), s(b"foo"), s(b"f")], env default),
        case!("color_context_line_raw_under_m", &[(b"f", Text(b"foo\nbar foo\n"))], &[s(b"--color=always"), s(b"-m1"), s(b"-A1"), s(b"-Hn"), s(b"foo"), s(b"f")], env mc_custom),
        case!(
            "color_auto_pipe_plain",
            &[(b"f", Text(b"foo\n"))],
            &[s(b"--color=auto"), s(b"-Hn"), s(b"foo"), s(b"f")],
            env & [("TERM", Some("xterm"))]
        ),
        case!("color_never_plain", &[(b"f", Text(b"foo\n"))], &[s(b"--color=never"), s(b"-Hn"), s(b"foo"), s(b"f")], env default),
        case!("color_invalid_setting_help", &[], &[s(b"--color=banana")]),
    ];
    assert_cases(cases).await;
}
