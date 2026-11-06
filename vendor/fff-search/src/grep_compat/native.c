/* Native GNU grep-compatible matching bridge.
 *
 * Backend A: glibc's GNU regex API (re_compile_pattern / re_search / re_match)
 * with RE_SYNTAX_GREP / RE_SYNTAX_EGREP / RE_ICASE, plus byte-literal matching
 * for -F with GNU's toupper-based case folding.  Semantics mirror GNU grep
 * 3.12's dfasearch.c (EGexecute exact path), kwsearch.c (Fexecute), and
 * searchutils.c (wordchar_next/wordchar_prev/mb_goback), minus the DFA/KWset
 * prefilters: the -w/-x acceptance checks are done in the search loop itself.
 *
 * The API is opaque-handle based; swapping the regex backend (e.g. gnulib
 * regex with large offsets) must not change any entry point signature.
 *
 * Threading: one matcher is used on one blocking thread at a time.  Locale is
 * per-matcher (newlocale), entered/restored around every call via uselocale;
 * setlocale is never called.  The only process-global state touched is
 * re_syntax_options, protected by a mutex during compilation.
 */
#define _GNU_SOURCE

#include <ctype.h>
#include <langinfo.h>
#include <limits.h>
#include <regex.h>
#include <stddef.h>
#include <locale.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <wchar.h>
#include <wctype.h>

/* ------------------------------------------------------------------ */
/* Locale handle                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    locale_t locale; /* owning handle from newlocale */
} fff_locale;

fff_locale *fff_locale_new(const char *name, size_t name_len) {
    char *copy = malloc(name_len + 1);
    if (!copy) return NULL;
    memcpy(copy, name, name_len);
    copy[name_len] = '\0';
    /* An empty name resolves all categories from the environment, exactly
       as glibc documents; an explicit "C" stays deterministic. */
    locale_t loc = newlocale(LC_ALL_MASK, copy, (locale_t)0);
    if (!loc) loc = newlocale(LC_ALL_MASK, "C", (locale_t)0);
    free(copy);
    if (!loc) return NULL;
    fff_locale *l = malloc(sizeof *l);
    if (!l) { freelocale(loc); return NULL; }
    l->locale = loc;
    return l;
}

void fff_locale_free(fff_locale *l) {
    if (l) { freelocale(l->locale); free(l); }
}

locale_t fff_locale_get(const fff_locale *l) { return l->locale; }

/* mb_cur_max / is_utf8 of the locale (caller must hold the locale). */
void fff_locale_info(const fff_locale *l, int *mb_cur_max, int *is_utf8) {
    locale_t prev = uselocale(l->locale);
    *mb_cur_max = MB_CUR_MAX;
    *is_utf8 = 0;
    if (*mb_cur_max > 1) {
        const char *cs = nl_langinfo(CODESET);
        if (cs && (strcasecmp(cs, "UTF-8") == 0 || strcasecmp(cs, "UTF8") == 0))
            *is_utf8 = 1;
    }
    uselocale(prev);
}

/* True if BYTES are valid text in the locale (always true for single-byte
   locales).  BYTES is the record content, without its terminator. */
int fff_valid_text(const fff_locale *l, const unsigned char *s, size_t len) {
    locale_t prev = uselocale(l->locale);
    int mb = MB_CUR_MAX;
    int ok = 1;
    if (mb > 1) {
        mbstate_t mbs;
        memset(&mbs, 0, sizeof mbs);
        for (size_t i = 0; i < len; ) {
            wchar_t wc = 0;
            size_t n = mbrtowc(&wc, (const char *)s + i, len - i, &mbs);
            if (n == (size_t)-1 || n == (size_t)-2) { ok = 0; break; }
            i += n == 0 ? 1 : n;
        }
    }
    uselocale(prev);
    return ok;
}

/* ------------------------------------------------------------------ */
/* Word-character tables (locale-dependent, built per matcher)         */
/* ------------------------------------------------------------------ */

typedef struct {
    unsigned char sb_wordchar[256]; /* byte is a single-byte word char */
    signed char sbclen[256];        /* 1 single-byte char, -2 multibyte lead,
                                       -1 encoding-error byte */
} fff_wc;

static int fff_wordchar_wc(wchar_t wc, locale_t loc) {
    return wc == L'_' || iswalnum_l(wc, loc);
}

static void fff_wc_init(fff_wc *w, locale_t loc) {
    for (int b = 0; b < 256; b++) {
        char cb = (char)b;
        wchar_t wc = 0;
        mbstate_t mbs;
        memset(&mbs, 0, sizeof mbs);
        size_t n = mbrtowc(&wc, &cb, 1, &mbs);
        if (n == 1 || n == 0) {
            w->sbclen[b] = 1;
            w->sb_wordchar[b] = n == 1 && fff_wordchar_wc(wc, loc) ? 1 : 0;
        } else if (n == (size_t)-2) {
            w->sbclen[b] = -2;
            w->sb_wordchar[b] = 0;
        } else {
            w->sbclen[b] = -1;
            w->sb_wordchar[b] = 0;
        }
    }
}

/* Bytes of word-characters at BUF (which ends at END); one char if !COUNTALL,
   as many as possible otherwise.  Mirrors GNU searchutils.c wordchars_count. */
static size_t fff_wordchars_count(const fff_wc *w, const unsigned char *buf,
                                  const unsigned char *end, int countall,
                                  locale_t loc) {
    mbstate_t mbs;
    memset(&mbs, 0, sizeof mbs);
    const unsigned char *p = buf;
    while (p < end) {
        unsigned char b = *p;
        if (w->sb_wordchar[b]) {
            p++;
        } else if (w->sbclen[b] != -2) {
            break;
        } else {
            wchar_t wc = 0;
            size_t nb = mbrtowc(&wc, (const char *)p, end - p, &mbs);
            if (nb == 0) nb = 1;
            if (nb == (size_t)-1 || nb == (size_t)-2
                || !fff_wordchar_wc(wc, loc))
                break;
            p += nb;
        }
        if (!countall) break;
    }
    return p - buf;
}

/* If BUF starts with a word constituent, return its byte length, else 0. */
static size_t fff_wordchar_next(const fff_wc *w, const unsigned char *buf,
                                const unsigned char *end, locale_t loc) {
    return fff_wordchars_count(w, buf, end, 0, loc);
}

/* Number of bytes needed to go back from CUR to the start of the multibyte
   character containing the byte at CUR-1; advances *MB_START past that
   character.  Mirrors GNU searchutils.c mb_goback. */
static size_t fff_mb_goback(const unsigned char **mb_start, size_t *mbclen,
                            const unsigned char *cur, const unsigned char *end,
                            int using_utf8) {
    const unsigned char *p = *mb_start;
    const unsigned char *p0 = p;
    if (cur <= p) return cur - p;
    if (using_utf8) {
        p = cur;
        if ((*cur & 0xc0) == 0x80)
            for (int i = 1; i <= 3; i++)
                if ((cur[-i] & 0xc0) != 0x80) {
                    int long_enough = (~cur[-i] & 0xff) >> (7 - i) == 0;
                    if (long_enough) {
                        mbstate_t mbs;
                        memset(&mbs, 0, sizeof mbs);
                        wchar_t wc;
                        ptrdiff_t clen = mbrtowc(&wc, (const char *)cur - i,
                                                 end - (cur - i), &mbs);
                        if (clen >= 0) { p0 = cur - i; p = p0 + clen; }
                    }
                    break;
                }
    } else {
        mbstate_t mbs;
        memset(&mbs, 0, sizeof mbs);
        ptrdiff_t clen;
        do {
            wchar_t wc;
            clen = mbrtowc(&wc, (const char *)p, end - p, &mbs);
            if (clen < 0) {
                /* Invalid or truncated: treat as a single-byte character. */
                clen = 1;
                memset(&mbs, 0, sizeof mbs);
            }
            p0 = p;
            p += clen;
        } while (p < cur);
        if (mbclen) *mbclen = clen;
    }
    *mb_start = p;
    return p == cur ? 0 : cur - p0;
}

/* In the buffer BUF, nonzero if the character whose encoding contains the
   byte before CUR is a word constituent.  Mirrors GNU wordchar_prev. */
static size_t fff_wordchar_prev(const fff_wc *w, const unsigned char *buf,
                                const unsigned char *cur,
                                const unsigned char *end, locale_t loc,
                                int mb_cur_max, int using_utf8) {
    if (buf == cur) return 0;
    unsigned char b = cur[-1];
    if (mb_cur_max == 1 || (using_utf8 && (b >> 7) == 0))
        return w->sb_wordchar[b];
    const unsigned char *p = buf;
    cur -= fff_mb_goback(&p, NULL, cur, end, using_utf8);
    return fff_wordchar_next(w, cur, end, loc);
}

/* ------------------------------------------------------------------ */
/* Matcher handle                                                      */
/* ------------------------------------------------------------------ */

enum { FFF_REGEX = 1, FFF_FIXED = 2 };

/* Result codes for fff_matcher_find / fff_matcher_is_match. */
enum {
    FFF_NOMATCH = 0,
    FFF_MATCH = 1,
    FFF_ERR_TOO_LARGE = -1, /* record exceeds the regex offset limit */
    FFF_ERR_INTERNAL = -2
};

typedef struct fff_matcher {
    int kind;
    locale_t locale;    /* borrowed from the owning fff_locale */
    int mb_cur_max;
    int using_utf8;
    int word, whole;    /* -w / -x */
    int icase;
    int eol_nl;         /* newline_anchor: terminator is '\n' (0 with -z) */
    fff_wc wc;
} fff_matcher;

typedef struct {
    struct re_pattern_buffer pb;
} fff_re_pat;

typedef struct {
    fff_matcher m;
    fff_re_pat *pats;
    int pcount;
    struct re_registers regs; /* reused across calls */
} fff_regex;

typedef struct {
    fff_matcher m;
    unsigned char **pats; /* literal bytes, sorted longest-first */
    size_t *lens;
    int pcount;
    unsigned char trans[256]; /* -i fold table (identity without -i) */
} fff_fixed;

/* Serializes re_set_syntax / re_compile_pattern (process-global state). */
static pthread_mutex_t fff_syntax_lock = PTHREAD_MUTEX_INITIALIZER;

/* ------------------------------------------------------------------ */
/* -F helpers                                                          */
/* ------------------------------------------------------------------ */

/* Escape a fixed pattern for use as a BRE; mirrors GNU grep.c
   fgrep_to_grep_pattern.  Single-byte characters in $ * . [ \ ^ are escaped;
   multibyte characters and error bytes pass through. */
static int fff_escape_pattern(const char *pat, size_t len, const fff_wc *w,
                              char **out, size_t *outlen) {
    char *n = malloc(2 * len + 1);
    if (!n) return -1;
    char *q = n;
    mbstate_t mbs;
    memset(&mbs, 0, sizeof mbs);
    size_t i = 0;
    while (i < len) {
        unsigned char b = (unsigned char)pat[i];
        if (w->sbclen[b] == 1) {
            switch (b) {
            case '$': case '*': case '.': case '[': case '\\': case '^':
                *q++ = '\\';
                break;
            }
            *q++ = (char)b;
            i++;
        } else if (w->sbclen[b] == -2) {
            wchar_t wc;
            size_t clen = mbrtowc(&wc, pat + i, len - i, &mbs);
            if (clen == (size_t)-1 || clen == (size_t)-2 || clen == 0)
                clen = 1;
            memcpy(q, pat + i, clen);
            q += clen;
            i += clen;
        } else {
            *q++ = (char)b;
            i++;
        }
    }
    *out = n;
    *outlen = q - n;
    return 0;
}

/* True if the byte string can be matched bytewise with -i in the current
   locale; approximates GNU grep.c fgrep_icase_charlen/fgrep_icase_available
   with towupper/towlower plus the known multi-character case folds. */
static ptrdiff_t fff_icase_charlen(const unsigned char *p, size_t len,
                                   const fff_wc *w, locale_t loc,
                                   mbstate_t *mbs);
static int fff_fold_safe(const char *p, size_t len, const fff_wc *w,
                         locale_t loc) {
    mbstate_t mbs;
    memset(&mbs, 0, sizeof mbs);
    size_t i = 0;
    while (i < len) {
        ptrdiff_t n = fff_icase_charlen((const unsigned char *)p + i,
                                   len - i, w, loc, &mbs);
        if (n < 0) return 0;
        i += n == 0 ? 1 : n;
    }
    return 1;
}

/* True if the byte string contains an encoding error (grep.c
   contains_encoding_error; -F converts to -G for such patterns in
   multibyte locales). */
static int fff_has_encoding_error(const char *p, size_t len) {
    mbstate_t mbs;
    memset(&mbs, 0, sizeof mbs);
    size_t i = 0;
    while (i < len) {
        wchar_t wc = 0;
        size_t n = mbrtowc(&wc, p + i, len - i, &mbs);
        if (n == (size_t)-1 || n == (size_t)-2) return 1;
        i += n == 0 ? 1 : n;
    }
    return 0;
}

/* Number of bytes in the character at P, or -1 if -F with -i cannot handle
   it bytewise (mirror of grep.c fgrep_icase_charlen, approximated with
   towupper/towlower and the known multi-character case folds). */
static ptrdiff_t fff_icase_charlen(const unsigned char *p, size_t len,
                                   const fff_wc *w, locale_t loc,
                                   mbstate_t *mbs) {
    unsigned char b = p[0];
    if (w->sbclen[b] == 1) {
        /* Single-byte character: every case counterpart must stay
           single-byte. */
        wint_t wi = btowc(b); /* thread locale is active */
        if (wi == WEOF) return -1;
        if (towupper_l(wi, loc) != wi || towlower_l(wi, loc) != wi)
            return -1;
        return 1;
    }
    wchar_t wc = 0;
    size_t wn = mbrtowc(&wc, (const char *)p, len, mbs);
    if (wn == 0) return 1; /* NUL */
    if (wn == (size_t)-1 || wn == (size_t)-2) return -1;
    if (towupper_l((wint_t)wc, loc) != (wint_t)wc
        || towlower_l((wint_t)wc, loc) != (wint_t)wc)
        return -1;
    switch (wc) {
    case 0x00DF: case 0x0130: case 0x0149: case 0x1E9E:
    case 0xFB00: case 0xFB01: case 0xFB02: case 0xFB03:
    case 0xFB04: case 0xFB05: case 0xFB06:
        return -1;
    }
    for (size_t i = 0; i < wn; i++)
        if (towupper_l((unsigned char)p[i], loc)
            != (wint_t)(unsigned char)p[i])
            return -1;
    return (ptrdiff_t)wn;
}

/* Mirror grep.c try_fgrep_pattern: true if every pattern is a literal (safe
   for -F byte matching).  GNU switches -E/-G to -F this way when there are
   2+ patterns; this is observable with -x -w (kwset reports no doubled
   terminator, the regex engine does). */
int fff_try_fgrep(const char *const *pats, const size_t *lens, int pcount,
                  int is_ere, int icase, const fff_locale *loc) {
    locale_t l = fff_locale_get(loc);
    locale_t prev = uselocale(l);
    fff_wc wc;
    fff_wc_init(&wc, l);
    int ok = 1;
    for (int pi = 0; pi < pcount && ok; pi++) {
        const unsigned char *q = (const unsigned char *)pats[pi];
        size_t len = lens[pi];
        mbstate_t mbs;
        memset(&mbs, 0, sizeof mbs);
        while (len != 0) {
            switch (*q) {
            case '$': case '*': case '.': case '[': case '^':
                ok = 0;
                break;
            case '(': case '+': case '?': case '{': case '|':
                /* GNU: these are literal only in -G (BRE). */
                if (is_ere) ok = 0;
                break;
            case '\\':
                if (1 < len)
                    switch (q[1]) {
                    case '\n': case 'B': case 'S': case 'W': case '\'':
                    case '<': case 'b': case 's': case 'w': case '`':
                    case '>': case '1': case '2': case '3': case '4':
                    case '5': case '6': case '7': case '8': case '9':
                        ok = 0;
                        break;
                    case '(': case '+': case '?': case '{': case '|':
                    case ')':
                        /* GNU: pass '\)' to GEAcompile so it can complain;
                           in -G these are operators, not literals. */
                        if (!is_ere) ok = 0;
                        q++, len--;
                        break;
                    default:
                        q++, len--;
                        break;
                    }
                break;
            }
            if (!ok || len == 0) break;
            ptrdiff_t clen;
            if (icase)
                clen = fff_icase_charlen(q, len, &wc, l, &mbs);
            else {
                wchar_t wcw = 0;
                clen = (ptrdiff_t)mbrtowc(&wcw, (const char *)q, len, &mbs);
                if (clen == 0) clen = 1;
            }
            if (clen < 0) {
                ok = 0;
                break;
            }
            q += clen;
            len -= clen;
        }
    }
    uselocale(prev);
    return ok;
}

/* Folded first-byte-scanned literal search: leftmost occurrence of N in H
   at or after FROM, folding bytes through TRANS (identity without -i). */
static size_t fff_memmem_folded(const unsigned char *h, size_t hn, size_t from,
                                const unsigned char *n, size_t nn,
                                const unsigned char *trans) {
    if (nn == 0) return from <= hn ? from : (size_t)-1;
    unsigned char first = trans[n[0]];
    for (size_t i = from; i + nn <= hn; i++) {
        if (trans[h[i]] != first) continue;
        size_t j;
        for (j = 1; j < nn; j++)
            if (trans[h[i + j]] != trans[n[j]]) break;
        if (j == nn) return i;
    }
    return (size_t)-1;
}

static int fff_folded_eq(const unsigned char *a, const unsigned char *b,
                         size_t len, const unsigned char *trans) {
    for (size_t i = 0; i < len; i++)
        if (trans[a[i]] != trans[b[i]]) return 0;
    return 1;
}

/* Leftmost position where any pattern occurs at or after FROM; the longest
   pattern at that position wins (pats sorted longest-first). */
static int fff_fixed_find_at(fff_fixed *f, const unsigned char *s, size_t len,
                             size_t from, size_t *pos, size_t *mlen) {
    size_t best = (size_t)-1; /* no candidate yet */
    for (int i = 0; i < f->pcount; i++) {
        size_t p = fff_memmem_folded(s, len, from, f->pats[i], f->lens[i],
                                     f->trans);
        if (p < best) best = p;
    }
    if (best == (size_t)-1) return FFF_NOMATCH;
    for (int i = 0; i < f->pcount; i++) {
        size_t pl = f->lens[i];
        if (pl <= len - best
            && fff_folded_eq(f->pats[i], s + best, pl, f->trans)) {
            *pos = best;
            *mlen = pl;
            return FFF_MATCH;
        }
    }
    return FFF_NOMATCH; /* unreachable */
}

/* Longest pattern matching AT with length <= MAXLEN (the -w shorter retry). */
static int fff_fixed_match_at(fff_fixed *f, const unsigned char *s, size_t len,
                              size_t at, size_t maxlen, size_t *mlen) {
    for (int i = 0; i < f->pcount; i++) {
        size_t pl = f->lens[i];
        if (pl <= maxlen && at + pl <= len
            && fff_folded_eq(f->pats[i], s + at, pl, f->trans)) {
            *mlen = pl;
            return FFF_MATCH;
        }
    }
    return FFF_NOMATCH;
}

static int fff_fixed_whole_eq(fff_fixed *f, const unsigned char *s,
                              size_t len) {
    for (int i = 0; i < f->pcount; i++)
        if (f->lens[i] == len && fff_folded_eq(f->pats[i], s, len, f->trans))
            return 1;
    return 0;
}

/* ------------------------------------------------------------------ */
/* Search cores                                                        */
/* ------------------------------------------------------------------ */

/* EGexecute's exact-mode per-pattern loop, without the DFA/KWset prefilter:
   leftmost match at or after START, then longest; -w and -x acceptance
   checks performed here (GNU does them here too when the prefilter has
   already localized the line). */
static int fff_regex_exact(fff_regex *r, const unsigned char *s, size_t len,
                           size_t start, size_t *ms, size_t *me) {
    if (len > (size_t)INT_MAX)
        return FFF_ERR_TOO_LARGE; /* GNU: TYPE_MAXIMUM (regoff_t) < end-beg-1 */
    /* GNU EGexecute initializes best_match to `end` (one past the content),
       so an empty match at any position, including the very end, is
       assessable; best_len 0 with the strict > keeps first-pattern tie wins. */
    size_t best = len + 1;
    size_t best_len = 0;
    int found = 0;
    for (int i = 0; i < r->pcount; i++) {
        struct re_pattern_buffer *pb = &r->pats[i].pb;
        pb->not_eol = 0;
        pb->newline_anchor = r->m.eol_nl;
        regoff_t st = re_search(pb, (const char *)s, (regoff_t)len,
                                (regoff_t)start, (regoff_t)(len - start),
                                &r->regs);
        if (st < -1) return FFF_ERR_INTERNAL;
        if (st < 0) continue;
        size_t mlen = (size_t)(r->regs.end[0] - st);
        size_t match = (size_t)st;
        if (match > best) continue;
        if (r->m.whole) {
            /* GNU: match_lines && len == end - ptr - 1.  With -w too, the
               reported span is [start, end) where end is one past the
               terminator (or the buffer sentinel for an unterminated final
               record) -- a GNU quirk visible as a doubled terminator with
               -o -x -w.  Without -w the span is the whole content. */
            if (mlen == len - start) {
                match = start;
                mlen = len - start + (r->m.word ? 1 : 0);
                goto assess;
            }
            continue;
        }
        if (!r->m.word) goto assess;
        /* -w: iteratively try shorter matches at the same start, then later
           starts, until a match aligns with word boundaries. */
        while (match <= best) {
            if (!fff_wordchar_next(&r->m.wc, s + match + mlen, s + len,
                                   r->m.locale)
                && !fff_wordchar_prev(&r->m.wc, s, s + match, s + len,
                                      r->m.locale, r->m.mb_cur_max,
                                      r->m.using_utf8))
                goto assess;
            regoff_t shorter = 0;
            if (mlen > 0) {
                mlen--;
                pb->not_eol = 1;
                shorter = re_match(pb, (const char *)s,
                                   (regoff_t)(match + mlen - start),
                                   (regoff_t)match, &r->regs);
                if (shorter < -1) return FFF_ERR_INTERNAL;
            }
            if (shorter > 0) {
                mlen = (size_t)shorter;
            } else {
                /* GNU: if (match == end - 1) break; end - 1 is the
                   content end (= len here): the empty match at the very
                   end of the content is a valid -w candidate. */
                if (match == len) break;
                match++;
                pb->not_eol = 0;
                st = re_search(pb, (const char *)s, (regoff_t)len,
                               (regoff_t)match, (regoff_t)(len - match),
                               &r->regs);
                if (st < -1) return FFF_ERR_INTERNAL;
                if (st < 0) break;
                mlen = (size_t)(r->regs.end[0] - st);
                match = (size_t)st;
            }
        }
        continue;
    assess:
        if (match < best || (match == best && mlen > best_len)) {
            best = match;
            best_len = mlen;
            found = 1;
        }
    }
    if (found) {
        *ms = best;
        *me = best + best_len;
        return FFF_MATCH;
    }
    return FFF_NOMATCH;
}

/* Fexecute's exact-mode search: leftmost byte-literal match at or after
   START with -w/-x acceptance (kwset prefilters replaced by the folded
   literal scan). */
static int fff_fixed_exact(fff_fixed *f, const unsigned char *s, size_t len,
                           size_t start, size_t *ms, size_t *me) {
    if (f->m.whole) {
        /* GNU -F -x pads patterns with the eol byte: a match exists only when
           the whole line equals a pattern and the search starts at 0. */
        if (start == 0 && fff_fixed_whole_eq(f, s, len)) {
            *ms = 0;
            *me = len;
            return FFF_MATCH;
        }
        return FFF_NOMATCH;
    }
    const fff_wc *w = &f->m.wc;
    locale_t loc = f->m.locale;
    size_t mb_start = start;
    int mb_check = f->m.mb_cur_max > 1 && !f->m.using_utf8;
    size_t beg = start;
    while (beg <= len) {
        size_t pos, mlen;
        if (fff_fixed_find_at(f, s, len, beg, &pos, &mlen) == FFF_NOMATCH)
            break;
        size_t mbclen = 0;
        if (mb_check) {
            const unsigned char *p = s + mb_start;
            size_t gb = fff_mb_goback(&p, &mbclen, s + pos, s + len,
                                      f->m.using_utf8);
            mb_start = p - s;
            if (gb != 0) {
                beg = mb_start; /* skip past the multibyte character */
                continue;
            }
        }
        beg = pos;
        if (!f->m.word) {
            *ms = pos;
            *me = pos + mlen;
            return FFF_MATCH;
        }
        int prev_ok = mbclen > 0
            ? !fff_wordchar_next(w, s + pos - mbclen, s + len, loc)
            : !fff_wordchar_prev(w, s + mb_start, s + pos, s + len, loc,
                                 f->m.mb_cur_max, f->m.using_utf8);
        if (prev_ok)
            for (;;) {
                if (!fff_wordchar_next(w, s + pos + mlen, s + len, loc)) {
                    *ms = pos;
                    *me = pos + mlen;
                    return FFF_MATCH;
                }
                if (!mlen) break;
                size_t sh_len;
                if (fff_fixed_match_at(f, s, len, pos, mlen - 1, &sh_len)
                    == FFF_NOMATCH)
                    break;
                mlen = sh_len;
            }
        /* No word match at BEG: skip past word constituents. */
        beg = pos + fff_wordchars_count(w, s + pos, s + len, 1, loc);
        mb_start = beg;
    }
    return FFF_NOMATCH;
}

/* ------------------------------------------------------------------ */
/* Compilation                                                         */
/* ------------------------------------------------------------------ */

/* MODE: 0 = BRE, 1 = ERE, 2 = fixed, 3 = AWK, 4 = GNU AWK,
   5 = POSIX AWK. EOL_NL is true when the record terminator is '\n'
   (false with -z). On failure returns NULL, sets *ERR_PAT to the failing
   pattern index (-1 when unattributable), and fills ERRBUF.
   LOC must outlive the matcher (Rust frees the matcher first). */
fff_matcher *fff_matcher_compile(const char *const *pats, const size_t *lens,
                                 int pcount, int mode, int icase, int word,
                                 int whole, int eol_nl,
                                 const fff_locale *loc,
                                 int *err_pat, char *errbuf,
                                 size_t errbuf_size) {
    *err_pat = -1;
    errbuf[0] = '\0';
    locale_t l = fff_locale_get(loc);
    if (!l) { snprintf(errbuf, errbuf_size, "cannot allocate locale"); return NULL; }
    locale_t prev = uselocale(l);
    int mb_cur_max = MB_CUR_MAX;
    int using_utf8 = 0;
    if (mb_cur_max > 1) {
        const char *cs = nl_langinfo(CODESET);
        if (cs && (strcasecmp(cs, "UTF-8") == 0 || strcasecmp(cs, "UTF8") == 0))
            using_utf8 = 1;
    }
    fff_wc wc;
    fff_wc_init(&wc, l);

    /* -F: decide between byte-literal matching and the regex engine, mirroring
       grep.c main()'s -F -> -G conversion plus Fcompile/Fexecute behavior:
       - single-byte locale, one pattern, -w (with or without -x): convert
         (GNU: n_patterns == 1 && match_words).  With -x -w this makes the
         regex engine's doubled-terminator quirk observable for -F too.
       - multibyte locale, pattern with an encoding error, or -i with a
         pattern that cannot be folded bytewise: convert.
       - -w without -x: routed through the escaped-BRE engine here (GNU's
         kwset word logic is equivalent for well-formed text).
       - otherwise (plain, and -x without conversion): byte-literal matching
         (GNU kwset with eol padding for -x).  G and E always use the regex
         engine. */
    int use_regex = mode != 2;
    if (mode == 2) {
        use_regex = word && !whole;
        if (!use_regex && word && whole && mb_cur_max == 1 && pcount == 1)
            use_regex = 1;
        if (!use_regex && mb_cur_max > 1) {
            if (!icase) {
                int enc_err = 0;
                for (int i = 0; i < pcount && !enc_err; i++)
                    enc_err = fff_has_encoding_error(pats[i], lens[i]);
                if (enc_err) use_regex = 1;
            } else {
                int safe = 1;
                for (int i = 0; i < pcount && safe; i++)
                    safe = fff_fold_safe(pats[i], lens[i], &wc, l);
                if (!safe) use_regex = 1;
            }
        }
    }
    if (!use_regex) {
        fff_fixed *f = calloc(1, sizeof *f);
        if (!f) { uselocale(prev); return NULL; }
        f->m.kind = FFF_FIXED;
        f->m.locale = l;
        f->m.mb_cur_max = mb_cur_max;
        f->m.using_utf8 = using_utf8;
        f->m.word = word;
        f->m.whole = whole;
        f->m.icase = icase;
        f->m.eol_nl = eol_nl;
        f->m.wc = wc;
        f->pcount = pcount;
        f->pats = calloc(pcount > 0 ? pcount : 1, sizeof *f->pats);
        f->lens = calloc(pcount > 0 ? pcount : 1, sizeof *f->lens);
        if (!f->pats || !f->lens) {
            free(f->pats); free(f->lens); free(f);
            uselocale(prev);
            return NULL;
        }
        for (int b = 0; b < 256; b++)
            f->trans[b] = icase
                ? (unsigned char)toupper_l(b, l)
                : (unsigned char)b;
        for (int i = 0; i < pcount; i++) {
            f->pats[i] = malloc(lens[i] + 1);
            if (!f->pats[i]) goto oom_fixed;
            memcpy(f->pats[i], pats[i], lens[i]);
            f->lens[i] = lens[i];
        }
        /* Sort longest-first so the first match at a position is the
           longest (GNU kwsexec 'longest' preference; ties share a span
           so order among equal lengths is unobservable). */
        for (int i = 1; i < pcount; i++)
            for (int j = i; j > 0 && f->lens[j] > f->lens[j - 1]; j--) {
                unsigned char *tp = f->pats[j]; f->pats[j] = f->pats[j - 1];
                f->pats[j - 1] = tp;
                size_t tl = f->lens[j]; f->lens[j] = f->lens[j - 1];
                f->lens[j - 1] = tl;
            }
        uselocale(prev);
        return (fff_matcher *)f;
    oom_fixed:
        for (int i = 0; i < pcount; i++) free(f->pats[i]);
        free(f->pats); free(f->lens); free(f);
        snprintf(errbuf, errbuf_size, "memory exhausted");
        uselocale(prev);
        return NULL;
    }

    /* Regex path: G, E, AWK variants, or F escaped to a BRE. */
    reg_syntax_t syntax = RE_SYNTAX_GREP;
    switch (mode) {
    case 1: syntax = RE_SYNTAX_EGREP; break;
    case 3: syntax = RE_SYNTAX_AWK; break;
    case 4: syntax = RE_SYNTAX_GNU_AWK; break;
    case 5: syntax = RE_SYNTAX_POSIX_AWK; break;
    }
    if (icase) syntax |= RE_ICASE;
    fff_regex *r = calloc(1, sizeof *r);
    if (!r) { uselocale(prev); return NULL; }
    r->m.kind = FFF_REGEX;
    r->m.locale = l;
    r->m.mb_cur_max = mb_cur_max;
    r->m.using_utf8 = using_utf8;
    r->m.word = word;
    r->m.whole = whole;
    r->m.icase = icase;
    r->m.eol_nl = eol_nl;
    r->m.wc = wc;
    r->pcount = pcount;
    r->pats = calloc(pcount > 0 ? pcount : 1, sizeof *r->pats);
    if (!r->pats) { free(r); uselocale(prev); return NULL; }
    for (int i = 0; i < pcount; i++) {
        char *compiled = NULL;
        size_t clen = 0;
        const char *src = pats[i];
        size_t slen = lens[i];
        if (mode == 2) {
            if (fff_escape_pattern(src, slen, &wc, &compiled, &clen) != 0) {
                snprintf(errbuf, errbuf_size, "memory exhausted");
                *err_pat = i;
                goto fail_compile;
            }
            src = compiled;
            slen = clen;
        }
        struct re_pattern_buffer *pb = &r->pats[i].pb;
        memset(pb, 0, sizeof *pb);
        /* No fastmap with -i: glibc bug 20381.  Mirrors GNU dfasearch.c. */
        pb->fastmap = icase ? NULL : malloc(UCHAR_MAX + 1);
        pb->translate = NULL;
        pthread_mutex_lock(&fff_syntax_lock);
        reg_syntax_t old = re_set_syntax(syntax);
        const char *err = re_compile_pattern(src, slen, pb);
        re_set_syntax(old);
        pthread_mutex_unlock(&fff_syntax_lock);
        free(compiled);
        if (err) {
            *err_pat = i;
            snprintf(errbuf, errbuf_size, "%s", err);
            goto fail_compile;
        }
    }
    uselocale(prev);
    return (fff_matcher *)r;
fail_compile:
    for (int i = 0; i < pcount; i++) {
        /* glibc regfree frees fastmap, translate and the compiled buffer;
           a pattern whose compilation failed has no buffer, so free its
           fastmap directly. */
        if (r->pats[i].pb.buffer)
            regfree(&r->pats[i].pb);
        else
            free(r->pats[i].pb.fastmap);
    }
    free(r->pats);
    free(r);
    uselocale(prev);
    return NULL;
}

void fff_matcher_free(fff_matcher *mm) {
    if (!mm) return;
    if (mm->kind == FFF_REGEX) {
        fff_regex *r = (fff_regex *)mm;
        for (int i = 0; i < r->pcount; i++) {
            if (r->pats[i].pb.buffer)
                regfree(&r->pats[i].pb); /* frees fastmap too */
            else
                free(r->pats[i].pb.fastmap);
        }
        free(r->regs.start);
        free(r->regs.end);
        free(r->pats);
        free(r);
    } else {
        fff_fixed *f = (fff_fixed *)mm;
        for (int i = 0; i < f->pcount; i++) free(f->pats[i]);
        free(f->pats);
        free(f->lens);
        free(f);
    }
}

/* ------------------------------------------------------------------ */
/* Entry points                                                        */
/* ------------------------------------------------------------------ */

int fff_matcher_find(fff_matcher *mm, const unsigned char *s, size_t len,
                     size_t start, size_t *ms, size_t *me) {
    locale_t prev = uselocale(mm->locale);
    int r;
    if (mm->kind == FFF_REGEX)
        r = fff_regex_exact((fff_regex *)mm, s, len, start, ms, me);
    else
        r = fff_fixed_exact((fff_fixed *)mm, s, len, start, ms, me);
    uselocale(prev);
    return r;
}

int fff_matcher_is_match(fff_matcher *mm, const unsigned char *s, size_t len) {
    size_t ms, me;
    return fff_matcher_find(mm, s, len, 0, &ms, &me);
}