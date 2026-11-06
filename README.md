# ffff

GNU grep 3.12 as an async Rust library. You pass argv and get back the same
stdout, stderr and exit status that `/usr/bin/grep` would produce, byte for
byte. Nothing is spawned. Repeated searches over one directory reuse a
persistent [FFF](https://crates.io/crates/fff-search) index and an in-memory
file cache.

```rust
let grep = ffff::Grep::new("/srv/project").await?; // once, at startup

let out = grep.search(["-rn", "--include=*.rs", "fn main", "."]).await?;
// out.stdout, out.stderr, out.status are exactly what GNU grep would produce
```

## API

```rust
impl Grep {
    async fn new(root: impl AsRef<Path>) -> Result<Grep, Error>;
    async fn search(&self, args) -> Result<Output, Error>;
    async fn search_with_input(&self, args, stdin: Vec<u8>) -> Result<Output, Error>;
    async fn search_with_environment(&self, args, stdin: Vec<u8>, env: Environment)
        -> Result<Output, Error>;
    async fn search_options(&self, "-Fn -C2 'some text' src") -> Result<Output, Error>;
    async fn wait_for_index(&self, timeout: Duration) -> Result<bool, Error>;
}

pub struct Output { stdout: Vec<u8>, stderr: Vec<u8>, status: i32, stdin_consumed: usize }
pub struct Environment { locale, grep_colors, posixly_correct, stdout_is_terminal, term }
```

- `args` is everything after `grep`: options, patterns and file operands, as
  raw `OsString`s.
- Relative paths resolve against `root`. The root is a working directory, not a
  sandbox: absolute paths and `..` behave as they do in grep.
- grep's failures (bad regex, missing file, unknown option) come back as
  `Ok(Output { status: 2, .. })` with GNU's exact diagnostic. `Err` only means
  the session couldn't be created or a Tokio worker failed.
- `search_options` splits the string with shell quoting only. It doesn't glob,
  expand variables or handle redirects. Pass argv when the input is untrusted.
- `Environment` applies per request: locale, `GREP_COLORS`, `POSIXLY_CORRECT`,
  `TERM`, and whether stdout counts as a terminal (for `--color=auto`). Nothing
  calls `setlocale`, `setenv`, `chdir`, or touches the process's stdio.
  `Environment::default()` reads the process environment and assumes stdout is
  not a terminal.
- `Grep` is cheap to clone, and concurrent searches on clones are fine.

## Compatibility

Every option in `grep --help` for 3.12 is supported, plus the undocumented
`-X MATCHER` (including the `awk`, `gawk` and `posixawk` syntaxes), `-y` and
`--fixed-regexp`. `-u` is rejected, as in GNU.

Exceptions:

- `--help`, `--version` and `-V` are rejected. An invalid `--color=WHEN` still
  prints the help text, because GNU does.
- `--line-buffered` produces the same bytes, but output is returned only when
  the search finishes, so nothing streams.
- The deprecated `GREP_COLOR` variable is ignored. `GREP_COLORS` works.

Matching uses the same engines GNU uses. BRE, ERE, AWK and `-F` go through
glibc's GNU regex (`re_compile_pattern`/`re_search`), with GNU's `-w`/`-x`
acceptance loops and multibyte word-boundary logic ported from
`dfasearch.c`, `kwsearch.c` and `searchutils.c`. `-P` uses PCRE2 with the
flags from `pcresearch.c`. Binary detection, NUL zapping, `-m` stdin
positioning, context groups, `-r`/`-R` symlink rules, include/exclude
ordering and color SGR sequences all follow `grep.c`.

## How the index is used

The index only ever skips work. It never decides a result on its own.

1. Files are read through a cache keyed by path and validated against
   dev, inode, size, and mtime/ctime to the nanosecond on every access. A file
   that changed since the last read is read again, even if the watcher hasn't
   caught up yet.
2. For case-sensitive, non-inverted searches whose patterns are plain printable
   literals of at least two bytes, a fresh, validated file whose FFF bigrams
   can't contain any pattern is skipped. The skip is applied only after its
   fingerprint is checked again.
3. Every other case scans the bytes: regex metacharacters, `-i`, `-v`, binary
   files, files over 8 MiB, paths outside the index, or an index that is still
   building.

The cache is capped at 128 MiB and 8192 files. The index builds in the
background, and searches are complete before it finishes.

## Requirements

- Linux with glibc. Other targets fail at compile time.
- A C compiler at build time.
- PCRE2 (`pcre2-sys` builds its bundled copy if no system library is found).

## Testing

```sh
cargo test
```

`tests/compat.rs` runs about 300 cases. Each one runs the same argv, stdin,
files and environment through `/usr/bin/grep` and through `ffff`, then asserts
that stdout, stderr and the exit status are identical. The tests need GNU grep
3.12 at `/usr/bin/grep`. `tests/adapter.rs` covers behavior grep itself can't
show: concurrent searches, freshness after writes, stdin accounting, and FIFO
handling with `-D skip`.

## Layout

```text
src/lib.rs                 async API
src/args.rs                getopt_long-compatible argv parser
vendor/fff-search/         fff-search 0.10.6, plus:
  src/grep_compat/engine.rs    traversal, records, context, output
  src/grep_compat/matcher.rs   matcher selection, PCRE2 backend
  src/grep_compat/native.c     glibc regex / fixed-string bridge
  src/grep_compat/session.rs   index + snapshot cache
tests/                     differential and adapter tests
```

## License

AGPL-3.0-only. The vendored `fff-search` keeps its MIT license
(`vendor/fff-search/LICENSE`).
