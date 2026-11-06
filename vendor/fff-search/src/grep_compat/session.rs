use std::collections::HashMap;
use std::fs::{File, Metadata};
use std::io::{self, BufRead, BufReader, Cursor, Read};
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::{ContentSource, Environment, Mode, Options, Output, engine};
use crate::{FFFMode, FilePicker, FilePickerOptions, SharedFilePicker, SharedFrecency};

const CACHE_BYTES: usize = 128 * 1024 * 1024;
const CACHE_FILES: usize = 8192;
const CACHE_FILE_BYTES: u64 = 8 * 1024 * 1024;

/// One persistent FFF index plus bounded immutable snapshots for byte-exact
/// output. Request state, native matchers and I/O cursors are never shared.
pub struct Session {
    root: PathBuf,
    picker: SharedFilePicker,
    cache: Arc<Mutex<Cache>>,
}
impl Session {
    pub fn new(root: impl AsRef<Path>) -> io::Result<Self> {
        let root = std::fs::canonicalize(root)?;
        if !root.is_dir() {
            return Err(io::Error::other("index root must be a directory"));
        }
        let picker = SharedFilePicker::default();
        // FFF's native path arena requires a UTF-8 root. The byte-oriented
        // scanner still handles other roots correctly without that accelerator.
        if let Some(base_path) = root.to_str() {
            FilePicker::new_with_shared_state(
                picker.clone(),
                SharedFrecency::default(),
                FilePickerOptions {
                    base_path: base_path.to_owned(),
                    mode: FFFMode::Ai,
                    enable_content_indexing: true,
                    // Live mmaps can fault on concurrent truncation. Compatibility
                    // output instead uses immutable snapshots populated while read.
                    enable_mmap_cache: false,
                    watch: true,
                    enable_fs_root_scanning: true,
                    enable_home_dir_scanning: true,
                    ..Default::default()
                },
            )
            .map_err(|e| io::Error::other(e.to_string()))?;
        }
        Ok(Self {
            root,
            picker,
            cache: Arc::new(Mutex::new(Cache::default())),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Optional warm-up barrier. False also covers roots FFF cannot index;
    /// searching them is still supported by the byte-oriented engine.
    pub fn wait_for_index(&self, timeout: Duration) -> bool {
        if self.picker.read().ok().is_none_or(|p| p.is_none()) {
            return false;
        }
        self.picker.wait_for_indexing_complete(timeout)
    }

    pub fn search(&self, options: Options, stdin: &[u8], environment: &Environment) -> Output {
        let mut source = Source {
            session: self,
            patterns: Vec::new(),
        };
        engine::run(options, &self.root, stdin, environment, &mut source)
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        self.picker.cancel();
        if let Ok(mut guard) = self.picker.write() {
            if let Some(picker) = guard.as_mut() {
                picker.stop_background_monitor();
            }
        }
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
struct Fingerprint {
    dev: u64,
    ino: u64,
    size: u64,
    mtime: i64,
    mtime_ns: i64,
    ctime: i64,
    ctime_ns: i64,
}
impl From<&Metadata> for Fingerprint {
    fn from(m: &Metadata) -> Self {
        Self {
            dev: m.dev(),
            ino: m.ino(),
            size: m.size(),
            mtime: m.mtime(),
            mtime_ns: m.mtime_nsec(),
            ctime: m.ctime(),
            ctime_ns: m.ctime_nsec(),
        }
    }
}
#[derive(Clone, Copy, PartialEq, Eq)]
enum IndexState {
    Ready,
    Pending,
    Unavailable,
}
#[derive(Clone)]
struct Entry {
    fingerprint: Fingerprint,
    bytes: Arc<Vec<u8>>,
    index: IndexState,
}
#[derive(Default)]
struct Cache {
    entries: HashMap<PathBuf, Entry>,
    bytes: usize,
}
impl Cache {
    fn insert(&mut self, path: PathBuf, entry: Entry) {
        if let Some(old) = self.entries.remove(&path) {
            self.bytes -= old.bytes.len();
        }
        if entry.bytes.len() > CACHE_BYTES {
            return;
        }
        while self.bytes > CACHE_BYTES - entry.bytes.len() || self.entries.len() >= CACHE_FILES {
            let Some(key) = self.entries.keys().next().cloned() else {
                break;
            };
            if let Some(old) = self.entries.remove(&key) {
                self.bytes -= old.bytes.len();
            }
        }
        self.bytes += entry.bytes.len();
        self.entries.insert(path, entry);
    }
}

fn refresh_index(
    picker: &SharedFilePicker,
    path: &Path,
    bytes: &[u8],
    fingerprint: Fingerprint,
) -> IndexState {
    let Ok(mut guard) = picker.write() else {
        return IndexState::Unavailable;
    };
    let Some(picker) = guard.as_mut() else {
        return IndexState::Unavailable;
    };
    if picker.is_scan_active() || picker.is_post_scan_active() {
        return IndexState::Pending;
    }
    if bytes.is_empty()
        || bytes.contains(&0)
        || std::str::from_utf8(bytes).is_err()
        || bytes.len() > crate::constants::MAX_INDEXABLE_FILE_SIZE
        || path.to_str().is_none()
    {
        return IndexState::Unavailable;
    }
    let Some(item) = picker.get_file_by_path(path) else {
        return IndexState::Unavailable;
    };
    if item.is_binary() {
        return IndexState::Unavailable;
    }
    // Recheck after acquiring the publication lock. An older reader may have
    // waited behind a newer one; it must not overwrite the newer overlay.
    if !std::fs::metadata(path).is_ok_and(|m| Fingerprint::from(&m) == fingerprint) {
        return IndexState::Unavailable;
    }
    if !picker.compat_update_snapshot(path, bytes, u64::try_from(fingerprint.mtime).ok()) {
        return IndexState::Unavailable;
    }
    if std::fs::metadata(path).is_ok_and(|m| Fingerprint::from(&m) == fingerprint) {
        IndexState::Ready
    } else {
        IndexState::Unavailable
    }
}

/// Retains the cached Vec and exposes GNU-sized read windows without copying.
struct SnapshotReader {
    bytes: Arc<Vec<u8>>,
    pos: usize,
}
impl SnapshotReader {
    fn new(bytes: Arc<Vec<u8>>) -> Self {
        Self { bytes, pos: 0 }
    }
}
impl Read for SnapshotReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let available = self.fill_buf()?;
        let count = available.len().min(out.len());
        out[..count].copy_from_slice(&available[..count]);
        self.consume(count);
        Ok(count)
    }
}
impl BufRead for SnapshotReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        let end = self
            .pos
            .saturating_add(engine::CHUNK_BYTES)
            .min(self.bytes.len());
        Ok(&self.bytes[self.pos..end])
    }

    fn consume(&mut self, amount: usize) {
        self.pos = self.pos.saturating_add(amount).min(self.bytes.len());
    }
}

/// Fill the cache only as the matcher consumes input. Pre-reading to EOF would
/// change `-q`/`-m` behavior on later I/O errors and would block on live streams.
struct CachingReader {
    reader: BufReader<File>,
    path: PathBuf,
    fingerprint: Fingerprint,
    bytes: Vec<u8>,
    cacheable: bool,
    finished: bool,
    picker: SharedFilePicker,
    cache: Arc<Mutex<Cache>>,
}
impl CachingReader {
    fn finish(&mut self) {
        self.finished = true;
        if !self.cacheable
            || self.bytes.len() as u64 != self.fingerprint.size
            || !self
                .reader
                .get_ref()
                .metadata()
                .is_ok_and(|m| Fingerprint::from(&m) == self.fingerprint)
            || !std::fs::metadata(&self.path)
                .is_ok_and(|m| Fingerprint::from(&m) == self.fingerprint)
        {
            return;
        }
        let index = refresh_index(&self.picker, &self.path, &self.bytes, self.fingerprint);
        let entry = Entry {
            fingerprint: self.fingerprint,
            bytes: Arc::new(std::mem::take(&mut self.bytes)),
            index,
        };
        // A cache failure must not turn successful file input into a grep error.
        if let Ok(mut cache) = self.cache.lock() {
            cache.insert(self.path.clone(), entry);
        }
    }
}
impl Read for CachingReader {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        if out.is_empty() {
            return Ok(0);
        }
        let buffer = self.fill_buf()?;
        let n = buffer.len().min(out.len());
        out[..n].copy_from_slice(&buffer[..n]);
        self.consume(n);
        Ok(n)
    }
}
impl BufRead for CachingReader {
    fn fill_buf(&mut self) -> io::Result<&[u8]> {
        if self.finished {
            return Ok(&[]);
        }
        if self.reader.fill_buf()?.is_empty() {
            self.finish();
            return Ok(&[]);
        }
        self.reader.fill_buf()
    }
    fn consume(&mut self, amount: usize) {
        let amount = amount.min(self.reader.buffer().len());
        if self.cacheable {
            if self.bytes.len().saturating_add(amount) as u64 <= CACHE_FILE_BYTES {
                self.bytes
                    .extend_from_slice(&self.reader.buffer()[..amount]);
            } else {
                self.cacheable = false;
                self.bytes = Vec::new();
            }
        }
        self.reader.consume(amount);
    }
}

struct Source<'a> {
    session: &'a Session,
    patterns: Vec<Vec<u16>>,
}
impl Source<'_> {
    fn indexed_miss(&self, path: &Path, entry: &Entry) -> bool {
        if entry.index != IndexState::Ready || self.patterns.is_empty() {
            return false;
        }
        let Ok(guard) = self.session.picker.read() else {
            return false;
        };
        let Some(picker) = guard.as_ref() else {
            return false;
        };
        if picker.compat_might_match(path, &self.patterns) {
            return false;
        }
        // Never trust a candidate bit across a write or path replacement.
        std::fs::metadata(path).is_ok_and(|m| Fingerprint::from(&m) == entry.fingerprint)
    }
}
impl ContentSource for Source<'_> {
    fn prepare(&mut self, patterns: &[Vec<u8>], options: &Options) {
        self.patterns.clear();
        if options.ignore_case || options.invert || patterns.is_empty() {
            return;
        }
        // Every alternative must contribute a printable bigram. Omitting a
        // short/unknown alternative from an OR would introduce false negatives.
        if patterns
            .iter()
            .any(|p| p.len() < 2 || !p.iter().all(|b| (b' '..=b'~').contains(b)))
        {
            return;
        }
        if options.mode != Mode::Fixed
            && patterns
                .iter()
                .any(|p| p.iter().any(|b| br"\.^$*+?()[]{}|".contains(b)))
        {
            return;
        }
        self.patterns
            .extend(patterns.iter().map(|p| crate::index::extract_bigrams(p)));
    }

    fn open(&mut self, path: &Path) -> io::Result<Box<dyn BufRead + Send>> {
        // Reopen even on cache hits: permissions and deletion stay observable.
        let file = File::open(path)?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() > CACHE_FILE_BYTES {
            return Ok(Box::new(BufReader::with_capacity(
                engine::CHUNK_BYTES,
                file,
            )));
        }
        let fingerprint = Fingerprint::from(&metadata);
        let key = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
        let cached = self.session.cache.lock().ok().and_then(|cache| {
            cache
                .entries
                .get(&key)
                .filter(|e| e.fingerprint == fingerprint)
                .cloned()
        });
        if let Some(mut entry) = cached {
            if entry.index == IndexState::Pending {
                entry.index = refresh_index(&self.session.picker, &key, &entry.bytes, fingerprint);
                if entry.index != IndexState::Pending {
                    if let Ok(mut cache) = self.session.cache.lock() {
                        cache.insert(key.clone(), entry.clone());
                    }
                }
            }
            if self.indexed_miss(&key, &entry) {
                return Ok(Box::new(Cursor::new(Vec::<u8>::new())));
            }
            return Ok(Box::new(SnapshotReader::new(entry.bytes)));
        }
        Ok(Box::new(CachingReader {
            reader: BufReader::with_capacity(engine::CHUNK_BYTES, file),
            path: key,
            fingerprint,
            bytes: Vec::new(),
            cacheable: true,
            finished: false,
            picker: self.session.picker.clone(),
            cache: self.session.cache.clone(),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::grep_compat::PatternSource;

    #[test]
    fn stale_snapshot_cannot_hide_a_newer_match() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("file.txt");
        std::fs::write(&path, b"old content\n").unwrap();
        let old = Fingerprint::from(&std::fs::metadata(&path).unwrap());
        let session = Session::new(root.path()).unwrap();
        assert!(session.wait_for_index(Duration::from_secs(10)));
        std::fs::write(&path, b"new content\n").unwrap();
        let options = Options {
            mode: Mode::Fixed,
            patterns: vec![PatternSource::Inline(b"new".to_vec())],
            files: vec![PathBuf::from("file.txt")],
            ..Default::default()
        };
        let env = Environment {
            locale: "C".into(),
            ..Default::default()
        };
        assert_eq!(
            session.search(options.clone(), &[], &env).stdout,
            b"new content\n"
        );
        // Model an older reader reaching publication after the newer request.
        let _ = refresh_index(&session.picker, &path, b"old content\n", old);
        assert_eq!(session.search(options, &[], &env).stdout, b"new content\n");
    }
}
