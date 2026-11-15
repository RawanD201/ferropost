//! Reading text files from the end, for log viewers.
//!
//! [`RevLines`] yields a file's lines last-to-first while reading it
//! backwards in chunks, so showing the newest lines of a large log costs
//! only as much as the lines returned. Line splitting matches Go's
//! `bufio.ScanLines`: `\n` separates lines, a trailing `\r` is dropped, a
//! final newline does not create an empty line, and invalid UTF-8 is
//! replaced rather than failing the file.

use std::fs::File;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::Path;

const CHUNK: u64 = 64 * 1024;

pub struct RevLines {
    file: File,
    /// Bytes before this offset have not been read yet.
    pos: u64,
    /// Read but not yet yielded; always a prefix of the unread tail.
    buf: Vec<u8>,
    /// The next split is the file's last line (skip it if empty).
    at_end: bool,
    finished: bool,
}

impl RevLines {
    pub fn open(path: &Path) -> io::Result<Self> {
        let file = File::open(path)?;
        let len = file.metadata()?.len();
        Ok(Self {
            file,
            pos: len,
            buf: Vec::new(),
            at_end: true,
            finished: len == 0,
        })
    }

    fn read_previous_chunk(&mut self) -> io::Result<()> {
        let start = self.pos.saturating_sub(CHUNK);
        let mut chunk = vec![0; usize::try_from(self.pos - start).unwrap_or(0)];
        self.file.seek(SeekFrom::Start(start))?;
        self.file.read_exact(&mut chunk)?;
        chunk.extend_from_slice(&self.buf);
        self.buf = chunk;
        self.pos = start;
        Ok(())
    }
}

fn decode(mut line: Vec<u8>) -> String {
    if line.last() == Some(&b'\r') {
        line.pop();
    }
    String::from_utf8(line).unwrap_or_else(|e| String::from_utf8_lossy(e.as_bytes()).into_owned())
}

impl Iterator for RevLines {
    type Item = io::Result<String>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if self.finished {
                return None;
            }
            if let Some(idx) = self.buf.iter().rposition(|b| *b == b'\n') {
                let line = self.buf.split_off(idx + 1);
                self.buf.truncate(idx);
                if std::mem::take(&mut self.at_end) && line.is_empty() {
                    continue;
                }
                return Some(Ok(decode(line)));
            }
            if self.pos == 0 {
                self.finished = true;
                return Some(Ok(decode(std::mem::take(&mut self.buf))));
            }
            if let Err(err) = self.read_previous_chunk() {
                self.finished = true;
                return Some(Err(err));
            }
        }
    }
}

/// Walks `files` newest first and returns matching lines in file order:
/// skips the newest `skip` matches, then keeps up to `take`.
pub fn newest_lines(
    files: &[impl AsRef<Path>],
    keyword: &str,
    skip: usize,
    take: usize,
) -> Vec<String> {
    let mut skip = skip;
    let mut picked = Vec::new();
    'files: for path in files {
        let Ok(lines) = RevLines::open(path.as_ref()) else {
            continue;
        };
        for line in lines {
            let Ok(line) = line else { continue 'files };
            if !keyword.is_empty() && !line.contains(keyword) {
                continue;
            }
            if skip > 0 {
                skip -= 1;
                continue;
            }
            picked.push(line);
            if picked.len() >= take {
                break 'files;
            }
        }
    }
    picked.reverse();
    picked
}

#[cfg(test)]
mod tests {
    use super::*;

    fn lines_of(content: &[u8]) -> Vec<String> {
        let dir = tempfile::tempdir().expect("tempdir");
        let path = dir.path().join("f.log");
        std::fs::write(&path, content).expect("write");
        RevLines::open(&path)
            .expect("open")
            .map(|l| l.expect("line"))
            .collect()
    }

    #[test]
    fn splits_like_bufio_scanlines() {
        assert_eq!(lines_of(b"a\nb\n"), ["b", "a"]);
        assert_eq!(lines_of(b"a\nb"), ["b", "a"]);
        assert_eq!(lines_of(b"a\r\n\nb\r\n"), ["b", "", "a"]);
        assert_eq!(lines_of(b"\n"), [""]);
        assert!(lines_of(b"").is_empty());
        assert_eq!(lines_of(b"bad \xff byte\n"), ["bad \u{fffd} byte"]);
    }

    #[test]
    fn handles_lines_longer_than_a_chunk() {
        let long = "x".repeat(200_000);
        let content = format!("first\n{long}\nlast\n");
        let got = lines_of(content.as_bytes());
        assert_eq!(got.len(), 3);
        assert_eq!(got[0], "last");
        assert_eq!(got[1].len(), 200_000);
        assert_eq!(got[2], "first");
    }

    #[test]
    fn newest_lines_pages_across_files() {
        let dir = tempfile::tempdir().expect("tempdir");
        let new = dir.path().join("2026-11-15.log");
        let old = dir.path().join("2026-11-14.log");
        std::fs::write(&old, "o1 x\no2\no3 x\n").expect("write");
        std::fs::write(&new, "n1 x\nn2 x\n").expect("write");
        let files = [&new, &old];

        assert_eq!(newest_lines(&files, "", 0, 3), ["o3 x", "n1 x", "n2 x"]);
        assert_eq!(newest_lines(&files, "x", 2, 2), ["o1 x", "o3 x"]);
        assert_eq!(newest_lines(&files, "x", 10, 2), Vec::<String>::new());
        assert_eq!(newest_lines(&files, "", 0, 100).len(), 5);
    }
}
