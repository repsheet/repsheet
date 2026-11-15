//! Following a log file the way `tail -F` does, across rotation.

use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;

pub struct Tailer {
    path: PathBuf,
    file: Option<File>,
    inode: u64,
    pos: u64,
    partial: Vec<u8>,
    /// Times the file was replaced or truncated.
    pub rotations: u64,
}

impl Tailer {
    /// Start following `path`. With `from_start` false, lines already in the
    /// file are skipped (a restart does not replay old traffic).
    pub fn new(path: PathBuf, from_start: bool) -> Tailer {
        let mut t = Tailer {
            path,
            file: None,
            inode: 0,
            pos: 0,
            partial: vec![],
            rotations: 0,
        };
        if let Ok(f) = File::open(&t.path) {
            let meta = f.metadata().ok();
            t.inode = meta.as_ref().map_or(0, |m| m.ino());
            t.pos = if from_start {
                0
            } else {
                meta.map_or(0, |m| m.len())
            };
            t.file = Some(f);
        }
        t
    }

    fn read_available(&mut self) {
        let Some(f) = self.file.as_mut() else { return };
        if f.seek(SeekFrom::Start(self.pos)).is_err() {
            return;
        }
        let mut buf = Vec::new();
        if let Ok(n) = f.read_to_end(&mut buf) {
            self.pos += n as u64;
            self.partial.extend_from_slice(&buf);
        }
    }

    /// Complete lines written since the last call.
    pub fn poll(&mut self) -> Vec<String> {
        match std::fs::metadata(&self.path) {
            Ok(meta) if self.file.is_none() => {
                // The file (re)appeared: read it from the beginning.
                if let Ok(f) = File::open(&self.path) {
                    self.inode = meta.ino();
                    self.pos = 0;
                    self.file = Some(f);
                }
            }
            Ok(meta) if meta.ino() != self.inode => {
                // Rotated: finish the old file, then switch to the new one.
                self.read_available();
                self.rotations += 1;
                if let Ok(f) = File::open(&self.path) {
                    self.inode = meta.ino();
                    self.pos = 0;
                    self.file = Some(f);
                }
            }
            Ok(meta) if meta.len() < self.pos => {
                // Truncated in place (copytruncate).
                self.rotations += 1;
                self.pos = 0;
                self.partial.clear();
            }
            _ => {}
        }
        self.read_available();

        let mut lines = vec![];
        let mut start = 0;
        for (i, &b) in self.partial.iter().enumerate() {
            if b == b'\n' {
                let line = String::from_utf8_lossy(&self.partial[start..i])
                    .trim_end_matches('\r')
                    .to_string();
                if !line.is_empty() {
                    lines.push(line);
                }
                start = i + 1;
            }
        }
        self.partial.drain(..start);
        if self.partial.len() > 1 << 20 {
            // A "line" over 1 MiB is not a log line; drop it.
            self.partial.clear();
        }
        lines
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn dir() -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "tail-test-{}-{}",
            std::process::id(),
            rand_suffix()
        ));
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn rand_suffix() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos() as u64
    }

    fn append(path: &PathBuf, text: &str) {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(path)
            .unwrap();
        f.write_all(text.as_bytes()).unwrap();
    }

    #[test]
    fn skips_existing_lines_and_follows_new_ones() {
        let d = dir();
        let p = d.join("a.log");
        append(&p, "old\n");
        let mut t = Tailer::new(p.clone(), false);
        assert!(t.poll().is_empty());
        append(&p, "one\ntw");
        assert_eq!(t.poll(), ["one"]);
        append(&p, "o\nthree\n");
        assert_eq!(t.poll(), ["two", "three"]);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn from_start_reads_everything() {
        let d = dir();
        let p = d.join("a.log");
        append(&p, "old\n");
        let mut t = Tailer::new(p.clone(), true);
        assert_eq!(t.poll(), ["old"]);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn follows_rename_rotation() {
        let d = dir();
        let p = d.join("a.log");
        append(&p, "");
        let mut t = Tailer::new(p.clone(), false);
        append(&p, "before\n");
        std::fs::rename(&p, d.join("a.log.1")).unwrap();
        append(&d.join("a.log.1"), "late\n"); // written by nginx before reopen
        append(&p, "after\n");
        assert_eq!(t.poll(), ["before", "late", "after"]);
        assert_eq!(t.rotations, 1);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn follows_truncation() {
        let d = dir();
        let p = d.join("a.log");
        append(&p, "");
        let mut t = Tailer::new(p.clone(), false);
        append(&p, "aaaaaaaaaa\n");
        assert_eq!(t.poll(), ["aaaaaaaaaa"]);
        std::fs::write(&p, "").unwrap();
        append(&p, "b\n");
        assert_eq!(t.poll(), ["b"]);
        assert_eq!(t.rotations, 1);
        std::fs::remove_dir_all(d).unwrap();
    }

    #[test]
    fn waits_for_a_missing_file() {
        let d = dir();
        let p = d.join("later.log");
        let mut t = Tailer::new(p.clone(), false);
        assert!(t.poll().is_empty());
        append(&p, "first\n");
        assert_eq!(t.poll(), ["first"]);
        std::fs::remove_dir_all(d).unwrap();
    }
}
