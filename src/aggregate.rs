//! Folds the event stream into one record per path. Events are not kept, so
//! memory grows with the number of distinct paths, not with the trace length.

use std::collections::HashMap;
use std::ffi::OsStr;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::backend::{Call, PathArg, SysEvent};

#[derive(Debug, Default, Clone)]
pub struct Ops {
    pub read: u32,
    pub list: u32,
    pub write: u32,
    pub create: u32,
    pub delete: u32,
    pub exec: u32,
    pub stat: u32,
    pub attr: u32,
    pub moved_in: u32,
    pub moved_out: u32,
}

impl Ops {
    pub fn any(&self) -> bool {
        self.read
            + self.list
            + self.write
            + self.create
            + self.delete
            + self.exec
            + self.stat
            + self.attr
            + self.moved_in
            + self.moved_out
            > 0
    }

    pub fn mutated(&self) -> bool {
        self.write + self.create + self.delete + self.attr + self.moved_in + self.moved_out > 0
    }
}

#[derive(Debug, Default, Clone)]
pub struct Errors {
    /// ENOENT and ENOTDIR.
    pub missing: u32,
    /// EACCES and EPERM.
    pub denied: u32,
    pub other: u32,
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    File,
    Dir,
    Symlink,
    Other,
}

#[derive(Debug, Clone)]
pub struct Record {
    /// Absolute and lexically normalized, symlinks not resolved.
    pub path: Vec<u8>,
    pub ops: Ops,
    pub errors: Errors,
    /// Whether the path existed before the command touched it, from the
    /// first event that tells. `None` if nothing did.
    pub before: Option<bool>,
    pub moved_from: Option<usize>,
    pub moved_to: Option<usize>,
    pub pids: Vec<i32>,
    /// Order of first appearance, used for sorting.
    pub first_seen: u64,
    pub first_seen_ms: u64,
    /// Filled in by `enrich` after the run; `None` if it doesn't exist.
    pub kind_after: Option<Kind>,
}

#[derive(Default)]
pub struct Aggregator {
    pub records: Vec<Record>,
    index: HashMap<Vec<u8>, usize>,
    seq: u64,
    ms: u64,
    pub io_uring: bool,
    pub execs: Vec<Exec>,
}

/// A successful execve.
pub struct Exec {
    pub pid: i32,
    pub path: Vec<u8>,
    pub argv: Vec<Vec<u8>>,
}

impl Aggregator {
    /// `ms` is when the event arrived, counted from the start of the run.
    pub fn add(&mut self, ev: &SysEvent, ms: u64) {
        self.seq += 1;
        self.ms = ms;
        let ok = ev.result.is_ok();
        match &ev.call {
            Call::Open {
                path,
                flags,
                existed,
            } => {
                let Some(r) = self.rec(path, ev.pid) else {
                    return;
                };
                let Ok(_) = ev.result else {
                    // O_CREAT|O_EXCL on an existing file: it's there.
                    if ev.result == Err(libc::EEXIST) {
                        r.ops.stat += 1;
                        r.before.get_or_insert(true);
                    } else {
                        r.failed(ev.result);
                    }
                    return;
                };
                let (acc, creat) = (flags & libc::O_ACCMODE, flags & libc::O_CREAT != 0);
                if flags & libc::O_PATH != 0 {
                    r.ops.stat += 1;
                    r.before.get_or_insert(true);
                    return;
                }
                if flags & libc::O_TMPFILE == libc::O_TMPFILE {
                    // An unnamed file in this directory; nothing to report.
                    return;
                }
                let excl = creat && flags & libc::O_EXCL != 0;
                let existed = if excl { Some(false) } else { *existed };
                if creat && existed == Some(false) {
                    r.ops.create += 1;
                    r.before.get_or_insert(false);
                } else if acc != libc::O_RDONLY || creat || flags & libc::O_TRUNC != 0 {
                    r.ops.write += 1;
                    if acc == libc::O_RDWR {
                        r.ops.read += 1;
                    }
                    if !creat || existed == Some(true) {
                        r.before.get_or_insert(true);
                    }
                } else if flags & libc::O_DIRECTORY != 0 {
                    r.ops.list += 1;
                    r.before.get_or_insert(true);
                } else {
                    r.ops.read += 1;
                    r.before.get_or_insert(true);
                }
            }
            Call::Stat { path } => {
                if let Some(r) = self.rec(path, ev.pid) {
                    r.simple(ev.result, |o| &mut o.stat);
                }
            }
            Call::Exec { path, argv } => {
                if let Some(r) = self.rec(path, ev.pid) {
                    r.simple(ev.result, |o| &mut o.exec);
                    if ok {
                        let path = r.path.clone();
                        self.execs.push(Exec {
                            pid: ev.pid,
                            path,
                            argv: argv.clone(),
                        });
                    }
                }
            }
            Call::Truncate { path } => {
                if let Some(r) = self.rec(path, ev.pid) {
                    r.simple(ev.result, |o| &mut o.write);
                }
            }
            Call::Attr { path } => {
                if let Some(r) = self.rec(path, ev.pid) {
                    r.simple(ev.result, |o| &mut o.attr);
                }
            }
            Call::Unlink { path, .. } => {
                if let Some(r) = self.rec(path, ev.pid) {
                    r.simple(ev.result, |o| &mut o.delete);
                }
            }
            Call::Mkdir { path } => self.creation(path, ev),
            Call::Link { from, to, symbolic } => {
                if !symbolic && ok {
                    // The source of a hard link has to exist.
                    if let Some(r) = self.rec(from, ev.pid) {
                        r.simple(Ok(0), |o| &mut o.stat);
                    }
                }
                self.creation(to, ev);
            }
            Call::Rename {
                from,
                to,
                flags,
                to_existed,
            } => {
                let (Some(f), Some(t)) = (self.id(from, ev.pid), self.id(to, ev.pid)) else {
                    return;
                };
                if !ok {
                    self.records[f].failed(ev.result);
                    return;
                }
                if flags & libc::RENAME_EXCHANGE != 0 {
                    for i in [f, t] {
                        self.records[i].ops.write += 1;
                        self.records[i].before.get_or_insert(true);
                    }
                    return;
                }
                let src = &mut self.records[f];
                src.ops.moved_out += 1;
                src.before.get_or_insert(true);
                src.moved_to = Some(t);
                let dst = &mut self.records[t];
                dst.ops.moved_in += 1;
                dst.moved_from = Some(f);
                let existed = if flags & libc::RENAME_NOREPLACE != 0 {
                    Some(false)
                } else {
                    *to_existed
                };
                if let Some(e) = existed {
                    dst.before.get_or_insert(e);
                }
                if existed == Some(false) {
                    dst.ops.create += 1;
                } else {
                    dst.ops.write += 1;
                }
            }
            Call::IoUringSetup => self.io_uring = true,
        }
    }

    /// mkdir, mknod, link and symlink: success means it didn't exist.
    fn creation(&mut self, path: &PathArg, ev: &SysEvent) {
        let Some(r) = self.rec(path, ev.pid) else {
            return;
        };
        match ev.result {
            Ok(_) => {
                r.ops.create += 1;
                r.before.get_or_insert(false);
            }
            Err(libc::EEXIST) => {
                r.ops.stat += 1;
                r.before.get_or_insert(true);
            }
            Err(_) => r.failed(ev.result),
        }
    }

    fn rec(&mut self, arg: &PathArg, pid: i32) -> Option<&mut Record> {
        let i = self.id(arg, pid)?;
        Some(&mut self.records[i])
    }

    fn id(&mut self, arg: &PathArg, pid: i32) -> Option<usize> {
        let path = normalize(&absolute(arg)?);
        let i = match self.index.get(&path) {
            Some(&i) => i,
            None => {
                let i = self.records.len();
                self.index.insert(path.clone(), i);
                self.records.push(Record {
                    path,
                    ops: Ops::default(),
                    errors: Errors::default(),
                    before: None,
                    moved_from: None,
                    moved_to: None,
                    pids: Vec::new(),
                    first_seen: self.seq,
                    first_seen_ms: self.ms,
                    kind_after: None,
                });
                i
            }
        };
        let r = &mut self.records[i];
        if !r.pids.contains(&pid) {
            r.pids.push(pid);
        }
        Some(i)
    }
}

impl Record {
    fn simple(&mut self, result: Result<i64, i32>, op: impl Fn(&mut Ops) -> &mut u32) {
        match result {
            Ok(_) => {
                *op(&mut self.ops) += 1;
                self.before.get_or_insert(true);
            }
            Err(_) => self.failed(result),
        }
    }

    fn failed(&mut self, result: Result<i64, i32>) {
        match result {
            Err(libc::ENOENT | libc::ENOTDIR) => {
                self.errors.missing += 1;
                self.before.get_or_insert(false);
            }
            Err(libc::EACCES | libc::EPERM) => self.errors.denied += 1,
            _ => self.errors.other += 1,
        }
    }
}

/// Paths relative to a directory we couldn't read, or to something that
/// isn't a directory at all (`pipe:[123]`), are dropped.
fn absolute(arg: &PathArg) -> Option<Vec<u8>> {
    if arg.raw.first() == Some(&b'/') {
        return Some(arg.raw.clone());
    }
    let dir = arg.dir.as_ref().filter(|d| d.first() == Some(&b'/'))?;
    let mut p = dir.clone();
    p.push(b'/');
    p.extend_from_slice(&arg.raw);
    Some(p)
}

/// Drops empty and `.` components and applies `..` lexically. That's wrong
/// for `link/..` when `link` is a symlink to another directory, which is
/// rare enough that it isn't worth a stat per path.
pub fn normalize(p: &[u8]) -> Vec<u8> {
    let mut parts: Vec<&[u8]> = Vec::new();
    for c in p.split(|&b| b == b'/') {
        match c {
            b"" | b"." => {}
            b".." => {
                parts.pop();
            }
            c => parts.push(c),
        }
    }
    if parts.is_empty() {
        return b"/".to_vec();
    }
    let mut out = Vec::with_capacity(p.len());
    for c in parts {
        out.push(b'/');
        out.extend_from_slice(c);
    }
    out
}

/// Looks at every path once the command is done.
pub fn enrich(records: &mut [Record]) {
    for r in records {
        r.kind_after = fs::symlink_metadata(OsStr::from_bytes(&r.path))
            .ok()
            .map(|m| {
                let t = m.file_type();
                if t.is_dir() {
                    Kind::Dir
                } else if t.is_symlink() {
                    Kind::Symlink
                } else if t.is_file() {
                    Kind::File
                } else {
                    Kind::Other
                }
            });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalize_is_lexical() {
        assert_eq!(normalize(b"/a//b/./c/"), b"/a/b/c");
        assert_eq!(normalize(b"/a/b/../c"), b"/a/c");
        assert_eq!(normalize(b"/.."), b"/");
    }
}
