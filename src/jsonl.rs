//! --jsonl: one JSON line per file access, as it happens, instead of the
//! report. Paths are absolute and each syscall is reduced to what it did.
//! Unlike --dump-events this is meant for other tools: fields can be added,
//! but not removed or changed.

use std::borrow::Cow;
use std::io::Write;

use nix::errno::Errno;
use serde::Serialize;

use crate::aggregate;
use crate::backend::{Call, Exit, PathArg, SysEvent};
use crate::classify::Bucket;
use crate::filter::Filter;
use crate::json::{base64, lossy};
use crate::zone::Context;

pub struct Stream {
    w: Box<dyn Write>,
}

#[derive(Serialize, Default)]
struct Line<'a> {
    ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pid: Option<i32>,
    op: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    path: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    zone: Option<&'static str>,
    /// rename: where it went.
    #[serde(skip_serializing_if = "Option::is_none")]
    to: Option<Cow<'a, str>>,
    /// link: the existing file; symlink: the target as written.
    #[serde(skip_serializing_if = "Option::is_none")]
    target: Option<Cow<'a, str>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    argv: Option<Vec<Cow<'a, str>>>,
    /// Like `ENOENT`; absent when the call worked.
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    ppid: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    signal: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    message: Option<&'a str>,
}

impl Stream {
    pub fn new(w: Box<dyn Write>) -> Stream {
        Stream { w }
    }

    pub fn event(&mut self, ev: &SysEvent, ms: u64, ctx: &Context, filter: &Filter) {
        let Some((op, path)) = op(&ev.call) else {
            return;
        };
        let mut line = Line {
            ms,
            pid: Some(ev.pid),
            op,
            error: ev.result.err().map(errno),
            ..Default::default()
        };
        if let Some(path) = path {
            let Some(abs) = absolute(path) else {
                return;
            };
            let shown = filter.shows(&abs);
            if !filter.keeps(&abs, shown, bucket(op, ev.result), ctx) {
                return;
            }
            line.zone = Some(ctx.zone(&abs).name());
            line.path_b64 = std::str::from_utf8(&abs).is_err().then(|| base64(&abs));
            line.path = Some(Cow::Owned(lossy(&abs).into_owned()));
        }
        match &ev.call {
            Call::Rename { to, .. } => {
                line.to = absolute(to).map(|p| lossy(&p).into_owned().into())
            }
            Call::Link {
                from,
                symbolic: false,
                ..
            } => line.target = absolute(from).map(|p| lossy(&p).into_owned().into()),
            Call::Link { from, .. } => line.target = Some(lossy(&from.raw)),
            Call::Exec { argv, .. } => line.argv = Some(argv.iter().map(|a| lossy(a)).collect()),
            _ => {}
        }
        self.write(&line);
    }

    pub fn spawn(&mut self, ms: u64, pid: i32, ppid: Option<i32>) {
        self.write(&Line {
            ms,
            pid: Some(pid),
            op: "spawn",
            ppid,
            ..Default::default()
        });
    }

    pub fn exit(&mut self, ms: u64, pid: i32, exit: Exit) {
        let (code, signal) = match exit {
            Exit::Code(c) => (Some(c), None),
            Exit::Signal(s) => (None, Some(s)),
        };
        self.write(&Line {
            ms,
            pid: Some(pid),
            op: "exit",
            code,
            signal,
            ..Default::default()
        });
    }

    /// Something the report would say at the top, like a setuid program
    /// that ran without its privileges.
    pub fn warning(&mut self, ms: u64, message: &str) {
        self.write(&Line {
            ms,
            op: "warning",
            message: Some(message),
            ..Default::default()
        });
    }

    pub fn flush(&mut self) {
        let _ = self.w.flush();
    }

    fn write(&mut self, line: &Line) {
        let _ = serde_json::to_writer(&mut self.w, line);
        let _ = self.w.write_all(b"\n");
    }
}

/// What the call did, and the path it did it to.
fn op(call: &Call) -> Option<(&'static str, Option<&PathArg>)> {
    Some(match call {
        Call::Open {
            path,
            flags,
            existed,
        } => {
            let creat = flags & libc::O_CREAT != 0;
            let op = if flags & libc::O_PATH != 0 {
                "stat"
            } else if flags & libc::O_TMPFILE == libc::O_TMPFILE {
                // An unnamed file; the path is only its directory.
                return None;
            } else if creat && (flags & libc::O_EXCL != 0 || *existed == Some(false)) {
                "create"
            } else if flags & libc::O_ACCMODE != libc::O_RDONLY
                || creat
                || flags & libc::O_TRUNC != 0
            {
                "write"
            } else if flags & libc::O_DIRECTORY != 0 {
                "list"
            } else {
                "read"
            };
            (op, Some(path))
        }
        Call::Stat { path } => ("stat", Some(path)),
        Call::Exec { path, .. } => ("exec", Some(path)),
        Call::Rename { from, .. } => ("rename", Some(from)),
        Call::Unlink { path, .. } => ("delete", Some(path)),
        Call::Mkdir { path } => ("mkdir", Some(path)),
        Call::Link {
            to, symbolic: true, ..
        } => ("symlink", Some(to)),
        Call::Link { to, .. } => ("link", Some(to)),
        Call::Truncate { path } => ("write", Some(path)),
        Call::Attr { path } => ("attr", Some(path)),
        Call::IoUringSetup => ("io_uring_setup", None),
    })
}

/// The report section an event would count towards, for the filters.
fn bucket(op: &str, result: Result<i64, i32>) -> Bucket {
    match result {
        Err(libc::ENOENT | libc::ENOTDIR) => return Bucket::Missing,
        Err(libc::EACCES | libc::EPERM) => return Bucket::Denied,
        _ => {}
    }
    match op {
        "read" | "list" => Bucket::Read,
        "write" | "attr" => Bucket::Write,
        "create" | "mkdir" | "link" | "symlink" => Bucket::Create,
        "delete" => Bucket::Delete,
        "rename" => Bucket::Rename,
        "exec" => Bucket::Exec,
        _ => Bucket::Stat,
    }
}

fn absolute(p: &PathArg) -> Option<Vec<u8>> {
    aggregate::absolute(p).map(|p| aggregate::normalize(&p))
}

fn errno(e: i32) -> String {
    match Errno::from_raw(e) {
        Errno::UnknownErrno => e.to_string(),
        e => format!("{e:?}"),
    }
}
