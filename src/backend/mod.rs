pub mod ptrace;

/// How the root process ended.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Exit {
    Code(i32),
    Signal(i32),
}

impl Exit {
    /// The status filetap itself exits with: 128 + N for a signal, like a shell.
    pub fn code(self) -> i32 {
        match self {
            Exit::Code(c) => c,
            Exit::Signal(s) => 128 + s,
        }
    }
}

/// One file-related syscall, as the backend saw it. Paths are raw bytes;
/// making them absolute and deciding what the call means is the core's job.
#[derive(Debug, Clone, PartialEq)]
pub struct SysEvent {
    pub pid: i32,
    pub call: Call,
    /// The return value, or the errno.
    pub result: Result<i64, i32>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct PathArg {
    /// What a relative `raw` was resolved against: the cwd or the dirfd's
    /// path. `None` when `raw` is absolute or the directory couldn't be read.
    pub dir: Option<Vec<u8>>,
    pub raw: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq)]
pub enum Call {
    /// `existed` is checked before the syscall runs, only for O_CREAT
    /// without O_EXCL, where the result alone can't tell.
    Open {
        path: PathArg,
        flags: i32,
        existed: Option<bool>,
    },
    /// stat, access, readlink, statfs and friends.
    Stat {
        path: PathArg,
    },
    Exec {
        path: PathArg,
        argv: Vec<Vec<u8>>,
    },
    Rename {
        from: PathArg,
        to: PathArg,
        flags: u32,
        to_existed: Option<bool>,
    },
    Unlink {
        path: PathArg,
        dir: bool,
    },
    /// mkdir and mknod.
    Mkdir {
        path: PathArg,
    },
    /// For a symlink, `from.raw` is the link's contents, not a path we saw
    /// being accessed.
    Link {
        from: PathArg,
        to: PathArg,
        symbolic: bool,
    },
    Truncate {
        path: PathArg,
    },
    /// chmod, chown, utimes, xattrs.
    Attr {
        path: PathArg,
    },
    IoUringSetup,
}
