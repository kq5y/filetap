//! Turns a syscall stopped at entry into a `Call`: which arguments are paths,
//! what they're relative to, and, for calls that may create a file, whether
//! the target already exists.

use std::ffi::CString;
use std::fs;
use std::os::unix::ffi::OsStrExt;

use crate::backend::{Call, PathArg};

// Not in libc for every target yet.
const SYS_FCHMODAT2: i64 = 452;
#[cfg(target_arch = "x86_64")]
const SYS_RENAMEAT: i64 = libc::SYS_renameat;
#[cfg(target_arch = "aarch64")]
const SYS_RENAMEAT: i64 = 38;

/// Syscalls the seccomp filter stops on. Everything here must be handled in
/// `decode`, or the tracee pays for a stop that produces nothing.
pub const TRACED: &[i64] = &[
    libc::SYS_openat,
    libc::SYS_openat2,
    libc::SYS_newfstatat,
    libc::SYS_statx,
    libc::SYS_faccessat,
    libc::SYS_faccessat2,
    libc::SYS_readlinkat,
    libc::SYS_statfs,
    libc::SYS_execve,
    libc::SYS_execveat,
    libc::SYS_mkdirat,
    libc::SYS_mknodat,
    libc::SYS_unlinkat,
    SYS_RENAMEAT,
    libc::SYS_renameat2,
    libc::SYS_linkat,
    libc::SYS_symlinkat,
    libc::SYS_truncate,
    libc::SYS_fchmodat,
    SYS_FCHMODAT2,
    libc::SYS_fchownat,
    libc::SYS_utimensat,
    libc::SYS_setxattr,
    libc::SYS_lsetxattr,
    libc::SYS_removexattr,
    libc::SYS_lremovexattr,
    libc::SYS_io_uring_setup,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_open,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_creat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_stat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lstat,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_access,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_readlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mkdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_mknod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_rmdir,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_unlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_rename,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_link,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_symlink,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chmod,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_chown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_lchown,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utime,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_utimes,
    #[cfg(target_arch = "x86_64")]
    libc::SYS_futimesat,
];

const CWD: i32 = libc::AT_FDCWD;
const MAX_ARGS: usize = 256;

pub fn decode(tid: i32, nr: i64, a: [u64; 6]) -> Option<Call> {
    let t = Tracee(tid);
    let fd = |i: usize| a[i] as i32;
    let flags = |i: usize| a[i] as i32;

    let call = match nr {
        libc::SYS_openat => t.open(fd(0), a[1], flags(2))?,
        libc::SYS_openat2 => t.open(fd(0), a[1], t.read_u64(a[2])? as i32)?,
        libc::SYS_newfstatat | libc::SYS_statx | libc::SYS_faccessat | libc::SYS_faccessat2 => {
            Call::Stat {
                path: t.path(fd(0), a[1])?,
            }
        }
        libc::SYS_readlinkat => Call::Stat {
            path: t.path(fd(0), a[1])?,
        },
        libc::SYS_statfs => Call::Stat {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_execve => t.exec(CWD, a[0], a[1])?,
        // TODO: execveat(fd, "", ..., AT_EMPTY_PATH) (fexecve) is skipped
        // because the path is empty; resolve it through /proc/<tid>/fd.
        libc::SYS_execveat => t.exec(fd(0), a[1], a[2])?,
        libc::SYS_mkdirat | libc::SYS_mknodat => Call::Mkdir {
            path: t.path(fd(0), a[1])?,
        },
        libc::SYS_unlinkat => Call::Unlink {
            path: t.path(fd(0), a[1])?,
            dir: flags(2) & libc::AT_REMOVEDIR != 0,
        },
        SYS_RENAMEAT => t.rename(fd(0), a[1], fd(2), a[3], 0)?,
        libc::SYS_renameat2 => t.rename(fd(0), a[1], fd(2), a[3], a[4] as u32)?,
        libc::SYS_linkat => Call::Link {
            from: t.path(fd(0), a[1])?,
            to: t.path(fd(2), a[3])?,
            symbolic: false,
        },
        libc::SYS_symlinkat => t.symlink(a[0], fd(1), a[2])?,
        libc::SYS_truncate => Call::Truncate {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_fchmodat | SYS_FCHMODAT2 | libc::SYS_fchownat | libc::SYS_utimensat => {
            Call::Attr {
                path: t.path(fd(0), a[1])?,
            }
        }
        libc::SYS_setxattr
        | libc::SYS_lsetxattr
        | libc::SYS_removexattr
        | libc::SYS_lremovexattr => Call::Attr {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_io_uring_setup => Call::IoUringSetup,
        _ => return decode_legacy(&t, nr, a),
    };
    Some(call)
}

#[cfg(target_arch = "x86_64")]
fn decode_legacy(t: &Tracee, nr: i64, a: [u64; 6]) -> Option<Call> {
    let call = match nr {
        libc::SYS_open => t.open(CWD, a[0], a[1] as i32)?,
        libc::SYS_creat => t.open(CWD, a[0], libc::O_CREAT | libc::O_WRONLY | libc::O_TRUNC)?,
        libc::SYS_stat | libc::SYS_lstat | libc::SYS_access | libc::SYS_readlink => Call::Stat {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_mkdir | libc::SYS_mknod => Call::Mkdir {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_rmdir => Call::Unlink {
            path: t.path(CWD, a[0])?,
            dir: true,
        },
        libc::SYS_unlink => Call::Unlink {
            path: t.path(CWD, a[0])?,
            dir: false,
        },
        libc::SYS_rename => t.rename(CWD, a[0], CWD, a[1], 0)?,
        libc::SYS_link => Call::Link {
            from: t.path(CWD, a[0])?,
            to: t.path(CWD, a[1])?,
            symbolic: false,
        },
        libc::SYS_symlink => t.symlink(a[0], CWD, a[1])?,
        libc::SYS_chmod
        | libc::SYS_chown
        | libc::SYS_lchown
        | libc::SYS_utime
        | libc::SYS_utimes => Call::Attr {
            path: t.path(CWD, a[0])?,
        },
        libc::SYS_futimesat => Call::Attr {
            path: t.path(a[0] as i32, a[1])?,
        },
        _ => return None,
    };
    Some(call)
}

#[cfg(not(target_arch = "x86_64"))]
fn decode_legacy(_: &Tracee, _: i64, _: [u64; 6]) -> Option<Call> {
    None
}

struct Tracee(i32);

impl Tracee {
    fn open(&self, dirfd: i32, addr: u64, flags: i32) -> Option<Call> {
        let path = self.path(dirfd, addr)?;
        // O_TMPFILE creates an unnamed file; the path is only its directory.
        let may_create = flags & libc::O_CREAT != 0
            && flags & libc::O_EXCL == 0
            && flags & libc::O_TMPFILE != libc::O_TMPFILE;
        let existed = if may_create {
            self.exists(dirfd, &path.raw, true)
        } else {
            None
        };
        Some(Call::Open {
            path,
            flags,
            existed,
        })
    }

    fn exec(&self, dirfd: i32, addr: u64, argv: u64) -> Option<Call> {
        Some(Call::Exec {
            path: self.path(dirfd, addr)?,
            argv: self.argv(argv),
        })
    }

    fn rename(&self, olddirfd: i32, old: u64, newdirfd: i32, new: u64, flags: u32) -> Option<Call> {
        let from = self.path(olddirfd, old)?;
        let to = self.path(newdirfd, new)?;
        let to_existed = if flags & libc::RENAME_NOREPLACE == 0 {
            self.exists(newdirfd, &to.raw, false)
        } else {
            None
        };
        Some(Call::Rename {
            from,
            to,
            flags,
            to_existed,
        })
    }

    fn symlink(&self, target: u64, dirfd: i32, addr: u64) -> Option<Call> {
        Some(Call::Link {
            from: PathArg {
                dir: None,
                raw: self.read_cstr(target)?,
            },
            to: self.path(dirfd, addr)?,
            symbolic: true,
        })
    }

    /// Reads a path argument. Empty paths are fd operations (AT_EMPTY_PATH)
    /// or plain ENOENT, and NULL shows up in utimensat(fd, NULL, ...); none of
    /// them name a file.
    fn path(&self, dirfd: i32, addr: u64) -> Option<PathArg> {
        if addr == 0 {
            return None;
        }
        let raw = self.read_cstr(addr)?;
        if raw.is_empty() {
            return None;
        }
        let dir = if raw[0] == b'/' {
            None
        } else {
            self.dir_path(dirfd)
        };
        Some(PathArg { dir, raw })
    }

    fn dir_path(&self, dirfd: i32) -> Option<Vec<u8>> {
        let link = if dirfd == CWD {
            format!("/proc/{}/cwd", self.0)
        } else {
            format!("/proc/{}/fd/{dirfd}", self.0)
        };
        fs::read_link(link)
            .ok()
            .map(|p| p.into_os_string().as_bytes().to_vec())
    }

    /// Checks whether `raw` exists, as the tracee would see it: relative to
    /// its cwd or dirfd, and absolute paths relative to its root, which may
    /// be a chroot. `None` when we can't tell, e.g. no permission to look.
    fn exists(&self, dirfd: i32, raw: &[u8], follow: bool) -> Option<bool> {
        let (base, rel) = if raw[0] == b'/' {
            let rel = &raw[raw.iter().position(|&b| b != b'/').unwrap_or(raw.len())..];
            (
                format!("/proc/{}/root", self.0),
                if rel.is_empty() { b"." } else { rel },
            )
        } else if dirfd == CWD {
            (format!("/proc/{}/cwd", self.0), raw)
        } else {
            (format!("/proc/{}/fd/{dirfd}", self.0), raw)
        };
        let base = CString::new(base).ok()?;
        let rel = CString::new(rel).ok()?;
        // SAFETY: base is a valid C string; the fd is closed below.
        let dfd = unsafe { libc::open(base.as_ptr(), libc::O_PATH | libc::O_CLOEXEC) };
        if dfd < 0 {
            return None;
        }
        // SAFETY: st is only read after fstatat succeeds.
        let mut st = unsafe { std::mem::zeroed::<libc::stat>() };
        let flags = if follow { 0 } else { libc::AT_SYMLINK_NOFOLLOW };
        // SAFETY: valid fd, C string and out pointer.
        let r = unsafe { libc::fstatat(dfd, rel.as_ptr(), &mut st, flags) };
        let err = std::io::Error::last_os_error().raw_os_error();
        // SAFETY: we own dfd.
        unsafe { libc::close(dfd) };
        match (r, err) {
            (0, _) => Some(true),
            (_, Some(libc::ENOENT | libc::ENOTDIR)) => Some(false),
            _ => None,
        }
    }

    fn argv(&self, addr: u64) -> Vec<Vec<u8>> {
        let mut argv = Vec::new();
        if addr == 0 {
            return argv;
        }
        for i in 0..MAX_ARGS as u64 {
            match self.read_u64(addr + i * 8) {
                Some(0) | None => break,
                Some(p) => match self.read_cstr(p) {
                    Some(s) => argv.push(s),
                    None => break,
                },
            }
        }
        argv
    }

    fn read_u64(&self, addr: u64) -> Option<u64> {
        let mut buf = [0u8; 8];
        (self.read(addr, &mut buf)? == 8).then(|| u64::from_ne_bytes(buf))
    }

    /// Reads a NUL-terminated string a page at a time, since a read that
    /// crosses into an unmapped page fails as a whole.
    fn read_cstr(&self, mut addr: u64) -> Option<Vec<u8>> {
        const PAGE: u64 = 4096;
        let mut out = Vec::new();
        let mut buf = [0u8; PAGE as usize];
        while out.len() <= libc::PATH_MAX as usize {
            let n = (PAGE - addr % PAGE) as usize;
            let got = self.read(addr, &mut buf[..n])?;
            if got == 0 {
                return None;
            }
            if let Some(end) = buf[..got].iter().position(|&b| b == 0) {
                out.extend_from_slice(&buf[..end]);
                return Some(out);
            }
            out.extend_from_slice(&buf[..got]);
            addr += got as u64;
        }
        None
    }

    fn read(&self, addr: u64, buf: &mut [u8]) -> Option<usize> {
        let local = libc::iovec {
            iov_base: buf.as_mut_ptr().cast(),
            iov_len: buf.len(),
        };
        let remote = libc::iovec {
            iov_base: addr as *mut libc::c_void,
            iov_len: buf.len(),
        };
        // SAFETY: local points at buf; the remote side is checked by the
        // kernel against the tracee's address space.
        let n = unsafe { libc::process_vm_readv(self.0, &local, 1, &remote, 1, 0) };
        (n >= 0).then_some(n as usize)
    }
}
