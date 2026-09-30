//! Native backend: a separate tracer process that follows the command with
//! ptrace(2).
//!
//! The tracer is a fork of the front rather than a thread so that it can
//! outlive it: when the root process exits the front prints the report and
//! returns to the shell, while the tracer keeps servicing any daemonized
//! descendants until they are gone.

mod msg;
mod tracer;

use std::ffi::{CString, OsString};
use std::fs::File;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::{mem, ptr};

use anyhow::{Context, Result};
use nix::fcntl::OFlag;
use nix::unistd::{ForkResult, fork, pipe2};

pub use msg::Msg;

/// Signals the front or the tracer change the disposition of. The command
/// gets the original dispositions back before exec.
const SIGNALS: [i32; 8] = [
    libc::SIGINT,
    libc::SIGQUIT,
    libc::SIGTERM,
    libc::SIGHUP,
    libc::SIGTSTP,
    libc::SIGTTIN,
    libc::SIGTTOU,
    libc::SIGPIPE,
];

pub struct SavedSignals(Vec<(i32, libc::sigaction)>);

impl SavedSignals {
    /// Must run before the front installs its own handlers.
    pub fn capture() -> SavedSignals {
        let mut saved = Vec::new();
        for sig in SIGNALS {
            // SAFETY: a null new action only queries the current one.
            unsafe {
                let mut old: libc::sigaction = mem::zeroed();
                if libc::sigaction(sig, ptr::null(), &mut old) == 0 {
                    saved.push((sig, old));
                }
            }
        }
        SavedSignals(saved)
    }

    fn restore(&self) {
        for (sig, act) in &self.0 {
            // Rust's runtime ignores SIGPIPE before main; the command
            // should get the default like std::process::Command does.
            let mut act = *act;
            if *sig == libc::SIGPIPE {
                act.sa_sigaction = libc::SIG_DFL;
            }
            // SAFETY: act is a disposition we read with sigaction(2) earlier.
            unsafe { libc::sigaction(*sig, &act, ptr::null_mut()) };
        }
    }
}

/// Forks the tracer, which in turn starts `prog` with `argv` under ptrace.
/// Returns the read end of the pipe the tracer reports on.
///
/// Must be called while the process is still single-threaded.
pub fn start(prog: &Path, argv: &[OsString], saved: &SavedSignals) -> Result<File> {
    let prog = CString::new(prog.as_os_str().as_bytes()).context("command contains a NUL byte")?;
    let argv = argv
        .iter()
        .map(|a| CString::new(a.as_bytes()))
        .collect::<Result<Vec<_>, _>>()
        .context("argument contains a NUL byte")?;

    let (rx, tx) = pipe2(OFlag::O_CLOEXEC).context("pipe")?;
    // SAFETY: the front has not started any threads yet.
    match unsafe { fork() }.context("fork")? {
        ForkResult::Child => {
            drop(rx);
            tracer::run(&prog, &argv, saved, File::from(tx))
        }
        ForkResult::Parent { .. } => Ok(File::from(rx)),
    }
}
