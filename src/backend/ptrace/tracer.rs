use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::os::fd::AsRawFd;
use std::{process, ptr};

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{Signal, kill, raise};
use nix::unistd::{ForkResult, Pid, execv, fork, pipe2};

use super::{Msg, SavedSignals};
use crate::backend::Exit;

pub fn run(prog: &CStr, argv: &[CString], saved: &SavedSignals, tx: File) -> ! {
    // The tracer must survive anything aimed at the command's process group:
    // Ctrl-C, Ctrl-Z, hangups. If it stopped, every tracee would stall in its
    // next ptrace-stop.
    for sig in [
        libc::SIGINT,
        libc::SIGQUIT,
        libc::SIGTERM,
        libc::SIGHUP,
        libc::SIGTSTP,
        libc::SIGTTIN,
        libc::SIGTTOU,
        libc::SIGPIPE,
    ] {
        // SAFETY: SIG_IGN is a valid disposition for all of these.
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }

    let mut t = match launch(prog, argv, saved) {
        Ok((root, exec_err)) => State::new(root, exec_err, tx),
        Err(e) => {
            let _ = (&tx).write_all(&Msg::Failed(e).encode());
            process::exit(1);
        }
    };
    t.send(&Msg::Started { pid: t.root });
    detach_stdio();
    t.trace();
    process::exit(0);
}

/// Starts the command stopped, seizes it and lets it run to its execve.
fn launch(prog: &CStr, argv: &[CString], saved: &SavedSignals) -> Result<(i32, File), String> {
    let (err_r, err_w) = pipe2(OFlag::O_CLOEXEC).map_err(|e| format!("pipe: {e}"))?;
    // SAFETY: the tracer is single-threaded.
    let child = match unsafe { fork() }.map_err(|e| format!("fork: {e}"))? {
        ForkResult::Child => {
            drop(err_r);
            saved.restore();
            let _ = raise(Signal::SIGSTOP);
            let e = execv(prog, argv).unwrap_err();
            let _ = nix::unistd::write(&err_w, &(e as i32).to_ne_bytes());
            // SAFETY: _exit is always safe; skip the front's atexit handlers.
            unsafe { libc::_exit(127) }
        }
        ForkResult::Parent { child } => child,
    };
    drop(err_w);

    let (_, status) = wait(child.as_raw(), libc::WUNTRACED).map_err(|e| format!("waitpid: {e}"))?;
    if !libc::WIFSTOPPED(status) {
        return Err("command exited before it could be traced".into());
    }

    let opts = Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_EXITKILL;
    if let Err(e) = ptrace::seize(child, opts) {
        let _ = kill(child, Signal::SIGKILL);
        let _ = wait(child.as_raw(), 0);
        return Err(seize_error(e));
    }
    let _ = kill(child, Signal::SIGCONT);
    Ok((child.as_raw(), File::from(err_r)))
}

fn seize_error(e: Errno) -> String {
    if e != Errno::EPERM {
        return format!("ptrace: {}", e.desc());
    }
    match fs::read_to_string("/proc/sys/kernel/yama/ptrace_scope") {
        Ok(s) if s.trim() == "3" => "ptrace not permitted (kernel.yama.ptrace_scope = 3)".into(),
        _ => "ptrace not permitted".into(),
    }
}

/// The command has the real stdio; the tracer holding on to it would keep a
/// pipe like `filetap -- cmd | less` open for as long as it lingers.
fn detach_stdio() {
    let Ok(null) = File::options().read(true).write(true).open("/dev/null") else {
        return;
    };
    for fd in 0..3 {
        // SAFETY: dup2 onto the standard descriptors; nothing in the tracer
        // holds Rust-level ownership of them.
        unsafe { libc::dup2(null.as_raw_fd(), fd) };
    }
}

struct State {
    tx: Option<File>,
    root: i32,
    root_resumed: bool,
    root_execed: bool,
    root_done: bool,
    exec_err: File,
    /// tid -> tgid for every live tracee.
    live: HashMap<i32, i32>,
    procs: u32,
}

impl State {
    fn new(root: i32, exec_err: File, tx: File) -> State {
        State {
            tx: Some(tx),
            root,
            root_resumed: false,
            root_execed: false,
            root_done: false,
            exec_err,
            live: HashMap::from([(root, root)]),
            procs: 1,
        }
    }

    fn send(&mut self, msg: &Msg) {
        if let Some(tx) = &mut self.tx {
            // The front is gone once it has printed the report; keep tracing
            // the leftovers regardless.
            if tx.write_all(&msg.encode()).is_err() {
                self.tx = None;
            }
        }
    }

    fn trace(&mut self) {
        loop {
            match wait(-1, libc::__WALL) {
                Ok(status) => self.handle(status),
                Err(Errno::EINTR) => continue,
                Err(_) => break,
            }
        }
        let procs = self.procs;
        self.send(&Msg::Done { procs });
    }

    fn handle(&mut self, (pid, status): (i32, i32)) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.live.remove(&pid);
            if pid == self.root {
                let exit = if libc::WIFEXITED(status) {
                    Exit::Code(libc::WEXITSTATUS(status))
                } else {
                    Exit::Signal(libc::WTERMSIG(status))
                };
                self.root_exited(exit);
            }
            return;
        }
        if !libc::WIFSTOPPED(status) {
            return;
        }
        self.seen(pid);

        let sig = libc::WSTOPSIG(status);
        let inject = match status >> 16 {
            0 => sig,
            libc::PTRACE_EVENT_STOP => {
                // The root was already stopped (by its own SIGSTOP) when we
                // seized it, so its first stop looks like a group-stop.
                // PTRACE_LISTEN here can leave it stopped forever if our
                // SIGCONT already arrived.
                if pid == self.root && !self.root_resumed {
                    self.root_resumed = true;
                    0
                } else if matches!(
                    sig,
                    libc::SIGSTOP | libc::SIGTSTP | libc::SIGTTIN | libc::SIGTTOU
                ) {
                    // ptrace(2) "Group-stop": with PTRACE_SEIZE the tracee
                    // must stay stopped until SIGCONT, which PTRACE_LISTEN
                    // does. PTRACE_CONT would break Ctrl-Z.
                    // SAFETY: plain ptrace request on a tracee in a stop.
                    unsafe {
                        libc::ptrace(
                            libc::PTRACE_LISTEN,
                            pid,
                            ptr::null_mut::<libc::c_void>(),
                            ptr::null_mut::<libc::c_void>(),
                        )
                    };
                    return;
                } else {
                    0
                }
            }
            libc::PTRACE_EVENT_FORK | libc::PTRACE_EVENT_VFORK | libc::PTRACE_EVENT_CLONE => {
                if let Ok(child) = ptrace::getevent(Pid::from_raw(pid)) {
                    self.seen(child as i32);
                }
                0
            }
            libc::PTRACE_EVENT_EXEC => {
                // A non-leader thread that execs takes over the leader's tid;
                // the old tid never reports an exit.
                if let Ok(old) = ptrace::getevent(Pid::from_raw(pid))
                    && old as i32 != pid
                {
                    self.live.remove(&(old as i32));
                }
                if pid == self.root {
                    self.root_execed = true;
                }
                0
            }
            _ => 0,
        };
        cont(pid, inject);
    }

    /// Registers a tracee the first time any stop or event mentions it. A new
    /// child's first stop can arrive before its parent's fork event.
    fn seen(&mut self, tid: i32) {
        if self.live.contains_key(&tid) {
            return;
        }
        let tgid = read_tgid(tid).unwrap_or(tid);
        self.live.insert(tid, tgid);
        if tgid == tid {
            self.procs += 1;
        }
    }

    fn root_exited(&mut self, exit: Exit) {
        if self.root_done {
            return;
        }
        self.root_done = true;
        if !self.root_execed {
            let mut buf = [0u8; 4];
            if self.exec_err.read_exact(&mut buf).is_ok() {
                self.send(&Msg::ExecFailed {
                    errno: i32::from_ne_bytes(buf),
                });
                return;
            }
        }

        let mut pids: Vec<i32> = self
            .live
            .values()
            .copied()
            .filter(|&tgid| tgid != self.root)
            .collect();
        pids.sort();
        pids.dedup();
        let running = pids.into_iter().map(|pid| (pid, comm(pid))).collect();
        let procs = self.procs;
        self.send(&Msg::RootExit {
            exit,
            procs,
            running,
        });
    }
}

// Wait statuses are decoded by hand instead of with nix's WaitStatus: its
// Signal enum can't represent realtime signals, and glibc itself sends one
// (SIGSETXID) to every thread when a threaded program calls setuid().
fn wait(pid: i32, flags: i32) -> Result<(i32, i32), Errno> {
    let mut status = 0;
    // SAFETY: status is a valid out pointer.
    let r = unsafe { libc::waitpid(pid, &mut status, flags) };
    if r < 0 {
        Err(Errno::last())
    } else {
        Ok((r, status))
    }
}

fn cont(pid: i32, sig: i32) {
    // ESRCH means the tracee was killed while stopped; its exit will show up
    // in the next wait.
    // SAFETY: plain ptrace request; data carries the signal to inject.
    unsafe {
        libc::ptrace(
            libc::PTRACE_CONT,
            pid,
            ptr::null_mut::<libc::c_void>(),
            sig as libc::c_long,
        )
    };
}

fn read_tgid(tid: i32) -> Option<i32> {
    let status = fs::read_to_string(format!("/proc/{tid}/status")).ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("Tgid:"))
        .and_then(|v| v.trim().parse().ok())
}

fn comm(pid: i32) -> String {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .map(|s| s.trim_end().to_string())
        .unwrap_or_else(|_| "?".into())
}
