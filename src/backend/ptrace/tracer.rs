use std::collections::HashMap;
use std::ffi::{CStr, CString};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::os::fd::AsRawFd;
use std::{process, ptr};

use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::ptrace::{self, Options};
use nix::sys::signal::{Signal, kill, raise};
use nix::unistd::{ForkResult, Pid, execv, fork, pipe2};

use super::{Msg, SavedSignals, decode, seccomp};
use crate::backend::{Call, Exit, SysEvent};

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
    t.flush();
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
            if let Err(e) = seccomp::install() {
                // Negative to tell it apart from an execve errno.
                let errno = -e.raw_os_error().unwrap_or(libc::EINVAL);
                let _ = nix::unistd::write(&err_w, &errno.to_ne_bytes());
                // SAFETY: _exit is always safe.
                unsafe { libc::_exit(127) }
            }
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
        let mut buf = [0u8; 4];
        if (&File::from(err_r)).read_exact(&mut buf).is_ok() {
            let errno = Errno::from_raw(-i32::from_ne_bytes(buf));
            return Err(format!("seccomp: {}", errno.desc()));
        }
        return Err("command exited before it could be traced".into());
    }

    let opts = Options::PTRACE_O_TRACEFORK
        | Options::PTRACE_O_TRACEVFORK
        | Options::PTRACE_O_TRACECLONE
        | Options::PTRACE_O_TRACEEXEC
        | Options::PTRACE_O_TRACESECCOMP
        | Options::PTRACE_O_TRACESYSGOOD
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
    tx: Option<BufWriter<File>>,
    root: i32,
    root_resumed: bool,
    root_execed: bool,
    root_done: bool,
    exec_err: File,
    /// tid -> tgid for every live tracee.
    live: HashMap<i32, i32>,
    /// Decoded at the seccomp stop, waiting for the syscall-exit-stop.
    pending: HashMap<i32, Call>,
    procs: u32,
}

impl State {
    fn new(root: i32, exec_err: File, tx: File) -> State {
        State {
            tx: Some(BufWriter::with_capacity(1 << 16, tx)),
            root,
            root_resumed: false,
            root_execed: false,
            root_done: false,
            exec_err,
            live: HashMap::from([(root, root)]),
            pending: HashMap::new(),
            procs: 1,
        }
    }

    /// Buffered: the front only needs events by the time the root process
    /// exits, and that message is flushed right away.
    fn send(&mut self, msg: &Msg) {
        if let Some(tx) = &mut self.tx {
            // The front is gone once it has printed the report; keep tracing
            // the leftovers regardless.
            if tx.write_all(&msg.encode()).is_err() {
                self.tx = None;
            }
        }
    }

    fn flush(&mut self) {
        if let Some(tx) = &mut self.tx
            && tx.flush().is_err()
        {
            self.tx = None;
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
        self.flush();
    }

    fn handle(&mut self, (pid, status): (i32, i32)) {
        if libc::WIFEXITED(status) || libc::WIFSIGNALED(status) {
            self.live.remove(&pid);
            self.pending.remove(&pid);
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
        if sig == libc::SIGTRAP | 0x80 {
            self.syscall_exit(pid);
            return;
        }
        let inject = match status >> 16 {
            0 => sig,
            libc::PTRACE_EVENT_SECCOMP => {
                self.syscall_entry(pid);
                return;
            }
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
                let old = ptrace::getevent(Pid::from_raw(pid)).map_or(pid, |t| t as i32);
                if old != pid {
                    self.live.remove(&old);
                    self.pending.remove(&pid);
                }
                // Report the exec here: the syscall-exit-stop that follows
                // only comes with PTRACE_SYSCALL, and argv is gone by now
                // anyway.
                if let Some(call) = self.pending.remove(&old) {
                    self.emit(pid, call, Ok(0));
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

    fn syscall_entry(&mut self, pid: i32) {
        // Nobody is listening once the front has printed its report; just
        // let the leftovers run.
        if self.tx.is_some()
            && let Some(info) = syscall_info(pid)
            && info.op == PTRACE_SYSCALL_INFO_SECCOMP
        {
            let d = info.data;
            let args = [d[1], d[2], d[3], d[4], d[5], d[6]];
            if let Some(call) = decode::decode(pid, d[0] as i64, args) {
                self.pending.insert(pid, call);
                // Since Linux 4.8 the seccomp stop comes after syscall entry,
                // so PTRACE_SYSCALL from here stops next at syscall exit.
                ptrace_resume(libc::PTRACE_SYSCALL, pid, 0);
                return;
            }
        }
        cont(pid, 0);
    }

    fn syscall_exit(&mut self, pid: i32) {
        if let Some(call) = self.pending.remove(&pid)
            && let Some(info) = syscall_info(pid)
            && info.op == PTRACE_SYSCALL_INFO_EXIT
        {
            let rval = info.data[0] as i64;
            let result = if info.data[1] as u8 != 0 {
                Err(-rval as i32)
            } else {
                Ok(rval)
            };
            // ERESTARTSYS and friends: the syscall runs again and we'll see
            // another seccomp stop for it.
            if !matches!(result, Err(512..=516)) {
                self.emit(pid, call, result);
            }
        }
        cont(pid, 0);
    }

    fn emit(&mut self, tid: i32, call: Call, result: Result<i64, i32>) {
        let pid = self.live.get(&tid).copied().unwrap_or(tid);
        self.send(&Msg::Event(SysEvent { pid, call, result }));
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
                self.flush();
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
        self.flush();
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
    ptrace_resume(libc::PTRACE_CONT, pid, sig);
}

// glibc declares ptrace's request as an unsigned int, musl as an int.
#[cfg(target_env = "musl")]
type Request = libc::c_int;
#[cfg(not(target_env = "musl"))]
type Request = libc::c_uint;

fn ptrace_resume(req: Request, pid: i32, sig: i32) {
    // ESRCH means the tracee was killed while stopped; its exit will show up
    // in the next wait.
    // SAFETY: plain ptrace request; data carries the signal to inject.
    unsafe {
        libc::ptrace(
            req,
            pid,
            ptr::null_mut::<libc::c_void>(),
            sig as libc::c_long,
        )
    };
}

// struct ptrace_syscall_info from <linux/ptrace.h>. libc only has it for
// glibc targets, and we build for musl too.
#[repr(C)]
struct SyscallInfo {
    op: u8,
    _pad: [u8; 3],
    _arch: u32,
    _ip: u64,
    _sp: u64,
    /// entry/seccomp: nr, args[6], ret_data. exit: rval, is_error.
    data: [u64; 8],
}

const PTRACE_GET_SYSCALL_INFO: Request = 0x420e;
const PTRACE_SYSCALL_INFO_EXIT: u8 = 2;
const PTRACE_SYSCALL_INFO_SECCOMP: u8 = 3;

fn syscall_info(pid: i32) -> Option<SyscallInfo> {
    let mut info = SyscallInfo {
        op: 0,
        _pad: [0; 3],
        _arch: 0,
        _ip: 0,
        _sp: 0,
        data: [0; 8],
    };
    // SAFETY: the kernel writes at most size_of::<SyscallInfo>() bytes.
    let r = unsafe {
        libc::ptrace(
            PTRACE_GET_SYSCALL_INFO,
            pid,
            std::mem::size_of::<SyscallInfo>(),
            &mut info as *mut SyscallInfo,
        )
    };
    (r > 0).then_some(info)
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
