mod backend;
mod cli;
mod launch;

use std::ffi::OsString;
use std::io::{self, Write};
use std::process::exit;
use std::sync::atomic::{AtomicI32, Ordering};
use std::time::{Duration, Instant};

use clap::Parser;
use nix::errno::Errno;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

use backend::Exit;
use backend::ptrace::{self, Msg, SavedSignals};

fn main() {
    // Usage errors exit with 125 like env(1) and timeout(1), so they can't be
    // mistaken for the command's own exit status.
    let args = cli::Args::try_parse().unwrap_or_else(|e| {
        let _ = e.print();
        exit(if e.use_stderr() { 125 } else { 0 });
    });

    let path_var = std::env::var_os("PATH");
    let prog = match launch::resolve(&args.command[0], path_var.as_deref()) {
        Ok(p) => p,
        Err(e) => {
            eprintln!("filetap: {e}");
            exit(e.exit_code());
        }
    };

    let saved = SavedSignals::capture();
    // Like time(1): Ctrl-C is for the command, which gets it anyway because
    // it's in the same foreground process group.
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: SIG_IGN is a valid disposition.
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
    // Unlike Ctrl-C, these are usually sent to filetap alone (kill, a CI
    // runner's timeout, a closed ssh session), so pass them on.
    for sig in [Signal::SIGTERM, Signal::SIGHUP] {
        if saved.is_ignored(sig as i32) {
            continue;
        }
        let act = SigAction::new(
            SigHandler::Handler(forward),
            SaFlags::SA_RESTART,
            SigSet::empty(),
        );
        // SAFETY: forward only touches atomics and calls kill(2).
        let _ = unsafe { sigaction(sig, &act) };
    }

    let mut rx = match ptrace::start(&prog, &args.command, &saved) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("filetap: {e:#}");
            exit(125);
        }
    };
    let started = Instant::now();

    let (exit_status, procs, running) = loop {
        match Msg::read(&mut rx) {
            Ok(Some(Msg::Started { pid })) => {
                ROOT.store(pid, Ordering::SeqCst);
                let sig = PENDING.swap(0, Ordering::SeqCst);
                if sig != 0 {
                    // SAFETY: plain kill(2).
                    unsafe { libc::kill(pid, sig) };
                }
            }
            Ok(Some(Msg::Failed(e))) => {
                eprintln!("filetap: {e}");
                exit(125);
            }
            Ok(Some(Msg::ExecFailed { errno })) => {
                let errno = Errno::from_raw(errno);
                eprintln!("filetap: {}: {}", prog.display(), lower(errno.desc()));
                exit(if errno == Errno::ENOENT { 127 } else { 126 });
            }
            Ok(Some(Msg::RootExit {
                exit,
                procs,
                running,
            })) => break (exit, procs, running),
            Ok(Some(Msg::Done { .. })) | Ok(None) => {
                eprintln!("filetap: tracer exited unexpectedly");
                exit(125);
            }
            Err(e) if e.kind() == io::ErrorKind::Interrupted => {}
            Err(e) => {
                eprintln!("filetap: reading from tracer: {e}");
                exit(125);
            }
        }
    };

    let mut out = io::stderr().lock();
    let _ = header(
        &mut out,
        &args.command,
        exit_status,
        started.elapsed(),
        procs,
        &running,
    );
    exit(exit_status.code());
}

static ROOT: AtomicI32 = AtomicI32::new(0);
static PENDING: AtomicI32 = AtomicI32::new(0);

extern "C" fn forward(sig: libc::c_int) {
    match ROOT.load(Ordering::SeqCst) {
        0 => PENDING.store(sig, Ordering::SeqCst),
        // SAFETY: kill(2) is async-signal-safe.
        pid => unsafe {
            libc::kill(pid, sig);
        },
    }
}

fn header(
    w: &mut impl Write,
    command: &[OsString],
    exit: Exit,
    elapsed: Duration,
    procs: u32,
    running: &[(i32, String)],
) -> io::Result<()> {
    let cmd = command
        .iter()
        .map(|a| a.to_string_lossy())
        .collect::<Vec<_>>()
        .join(" ");
    let how = match exit {
        Exit::Code(c) => format!("exited {c}"),
        Exit::Signal(s) => format!("was killed by {}", signame(s)),
    };
    let plural = if procs == 1 { "process" } else { "processes" };
    writeln!(w)?;
    writeln!(
        w,
        "filetap: {cmd} {how} after {:.2}s ({procs} {plural})",
        elapsed.as_secs_f64()
    )?;
    if !running.is_empty() {
        let list = running
            .iter()
            .map(|(pid, comm)| format!("{comm}[{pid}]"))
            .collect::<Vec<_>>()
            .join(", ");
        let (n, what) = match running.len() {
            1 => (1, "background process"),
            n => (n, "background processes"),
        };
        writeln!(
            w,
            "filetap: {n} {what} still running ({list}); their later file access is not in this report"
        )?;
    }
    Ok(())
}

fn signame(sig: i32) -> String {
    match Signal::try_from(sig) {
        Ok(s) => s.as_str().to_string(),
        Err(_) => format!("signal {sig}"),
    }
}

fn lower(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}
