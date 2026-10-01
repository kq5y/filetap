mod aggregate;
mod backend;
mod classify;
mod cli;
mod dump;
mod filter;
mod json;
mod launch;
mod live;
mod text;
mod zone;

use std::collections::BTreeMap;
use std::ffi::OsString;
use std::fs::File;
use std::io::{self, Write};
use std::os::unix::ffi::OsStringExt;
use std::path::Path;
use std::process::exit;
use std::sync::atomic::{AtomicBool, AtomicI32, Ordering};
use std::time::{Duration, Instant, SystemTime};

use clap::Parser;
use nix::errno::Errno;
use nix::sys::signal::{SaFlags, SigAction, SigHandler, SigSet, Signal, sigaction};

use aggregate::Aggregator;
use backend::ptrace::{self, Msg, SavedSignals};
use backend::{Exit, SysEvent};

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

    // Before running anything, so a bad --root or glob doesn't waste a run.
    let root = args.root.as_deref().map(|r| {
        std::path::absolute(r).unwrap_or_else(|e| {
            eprintln!("filetap: {}: {}", r.display(), ioerr(&e));
            exit(125);
        })
    });
    let mut ctx = zone::Context::from_env(root.as_deref());
    let filter = filter::Filter::new(&args, &ctx).unwrap_or_else(|e| {
        eprintln!("filetap: {e}");
        exit(125);
    });

    let saved = SavedSignals::capture();
    // Like time(1): Ctrl-C is for the command, which gets it anyway because
    // it's in the same foreground process group.
    for sig in [libc::SIGINT, libc::SIGQUIT] {
        // SAFETY: SIG_IGN is a valid disposition.
        unsafe { libc::signal(sig, libc::SIG_IGN) };
    }
    if args.wait && !saved.is_ignored(libc::SIGINT) {
        // No SA_RESTART: the blocking read has to return so we can stop
        // waiting for background processes.
        let act = SigAction::new(
            SigHandler::Handler(interrupted),
            SaFlags::empty(),
            SigSet::empty(),
        );
        // SAFETY: interrupted only stores to an atomic.
        let _ = unsafe { sigaction(Signal::SIGINT, &act) };
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

    let dump = args.dump_events.as_deref().map(|p| {
        File::create(p).map(io::BufWriter::new).unwrap_or_else(|e| {
            eprintln!("filetap: {}: {}", p.display(), ioerr(&e));
            exit(125);
        })
    });
    let mut sink = Sink {
        dump,
        live: args
            .live
            .then(|| live::Live::new(args.all, use_color(args.color, None))),
        agg: Aggregator::default(),
        warnings: Vec::new(),
        procs: Default::default(),
        started: Instant::now(),
    };

    let cfg = ptrace::Config {
        seccomp: !args.no_seccomp,
        live: args.live,
    };
    let mut rx = match ptrace::start(&prog, &args.command, &saved, cfg) {
        Ok(t) => io::BufReader::with_capacity(1 << 16, t),
        Err(e) => {
            eprintln!("filetap: {e:#}");
            exit(125);
        }
    };
    let started = Instant::now();
    let started_at = SystemTime::now();

    let (exit_status, mut procs, mut running) = loop {
        match Msg::read(&mut rx) {
            Ok(Some(Msg::Event(ev))) => sink.event(&ev, &mut ctx, &filter),
            Ok(Some(Msg::Warning(w))) => sink.warnings.push(w),
            Ok(Some(Msg::Spawn { parent, child })) => {
                sink.procs.entry(child).or_default().ppid = Some(parent);
            }
            Ok(Some(Msg::ProcExit { pid, exit })) => {
                sink.procs.entry(pid).or_default().exit = Some(exit)
            }
            Ok(Some(Msg::Started { pid })) => {
                sink.procs.entry(pid).or_default();
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

    let elapsed = started.elapsed();
    sink.procs
        .entry(ROOT.load(Ordering::SeqCst))
        .or_default()
        .exit = Some(exit_status);

    let mut gave_up = false;
    if args.wait && !running.is_empty() {
        // Only a Ctrl-C after the command itself is done means "stop waiting".
        INTERRUPTED.store(false, Ordering::SeqCst);
        loop {
            match Msg::read(&mut rx) {
                Ok(Some(Msg::Done { procs: n })) => {
                    procs = n;
                    running.clear();
                    break;
                }
                Ok(Some(Msg::Event(ev))) => sink.event(&ev, &mut ctx, &filter),
                Ok(Some(Msg::Warning(w))) => sink.warnings.push(w),
                Ok(Some(Msg::Spawn { parent, child })) => {
                    sink.procs.entry(child).or_default().ppid = Some(parent);
                }
                Ok(Some(Msg::ProcExit { pid, exit })) => {
                    sink.procs.entry(pid).or_default().exit = Some(exit)
                }
                Ok(Some(_)) => {}
                Err(e)
                    if e.kind() == io::ErrorKind::Interrupted
                        && !INTERRUPTED.load(Ordering::SeqCst) => {}
                Ok(None) | Err(_) => {
                    running.clear();
                    gave_up = true;
                    break;
                }
            }
        }
    }

    if let Some(d) = &mut sink.dump {
        let _ = d.flush();
    }

    let mut records = sink.agg.records;
    aggregate::enrich(&mut records, args.json);
    for r in &records {
        if r.ops.exec > 0 {
            ctx.exec_seen(&r.path);
        }
    }
    let mut classes = classify::classify(&records, &ctx);
    filter.apply(&records, &mut classes, &ctx);

    let mut warnings = sink.warnings.clone();
    if !running.is_empty() {
        warnings.push(format!(
            "{} background processes still running; their later file access is not in this report",
            running.len()
        ));
    }
    if gave_up {
        warnings.push("stopped waiting for background processes".to_string());
    }
    if sink.agg.io_uring {
        warnings
            .push("the command set up io_uring; file access through it is not seen".to_string());
    }

    let names = sink
        .agg
        .execs
        .iter()
        .map(|e| {
            let name = e.path.rsplit(|&b| b == b'/').next().unwrap_or(&e.path);
            (e.pid, String::from_utf8_lossy(name).into_owned())
        })
        .collect();
    let mut report = text::Report {
        records: &records,
        classes: &classes,
        ctx: &ctx,
        all: args.all,
        verbose: args.verbose,
        by_path: args.sort == cli::Sort::Path,
        names,
        color: use_color(args.color, args.output.as_deref()),
        pid: None,
    };
    let (mut out, shared) = report_writer(args.output.as_deref());
    if args.json {
        let run = json::Run {
            command: &args.command,
            started_at,
            duration: elapsed,
            exit: exit_status,
            complete: !gave_up,
            filters: filter.to_json(),
            seccomp: !args.no_seccomp,
            execs: &sink.agg.execs,
            procs: &sink.procs,
            warnings,
        };
        let _ = json::write(&mut out, &run, &records, &classes, &ctx, &report.folded());
        let _ = out.flush();
        exit(exit_status.code());
    }
    if shared {
        // Separates the report from whatever the command printed last.
        let _ = writeln!(out);
    }
    let _ = header(
        &mut out,
        &args.command,
        exit_status,
        elapsed,
        procs,
        &running,
        &filter.described,
    );
    if gave_up {
        let _ = writeln!(
            out,
            "filetap: stopped waiting for background processes; their later file access is not in this report"
        );
    }
    for w in &sink.warnings {
        let _ = writeln!(out, "filetap: {w}");
    }
    // libuv sets up io_uring in every node process just to batch epoll
    // calls, so saying this by default would mostly be a false alarm.
    if sink.agg.io_uring && args.all {
        let _ = writeln!(
            out,
            "filetap: the command set up io_uring; file access through it is not in this report"
        );
    }
    if args.by_process {
        let _ = by_process(&mut out, &mut report, &sink.procs, &sink.agg.execs);
    } else {
        let _ = report.write(&mut out);
    }
    let _ = out.flush();
    exit(exit_status.code());
}

/// Each process that did anything worth showing, under a line that says
/// which one it is, then the summary for the whole run.
fn by_process(
    w: &mut dyn Write,
    report: &mut text::Report,
    procs: &BTreeMap<i32, json::Proc>,
    execs: &[aggregate::Exec],
) -> io::Result<()> {
    for (&pid, p) in procs {
        report.pid = Some(pid);
        let mut buf = Vec::new();
        report.write_sections(&mut buf)?;
        if buf.is_empty() {
            continue;
        }
        let title = match execs.iter().rev().find(|e| e.pid == pid) {
            Some(e) => {
                let argv: Vec<OsString> = e
                    .argv
                    .iter()
                    .map(|a| OsString::from_vec(a.clone()))
                    .collect();
                format!("{}[{pid}] {}", report.names[&pid], command_line(&argv))
            }
            None => {
                // A fork that never exec'd runs whatever its parent runs.
                let parent = p.ppid.map_or(String::new(), |pp| {
                    let name = report.names.get(&pp).map_or("", String::as_str);
                    format!(", a fork of {name}[{pp}]")
                });
                format!("[{pid}]{parent}")
            }
        };
        writeln!(w)?;
        writeln!(w, "{}", report.bold(&title))?;
        for line in String::from_utf8_lossy(&buf).lines() {
            if line.is_empty() {
                writeln!(w)?;
            } else {
                writeln!(w, "  {line}")?;
            }
        }
    }
    report.pid = None;
    report.summary(w)
}

/// Opened only after the command is done, so a command that reads the
/// report file (or its directory) doesn't see it truncated. The flag says
/// whether the report shares a stream with the command's own output.
fn report_writer(path: Option<&Path>) -> (Box<dyn Write>, bool) {
    match path {
        None => (Box::new(io::stderr()), true),
        Some(p) if p == Path::new("-") => (Box::new(io::stdout()), true),
        Some(p) => match File::create(p) {
            Ok(f) => (Box::new(io::BufWriter::new(f)), false),
            Err(e) => {
                eprintln!(
                    "filetap: {}: {}; writing the report to stderr",
                    p.display(),
                    ioerr(&e)
                );
                (Box::new(io::stderr()), true)
            }
        },
    }
}

struct Sink {
    dump: Option<io::BufWriter<File>>,
    live: Option<live::Live>,
    agg: Aggregator,
    warnings: Vec<String>,
    procs: BTreeMap<i32, json::Proc>,
    started: Instant,
}

impl Sink {
    fn event(&mut self, ev: &SysEvent, ctx: &mut zone::Context, filter: &filter::Filter) {
        if let Some(d) = &mut self.dump {
            let _ = dump::write_event(d, ev);
        }
        self.agg.add(ev, self.started.elapsed().as_millis() as u64);
        if let Some(l) = &mut self.live {
            l.update(&self.agg.records, &self.agg.touched, ctx, filter);
        }
    }
}

fn use_color(when: cli::Color, output: Option<&Path>) -> bool {
    let fd = match output {
        None => libc::STDERR_FILENO,
        Some(p) if p == Path::new("-") => libc::STDOUT_FILENO,
        Some(_) => return when == cli::Color::Always,
    };
    match when {
        cli::Color::Always => true,
        cli::Color::Never => false,
        cli::Color::Auto => {
            // https://no-color.org
            let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
            let dumb = std::env::var_os("TERM").is_some_and(|t| t == "dumb");
            // SAFETY: isatty only looks at the fd.
            !no_color && !dumb && unsafe { libc::isatty(fd) } == 1
        }
    }
}

static ROOT: AtomicI32 = AtomicI32::new(0);
static PENDING: AtomicI32 = AtomicI32::new(0);
static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn interrupted(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

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
    w: &mut dyn Write,
    command: &[OsString],
    exit: Exit,
    elapsed: Duration,
    procs: u32,
    running: &[(i32, String)],
    filters: &[String],
) -> io::Result<()> {
    let cmd = command_line(command);
    let how = match exit {
        Exit::Code(c) => format!("exited {c}"),
        Exit::Signal(s) => format!("was killed by {}", signame(s)),
    };
    let plural = if procs == 1 { "process" } else { "processes" };
    let filtered = if filters.is_empty() {
        String::new()
    } else {
        format!(" (filtered: {})", filters.join(", "))
    };
    writeln!(
        w,
        "filetap: {cmd} {how} after {:.2}s ({procs} {plural}){filtered}",
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

/// The command as a shell would take it back, cut short if it's long: a
/// `sh -c` script shouldn't take over the header.
fn command_line(command: &[OsString]) -> String {
    const MAX: usize = 60;
    let quoted: Vec<String> = command
        .iter()
        .map(|a| {
            let a = a.to_string_lossy();
            let plain = !a.is_empty()
                && a.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "-_./=:,+@%".contains(c));
            if plain {
                a.into_owned()
            } else {
                format!("'{}'", a.replace('\'', "'\\''"))
            }
        })
        .collect();
    let line: String = quoted.join(" ").replace('\n', "\\n").replace('\t', " ");
    if line.chars().count() <= MAX {
        return line;
    }
    let cut: String = line.chars().take(MAX - 3).collect();
    format!("{}...", cut.trim_end())
}

fn signame(sig: i32) -> String {
    match Signal::try_from(sig) {
        Ok(s) => s.as_str().to_string(),
        Err(_) => format!("signal {sig}"),
    }
}

fn ioerr(e: &io::Error) -> String {
    match e.raw_os_error() {
        Some(n) => lower(Errno::from_raw(n).desc()),
        None => e.to_string(),
    }
}

fn lower(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_lowercase().chain(c).collect(),
        None => String::new(),
    }
}
