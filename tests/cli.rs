use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;
use std::process::{Command, Output, Stdio};
use std::thread::sleep;
use std::time::{Duration, Instant};

fn filetap() -> Command {
    Command::new(env!("CARGO_BIN_EXE_filetap"))
}

fn run(args: &[&str]) -> Output {
    filetap().args(args).output().unwrap()
}

fn stderr(out: &Output) -> String {
    String::from_utf8_lossy(&out.stderr).into_owned()
}

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("filetap-cli-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

#[test]
fn exit_code_is_passed_through() {
    let out = run(&["--", "sh", "-c", "exit 7"]);
    assert_eq!(out.status.code(), Some(7));
    assert!(stderr(&out).contains("filetap: sh -c exit 7 exited 7 after"));
}

// The root's first stop after PTRACE_SEIZE must be resumed with PTRACE_CONT;
// treating it as a group-stop hung the command now and then.
#[test]
fn startup_never_hangs() {
    for _ in 0..100 {
        let out = run(&["--", "sh", "-c", "exit 3"]);
        assert_eq!(out.status.code(), Some(3));
    }
}

#[test]
fn death_by_signal_exits_128_plus_signal() {
    let out = run(&["--", "sh", "-c", "kill -TERM $$"]);
    assert_eq!(out.status.code(), Some(143));
    assert!(stderr(&out).contains("was killed by SIGTERM"));
}

#[test]
fn missing_command_exits_127() {
    let out = run(&["--", "filetap-no-such-command"]);
    assert_eq!(out.status.code(), Some(127));
    assert_eq!(
        stderr(&out),
        "filetap: filetap-no-such-command: command not found\n"
    );
}

#[test]
fn non_executable_command_exits_126() {
    let dir = tempdir("noexec");
    let script = dir.join("script.sh");
    fs::write(&script, "#!/bin/sh\n").unwrap();
    fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
    let out = run(&["--", script.to_str().unwrap()]);
    assert_eq!(out.status.code(), Some(126));
}

#[test]
fn usage_error_exits_125() {
    let out = run(&["sh"]);
    assert_eq!(out.status.code(), Some(125));
}

#[test]
fn stdout_is_left_to_the_command() {
    let out = run(&["--", "echo", "hi"]);
    assert_eq!(out.stdout, b"hi\n");
    assert!(stderr(&out).contains("filetap: echo hi exited 0"));
}

#[test]
fn stdin_reaches_the_command() {
    let mut child = filetap()
        .args(["--", "sh", "-c", "read x; echo got $x"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(b"hello\n").unwrap();
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.stdout, b"got hello\n");
}

#[test]
fn report_to_stdout_with_dash() {
    let out = run(&["-o", "-", "--", "true"]);
    assert!(String::from_utf8_lossy(&out.stdout).contains("filetap: true exited 0"));
    assert!(out.stderr.is_empty());
}

#[test]
fn report_to_file_has_no_leading_blank_line() {
    let dir = tempdir("report");
    let path = dir.join("report.txt");
    let out = run(&["-o", path.to_str().unwrap(), "--", "true"]);
    assert!(out.stderr.is_empty());
    let report = fs::read_to_string(&path).unwrap();
    assert!(report.starts_with("filetap: true exited 0"), "{report:?}");
}

#[test]
fn returns_while_background_process_runs() {
    let t = Instant::now();
    let out = run(&["--", "sh", "-c", "sleep 3 >/dev/null 2>&1 & exit 0"]);
    assert!(t.elapsed() < Duration::from_secs(2));
    assert_eq!(out.status.code(), Some(0));
    assert!(
        // The name is whatever the process is at that moment: sh if it
        // hasn't exec'd sleep yet.
        stderr(&out).contains("filetap: 1 background process still running ("),
        "{}",
        stderr(&out)
    );
}

#[test]
fn wait_waits_for_background_processes() {
    let t = Instant::now();
    let out = run(&[
        "--wait",
        "--",
        "sh",
        "-c",
        "sleep 1 >/dev/null 2>&1 & exit 0",
    ]);
    assert!(t.elapsed() >= Duration::from_secs(1));
    assert!(!stderr(&out).contains("still running"));
}

// Tracees that outlive the report must keep working: the tracer stays around
// and keeps resuming them.
#[test]
fn daemonized_descendant_keeps_working_after_report() {
    let dir = tempdir("daemon");
    let marker = dir.join("marker");
    let script = format!(
        "setsid sh -c 'sleep 0.5; echo done > {}' </dev/null >/dev/null 2>&1 & exit 0",
        marker.display()
    );
    let out = run(&["--", "sh", "-c", &script]);
    assert_eq!(out.status.code(), Some(0));
    for _ in 0..40 {
        if fs::read_to_string(&marker).is_ok_and(|s| s == "done\n") {
            return;
        }
        sleep(Duration::from_millis(100));
    }
    panic!("background process never wrote {}", marker.display());
}

// A lingering tracer must not hold on to filetap's stdout, or
// `filetap -- cmd | less` would wait for the daemon.
#[test]
fn lingering_tracer_does_not_keep_stdout_open() {
    let mut child = filetap()
        .args([
            "--",
            "sh",
            "-c",
            "setsid sleep 3 </dev/null >/dev/null 2>&1 & echo hi",
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let t = Instant::now();
    let mut buf = String::new();
    child
        .stdout
        .take()
        .unwrap()
        .read_to_string(&mut buf)
        .unwrap();
    child.wait().unwrap();
    assert_eq!(buf, "hi\n");
    assert!(t.elapsed() < Duration::from_secs(2));
}

#[test]
fn child_processes_are_counted() {
    let out = run(&["--", "sh", "-c", "/bin/true; /bin/true; /bin/true; exit 0"]);
    assert!(stderr(&out).contains("(4 processes)"), "{}", stderr(&out));
}

#[test]
fn threads_are_not_counted_as_processes() {
    let code = "import threading\n\
                ts = [threading.Thread(target=lambda: None) for _ in range(4)]\n\
                [t.start() for t in ts]; [t.join() for t in ts]";
    let out = run(&["--", "python3", "-c", code]);
    assert_eq!(out.status.code(), Some(0), "{}", stderr(&out));
    assert!(stderr(&out).contains("(1 process)"), "{}", stderr(&out));
}

#[test]
fn sigterm_is_forwarded_to_the_command() {
    let child = filetap()
        .args([
            "--",
            "sh",
            "-c",
            "trap 'exit 9' TERM; sleep 5 >/dev/null 2>&1 & wait",
        ])
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    sleep(Duration::from_millis(300));
    // SAFETY: plain kill(2) on our own child.
    unsafe { libc::kill(child.id() as i32, libc::SIGTERM) };
    let out = child.wait_with_output().unwrap();
    assert_eq!(out.status.code(), Some(9));
}
