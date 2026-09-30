//! Runs small scripts under both strace and filetap and checks that the
//! backend saw the same paths with the same outcomes.

#[path = "support/strace.rs"]
mod strace;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

fn tempdir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("filetap-sc-{}-{name}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn fresh(dir: &Path) {
    let _ = fs::remove_dir_all(dir);
    fs::create_dir_all(dir).unwrap();
}

fn events(path: &Path) -> Vec<Value> {
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap())
        .collect()
}

/// The (path, outcome) pairs from our dump, same shape as the strace side.
fn our_accesses(events: &[Value]) -> BTreeSet<strace::Access> {
    let mut out = BTreeSet::new();
    for ev in events {
        let outcome = match ev.get("error") {
            Some(e) => e.as_str().unwrap().to_string(),
            None => "ok".to_string(),
        };
        let symlink = ev["call"] == "link" && ev["symbolic"] == true;
        for key in ["path", "from", "to"] {
            if key == "from" && symlink {
                continue;
            }
            let Some(raw) = ev.get(key).and_then(|v| v.as_str()) else {
                continue;
            };
            let abs = match ev.get(format!("{key}_dir")).and_then(|v| v.as_str()) {
                Some(dir) if !raw.starts_with('/') => format!("{dir}/{raw}"),
                _ => raw.to_string(),
            };
            out.insert((abs, outcome.clone()));
        }
    }
    out
}

fn run_script(
    name: &str,
    interpreter: &str,
    script: &str,
) -> (Vec<Value>, BTreeSet<strace::Access>) {
    let base = tempdir(name);
    let work = base.join("work");
    let script_path = base.join("script");
    fs::write(&script_path, script).unwrap();
    let work_str = work.to_str().unwrap().to_string();
    let only_work = |set: BTreeSet<strace::Access>| -> BTreeSet<strace::Access> {
        set.into_iter()
            .filter(|(p, _)| p == &work_str || p.starts_with(&format!("{work_str}/")))
            .collect()
    };

    fresh(&work);
    let status = Command::new("strace")
        .args(["-ff", "-qq", "-y", "-xx", "-o"])
        .arg(base.join("st"))
        .arg("--")
        .arg(interpreter)
        .arg(&script_path)
        .current_dir(&work)
        .status()
        .expect("strace is needed for these tests");
    assert!(status.success());
    let theirs = only_work(strace::accesses(&base, "st", &work_str));

    fresh(&work);
    let dump = base.join("events.jsonl");
    let status = Command::new(env!("CARGO_BIN_EXE_filetap"))
        .arg("--dump-events")
        .arg(&dump)
        .args(["-o", "/dev/null", "--", interpreter])
        .arg(&script_path)
        .current_dir(&work)
        .status()
        .unwrap();
    assert!(status.success());
    let evs = events(&dump);
    let ours = only_work(our_accesses(&evs));

    assert!(!theirs.is_empty(), "strace saw nothing under {work_str}");
    let missing: Vec<_> = theirs.difference(&ours).collect();
    let extra: Vec<_> = ours.difference(&theirs).collect();
    assert!(
        missing.is_empty() && extra.is_empty(),
        "only strace saw: {missing:#?}\nonly filetap saw: {extra:#?}"
    );
    (evs, ours)
}

#[test]
fn shell_file_operations_match_strace() {
    run_script(
        "shell",
        "sh",
        r#"
echo one > new.txt
echo two > new.txt
echo three >> new.txt
cat new.txt > /dev/null
cat missing.txt 2>/dev/null
mkdir -p a/b
touch a/b/c
mv a/b/c a/b/d
ln -s d a/b/link
ln a/b/d a/b/hard
chmod 600 a/b/d
truncate -s 0 a/b/d
touch "$(printf 'bad\377name')"
rm a/b/link a/b/hard a/b/d "$(printf 'bad\377name')"
rmdir a/b a
ls -la > /dev/null
exit 0
"#,
    );
}

#[test]
fn python_threads_and_forks_match_strace() {
    run_script(
        "python",
        "python3",
        r#"
import os, threading
with open("cfg.toml", "w") as f:
    f.write("x = 1")
fd = os.open(".cfg.toml.tmp", os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o644)
os.write(fd, b"x = 2")
os.close(fd)
os.replace(".cfg.toml.tmp", "cfg.toml")

def worker(i):
    with open(f"t{i}.txt", "w") as f:
        f.write(str(i))
ts = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
for t in ts: t.start()
for t in ts: t.join()

if os.fork() == 0:
    open("child.txt", "w").close()
    os._exit(0)
os.wait()
os.path.exists("nope.json")
os.mkdir("d")
os.rmdir("d")
"#,
    );
}

fn find<'a>(evs: &'a [Value], call: &str, key: &str, path: &str) -> &'a Value {
    evs.iter()
        .find(|e| e["call"] == call && e[key] == path)
        .unwrap_or_else(|| panic!("no {call} with {key} {path}"))
}

#[test]
fn existence_before_create_is_recorded() {
    let (evs, _) = run_script(
        "existed",
        "sh",
        r#"
echo a > fresh.txt
echo b > fresh.txt
exit 0
"#,
    );
    let opens: Vec<_> = evs
        .iter()
        .filter(|e| e["call"] == "open" && e["path"] == "fresh.txt")
        .collect();
    assert_eq!(opens.len(), 2);
    assert_eq!(opens[0]["existed"], false);
    assert_eq!(opens[1]["existed"], true);
}

#[test]
fn rename_over_existing_file_records_the_target_existed() {
    let (evs, _) = run_script(
        "replace",
        "python3",
        r#"
import os
open("target", "w").close()
open("tmp", "w").close()
os.replace("tmp", "target")
os.replace("target", "other")
"#,
    );
    let replace = find(&evs, "rename", "to", "target");
    assert_eq!(replace["to_existed"], true);
    let moved = find(&evs, "rename", "to", "other");
    assert_eq!(moved["to_existed"], false);
}
