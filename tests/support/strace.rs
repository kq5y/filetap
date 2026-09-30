//! Just enough of a parser for `strace -ff -y -xx` output to compare the
//! paths it saw with ours. Test-only; filetap itself never runs strace.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

/// (absolute path, "ok" or the errno name)
pub type Access = (String, String);

/// Syscall name -> positions of (dirfd arg, path arg). `None` for the dirfd
/// means the path is relative to the cwd.
fn path_args(name: &str) -> &'static [(Option<usize>, usize)] {
    match name {
        "open" | "creat" | "stat" | "lstat" | "access" | "readlink" | "statfs" | "truncate"
        | "chmod" | "chown" | "lchown" | "utime" | "utimes" | "setxattr" | "lsetxattr"
        | "removexattr" | "lremovexattr" | "execve" | "mkdir" | "mknod" | "rmdir" | "unlink" => {
            &[(None, 0)]
        }
        "rename" | "link" => &[(None, 0), (None, 1)],
        "symlink" => &[(None, 1)],
        "openat" | "openat2" | "newfstatat" | "statx" | "faccessat" | "faccessat2"
        | "readlinkat" | "mkdirat" | "mknodat" | "unlinkat" | "fchmodat" | "fchmodat2"
        | "fchownat" | "utimensat" | "futimesat" | "execveat" => &[(Some(0), 1)],
        "renameat" | "renameat2" | "linkat" => &[(Some(0), 1), (Some(2), 3)],
        "symlinkat" => &[(Some(1), 2)],
        _ => &[],
    }
}

/// Reads every `<prefix>.<pid>` file written by `strace -ff -o <prefix>`.
///
/// Non-at syscalls have no cwd annotation, so the cwd is followed through
/// chdir/fchdir within each file, starting from `cwd`. That's wrong for a
/// child forked after its parent changed directory, which the scenarios
/// don't do.
pub fn accesses(dir: &Path, prefix: &str, cwd: &str) -> BTreeSet<Access> {
    let mut out = BTreeSet::new();
    for entry in fs::read_dir(dir).unwrap() {
        let entry = entry.unwrap();
        let name = entry.file_name().to_string_lossy().into_owned();
        if !name.starts_with(&format!("{prefix}.")) {
            continue;
        }
        let text = fs::read_to_string(entry.path()).unwrap();
        let mut cwd = cwd.as_bytes().to_vec();
        for line in text.lines() {
            parse_line(line, &mut cwd, &mut out);
        }
    }
    out
}

fn parse_line(line: &str, cwd: &mut Vec<u8>, out: &mut BTreeSet<Access>) {
    let Some(open) = line.find('(') else { return };
    let name = &line[..open];
    // strace pads short calls with spaces before the " = ".
    let Some(eq) = line.rfind(" = ") else { return };
    let Some(call) = line[..eq].trim_end().strip_suffix(')') else {
        return;
    };
    let args = split_args(&call[open + 1..]);
    let ret = &line[eq + 3..];

    if ret == "0" && (name == "chdir" || name == "fchdir") {
        let new = match name {
            "chdir" => args.first().and_then(|a| unquote(a)).map(|p| join(cwd, &p)),
            _ => args.first().and_then(|a| annotation(a)),
        };
        if let Some(new) = new {
            *cwd = new;
        }
        return;
    }
    let positions = path_args(name);
    if positions.is_empty() {
        return;
    }
    let result = if let Some(err) = ret.strip_prefix("-1 ") {
        err.split(' ').next().unwrap().to_string()
    } else if ret.starts_with('?') {
        return;
    } else {
        "ok".to_string()
    };

    for &(dirfd, path) in positions {
        let Some(raw) = args.get(path).and_then(|a| unquote(a)) else {
            continue;
        };
        if raw.is_empty() {
            continue;
        }
        let base = match dirfd {
            Some(i) => match args.get(i).and_then(|a| annotation(a)) {
                Some(b) => b,
                None if raw[0] == b'/' => Vec::new(),
                None => continue,
            },
            None => cwd.clone(),
        };
        out.insert((escape(&join(&base, &raw)), result.clone()));
    }
}

fn join(base: &[u8], p: &[u8]) -> Vec<u8> {
    if p.first() == Some(&b'/') {
        return p.to_vec();
    }
    let mut out = base.to_vec();
    out.push(b'/');
    out.extend_from_slice(p);
    out
}

/// Splits the argument list at top-level commas.
fn split_args(s: &str) -> Vec<&str> {
    let mut args = Vec::new();
    let (mut depth, mut in_str, mut escaped, mut start) = (0i32, false, false, 0);
    for (i, c) in s.char_indices() {
        if in_str {
            match c {
                _ if escaped => escaped = false,
                '\\' => escaped = true,
                '"' => in_str = false,
                _ => {}
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '(' | '[' | '{' | '<' => depth += 1,
            ')' | ']' | '}' | '>' => depth -= 1,
            ',' if depth == 0 => {
                args.push(s[start..i].trim());
                start = i + 1;
            }
            _ => {}
        }
    }
    args.push(s[start..].trim());
    args
}

/// `"\x61\x62"` -> b"ab". With -xx every byte is escaped.
fn unquote(arg: &str) -> Option<Vec<u8>> {
    let s = arg.strip_prefix('"')?;
    let end = s.find('"')?;
    hex(&s[..end])
}

/// `AT_FDCWD</tmp/x>` or `3</tmp/x>` -> b"/tmp/x".
fn annotation(arg: &str) -> Option<Vec<u8>> {
    let start = arg.find('<')?;
    let inner = arg[start + 1..].strip_suffix('>')?;
    hex(inner)
}

fn hex(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = s;
    while !rest.is_empty() {
        let h = rest.strip_prefix("\\x")?;
        out.push(u8::from_str_radix(h.get(..2)?, 16).ok()?);
        rest = &h[2..];
    }
    Some(out)
}

/// Same escaping as --dump-events, so the two sides compare as strings.
pub fn escape(b: &[u8]) -> String {
    let mut s = String::new();
    for chunk in b.utf8_chunks() {
        s.push_str(chunk.valid());
        for byte in chunk.invalid() {
            s.push_str(&format!("\\x{byte:02x}"));
        }
    }
    s
}

#[cfg(test)]
#[test]
fn parses_at_calls_with_annotations() {
    let mut out = BTreeSet::new();
    let mut cwd = b"/".to_vec();
    parse_line(
        r#"openat(AT_FDCWD<\x2f\x74\x6d\x70>, "\x61", O_RDONLY) = -1 ENOENT (No such file or directory)"#,
        &mut cwd,
        &mut out,
    );
    parse_line(
        r#"renameat2(3<\x2f\x64>, "\x61", AT_FDCWD<\x2f\x65>, "\x62", RENAME_NOREPLACE) = 0"#,
        &mut cwd,
        &mut out,
    );
    parse_line(r#"chdir("\x2f\x78") = 0"#, &mut cwd, &mut out);
    parse_line(
        r#"mkdir("\x79", 0777)                     = 0"#,
        &mut cwd,
        &mut out,
    );
    assert_eq!(
        out.into_iter().collect::<Vec<_>>(),
        [
            ("/d/a".into(), "ok".into()),
            ("/e/b".into(), "ok".into()),
            ("/tmp/a".into(), "ENOENT".into()),
            ("/x/y".into(), "ok".into()),
        ]
    );
}
