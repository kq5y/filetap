//! --dump-events: the backend's events as JSON lines, before any
//! interpretation. Meant for bug reports, so the format may change.

use std::io::{self, Write};

use nix::errno::Errno;

use crate::backend::{Call, PathArg, SysEvent};

pub fn write_event(w: &mut impl Write, ev: &SysEvent) -> io::Result<()> {
    let mut s = String::new();
    let name = match &ev.call {
        Call::Open {
            path,
            flags,
            existed,
        } => {
            path_field(&mut s, "path", path);
            s += &format!(",\"flags\":\"{:#o}\"", flags);
            tri_field(&mut s, "existed", *existed);
            "open"
        }
        Call::Stat { path } => {
            path_field(&mut s, "path", path);
            "stat"
        }
        Call::Exec { path, argv } => {
            path_field(&mut s, "path", path);
            s += ",\"argv\":[";
            for (i, a) in argv.iter().enumerate() {
                if i > 0 {
                    s.push(',');
                }
                push_str(&mut s, a);
            }
            s.push(']');
            "exec"
        }
        Call::Rename {
            from,
            to,
            flags,
            to_existed,
        } => {
            path_field(&mut s, "from", from);
            path_field(&mut s, "to", to);
            s += &format!(",\"flags\":{flags}");
            tri_field(&mut s, "to_existed", *to_existed);
            "rename"
        }
        Call::Unlink { path, dir } => {
            path_field(&mut s, "path", path);
            s += &format!(",\"dir\":{dir}");
            "unlink"
        }
        Call::Mkdir { path } => {
            path_field(&mut s, "path", path);
            "mkdir"
        }
        Call::Link { from, to, symbolic } => {
            path_field(&mut s, "from", from);
            path_field(&mut s, "to", to);
            s += &format!(",\"symbolic\":{symbolic}");
            "link"
        }
        Call::Truncate { path } => {
            path_field(&mut s, "path", path);
            "truncate"
        }
        Call::Attr { path } => {
            path_field(&mut s, "path", path);
            "attr"
        }
        Call::IoUringSetup => "io_uring_setup",
    };
    let mut s = format!("{{\"pid\":{},\"call\":\"{name}\"{s}", ev.pid);
    match ev.result {
        Ok(v) => s += &format!(",\"result\":{v}"),
        Err(e) => s += &format!(",\"error\":\"{:?}\"", Errno::from_raw(e)),
    }
    s += "}\n";
    w.write_all(s.as_bytes())
}

fn path_field(s: &mut String, key: &str, p: &PathArg) {
    *s += &format!(",\"{key}\":");
    push_str(s, &p.raw);
    if let Some(dir) = &p.dir {
        *s += &format!(",\"{key}_dir\":");
        push_str(s, dir);
    }
}

fn tri_field(s: &mut String, key: &str, v: Option<bool>) {
    if let Some(v) = v {
        *s += &format!(",\"{key}\":{v}");
    }
}

/// JSON string from raw bytes. Bytes that aren't UTF-8 come out as a literal
/// `\xNN`, which is ambiguous but readable, and this is a debugging aid.
fn push_str(s: &mut String, b: &[u8]) {
    s.push('"');
    for chunk in b.utf8_chunks() {
        for c in chunk.valid().chars() {
            match c {
                '"' => s.push_str("\\\""),
                '\\' => s.push_str("\\\\"),
                c if (c as u32) < 0x20 => s.push_str(&format!("\\u{:04x}", c as u32)),
                c => s.push(c),
            }
        }
        for byte in chunk.invalid() {
            s.push_str(&format!("\\\\x{byte:02x}"));
        }
    }
    s.push('"');
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dump(ev: SysEvent) -> String {
        let mut out = Vec::new();
        write_event(&mut out, &ev).unwrap();
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn failed_open_shows_errno_name() {
        let line = dump(SysEvent {
            pid: 5,
            call: Call::Open {
                path: PathArg {
                    dir: Some(b"/home/u".to_vec()),
                    raw: b".env".to_vec(),
                },
                flags: 0,
                existed: None,
            },
            result: Err(libc::ENOENT),
        });
        assert_eq!(
            line,
            "{\"pid\":5,\"call\":\"open\",\"path\":\".env\",\"path_dir\":\"/home/u\",\"flags\":\"0o0\",\"error\":\"ENOENT\"}\n"
        );
    }

    #[test]
    fn non_utf8_and_quotes_are_escaped() {
        let mut s = String::new();
        push_str(&mut s, b"a\"b\xffc\n");
        assert_eq!(s, r#""a\"b\\xffc\u000a""#);
    }
}
