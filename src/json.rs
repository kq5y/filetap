//! --json: the whole report, hidden entries included, for other tools.
//! Fields can be added within `filetap.report/v1`; removing or changing
//! one means a v2.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use serde_json::{Map, Value, json};

use crate::aggregate::{Exec, Kind, Record};
use crate::backend::Exit;
use crate::classify::{Class, Hidden};
use crate::zone::{Context, Zone};

pub struct Run<'a> {
    pub command: &'a [std::ffi::OsString],
    pub started_at: SystemTime,
    pub duration: Duration,
    pub exit: Exit,
    pub complete: bool,
    pub filters: Value,
    pub execs: &'a [Exec],
    pub warnings: Vec<String>,
}

pub fn write(
    w: &mut dyn Write,
    run: &Run,
    records: &[Record],
    classes: &[Class],
    ctx: &Context,
) -> io::Result<()> {
    let mut files = Vec::new();
    let mut hidden_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut summary: BTreeMap<&str, usize> = BTreeMap::new();

    for (r, c) in records.iter().zip(classes) {
        if c.hidden == Some(Hidden::Filtered) {
            continue;
        }
        let zone = ctx.zone(&r.path);
        let reason = c.hidden.map(|h| hidden_reason(h, zone));
        match reason {
            Some(why) => *hidden_counts.entry(why).or_default() += 1,
            None => *summary.entry(c.bucket.name()).or_default() += 1,
        }

        let mut f = Map::new();
        f.insert("path".into(), json!(String::from_utf8_lossy(&r.path)));
        if std::str::from_utf8(&r.path).is_err() {
            f.insert("path_b64".into(), json!(base64(&r.path)));
        }
        f.insert("display".into(), json!(ctx.display(&r.path)));
        f.insert("zone".into(), json!(zone.name()));
        f.insert("kind".into(), json!(r.kind_after.map(kind_name)));
        f.insert("bucket".into(), json!(c.bucket.name()));
        f.insert(
            "visibility".into(),
            json!(if reason.is_some() { "hidden" } else { "shown" }),
        );
        if let Some(why) = reason {
            f.insert("hidden_reason".into(), json!(why));
        }
        f.insert("ops".into(), ops(r));
        f.insert("errors".into(), errors(r));
        f.insert(
            "existed_before".into(),
            json!(match r.before {
                Some(true) => "yes",
                Some(false) => "no",
                None => "unknown",
            }),
        );
        f.insert("exists_after".into(), json!(r.kind_after.is_some()));
        let path_of = |i: Option<usize>| i.map(|i| String::from_utf8_lossy(&records[i].path));
        f.insert("moved_from".into(), json!(path_of(r.moved_from)));
        f.insert("moved_to".into(), json!(path_of(r.moved_to)));
        f.insert("atomic".into(), json!(c.atomic));
        let lookups: Vec<_> = c
            .lookups_before
            .iter()
            .map(|&i| String::from_utf8_lossy(&records[i].path))
            .collect();
        f.insert("lookups_before".into(), json!(lookups));
        f.insert("pids".into(), json!(r.pids));
        f.insert("first_seen_ms".into(), json!(r.first_seen_ms));
        files.push(Value::Object(f));
    }

    let processes: Vec<Value> = run
        .execs
        .iter()
        .map(|e| {
            let argv: Vec<_> = e.argv.iter().map(|a| String::from_utf8_lossy(a)).collect();
            json!({ "pid": e.pid, "exe": String::from_utf8_lossy(&e.path), "argv": argv })
        })
        .collect();
    let (code, signal) = match run.exit {
        Exit::Code(c) => (Some(c), None),
        Exit::Signal(s) => (None, Some(s)),
    };
    let bytes = |b: &[u8]| String::from_utf8_lossy(b).into_owned();

    let report = json!({
        "schema": "filetap.report/v1",
        "filetap_version": env!("CARGO_PKG_VERSION"),
        "backend": { "name": "ptrace", "seccomp": true },
        "command": run.command.iter().map(|a| a.to_string_lossy()).collect::<Vec<_>>(),
        "cwd": bytes(&ctx.cwd),
        "root": bytes(&ctx.root),
        "home": ctx.home.as_deref().map(bytes),
        "started_at": rfc3339(run.started_at),
        "duration_ms": run.duration.as_millis() as u64,
        "exit": { "code": code, "signal": signal },
        "complete": run.complete,
        "filters": run.filters,
        "processes": processes,
        "files": files,
        "hidden_counts": hidden_counts,
        "summary": summary,
        "warnings": run.warnings,
    });
    serde_json::to_writer_pretty(&mut *w, &report)?;
    writeln!(w)
}

fn hidden_reason(h: Hidden, zone: Zone) -> &'static str {
    match h {
        Hidden::Zone if zone == Zone::Toolchain => "toolchain",
        Hidden::Zone => "system",
        Hidden::Virtual => "virtual",
        Hidden::Probe => "probe",
        Hidden::Temp => "temp",
        Hidden::Stat => "stat_only",
        Hidden::Pseudo => "pseudo",
        Hidden::Moved => "moved",
        Hidden::Filtered => "filtered",
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::File => "file",
        Kind::Dir => "dir",
        Kind::Symlink => "symlink",
        Kind::Other => "other",
    }
}

fn ops(r: &Record) -> Value {
    let o = &r.ops;
    let all = [
        ("read", o.read),
        ("list", o.list),
        ("write", o.write),
        ("create", o.create),
        ("delete", o.delete),
        ("exec", o.exec),
        ("stat", o.stat),
        ("attr", o.attr),
        ("moved_in", o.moved_in),
        ("moved_out", o.moved_out),
    ];
    nonzero(&all)
}

fn errors(r: &Record) -> Value {
    let e = &r.errors;
    nonzero(&[
        ("missing", e.missing),
        ("denied", e.denied),
        ("other", e.other),
    ])
}

fn nonzero(counts: &[(&str, u32)]) -> Value {
    let m: Map<String, Value> = counts
        .iter()
        .filter(|(_, n)| *n > 0)
        .map(|(k, n)| (k.to_string(), json!(n)))
        .collect();
    Value::Object(m)
}

fn base64(b: &[u8]) -> String {
    const ABC: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in b.chunks(3) {
        let n = chunk.iter().fold(0u32, |n, &c| n << 8 | c as u32) << (8 * (3 - chunk.len()));
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(ABC[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// UTC, to the millisecond. Days to a civil date as in Howard Hinnant's
/// `civil_from_days`.
fn rfc3339(t: SystemTime) -> String {
    let d = t.duration_since(UNIX_EPOCH).unwrap_or_default();
    let secs = d.as_secs();
    let (days, rem) = ((secs / 86400) as i64, secs % 86400);
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}.{:03}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60,
        d.subsec_millis()
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hand_rolled_encoders_match_known_values() {
        assert_eq!(base64(b"a\xffb"), "Yf9i");
        assert_eq!(base64(b"ab"), "YWI=");
        let t = UNIX_EPOCH + Duration::from_millis(1_790_812_800_123);
        assert_eq!(rfc3339(t), "2026-10-01T00:00:00.123Z");
    }
}
