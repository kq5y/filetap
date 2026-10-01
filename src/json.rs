//! --json: the whole report, hidden entries included, for other tools.
//! Fields can be added within `filetap.report/v1`; removing or changing
//! one means a v2.

use std::collections::{BTreeMap, HashMap};
use std::io::{self, Write};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use std::borrow::Cow;

use serde::Serialize;
use serde::ser::{SerializeMap, Serializer};
use serde_json::Value;

use crate::aggregate::{self, Exec, Kind, Record};
use crate::backend::Exit;
use crate::classify::{Class, Hidden};
use crate::zone::{Context, Zone};

/// What the tracer said about one process besides its execs.
#[derive(Default)]
pub struct Proc {
    pub ppid: Option<i32>,
    /// `None` while it's still running.
    pub exit: Option<Exit>,
}

pub struct Run<'a> {
    pub command: &'a [std::ffi::OsString],
    pub started_at: SystemTime,
    pub duration: Duration,
    pub exit: Exit,
    pub complete: bool,
    pub filters: Value,
    pub seccomp: bool,
    pub execs: &'a [Exec],
    pub procs: &'a BTreeMap<i32, Proc>,
    pub warnings: Vec<String>,
}

pub fn write(
    w: &mut dyn Write,
    run: &Run,
    records: &[Record],
    classes: &[Class],
    ctx: &Context,
    folded: &HashMap<usize, Option<String>>,
) -> io::Result<()> {
    let mut hidden_counts: BTreeMap<&str, usize> = BTreeMap::new();
    let mut summary: BTreeMap<&str, usize> = BTreeMap::new();
    for (r, c) in records.iter().zip(classes) {
        match c.hidden {
            Some(Hidden::Filtered) => {}
            Some(h) => {
                *hidden_counts
                    .entry(hidden_reason(h, ctx.zone(&r.path)))
                    .or_default() += 1
            }
            None => *summary.entry(c.bucket.name()).or_default() += 1,
        }
    }

    let processes: Vec<Process> = run
        .procs
        .iter()
        .map(|(&pid, p)| {
            // The program it ended up running, if it exec'd at all.
            let exec = run.execs.iter().rev().find(|e| e.pid == pid);
            Process {
                pid,
                ppid: p.ppid,
                exe: exec.map(|e| lossy(&e.path)),
                argv: exec.map(|e| e.argv.iter().map(|a| lossy(a)).collect()),
                exit: p.exit.map(ExitStatus::from),
            }
        })
        .collect();

    let report = Report {
        schema: "filetap.report/v1",
        filetap_version: env!("CARGO_PKG_VERSION"),
        backend: Backend {
            name: "ptrace",
            seccomp: run.seccomp,
        },
        command: run.command.iter().map(|a| a.to_string_lossy()).collect(),
        cwd: lossy(&ctx.cwd),
        root: lossy(&ctx.root),
        home: ctx.home.as_deref().map(lossy),
        started_at: rfc3339(run.started_at),
        duration_ms: run.duration.as_millis() as u64,
        exit: run.exit.into(),
        complete: run.complete,
        filters: &run.filters,
        processes,
        files: Files {
            records,
            classes,
            ctx,
            folded,
        },
        hidden_counts,
        summary,
        warnings: &run.warnings,
    };
    // Entries are built one at a time while writing, so a trace with a
    // hundred thousand paths doesn't need a second copy of all of them.
    serde_json::to_writer_pretty(&mut *w, &report)?;
    writeln!(w)
}

#[derive(Serialize)]
struct Report<'a> {
    schema: &'static str,
    filetap_version: &'static str,
    backend: Backend,
    command: Vec<Cow<'a, str>>,
    cwd: Cow<'a, str>,
    root: Cow<'a, str>,
    home: Option<Cow<'a, str>>,
    started_at: String,
    duration_ms: u64,
    exit: ExitStatus,
    complete: bool,
    filters: &'a Value,
    processes: Vec<Process<'a>>,
    files: Files<'a>,
    hidden_counts: BTreeMap<&'static str, usize>,
    summary: BTreeMap<&'static str, usize>,
    warnings: &'a [String],
}

#[derive(Serialize)]
struct Backend {
    name: &'static str,
    seccomp: bool,
}

#[derive(Serialize)]
struct Process<'a> {
    pid: i32,
    ppid: Option<i32>,
    exe: Option<Cow<'a, str>>,
    argv: Option<Vec<Cow<'a, str>>>,
    exit: Option<ExitStatus>,
}

#[derive(Serialize)]
struct ExitStatus {
    code: Option<i32>,
    signal: Option<i32>,
}

impl From<Exit> for ExitStatus {
    fn from(e: Exit) -> ExitStatus {
        match e {
            Exit::Code(c) => ExitStatus {
                code: Some(c),
                signal: None,
            },
            Exit::Signal(s) => ExitStatus {
                code: None,
                signal: Some(s),
            },
        }
    }
}

struct Files<'a> {
    records: &'a [Record],
    classes: &'a [Class],
    ctx: &'a Context,
    /// From the text report: what it didn't give a line of its own.
    folded: &'a HashMap<usize, Option<String>>,
}

impl Serialize for Files<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let records = self.records;
        s.collect_seq(
            records
                .iter()
                .zip(self.classes)
                .enumerate()
                .filter(|(_, (_, c))| c.hidden != Some(Hidden::Filtered))
                .map(|(i, (r, c))| {
                    let zone = self.ctx.zone(&r.path);
                    let path_of = |i: Option<usize>| i.map(|i| lossy(&records[i].path));
                    File {
                        path: lossy(&r.path),
                        path_b64: std::str::from_utf8(&r.path)
                            .is_err()
                            .then(|| base64(&r.path)),
                        display: self.ctx.display(&r.path),
                        resolved: r.resolved.as_deref().map(lossy),
                        zone: zone.name(),
                        kind: r.kind_after.map(kind_name),
                        bucket: c.bucket.name(),
                        visibility: if c.hidden.is_some() {
                            "hidden"
                        } else if self.folded.contains_key(&i) {
                            "folded"
                        } else {
                            "shown"
                        },
                        folded_into: self.folded.get(&i).cloned().flatten(),
                        hidden_reason: c.hidden.map(|h| hidden_reason(h, zone)),
                        ops: Ops(&r.ops),
                        errors: Errors(&r.errors),
                        existed_before: match r.before {
                            Some(true) => "yes",
                            Some(false) => "no",
                            None => "unknown",
                        },
                        exists_after: r.kind_after.is_some(),
                        moved_from: path_of(r.moved_from),
                        moved_to: path_of(r.moved_to),
                        atomic: c.atomic,
                        credentials: c.credentials,
                        lookups_before: c
                            .lookups_before
                            .iter()
                            .map(|&i| lossy(&records[i].path))
                            .collect(),
                        pids: &r.pids,
                        first_seen_ms: r.first_seen_ms,
                    }
                }),
        )
    }
}

#[derive(Serialize)]
struct File<'a> {
    path: Cow<'a, str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    path_b64: Option<String>,
    display: String,
    resolved: Option<Cow<'a, str>>,
    zone: &'static str,
    kind: Option<&'static str>,
    bucket: &'static str,
    visibility: &'static str,
    /// The text line it went into; absent when it was cut off by the
    /// line limit instead.
    #[serde(skip_serializing_if = "Option::is_none")]
    folded_into: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hidden_reason: Option<&'static str>,
    ops: Ops<'a>,
    errors: Errors<'a>,
    existed_before: &'static str,
    exists_after: bool,
    moved_from: Option<Cow<'a, str>>,
    moved_to: Option<Cow<'a, str>>,
    atomic: bool,
    credentials: bool,
    lookups_before: Vec<Cow<'a, str>>,
    pids: &'a [i32],
    first_seen_ms: u64,
}

/// Only the counts that aren't zero.
struct Ops<'a>(&'a aggregate::Ops);
struct Errors<'a>(&'a aggregate::Errors);

impl Serialize for Ops<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let o = self.0;
        nonzero(
            s,
            &[
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
            ],
        )
    }
}

impl Serialize for Errors<'_> {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        let e = self.0;
        nonzero(
            s,
            &[
                ("missing", e.missing),
                ("denied", e.denied),
                ("other", e.other),
            ],
        )
    }
}

fn nonzero<S: Serializer>(s: S, counts: &[(&str, u32)]) -> Result<S::Ok, S::Error> {
    let mut m = s.serialize_map(None)?;
    for (k, n) in counts.iter().filter(|(_, n)| *n > 0) {
        m.serialize_entry(k, n)?;
    }
    m.end()
}

pub fn lossy(b: &[u8]) -> Cow<'_, str> {
    String::from_utf8_lossy(b)
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

pub fn base64(b: &[u8]) -> String {
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
