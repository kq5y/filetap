//! Puts every record in exactly one bucket and decides whether it's worth
//! showing. Filtering by zone only ever hides reads and failed lookups;
//! changes to files are always shown.

use std::collections::HashMap;

use crate::aggregate::Record;
use crate::zone::{Context, Zone, parent, under};

/// In report order: what came in, then what went out.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Bucket {
    Exec,
    Read,
    Missing,
    Denied,
    Create,
    Write,
    Rename,
    Delete,
    /// Created and gone again before the end.
    Temp,
    /// Only checked for existence.
    Stat,
}

impl Bucket {
    pub fn name(self) -> &'static str {
        match self {
            Bucket::Exec => "exec",
            Bucket::Read => "read",
            Bucket::Missing => "missing",
            Bucket::Denied => "denied",
            Bucket::Create => "create",
            Bucket::Write => "write",
            Bucket::Rename => "rename",
            Bucket::Delete => "delete",
            Bucket::Temp => "temp",
            Bucket::Stat => "stat",
        }
    }

    pub fn is_change(self) -> bool {
        matches!(
            self,
            Bucket::Create | Bucket::Write | Bucket::Rename | Bucket::Delete
        )
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Hidden {
    /// Reads of system and toolchain files.
    Zone,
    Virtual,
    /// A failed lookup that was part of a search (PATH, module resolution).
    Probe,
    Temp,
    Stat,
    /// /dev/null and friends.
    Pseudo,
    /// The target of a rename, already shown as `old -> new`.
    Moved,
    /// Left out by --only, --outside or --hide.
    Filtered,
}

#[derive(Debug, Clone)]
pub struct Class {
    pub bucket: Bucket,
    pub hidden: Option<Hidden>,
    /// Written by renaming a temporary file over it.
    pub atomic: bool,
    /// Failed lookups that ended up finding this path, in order.
    pub lookups_before: Vec<usize>,
    /// Matched --show: never folded.
    pub pinned: bool,
}

const CODE_EXTS: &[&[u8]] = &[
    b"js", b"mjs", b"cjs", b"jsx", b"ts", b"tsx", b"mts", b"cts", b"json", b"node", b"py", b"so",
    b"wasm",
];

pub fn classify(records: &[Record], ctx: &Context) -> Vec<Class> {
    let mut classes: Vec<Class> = records
        .iter()
        .map(|r| {
            let bucket = bucket(r);
            let zone = ctx.zone(&r.path);
            Class {
                bucket,
                hidden: hidden(r, bucket, zone),
                atomic: false,
                lookups_before: Vec::new(),
                pinned: false,
            }
        })
        .collect();

    for (i, r) in records.iter().enumerate() {
        // A temp file renamed over the target is how editors and package
        // managers save; the target is what changed.
        if let Some(src) = r.moved_from
            && classes[src].bucket == Bucket::Temp
            && matches!(classes[i].bucket, Bucket::Create | Bucket::Write)
        {
            classes[i].atomic = true;
        }
        if classes[i].bucket == Bucket::Rename
            && let Some(dst) = r.moved_to
            && records[dst].ops.moved_in == renames_into(&records[dst])
            && classes[dst].hidden.is_none()
        {
            classes[dst].hidden = Some(Hidden::Moved);
        }
    }

    find_probes(records, &mut classes);
    classes
}

fn renames_into(r: &Record) -> u32 {
    let o = &r.ops;
    o.write + o.create + o.attr + o.delete + o.moved_out
}

fn bucket(r: &Record) -> Bucket {
    let o = &r.ops;
    let exists = r.kind_after.is_some();
    if o.create > 0 && r.before != Some(true) {
        return if exists { Bucket::Create } else { Bucket::Temp };
    }
    if r.before == Some(true) && !exists {
        if o.delete > 0 {
            return Bucket::Delete;
        }
        if o.moved_out > 0 {
            return Bucket::Rename;
        }
    }
    if o.mutated() {
        return Bucket::Write;
    }
    if o.exec > 0 {
        return Bucket::Exec;
    }
    if o.read + o.list > 0 {
        return Bucket::Read;
    }
    if o.stat > 0 {
        return Bucket::Stat;
    }
    if r.errors.missing > 0 {
        return Bucket::Missing;
    }
    if r.errors.denied > 0 {
        return Bucket::Denied;
    }
    Bucket::Stat
}

fn hidden(r: &Record, bucket: Bucket, zone: Zone) -> Option<Hidden> {
    match bucket {
        Bucket::Temp => Some(Hidden::Temp),
        Bucket::Stat => Some(Hidden::Stat),
        Bucket::Exec => None,
        b if b.is_change() => pseudo(&r.path).then_some(Hidden::Pseudo),
        _ if zone == Zone::Virtual => Some(Hidden::Virtual),
        _ if zone.hides_reads() => Some(Hidden::Zone),
        // Dependency and cache directories are searched all the time.
        Bucket::Missing if matches!(zone, Zone::ProjectDeps | Zone::HomeCache) => {
            Some(Hidden::Probe)
        }
        _ => None,
    }
}

/// Files whose "writes" don't change anything on disk.
fn pseudo(p: &[u8]) -> bool {
    const FILES: &[&[u8]] = &[
        b"/dev/null",
        b"/dev/zero",
        b"/dev/full",
        b"/dev/random",
        b"/dev/urandom",
        b"/dev/tty",
        b"/dev/ptmx",
        b"/dev/stdin",
        b"/dev/stdout",
        b"/dev/stderr",
    ];
    if FILES.contains(&p) || p.starts_with(b"/dev/tty") {
        return true;
    }
    if under(p, b"/dev/pts") || under(p, b"/dev/fd") {
        return true;
    }
    let Some(rest) = p.strip_prefix(b"/proc/") else {
        return false;
    };
    let first = rest.split(|&b| b == b'/').next().unwrap_or_default();
    first == b"self" || first == b"thread-self" || first.iter().all(u8::is_ascii_digit)
}

/// A failed lookup is part of a search, not something missing, when the
/// search found what it was after elsewhere: the same name in another
/// directory, looked up by the same process (PATH, library and config
/// search paths), or a sibling with another extension or an `index` file
/// (module resolution).
fn find_probes(records: &[Record], classes: &mut [Class]) {
    let mut by_name: HashMap<&[u8], Vec<usize>> = HashMap::new();
    let mut by_dir: HashMap<&[u8], Vec<usize>> = HashMap::new();
    for (i, r) in records.iter().enumerate() {
        if r.ops.any() {
            by_name.entry(basename(&r.path)).or_default().push(i);
            if let Some(d) = parent(&r.path) {
                by_dir.entry(d).or_default().push(i);
            }
        }
    }

    for (i, r) in records.iter().enumerate() {
        if classes[i].bucket != Bucket::Missing {
            continue;
        }
        let name = basename(&r.path);
        let same_name = by_name.get(name).and_then(|found| {
            found
                .iter()
                .copied()
                .find(|&j| records[j].pids.iter().any(|p| r.pids.contains(p)))
        });
        let found = same_name.or_else(|| sibling(records, &by_dir, &r.path));
        let Some(j) = found else { continue };
        if classes[i].hidden.is_none() {
            classes[j].lookups_before.push(i);
        }
        classes[i].hidden = Some(Hidden::Probe);
    }
}

fn sibling(records: &[Record], by_dir: &HashMap<&[u8], Vec<usize>>, path: &[u8]) -> Option<usize> {
    let dir = parent(path)?;
    let name = basename(path);
    let stem = match name.iter().rposition(|&b| b == b'.') {
        Some(dot) if dot > 0 && CODE_EXTS.contains(&&name[dot + 1..]) => &name[..dot],
        _ => name,
    };
    let code_ext = |n: &[u8], s: &[u8]| {
        n.len() > s.len() + 1
            && n.starts_with(s)
            && n[s.len()] == b'.'
            && CODE_EXTS.contains(&&n[s.len() + 1..])
    };
    if let Some(found) = by_dir.get(dir)
        && let Some(&j) = found
            .iter()
            .find(|&&j| code_ext(basename(&records[j].path), stem))
    {
        return Some(j);
    }
    // `./src/foo` resolved to `./src/foo/index.ts`.
    let as_dir = [dir, b"/", stem].concat();
    let found = by_dir.get(as_dir.as_slice())?;
    found.iter().copied().find(|&j| {
        let n = basename(&records[j].path);
        code_ext(n, b"index") || n == b"package.json"
    })
}

fn basename(p: &[u8]) -> &[u8] {
    match p.iter().rposition(|&b| b == b'/') {
        Some(i) => &p[i + 1..],
        None => p,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::aggregate::Aggregator;
    use crate::backend::{Call, PathArg, SysEvent};

    fn ctx() -> Context {
        Context::new(
            b"/p".to_vec(),
            b"/p".to_vec(),
            Some(b"/h".to_vec()),
            1000,
            None,
            None,
            None,
        )
    }

    fn arg(p: &str) -> PathArg {
        PathArg {
            dir: None,
            raw: p.as_bytes().to_vec(),
        }
    }

    fn ev(call: Call, result: Result<i64, i32>) -> SysEvent {
        SysEvent {
            pid: 1,
            call,
            result,
        }
    }

    fn open(p: &str, flags: i32, existed: Option<bool>, result: Result<i64, i32>) -> SysEvent {
        ev(
            Call::Open {
                path: arg(p),
                flags,
                existed,
            },
            result,
        )
    }

    fn stat(p: &str, result: Result<i64, i32>) -> SysEvent {
        ev(Call::Stat { path: arg(p) }, result)
    }

    /// Runs events through the aggregator, then pretends `exists` are the
    /// paths left on disk afterwards.
    fn run(events: &[SysEvent], exists: &[&str]) -> Vec<(String, Bucket, Option<Hidden>)> {
        let mut agg = Aggregator::default();
        for e in events {
            agg.add(e, 0);
        }
        for r in &mut agg.records {
            let p = String::from_utf8(r.path.clone()).unwrap();
            if exists.contains(&p.as_str()) {
                r.kind_after = Some(crate::aggregate::Kind::File);
            }
        }
        classify(&agg.records, &ctx())
            .into_iter()
            .zip(&agg.records)
            .map(|(c, r)| {
                (
                    String::from_utf8(r.path.clone()).unwrap(),
                    c.bucket,
                    c.hidden,
                )
            })
            .collect()
    }

    const WRITE_NEW: i32 = libc::O_WRONLY | libc::O_CREAT | libc::O_TRUNC;

    #[test]
    fn o_creat_on_an_existing_file_is_a_write() {
        let out = run(
            &[
                open("/p/new", WRITE_NEW, Some(false), Ok(3)),
                open("/p/old", WRITE_NEW, Some(true), Ok(3)),
            ],
            &["/p/new", "/p/old"],
        );
        assert_eq!(out[0].1, Bucket::Create);
        assert_eq!(out[1].1, Bucket::Write);
    }

    #[test]
    fn atomic_rename_is_reported_as_write() {
        let out = run(
            &[
                open("/p/.cfg.tmp", WRITE_NEW, Some(false), Ok(3)),
                ev(
                    Call::Rename {
                        from: arg("/p/.cfg.tmp"),
                        to: arg("/p/cfg"),
                        flags: 0,
                        to_existed: Some(true),
                    },
                    Ok(0),
                ),
            ],
            &["/p/cfg"],
        );
        assert_eq!(
            out[0],
            ("/p/.cfg.tmp".into(), Bucket::Temp, Some(Hidden::Temp))
        );
        assert_eq!(out[1], ("/p/cfg".into(), Bucket::Write, None));
    }

    #[test]
    fn path_search_misses_are_not_missing() {
        let out = run(
            &[
                stat("/h/.local/bin/git", Err(libc::ENOENT)),
                stat("/usr/bin/git", Ok(0)),
                open("/p/src/foo.ts", 0, None, Err(libc::ENOENT)),
                open("/p/src/foo.tsx", 0, None, Ok(3)),
                open("/p/.env.local", 0, None, Err(libc::ENOENT)),
                open("/p/.env", 0, None, Ok(3)),
            ],
            &["/usr/bin/git", "/p/src/foo.tsx", "/p/.env"],
        );
        assert_eq!(out[0].2, Some(Hidden::Probe));
        assert_eq!(out[2].2, Some(Hidden::Probe));
        assert_eq!(out[4], ("/p/.env.local".into(), Bucket::Missing, None));
    }

    #[test]
    fn writes_are_shown_even_in_system_dirs() {
        let out = run(
            &[
                open("/usr/local/bin/tool", WRITE_NEW, Some(false), Ok(3)),
                open("/usr/lib/libc.so.6", libc::O_RDONLY, None, Ok(3)),
                open("/dev/null", libc::O_WRONLY, None, Ok(3)),
            ],
            &["/usr/local/bin/tool", "/usr/lib/libc.so.6", "/dev/null"],
        );
        assert_eq!(out[0], ("/usr/local/bin/tool".into(), Bucket::Create, None));
        assert_eq!(out[1].2, Some(Hidden::Zone));
        assert_eq!(out[2].2, Some(Hidden::Pseudo));
    }
}
