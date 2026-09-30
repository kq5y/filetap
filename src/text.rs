//! The report as text: one line per path, grouped by what happened to it,
//! with big directories folded into one line.

use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use crate::aggregate::{Kind, Record};
use crate::classify::{Bucket, Class, Hidden};
use crate::zone::{Context, parent, under};

/// Entries under one directory before it folds into a single line.
const FOLD_MIN: usize = 10;
/// Missing paths under one missing directory before they fold.
const MISSING_FOLD_MIN: usize = 5;
/// Directories one missing name was looked for in before they fold.
const SAME_NAME_MIN: usize = 3;
const MAX_LINES: usize = 40;
const MAX_NOTE_COLUMN: usize = 40;

const SECTIONS: &[(Bucket, &str)] = &[
    (Bucket::Exec, "EXEC"),
    (Bucket::Read, "READ"),
    (Bucket::Missing, "MISSING"),
    (Bucket::Denied, "DENIED"),
    (Bucket::Create, "CREATE"),
    (Bucket::Write, "WRITE"),
    (Bucket::Rename, "RENAME"),
    (Bucket::Delete, "DELETE"),
    (Bucket::Temp, "TEMPORARY"),
    (Bucket::Stat, "STAT ONLY"),
];

struct Line {
    text: String,
    note: String,
}

pub struct Report<'a> {
    pub records: &'a [Record],
    pub classes: &'a [Class],
    pub ctx: &'a Context,
    /// -a: nothing hidden, nothing folded.
    pub all: bool,
    /// -v: which programs touched each path, and what they tried first.
    pub verbose: bool,
    /// pid -> the program it last exec'd, for -v.
    pub names: HashMap<i32, String>,
    pub color: bool,
    /// --sort path: by path instead of in the order things happened.
    pub by_path: bool,
}

const BOLD: &str = "\x1b[1m";
const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

impl Report<'_> {
    pub fn write(&self, w: &mut dyn Write) -> io::Result<()> {
        for &(bucket, title) in SECTIONS {
            let mut entries: Vec<usize> = (0..self.records.len())
                .filter(|&i| self.classes[i].bucket == bucket && self.visible(i))
                .collect();
            if entries.is_empty() {
                continue;
            }
            entries.sort_by(|&a, &b| {
                let (a, b) = (&self.records[a], &self.records[b]);
                let key = |r: &Record| {
                    let order = if self.by_path { 0 } else { r.first_seen };
                    (self.ctx.rank(&r.path), order)
                };
                key(a).cmp(&key(b)).then_with(|| a.path.cmp(&b.path))
            });
            let lines = if self.all || matches!(bucket, Bucket::Exec | Bucket::Rename) {
                entries.iter().map(|&i| self.line(i)).collect()
            } else {
                self.fold(bucket, &entries)
            };
            let color = match bucket {
                _ if !self.color => "",
                Bucket::Missing => YELLOW,
                Bucket::Denied => RED,
                _ => "",
            };
            writeln!(w)?;
            writeln!(w, "{}", self.bold(title))?;
            write_lines(w, &lines, !self.all, color)?;
        }
        self.summary(w)
    }

    fn bold(&self, s: &str) -> String {
        if self.color {
            format!("{BOLD}{s}{RESET}")
        } else {
            s.to_string()
        }
    }

    fn visible(&self, i: usize) -> bool {
        match self.classes[i].hidden {
            None => true,
            Some(Hidden::Moved | Hidden::Filtered) => false,
            Some(_) => self.all,
        }
    }

    fn line(&self, i: usize) -> Line {
        let r = &self.records[i];
        let c = &self.classes[i];
        let mut text = self.ctx.display(&r.path);
        if r.kind_after == Some(Kind::Dir) && !text.ends_with('/') {
            text.push('/');
        }
        if c.bucket == Bucket::Rename
            && let Some(to) = r.moved_to
        {
            text = format!("{text} -> {}", self.ctx.display(&self.records[to].path));
        }
        let o = &r.ops;
        let mut notes: Vec<String> = Vec::new();
        if c.atomic {
            notes.push("atomic".into());
        } else if c.bucket == Bucket::Write && o.attr > 0 && o.write + o.create + o.moved_in == 0 {
            notes.push("attrs".into());
        } else if c.hidden == Some(Hidden::Probe) {
            notes.push("lookup".into());
        }
        if self.verbose {
            if c.bucket == Bucket::Write && o.read > 0 {
                notes.push("rw".into());
            }
            let times = o.read
                + o.list
                + o.write
                + o.create
                + o.delete
                + o.exec
                + o.stat
                + o.attr
                + o.moved_in
                + o.moved_out
                + r.errors.missing
                + r.errors.denied
                + r.errors.other;
            if times > 1 {
                notes.push(format!("{times}x"));
            }
            let mut by: Vec<&str> = Vec::new();
            for pid in &r.pids {
                if let Some(n) = self.names.get(pid)
                    && !by.contains(&n.as_str())
                {
                    by.push(n);
                }
            }
            if !by.is_empty() {
                notes.push(by.join(", "));
            }
            if !c.lookups_before.is_empty() {
                let tried: Vec<String> = c
                    .lookups_before
                    .iter()
                    .map(|&j| self.ctx.display(&self.records[j].path))
                    .collect();
                notes.push(format!("tried {} first", tried.join(", ")));
            }
        }
        Line {
            text,
            note: if notes.is_empty() {
                String::new()
            } else {
                format!("({})", notes.join("; "))
            },
        }
    }

    fn fold(&self, bucket: Bucket, entries: &[usize]) -> Vec<Line> {
        let paths: Vec<&[u8]> = entries
            .iter()
            .map(|&i| self.records[i].path.as_slice())
            .collect();

        let mut counts: HashMap<&[u8], usize> = HashMap::new();
        for &p in &paths {
            for a in ancestors(p, &self.ctx.fold_base(p)) {
                *counts.entry(a).or_default() += 1;
            }
        }

        let mut walks: HashMap<&[u8], usize> = HashMap::new();
        let mut names: HashMap<(u8, &[u8]), usize> = HashMap::new();
        if bucket == Bucket::Missing {
            for &p in &paths {
                if let Some(t) = self.walk_tail(p) {
                    *walks.entry(t).or_default() += 1;
                }
            }
            for &p in &paths {
                if self.walk_tail(p).is_none_or(|t| walks[t] == 1) {
                    *names.entry((self.ctx.rank(p), basename(p))).or_default() += 1;
                }
            }
        }

        let mut keys: Vec<Key> = entries
            .iter()
            .zip(&paths)
            .map(|(&i, &p)| {
                if self.classes[i].pinned {
                    return Key::Path(p);
                }
                if bucket != Bucket::Missing {
                    return self.fold_key(p, &counts).map_or(Key::Path(p), Key::Dir);
                }
                let name = (self.ctx.rank(p), basename(p));
                match self.walk_tail(p) {
                    Some(t) if walks[t] > 1 => Key::Walk(t),
                    _ if names[&name] >= SAME_NAME_MIN => Key::Name(name.0, name.1),
                    _ => self.missing_dir(p, &paths).map_or(Key::Path(p), Key::Dir),
                }
            })
            .collect();
        // A directory that's listed itself joins the line its contents
        // folded into.
        let dirs: HashSet<Key> = keys
            .iter()
            .filter(|k| matches!(k, Key::Dir(_)))
            .copied()
            .collect();
        for k in &mut keys {
            if let Key::Path(p) = *k
                && dirs.contains(&Key::Dir(p))
            {
                *k = Key::Dir(p);
            }
        }

        // Keep the order in which the groups first appear.
        let mut order: Vec<Key> = Vec::new();
        let mut groups: HashMap<Key, Vec<usize>> = HashMap::new();
        for (&i, &key) in entries.iter().zip(&keys) {
            groups
                .entry(key)
                .or_insert_with(|| {
                    order.push(key);
                    Vec::new()
                })
                .push(i);
        }

        order
            .into_iter()
            .map(|key| {
                let members = &groups[&key];
                let n = members.len();
                match key {
                    Key::Path(_) => self.line(members[0]),
                    Key::Walk(_) | Key::Name(..) if n == 1 => self.line(members[0]),
                    Key::Walk(_) => {
                        let mut line = self.line(members[0]);
                        let dirs = if n == 2 { "dir" } else { "dirs" };
                        line.note = format!("(and {} parent {dirs})", count(n - 1));
                        line
                    }
                    Key::Name(..) => {
                        let mut line = self.line(members[0]);
                        line.note = format!("(and {} other dirs)", count(n - 1));
                        line
                    }
                    Key::Dir(dir) => Line {
                        text: format!("{}/", self.ctx.display(dir)),
                        note: if bucket == Bucket::Missing {
                            format!("({} paths; directory missing)", count(n))
                        } else {
                            format!("({} {})", count(n), if n == 1 { "file" } else { "files" })
                        },
                    },
                }
            })
            .collect()
    }

    /// Tools that look for their config in the cwd and every directory above
    /// it (`rust-toolchain.toml`, `.cargo/config.toml`, `.eslintrc`) try
    /// the same name in each. Returns that name when `p` is one of those
    /// tries.
    fn walk_tail<'p>(&self, p: &'p [u8]) -> Option<&'p [u8]> {
        let mut end = p.len();
        for _ in 0..2 {
            let slash = p[..end].iter().rposition(|&b| b == b'/')?;
            let dir: &[u8] = if slash == 0 { b"/" } else { &p[..slash] };
            if under(&self.ctx.cwd, dir) {
                return Some(&p[slash + 1..]);
            }
            end = slash;
        }
        None
    }

    /// The shallowest directory that has enough entries under it, then as
    /// deep as it goes without losing any of them: `/usr/local/lib/foo/`
    /// says more than `/usr/`.
    fn fold_key<'p>(&self, p: &'p [u8], counts: &HashMap<&[u8], usize>) -> Option<&'p [u8]> {
        let point = self.ctx.fold_point(p);
        let chain: Vec<&[u8]> = ancestors(p, &self.ctx.fold_base(p)).collect();
        for (k, &a) in chain.iter().enumerate() {
            let n = counts[a];
            if (point.as_deref() == Some(a) && n >= 2) || n >= FOLD_MIN {
                return chain[k..]
                    .iter()
                    .take_while(|&&b| counts[b] == n)
                    .last()
                    .copied();
            }
        }
        None
    }

    /// `./.cache/foo/` when a lookup tried many names in a directory that
    /// doesn't exist.
    fn missing_dir<'p>(&self, p: &'p [u8], paths: &[&[u8]]) -> Option<&'p [u8]> {
        let dir = parent(p)?;
        let n = paths.iter().filter(|q| parent(q) == Some(dir)).count();
        let gone = !Path::new(OsStr::from_bytes(dir)).exists();
        (n >= MISSING_FOLD_MIN && gone).then_some(dir)
    }

    fn summary(&self, w: &mut dyn Write) -> io::Result<()> {
        let mut shown: HashMap<Bucket, usize> = HashMap::new();
        let mut hidden: HashMap<&str, usize> = HashMap::new();
        for c in self.classes {
            match c.hidden {
                None => *shown.entry(c.bucket).or_default() += 1,
                Some(h) => {
                    let what = match h {
                        Hidden::Zone => "system/toolchain",
                        Hidden::Virtual => "virtual",
                        Hidden::Probe => "lookup probes",
                        Hidden::Temp => "temp files",
                        Hidden::Stat | Hidden::Pseudo | Hidden::Moved | Hidden::Filtered => {
                            continue;
                        }
                    };
                    *hidden.entry(what).or_default() += 1;
                }
            }
        }
        let n = |b| shown.get(&b).copied().unwrap_or(0);

        let mut parts: Vec<String> = [
            (Bucket::Read, "read"),
            (Bucket::Write, "written"),
            (Bucket::Create, "created"),
            (Bucket::Rename, "renamed"),
            (Bucket::Delete, "deleted"),
            (Bucket::Missing, "missing"),
            (Bucket::Denied, "denied"),
        ]
        .iter()
        .filter(|(b, _)| n(*b) > 0)
        .map(|(b, what)| format!("{} {what}", count(n(*b))))
        .collect();
        match n(Bucket::Exec) {
            0 => {}
            1 => parts.push("1 program run".into()),
            e => parts.push(format!("{} programs run", count(e))),
        }
        let changed: usize = [
            Bucket::Create,
            Bucket::Write,
            Bucket::Rename,
            Bucket::Delete,
        ]
        .iter()
        .map(|&b| n(b))
        .sum();
        if changed == 0 {
            // Worth saying out loud: often the question is "does this only
            // read?"
            parts.push("no files modified".into());
        }

        writeln!(w)?;
        writeln!(w, "{}", self.bold("Summary"))?;
        writeln!(w, "  {}", parts.join(", "))?;
        if !self.all && !hidden.is_empty() {
            let parts: Vec<String> = ["system/toolchain", "virtual", "lookup probes", "temp files"]
                .iter()
                .filter_map(|k| {
                    let n = *hidden.get(k)?;
                    let k = if n == 1 { k.trim_end_matches('s') } else { k };
                    Some(format!("{} {k}", count(n)))
                })
                .collect();
            writeln!(w, "  not shown: {} (use -a)", parts.join(", "))?;
        }
        Ok(())
    }
}

fn write_lines(w: &mut dyn Write, lines: &[Line], limit: bool, color: &str) -> io::Result<()> {
    let reset = if color.is_empty() { "" } else { RESET };
    let shown = if limit && lines.len() > MAX_LINES {
        &lines[..MAX_LINES]
    } else {
        lines
    };
    let width = shown
        .iter()
        .filter(|l| !l.note.is_empty())
        .map(|l| l.text.chars().count())
        .max()
        .unwrap_or(0)
        .min(MAX_NOTE_COLUMN);
    for l in shown {
        if l.note.is_empty() {
            writeln!(w, "  {color}{}{reset}", l.text)?;
        } else {
            let pad = width.saturating_sub(l.text.chars().count());
            writeln!(w, "  {color}{}{reset}{:pad$}  {}", l.text, "", l.note)?;
        }
    }
    if shown.len() < lines.len() {
        writeln!(
            w,
            "  ... and {} more (use -a to see all)",
            count(lines.len() - shown.len())
        )?;
    }
    Ok(())
}

#[derive(Clone, Copy, PartialEq, Eq, Hash)]
enum Key<'a> {
    Path(&'a [u8]),
    /// Folded into a directory line.
    Dir(&'a [u8]),
    /// The same name looked up in the cwd and its parents.
    Walk(&'a [u8]),
    /// The same name looked up in many directories of one area, like
    /// `.gitattributes` in every directory git looks at.
    Name(u8, &'a [u8]),
}

/// Directories strictly between `base` and `p`, shallowest first.
fn ancestors<'p>(p: &'p [u8], base: &[u8]) -> impl Iterator<Item = &'p [u8]> {
    let start = if base == b"/" { 1 } else { base.len() + 1 };
    (start..p.len())
        .filter(move |&i| p[i] == b'/')
        .map(move |i| &p[..i])
}

fn basename(p: &[u8]) -> &[u8] {
    p.rsplit(|&b| b == b'/').next().unwrap_or(p)
}

/// 1,732
fn count(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}
