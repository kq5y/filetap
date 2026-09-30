//! --only, --outside, --hide and --show. Unlike folding, which is only about
//! how the text looks, these decide what's in the report at all.

use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;

use globset::{GlobBuilder, GlobSet, GlobSetBuilder};

use crate::aggregate::Record;
use crate::classify::{Bucket, Class, Hidden};
use crate::cli::Args;
use crate::zone::{Context, Zone, escape, under};

pub struct Filter {
    only: Option<Vec<Bucket>>,
    outside: bool,
    hide: GlobSet,
    show: GlobSet,
    /// For the header and the JSON: what was asked for, as it was typed.
    pub described: Vec<String>,
}

impl Filter {
    pub fn new(args: &Args, ctx: &Context) -> Result<Filter, String> {
        let mut only: Vec<Bucket> = Vec::new();
        let mut described = Vec::new();
        if args.writes {
            only.extend([
                Bucket::Create,
                Bucket::Write,
                Bucket::Rename,
                Bucket::Delete,
            ]);
            described.push("--writes".to_string());
        }
        if args.missing {
            only.extend([Bucket::Missing, Bucket::Denied]);
            described.push("--missing".to_string());
        }
        if !args.only.is_empty() {
            only.extend(args.only.iter().map(|k| bucket(k)));
            described.push(format!("--only {}", args.only.join(",")));
        }
        if args.outside {
            described.push("--outside".to_string());
        }
        if !args.hide.is_empty() {
            described.push(format!("--hide {}", args.hide.join(" --hide ")));
        }
        Ok(Filter {
            only: (!only.is_empty()).then_some(only),
            outside: args.outside,
            hide: globs(&args.hide, ctx)?,
            show: globs(&args.show, ctx)?,
            described,
        })
    }

    pub fn apply(&self, records: &[Record], classes: &mut [Class], ctx: &Context) {
        for (r, c) in records.iter().zip(classes.iter_mut()) {
            let path = OsStr::from_bytes(&r.path);
            let shown = self.show.is_match(path);
            let dropped = self.only.as_ref().is_some_and(|o| !o.contains(&c.bucket))
                || (self.outside && !outside(r, c, ctx))
                || (!shown && self.hide.is_match(path));
            if dropped {
                c.hidden = Some(Hidden::Filtered);
            } else if shown {
                if c.hidden != Some(Hidden::Moved) {
                    c.hidden = None;
                }
                c.pinned = true;
            }
        }
    }
}

/// Outside the project, not counting the system and toolchains every
/// program reads. Changes count wherever they are.
fn outside(r: &Record, c: &Class, ctx: &Context) -> bool {
    if under(&r.path, &ctx.root) {
        return false;
    }
    c.bucket.is_change()
        || !matches!(
            ctx.zone(&r.path),
            Zone::System | Zone::Toolchain | Zone::Virtual
        )
}

pub const KINDS: [&str; 8] = [
    "read", "write", "create", "delete", "rename", "exec", "missing", "denied",
];

fn bucket(kind: &str) -> Bucket {
    match kind {
        "read" => Bucket::Read,
        "write" => Bucket::Write,
        "create" => Bucket::Create,
        "delete" => Bucket::Delete,
        "rename" => Bucket::Rename,
        "exec" => Bucket::Exec,
        "missing" => Bucket::Missing,
        _ => Bucket::Denied,
    }
}

/// `/x` is absolute, `~/x` is under $HOME, `./x` and `x/y` are under the
/// project root, and a bare `*.log` matches file names anywhere. A pattern
/// without wildcards also matches everything under it, so `--hide /opt`
/// works like `--hide '/opt/**'`.
fn globs(pats: &[String], ctx: &Context) -> Result<GlobSet, String> {
    let mut set = GlobSetBuilder::new();
    for pat in pats {
        let root = escape(&ctx.root);
        let full = if let Some(rest) = pat.strip_prefix("~/") {
            let home = ctx
                .home
                .as_deref()
                .ok_or("--hide/--show: $HOME is not set")?;
            format!("{}/{rest}", escape(home))
        } else if let Some(rest) = pat.strip_prefix("./") {
            format!("{root}/{rest}")
        } else if pat.starts_with('/') {
            pat.clone()
        } else if pat.contains('/') {
            format!("{root}/{pat}")
        } else {
            format!("**/{pat}")
        };
        let full = full.trim_end_matches('/');
        let mut variants = vec![full.to_string()];
        if !full.contains(['*', '?', '[', '{']) {
            variants.push(format!("{full}/**"));
        }
        for v in variants {
            let glob = GlobBuilder::new(&v)
                .literal_separator(true)
                .build()
                .map_err(|e| format!("{pat}: {e}"))?;
            set.add(glob);
        }
    }
    set.build().map_err(|e| e.to_string())
}
