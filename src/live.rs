//! --live: a line on stderr the first time each path is read, written, run
//! or looked for, while the command runs. Some of it can only be a guess at
//! that point: a failed lookup may turn out to be one step of a search, so
//! it's marked with `?`. The report at the end has the final word.

use std::io::{self, Write};

use crate::aggregate::Record;
use crate::classify::{self, Bucket};
use crate::filter::Filter;
use crate::zone::{Context, parent};

const READ: u8 = 1;
const WRITE: u8 = 1 << 1;
const CREATE: u8 = 1 << 2;
const DELETE: u8 = 1 << 3;
const MOVE: u8 = 1 << 4;
const EXEC: u8 = 1 << 5;
const MISSING: u8 = 1 << 6;
const DENIED: u8 = 1 << 7;

const YELLOW: &str = "\x1b[33m";
const RED: &str = "\x1b[31m";
const RESET: &str = "\x1b[0m";

pub struct Live {
    /// What has been printed for each record so far.
    printed: Vec<u8>,
    all: bool,
    color: bool,
}

impl Live {
    pub fn new(all: bool, color: bool) -> Live {
        Live {
            printed: Vec::new(),
            all,
            color,
        }
    }

    /// Called after each event with the records it touched.
    pub fn update(
        &mut self,
        records: &[Record],
        touched: &[usize],
        ctx: &mut Context,
        filter: &Filter,
    ) {
        if self.printed.len() < records.len() {
            self.printed.resize(records.len(), 0);
        }
        for &i in touched {
            let r = &records[i];
            let new = what(r) & !self.printed[i];
            self.printed[i] |= new;
            for bit in (0..8).map(|n| 1 << n).filter(|b| new & b != 0) {
                if bit == EXEC {
                    // So reads from its own install are hidden from now on.
                    ctx.exec_seen(&r.path);
                }
                if bit == MOVE
                    && let Some(to) = r.moved_to
                {
                    // Already said as `old -> new`.
                    self.printed[to] |= WRITE | CREATE;
                }
                if self.shows(r, bit, ctx, filter) {
                    self.line(records, r, bit, ctx);
                }
            }
        }
    }

    fn shows(&self, r: &Record, bit: u8, ctx: &Context, filter: &Filter) -> bool {
        let bucket = match bit {
            READ => Bucket::Read,
            WRITE => Bucket::Write,
            CREATE => Bucket::Create,
            DELETE => Bucket::Delete,
            MOVE => Bucket::Rename,
            EXEC => Bucket::Exec,
            MISSING => Bucket::Missing,
            _ => Bucket::Denied,
        };
        let pinned = filter.shows(&r.path);
        if !filter.keeps(&r.path, pinned, bucket, ctx) {
            return false;
        }
        if self.all || pinned {
            return true;
        }
        if classify::hidden(r, bucket, ctx.zone(&r.path)).is_some() {
            return false;
        }
        // A command looked up in each $PATH entry.
        !(bucket == Bucket::Missing
            && parent(&r.path).is_some_and(|d| ctx.path_dirs.iter().any(|p| p == d)))
    }

    fn line(&self, records: &[Record], r: &Record, bit: u8, ctx: &Context) {
        let arrow = match bit {
            READ => "<---",
            EXEC => " >>>",
            MISSING => " ?--",
            DENIED => " !--",
            _ => "--->",
        };
        let mut text = ctx.display(&r.path);
        if bit == READ && r.ops.list > 0 && !text.ends_with('/') {
            text.push('/');
        }
        match bit {
            CREATE => text.push_str(" (new)"),
            DELETE => text.push_str(" (deleted)"),
            MOVE => {
                if let Some(to) = r.moved_to {
                    text = format!("{text} -> {}", ctx.display(&records[to].path));
                }
            }
            _ => {}
        }
        if matches!(bit, READ | WRITE | CREATE)
            && classify::credentials(&r.path, ctx.home.as_deref())
        {
            text.push_str(" (credentials)");
        }
        let color = match bit {
            _ if !self.color => "",
            MISSING => YELLOW,
            DENIED => RED,
            _ => "",
        };
        let reset = if color.is_empty() { "" } else { RESET };
        let _ = writeln!(io::stderr().lock(), "{color}{arrow} {text}{reset}");
    }
}

/// What has happened to a path so far.
fn what(r: &Record) -> u8 {
    let (o, e) = (&r.ops, &r.errors);
    let mut w = 0;
    if o.exec > 0 {
        w |= EXEC;
    }
    if o.read + o.list > 0 {
        w |= READ;
    }
    if o.create > 0 && r.before != Some(true) {
        w |= CREATE;
    } else if o.create + o.write + o.attr + o.moved_in > 0 {
        w |= WRITE;
    }
    if o.delete > 0 {
        w |= DELETE;
    }
    if o.moved_out > 0 {
        w |= MOVE;
    }
    if e.missing > 0 && !o.any() {
        w |= MISSING;
    }
    if e.denied > 0 {
        w |= DENIED;
    }
    w
}
