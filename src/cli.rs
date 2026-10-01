use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};

#[derive(Parser, Debug)]
#[command(
    version,
    about = "See what files a command actually touches",
    after_help = "Examples:
  filetap -- npm test
  filetap --outside -- npm test     what it reads from outside the repo
  filetap -w -- ./install.sh        what it changed
  filetap -m -- mycli               what it looked for and didn't find"
)]
pub struct Args {
    /// Only show changes: created, written, renamed and deleted files
    #[arg(short, long)]
    pub writes: bool,

    /// Only show what wasn't found or wasn't allowed
    #[arg(short, long)]
    pub missing: bool,

    /// Only show these kinds of access
    #[arg(long, value_name = "KINDS", value_delimiter = ',', value_parser = crate::filter::KINDS)]
    pub only: Vec<String>,

    /// Only show paths outside the project (leaving out system files)
    #[arg(long)]
    pub outside: bool,

    /// Leave out paths matching GLOB
    #[arg(long, value_name = "GLOB")]
    pub hide: Vec<String>,

    /// Always show paths matching GLOB, unfolded, even if hidden otherwise
    #[arg(long, value_name = "GLOB")]
    pub show: Vec<String>,

    /// Show everything: no folding, nothing hidden
    #[arg(short, long)]
    pub all: bool,

    /// Also show which programs touched each path and what they looked for
    /// first
    #[arg(short, long)]
    pub verbose: bool,

    /// List what each process did, one process at a time
    #[arg(long)]
    pub by_process: bool,

    /// Also print each path to stderr as it's first touched, while the
    /// command runs
    #[arg(long)]
    pub live: bool,

    #[arg(long, value_name = "WHEN", default_value = "auto")]
    pub color: Color,

    /// Order within each section: when first touched, or by path
    #[arg(long, value_name = "ORDER", default_value = "time")]
    pub sort: Sort,

    /// Write the report as JSON, hidden entries included
    #[arg(long)]
    pub json: bool,

    /// Instead of the report, write each file access as a JSON line as it
    /// happens
    #[arg(long, conflicts_with_all = ["json", "by_process", "live"])]
    pub jsonl: bool,

    /// Write the report to FILE instead of stderr ("-" for stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Treat DIR as the project root [default: the git toplevel, or the cwd]
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Keep tracing until background processes started by the command exit
    #[arg(long)]
    pub wait: bool,

    /// Stop the command at every syscall instead of using a seccomp filter
    /// (much slower; for systems where seccomp isn't available)
    #[arg(long)]
    pub no_seccomp: bool,

    /// Save the raw syscall events as JSON lines to FILE (for bug reports)
    #[arg(long, value_name = "FILE")]
    pub dump_events: Option<PathBuf>,

    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Sort {
    Time,
    Path,
}

#[derive(ValueEnum, Clone, Copy, Debug, PartialEq)]
pub enum Color {
    Auto,
    Always,
    Never,
}
