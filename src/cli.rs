use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

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

    /// Write the report to FILE instead of stderr ("-" for stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Treat DIR as the project root [default: the git toplevel, or the cwd]
    #[arg(long, value_name = "DIR")]
    pub root: Option<PathBuf>,

    /// Keep tracing until background processes started by the command exit
    #[arg(long)]
    pub wait: bool,

    /// Save the raw syscall events as JSON lines to FILE (for bug reports)
    #[arg(long, value_name = "FILE")]
    pub dump_events: Option<PathBuf>,

    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}
