use std::ffi::OsString;
use std::path::PathBuf;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "See what files a command actually touches",
    after_help = "Examples:
  filetap -- npm test
  filetap -o report.txt -- make"
)]
pub struct Args {
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
