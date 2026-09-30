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
    /// Write the report to FILE instead of stderr ("-" for stdout)
    #[arg(short, long, value_name = "FILE")]
    pub output: Option<PathBuf>,

    /// Keep tracing until background processes started by the command exit
    #[arg(long)]
    pub wait: bool,

    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}
