use std::ffi::OsString;

use clap::Parser;

#[derive(Parser, Debug)]
#[command(
    version,
    about = "See what files a command actually touches",
    after_help = "Examples:
  filetap -- npm test
  filetap -- make"
)]
pub struct Args {
    /// Keep tracing until background processes started by the command exit
    #[arg(long)]
    pub wait: bool,

    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}
