mod cli;

use std::process::exit;

use clap::Parser;

fn main() {
    // Usage errors exit with 125 like env(1) and timeout(1), so they can't be
    // mistaken for the command's own exit status.
    let args = cli::Args::try_parse().unwrap_or_else(|e| {
        let _ = e.print();
        exit(if e.use_stderr() { 125 } else { 0 });
    });
    eprintln!("{:?}", args.command);
}
