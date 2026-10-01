# filetap

See what files a command actually touches.

`filetap -- <command>` runs a command and, when it exits, prints what it and
every process it started read, wrote, created, deleted and ran, and what
they looked for and didn't find. One line per path.

This is an alpha: options and the report format may still change.

```
$ filetap --outside -- cargo build
   Compiling filetap v0.0.1 (/home/dev/src/filetap)
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 1.57s

filetap: cargo build exited 0 after 1.60s (5 processes) (filtered: --outside)

EXEC
  ~/.cargo/bin/cargo

READ
  ~/.gitconfig
  ~/.cargo/registry/  (145 files)

MISSING
  ~/src/rust-toolchain       (and 3 parent dirs)
  ~/src/rust-toolchain.toml  (and 3 parent dirs)
  ~/src/.cargo/config        (and 3 parent dirs)
  ~/src/.cargo/config.toml   (and 3 parent dirs)
  ~/.config/git/config
  /etc/gitconfig

WRITE
  ~/.cargo/.package-cache
  ~/.cargo/.global-cache
  ~/.cargo/.package-cache-mutate

Summary
  146 read, 3 written, 18 missing, 1 program run
  not shown: 28 lookup probes, 3 temp files (use -a)
```

Cargo looks for `rust-toolchain` and `.cargo/config.toml` in every directory
from the repo up to `/`. None exist here, but one in `~/src` on another
machine would change the build there.

## Install

```
curl -L https://github.com/kq5y/filetap/releases/latest/download/filetap_linux_$(uname -m).tar.gz | tar xz
```

or `cargo install --git https://github.com/kq5y/filetap`.

- Linux 5.3 or later, x86_64 or aarch64
- Static binary, no root, nothing to set up

## Usage

```
filetap [OPTIONS] -- <COMMAND> [ARGS...]
```

| Option | |
| --- | --- |
| `--outside` | Only paths outside the project, leaving out system files |
| `-w`, `--writes` | Only created, written, renamed and deleted files |
| `-m`, `--missing` | Only what wasn't found or wasn't allowed |
| `--only KINDS` | Only these sections: `read,write,create,delete,rename,exec,missing,denied` |
| `--hide GLOB` | Leave out matching paths |
| `--show GLOB` | Always list matching paths, unfolded |
| `-a`, `--all` | Nothing hidden, nothing folded |
| `-v`, `--verbose` | How often each path was touched, by which programs, and what they tried first |
| `--by-process` | One list per process, under the command line it ran |
| `--live` | Also print each path to stderr as it's first touched (`<---` read, `--->` written, ` >>>` run, ` ?--` not found) |
| `--sort path` | Sort by path instead of by when each path was first touched |
| `--json` | Everything, including what's hidden and why |
| `-o FILE` | Write the report to FILE (default stderr, `-` for stdout) |
| `--wait` | Also wait for processes the command left running |
| `--root DIR` | Project root (default: git toplevel, else the cwd) |
| `--no-seccomp` | Stop at every syscall; slower, for systems without seccomp |

Globs starting with `/`, `~/` or `./` are absolute, home-relative or
root-relative. `*.log` matches a file name anywhere.

filetap exits with the command's status (128+N if it was killed by signal
N), or 125 if filetap itself failed, 126 if the command couldn't be run,
127 if it wasn't found.

## Examples

What did an install change?

```
$ filetap -w -- .venv/bin/pip install -q requests

filetap: .venv/bin/pip install -q requests exited 0 after 4.00s (18 processes) (filtered: --writes)

CREATE
  ./.venv/   (239 files)
  ~/.cache/  (102 files)

Summary
  341 created
```

What did it look for and not find?

```
$ filetap -m -- git status --short

filetap: git status --short exited 0 after 0.03s (1 process) (filtered: --missing)

MISSING
  ./.gitattributes  (and 7 other dirs)
  ~/.config/git/attributes
  ~/.config/git/ignore
  /etc/gitconfig
  /etc/gitattributes

Summary
  12 missing, no files modified
  not shown: 2 system/toolchain, 29 lookup probes (use -a)
```

## The report

| Section | |
| --- | --- |
| EXEC | Programs run |
| READ | Files and directories read |
| MISSING | Looked for, not there |
| DENIED | There, but not allowed |
| CREATE | Didn't exist before, exists now |
| WRITE | Existed and was changed, including by renaming a new file over it (`(atomic)`) |
| RENAME | Moved, as `old -> new` |
| DELETE | Existed and is gone |

Each path is listed once. Paths in the current directory come first, then
the rest of the project, your home directory, and the rest of the system.

Left out unless you ask with `-a`, and counted in the summary:

- reads of system files and toolchains (`/usr`, `~/.rustup`, `~/.nvm`), and
  of `/proc`, `/sys` and `/dev`
- failed lookups that were part of a search: `PATH`, module resolution,
  a config file tried in several places before one was found
- files created and removed again during the run

Changes are always listed, wherever they are. Directories with many entries
fold into one line, and so does a name looked up in many directories.

Files that exist to hold a key or a token (`~/.ssh/id_*`,
`~/.aws/credentials`, `~/.netrc`, `.env`) are marked `(credentials)` when
opened, and never folded.

## Background processes

If the command leaves processes running (a daemon, a build server), filetap
reports when the command exits and says what's still running. Those
processes keep working, but what they do afterwards isn't in the report.
`--wait` waits for them first.

## How it works

- filetap forks a tracer, which starts the command under ptrace with a
  seccomp filter that stops it only on file syscalls (open, stat, exec,
  rename, unlink, mkdir and about 40 more).
- At each stop the tracer reads the path, resolves it against the process's
  cwd or dirfd through `/proc`, and, for calls that can create a file,
  checks whether it already exists before the kernel runs the call. That's
  how CREATE and WRITE are told apart.
- `read` and `write` aren't traced. A file opened for writing counts as
  written.
- The tracer is a separate process so it can stay behind for anything the
  command left running. A process with the seccomp filter can't run without
  a tracer.

## Caveats

- Linux only, x86_64 and aarch64 (both tested in CI). 32-bit programs
  aren't traced; filetap warns when one runs.
- setuid programs lose their privileges (filetap says when that happens):
  use `sudo filetap -- make install`, not `filetap -- sudo make install`.
- A debugger or tracer (`gdb`, `strace`) can't run under filetap.
- Not seen: access through io_uring, or through file descriptors inherited
  from before the command started.
- `--json` output has full paths, including your home directory.
- Each file syscall costs a stop. Reading the whole Python standard library
  (13,000 file syscalls in 1.3 s) takes about twice as long, the same as
  under strace.

If something is reported wrong, `--dump-events FILE` saves the raw events;
please attach it to the issue.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in filetap by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
