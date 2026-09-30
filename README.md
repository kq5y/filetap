# filetap

See what files a command actually touches.

`filetap -- <command>` runs the command, follows it and everything it starts,
and when it exits prints which files were read, written, created, deleted and
run, and which were looked for and not found. One line per path, not a log of
every syscall.

Here is `cargo build` in this repository, showing only what's outside it:

```
$ filetap --outside -- cargo build
    Finished `dev` profile [unoptimized + debuginfo] target(s) in 0.18s

filetap: cargo build exited 0 after 0.23s (1 process) (filtered: --outside)

READ
  ~/.gitconfig

MISSING
  ~/.config/git/config
  /home/user/rust-toolchain       (and 2 parent dirs)
  /home/user/rust-toolchain.toml  (and 2 parent dirs)
  /home/user/.cargo/config        (and 2 parent dirs)
  /home/user/.cargo/config.toml   (and 2 parent dirs)
  /etc/gitconfig

WRITE
  ~/.cargo/.package-cache
  ~/.cargo/.global-cache
  ~/.cargo/.package-cache-mutate

Summary
  1 read, 3 written, 14 missing
  not shown: 11 lookup probes (use -a)
```

Cargo reads my git config, and looks for `rust-toolchain` and
`.cargo/config.toml` in the repo and in every directory above it, up to `/`.
None of those exist on this machine. If one turned up in `/home` on someone
else's, their build would be different from mine and nothing in the repo
would say why. Finding that kind of thing is what filetap is for.

## Install

```
curl -L https://github.com/kq5y/filetap/releases/latest/download/filetap_linux_$(uname -m).tar.gz | tar xz
```

The release binaries are static, for x86_64 and aarch64. To build from
source: `cargo install --git https://github.com/kq5y/filetap`.

Linux 5.3 or later. It doesn't need root and doesn't change anything on the
system.

## More examples

What did an install change? `-w` shows only created, written, renamed and
deleted files:

```
$ filetap -w -- .venv/bin/pip install --no-cache-dir -q six

filetap: .venv/bin/pip install --no-cache-dir -q six exited 0 after 3.40s (19 processes) (filtered: --writes)

CREATE
  ./.venv/lib/python3.11/site-packages/  (11 files)

Summary
  11 created
```

Everything went into the venv. The 11 files are folded into their directory;
`-a` lists them.

What did it look for and not find? `-m`:

```
$ filetap -m -- git status --short

filetap: git status --short exited 0 after 0.02s (1 process) (filtered: --missing)

MISSING
  ~/.config/git/ignore
  /etc/gitconfig

Summary
  2 missing, no files modified
  not shown: 1 system/toolchain, 27 lookup probes (use -a)
```

`--only exec` shows which programs were run, `--json` writes everything
(hidden entries included, with the reason they were hidden) for other tools,
and `-v` adds which programs touched each path and what they tried before
finding it. `filetap --help` has the rest.

## Reading the report

Each path is listed once, under the thing that happened to it, in this order:
EXEC, READ, MISSING, DENIED, then CREATE, WRITE, RENAME, DELETE. Within a
section, paths in the current directory come first, then the rest of the
project, then your home directory, then everything else.

A lot is left out by default, and the summary says how much:

- Reads of system files and toolchains (`/usr`, `~/.rustup`, `~/.nvm`, a
  Python or Node install found from where it was run), and of `/proc`,
  `/sys` and `/dev`.
- Lookups that were part of a search: `PATH`, module resolution trying
  `foo.ts` before `foo.tsx`, a config file tried in several places before it
  was found. These aren't missing, they're how the program found what it
  used.
- Files that were created and removed again before the command ended.

Changes are never left out, wherever they are. A write under `/usr/local` or
`/etc` is listed like one in your project. Directories with many entries fold
into one line, and a file looked for in the current directory and all its
parents shows once. `-a` turns all of this off. `--show GLOB` does it for
matching paths only, `--hide GLOB` goes the other way.

## Background processes

If the command leaves something running (a daemon, a build server,
anything started with `setsid`), filetap still reports as soon as the command
itself exits, and says what's left:

```
filetap: 1 background process still running (sleep[4121]); their later file access is not in this report
```

Those processes keep being traced in the background so they work normally,
but what they do from then on isn't reported. `--wait` waits for them before
printing the report; Ctrl-C while it waits prints what it has so far.

## How it works

filetap forks a tracer process, which starts the command under ptrace with a
seccomp filter. The filter stops the command only on file-related syscalls:
open, stat, exec, rename, unlink, mkdir and a few dozen others. Everything
else runs at full speed.

At each stop, before the kernel runs the call, the tracer reads the
arguments, resolves relative paths through `/proc/<pid>/cwd` and
`/proc/<pid>/fd`, and for calls that can create a file checks whether it's
already there. That's how a file created by `O_CREAT` is told apart from an
existing one being overwritten. It then lets the call run and picks up the
result when it returns.

The report is built from those events once the command exits. `read` and
`write` aren't traced: a file opened for writing counts as written.

The tracer is a separate process so it can outlive the report. When the
command exits, filetap prints and returns to the shell, and the tracer stays
behind until anything the command left running is gone. It can't just
detach from them: the seccomp filter stays with a process for good, and
without a tracer every filtered syscall would fail.

## Caveats

- Linux only. x86_64 is what I use it on; aarch64 builds and should work
  but has seen less use. 32-bit programs on x86_64 aren't traced.
- setuid programs don't get their privileges under filetap, so
  `filetap -- sudo make install` doesn't work. `sudo filetap -- make install`
  does.
- It can't trace a debugger or another tracer (`gdb`, `strace`).
- Access through io_uring, or through file descriptors that were already open
  when the command started, isn't seen.
- READ and WRITE mean the file was opened to read or write, not that any
  bytes moved.
- `..` in a path is resolved without looking at symlinks.
- Paths in `--json` include your home directory, which has your user name
  in it.
- It costs a stop per file syscall. A build that spends its time compiling
  hardly notices. A script that imports and reads the whole Python standard
  library (about 13,000 file syscalls in 1.3 seconds) takes about twice as
  long, which is also what strace takes.

If something is reported wrong, `--dump-events FILE` saves what the tracer
saw before any of the above was applied; attaching it to an issue helps.

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or
[MIT license](LICENSE-MIT) at your option.

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in filetap by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.
