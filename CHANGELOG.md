# Changelog

## 0.0.1

First release.

- Traces a command and everything it starts with ptrace and a seccomp filter, and reports files read, written, created, renamed, deleted and run, and those looked for and not found or not allowed.
- Tells a new file from an overwritten one by checking before the syscall runs, and reports a temp file renamed over a file as a write to that file.
- Hides reads of system and toolchain files, and failed lookups that were part of a search, unless `-a`.
- `--outside`, `-w`, `-m`, `--only`, `--hide`, `--show`, `--root`, `--json`, `-v`, `--wait`, `-o`, `--dump-events`.
- Passes the command's exit status through; 125 to 127 for filetap's own failures.
