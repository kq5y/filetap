use std::ffi::{OsStr, OsString};
use std::fmt;
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

// Same default as glibc's execvp(3) when PATH is unset.
const DEFAULT_PATH: &str = "/bin:/usr/bin";

#[derive(Debug, PartialEq)]
pub enum LaunchError {
    NotFound(OsString),
    NotExecutable(PathBuf),
}

impl LaunchError {
    pub fn exit_code(&self) -> i32 {
        match self {
            LaunchError::NotFound(_) => 127,
            LaunchError::NotExecutable(_) => 126,
        }
    }
}

impl fmt::Display for LaunchError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            LaunchError::NotFound(name) if name.as_bytes().contains(&b'/') => {
                write!(f, "{}: no such file or directory", name.display())
            }
            LaunchError::NotFound(name) => write!(f, "{}: command not found", name.display()),
            LaunchError::NotExecutable(path) => write!(f, "{}: permission denied", path.display()),
        }
    }
}

/// Finds the program the way execvp(3) would, so that a missing or
/// non-executable command is reported before anything is traced. Resolving
/// here also keeps the PATH lookups out of the trace.
pub fn resolve(name: &OsStr, path_var: Option<&OsStr>) -> Result<PathBuf, LaunchError> {
    if name.as_bytes().contains(&b'/') {
        let p = Path::new(name);
        return match executable(p) {
            Some(true) => Ok(p.to_path_buf()),
            Some(false) => Err(LaunchError::NotExecutable(p.to_path_buf())),
            None => Err(LaunchError::NotFound(name.to_owned())),
        };
    }
    if name.is_empty() {
        return Err(LaunchError::NotFound(name.to_owned()));
    }

    let path_var = path_var.unwrap_or(OsStr::new(DEFAULT_PATH));
    let mut denied = None;
    for dir in path_var.as_bytes().split(|&b| b == b':') {
        // An empty entry means the current directory.
        let dir = if dir.is_empty() {
            Path::new(".")
        } else {
            Path::new(OsStr::from_bytes(dir))
        };
        let candidate = dir.join(name);
        match executable(&candidate) {
            Some(true) => return Ok(candidate),
            Some(false) if denied.is_none() => denied = Some(candidate),
            _ => {}
        }
    }
    // execvp(3) also reports EACCES only when nothing executable was found.
    match denied {
        Some(p) => Err(LaunchError::NotExecutable(p)),
        None => Err(LaunchError::NotFound(name.to_owned())),
    }
}

fn executable(p: &Path) -> Option<bool> {
    let meta = fs::metadata(p).ok()?;
    if meta.is_dir() {
        return Some(false);
    }
    // Checking mode bits instead of access(2) is close enough here; the
    // exec itself still reports EACCES if we got it wrong.
    Some(meta.permissions().mode() & 0o111 != 0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;

    fn tempdir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("filetap-launch-{}-{}", std::process::id(), name));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn touch(p: &Path, mode: u32) {
        File::create(p).unwrap();
        fs::set_permissions(p, fs::Permissions::from_mode(mode)).unwrap();
    }

    #[test]
    fn skips_non_executable_matches_in_path() {
        let d = tempdir("path");
        fs::create_dir_all(d.join("a")).unwrap();
        fs::create_dir_all(d.join("b")).unwrap();
        touch(&d.join("a/tool"), 0o644);
        touch(&d.join("b/tool"), 0o755);
        let path = format!("{}:{}", d.join("a").display(), d.join("b").display());
        assert_eq!(
            resolve(OsStr::new("tool"), Some(OsStr::new(&path))),
            Ok(d.join("b/tool"))
        );
        // Only a non-executable match: 126, like execvp's EACCES.
        let only_a = d.join("a");
        let err = resolve(OsStr::new("tool"), Some(only_a.as_os_str())).unwrap_err();
        assert_eq!(err.exit_code(), 126);
        let err = resolve(OsStr::new("no-such-tool"), Some(OsStr::new(&path))).unwrap_err();
        assert_eq!(err.exit_code(), 127);
    }
}
