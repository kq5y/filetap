//! `.filetap.toml` in the project root: --hide and --show patterns for
//! every run in that project, on top of the ones given as flags.

use std::ffi::OsStr;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

use serde::Deserialize;

#[derive(Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default)]
    pub hide: Vec<String>,
    #[serde(default)]
    pub show: Vec<String>,
}

pub fn load(root: &[u8]) -> Result<Config, String> {
    let path = Path::new(OsStr::from_bytes(root)).join(".filetap.toml");
    let text = match fs::read_to_string(&path) {
        Ok(t) => t,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Config::default()),
        Err(e) => return Err(format!("{}: {e}", path.display())),
    };
    toml::from_str(&text).map_err(|e| {
        let line = e
            .span()
            .map_or(1, |s| text[..s.start].matches('\n').count() + 1);
        format!("{}:{line}: {}", path.display(), e.message())
    })
}
