//! Where a path lives, which decides whether reading it is worth showing, and
//! how it's displayed (`./`, `../`, `~/` or absolute).

use std::env;
use std::ffi::OsStr;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Zone {
    Virtual,
    ProjectDeps,
    Project,
    Toolchain,
    HomeCache,
    HomeConfig,
    Home,
    Temp,
    SystemConfig,
    System,
    SystemState,
    External,
}

impl Zone {
    pub fn name(self) -> &'static str {
        match self {
            Zone::Virtual => "virtual",
            Zone::ProjectDeps => "project-deps",
            Zone::Project => "project",
            Zone::Toolchain => "toolchain",
            Zone::HomeCache => "home-cache",
            Zone::HomeConfig => "home-config",
            Zone::Home => "home",
            Zone::Temp => "temp",
            Zone::SystemConfig => "system-config",
            Zone::System => "system",
            Zone::SystemState => "system-state",
            Zone::External => "external",
        }
    }

    /// Reads here are noise unless asked for.
    pub fn hides_reads(self) -> bool {
        matches!(self, Zone::Virtual | Zone::Toolchain | Zone::System)
    }
}

const DEPS_DIRS: &[&[u8]] = &[
    b"node_modules",
    b".venv",
    b"venv",
    b".tox",
    b"vendor",
    b"target",
    b"__pycache__",
    b".git",
    b".gradle",
];

const TOOLCHAIN_DIRS: &[&str] = &[
    ".nvm",
    ".rustup",
    ".pyenv",
    ".asdf",
    ".local/share/mise",
    ".volta",
    ".sdkman",
    ".bun",
];

const CACHE_DIRS: &[&str] = &[
    ".npm",
    ".yarn",
    ".pnpm-store",
    ".cargo/registry",
    ".cargo/git",
    ".m2",
    ".gradle/caches",
    "go/pkg/mod",
];

/// Read by nearly every program; showing them would say nothing.
const ETC_NOISE: &[&str] = &[
    "/etc/ld.so.cache",
    "/etc/ld.so.preload",
    "/etc/ld.so.conf",
    "/etc/ld.so.conf.d",
    "/etc/localtime",
    "/etc/nsswitch.conf",
    "/etc/host.conf",
    "/etc/gai.conf",
    "/etc/passwd",
    "/etc/group",
    "/etc/locale.alias",
    // c-ares looks for these on every lookup, AIX and Tru64 leftovers.
    "/etc/svc.conf",
    "/etc/netsvc.conf",
    // jemalloc's options.
    "/etc/malloc.conf",
    // libselinux, linked into coreutils on many distros.
    "/etc/selinux",
];

const SYSTEM_DIRS: &[&str] = &[
    "/usr",
    "/lib",
    "/lib32",
    "/lib64",
    "/libx32",
    "/bin",
    "/sbin",
    "/opt",
    "/nix/store",
    "/gnu/store",
    "/snap",
];

pub struct Context {
    pub cwd: Vec<u8>,
    pub root: Vec<u8>,
    pub home: Option<Vec<u8>>,
    run_user: Vec<u8>,
    temp: Vec<Vec<u8>>,
    config: Option<Vec<u8>>,
    caches: Vec<Vec<u8>>,
    toolchains: Vec<Vec<u8>>,
}

impl Context {
    pub fn from_env(root: Option<&Path>) -> Context {
        let cwd = env::current_dir()
            .map(|p| p.into_os_string().as_bytes().to_vec())
            .unwrap_or_else(|_| b"/".to_vec());
        let root = match root {
            Some(r) => crate::aggregate::normalize(r.as_os_str().as_bytes()),
            None => git_toplevel(&cwd).unwrap_or_else(|| cwd.clone()),
        };
        let var = |k: &str| {
            env::var_os(k)
                .map(|v| v.as_bytes().to_vec())
                .filter(|v| v.first() == Some(&b'/'))
        };
        // SAFETY: getuid can't fail.
        let uid = unsafe { libc::getuid() };
        Context::new(
            cwd,
            root,
            var("HOME").filter(|h| h != b"/"),
            uid,
            var("TMPDIR"),
            var("XDG_CACHE_HOME"),
            var("XDG_CONFIG_HOME"),
        )
    }

    pub fn new(
        cwd: Vec<u8>,
        root: Vec<u8>,
        home: Option<Vec<u8>>,
        uid: u32,
        tmpdir: Option<Vec<u8>>,
        cache_home: Option<Vec<u8>>,
        config_home: Option<Vec<u8>>,
    ) -> Context {
        let under_home = |rel: &str| {
            home.as_ref().map(|h| {
                let mut p = h.clone();
                p.push(b'/');
                p.extend_from_slice(rel.as_bytes());
                p
            })
        };
        let mut temp = vec![b"/tmp".to_vec(), b"/var/tmp".to_vec(), b"/dev/shm".to_vec()];
        temp.extend(tmpdir);
        let mut caches: Vec<Vec<u8>> = CACHE_DIRS.iter().filter_map(|d| under_home(d)).collect();
        caches.extend(cache_home.or_else(|| under_home(".cache")));
        Context {
            run_user: format!("/run/user/{uid}").into_bytes(),
            temp,
            config: config_home.or_else(|| under_home(".config")),
            caches,
            toolchains: TOOLCHAIN_DIRS
                .iter()
                .filter_map(|d| under_home(d))
                .collect(),
            cwd,
            root,
            home,
        }
    }

    /// Records where a runtime lives, going by where its binary was exec'd
    /// from: `~/.nvm/versions/node/v22/bin/node` makes everything under
    /// `~/.nvm/versions/node/v22` toolchain. Keeps the known-directory list
    /// from having to name every version manager.
    pub fn exec_seen(&mut self, path: &[u8]) {
        let Some(bin) = parent(path) else { return };
        if !bin.ends_with(b"/bin") {
            return;
        }
        let Some(prefix) = parent(bin) else { return };
        let home_local = self
            .home
            .as_ref()
            .map(|h| [h.as_slice(), b"/.local"].concat());
        let too_broad = prefix == b"/"
            || prefix == b"/usr"
            || prefix == b"/usr/local"
            || prefix == self.root.as_slice()
            || Some(prefix) == self.home.as_deref()
            || Some(prefix) == home_local.as_deref();
        if !too_broad && !self.toolchains.iter().any(|t| t == prefix) {
            self.toolchains.push(prefix.to_vec());
        }
    }

    pub fn zone(&self, path: &[u8]) -> Zone {
        // /selinux is where libselinux looks for an old-style selinuxfs.
        if under_any(path, &[b"/proc", b"/sys", b"/selinux"])
            || (under(path, b"/dev") && !under(path, b"/dev/shm"))
            || (under(path, b"/run") && !under(path, &self.run_user))
        {
            return Zone::Virtual;
        }
        if under(path, &self.root) {
            let rel = &path[self.root.len()..];
            if rel.split(|&b| b == b'/').any(|c| DEPS_DIRS.contains(&c)) {
                return Zone::ProjectDeps;
            }
            return Zone::Project;
        }
        if self.toolchains.iter().any(|t| under(path, t)) {
            return Zone::Toolchain;
        }
        if let Some(home) = &self.home
            && under(path, home)
        {
            if self.caches.iter().any(|c| under(path, c)) {
                return Zone::HomeCache;
            }
            if let Some(c) = &self.config
                && under(path, c)
            {
                return Zone::HomeConfig;
            }
            let rel = &path[home.len()..];
            if rel.starts_with(b"/.local/lib/python") {
                return Zone::Toolchain;
            }
            if rel.starts_with(b"/.") {
                return Zone::HomeConfig;
            }
            return Zone::Home;
        }
        if self.temp.iter().any(|t| under(path, t)) || under(path, &self.run_user) {
            return Zone::Temp;
        }
        if under(path, b"/etc") {
            if ETC_NOISE.iter().any(|n| under(path, n.as_bytes())) {
                return Zone::System;
            }
            return Zone::SystemConfig;
        }
        if SYSTEM_DIRS.iter().any(|d| under(path, d.as_bytes())) {
            return Zone::System;
        }
        if under(path, b"/var") {
            return Zone::SystemState;
        }
        Zone::External
    }

    /// Where folding stops: `./src/` can fold, `./` itself can't.
    pub fn fold_base(&self, path: &[u8]) -> Vec<u8> {
        if under(path, &self.cwd) {
            return self.cwd.clone();
        }
        if under(path, &self.root) {
            return self.root.clone();
        }
        if let Some(c) = &self.config
            && under(path, c)
        {
            return c.clone();
        }
        if let Some(h) = &self.home
            && under(path, h)
        {
            return h.clone();
        }
        for t in &self.temp {
            if under(path, t) {
                return t.clone();
            }
        }
        if under(path, b"/etc") {
            return b"/etc".to_vec();
        }
        b"/".to_vec()
    }

    /// Directories that fold as a whole whenever there's more than one entry
    /// under them: `./node_modules/`, `~/.cache/`.
    pub fn fold_point(&self, path: &[u8]) -> Option<Vec<u8>> {
        if under(path, &self.root) {
            let rel = &path[self.root.len()..];
            let mut end = self.root.len();
            for c in rel.split(|&b| b == b'/').skip(1) {
                end += 1 + c.len();
                if DEPS_DIRS.contains(&c) {
                    return Some(path[..end].to_vec());
                }
            }
            return None;
        }
        self.caches.iter().find(|c| under(path, c)).cloned()
    }

    /// Order of zones in the report: the project first, the system last.
    pub fn rank(&self, path: &[u8]) -> u8 {
        if under(path, &self.cwd) {
            return 0;
        }
        match self.zone(path) {
            Zone::Project | Zone::ProjectDeps => 1,
            Zone::HomeConfig | Zone::Home | Zone::HomeCache | Zone::Toolchain => 2,
            Zone::External => 3,
            Zone::Temp => 4,
            Zone::SystemConfig => 5,
            Zone::System => 6,
            Zone::SystemState => 7,
            Zone::Virtual => 8,
        }
    }

    pub fn display(&self, path: &[u8]) -> String {
        let shown: Vec<u8> = if under(path, &self.cwd) {
            [b"./", strip(path, &self.cwd)].concat()
        } else if under(path, &self.root) {
            relative(&self.cwd, path)
        } else if let Some(h) = self.home.as_ref().filter(|h| under(path, h)) {
            [b"~/", strip(path, h)].concat()
        } else {
            path.to_vec()
        };
        escape(&shown)
    }
}

pub fn under(path: &[u8], dir: &[u8]) -> bool {
    if dir == b"/" {
        return path.first() == Some(&b'/');
    }
    path.starts_with(dir) && (path.len() == dir.len() || path[dir.len()] == b'/')
}

fn under_any(path: &[u8], dirs: &[&[u8]]) -> bool {
    dirs.iter().any(|d| under(path, d))
}

fn strip<'a>(path: &'a [u8], dir: &[u8]) -> &'a [u8] {
    let rest = &path[dir.len()..];
    rest.strip_prefix(b"/").unwrap_or(rest)
}

pub fn parent(path: &[u8]) -> Option<&[u8]> {
    let i = path.iter().rposition(|&b| b == b'/')?;
    Some(if i == 0 { b"/" } else { &path[..i] })
}

/// `../shared/x` for a path under the project but outside the cwd.
fn relative(from: &[u8], to: &[u8]) -> Vec<u8> {
    let a: Vec<&[u8]> = from
        .split(|&b| b == b'/')
        .filter(|c| !c.is_empty())
        .collect();
    let b: Vec<&[u8]> = to.split(|&b| b == b'/').filter(|c| !c.is_empty()).collect();
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    let mut out = Vec::new();
    for _ in common..a.len() {
        out.extend_from_slice(b"../");
    }
    out.extend_from_slice(&b[common..].join(&b'/'));
    out
}

/// Non-UTF-8 bytes become `\xNN`.
pub fn escape(b: &[u8]) -> String {
    let mut s = String::with_capacity(b.len());
    for chunk in b.utf8_chunks() {
        s.push_str(chunk.valid());
        for byte in chunk.invalid() {
            s.push_str(&format!("\\x{byte:02x}"));
        }
    }
    s
}

fn git_toplevel(cwd: &[u8]) -> Option<Vec<u8>> {
    let mut dir = cwd;
    loop {
        let git = [dir, b"/.git"].concat();
        if Path::new(OsStr::from_bytes(&git)).exists() {
            return Some(dir.to_vec());
        }
        dir = parent(dir).filter(|p| *p != dir)?;
        if dir == b"/" {
            return None;
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> Context {
        Context::new(
            b"/home/u/proj/sub".to_vec(),
            b"/home/u/proj".to_vec(),
            Some(b"/home/u".to_vec()),
            1000,
            None,
            None,
            None,
        )
    }

    #[test]
    fn zones_and_display() {
        let c = ctx();
        let cases: &[(&str, Zone, &str)] = &[
            ("/home/u/proj/sub/a.ts", Zone::Project, "./a.ts"),
            (
                "/home/u/proj/shared/x.json",
                Zone::Project,
                "../shared/x.json",
            ),
            (
                "/home/u/proj/node_modules/a/i.js",
                Zone::ProjectDeps,
                "../node_modules/a/i.js",
            ),
            ("/home/u/.npmrc", Zone::HomeConfig, "~/.npmrc"),
            ("/home/u/.cache/x", Zone::HomeCache, "~/.cache/x"),
            (
                "/home/u/.nvm/versions/node/v22/lib/x.js",
                Zone::Toolchain,
                "~/.nvm/versions/node/v22/lib/x.js",
            ),
            ("/dev/shm/x", Zone::Temp, "/dev/shm/x"),
            ("/dev/null", Zone::Virtual, "/dev/null"),
            ("/run/user/1000/bus", Zone::Temp, "/run/user/1000/bus"),
            ("/etc/ld.so.cache", Zone::System, "/etc/ld.so.cache"),
            (
                "/etc/ssl/certs/ca.crt",
                Zone::SystemConfig,
                "/etc/ssl/certs/ca.crt",
            ),
            ("/mnt/data", Zone::External, "/mnt/data"),
        ];
        for (p, zone, shown) in cases {
            assert_eq!(c.zone(p.as_bytes()), *zone, "{p}");
            assert_eq!(c.display(p.as_bytes()), *shown, "{p}");
        }
    }

    #[test]
    fn runtime_prefix_is_inferred_from_exec() {
        let mut c = ctx();
        c.exec_seen(b"/srv/node/bin/node");
        c.exec_seen(b"/home/u/.local/bin/tool");
        c.exec_seen(b"/usr/bin/sh");
        assert_eq!(c.zone(b"/srv/node/lib/x.js"), Zone::Toolchain);
        assert_eq!(c.zone(b"/home/u/.local/share/tool/cfg"), Zone::HomeConfig);
    }
}
