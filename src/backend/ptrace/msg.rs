//! What the tracer process tells the front over the pipe.

use std::io::{self, Read};

use crate::backend::{Call, Exit, PathArg, SysEvent};

#[derive(Debug, PartialEq)]
pub enum Msg {
    Started {
        pid: i32,
    },
    /// The tracer couldn't start tracing (ptrace refused, etc.).
    Failed(String),
    /// execve of the command itself failed after the fork.
    ExecFailed {
        errno: i32,
    },
    RootExit {
        exit: Exit,
        procs: u32,
        running: Vec<(i32, String)>,
    },
    /// Every traced process is gone.
    Done {
        procs: u32,
    },
    Event(SysEvent),
    /// Something the report should mention, like a setuid program that
    /// couldn't get its privileges.
    Warning(String),
    /// A new process (not a thread), and which process started it.
    Spawn {
        parent: i32,
        child: i32,
    },
    /// A process (its last thread) is gone.
    ProcExit {
        pid: i32,
        exit: Exit,
    },
}

impl Msg {
    pub fn encode(&self) -> Vec<u8> {
        let mut b = Vec::new();
        match self {
            Msg::Started { pid } => {
                b.push(1);
                put_i32(&mut b, *pid);
            }
            Msg::Failed(s) => {
                b.push(2);
                put_str(&mut b, s);
            }
            Msg::ExecFailed { errno } => {
                b.push(3);
                put_i32(&mut b, *errno);
            }
            Msg::RootExit {
                exit,
                procs,
                running,
            } => {
                b.push(4);
                put_exit(&mut b, *exit);
                put_u32(&mut b, *procs);
                put_u32(&mut b, running.len() as u32);
                for (pid, comm) in running {
                    put_i32(&mut b, *pid);
                    put_str(&mut b, comm);
                }
            }
            Msg::Done { procs } => {
                b.push(5);
                put_u32(&mut b, *procs);
            }
            Msg::Event(ev) => {
                b.push(6);
                put_event(&mut b, ev);
            }
            Msg::Warning(s) => {
                b.push(7);
                put_str(&mut b, s);
            }
            Msg::Spawn { parent, child } => {
                b.push(8);
                put_i32(&mut b, *parent);
                put_i32(&mut b, *child);
            }
            Msg::ProcExit { pid, exit } => {
                b.push(9);
                put_i32(&mut b, *pid);
                put_exit(&mut b, *exit);
            }
        }
        b
    }

    /// Reads the next message. `Ok(None)` means the tracer closed the pipe.
    ///
    /// The first read is a plain `read` so that a signal arriving while we
    /// wait shows up as `ErrorKind::Interrupted` instead of being retried.
    pub fn read(r: &mut impl Read) -> io::Result<Option<Msg>> {
        let mut tag = [0u8; 1];
        if r.read(&mut tag)? == 0 {
            return Ok(None);
        }
        let msg = match tag[0] {
            1 => Msg::Started { pid: get_i32(r)? },
            2 => Msg::Failed(get_str(r)?),
            3 => Msg::ExecFailed { errno: get_i32(r)? },
            4 => {
                let exit = get_exit(r)?;
                let procs = get_u32(r)?;
                let n = get_u32(r)?;
                let mut running = Vec::with_capacity(n as usize);
                for _ in 0..n {
                    running.push((get_i32(r)?, get_str(r)?));
                }
                Msg::RootExit {
                    exit,
                    procs,
                    running,
                }
            }
            5 => Msg::Done { procs: get_u32(r)? },
            6 => Msg::Event(get_event(r)?),
            7 => Msg::Warning(get_str(r)?),
            8 => Msg::Spawn {
                parent: get_i32(r)?,
                child: get_i32(r)?,
            },
            9 => Msg::ProcExit {
                pid: get_i32(r)?,
                exit: get_exit(r)?,
            },
            t => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unknown message tag {t}"),
                ));
            }
        };
        Ok(Some(msg))
    }
}

fn put_exit(b: &mut Vec<u8>, exit: Exit) {
    match exit {
        Exit::Code(c) => {
            b.push(0);
            put_i32(b, c);
        }
        Exit::Signal(s) => {
            b.push(1);
            put_i32(b, s);
        }
    }
}

fn get_exit(r: &mut impl Read) -> io::Result<Exit> {
    Ok(match get_u8(r)? {
        0 => Exit::Code(get_i32(r)?),
        _ => Exit::Signal(get_i32(r)?),
    })
}

fn put_event(b: &mut Vec<u8>, ev: &SysEvent) {
    put_i32(b, ev.pid);
    match ev.result {
        Ok(v) => {
            b.push(0);
            b.extend_from_slice(&v.to_ne_bytes());
        }
        Err(e) => {
            b.push(1);
            put_i32(b, e);
        }
    }
    match &ev.call {
        Call::Open {
            path,
            flags,
            existed,
        } => {
            b.push(1);
            put_path(b, path);
            put_i32(b, *flags);
            put_tri(b, *existed);
        }
        Call::Stat { path } => {
            b.push(2);
            put_path(b, path);
        }
        Call::Exec { path, argv } => {
            b.push(3);
            put_path(b, path);
            put_u32(b, argv.len() as u32);
            for a in argv {
                put_bytes(b, a);
            }
        }
        Call::Rename {
            from,
            to,
            flags,
            to_existed,
        } => {
            b.push(4);
            put_path(b, from);
            put_path(b, to);
            put_u32(b, *flags);
            put_tri(b, *to_existed);
        }
        Call::Unlink { path, dir } => {
            b.push(5);
            put_path(b, path);
            b.push(*dir as u8);
        }
        Call::Mkdir { path } => {
            b.push(6);
            put_path(b, path);
        }
        Call::Link { from, to, symbolic } => {
            b.push(7);
            put_path(b, from);
            put_path(b, to);
            b.push(*symbolic as u8);
        }
        Call::Truncate { path } => {
            b.push(8);
            put_path(b, path);
        }
        Call::Attr { path } => {
            b.push(9);
            put_path(b, path);
        }
        Call::IoUringSetup => b.push(10),
    }
}

fn get_event(r: &mut impl Read) -> io::Result<SysEvent> {
    let pid = get_i32(r)?;
    let result = match get_u8(r)? {
        0 => {
            let mut v = [0u8; 8];
            r.read_exact(&mut v)?;
            Ok(i64::from_ne_bytes(v))
        }
        _ => Err(get_i32(r)?),
    };
    let call = match get_u8(r)? {
        1 => Call::Open {
            path: get_path(r)?,
            flags: get_i32(r)?,
            existed: get_tri(r)?,
        },
        2 => Call::Stat { path: get_path(r)? },
        3 => {
            let path = get_path(r)?;
            let n = get_u32(r)?;
            let mut argv = Vec::with_capacity(n as usize);
            for _ in 0..n {
                argv.push(get_bytes(r)?);
            }
            Call::Exec { path, argv }
        }
        4 => Call::Rename {
            from: get_path(r)?,
            to: get_path(r)?,
            flags: get_u32(r)?,
            to_existed: get_tri(r)?,
        },
        5 => Call::Unlink {
            path: get_path(r)?,
            dir: get_u8(r)? != 0,
        },
        6 => Call::Mkdir { path: get_path(r)? },
        7 => Call::Link {
            from: get_path(r)?,
            to: get_path(r)?,
            symbolic: get_u8(r)? != 0,
        },
        8 => Call::Truncate { path: get_path(r)? },
        9 => Call::Attr { path: get_path(r)? },
        10 => Call::IoUringSetup,
        t => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unknown call tag {t}"),
            ));
        }
    };
    Ok(SysEvent { pid, call, result })
}

fn put_path(b: &mut Vec<u8>, p: &PathArg) {
    match &p.dir {
        Some(d) => {
            b.push(1);
            put_bytes(b, d);
        }
        None => b.push(0),
    }
    put_bytes(b, &p.raw);
}

fn get_path(r: &mut impl Read) -> io::Result<PathArg> {
    let dir = match get_u8(r)? {
        0 => None,
        _ => Some(get_bytes(r)?),
    };
    Ok(PathArg {
        dir,
        raw: get_bytes(r)?,
    })
}

fn put_tri(b: &mut Vec<u8>, v: Option<bool>) {
    b.push(match v {
        None => 0,
        Some(false) => 1,
        Some(true) => 2,
    });
}

fn get_tri(r: &mut impl Read) -> io::Result<Option<bool>> {
    Ok(match get_u8(r)? {
        0 => None,
        1 => Some(false),
        _ => Some(true),
    })
}

fn put_bytes(b: &mut Vec<u8>, v: &[u8]) {
    put_u32(b, v.len() as u32);
    b.extend_from_slice(v);
}

fn get_bytes(r: &mut impl Read) -> io::Result<Vec<u8>> {
    let mut v = vec![0u8; get_u32(r)? as usize];
    r.read_exact(&mut v)?;
    Ok(v)
}

fn put_i32(b: &mut Vec<u8>, v: i32) {
    b.extend_from_slice(&v.to_ne_bytes());
}

fn put_u32(b: &mut Vec<u8>, v: u32) {
    b.extend_from_slice(&v.to_ne_bytes());
}

fn put_str(b: &mut Vec<u8>, s: &str) {
    put_u32(b, s.len() as u32);
    b.extend_from_slice(s.as_bytes());
}

fn get_u8(r: &mut impl Read) -> io::Result<u8> {
    let mut v = [0u8; 1];
    r.read_exact(&mut v)?;
    Ok(v[0])
}

fn get_i32(r: &mut impl Read) -> io::Result<i32> {
    let mut v = [0u8; 4];
    r.read_exact(&mut v)?;
    Ok(i32::from_ne_bytes(v))
}

fn get_u32(r: &mut impl Read) -> io::Result<u32> {
    let mut v = [0u8; 4];
    r.read_exact(&mut v)?;
    Ok(u32::from_ne_bytes(v))
}

fn get_str(r: &mut impl Read) -> io::Result<String> {
    let mut v = vec![0u8; get_u32(r)? as usize];
    r.read_exact(&mut v)?;
    String::from_utf8(v).map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn messages_survive_a_round_trip() {
        let msgs = [
            Msg::Started { pid: 42 },
            Msg::Failed("ptrace not permitted".into()),
            Msg::ExecFailed { errno: 2 },
            Msg::RootExit {
                exit: Exit::Signal(15),
                procs: 7,
                running: vec![(1234, "esbuild".into()), (1301, "node".into())],
            },
            Msg::Done { procs: 9 },
            Msg::Spawn {
                parent: 1,
                child: 2,
            },
            Msg::ProcExit {
                pid: 2,
                exit: Exit::Code(3),
            },
            Msg::Event(SysEvent {
                pid: 7,
                call: Call::Rename {
                    from: PathArg {
                        dir: Some(b"/tmp".to_vec()),
                        raw: b"a\xff".to_vec(),
                    },
                    to: PathArg {
                        dir: None,
                        raw: b"/tmp/b".to_vec(),
                    },
                    flags: 0,
                    to_existed: Some(true),
                },
                result: Err(2),
            }),
            Msg::Event(SysEvent {
                pid: 8,
                call: Call::Exec {
                    path: PathArg {
                        dir: None,
                        raw: b"/bin/sh".to_vec(),
                    },
                    argv: vec![b"sh".to_vec(), b"-c".to_vec()],
                },
                result: Ok(0),
            }),
        ];
        let buf: Vec<u8> = msgs.iter().flat_map(|m| m.encode()).collect();
        let mut r = &buf[..];
        for m in &msgs {
            assert_eq!(Msg::read(&mut r).unwrap().as_ref(), Some(m));
        }
        assert_eq!(Msg::read(&mut r).unwrap(), None);
    }
}
