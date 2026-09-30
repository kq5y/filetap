//! What the tracer process tells the front over the pipe.

use std::io::{self, Read};

use crate::backend::Exit;

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
                match exit {
                    Exit::Code(c) => {
                        b.push(0);
                        put_i32(&mut b, *c);
                    }
                    Exit::Signal(s) => {
                        b.push(1);
                        put_i32(&mut b, *s);
                    }
                }
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
                let exit = match get_u8(r)? {
                    0 => Exit::Code(get_i32(r)?),
                    _ => Exit::Signal(get_i32(r)?),
                };
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
        ];
        let buf: Vec<u8> = msgs.iter().flat_map(|m| m.encode()).collect();
        let mut r = &buf[..];
        for m in &msgs {
            assert_eq!(Msg::read(&mut r).unwrap().as_ref(), Some(m));
        }
        assert_eq!(Msg::read(&mut r).unwrap(), None);
    }
}
