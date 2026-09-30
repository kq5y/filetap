//! A seccomp filter that makes the kernel stop the tracee (SECCOMP_RET_TRACE)
//! on the syscalls we decode and lets everything else through untouched.

use std::io;

use super::decode::TRACED;

#[cfg(target_arch = "x86_64")]
const AUDIT_ARCH: u32 = 0xc000_003e; // AUDIT_ARCH_X86_64
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH: u32 = 0xc000_00b7; // AUDIT_ARCH_AARCH64

// x32 syscalls share AUDIT_ARCH_X86_64 and set this bit in the number.
#[cfg(target_arch = "x86_64")]
const X32_SYSCALL_BIT: u32 = 0x4000_0000;

const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JEQ_K: u16 = 0x15;
#[cfg(target_arch = "x86_64")]
const BPF_JGE_K: u16 = 0x35;
const BPF_JSET_K: u16 = 0x45;
const BPF_RET_K: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7fff_0000;
const SECCOMP_RET_TRACE: u32 = 0x7ff0_0000;

// offsetof(struct seccomp_data, ...)
const NR: u32 = 0;
const ARCH: u32 = 4;
/// The low half of args[i], on a little-endian machine.
const fn arg(i: u32) -> u32 {
    16 + 8 * i
}

/// fstat() is newfstatat(fd, "", AT_EMPTY_PATH) in newer glibc, and Rust's
/// File::metadata() is statx(fd, "", AT_EMPTY_PATH). Neither names a file,
/// and they come by the hundreds, so don't stop for them.
const EMPTY_PATH_FLAGS: &[(i64, u32)] =
    &[(libc::SYS_newfstatat, arg(3)), (libc::SYS_statx, arg(2))];

fn stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

fn program() -> Vec<libc::sock_filter> {
    let mut p = vec![
        stmt(BPF_LD_W_ABS, ARCH),
        jump(BPF_JEQ_K, AUDIT_ARCH, 1, 0),
        // TODO: 32-bit programs on x86_64 run untraced; at least warn.
        stmt(BPF_RET_K, SECCOMP_RET_ALLOW),
        stmt(BPF_LD_W_ABS, NR),
    ];
    #[cfg(target_arch = "x86_64")]
    {
        p.push(jump(BPF_JGE_K, X32_SYSCALL_BIT, 0, 1));
        p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    }
    for &nr in TRACED {
        if let Some(&(_, flags)) = EMPTY_PATH_FLAGS.iter().find(|(n, _)| *n == nr) {
            p.push(jump(BPF_JEQ_K, nr as u32, 0, 4));
            p.push(stmt(BPF_LD_W_ABS, flags));
            p.push(jump(BPF_JSET_K, libc::AT_EMPTY_PATH as u32, 0, 1));
            p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
            p.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
            continue;
        }
        p.push(jump(BPF_JEQ_K, nr as u32, 0, 1));
        p.push(stmt(BPF_RET_K, SECCOMP_RET_TRACE));
    }
    p.push(stmt(BPF_RET_K, SECCOMP_RET_ALLOW));
    p
}

/// Installs the filter on the calling process. Runs in the forked child,
/// right before it stops itself and waits to be seized.
pub fn install() -> io::Result<()> {
    let mut filter = program();
    let prog = libc::sock_fprog {
        len: filter.len() as u16,
        filter: filter.as_mut_ptr(),
    };
    let load = || {
        // SAFETY: prog points at a live, well-formed filter.
        let r = unsafe {
            libc::syscall(
                libc::SYS_seccomp,
                libc::SECCOMP_SET_MODE_FILTER,
                0,
                &prog as *const libc::sock_fprog,
            )
        };
        if r == 0 {
            Ok(())
        } else {
            Err(io::Error::last_os_error())
        }
    };
    // With CAP_SYS_ADMIN (sudo filetap ...) the filter loads without
    // no_new_privs, and setuid programs under it keep working. Everyone else
    // needs no_new_privs, which makes setuid a no-op.
    if load().is_ok() {
        return Ok(());
    }
    // SAFETY: plain prctl.
    if unsafe { libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) } != 0 {
        return Err(io::Error::last_os_error());
    }
    load()
}
