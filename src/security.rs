//! System-level process and memory security hardening.

#![allow(unsafe_code)]

use tracing::{debug, info, warn};

/// Hardens process memory against involuntary core dumps containing sensitive cryptographic keys.
///
/// Implements:
/// 1. POSIX `setrlimit(RLIMIT_CORE, {0, 0})` on all Unix platforms to set core dump limit to 0.
/// 2. Linux `prctl(PR_SET_DUMPABLE, 0)` to disable ptrace attachment and dump generation.
/// 3. Linux `/proc/self/coredump_filter = 0` as defense-in-depth safe file I/O.
pub fn harden_process_memory() {
    #[cfg(unix)]
    {
        // 1. POSIX RLIMIT_CORE = 0: Disables core dump file creation on Unix kernels
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit is invoked with a valid pointer to stack-allocated rlimit struct.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret != 0 {
            warn!("unable to set RLIMIT_CORE to 0 via setrlimit");
        } else {
            info!("process RLIMIT_CORE set to 0 (core dumps disabled)");
        }

        // 2. Linux-specific PR_SET_DUMPABLE = 0
        #[cfg(target_os = "linux")]
        {
            // SAFETY: prctl with PR_SET_DUMPABLE and arg 0 is a standard Linux syscall.
            let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) };
            if ret != 0 {
                warn!("unable to set PR_SET_DUMPABLE to 0 via prctl");
            } else {
                info!("process PR_SET_DUMPABLE set to 0");
            }

            // 3. Defense-in-depth: /proc/self/coredump_filter = 0
            match std::fs::write("/proc/self/coredump_filter", "0\n") {
                Ok(()) => {
                    debug!("process core dump filter set to 0");
                }
                Err(e) => {
                    debug!(error = %e, "unable to write to /proc/self/coredump_filter (possibly read-only)");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        debug!("core dump protection is only available on Unix targets");
    }
}
