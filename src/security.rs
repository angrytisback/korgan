//! System-level process and memory security hardening.

#![allow(unsafe_code)]

use tracing::{debug, info, warn};

/// Sets the process `RLIMIT_CORE` resource limit to 0, preventing core dump generation.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the `setrlimit` system call fails.
pub fn disable_core_dumps() -> Result<(), std::io::Error> {
    #[cfg(unix)]
    {
        let rlim = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: setrlimit is invoked with a valid pointer to a stack-allocated rlimit struct.
        let ret = unsafe { libc::setrlimit(libc::RLIMIT_CORE, &rlim) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Ok(())
    }
}

/// Sets the Linux `PR_SET_DUMPABLE` flag for the current process.
///
/// Setting `dumpable` to `false` disables ptrace attachment and core dump creation.
///
/// # Errors
///
/// Returns an [`std::io::Error`] if the `prctl` system call fails.
pub fn set_dumpable(dumpable: bool) -> Result<(), std::io::Error> {
    #[cfg(target_os = "linux")]
    {
        let arg = if dumpable { 1 } else { 0 };
        // SAFETY: prctl with PR_SET_DUMPABLE and valid integer flag is a standard Linux syscall.
        let ret = unsafe { libc::prctl(libc::PR_SET_DUMPABLE, arg, 0, 0, 0) };
        if ret != 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = dumpable;
        Ok(())
    }
}

/// Hardens process memory against involuntary core dumps containing sensitive cryptographic keys.
///
/// Implements:
/// 1. POSIX `setrlimit(RLIMIT_CORE, {0, 0})` on all Unix platforms to set core dump limit to 0.
/// 2. Linux `prctl(PR_SET_DUMPABLE, 0)` to disable ptrace attachment and dump generation.
/// 3. Linux `/proc/self/coredump_filter = 0` as defense-in-depth safe file I/O.
pub fn harden_process_memory() {
    #[cfg(unix)]
    {
        match disable_core_dumps() {
            Ok(()) => info!("process RLIMIT_CORE set to 0 (core dumps disabled)"),
            Err(e) => warn!(error = %e, "unable to set RLIMIT_CORE to 0 via setrlimit"),
        }

        #[cfg(target_os = "linux")]
        {
            match set_dumpable(false) {
                Ok(()) => info!("process PR_SET_DUMPABLE set to 0"),
                Err(e) => warn!(error = %e, "unable to set PR_SET_DUMPABLE to 0 via prctl"),
            }

            // Defense-in-depth: /proc/self/coredump_filter = 0
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
