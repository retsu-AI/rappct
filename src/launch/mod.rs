//! Process launch in AppContainer / LPAC with STARTUPINFOEX and security capabilities.

// legacy launch::attr module no longer used; relying on ffi::attr_list wrappers

#[cfg(windows)]
mod attributes;
#[cfg(windows)]
mod capture;
#[cfg(windows)]
mod env;
#[cfg(windows)]
mod job;
#[cfg(windows)]
mod spawn;
#[cfg(windows)]
mod startup;
#[cfg(windows)]
mod stdio;
#[cfg(all(test, windows))]
mod tests;

use crate::capability::SecurityCapabilities;
use crate::{AcError, Result};

#[cfg(windows)]
use crate::ffi::handles::{self, Handle as FHandle};
use std::ffi::OsString;
#[cfg(windows)]
use std::os::windows::io::BorrowedHandle;
#[cfg(windows)]
use std::sync::Arc;

#[cfg(windows)]
pub use capture::{CapturedOutput, OutputCapture};
#[cfg(windows)]
pub use job::{JobGuard, JobObjectDropGuard};
#[cfg(windows)]
use spawn::launch_impl;
#[cfg(all(test, windows))]
use spawn::make_cmd_args;

#[derive(Clone, Copy, Debug)]
pub enum StdioConfig {
    Inherit,
    Null,
    Pipe,
}

#[derive(Clone, Debug, Default)]
pub struct JobLimits {
    pub memory_bytes: Option<usize>,
    pub cpu_rate_percent: Option<u32>,
    pub kill_on_job_close: bool,
}

#[derive(Clone, Debug)]
pub struct LaunchOptions {
    pub exe: std::path::PathBuf,
    pub cmdline: Option<String>,
    pub cwd: Option<std::path::PathBuf>,
    /// Explicit desktop or window-station\\desktop name for the child.
    pub desktop: Option<std::ffi::OsString>,
    pub env: Option<Vec<(std::ffi::OsString, std::ffi::OsString)>>,
    pub stdio: StdioConfig,
    pub suspended: bool,
    pub join_job: Option<JobLimits>,
    /// Maximum wait for child startup to reach input-idle.
    /// Ignored when `suspended` is `true`, because the child thread is not running yet.
    pub startup_timeout: Option<std::time::Duration>,
    /// Reserved for internal use; use `..Default::default()` when constructing.
    #[cfg(windows)]
    #[doc(hidden)]
    pub extra: LaunchExtra,
}

#[cfg(windows)]
#[derive(Clone, Debug, Default)]
#[doc(hidden)]
pub struct LaunchExtra {
    handle_list: Vec<Arc<FHandle>>,
    primary_token: Option<Arc<FHandle>>,
    stdio: StdioOverrides,
}

#[cfg(windows)]
#[derive(Clone, Debug, Default)]
struct StdioOverrides {
    stdin: Option<Arc<FHandle>>,
    stdout: Option<Arc<FHandle>>,
    stderr: Option<Arc<FHandle>>,
}

impl Default for LaunchOptions {
    fn default() -> Self {
        #[cfg(target_os = "windows")]
        let cwd = Some(std::path::PathBuf::from("C:\\Windows\\System32"));
        #[cfg(not(target_os = "windows"))]
        let cwd = None;
        #[cfg(target_os = "windows")]
        let exe = std::path::PathBuf::from("C:\\Windows\\System32\\notepad.exe");
        #[cfg(not(target_os = "windows"))]
        let exe = std::path::PathBuf::new();
        Self {
            exe,
            cmdline: None,
            desktop: None,
            cwd,
            env: None,
            stdio: StdioConfig::Inherit,
            suspended: false,
            join_job: None,
            startup_timeout: None,
            #[cfg(windows)]
            extra: LaunchExtra::default(),
        }
    }
}

impl LaunchOptions {
    /// Launch as this primary token, cloned with minimal rights and never inherited.
    /// Requires a kill-on-close job, no startup timeout, and explicit child resume.
    #[cfg(windows)]
    pub fn try_with_primary_token(mut self, token: BorrowedHandle<'_>) -> Result<Self> {
        if !self
            .join_job
            .as_ref()
            .is_some_and(|job| job.kill_on_job_close)
        {
            return Err(crate::AcError::Win32(
                "explicit token requires kill-on-close job".into(),
            ));
        }
        if self.startup_timeout.is_some() {
            return Err(crate::AcError::Win32(
                "explicit token requires no startup timeout".into(),
            ));
        }
        self.extra.primary_token = Some(Arc::new(handles::duplicate_primary_token(token)?));
        self.suspended = true;
        Ok(self)
    }

    /// Duplicate additional inheritable handles for the child.
    ///
    /// # Panics
    ///
    /// Panics if Windows cannot duplicate a handle. Use
    /// [`Self::try_with_handle_list`] when duplication failure must be handled.
    #[cfg(windows)]
    pub fn with_handle_list(self, inheritable: &[BorrowedHandle<'_>]) -> Self {
        self.try_with_handle_list(inheritable)
            .expect("failed to duplicate inheritable handle list")
    }

    #[cfg(windows)]
    pub fn try_with_handle_list(mut self, inheritable: &[BorrowedHandle<'_>]) -> Result<Self> {
        for h in inheritable {
            let duplicated = handles::duplicate_handle(*h, true)?;
            self.extra.handle_list.push(Arc::new(duplicated));
        }
        Ok(self)
    }

    /// Duplicate explicit child standard-I/O handles.
    ///
    /// # Panics
    ///
    /// Panics if Windows cannot duplicate a handle. Use
    /// [`Self::try_with_stdio_inherit`] when duplication failure must be handled.
    #[cfg(windows)]
    pub fn with_stdio_inherit(
        self,
        stdin: Option<BorrowedHandle<'_>>,
        stdout: Option<BorrowedHandle<'_>>,
        stderr: Option<BorrowedHandle<'_>>,
    ) -> Self {
        self.try_with_stdio_inherit(stdin, stdout, stderr)
            .expect("failed to duplicate inherited stdio handle")
    }

    #[cfg(windows)]
    pub fn try_with_stdio_inherit(
        mut self,
        stdin: Option<BorrowedHandle<'_>>,
        stdout: Option<BorrowedHandle<'_>>,
        stderr: Option<BorrowedHandle<'_>>,
    ) -> Result<Self> {
        self.extra.stdio.stdin = Self::duplicate_stdio_handle(stdin)?;
        self.extra.stdio.stdout = Self::duplicate_stdio_handle(stdout)?;
        self.extra.stdio.stderr = Self::duplicate_stdio_handle(stderr)?;
        Ok(self)
    }

    #[cfg(windows)]
    fn duplicate_stdio_handle(handle: Option<BorrowedHandle<'_>>) -> Result<Option<Arc<FHandle>>> {
        let Some(handle) = handle else {
            return Ok(None);
        };
        let duplicated = handles::duplicate_handle(handle, true)?;
        Ok(Some(Arc::new(duplicated)))
    }

    pub fn with_env_merge(mut self, add: &[(OsString, OsString)]) -> Self {
        let mut env = self.env.take().unwrap_or_default();
        env.extend(add.iter().cloned());
        self.env = Some(merge_parent_env(env));
        self
    }
}

#[derive(Debug)]
pub struct Launched {
    pub pid: u32,
    #[cfg(windows)]
    control: ProcessControl,
    #[cfg(windows)]
    _job_guard: Option<JobGuard>,
}

#[cfg(windows)]
#[derive(Debug)]
pub struct LaunchedIo {
    pub pid: u32,
    pub stdin: Option<std::fs::File>,
    pub stdout: Option<std::fs::File>,
    pub stderr: Option<std::fs::File>,
    pub job_guard: Option<JobGuard>,
    control: ProcessControl,
}

#[cfg(not(windows))]
pub struct LaunchedIo;

#[cfg(windows)]
#[derive(Debug)]
struct ProcessControl {
    process: FHandle,
    suspended_thread: Option<FHandle>,
}

pub fn launch_in_container(_sec: &SecurityCapabilities, _opts: &LaunchOptions) -> Result<Launched> {
    #[cfg(windows)]
    {
        if matches!(_opts.stdio, StdioConfig::Pipe) {
            return Err(AcError::LaunchFailed {
                stage: "launch_options",
                hint: "use launch_in_container_with_io when stdio is Pipe",
                source: Box::new(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "pipe handles require the I/O launch API",
                )),
            });
        }
        launch_impl(_sec, _opts).map(LaunchedIo::without_io)
    }
    #[cfg(not(windows))]
    {
        Err(AcError::UnsupportedPlatform)
    }
}

/// Merge caller-supplied env vars with essential Windows variables.
/// When passing a custom environment to `CreateProcessW`, the parent env is
/// fully replaced. Including these keys avoids common failures (e.g., error 203).
pub fn merge_parent_env(mut custom: Vec<(OsString, OsString)>) -> Vec<(OsString, OsString)> {
    const KEYS: &[&str] = &[
        "SystemRoot",
        "windir",
        "ComSpec",
        "PATHEXT",
        "TEMP",
        "TMP",
        "PATH",
    ];

    fn key_matches(lhs: &OsString, rhs: &str) -> bool {
        lhs.to_string_lossy().eq_ignore_ascii_case(rhs)
    }

    fn merge_env_entry(
        merged: &mut Vec<(OsString, OsString)>,
        key: OsString,
        value: OsString,
        overwrite: bool,
    ) {
        if let Some((existing_key, existing_value)) = merged
            .iter_mut()
            .find(|(k, _)| key_matches(k, key.to_string_lossy().as_ref()))
        {
            if overwrite {
                *existing_key = key;
                *existing_value = value;
            }
            return;
        }
        merged.push((key, value));
    }

    let mut merged = Vec::with_capacity(custom.len() + KEYS.len());
    for (key, value) in custom.drain(..) {
        merge_env_entry(&mut merged, key, value, true);
    }
    for key in KEYS {
        if let Some(val) = std::env::var_os(key) {
            merge_env_entry(&mut merged, OsString::from(key), val, false);
        }
    }
    merged
}

#[cfg(windows)]
pub fn launch_in_container_with_io(
    sec: &SecurityCapabilities,
    opts: &LaunchOptions,
) -> Result<LaunchedIo> {
    launch_impl(sec, opts)
}

#[cfg(windows)]
impl LaunchedIo {
    fn without_io(self) -> Launched {
        let LaunchedIo {
            pid,
            job_guard,
            control,
            ..
        } = self;
        Launched {
            pid,
            control,
            _job_guard: job_guard,
        }
    }

    pub fn wait(&self, timeout: Option<std::time::Duration>) -> Result<u32> {
        self.control.wait(timeout)
    }

    /// Resume a child created with [`LaunchOptions::suspended`].
    pub fn resume(&mut self) -> Result<()> {
        self.control.resume()
    }

    /// Terminate the child and wait for it to exit.
    pub fn terminate(&mut self, exit_code: u32) -> Result<u32> {
        self.control.terminate(exit_code)
    }

    /// Start draining stdout and stderr concurrently.
    pub fn capture_output(&mut self) -> OutputCapture {
        OutputCapture::start(self.stdout.take(), self.stderr.take())
    }
}

#[cfg(windows)]
impl Launched {
    pub fn wait(&self, timeout: Option<std::time::Duration>) -> Result<u32> {
        self.control.wait(timeout)
    }

    /// Resume a child created with [`LaunchOptions::suspended`].
    pub fn resume(&mut self) -> Result<()> {
        self.control.resume()
    }

    /// Terminate the child and wait for it to exit.
    pub fn terminate(&mut self, exit_code: u32) -> Result<u32> {
        self.control.terminate(exit_code)
    }
}

#[cfg(windows)]
impl ProcessControl {
    fn wait(&self, timeout: Option<std::time::Duration>) -> Result<u32> {
        use windows::Win32::Foundation::{STILL_ACTIVE, WAIT_FAILED, WAIT_TIMEOUT};
        use windows::Win32::System::Threading::{
            GetExitCodeProcess, INFINITE, WaitForSingleObject,
        };
        // SAFETY: Wait and query exit code for a live process handle; convert duration to ms.
        unsafe {
            let ms = timeout
                .map(|d| d.as_millis().min(u128::from(u32::MAX)) as u32)
                .unwrap_or(INFINITE);
            let r = WaitForSingleObject(self.process.as_win32(), ms);
            if r == WAIT_FAILED {
                return Err(AcError::Win32("WaitForSingleObject failed".into()));
            }
            if r == WAIT_TIMEOUT {
                return Err(AcError::LaunchFailed {
                    stage: "wait",
                    hint: "timeout",
                    source: Box::new(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "wait timeout",
                    )),
                });
            }
            let mut code: u32 = STILL_ACTIVE.0 as u32;
            GetExitCodeProcess(self.process.as_win32(), &mut code)
                .map_err(|_| AcError::Win32("GetExitCodeProcess failed".into()))?;
            Ok(code)
        }
    }

    fn resume(&mut self) -> Result<()> {
        use windows::Win32::System::Threading::ResumeThread;
        let thread = self.suspended_thread.take().ok_or_else(|| {
            AcError::Win32("process is not suspended or was already resumed".into())
        })?;
        // SAFETY: The retained handle is the primary thread created suspended by CreateProcessW.
        let previous = unsafe { ResumeThread(thread.as_win32()) };
        if previous == u32::MAX {
            self.suspended_thread = Some(thread);
            return Err(AcError::Win32("ResumeThread failed".into()));
        }
        Ok(())
    }

    fn terminate(&mut self, exit_code: u32) -> Result<u32> {
        use windows::Win32::System::Threading::TerminateProcess;
        // SAFETY: The process handle is owned and remains live for this call.
        unsafe { TerminateProcess(self.process.as_win32(), exit_code) }
            .map_err(|_| AcError::Win32("TerminateProcess failed".into()))?;
        self.wait(None)
    }
}

#[cfg(not(windows))]
pub fn launch_in_container_with_io(
    _sec: &SecurityCapabilities,
    _opts: &LaunchOptions,
) -> Result<LaunchedIo> {
    Err(AcError::UnsupportedPlatform)
}
