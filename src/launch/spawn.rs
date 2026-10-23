use super::attributes::{
    InheritList, LaunchAttributes, StartUpInfoExGuard, duplicate_additional_handles,
    inflate_security_caps,
};
use super::env::{WideBlock, make_wide_block};
use super::job;
use super::startup;
use super::stdio::{StdioSetupResult, setup_stdio};
use super::{LaunchOptions, LaunchedIo};
use crate::capability::SecurityCapabilities;
use crate::ffi::handles::{self, Handle as FHandle};
use crate::ffi::wstr::WideString;
use crate::{AcError, Result};
use core::ffi::c_void;
#[cfg(test)]
use std::cell::{Cell, RefCell};
use windows::Win32::Foundation::{CloseHandle, WAIT_OBJECT_0};
use windows::Win32::System::Threading::{
    CREATE_SUSPENDED, CREATE_UNICODE_ENVIRONMENT, CreateProcessAsUserW, CreateProcessW,
    EXTENDED_STARTUPINFO_PRESENT, INFINITE, PROCESS_CREATION_FLAGS, PROCESS_INFORMATION,
    STARTUPINFOEXW, TerminateProcess, WaitForSingleObject,
};
use windows::core::{PCWSTR, PWSTR};

struct ProcessInputs {
    env_block: Option<WideBlock>,
    exe_w: WideString,
    args_w: Option<Vec<u16>>,
    cwd_w: Option<WideString>,
    desktop_w: Option<Vec<u16>>,
}

struct ChildHandles {
    thread: Option<FHandle>,
    process: FHandle,
}

#[cfg(test)]
std::thread_local! {
    static FAIL_NEXT_POST_SPAWN_SETUP: Cell<bool> = const { Cell::new(false) };
    static POST_SPAWN_REAP_WITNESS: RefCell<Option<FHandle>> = const { RefCell::new(None) };
}

pub(super) fn launch_impl(sec: &SecurityCapabilities, opts: &LaunchOptions) -> Result<LaunchedIo> {
    ensure_lpac_supported(sec)?;
    let explicit_token = opts.extra.primary_token.as_deref();
    let birth_job = prepare_birth_job(opts)?;
    let mut inputs = ProcessInputs::from_options(opts)?;
    let mut inherit_list = InheritList::default();
    let mut startup_info = base_startup_info();
    // ProcessInputs owns this buffer through CreateProcessW.
    startup_info.StartupInfo.lpDesktop = inputs
        .desktop_w
        .as_mut()
        .map_or(PWSTR::null(), |buffer| PWSTR(buffer.as_mut_ptr()));

    let stdio = setup_stdio(opts, &mut startup_info, &mut inherit_list)?;
    duplicate_additional_handles(&opts.extra.handle_list, &mut inherit_list)?;

    let security_caps = inflate_security_caps(sec)?;
    let attributes = if let Some(job) = &birth_job {
        LaunchAttributes::new_with_job(
            security_caps,
            sec.lpac,
            inherit_list.slice(),
            Some(job.as_handle()),
        )?
    } else {
        LaunchAttributes::new(security_caps, sec.lpac, inherit_list.slice())?
    };
    let mut startup_guard = StartUpInfoExGuard::new(startup_info, attributes);
    let mut pi = PROCESS_INFORMATION::default();
    let flags = creation_flags(opts, inputs.env_block.is_some());
    let inherit_handles = !inherit_list.is_empty();

    create_child_process(
        &mut inputs,
        startup_guard.info_mut(),
        inherit_handles,
        flags,
        &mut pi,
        explicit_token,
    )?;
    drop(inherit_list);

    let mut child = process_handles(pi)?;
    let job_guard = match prepare_child(opts, &child, birth_job) {
        Ok(guard) => guard,
        Err(error) => {
            return match terminate_and_reap(&child.process) {
                Ok(()) => Err(error),
                Err(cleanup) => Err(post_spawn_cleanup_error(error, cleanup)),
            };
        }
    };
    let suspended_thread = if opts.suspended {
        child.thread.take()
    } else {
        None
    };
    Ok(launched_io(
        pi.dwProcessId,
        stdio,
        child.process,
        suspended_thread,
        job_guard,
    ))
}

pub(super) fn make_cmd_args(cmdline: &Option<String>) -> Option<Vec<u16>> {
    cmdline.as_ref().map(|cl| {
        let mut w: Vec<u16> = cl.encode_utf16().collect();
        w.push(0);
        w
    })
}

fn prepare_birth_job(opts: &LaunchOptions) -> Result<Option<job::JobGuard>> {
    Ok(if opts.extra.primary_token.is_some() {
        if opts.startup_timeout.is_some() {
            return Err(AcError::Win32(
                "explicit token requires no startup timeout".into(),
            ));
        }
        if !opts.suspended
            || !opts
                .join_job
                .as_ref()
                .is_some_and(|job| job.kill_on_job_close)
        {
            return Err(AcError::Win32(
                "explicit token requires suspended kill-on-close job".into(),
            ));
        }
        Some(job::create_birth_job_guard(
            opts.join_job.as_ref().expect("validated job"),
        )?)
    } else {
        None
    })
}

impl ProcessInputs {
    fn from_options(opts: &LaunchOptions) -> Result<Self> {
        Ok(Self {
            env_block: build_env_block(opts)?,
            exe_w: WideString::from_os_str(opts.exe.as_os_str()),
            args_w: make_cmd_args(&opts.cmdline),
            cwd_w: build_cwd(opts),
            desktop_w: desktop_buffer(opts)?,
        })
    }

    fn env_ptr(&self) -> Option<*const c_void> {
        self.env_block
            .as_ref()
            .map(|block| block.as_ptr() as *const c_void)
    }

    fn cwd_ptr(&mut self) -> PCWSTR {
        self.cwd_w
            .as_mut()
            .map(|c| c.as_pcwstr())
            .unwrap_or(PCWSTR::null())
    }

    fn cmd_ptr(&mut self) -> Option<PWSTR> {
        self.args_w.as_mut().map(|v| PWSTR(v.as_mut_ptr()))
    }
}

fn ensure_lpac_supported(sec: &SecurityCapabilities) -> Result<()> {
    if sec.lpac {
        crate::supports_lpac()
    } else {
        Ok(())
    }
}

pub(super) fn build_env_block(opts: &LaunchOptions) -> Result<Option<WideBlock>> {
    opts.env
        .as_ref()
        .map(|env| make_wide_block(env))
        .transpose()
}

pub(super) fn build_cwd(opts: &LaunchOptions) -> Option<WideString> {
    opts.cwd
        .as_ref()
        .map(|p| WideString::from_os_str(p.as_os_str()))
}

fn base_startup_info() -> STARTUPINFOEXW {
    let mut startup_info = STARTUPINFOEXW::default();
    startup_info.StartupInfo.cb = std::mem::size_of::<STARTUPINFOEXW>() as u32;
    startup_info
}

fn creation_flags(opts: &LaunchOptions, has_env_block: bool) -> PROCESS_CREATION_FLAGS {
    let mut flags = EXTENDED_STARTUPINFO_PRESENT;
    if has_env_block {
        flags |= CREATE_UNICODE_ENVIRONMENT;
    }
    if opts.suspended {
        flags |= CREATE_SUSPENDED;
    }
    flags
}

fn create_child_process(
    inputs: &mut ProcessInputs,
    info: &mut STARTUPINFOEXW,
    inherit_handles: bool,
    flags: PROCESS_CREATION_FLAGS,
    pi: &mut PROCESS_INFORMATION,
    token: Option<&FHandle>,
) -> Result<()> {
    trace_create_process(inputs, inherit_handles, flags);
    let env_ptr = inputs.env_ptr();
    let cwd_ptr = inputs.cwd_ptr();
    let cmd_ptr = inputs.cmd_ptr();

    let stage = if token.is_some() {
        "CreateProcessAsUserW"
    } else {
        "CreateProcessW"
    };
    // SAFETY: All token/UTF16/env/attribute owners outlive this synchronous call.
    let create_res = unsafe {
        if let Some(token) = token {
            CreateProcessAsUserW(
                Some(token.as_win32()),
                inputs.exe_w.as_pcwstr(),
                cmd_ptr,
                None,
                None,
                inherit_handles,
                flags,
                env_ptr,
                cwd_ptr,
                &info.StartupInfo,
                pi,
            )
        } else {
            CreateProcessW(
                inputs.exe_w.as_pcwstr(),
                cmd_ptr,
                None,
                None,
                inherit_handles,
                flags,
                env_ptr,
                cwd_ptr,
                &info.StartupInfo,
                pi,
            )
        }
    };
    create_res.map_err(|_| AcError::LaunchFailed {
        stage,
        hint: "launch",
        source: Box::new(std::io::Error::last_os_error()),
    })
}

fn process_handles(pi: PROCESS_INFORMATION) -> Result<ChildHandles> {
    let process = match handles::from_win32(pi.hProcess) {
        Ok(process) => process,
        Err(_) => {
            // SAFETY: CreateProcessW transferred ownership of hThread to this function.
            unsafe {
                let _ = CloseHandle(pi.hThread);
            }
            return Err(AcError::Win32("invalid process handle".into()));
        }
    };
    let thread = match handles::from_win32(pi.hThread) {
        Ok(thread) => thread,
        Err(_) => {
            let original = AcError::Win32("invalid thread handle".into());
            return match terminate_and_reap(&process) {
                Ok(()) => Err(original),
                Err(cleanup) => Err(post_spawn_cleanup_error(original, cleanup)),
            };
        }
    };
    Ok(ChildHandles {
        thread: Some(thread),
        process,
    })
}

fn launched_io(
    pid: u32,
    stdio: StdioSetupResult,
    process: FHandle,
    suspended_thread: Option<FHandle>,
    job_guard: Option<job::JobGuard>,
) -> LaunchedIo {
    LaunchedIo {
        pid,
        stdin: stdio.parent_stdin.map(|h| h.into_file()),
        stdout: stdio.parent_stdout.map(|h| h.into_file()),
        stderr: stdio.parent_stderr.map(|h| h.into_file()),
        job_guard,
        control: super::ProcessControl {
            process,
            suspended_thread,
        },
    }
}

fn prepare_child(
    opts: &LaunchOptions,
    child: &ChildHandles,
    birth_job: Option<job::JobGuard>,
) -> Result<Option<job::JobGuard>> {
    #[cfg(test)]
    fail_post_spawn_setup_for_test(child)?;
    let guard = match birth_job {
        Some(job) => Some(job),
        None => job::create_job_guard(opts.join_job.as_ref(), child.process.as_win32())?,
    };
    startup::wait_for_startup(opts, child.process.as_win32())?;
    Ok(guard)
}

#[cfg(test)]
pub(super) fn fail_next_post_spawn_setup_for_test() {
    FAIL_NEXT_POST_SPAWN_SETUP.with(|armed| {
        assert!(
            !armed.replace(true),
            "post-spawn failure injection is already armed"
        );
    });
    POST_SPAWN_REAP_WITNESS.with(|witness| *witness.borrow_mut() = None);
}

#[cfg(test)]
pub(super) fn take_post_spawn_reap_witness_for_test() -> Option<FHandle> {
    POST_SPAWN_REAP_WITNESS.with(|witness| witness.borrow_mut().take())
}

#[cfg(test)]
fn fail_post_spawn_setup_for_test(child: &ChildHandles) -> Result<()> {
    if !FAIL_NEXT_POST_SPAWN_SETUP.with(|armed| armed.replace(false)) {
        return Ok(());
    }
    let witness = handles::duplicate_handle(child.process.as_borrowed(), false)?;
    POST_SPAWN_REAP_WITNESS.with(|slot| *slot.borrow_mut() = Some(witness));
    Err(AcError::LaunchFailed {
        stage: "test_post_spawn_setup",
        hint: "inject post-spawn setup failure",
        source: Box::new(std::io::Error::other("deterministic test failure")),
    })
}

pub(super) fn terminate_and_reap(process: &FHandle) -> Result<()> {
    // SAFETY: The process handle remains owned and live for both calls. A successful
    // TerminateProcess guarantees eventual signaling, so the infinite reap wait cannot
    // strand a still-running child. A failed termination is probed without blocking.
    match unsafe { TerminateProcess(process.as_win32(), 1) } {
        Ok(()) => {
            // SAFETY: Successful termination guarantees eventual process signaling.
            let wait = unsafe { WaitForSingleObject(process.as_win32(), INFINITE) };
            if wait == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err(cleanup_failure(format!("process reap failed: {wait:?}")))
            }
        }
        Err(terminate_error) => {
            // SAFETY: Zero-time probe on the still-owned process handle cannot block.
            let wait = unsafe { WaitForSingleObject(process.as_win32(), 0) };
            if wait == WAIT_OBJECT_0 {
                Ok(())
            } else {
                Err(cleanup_failure(format!(
                    "TerminateProcess failed: {terminate_error}; process state: {wait:?}"
                )))
            }
        }
    }
}

fn cleanup_failure(message: String) -> AcError {
    AcError::LaunchFailed {
        stage: "post_spawn_cleanup",
        hint: "terminate and reap spawned child",
        source: Box::new(std::io::Error::other(message)),
    }
}

fn post_spawn_cleanup_error(original: AcError, cleanup: AcError) -> AcError {
    AcError::LaunchFailed {
        stage: "post_spawn_cleanup",
        hint: "child cleanup failed after launch setup error",
        source: Box::new(std::io::Error::other(format!(
            "launch setup error: {original}; cleanup error: {cleanup}"
        ))),
    }
}

#[cfg(feature = "tracing")]
fn trace_create_process(
    inputs: &ProcessInputs,
    inherit_handles: bool,
    flags: PROCESS_CREATION_FLAGS,
) {
    let env_bytes = inputs
        .env_block
        .as_ref()
        .map(|block| block.len() * std::mem::size_of::<u16>())
        .unwrap_or(0);
    tracing::trace!(
        "CreateProcessW: args_present={}, cwd_present={}, inherit_handles={}, flags=0x{:X}, env_bytes={}",
        inputs.args_w.is_some(),
        inputs.cwd_w.is_some(),
        inherit_handles,
        flags.0,
        env_bytes
    );
}

#[cfg(not(feature = "tracing"))]
fn trace_create_process(
    _inputs: &ProcessInputs,
    _inherit_handles: bool,
    _flags: PROCESS_CREATION_FLAGS,
) {
}

fn desktop_buffer(opts: &LaunchOptions) -> Result<Option<Vec<u16>>> {
    use std::os::windows::ffi::OsStrExt;
    opts.desktop
        .as_ref()
        .map(|desktop| {
            let mut buffer: Vec<u16> = desktop.encode_wide().collect();
            if buffer.contains(&0) {
                return Err(AcError::Win32("desktop name contains interior NUL".into()));
            }
            buffer.push(0);
            Ok(buffer)
        })
        .transpose()
}

#[cfg(test)]
mod desktop_tests {
    use super::*;

    #[test]
    fn absent_desktop_preserves_null_default() {
        assert!(
            ProcessInputs::from_options(&LaunchOptions::default())
                .unwrap()
                .desktop_w
                .is_none()
        );
    }

    #[test]
    fn named_desktop_retains_unicode_spaces_and_terminator() {
        let options = LaunchOptions {
            desktop: Some("QQ station\\任务 desktop".into()),
            ..Default::default()
        };
        let inputs = ProcessInputs::from_options(&options).unwrap();
        let expected: Vec<u16> = "QQ station\\任务 desktop"
            .encode_utf16()
            .chain(Some(0))
            .collect();
        assert_eq!(inputs.desktop_w.as_ref().unwrap(), &expected);
    }

    #[test]
    fn interior_nul_is_refused_before_process_creation() {
        let options = LaunchOptions {
            desktop: Some("QQ\0wrong".into()),
            ..Default::default()
        };
        assert!(
            matches!(ProcessInputs::from_options(&options), Err(AcError::Win32(message)) if message == "desktop name contains interior NUL")
        );
    }
}

#[cfg(test)]
#[path = "broker_tests.rs"]
mod broker_tests;
