use super::JobLimits;
use crate::ffi::handles::{self, Handle as FHandle};
use crate::{AcError, Result};
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::JobObjects::{
    AssignProcessToJobObject, CreateJobObjectW, JOB_OBJECT_CPU_RATE_CONTROL_ENABLE,
    JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
    JOB_OBJECT_LIMIT_PROCESS_MEMORY, JOBOBJECT_CPU_RATE_CONTROL_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectCpuRateControlInformation,
    JobObjectExtendedLimitInformation, SetInformationJobObject,
};
use windows::core::PCWSTR;

#[derive(Debug)]
pub struct JobGuard(FHandle);

impl JobGuard {
    /// Returns the underlying job handle for inspection without taking ownership.
    pub fn as_handle(&self) -> HANDLE {
        self.0.as_win32()
    }

    /// Number of processes currently held by this command job.
    pub fn active_processes(&self) -> Result<u32> {
        use windows::Win32::System::JobObjects::{
            JOBOBJECT_BASIC_ACCOUNTING_INFORMATION, JobObjectBasicAccountingInformation,
            QueryInformationJobObject,
        };
        let mut info = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
        // SAFETY: Owned job and correctly sized output buffer remain live.
        unsafe {
            QueryInformationJobObject(
                Some(self.0.as_win32()),
                JobObjectBasicAccountingInformation,
                (&mut info as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
                std::mem::size_of_val(&info) as u32,
                None,
            )
        }
        .map_err(|error| AcError::Win32(format!("QueryInformationJobObject(active): {error}")))?;
        Ok(info.ActiveProcesses)
    }
}

/// Job object drop-guard that enables kill-on-close by default.
/// Dropping this guard will terminate attached processes unless explicitly disabled.
#[derive(Debug)]
pub struct JobObjectDropGuard {
    handle: FHandle,
    kill_on_drop: bool,
}

impl JobObjectDropGuard {
    pub fn new() -> Result<Self> {
        let handle = create_job_handle()?;
        apply_drop_guard_kill_limit(&handle)?;
        Ok(Self {
            handle,
            kill_on_drop: true,
        })
    }

    pub fn as_handle(&self) -> HANDLE {
        self.handle.as_win32()
    }

    pub fn assign_process_handle(&self, process: HANDLE) -> Result<()> {
        // SAFETY: Attach the provided process to the job represented by this guard.
        unsafe { AssignProcessToJobObject(self.handle.as_win32(), process) }
            .map_err(|_| AcError::Win32("AssignProcessToJobObject failed".into()))
    }

    /// Clears the kill-on-close flag so dropping this guard will not
    /// terminate attached processes.
    pub fn disable_kill_on_drop(&mut self) -> Result<()> {
        clear_drop_guard_limits(&self.handle)?;
        self.kill_on_drop = false;
        Ok(())
    }

    #[cfg(test)]
    pub(super) fn kill_on_drop_enabled(&self) -> bool {
        self.kill_on_drop
    }
}

pub(super) fn create_birth_job_guard(limits: &JobLimits) -> Result<JobGuard> {
    let handle = create_job_handle()?;
    apply_extended_limits(&handle, limits)?;
    apply_cpu_limit(&handle, limits.cpu_rate_percent)?;
    Ok(JobGuard(handle))
}

pub(super) fn create_job_guard(
    limits: Option<&JobLimits>,
    process: HANDLE,
) -> Result<Option<JobGuard>> {
    let Some(limits) = limits else {
        return Ok(None);
    };

    let hjob = create_job_handle()?;
    apply_extended_limits(&hjob, limits)?;
    apply_cpu_limit(&hjob, limits.cpu_rate_percent)?;
    assign_child_process(&hjob, process)?;

    Ok(limits.kill_on_job_close.then_some(JobGuard(hjob)))
}

fn create_job_handle() -> Result<FHandle> {
    // SAFETY: `CreateJobObjectW` creates a valid job object handle for the current process.
    let hjob_raw = unsafe { CreateJobObjectW(None, PCWSTR::null()) }
        .map_err(|e| AcError::Win32(format!("CreateJobObjectW failed: {e}")))?;
    handles::from_win32(hjob_raw).map_err(|_| AcError::Win32("invalid job handle".into()))
}

fn apply_drop_guard_kill_limit(job: &FHandle) -> Result<()> {
    let mut info = empty_extended_limits();
    info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    // SAFETY: Pass a valid reference to the initialized struct; size matches the type.
    unsafe {
        SetInformationJobObject(
            job.as_win32(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(|_| AcError::Win32("SetInformationJobObject(kill_on_close) failed".into()))
    }
}

fn clear_drop_guard_limits(job: &FHandle) -> Result<()> {
    let info = empty_extended_limits();
    // SAFETY: Pass a valid reference with correct size; clears kill-on-close.
    unsafe {
        SetInformationJobObject(
            job.as_win32(),
            JobObjectExtendedLimitInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
        .map_err(|_| AcError::Win32("SetInformationJobObject(clear) failed".into()))
    }
}

fn apply_extended_limits(job: &FHandle, limits: &JobLimits) -> Result<()> {
    if limits.memory_bytes.is_none() && !limits.kill_on_job_close {
        return Ok(());
    }

    let mut info = empty_extended_limits();
    if let Some(bytes) = limits.memory_bytes {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_PROCESS_MEMORY;
        info.ProcessMemoryLimit = bytes;
    }
    if limits.kill_on_job_close {
        info.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    }

    set_launch_job_extended_info(job, &info)
}

fn apply_cpu_limit(job: &FHandle, cpu_rate_percent: Option<u32>) -> Result<()> {
    let Some(percent) = cpu_rate_percent else {
        return Ok(());
    };

    let info = JOBOBJECT_CPU_RATE_CONTROL_INFORMATION {
        ControlFlags: JOB_OBJECT_CPU_RATE_CONTROL_ENABLE | JOB_OBJECT_CPU_RATE_CONTROL_HARD_CAP,
        Anonymous: windows::Win32::System::JobObjects::JOBOBJECT_CPU_RATE_CONTROL_INFORMATION_0 {
            CpuRate: percent.clamp(1, 100) * 100,
        },
    };

    // SAFETY: `job` is a live handle and `info` structure is fully initialized.
    unsafe {
        SetInformationJobObject(
            job.as_win32(),
            JobObjectCpuRateControlInformation,
            &info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_CPU_RATE_CONTROL_INFORMATION>() as u32,
        )
    }
    .map_err(|_| AcError::LaunchFailed {
        stage: "SetInformationJobObject(cpu)",
        hint: "set cpu cap",
        source: Box::new(std::io::Error::last_os_error()),
    })
}

fn set_launch_job_extended_info(
    job: &FHandle,
    info: &JOBOBJECT_EXTENDED_LIMIT_INFORMATION,
) -> Result<()> {
    // SAFETY: `job` is a live handle and `info` structure is fully initialized.
    unsafe {
        SetInformationJobObject(
            job.as_win32(),
            JobObjectExtendedLimitInformation,
            info as *const _ as *const _,
            std::mem::size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    }
    .map_err(|_| AcError::LaunchFailed {
        stage: "SetInformationJobObject(ext)",
        hint: "set job limits",
        source: Box::new(std::io::Error::last_os_error()),
    })
}

fn assign_child_process(job: &FHandle, process: HANDLE) -> Result<()> {
    // SAFETY: Both handles are valid live handles for this operation.
    unsafe { AssignProcessToJobObject(job.as_win32(), process) }.map_err(|_| {
        AcError::LaunchFailed {
            stage: "AssignProcessToJobObject",
            hint: "attach child",
            source: Box::new(std::io::Error::last_os_error()),
        }
    })
}

fn empty_extended_limits() -> JOBOBJECT_EXTENDED_LIMIT_INFORMATION {
    // SAFETY: Zero-initialize the structure per Win32 API requirements.
    unsafe { std::mem::zeroed() }
}
