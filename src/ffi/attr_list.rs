//! Owned `PROC_THREAD_ATTRIBUTE_LIST` with helpers for security capabilities.

use crate::{AcError, Result};
use core::ffi::c_void;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{
    DeleteProcThreadAttributeList, InitializeProcThreadAttributeList, LPPROC_THREAD_ATTRIBUTE_LIST,
    PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES, UpdateProcThreadAttribute,
};

#[derive(Debug)]
pub(crate) struct AttrList {
    _buf: Vec<u8>,
    ptr: LPPROC_THREAD_ATTRIBUTE_LIST,
}

impl AttrList {
    pub(crate) fn with_capacity(count: u32) -> Result<Self> {
        let mut bytes: usize = 0;
        // SAFETY: Probe for size; passing None and flags=0 per API contract.
        unsafe {
            let _ =
                InitializeProcThreadAttributeList(None, count, Some(0), &mut bytes as *mut usize);
        }
        let mut buf = vec![0u8; bytes];
        let ptr = LPPROC_THREAD_ATTRIBUTE_LIST(buf.as_mut_ptr() as _);
        // SAFETY: Initialize with computed size.
        unsafe {
            InitializeProcThreadAttributeList(Some(ptr), count, Some(0), &mut bytes as *mut usize)
                .map_err(|e| AcError::Win32(format!("InitializeProcThreadAttributeList: {e}")))?;
        }
        Ok(Self { _buf: buf, ptr })
    }

    pub(crate) fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.ptr
    }

    pub(crate) fn set_security_capabilities(
        &mut self,
        sc: &crate::ffi::sec_caps::OwnedSecurityCapabilities,
    ) -> Result<()> {
        let size = core::mem::size_of::<windows::Win32::Security::SECURITY_CAPABILITIES>();
        // SAFETY: `sc` points to stable, owned memory; attribute list initialized.
        unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES as usize,
                Some(sc.as_ptr() as *const _),
                size,
                None,
                None,
            )
            .map_err(|e| AcError::Win32(format!("UpdateProcThreadAttribute: {e}")))
        }
    }

    /// Attach the All App Packages policy (LPAC opt-out) attribute.
    /// Caller must ensure `policy` outlives CreateProcessW.
    pub(crate) fn set_all_app_packages_policy(&mut self, policy: &u32) -> Result<()> {
        use windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY;
        let size = core::mem::size_of::<u32>();
        // SAFETY: `policy` points to stable memory alive until CreateProcessW returns.
        unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_ALL_APPLICATION_PACKAGES_POLICY as usize,
                Some(policy as *const u32 as *const c_void),
                size,
                None,
                None,
            )
            .map_err(|e| AcError::Win32(format!("UpdateProcThreadAttribute(AAPolicy): {e}")))
        }
    }

    /// Attach the sole owned command job; caller retains the array through attribute destruction.
    pub(crate) fn set_job_list(&mut self, jobs: &[HANDLE]) -> Result<()> {
        use windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_JOB_LIST;
        // SAFETY: Retained slice and live owned job outlive the attribute list.
        unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                Some(jobs.as_ptr().cast()),
                std::mem::size_of_val(jobs),
                None,
                None,
            )
        }
        .map_err(|error| AcError::Win32(format!("UpdateProcThreadAttribute(JobList): {error}")))
    }

    /// Attach a handle inheritance list.
    /// The slice must remain valid until CreateProcessW returns.
    pub(crate) fn set_handle_list(&mut self, handles: &[HANDLE]) -> Result<()> {
        use windows::Win32::System::Threading::PROC_THREAD_ATTRIBUTE_HANDLE_LIST;
        let bytes = std::mem::size_of_val(handles);
        // SAFETY: `handles` points to a valid slice alive until CreateProcessW returns.
        unsafe {
            UpdateProcThreadAttribute(
                self.ptr,
                0,
                PROC_THREAD_ATTRIBUTE_HANDLE_LIST as usize,
                Some(handles.as_ptr() as *const c_void),
                bytes,
                None,
                None,
            )
            .map_err(|e| AcError::Win32(format!("UpdateProcThreadAttribute(HandleList): {e}")))
        }
    }
}

impl Drop for AttrList {
    fn drop(&mut self) {
        // SAFETY: Attribute list was initialized; ok to delete once.
        unsafe {
            DeleteProcThreadAttributeList(self.ptr);
        }
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::core::PCWSTR;

    #[test]
    fn attr_list_init_and_set_sc() {
        // SAFETY: SDDL strings are valid; PSIDs are converted into owned SIDs and kept alive.
        unsafe {
            let s_app = crate::ffi::wstr::WideString::from_str("S-1-5-32-544");
            let mut app_sid = windows::Win32::Security::PSID::default();
            ConvertStringSidToSidW(PCWSTR(s_app.as_pcwstr().0), &mut app_sid).unwrap();
            let app_owned =
                crate::ffi::sid::OwnedSid::from_localfree_psid(app_sid.0).expect("owned app SID");

            let s_cap = crate::ffi::wstr::WideString::from_str("S-1-15-3-1024-0-0-0-0");
            let mut cap_sid = windows::Win32::Security::PSID::default();
            ConvertStringSidToSidW(PCWSTR(s_cap.as_pcwstr().0), &mut cap_sid).unwrap();
            let cap_owned =
                crate::ffi::sid::OwnedSid::from_localfree_psid(cap_sid.0).expect("owned cap SID");

            let sc = crate::ffi::sec_caps::OwnedSecurityCapabilities::new(app_owned, [cap_owned]);
            let mut al = AttrList::with_capacity(1).unwrap();
            al.set_security_capabilities(&sc).unwrap();
        }
    }
}
