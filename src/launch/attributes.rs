use crate::Result;
use crate::capability::SecurityCapabilities;
use crate::ffi::attr_list::AttrList as FAttrList;
use crate::ffi::handles::Handle as FHandle;
use crate::ffi::sec_caps::OwnedSecurityCapabilities;
use crate::ffi::sid::OwnedSid;
use std::rc::Rc;
use std::sync::Arc;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::System::Threading::{LPPROC_THREAD_ATTRIBUTE_LIST, STARTUPINFOEXW};
use windows::Win32::System::WindowsProgramming::PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT;

#[derive(Default)]
pub(super) struct InheritList {
    handles: Vec<FHandle>,
    shared_handles: Vec<Arc<FHandle>>,
    raw: Vec<HANDLE>,
}

impl InheritList {
    pub(super) fn push(&mut self, handle: FHandle) {
        let raw = handle.as_win32();
        self.raw.push(raw);
        self.handles.push(handle);
    }

    pub(super) fn push_shared(&mut self, handle: Arc<FHandle>) {
        let raw = handle.as_win32();
        self.raw.push(raw);
        self.shared_handles.push(handle);
    }

    pub(super) fn is_empty(&self) -> bool {
        self.raw.is_empty()
    }

    pub(super) fn slice(&self) -> &[HANDLE] {
        &self.raw
    }
}

pub(super) struct LaunchAttributes {
    attr_list: FAttrList,
    security_caps: Rc<OwnedSecurityCapabilities>,
    lpac_policy: Option<Box<u32>>,
    handle_list: Vec<HANDLE>,
    birth_jobs: Option<Box<[HANDLE; 1]>>,
}

impl LaunchAttributes {
    pub(super) fn new(
        security_caps: Rc<OwnedSecurityCapabilities>,
        lpac: bool,
        handles: &[HANDLE],
    ) -> Result<Self> {
        Self::new_with_job(security_caps, lpac, handles, None)
    }

    pub(super) fn new_with_job(
        security_caps: Rc<OwnedSecurityCapabilities>,
        lpac: bool,
        handles: &[HANDLE],
        job: Option<HANDLE>,
    ) -> Result<Self> {
        // These buffers must outlive attr_list on every registration error as well.
        let birth_jobs = job.map(|job| Box::new([job]));
        let lpac_policy = lpac.then(|| Box::new(PROCESS_CREATION_ALL_APPLICATION_PACKAGES_OPT_OUT));
        let handle_list = handles.to_vec();
        let mut attr_list =
            FAttrList::with_capacity(attribute_count(lpac, handles) + u32::from(job.is_some()))?;
        if let Some(jobs) = &birth_jobs {
            attr_list.set_job_list(jobs.as_ref())?;
        }

        attr_list.set_security_capabilities(security_caps.as_ref())?;

        if let Some(policy) = &lpac_policy {
            attr_list.set_all_app_packages_policy(policy.as_ref())?;
        }
        if !handle_list.is_empty() {
            attr_list.set_handle_list(&handle_list)?;
        }

        Ok(Self {
            attr_list,
            security_caps,
            lpac_policy,
            handle_list,
            birth_jobs,
        })
    }

    fn as_mut_ptr(&mut self) -> LPPROC_THREAD_ATTRIBUTE_LIST {
        self.keep_alive();
        self.attr_list.as_mut_ptr()
    }

    fn keep_alive(&self) {
        let _ = (
            &self.security_caps,
            &self.lpac_policy,
            &self.handle_list,
            &self.birth_jobs,
        );
    }
}

pub(super) struct StartUpInfoExGuard {
    info: STARTUPINFOEXW,
    attrs: LaunchAttributes,
}

impl StartUpInfoExGuard {
    pub(super) fn new(mut info: STARTUPINFOEXW, mut attrs: LaunchAttributes) -> Self {
        info.lpAttributeList = attrs.as_mut_ptr();
        Self { info, attrs }
    }

    pub(super) fn info_mut(&mut self) -> &mut STARTUPINFOEXW {
        self.info.lpAttributeList = self.attrs.as_mut_ptr();
        &mut self.info
    }
}

pub(super) fn inflate_security_caps(
    sec: &SecurityCapabilities,
) -> Result<Rc<OwnedSecurityCapabilities>> {
    let app_sid = OwnedSid::from_sddl(sec.package.as_string())?;
    let mut caps_owned = Vec::with_capacity(sec.caps.len());
    for cap in &sec.caps {
        caps_owned.push(OwnedSid::from_sddl(&cap.sid_sddl)?);
    }

    Ok(Rc::new(OwnedSecurityCapabilities::new(app_sid, caps_owned)))
}

pub(super) fn duplicate_additional_handles(
    handles: &[Arc<FHandle>],
    inherit_list: &mut InheritList,
) -> Result<()> {
    for handle in handles {
        inherit_list.push_shared(handle.clone());
    }
    Ok(())
}

fn attribute_count(lpac: bool, handles: &[HANDLE]) -> u32 {
    let mut count = 1;
    if lpac {
        count += 1;
    }
    if !handles.is_empty() {
        count += 1;
    }
    count
}
