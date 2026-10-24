//! Owned SECURITY_CAPABILITIES with owned SIDs and SID_AND_ATTRIBUTES.

use crate::capability::{CapabilityCatalog, CapabilityName};
use crate::ffi::sid::OwnedSid;
use crate::{AcError, Result};
use windows::Win32::Security::{SECURITY_CAPABILITIES, SID_AND_ATTRIBUTES};

use super::SE_GROUP_ENABLED;

#[derive(Debug)]
pub(crate) struct OwnedSecurityCapabilities {
    _appcontainer_sid: OwnedSid,
    // Keep capability SIDs alive for the lifetime of SECURITY_CAPABILITIES
    _cap_sids: Vec<OwnedSid>,
    _caps: Box<[SID_AND_ATTRIBUTES]>,
    sc: SECURITY_CAPABILITIES,
}

impl OwnedSecurityCapabilities {
    pub(crate) fn new(app_sid: OwnedSid, caps_in: impl IntoIterator<Item = OwnedSid>) -> Self {
        let cap_sids: Vec<OwnedSid> = caps_in.into_iter().collect();
        let caps_vec: Vec<SID_AND_ATTRIBUTES> = cap_sids
            .iter()
            .map(|sid| SID_AND_ATTRIBUTES {
                Sid: sid.as_psid(),
                Attributes: SE_GROUP_ENABLED,
            })
            .collect();
        let caps = caps_vec.into_boxed_slice();
        let sc = SECURITY_CAPABILITIES {
            AppContainerSid: app_sid.as_psid(),
            Capabilities: caps.as_ptr() as *mut _,
            CapabilityCount: caps.len() as u32,
            Reserved: 0,
        };
        Self {
            _appcontainer_sid: app_sid,
            _cap_sids: cap_sids,
            _caps: caps,
            sc,
        }
    }

    #[cfg_attr(not(test), allow(dead_code))]
    pub fn from_catalog(app_sid: OwnedSid, caps: &[CapabilityName]) -> Result<Self> {
        if caps.is_empty() {
            return Ok(Self::new(app_sid, std::iter::empty::<OwnedSid>()));
        }
        let catalog = CapabilityCatalog::from_names(caps)?;
        let mut owned_caps = Vec::with_capacity(caps.len());
        for &cap_name in caps {
            let capability =
                catalog
                    .capability(cap_name)
                    .ok_or_else(|| AcError::UnknownCapability {
                        name: cap_name.as_str().to_string(),
                        suggestion: None,
                    })?;
            owned_caps.push(capability.to_sid()?);
        }
        Ok(Self::new(app_sid, owned_caps))
    }

    pub(crate) fn as_ptr(&self) -> *const SECURITY_CAPABILITIES {
        &self.sc as *const _
    }
}

#[cfg(test)]
#[cfg(windows)]
mod tests {
    use super::*;
    use crate::capability::CapabilityName;
    use windows::Win32::Security::Authorization::ConvertStringSidToSidW;
    use windows::Win32::Security::IsValidSid;
    use windows::core::PCWSTR;

    #[test]
    fn empty_capabilities_use_a_null_pointer() {
        let package = OwnedSid::from_sddl("S-1-15-2-1").unwrap();
        let capabilities = OwnedSecurityCapabilities::new(package, std::iter::empty());
        assert_eq!(capabilities.sc.CapabilityCount, 0);
        assert!(capabilities.sc.Capabilities.is_null());
        assert!(!capabilities.sc.AppContainerSid.0.is_null());
        assert_eq!(capabilities.sc.Reserved, 0);
    }

    #[test]
    fn build_security_capabilities() {
        // SAFETY: SDDL strings are valid; resulting PSIDs are converted into owned SIDs.
        unsafe {
            let s_app = crate::ffi::wstr::WideString::from_str("S-1-5-32-544");
            let mut app_sid = windows::Win32::Security::PSID::default();
            ConvertStringSidToSidW(PCWSTR(s_app.as_pcwstr().0), &mut app_sid).unwrap();
            let app_owned = OwnedSid::from_localfree_psid(app_sid.0).expect("owned app SID");

            let s_cap = crate::ffi::wstr::WideString::from_str("S-1-15-3-1024-0-0-0-0");
            let mut cap_sid = windows::Win32::Security::PSID::default();
            ConvertStringSidToSidW(PCWSTR(s_cap.as_pcwstr().0), &mut cap_sid).unwrap();
            let cap_owned = OwnedSid::from_localfree_psid(cap_sid.0).expect("owned cap SID");

            let sc = OwnedSecurityCapabilities::new(app_owned, [cap_owned]);
            let _p = sc.as_ptr();
        }
    }

    #[test]
    fn build_security_capabilities_from_catalog() {
        // SAFETY: SDDL strings are valid; resulting PSIDs are converted into owned SIDs.
        unsafe {
            let s_app = crate::ffi::wstr::WideString::from_str("S-1-15-2-1");
            let mut app_sid = windows::Win32::Security::PSID::default();
            ConvertStringSidToSidW(PCWSTR(s_app.as_pcwstr().0), &mut app_sid).unwrap();
            let app_owned = OwnedSid::from_localfree_psid(app_sid.0).expect("owned app SID");

            let sc = OwnedSecurityCapabilities::from_catalog(
                app_owned,
                &[
                    CapabilityName::InternetClient,
                    CapabilityName::PrivateNetworkClientServer,
                ],
            )
            .expect("from_catalog");
            let ptr = sc.as_ptr();
            assert!(!ptr.is_null());
            let sc_ref = &*ptr;
            assert_eq!(sc_ref.CapabilityCount, 2);
            assert!(
                !sc_ref.Capabilities.is_null(),
                "Capabilities pointer must not be null"
            );
            let entries =
                std::slice::from_raw_parts(sc_ref.Capabilities, sc_ref.CapabilityCount as usize);
            assert_eq!(entries.len(), 2);
            for (idx, entry) in entries.iter().enumerate() {
                assert!(
                    !entry.Sid.0.is_null(),
                    "capability SID pointer {idx} must not be null"
                );
                let attrs = entry.Attributes;
                assert_eq!(
                    attrs & SE_GROUP_ENABLED,
                    SE_GROUP_ENABLED,
                    "capability {idx} missing SE_GROUP_ENABLED attribute"
                );
                // Capability SID pointers originate from OwnedSecurityCapabilities and remain valid here.
                let is_valid = IsValidSid(entry.Sid).as_bool();
                assert!(is_valid, "capability SID {idx} failed IsValidSid");
            }
        }
    }
}
