use super::*;
use windows::Win32::Security::{TOKEN_ASSIGN_PRIMARY, TOKEN_DUPLICATE, TOKEN_QUERY};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

fn current_primary() -> FHandle {
    let mut token = windows::Win32::Foundation::HANDLE::default();
    // SAFETY: Current process and initialized token out pointer are valid.
    unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY,
            &mut token,
        )
    }
    .unwrap();
    handles::from_win32(token).unwrap()
}

fn options() -> LaunchOptions {
    LaunchOptions {
        join_job: Some(super::super::JobLimits {
            kill_on_job_close: true,
            ..Default::default()
        }),
        ..Default::default()
    }
}

#[test]
fn explicit_token_requires_kill_on_close_job() {
    let token = current_primary();
    assert!(
        LaunchOptions::default()
            .try_with_primary_token(token.as_borrowed())
            .is_err()
    );
}

#[test]
fn token_clone_is_owned_noninheritable_and_forces_suspension() {
    use windows::Win32::Foundation::GetHandleInformation;
    let token = current_primary();
    let options = options()
        .try_with_primary_token(token.as_borrowed())
        .unwrap();
    drop(token);
    assert!(options.suspended);
    let clone = options.extra.primary_token.as_ref().unwrap();
    let mut flags = 0_u32;
    // SAFETY: Cloned token is owned by options; flags is valid output storage.
    unsafe { GetHandleInformation(clone.as_win32(), &mut flags) }.unwrap();
    assert_eq!(flags & 1, 0);
}

#[test]
fn caller_cannot_remove_required_suspension() {
    let token = current_primary();
    let mut options = options()
        .try_with_primary_token(token.as_borrowed())
        .unwrap();
    options.suspended = false;
    let sec = SecurityCapabilities {
        package: crate::AppContainerSid::try_from_sddl("S-1-15-2-1").unwrap(),
        caps: vec![],
        lpac: false,
    };
    assert!(
        matches!(launch_impl(&sec, &options), Err(AcError::Win32(message))
        if message == "explicit token requires suspended kill-on-close job")
    );
}

#[test]
fn birth_job_attribute_keeps_job_owned_until_attribute_destruction() {
    let limits = super::super::JobLimits {
        kill_on_job_close: true,
        ..Default::default()
    };
    let job = job::create_birth_job_guard(&limits).unwrap();
    let sec = SecurityCapabilities {
        package: crate::AppContainerSid::try_from_sddl("S-1-15-2-1").unwrap(),
        caps: vec![],
        lpac: false,
    };
    let caps = inflate_security_caps(&sec).unwrap();
    let attrs = LaunchAttributes::new_with_job(caps, false, &[], Some(job.as_handle())).unwrap();
    drop(attrs);
    assert_eq!(job.active_processes().unwrap(), 0);
}

#[test]
fn explicit_token_refuses_startup_timeout_before_and_after_builder() {
    let token = current_primary();
    let mut initial = options();
    initial.startup_timeout = Some(std::time::Duration::ZERO);
    assert!(
        matches!(initial.try_with_primary_token(token.as_borrowed()),
        Err(AcError::Win32(message)) if message == "explicit token requires no startup timeout")
    );
    let mut options = options()
        .try_with_primary_token(token.as_borrowed())
        .unwrap();
    options.startup_timeout = Some(std::time::Duration::ZERO);
    let sec = SecurityCapabilities {
        package: crate::AppContainerSid::try_from_sddl("S-1-15-2-1").unwrap(),
        caps: vec![],
        lpac: false,
    };
    assert!(matches!(launch_impl(&sec, &options),
        Err(AcError::Win32(message)) if message == "explicit token requires no startup timeout"));
}
