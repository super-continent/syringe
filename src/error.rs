use thiserror::Error;

/// Error types for Syringe
#[derive(Debug, Error)]
pub enum SyringeError {
    /// The given process ID was not valid
    #[error("Could not find process")]
    ProcessNotFound,
    /// The DLL could not be found in the specified path
    #[error("Unable to locate DLL in specified path")]
    DllNotFound,
    /// The PathBuf could not be converted to `&str` or `CString` properly
    #[error("Invalid DLL path: {0}")]
    InvalidPath(String),
    /// VirtualAllocEx failed
    #[error("VirtualAllocEx on remote process failed")]
    AllocFailed,
    /// WriteProcessMemory failed
    #[error("WriteProcessMemory failed on remote process")]
    WriteMemoryFailure,
    /// CreateRemoteThread failed
    #[error("CreateRemoteThread failed on remote process")]
    CreateThreadFailure,
    #[error("Could not get debug privileges: {0}")]
    SetPrivilegesFailure(String),
}
