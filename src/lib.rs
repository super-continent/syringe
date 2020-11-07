//! Tools for injecting DLLs into windows processes, these are organized into types
//! [`RunningInjector`] and [`StartupInjector`], used for injecting into arbitrary running
//! processes and processes that are created by directly opening their executable respectively

pub mod error;

use crate::error::SyringeError;

use std::ffi::{
    OsString,
    OsStr,
    CString
};
use std::mem;
use std::os::windows::ffi::{
    OsStrExt, OsStringExt
};
use std::path::PathBuf;
use std::ptr;

use dunce;
use winapi::shared::minwindef::*;
use winapi::um::{
    handleapi::CloseHandle,
    handleapi::INVALID_HANDLE_VALUE,
    libloaderapi::{GetModuleHandleW, GetProcAddress},
    memoryapi::{VirtualAllocEx, WriteProcessMemory},
    processthreadsapi::{CreateRemoteThread, GetCurrentProcess, OpenProcess, OpenProcessToken},
    securitybaseapi::AdjustTokenPrivileges,
    tlhelp32::{
        CreateToolhelp32Snapshot, Process32FirstW, Process32NextW, PROCESSENTRY32W, TH32CS_SNAPPROCESS,
    },
    winbase::LookupPrivilegeValueA,
    winnt::{
        HANDLE, LUID, MEM_COMMIT, PAGE_READWRITE, PROCESS_ALL_ACCESS, SE_DEBUG_NAME,
        SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES, TOKEN_PRIVILEGES, TOKEN_QUERY,
    },
};

type LPThreadStartRoutineFn = unsafe extern "system" fn(*mut winapi::ctypes::c_void) -> u32;

pub struct RunningInjector {
    process_id: DWORD,
    dll_path: PathBuf,
}

impl RunningInjector {
    /// Create a new RunningInjector
    pub fn new<P: Into<PathBuf>>(
        process_id: DWORD,
        dll_path: P,
    ) -> Result<RunningInjector, SyringeError> {
        let path: PathBuf = if let Ok(p) = dunce::canonicalize(dll_path.into()) {
            p
        } else {
            return Err(SyringeError::DllNotFound);
        };

        if !path.exists() || !path.is_file() {
            return Err(SyringeError::DllNotFound);
        }

        Ok(RunningInjector {
            process_id,
            dll_path: path,
        })
    }

    pub fn from_exe_name<P: Into<PathBuf>>(
        name: &str,
        dll_path: P,
    ) -> Result<RunningInjector, SyringeError> {
        let pid = match get_pid_from_name(name) {
            Some(pid) => pid,
            None => return Err(SyringeError::ProcessNotFound),
        };

        RunningInjector::new(pid, dll_path)
    }

    pub unsafe fn inject(&self) -> Result<(), SyringeError> {
        let dll_path = match self.dll_path.to_str() {
            Some(p) => p,
            None => return Err(SyringeError::DllNotFound),
        };
        let dll_path_size = (dll_path.len() + 1) * mem::size_of::<u16>();

        let process_handle;
        unsafe {
            if let Err(e) = get_debug_privilege() {
                return Err(e);
            }
            process_handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, self.process_id);
        }

        if process_handle.is_null() || process_handle == INVALID_HANDLE_VALUE {
            return Err(SyringeError::ProcessNotFound);
        }

        let path_address;
        unsafe {
            // Alloc memory and write path to its address
            path_address = VirtualAllocEx(
                process_handle,
                ptr::null_mut(),
                dll_path_size,
                MEM_COMMIT,
                PAGE_READWRITE,
            );

            if path_address.is_null() {
                return Err(SyringeError::AllocFailed);
            }

            let wpm_successful = WriteProcessMemory(
                process_handle,
                path_address,
                win32_wstring(dll_path).as_ptr() as *mut _,
                dll_path_size,
                ptr::null_mut(),
            );

            if wpm_successful == FALSE {
                return Err(SyringeError::WriteMemoryFailure);
            }

            // Get LoadLibraryW address, should be the same as the address in memory of the remote process
            let kernel32_name = win32_wstring("Kernel32.dll");
            let loadlibraryw_name = CString::new("LoadLibraryW").expect("CString::new() failed");
            let loadlibrary_address = GetProcAddress(
                GetModuleHandleW(kernel32_name.as_ptr()),
                loadlibraryw_name.as_ptr(),
            );

            if loadlibrary_address.is_null() {
                return Err(SyringeError::CreateThreadFailure);
            }

            let remote_thread = CreateRemoteThread(
                process_handle,
                ptr::null_mut(),
                0,
                Some(std::mem::transmute::<*mut _, LPThreadStartRoutineFn>(
                    loadlibrary_address,
                )),
                path_address,
                0,
                ptr::null_mut(),
            );

            if remote_thread.is_null() {
                return Err(SyringeError::CreateThreadFailure);
            }
        }

        unsafe {
            CloseHandle(process_handle);
        }
        Ok(())
    }
}

// Gets SeDebugPrivilege for injection
fn get_debug_privilege() -> Result<(), SyringeError> {
    unsafe {
        let mut token: HANDLE = ptr::null_mut();
        if OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token,
        ) == FALSE
        {
            return Err(SyringeError::SetPrivilegesFailure(
                "Could not open process token".into(),
            ));
        };

        let mut luid: LUID = mem::zeroed();

        let se_debug_name =
            CString::new(SE_DEBUG_NAME).expect("CString::new(SE_DEBUG_NAME) failed");
        if LookupPrivilegeValueA(ptr::null_mut(), se_debug_name.as_ptr(), &mut luid) == FALSE {
            return Err(SyringeError::SetPrivilegesFailure(
                "Could not look up privilege value".into(),
            ));
        };

        let mut privilege: TOKEN_PRIVILEGES = mem::zeroed();
        privilege.PrivilegeCount = 1;
        privilege.Privileges[0].Luid = luid;
        privilege.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

        if AdjustTokenPrivileges(
            token,
            FALSE,
            &mut privilege,
            mem::size_of_val(&privilege) as u32,
            ptr::null_mut(),
            ptr::null_mut(),
        ) == FALSE
        {
            let err = winapi::um::errhandlingapi::GetLastError();
            return Err(SyringeError::SetPrivilegesFailure(format!(
                "AdjustTokenPrivileges failed: {:#X}",
                err
            )));
        };
        winapi::um::errhandlingapi::GetLastError();

        CloseHandle(token);
        winapi::um::errhandlingapi::GetLastError();
    }

    Ok(())
}

fn get_pid_from_name(name: &str) -> Option<DWORD> {
    unsafe {
        let snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

        if !snapshot.is_null() && snapshot != INVALID_HANDLE_VALUE {
            let mut process: PROCESSENTRY32W = mem::zeroed();
            process.dwSize = mem::size_of::<PROCESSENTRY32W>() as u32;

            let mut fetch_process_success = Process32FirstW(snapshot, &mut process);
            while fetch_process_success == TRUE {
                // Get OsString from wide, make sure it converts to str, and trim NULLs
                let exe_file: OsString = OsStringExt::from_wide(&process.szExeFile);

                if let Some(untrimmed_name) = exe_file.to_str() {
                    let current_exe_name = untrimmed_name.trim_matches(char::from(0));

                    // Check for match
                    if name.to_lowercase() == current_exe_name.to_lowercase() {
                        return Some(process.th32ProcessID)
                    }
                }

                fetch_process_success = Process32NextW(snapshot, &mut process);
            }
        }
    }
    None
}

fn win32_wstring(val: &str) -> Vec<u16> {
    // Encode string wide and then add null at the end, collect to Vec<u16>
    OsStr::new(val)
        .encode_wide()
        .chain(std::iter::once(0))
        .collect::<Vec<u16>>()
}
