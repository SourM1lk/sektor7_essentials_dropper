use std::ffi::CString;
use winapi::{
    shared::minwindef::{DWORD, FALSE},
    um::{
        handleapi::INVALID_HANDLE_VALUE,
        tlhelp32::{
            CreateToolhelp32Snapshot, Process32First, Process32Next, PROCESSENTRY32,
            TH32CS_SNAPPROCESS,
        },
        winbase::lstrcmpiA,
    },
};

// Find target process
pub fn find_target(procname: &str) -> DWORD {
    // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/ns-tlhelp32-processentry32
    let mut pe32 = PROCESSENTRY32 {
        dwSize: std::mem::size_of::<PROCESSENTRY32>() as DWORD,
        cntUsage: 0,
        th32ProcessID: 0,
        th32DefaultHeapID: 0,
        th32ModuleID: 0,
        cntThreads: 0,
        th32ParentProcessID: 0,
        pcPriClassBase: 0,
        dwFlags: 0,
        szExeFile: [0; 260],
    };
    // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-createtoolhelp32snapshot
    // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32first
    // https://docs.microsoft.com/en-us/windows/win32/api/tlhelp32/nf-tlhelp32-process32next
    // procname_cstring.as_ptr() is a pointer to the first element of the array
    let procname_cstring = CString::new(procname).unwrap();
    // h_proc_snap is a handle to the snapshot
    let h_proc_snap = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0) };
    // h_proc_snap is INVALID_HANDLE_VALUE if CreateToolhelp32Snapshot fails
    if h_proc_snap == INVALID_HANDLE_VALUE {
        return 0;
    }
    // Return 0 if Process32First fails
    if unsafe { Process32First(h_proc_snap, &mut pe32) } == FALSE {
        return 0;
    }
    // Return pe32.th32ProcessID if procname matches pe32.szExeFile
    while unsafe { Process32Next(h_proc_snap, &mut pe32) } != FALSE {
        if unsafe { lstrcmpiA(procname_cstring.as_ptr(), pe32.szExeFile.as_ptr()) } == 0 {
            return pe32.th32ProcessID;
        }
    }

    0
}
