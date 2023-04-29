use std::ptr;
use winapi::um::wincrypt::{
    CryptAcquireContextW, CryptCreateHash, CryptDecrypt, CryptDeriveKey, CryptDestroyHash,
    CryptDestroyKey, CryptHashData, CryptReleaseContext, CALG_AES_256, CALG_SHA_256, HCRYPTHASH,
    HCRYPTKEY, HCRYPTPROV, PROV_RSA_AES,
};

pub fn aes_decrypt(payload: &mut [u8], key: &[u8]) -> i32 {
    // Initialize cryptographic service provider, hash, and key handles.
    let mut h_prov: HCRYPTPROV = 0;
    let mut h_hash: HCRYPTHASH = 0;
    let mut h_key: HCRYPTKEY = 0;
    let mut payload_len = payload.len() as u32;

    // https://docs.microsoft.com/en-us/windows/win32/api/wincrypt/nf-wincrypt-cryptacquirecontextw
    unsafe {
        // Call CryptAcquireContext to get a handle to the default key container.
        if CryptAcquireContextW(
            &mut h_prov,
            ptr::null_mut(),
            ptr::null_mut(),
            PROV_RSA_AES,
            0,
        ) == 0
        {
            return -1;
        }
        // Create an SHA-256 hash object.
        if CryptCreateHash(h_prov, CALG_SHA_256, 0, 0, &mut h_hash) == 0 {
            return -1;
        }
        // Hash the password.
        if CryptHashData(h_hash, key.as_ptr(), key.len() as u32, 0) == 0 {
            return -1;
        }
        // Derive a AES-256 session key from the hash object.
        if CryptDeriveKey(h_prov, CALG_AES_256, h_hash, 0, &mut h_key) == 0 {
            return -1;
        }
        // Decrypt the payload using the key.
        if CryptDecrypt(
            h_key,
            0 as usize,
            0,
            0,
            payload.as_mut_ptr(),
            &mut payload_len,
        ) == 0
        {
            return -1;
        }
        // Destroy the hash object. Clean up :)
        CryptReleaseContext(h_prov, 0);
        CryptDestroyHash(h_hash);
        CryptDestroyKey(h_key);
    }
    // Return the decrypted payload length.
    0
}
