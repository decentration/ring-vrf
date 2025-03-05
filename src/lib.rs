use std::ffi::{CStr};
use std::os::raw::{c_char, c_int, c_uchar};
use std::ptr;

mod ring_vrf_api;
use ring_vrf_api::*;
use libc;

/// Return pointer to aggregator bytes. Freed with ring_vrf_ffi_free.
#[no_mangle]
pub extern "C" fn ring_vrf_ffi_aggregator(
    keys_str: *const c_char,
    ring_size: c_int,
    srs_path: *const c_char,
    out_len: *mut c_int
) -> *mut c_uchar {
    if keys_str.is_null() || srs_path.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }
    let keys_cstr = unsafe { CStr::from_ptr(keys_str) }.to_str().unwrap();
    let srs_cstr = unsafe { CStr::from_ptr(srs_path) }.to_str().unwrap();

    // Suppose keys_str is space-separated hex pubkeys
    let splitted: Vec<&str> = keys_cstr.split_whitespace().collect();
    eprintln!("ENTER ring_vrf_ffi_aggregator");

     // Convert to owned Strings so we can pad if needed
     let mut all_keys: Vec<String> = splitted.iter().map(|s| s.to_string()).collect();

     // Pad so we end up with ring_size, and then we will convert to the bandersnatch padding point in parse_public
     let needed = ring_size as usize;
     if all_keys.len() < needed {
         eprintln!("  We have only {} keys, but ring_size={} => padding with zero hex", all_keys.len(), needed);
         while all_keys.len() < needed {
             all_keys.push("0000000000000000000000000000000000000000000000000000000000000000".to_string());
         }
         eprintln!("  We have only {} keys, but ring_size={} => padding with zero hex", all_keys.len(), needed);

     } else if all_keys.len() > needed {
         eprintln!("  We have {} keys but ring_size={} => truncating extras", all_keys.len(), needed);
         all_keys.truncate(needed);
     }
    eprintln!("  all_keys.len() = {}", all_keys.len());
    let aggregator = ring_vrf_produce_aggregator(&splitted, ring_size as usize, srs_cstr);
    eprintln!("aggregator.len() = {}", aggregator.len());

    // allocate
    let len = aggregator.len();
    unsafe { *out_len = len as c_int };
    let buf_ptr = unsafe { libc::malloc(len) as *mut c_uchar };
    if buf_ptr.is_null() {
        eprintln!("malloc returned null!");
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(aggregator.as_ptr(), buf_ptr, len);
    }
    eprintln!("EXIT aggregator, returning ptr: {:p}", buf_ptr);

    buf_ptr
}

/// Produce ring VRF signature
/// Return pointer to signature bytes. Freed with ring_vrf_ffi_free.
#[no_mangle]
pub extern "C" fn ring_vrf_ffi_sign(
    secret_hex: *const c_char,
    keys_str: *const c_char,
    ring_size: c_int,
    srs_path: *const c_char,
    input_data_ptr: *const c_uchar,
    input_len: c_int,
    aux_data_ptr: *const c_uchar,
    aux_len: c_int,
    signer_idx: c_int,
    out_len: *mut c_int
) -> *mut c_uchar {
    if secret_hex.is_null() || keys_str.is_null() || srs_path.is_null() ||
       input_data_ptr.is_null() || aux_data_ptr.is_null() || out_len.is_null() {
        return ptr::null_mut();
    }

    let secret_str = unsafe { CStr::from_ptr(secret_hex) }.to_str().unwrap();
    let keys_cstr = unsafe { CStr::from_ptr(keys_str) }.to_str().unwrap();
    let splitted: Vec<&str> = keys_cstr.split_whitespace().collect();

    let srs_cstr = unsafe { CStr::from_ptr(srs_path) }.to_str().unwrap();

    let input_data = unsafe { std::slice::from_raw_parts(input_data_ptr, input_len as usize) };
    let aux_data = unsafe { std::slice::from_raw_parts(aux_data_ptr, aux_len as usize) };

    let sig_bytes = ring_vrf_sign(
        secret_str,
        &splitted,
        ring_size as usize,
        srs_cstr,
        input_data,
        aux_data,
        signer_idx as usize
    );

    let len = sig_bytes.len();
    unsafe { *out_len = len as c_int };
    let buf_ptr = unsafe { libc::malloc(len) as *mut c_uchar };
    if buf_ptr.is_null() {
        return ptr::null_mut();
    }
    unsafe {
        ptr::copy_nonoverlapping(sig_bytes.as_ptr(), buf_ptr, len);
    }
    buf_ptr
}

/// Verify ring VRF signature. Return 0 if fail, 1 if success. If success, copy 32 bytes of VRF output into out_ptr
#[no_mangle]
pub extern "C" fn ring_vrf_ffi_verify(
    keys_str: *const c_char,
    ring_size: c_int,
    srs_path: *const c_char,
    input_data_ptr: *const c_uchar,
    input_len: c_int,
    aux_data_ptr: *const c_uchar,
    aux_len: c_int,
    sig_ptr: *const c_uchar,
    sig_len: c_int,
    out_vrf: *mut c_uchar
) -> c_int {
    if keys_str.is_null() || srs_path.is_null() ||
       input_data_ptr.is_null() || aux_data_ptr.is_null() ||
       sig_ptr.is_null() || out_vrf.is_null() {
        return 0;
    }

    let keys_cstr = unsafe { CStr::from_ptr(keys_str) }.to_str().unwrap();
    let splitted: Vec<&str> = keys_cstr.split_whitespace().collect();
    let srs_cstr = unsafe { CStr::from_ptr(srs_path) }.to_str().unwrap();

    let input_data = unsafe { std::slice::from_raw_parts(input_data_ptr, input_len as usize) };
    let aux_data = unsafe { std::slice::from_raw_parts(aux_data_ptr, aux_len as usize) };
    let sig_bytes = unsafe { std::slice::from_raw_parts(sig_ptr, sig_len as usize) };

    match ring_vrf_verify(
        &splitted,
        ring_size as usize,
        srs_cstr,
        input_data,
        aux_data,
        sig_bytes
    ) {
        Ok(vrf_out_32) => {
            // copy to out_vrf
            unsafe {
                ptr::copy_nonoverlapping(vrf_out_32.as_ptr(), out_vrf, 32);
            }
            1
        }
        Err(_) => 0
    }
}


#[no_mangle]
pub extern "C" fn ring_vrf_ffi_aggregator_test(
    _keys_str: *const c_char,
    _ring_size: c_int,
    _srs_path: *const c_char,
    out_len: *mut c_int
) -> *mut c_uchar {
    // Hard-code 4 bytes for a minimal test
    let bytes = [0xde, 0xad, 0xbe, 0xef];
    let len = bytes.len();

    unsafe {
        if !out_len.is_null() {
            *out_len = len as c_int;
        }
    }

    // Allocate 4 bytes with malloc
    let ptr = unsafe { libc::malloc(len) } as *mut c_uchar;
    if ptr.is_null() {
        return ptr::null_mut();
    }

    // Copy the 4 bytes
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), ptr, len);
    }

    // Return pointer
    ptr
}


/// Free pointer from ring_vrf_ffi_aggregator or ring_vrf_ffi_sign
#[no_mangle]
pub extern "C" fn ring_vrf_ffi_free(ptr: *mut c_uchar, _len: c_int) {
    if ptr.is_null() {
        return;
    }
    unsafe {
        libc::free(ptr as *mut libc::c_void);
    }
}

