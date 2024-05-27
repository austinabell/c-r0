use core::{ptr, slice};
use risc0_binfmt::tagged_struct;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::hash::sha::guest::Impl;
use risc0_zkp::core::hash::sha::rust_crypto::{Digest as _, Sha256};
use risc0_zkvm_platform::fileno;
use risc0_zkvm_platform::syscall::{sys_halt, sys_write};

use risc0_zkvm_platform;

/// C wrapper for guest sha256 implementation. 
/// 
/// This is used in the guest to generate any sha256
/// hash, but also to accumulate the Sha256 state of all data written to journal through
/// [commit].
/// 
/// Initialize with [init_sha256], and can retrieve the final hash through [sha256_finalize],
/// or pass it into [zkvm_exit] to exit the program.
#[repr(C)]
pub struct CSha256 {
    inner: *mut Sha256<Impl>,
}

impl CSha256 {
    fn new() -> Self {
        CSha256 {
            inner: Box::into_raw(Box::new(Sha256::new())),
        }
    }

    fn update(&mut self, data: &[u8]) {
        unsafe {
            (*self.inner).update(data);
        }
    }

    fn finalize(&mut self) -> Box<Digest> {
        unsafe {
            let hasher = Box::from_raw(self.inner);
            let result = hasher.finalize();
            self.inner = core::ptr::null_mut(); // Prevent double free
            let arr: [u8; 32] = result.into();
            Box::new(arr.into())
        }
    }
}

#[no_mangle]
pub extern "C" fn init_sha256() -> *mut CSha256 {
    let hasher = Box::new(CSha256::new());
    Box::into_raw(hasher)
}

#[no_mangle]
pub unsafe extern "C" fn sha256_update(hasher: *mut CSha256, data: *const u8, len: u32) {
    if hasher.is_null() || data.is_null() {
        return;
    }
    let data_slice = slice::from_raw_parts(data, len as usize);
    (*hasher).update(data_slice);
}

#[no_mangle]
pub unsafe extern "C" fn sha256_finalize(hasher: *mut CSha256) -> *mut Digest {
    if hasher.is_null() {
        return ptr::null_mut();
    }

    let boxed_result = (*hasher).finalize();
    Box::into_raw(boxed_result)
}

#[no_mangle]
pub unsafe extern "C" fn sha256_free(hasher: *mut CSha256) {
    if !hasher.is_null() {
        drop(Box::from_raw(hasher));
    }
}

#[no_mangle]
pub unsafe extern "C" fn zkvm_exit(hasher: *mut CSha256, exit_code: u8) -> ! {
    let journal_digest = sha256_finalize(hasher);
    let output_words: [u32; 8] =
        tagged_struct::<Impl>("risc0.output", &[&*journal_digest, &Digest::ZERO], &[]).into();
    sys_halt(exit_code, &output_words)
}

#[no_mangle]
pub unsafe extern "C" fn commit(hasher: *mut CSha256, bytes_ptr: *const u8, len: u32) {
    sha256_update(hasher, bytes_ptr, len);
    sys_write(fileno::JOURNAL, bytes_ptr, len as usize);
}
