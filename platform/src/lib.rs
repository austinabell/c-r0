use core::ptr::slice_from_raw_parts;
use risc0_binfmt::tagged_struct;
use risc0_zkp::core::digest::Digest;
use risc0_zkp::core::hash::sha::guest::Impl;
use risc0_zkp::core::hash::sha::rust_crypto::{Digest as _, Sha256};
use risc0_zkvm_platform::fileno;
use risc0_zkvm_platform::syscall::{sys_halt, sys_write};

#[repr(C)]
#[derive(Default)]
pub struct CSha256(Sha256<Impl>);

#[no_mangle]
pub extern "C" fn init_sha256() -> *mut CSha256 {
    let struct_instance = CSha256(Sha256::default());
    let b = Box::new(struct_instance);
    Box::into_raw(b)
}

#[no_mangle]
pub unsafe extern "C" fn sha256_update(hasher: *mut CSha256, bytes_ptr: *const u8, len: u32) {
    (&mut (*hasher).0).update(&*slice_from_raw_parts(bytes_ptr, len as usize));
}

#[no_mangle]
pub unsafe extern "C" fn sha256_finalize(hasher: *mut CSha256) -> *mut Digest {
    // Take the hasher to get an owned value. This replaces with a default hasher, as there isn't
    // a clean way to take ownership and force the pointer isn't used after.
    let hasher = core::mem::take(&mut (*hasher).0);
    let b = Box::new(hasher.finalize().as_slice().try_into().unwrap());
    Box::into_raw(b)
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
