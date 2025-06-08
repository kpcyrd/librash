#![allow(clippy::missing_safety_doc)] // for now

use core::ffi::{CStr, c_char, c_uint, c_void};
use core::mem;
use core::ptr;
use core::slice;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::Sha256;

#[derive(Clone, Copy)]
pub enum RashDigest {
    Sha256,
    Sha1,
    Md5,
}

pub const RASH_MAX_DIGEST_SIZE: usize = 64; /* SHA512 */

static SHA256: RashDigest = RashDigest::Sha256;
static SHA1: RashDigest = RashDigest::Sha1;
static MD5: RashDigest = RashDigest::Md5;

#[derive(Default)]
pub enum RashCtx {
    #[default]
    Uninitialized,
    Sha256(Sha256),
    Sha1(Sha1),
    Md5(Md5),
}

/// EVP_get_digestbyname
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digestbyname(name: *const c_char) -> *const RashDigest {
    let name = unsafe { CStr::from_ptr(name) };
    let Ok(digest) = name.to_str() else { return ptr::null() };

    let digest = if digest.eq_ignore_ascii_case("SHA256") {
        SHA256
    } else if digest.eq_ignore_ascii_case("SHA1") {
        SHA1
    } else if digest.eq_ignore_ascii_case("MD5") {
        MD5
    } else {
        return ptr::null();
    };

    &digest as *const RashDigest
}

/// EVP_MD_CTX_new
#[unsafe(no_mangle)]
pub extern "C" fn rash_ctx_new() -> *mut RashCtx {
    let ctx = Box::new(RashCtx::Uninitialized);
    Box::into_raw(ctx)
}

/// EVP_MD_CTX_reset
#[unsafe(no_mangle)]
pub extern "C" fn rash_ctx_reset(ctx: *mut RashCtx) {
    let digest = match unsafe { &mut *ctx } {
        RashCtx::Uninitialized => return,
        RashCtx::Sha256(_sha256) => RashDigest::Sha256,
        RashCtx::Sha1(_sha1) => RashDigest::Sha1,
        RashCtx::Md5(_md5) => RashDigest::Md5,
    };
    unsafe { rash_digest_init(ctx, &digest, ptr::null()) };
}

/// EVP_DigestInit_ex
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_init(
    ctx: *mut RashCtx,
    digest: *const RashDigest,
    _engine: *const c_void,
) {
    let new = match unsafe { *digest } {
        RashDigest::Sha256 => RashCtx::Sha256(Sha256::new()),
        RashDigest::Sha1 => RashCtx::Sha1(Sha1::new()),
        RashDigest::Md5 => RashCtx::Md5(Md5::new()),
    };
    unsafe { *ctx = new };
}

/// EVP_DigestUpdate
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_update(ctx: *mut RashCtx, buf: *const u8, n: usize) {
    let buf = unsafe { slice::from_raw_parts(buf, n) };
    match unsafe { &mut *ctx } {
        RashCtx::Uninitialized => (),
        RashCtx::Sha256(sha256) => sha256.update(buf),
        RashCtx::Sha1(sha1) => sha1.update(buf),
        RashCtx::Md5(md5) => md5.update(buf),
    }
}

/// EVP_DigestFinal_ex
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_final(ctx: *mut RashCtx, output: *mut u8, len: *mut c_uint) {
    let ctx = mem::take(unsafe { &mut *ctx });
    let n = match ctx {
        RashCtx::Uninitialized => 0,
        RashCtx::Sha256(sha256) => {
            let len = Sha256::output_size();
            let output = unsafe { slice::from_raw_parts_mut(output, len) };
            sha256.finalize_into(output.into());
            len
        }
        RashCtx::Sha1(sha1) => {
            let len = Sha1::output_size();
            let output = unsafe { slice::from_raw_parts_mut(output, len) };
            sha1.finalize_into(output.into());
            len
        }
        RashCtx::Md5(md5) => {
            let len = Md5::output_size();
            let output = unsafe { slice::from_raw_parts_mut(output, len) };
            md5.finalize_into(output.into());
            len
        }
    };
    unsafe { *len = n as c_uint };
}

/// EVP_MD_CTX_free
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_ctx_free(ctx: *mut RashCtx) {
    let ctx = unsafe { Box::from_raw(ctx) };
    drop(ctx);
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr;

    #[test]
    fn test_invalid_digest() {
        let digest = unsafe { rash_digestbyname(c"invalid".as_ptr()) };
        assert_eq!(digest, ptr::null());
    }

    #[test]
    fn test_sha256() {
        let digest = unsafe { rash_digestbyname(c"SHA256".as_ptr()) };
        let ctx = rash_ctx_new();
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr(), 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr(), 5) };

        let mut buf = [0u8; 32];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), ptr::null()) };
        assert_eq!(
            &buf,
            b"\xb9\x4d\x27\xb9\x93\x4d\x3e\x08\xa5\x2e\x52\xd7\xda\x7d\xab\xfa\xc4\x84\xef\xe3\x7a\x53\x80\xee\x90\x88\xf7\xac\xe2\xef\xcd\xe9"
        );

        unsafe { rash_ctx_free(ctx) };
    }

    #[test]
    fn test_sha1() {
        let digest = unsafe { rash_digestbyname(c"SHA1".as_ptr()) };
        let ctx = rash_ctx_new();
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr(), 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr(), 5) };

        let mut buf = [0u8; 20];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), ptr::null()) };
        assert_eq!(
            &buf,
            b"\x2a\xae\x6c\x35\xc9\x4f\xcf\xb4\x15\xdb\xe9\x5f\x40\x8b\x9c\xe9\x1e\xe8\x46\xed"
        );

        unsafe { rash_ctx_free(ctx) };
    }

    #[test]
    fn test_md5() {
        let digest = unsafe { rash_digestbyname(c"MD5".as_ptr()) };
        let ctx = rash_ctx_new();
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr(), 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr(), 5) };

        let mut buf = [0u8; 16];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), ptr::null()) };
        assert_eq!(
            &buf,
            b"\x5e\xb6\x3b\xbb\xe0\x1e\xee\xd0\x93\xcb\x22\xbb\x8f\x5a\xcd\xc3"
        );

        unsafe { rash_ctx_free(ctx) };
    }
}
