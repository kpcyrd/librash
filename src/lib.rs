#![allow(clippy::missing_safety_doc)] // for now

use core::ffi::{CStr, c_char, c_int, c_uint, c_void};
use core::mem;
use core::ptr;
use core::slice;
use digest::Digest;
use md5::Md5;
use sha1::Sha1;
use sha2::{Sha256, Sha512};

#[derive(Clone, Copy)]
pub enum RashDigest {
    Sha256,
    Sha512,
    Sha1,
    Md5,
}

pub const RASH_MAX_DIGEST_SIZE: usize = 64; /* SHA512 */

static SHA256: RashDigest = RashDigest::Sha256;
static SHA512: RashDigest = RashDigest::Sha512;
static SHA1: RashDigest = RashDigest::Sha1;
static MD5: RashDigest = RashDigest::Md5;

#[derive(Default)]
pub enum RashCtx {
    #[default]
    Uninitialized,
    Sha256(Sha256),
    Sha512(Sha512),
    Sha1(Sha1),
    Md5(Md5),
}

impl From<RashDigest> for RashCtx {
    fn from(digest: RashDigest) -> Self {
        match digest {
            RashDigest::Sha256 => RashCtx::Sha256(Sha256::new()),
            RashDigest::Sha512 => RashCtx::Sha512(Sha512::new()),
            RashDigest::Sha1 => RashCtx::Sha1(Sha1::new()),
            RashDigest::Md5 => RashCtx::Md5(Md5::new()),
        }
    }
}

/// EVP_get_digestbyname
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digestbyname(name: *const c_char) -> *const RashDigest {
    let name = unsafe { CStr::from_ptr(name) };
    let Ok(digest) = name.to_str() else {
        return ptr::null();
    };

    let digest: &'static RashDigest = if digest.eq_ignore_ascii_case("SHA256") {
        &SHA256
    } else if digest.eq_ignore_ascii_case("SHA512") {
        &SHA512
    } else if digest.eq_ignore_ascii_case("SHA1") {
        &SHA1
    } else if digest.eq_ignore_ascii_case("MD5") {
        &MD5
    } else {
        return ptr::null();
    };

    digest as *const RashDigest
}

/// EVP_MD_CTX_new
#[unsafe(no_mangle)]
pub extern "C" fn rash_ctx_new() -> *mut RashCtx {
    let ctx = Box::new(RashCtx::Uninitialized);
    Box::into_raw(ctx)
}

/// EVP_MD_CTX_reset
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_ctx_reset(ctx: *mut RashCtx) {
    unsafe { *ctx = RashCtx::Uninitialized };
}

/// EVP_DigestInit_ex
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_init(
    ctx: *mut RashCtx,
    digest: *const RashDigest,
    _engine: *const c_void,
) -> c_int {
    let new = RashCtx::from(unsafe { *digest });
    unsafe { *ctx = new };
    1
}

/// EVP_DigestInit_ex2
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_init2(
    ctx: *mut RashCtx,
    digest: *const RashDigest,
    _params: *const c_void,
) -> c_int {
    let digest = if let Some(digest) = unsafe { digest.as_ref() } {
        *digest
    } else {
        match unsafe { &*ctx } {
            RashCtx::Uninitialized => return 0,
            RashCtx::Sha256(_sha256) => RashDigest::Sha256,
            RashCtx::Sha512(_sha512) => RashDigest::Sha512,
            RashCtx::Sha1(_sha1) => RashDigest::Sha1,
            RashCtx::Md5(_md5) => RashDigest::Md5,
        }
    };

    let new = RashCtx::from(digest);
    unsafe { *ctx = new };
    1
}

/// EVP_DigestUpdate
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_update(
    ctx: *mut RashCtx,
    buf: *const c_char,
    n: usize,
) -> c_int {
    let buf = unsafe { slice::from_raw_parts(buf as *const u8, n) };
    match unsafe { &mut *ctx } {
        RashCtx::Uninitialized => return 0,
        RashCtx::Sha256(sha256) => sha256.update(buf),
        RashCtx::Sha512(sha512) => sha512.update(buf),
        RashCtx::Sha1(sha1) => sha1.update(buf),
        RashCtx::Md5(md5) => md5.update(buf),
    }
    1
}

/// EVP_DigestFinal_ex
#[unsafe(no_mangle)]
pub unsafe extern "C" fn rash_digest_final(
    ctx: *mut RashCtx,
    output: *mut u8,
    len: *mut c_uint,
) -> c_int {
    let ctx = mem::take(unsafe { &mut *ctx });
    let n = match ctx {
        RashCtx::Uninitialized => return 0,
        RashCtx::Sha256(sha256) => {
            let len = Sha256::output_size();
            let output = unsafe { slice::from_raw_parts_mut(output, len) };
            sha256.finalize_into(output.into());
            len
        }
        RashCtx::Sha512(sha512) => {
            let len = Sha512::output_size();
            let output = unsafe { slice::from_raw_parts_mut(output, len) };
            sha512.finalize_into(output.into());
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
    1
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
        assert!(!digest.is_null());
        let ctx = rash_ctx_new();
        assert!(!ctx.is_null());
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr() as *const c_char, 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr() as *const c_char, 5) };

        let mut len = 0u32;
        let mut buf = [0u8; 32];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), &mut len as *mut u32) };
        assert_eq!(len, 32);
        assert_eq!(
            &buf,
            b"\xb9\x4d\x27\xb9\x93\x4d\x3e\x08\xa5\x2e\x52\xd7\xda\x7d\xab\xfa\xc4\x84\xef\xe3\x7a\x53\x80\xee\x90\x88\xf7\xac\xe2\xef\xcd\xe9"
        );

        unsafe { rash_ctx_free(ctx) };
    }

    #[test]
    fn test_sha512() {
        let digest = unsafe { rash_digestbyname(c"sha512".as_ptr()) };
        assert!(!digest.is_null());
        let ctx = rash_ctx_new();
        assert!(!ctx.is_null());
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr() as *const c_char, 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr() as *const c_char, 5) };

        let mut len = 0u32;
        let mut buf = [0u8; 64];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), &mut len as *mut u32) };
        assert_eq!(len, 64);
        assert_eq!(
            &buf,
            b"\x30\x9e\xcc\x48\x9c\x12\xd6\xeb\x4c\xc4\x0f\x50\xc9\x02\xf2\xb4\xd0\xed\x77\xee\x51\x1a\x7c\x7a\x9b\xcd\x3c\xa8\x6d\x4c\xd8\x6f\x98\x9d\xd3\x5b\xc5\xff\x49\x96\x70\xda\x34\x25\x5b\x45\xb0\xcf\xd8\x30\xe8\x1f\x60\x5d\xcf\x7d\xc5\x54\x2e\x93\xae\x9c\xd7\x6f"
        );

        unsafe { rash_ctx_free(ctx) };
    }

    #[test]
    fn test_sha1() {
        let digest = unsafe { rash_digestbyname(c"SHA1".as_ptr()) };
        assert!(!digest.is_null());
        let ctx = rash_ctx_new();
        assert!(!ctx.is_null());
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr() as *const c_char, 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr() as *const c_char, 5) };

        let mut len = 0u32;
        let mut buf = [0u8; 20];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), &mut len as *mut u32) };
        assert_eq!(len, 20);
        assert_eq!(
            &buf,
            b"\x2a\xae\x6c\x35\xc9\x4f\xcf\xb4\x15\xdb\xe9\x5f\x40\x8b\x9c\xe9\x1e\xe8\x46\xed"
        );

        unsafe { rash_ctx_free(ctx) };
    }

    #[test]
    fn test_md5() {
        let digest = unsafe { rash_digestbyname(c"MD5".as_ptr()) };
        assert!(!digest.is_null());
        let ctx = rash_ctx_new();
        assert!(!ctx.is_null());
        unsafe { rash_digest_init(ctx, digest, ptr::null()) };
        unsafe { rash_digest_update(ctx, b"hello ".as_ptr() as *const c_char, 6) };
        unsafe { rash_digest_update(ctx, b"world".as_ptr() as *const c_char, 5) };

        let mut len = 0u32;
        let mut buf = [0u8; 16];
        unsafe { rash_digest_final(ctx, buf.as_mut_ptr(), &mut len as *mut u32) };
        assert_eq!(len, 16);
        assert_eq!(
            &buf,
            b"\x5e\xb6\x3b\xbb\xe0\x1e\xee\xd0\x93\xcb\x22\xbb\x8f\x5a\xcd\xc3"
        );

        unsafe { rash_ctx_free(ctx) };
    }
}
