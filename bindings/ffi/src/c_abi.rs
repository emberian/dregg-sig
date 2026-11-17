//! The `extern "C"` surface.
//!
//! Rules this layer keeps, without exception:
//!
//! * the caller owns every buffer; nothing here allocates on the caller's behalf;
//! * every length is explicit, and an output's required length is reported back once the
//!   call reaches the copy, so a short buffer can be retried;
//! * output buffers must not overlap any input buffer or each other;
//! * failure is an integer code, never a string and never a panic;
//! * `catch_unwind` wraps every entry point, so no unwind crosses the boundary;
//! * secret material is wiped: the caller's secret-key output on every error path, and every
//!   copy this crate makes when it drops.

use core::ffi::{c_char, c_int};
use core::panic::AssertUnwindSafe;
use core::ptr;
use core::slice;

use crate::api;

/// Success.
pub const DREGG_SIG_OK: c_int = api::OK;
/// A required pointer argument was null.
pub const DREGG_SIG_ERR_NULL_POINTER: c_int = api::ERR_NULL_POINTER;
/// The caller's output buffer was too small.
pub const DREGG_SIG_ERR_BUFFER_TOO_SMALL: c_int = api::ERR_BUFFER_TOO_SMALL;
/// Unknown parameter-set identifier.
pub const DREGG_SIG_ERR_INVALID_PARAM: c_int = api::ERR_INVALID_PARAM;
/// Wrong key, signature or seed length.
pub const DREGG_SIG_ERR_INVALID_LENGTH: c_int = api::ERR_INVALID_LENGTH;
/// Context string longer than 255 bytes.
pub const DREGG_SIG_ERR_CONTEXT_TOO_LONG: c_int = api::ERR_CONTEXT_TOO_LONG;
/// The signature did not verify.
pub const DREGG_SIG_ERR_VERIFY_FAILED: c_int = api::ERR_VERIFY_FAILED;
/// A panic was caught at the boundary.
pub const DREGG_SIG_ERR_PANIC: c_int = api::ERR_PANIC;
/// Unexpected internal failure.
pub const DREGG_SIG_ERR_INTERNAL: c_int = api::ERR_INTERNAL;

/// Parameter-set identifiers.
pub const DREGG_SIG_PARAM_128S: u32 = api::PARAM_128S;
pub const DREGG_SIG_PARAM_128F: u32 = api::PARAM_128F;
pub const DREGG_SIG_PARAM_192S: u32 = api::PARAM_192S;
pub const DREGG_SIG_PARAM_192F: u32 = api::PARAM_192F;
pub const DREGG_SIG_PARAM_256S: u32 = api::PARAM_256S;
pub const DREGG_SIG_PARAM_256F: u32 = api::PARAM_256F;

// The size bounds are compile-time constants in the generated header, not exported symbols:
// a C caller sizes a buffer at compile time, and a `static` of the same name would collide
// with the macro. `dregg_sig_pk_bytes` and friends answer the same question at run time.

/// Run `f`, turning a panic into [`DREGG_SIG_ERR_PANIC`].
fn guard<F: FnOnce() -> c_int>(f: F) -> c_int {
    match std::panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(code) => code,
        Err(_) => DREGG_SIG_ERR_PANIC,
    }
}

/// Build a slice from a pointer and length, refusing a null pointer with a nonzero length.
///
/// # Safety
/// `ptr` must be null, or valid for reads of `len` bytes for the duration of the call.
unsafe fn input<'a>(ptr: *const u8, len: usize) -> Option<&'a [u8]> {
    if len == 0 {
        return Some(&[]);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts(ptr, len) })
}

/// Build a mutable slice from a pointer and length, refusing a null pointer with a nonzero length.
///
/// # Safety
/// `ptr` must be null, or valid for writes of `len` bytes for the duration of the call.
unsafe fn output<'a>(ptr: *mut u8, len: usize) -> Option<&'a mut [u8]> {
    if len == 0 {
        return Some(&mut []);
    }
    if ptr.is_null() {
        return None;
    }
    Some(unsafe { slice::from_raw_parts_mut(ptr, len) })
}

/// Copy `src` into the caller's buffer, reporting the required length when it does not fit.
///
/// # Safety
/// `out` must be null or valid for writes of `out_len` bytes; `written` must be null or valid
/// for a write of one `usize`.
unsafe fn emit(src: &[u8], out: *mut u8, out_len: usize, written: *mut usize) -> c_int {
    if !written.is_null() {
        unsafe { ptr::write(written, src.len()) };
    }
    let Some(dst) = (unsafe { output(out, out_len) }) else {
        return DREGG_SIG_ERR_NULL_POINTER;
    };
    if dst.len() < src.len() {
        return DREGG_SIG_ERR_BUFFER_TOO_SMALL;
    }
    dst[..src.len()].copy_from_slice(src);
    DREGG_SIG_OK
}

/// Public key length for a parameter set, or `0` for an unknown identifier.
#[no_mangle]
pub extern "C" fn dregg_sig_pk_bytes(param: u32) -> usize {
    api::pk_bytes(param).unwrap_or(0)
}

/// Secret key length for a parameter set, or `0` for an unknown identifier.
#[no_mangle]
pub extern "C" fn dregg_sig_sk_bytes(param: u32) -> usize {
    api::sk_bytes(param).unwrap_or(0)
}

/// Signature length for a parameter set, or `0` for an unknown identifier.
#[no_mangle]
pub extern "C" fn dregg_sig_sig_bytes(param: u32) -> usize {
    api::sig_bytes(param).unwrap_or(0)
}

/// A static, NUL-terminated description of an error code. Never allocates.
#[no_mangle]
pub extern "C" fn dregg_sig_strerror(code: c_int) -> *const c_char {
    let s: &'static [u8] = match code {
        DREGG_SIG_OK => b"ok\0",
        DREGG_SIG_ERR_NULL_POINTER => b"null pointer argument\0",
        DREGG_SIG_ERR_BUFFER_TOO_SMALL => b"output buffer too small\0",
        DREGG_SIG_ERR_INVALID_PARAM => b"unknown parameter set\0",
        DREGG_SIG_ERR_INVALID_LENGTH => b"wrong key, signature or seed length\0",
        DREGG_SIG_ERR_CONTEXT_TOO_LONG => b"context string longer than 255 bytes\0",
        DREGG_SIG_ERR_VERIFY_FAILED => b"signature did not verify\0",
        DREGG_SIG_ERR_PANIC => b"panic caught at the FFI boundary\0",
        _ => b"internal error\0",
    };
    s.as_ptr() as *const c_char
}

/// Overwrite `len` bytes at `buf` with zeros.
///
/// # Safety
/// `buf` must be null or valid for writes of `len` bytes.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_wipe(buf: *mut u8, len: usize) {
    let _ = guard(|| {
        if let Some(s) = unsafe { output(buf, len) } {
            api::wipe(s);
        }
        DREGG_SIG_OK
    });
}

/// Generate a keypair from explicit `(SK.seed, SK.prf, PK.seed)` components.
///
/// Writes `4*n` secret-key bytes and `2*n` public-key bytes. On any error, including a
/// public-key buffer that is too small, the secret-key output buffer is wiped before returning.
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_keygen(
    param: u32,
    sk_seed: *const u8,
    sk_seed_len: usize,
    sk_prf: *const u8,
    sk_prf_len: usize,
    pk_seed: *const u8,
    pk_seed_len: usize,
    sk_out: *mut u8,
    sk_out_len: usize,
    sk_written: *mut usize,
    pk_out: *mut u8,
    pk_out_len: usize,
    pk_written: *mut usize,
) -> c_int {
    guard(|| {
        let (Some(a), Some(b), Some(c)) = (
            unsafe { input(sk_seed, sk_seed_len) },
            unsafe { input(sk_prf, sk_prf_len) },
            unsafe { input(pk_seed, pk_seed_len) },
        ) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        match api::keygen(param, a, b, c) {
            Ok((sk, pk)) => {
                let rc = unsafe { emit(&sk, sk_out, sk_out_len, sk_written) };
                if rc != DREGG_SIG_OK {
                    if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                        api::wipe(dst);
                    }
                    return rc;
                }
                let rc = unsafe { emit(&pk, pk_out, pk_out_len, pk_written) };
                if rc != DREGG_SIG_OK {
                    // The secret key is already in the caller's buffer; a failed call must
                    // not leave it there.
                    if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                        api::wipe(dst);
                    }
                }
                rc
            }
            Err(code) => {
                if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                    api::wipe(dst);
                }
                code
            }
        }
    })
}

/// Generate a keypair from one master seed.
///
/// On any error, including a public-key buffer that is too small, the secret-key output
/// buffer is wiped before returning.
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_keygen_from_seed(
    param: u32,
    seed: *const u8,
    seed_len: usize,
    sk_out: *mut u8,
    sk_out_len: usize,
    sk_written: *mut usize,
    pk_out: *mut u8,
    pk_out_len: usize,
    pk_written: *mut usize,
) -> c_int {
    guard(|| {
        let Some(seed) = (unsafe { input(seed, seed_len) }) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        match api::keygen_from_seed(param, seed) {
            Ok((sk, pk)) => {
                let rc = unsafe { emit(&sk, sk_out, sk_out_len, sk_written) };
                if rc != DREGG_SIG_OK {
                    if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                        api::wipe(dst);
                    }
                    return rc;
                }
                let rc = unsafe { emit(&pk, pk_out, pk_out_len, pk_written) };
                if rc != DREGG_SIG_OK {
                    // The secret key is already in the caller's buffer; a failed call must
                    // not leave it there.
                    if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                        api::wipe(dst);
                    }
                }
                rc
            }
            Err(code) => {
                if let Some(dst) = unsafe { output(sk_out, sk_out_len) } {
                    api::wipe(dst);
                }
                code
            }
        }
    })
}

/// Derive the public key from a canonical secret key.
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_pk_from_sk(
    param: u32,
    sk: *const u8,
    sk_len: usize,
    pk_out: *mut u8,
    pk_out_len: usize,
    pk_written: *mut usize,
) -> c_int {
    guard(|| {
        let Some(sk) = (unsafe { input(sk, sk_len) }) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        match api::pk_from_sk(param, sk) {
            Ok(pk) => unsafe { emit(&pk, pk_out, pk_out_len, pk_written) },
            Err(code) => code,
        }
    })
}

/// Sign `msg` under `ctx` (pure SLH-DSA, deterministic).
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_sign(
    param: u32,
    sk: *const u8,
    sk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig_out: *mut u8,
    sig_out_len: usize,
    sig_written: *mut usize,
) -> c_int {
    guard(|| {
        let (Some(sk), Some(msg), Some(ctx)) = (
            unsafe { input(sk, sk_len) },
            unsafe { input(msg, msg_len) },
            unsafe { input(ctx, ctx_len) },
        ) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        match api::sign(param, sk, msg, ctx) {
            Ok(sig) => unsafe { emit(&sig, sig_out, sig_out_len, sig_written) },
            Err(code) => code,
        }
    })
}

/// SHAKE256 with a 32-byte output, written to `out`.
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_shake256_32(
    data: *const u8,
    data_len: usize,
    out: *mut u8,
    out_len: usize,
    written: *mut usize,
) -> c_int {
    guard(|| {
        let Some(data) = (unsafe { input(data, data_len) }) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        let digest = api::shake256_32(data);
        unsafe { emit(&digest, out, out_len, written) }
    })
}

/// Verify a signature. Returns [`DREGG_SIG_OK`] when it verifies and
/// [`DREGG_SIG_ERR_VERIFY_FAILED`] when it does not.
///
/// # Safety
/// Every pointer must be null or valid for the length given beside it.
#[no_mangle]
pub unsafe extern "C" fn dregg_sig_verify(
    param: u32,
    pk: *const u8,
    pk_len: usize,
    msg: *const u8,
    msg_len: usize,
    ctx: *const u8,
    ctx_len: usize,
    sig: *const u8,
    sig_len: usize,
) -> c_int {
    guard(|| {
        let (Some(pk), Some(msg), Some(ctx), Some(sig)) = (
            unsafe { input(pk, pk_len) },
            unsafe { input(msg, msg_len) },
            unsafe { input(ctx, ctx_len) },
            unsafe { input(sig, sig_len) },
        ) else {
            return DREGG_SIG_ERR_NULL_POINTER;
        };
        match api::verify(param, pk, msg, ctx, sig) {
            Ok(true) => DREGG_SIG_OK,
            Ok(false) => DREGG_SIG_ERR_VERIFY_FAILED,
            Err(code) => code,
        }
    })
}
