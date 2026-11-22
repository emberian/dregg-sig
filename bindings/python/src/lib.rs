//! Python bindings for the stateless FIPS 205 SLH-DSA surface of `dregg-sig-core`.
//!
//! Bytes in, bytes out. Every function takes and returns `bytes`; there is no object graph to
//! keep in sync with the Rust side, and no state to leak between calls.
//!
//! Every copy of a secret key or seed this module makes on the Rust side is wiped when it
//! drops. The `bytes` objects handed back to Python are immutable and live in the Python heap
//! until collected; nothing here can wipe them, and a caller who needs that must not hold
//! secret keys as Python `bytes`.
//!
//! The GIL is released for the whole of `keygen`, `keygen_from_seed` and `sign`. Those are the
//! expensive calls (a 128f signature is tens of milliseconds of hashing), and a Python caller
//! must not block other threads while one runs. `verify` is cheap by comparison but is released
//! too, for the same reason: it is pure computation over owned buffers.

use pyo3::exceptions::{PyBufferError, PyValueError};
use pyo3::prelude::*;
use pyo3::types::PyBytes;

use dregg_sig_ffi::api;

fn err(code: i32) -> PyErr {
    let msg = match code {
        api::ERR_NULL_POINTER => "null pointer argument".to_string(),
        api::ERR_BUFFER_TOO_SMALL => "output buffer too small".to_string(),
        api::ERR_INVALID_PARAM => "unknown parameter set".to_string(),
        api::ERR_INVALID_LENGTH => "wrong key, signature or seed length".to_string(),
        api::ERR_CONTEXT_TOO_LONG => "context string longer than 255 bytes".to_string(),
        api::ERR_VERIFY_FAILED => "signature did not verify".to_string(),
        api::ERR_PANIC => "panic caught at the binding boundary".to_string(),
        other => format!("internal error ({other})"),
    };
    if code == api::ERR_BUFFER_TOO_SMALL {
        PyBufferError::new_err(msg)
    } else {
        PyValueError::new_err(msg)
    }
}

fn param_id(name: &str) -> PyResult<u32> {
    match name {
        "128s" | "SLH-DSA-SHAKE-128s" => Ok(api::PARAM_128S),
        "128f" | "SLH-DSA-SHAKE-128f" => Ok(api::PARAM_128F),
        "192s" | "SLH-DSA-SHAKE-192s" => Ok(api::PARAM_192S),
        "192f" | "SLH-DSA-SHAKE-192f" => Ok(api::PARAM_192F),
        "256s" | "SLH-DSA-SHAKE-256s" => Ok(api::PARAM_256S),
        "256f" | "SLH-DSA-SHAKE-256f" => Ok(api::PARAM_256F),
        other => Err(PyValueError::new_err(format!(
            "unknown parameter set {other:?}; expected one of 128s, 128f, 192s, 192f, 256s, 256f"
        ))),
    }
}

/// Exact public-key length in bytes for a parameter set.
#[pyfunction]
fn pk_bytes(param: &str) -> PyResult<usize> {
    api::pk_bytes(param_id(param)?).ok_or_else(|| err(api::ERR_INVALID_PARAM))
}

/// Exact secret-key length in bytes for a parameter set.
#[pyfunction]
fn sk_bytes(param: &str) -> PyResult<usize> {
    api::sk_bytes(param_id(param)?).ok_or_else(|| err(api::ERR_INVALID_PARAM))
}

/// Exact signature length in bytes for a parameter set.
#[pyfunction]
fn sig_bytes(param: &str) -> PyResult<usize> {
    api::sig_bytes(param_id(param)?).ok_or_else(|| err(api::ERR_INVALID_PARAM))
}

/// Generate a keypair from explicit `(sk_seed, sk_prf, pk_seed)` components.
///
/// Returns `(secret_key, public_key)`. The GIL is released for the whole call.
#[pyfunction]
fn keygen<'py>(
    py: Python<'py>,
    param: &str,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let id = param_id(param)?;
    let sk_seed = api::SecretBytes::copy_from(sk_seed);
    let sk_prf = api::SecretBytes::copy_from(sk_prf);
    let pk_seed = pk_seed.to_vec();
    let (sk, pk) = py
        .detach(move || api::keygen(id, &sk_seed, &sk_prf, &pk_seed))
        .map_err(err)?;
    Ok((PyBytes::new(py, &sk), PyBytes::new(py, &pk)))
}

/// Generate a keypair from one master seed. The GIL is released for the whole call.
#[pyfunction]
fn keygen_from_seed<'py>(
    py: Python<'py>,
    param: &str,
    seed: &[u8],
) -> PyResult<(Bound<'py, PyBytes>, Bound<'py, PyBytes>)> {
    let id = param_id(param)?;
    let seed = api::SecretBytes::copy_from(seed);
    let (sk, pk) = py
        .detach(move || api::keygen_from_seed(id, &seed))
        .map_err(err)?;
    Ok((PyBytes::new(py, &sk), PyBytes::new(py, &pk)))
}

/// Derive the public key from a canonical secret key.
#[pyfunction]
fn pk_from_sk<'py>(py: Python<'py>, param: &str, sk: &[u8]) -> PyResult<Bound<'py, PyBytes>> {
    let id = param_id(param)?;
    let sk = api::SecretBytes::copy_from(sk);
    let pk = py.detach(move || api::pk_from_sk(id, &sk)).map_err(err)?;
    Ok(PyBytes::new(py, &pk))
}

/// Sign `msg` under `ctx` (pure SLH-DSA, deterministic).
///
/// The GIL is released for the whole call: a Python caller must not block other threads
/// while a signature is computed.
#[pyfunction]
#[pyo3(signature = (param, sk, msg, ctx = &b""[..]))]
fn sign<'py>(
    py: Python<'py>,
    param: &str,
    sk: &[u8],
    msg: &[u8],
    ctx: &[u8],
) -> PyResult<Bound<'py, PyBytes>> {
    let id = param_id(param)?;
    let sk = api::SecretBytes::copy_from(sk);
    let msg = msg.to_vec();
    let ctx = ctx.to_vec();
    let sig = py
        .detach(move || api::sign(id, &sk, &msg, &ctx))
        .map_err(err)?;
    Ok(PyBytes::new(py, &sig))
}

/// Verify a signature. Returns `True` when it verifies, `False` when it does not.
#[pyfunction]
#[pyo3(signature = (param, pk, msg, sig, ctx = &b""[..]))]
fn verify(
    py: Python<'_>,
    param: &str,
    pk: &[u8],
    msg: &[u8],
    sig: &[u8],
    ctx: &[u8],
) -> PyResult<bool> {
    let id = param_id(param)?;
    let pk = pk.to_vec();
    let msg = msg.to_vec();
    let sig = sig.to_vec();
    let ctx = ctx.to_vec();
    py.detach(move || api::verify(id, &pk, &msg, &ctx, &sig))
        .map_err(err)
}

/// SHAKE256 with a 32-byte output.
#[pyfunction]
fn shake256_32<'py>(py: Python<'py>, data: &[u8]) -> Bound<'py, PyBytes> {
    let data = data.to_vec();
    let digest = py.detach(move || api::shake256_32(&data));
    PyBytes::new(py, &digest)
}

#[pymodule]
fn dregg_sig(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    m.add("MAX_PK_BYTES", api::MAX_PK_BYTES)?;
    m.add("MAX_SK_BYTES", api::MAX_SK_BYTES)?;
    m.add("MAX_SIG_BYTES", api::MAX_SIG_BYTES)?;
    m.add("MAX_CTX_BYTES", api::MAX_CTX_BYTES)?;
    m.add_function(wrap_pyfunction!(pk_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(sk_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(sig_bytes, m)?)?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(keygen_from_seed, m)?)?;
    m.add_function(wrap_pyfunction!(pk_from_sk, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(shake256_32, m)?)?;
    Ok(())
}
