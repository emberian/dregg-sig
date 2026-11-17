//! Safe Rust surface shared by the C ABI and the Python extension.
//!
//! Every function here is plain Rust: it takes slices, returns owned `Vec`s, and reports
//! failure as an integer code. The `extern "C"` layer in [`crate::c_abi`] and the pyo3 layer
//! in `dregg-sig-python` are both thin adapters over this module, so the two bindings cannot
//! drift apart in behaviour.

use dregg_sig_core::fips205::{
    slh_keygen_from_seed, slh_keygen_internal, slh_sign, slh_verify, Fips205Error, Fips205Params,
    SlhPublicKey, SlhSecretKey, FIPS205_MAX_CTX_LEN,
};
use dregg_sig_core::wipe::wipe_bytes;

/// Success.
pub const OK: i32 = 0;
/// A required pointer argument was null.
pub const ERR_NULL_POINTER: i32 = 1;
/// The caller's output buffer was too small; the required length is reported back.
pub const ERR_BUFFER_TOO_SMALL: i32 = 2;
/// The parameter-set identifier is not one of the six official SLH-DSA-SHAKE sets.
pub const ERR_INVALID_PARAM: i32 = 3;
/// A key, signature or seed had the wrong byte length.
pub const ERR_INVALID_LENGTH: i32 = 4;
/// The context string exceeded the FIPS 205 limit of 255 bytes.
pub const ERR_CONTEXT_TOO_LONG: i32 = 5;
/// The signature did not verify.
pub const ERR_VERIFY_FAILED: i32 = 6;
/// A panic was caught at the boundary. The binding never lets one escape.
pub const ERR_PANIC: i32 = 7;
/// An unexpected internal failure.
pub const ERR_INTERNAL: i32 = 8;

/// Parameter-set identifiers, stable across releases.
pub const PARAM_128S: u32 = 0;
pub const PARAM_128F: u32 = 1;
pub const PARAM_192S: u32 = 2;
pub const PARAM_192F: u32 = 3;
pub const PARAM_256S: u32 = 4;
pub const PARAM_256F: u32 = 5;

/// Largest public key over all six sets (`2 * 32`).
pub const MAX_PK_BYTES: usize = 64;
/// Largest secret key over all six sets (`4 * 32`).
pub const MAX_SK_BYTES: usize = 128;
/// Largest signature over all six sets (`SLH-DSA-SHAKE-256f`).
pub const MAX_SIG_BYTES: usize = 49_856;
/// FIPS 205 context-string limit.
pub const MAX_CTX_BYTES: usize = FIPS205_MAX_CTX_LEN;

/// An owned byte buffer holding secret material, overwritten with zeros when dropped.
///
/// `SlhSecretKey::to_bytes` returns a plain `Vec<u8>`; every copy of a secret key or seed this
/// crate makes lives in one of these, so no copy outlives its call unwiped on any path,
/// including an error return or a caught panic.
pub struct SecretBytes(Vec<u8>);

impl SecretBytes {
    /// Take ownership of `v`; it is wiped when the returned value drops.
    pub fn new(v: Vec<u8>) -> Self {
        SecretBytes(v)
    }

    /// Copy `s` into a new wiping buffer.
    pub fn copy_from(s: &[u8]) -> Self {
        SecretBytes(s.to_vec())
    }
}

impl core::ops::Deref for SecretBytes {
    type Target = [u8];
    fn deref(&self) -> &[u8] {
        &self.0
    }
}

impl Drop for SecretBytes {
    fn drop(&mut self) {
        wipe_bytes(&mut self.0);
    }
}

/// Resolve a parameter-set identifier to its parameters.
pub fn params(id: u32) -> Option<Fips205Params> {
    Some(match id {
        PARAM_128S => Fips205Params::SLH_DSA_SHAKE_128S,
        PARAM_128F => Fips205Params::SLH_DSA_SHAKE_128F,
        PARAM_192S => Fips205Params::SLH_DSA_SHAKE_192S,
        PARAM_192F => Fips205Params::SLH_DSA_SHAKE_192F,
        PARAM_256S => Fips205Params::SLH_DSA_SHAKE_256S,
        PARAM_256F => Fips205Params::SLH_DSA_SHAKE_256F,
        _ => return None,
    })
}

/// Public key length for a parameter set, or `None` for an unknown identifier.
pub fn pk_bytes(id: u32) -> Option<usize> {
    params(id).map(|p| p.pk_bytes())
}

/// Secret key length for a parameter set, or `None` for an unknown identifier.
pub fn sk_bytes(id: u32) -> Option<usize> {
    params(id).map(|p| p.sk_bytes())
}

/// Signature length for a parameter set, or `None` for an unknown identifier.
pub fn sig_bytes(id: u32) -> Option<usize> {
    params(id).map(|p| p.sig_bytes())
}

fn map_err(e: Fips205Error) -> i32 {
    match e {
        Fips205Error::InvalidParameterSet => ERR_INVALID_PARAM,
        Fips205Error::ContextTooLong(_) => ERR_CONTEXT_TOO_LONG,
        Fips205Error::InvalidPublicKeyBytes(_)
        | Fips205Error::InvalidSecretKeyBytes(_)
        | Fips205Error::InvalidSignatureLength { .. }
        | Fips205Error::InvalidNodeBytes { .. } => ERR_INVALID_LENGTH,
        _ => ERR_INTERNAL,
    }
}

/// Generate a keypair from explicit `(SK.seed, SK.prf, PK.seed)` components.
///
/// Returns `(secret_key, public_key)` as canonical byte strings: `4*n` and `2*n` bytes.
/// The `SlhSecretKey` is wiped on drop inside this call; the returned secret-key bytes are a
/// [`SecretBytes`], wiped when the caller drops them.
pub fn keygen(
    id: u32,
    sk_seed: &[u8],
    sk_prf: &[u8],
    pk_seed: &[u8],
) -> Result<(SecretBytes, Vec<u8>), i32> {
    let p = params(id).ok_or(ERR_INVALID_PARAM)?;
    let n = p.n;
    if sk_seed.len() != n || sk_prf.len() != n || pk_seed.len() != n {
        return Err(ERR_INVALID_LENGTH);
    }
    let (sk, pk) = slh_keygen_internal(&p, sk_seed, sk_prf, pk_seed).map_err(map_err)?;
    Ok((SecretBytes::new(sk.to_bytes()), pk.to_bytes()))
}

/// Generate a keypair from one master seed (`SHAKE256(seed, 3*n)` expansion).
pub fn keygen_from_seed(id: u32, master_seed: &[u8]) -> Result<(SecretBytes, Vec<u8>), i32> {
    let p = params(id).ok_or(ERR_INVALID_PARAM)?;
    let (sk, pk) = slh_keygen_from_seed(&p, master_seed).map_err(map_err)?;
    Ok((SecretBytes::new(sk.to_bytes()), pk.to_bytes()))
}

/// Derive the public key from a canonical secret key.
pub fn pk_from_sk(id: u32, sk: &[u8]) -> Result<Vec<u8>, i32> {
    let p = params(id).ok_or(ERR_INVALID_PARAM)?;
    let sk = SlhSecretKey::from_bytes_for_params(&p, sk).map_err(map_err)?;
    Ok(sk.public_key().to_bytes())
}

/// Sign `msg` under `ctx` (pure SLH-DSA, deterministic).
pub fn sign(id: u32, sk: &[u8], msg: &[u8], ctx: &[u8]) -> Result<Vec<u8>, i32> {
    let p = params(id).ok_or(ERR_INVALID_PARAM)?;
    if ctx.len() > MAX_CTX_BYTES {
        return Err(ERR_CONTEXT_TOO_LONG);
    }
    let sk = SlhSecretKey::from_bytes_for_params(&p, sk).map_err(map_err)?;
    slh_sign(&p, msg, ctx, &sk, None).map_err(map_err)
}

/// Verify a signature. `Ok(true)` means it verified; `Ok(false)` means it did not.
pub fn verify(id: u32, pk: &[u8], msg: &[u8], ctx: &[u8], sig: &[u8]) -> Result<bool, i32> {
    let p = params(id).ok_or(ERR_INVALID_PARAM)?;
    if ctx.len() > MAX_CTX_BYTES {
        return Err(ERR_CONTEXT_TOO_LONG);
    }
    let pk = SlhPublicKey::from_bytes_for_params(&p, pk).map_err(map_err)?;
    if sig.len() != p.sig_bytes() {
        return Err(ERR_INVALID_LENGTH);
    }
    Ok(slh_verify(&p, msg, sig, ctx, &pk))
}

/// SHAKE256 with a 32-byte output. Exposed so a caller can reproduce the repository's
/// signature-digest known-answer check without linking a second hash library.
pub fn shake256_32(input: &[u8]) -> [u8; 32] {
    let v = dregg_sig_core::sponge::keccak::shake256_xof(32, input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&v);
    out
}

/// Overwrite a byte buffer with zeros. Used by the C ABI on error paths.
pub fn wipe(buf: &mut [u8]) {
    wipe_bytes(buf);
}
