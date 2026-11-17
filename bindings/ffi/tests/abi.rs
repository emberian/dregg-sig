//! Rust-side tests for the C ABI: the same known-answer checks the C program makes, plus the
//! boundary rules (null pointers, short buffers, panics) exercised through the `extern "C"`
//! entry points rather than the safe layer.

use dregg_sig_ffi::api;
use dregg_sig_ffi::c_abi::*;

const KAT: &str = include_str!("../../../tests/kat_vectors.json");

fn field(name: &str) -> String {
    // The vector file is small and flat enough that a substring scan is honest here: the
    // value is quoted and the key is unique within the fips205 object.
    let key = format!("\"{name}\": ");
    let start = KAT.find(&key).expect("key present") + key.len();
    let rest = &KAT[start..];
    let rest = rest.strip_prefix('"').unwrap_or(rest);
    let end = rest.find(['"', ',', '\n']).expect("value end");
    rest[..end].to_string()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
        .collect()
}

#[test]
fn sizes_are_the_documented_constants() {
    assert_eq!(api::pk_bytes(api::PARAM_128F), Some(32));
    assert_eq!(api::sk_bytes(api::PARAM_128F), Some(64));
    assert_eq!(api::sig_bytes(api::PARAM_128F), Some(17_088));
    assert_eq!(api::sig_bytes(api::PARAM_128S), Some(7_856));
    assert_eq!(api::sig_bytes(api::PARAM_192F), Some(35_664));
    assert_eq!(api::sig_bytes(api::PARAM_256F), Some(49_856));
    assert_eq!(api::pk_bytes(99), None);
    assert_eq!(api::MAX_SIG_BYTES, 49_856);
}

#[test]
fn kat_public_key_and_signature_match_byte_for_byte() {
    let sk_seed = unhex(&field("sk_seed_hex"));
    let sk_prf = unhex(&field("sk_prf_hex"));
    let pk_seed = unhex(&field("pk_seed_hex"));
    let msg = field("msg_ascii").into_bytes();
    let ctx = unhex(&field("ctx_hex"));

    let (sk, pk) = api::keygen(api::PARAM_128F, &sk_seed, &sk_prf, &pk_seed).unwrap();
    assert_eq!(pk, unhex(&field("pk_hex")), "public key");

    let sig = api::sign(api::PARAM_128F, &sk, &msg, &ctx).unwrap();
    assert_eq!(sig.len(), 17_088);
    assert_eq!(&sig[..64], &unhex(&field("sig_head_64_hex"))[..], "head");
    assert_eq!(
        &sig[sig.len() - 64..],
        &unhex(&field("sig_tail_64_hex"))[..],
        "tail"
    );
    assert_eq!(
        api::shake256_32(&sig).to_vec(),
        unhex(&field("sig_shake256_32")),
        "digest"
    );
    assert_eq!(
        api::verify(api::PARAM_128F, &pk, &msg, &ctx, &sig),
        Ok(true)
    );
}

#[test]
fn c_entry_points_report_errors_as_codes() {
    let sk_seed = unhex(&field("sk_seed_hex"));
    let sk_prf = unhex(&field("sk_prf_hex"));
    let pk_seed = unhex(&field("pk_seed_hex"));
    let msg = field("msg_ascii").into_bytes();

    let mut sk = [0u8; 64];
    let mut pk = [0u8; 32];
    let mut sk_w = 0usize;
    let mut pk_w = 0usize;
    let rc = unsafe {
        dregg_sig_keygen(
            DREGG_SIG_PARAM_128F,
            sk_seed.as_ptr(),
            16,
            sk_prf.as_ptr(),
            16,
            pk_seed.as_ptr(),
            16,
            sk.as_mut_ptr(),
            sk.len(),
            &mut sk_w,
            pk.as_mut_ptr(),
            pk.len(),
            &mut pk_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_OK);
    assert_eq!((sk_w, pk_w), (64, 32));

    // A short output buffer is refused and still reports the required length.
    let mut sig = [0u8; 17_088];
    let mut sig_w = 0usize;
    let rc = unsafe {
        dregg_sig_sign(
            DREGG_SIG_PARAM_128F,
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            0,
            sig.as_mut_ptr(),
            16,
            &mut sig_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_ERR_BUFFER_TOO_SMALL);
    assert_eq!(sig_w, 17_088);

    // A null pointer with a nonzero length is refused, not dereferenced.
    let rc = unsafe {
        dregg_sig_sign(
            DREGG_SIG_PARAM_128F,
            core::ptr::null(),
            64,
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            0,
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_ERR_NULL_POINTER);

    // An unknown parameter set is refused.
    let rc = unsafe {
        dregg_sig_sign(
            99,
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            core::ptr::null(),
            0,
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_ERR_INVALID_PARAM);

    // An over-long context is refused.
    let long_ctx = [0x42u8; 256];
    let rc = unsafe {
        dregg_sig_sign(
            DREGG_SIG_PARAM_128F,
            sk.as_ptr(),
            sk.len(),
            msg.as_ptr(),
            msg.len(),
            long_ctx.as_ptr(),
            long_ctx.len(),
            sig.as_mut_ptr(),
            sig.len(),
            &mut sig_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_ERR_CONTEXT_TOO_LONG);
}

#[test]
fn a_failed_keygen_wipes_the_secret_key_buffer() {
    let sk_seed = unhex(&field("sk_seed_hex"));
    let sk_prf = unhex(&field("sk_prf_hex"));
    let pk_seed = unhex(&field("pk_seed_hex"));

    let mut sk = [0xAAu8; 64];
    let mut pk = [0u8; 32];
    let mut sk_w = 0usize;
    let mut pk_w = 0usize;
    // A 15-byte seed is the wrong length, so keygen fails after the buffer is in play.
    let rc = unsafe {
        dregg_sig_keygen(
            DREGG_SIG_PARAM_128F,
            sk_seed.as_ptr(),
            15,
            sk_prf.as_ptr(),
            16,
            pk_seed.as_ptr(),
            16,
            sk.as_mut_ptr(),
            sk.len(),
            &mut sk_w,
            pk.as_mut_ptr(),
            pk.len(),
            &mut pk_w,
        )
    };
    assert_eq!(rc, DREGG_SIG_ERR_INVALID_LENGTH);
    assert!(
        sk.iter().all(|&b| b == 0),
        "secret-key buffer was not wiped"
    );
}

#[test]
fn the_max_constants_are_the_max_over_all_six_sets() {
    let ids = [
        api::PARAM_128S,
        api::PARAM_128F,
        api::PARAM_192S,
        api::PARAM_192F,
        api::PARAM_256S,
        api::PARAM_256F,
    ];
    let max = |f: fn(u32) -> Option<usize>| ids.iter().map(|&i| f(i).unwrap()).max().unwrap();
    assert_eq!(api::MAX_PK_BYTES, max(api::pk_bytes));
    assert_eq!(api::MAX_SK_BYTES, max(api::sk_bytes));
    assert_eq!(api::MAX_SIG_BYTES, max(api::sig_bytes));
}

#[test]
fn strerror_is_static_and_never_null() {
    for code in 0..=8 {
        let p = dregg_sig_strerror(code);
        assert!(!p.is_null());
        let s = unsafe { core::ffi::CStr::from_ptr(p) };
        assert!(!s.to_bytes().is_empty());
    }
}
