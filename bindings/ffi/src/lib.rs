//! C ABI for the stateless FIPS 205 SLH-DSA surface of `dregg-sig-core`.
//!
//! The core crate stays `no_std` and dependency-free; this crate is a separate workspace that
//! depends on it and adds nothing to it. See `include/dregg_sig.h` for the C declarations and
//! `README.md` for the representation analysis.

pub mod api;
pub mod c_abi;

pub use api::*;
