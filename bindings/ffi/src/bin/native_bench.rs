//! Native timing baseline for the binding comparison.
//!
//! Prints one line per operation in a fixed, greppable shape so the C, Go and Python timing
//! lines can be read beside it:
//!
//! ```text
//! native <op> <param> <milliseconds> <iterations>
//! ```
//!
//! `op` is `keygen`, `sign` or `verify`. The measurement is wall-clock over `iterations`
//! repetitions after one warm-up, so it is a comparison figure, not a benchmark.

use std::time::Instant;

use dregg_sig_core::fips205::{
    slh_keygen_internal, slh_sign, slh_verify, Fips205Params, SlhPublicKey, SlhSecretKey,
};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let iters: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(3);
    let sets: [(&str, Fips205Params); 2] = [
        ("128f", Fips205Params::SLH_DSA_SHAKE_128F),
        ("128s", Fips205Params::SLH_DSA_SHAKE_128S),
    ];
    let msg = b"dregg-sig binding timing";

    for (label, p) in sets {
        let n = p.n;
        let sk_seed = vec![0x11u8; n];
        let sk_prf = vec![0x22u8; n];
        let pk_seed = vec![0x33u8; n];

        // Warm-up, then measure.
        let (sk, pk) = slh_keygen_internal(&p, &sk_seed, &sk_prf, &pk_seed).unwrap();
        let sig = slh_sign(&p, msg, &[], &sk, None).unwrap();
        assert!(slh_verify(&p, msg, &sig, &[], &pk));

        let t = Instant::now();
        for _ in 0..iters {
            let _ = slh_keygen_internal(&p, &sk_seed, &sk_prf, &pk_seed).unwrap();
        }
        println!(
            "native keygen {label} {:.3} {iters}",
            t.elapsed().as_secs_f64() * 1000.0
        );

        let t = Instant::now();
        for _ in 0..iters {
            let _ = slh_sign(&p, msg, &[], &sk, None).unwrap();
        }
        println!(
            "native sign {label} {:.3} {iters}",
            t.elapsed().as_secs_f64() * 1000.0
        );

        let t = Instant::now();
        for _ in 0..iters {
            assert!(slh_verify(&p, msg, &sig, &[], &pk));
        }
        println!(
            "native verify {label} {:.3} {iters}",
            t.elapsed().as_secs_f64() * 1000.0
        );

        // Keep the types alive so the compiler cannot elide the work above.
        let _: (&SlhSecretKey, &SlhPublicKey) = (&sk, &pk);
    }
}
