"""Timing line for the Python binding, in the same shape as the native baseline:

    python <op> <param> <milliseconds> <iterations>

Run with `PYTHONPATH=target/python python3 bindings/python/tests/bench.py [iterations]`.
"""

import sys
import time

import dregg_sig

ITERS = int(sys.argv[1]) if len(sys.argv) > 1 else 3
MSG = b"dregg-sig binding timing"


def bench(param, label):
    n = dregg_sig.pk_bytes(param) // 2
    sk_seed = bytes([0x11]) * n
    sk_prf = bytes([0x22]) * n
    pk_seed = bytes([0x33]) * n

    # Warm-up.
    sk, pk = dregg_sig.keygen(param, sk_seed, sk_prf, pk_seed)
    sig = dregg_sig.sign(param, sk, MSG)
    assert dregg_sig.verify(param, pk, MSG, sig)

    t = time.perf_counter()
    for _ in range(ITERS):
        dregg_sig.keygen(param, sk_seed, sk_prf, pk_seed)
    print(f"python keygen {label} {(time.perf_counter() - t) * 1000:.3f} {ITERS}")

    t = time.perf_counter()
    for _ in range(ITERS):
        dregg_sig.sign(param, sk, MSG)
    print(f"python sign {label} {(time.perf_counter() - t) * 1000:.3f} {ITERS}")

    t = time.perf_counter()
    for _ in range(ITERS):
        assert dregg_sig.verify(param, pk, MSG, sig)
    print(f"python verify {label} {(time.perf_counter() - t) * 1000:.3f} {ITERS}")


bench("128f", "128f")
bench("128s", "128s")
