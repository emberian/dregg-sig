"""Known-answer and behaviour tests for the Python binding.

The expected bytes are read from the repository's own `tests/kat_vectors.json`, so the test
cannot carry its own copy of the answer. Run with:

    python3 -m pytest bindings/python/tests -q

after `sh bindings/python/tests/build.sh` has put the extension on `PYTHONPATH`.
"""

import json
import os
import pathlib
import sys
import threading
import time

import pytest

import dregg_sig

ROOT = pathlib.Path(__file__).resolve().parents[3]
KAT = json.loads((ROOT / "tests" / "kat_vectors.json").read_text())
V = KAT["fips205_slh_dsa_shake_128f"]


def h(s):
    return bytes.fromhex(s)


def test_sizes_match_the_vector():
    assert dregg_sig.pk_bytes("128f") == len(h(V["pk_hex"]))
    assert dregg_sig.sk_bytes("128f") == 4 * 16
    assert dregg_sig.sig_bytes("128f") == V["sig_bytes"]


def test_public_key_matches_the_vector_byte_for_byte():
    sk, pk = dregg_sig.keygen(
        "128f", h(V["sk_seed_hex"]), h(V["sk_prf_hex"]), h(V["pk_seed_hex"])
    )
    assert pk == h(V["pk_hex"])
    assert len(sk) == dregg_sig.sk_bytes("128f")


def test_signature_matches_the_vector_byte_for_byte():
    sk, pk = dregg_sig.keygen(
        "128f", h(V["sk_seed_hex"]), h(V["sk_prf_hex"]), h(V["pk_seed_hex"])
    )
    sig = dregg_sig.sign("128f", sk, V["msg_ascii"].encode(), h(V["ctx_hex"]))
    assert len(sig) == V["sig_bytes"]
    assert sig[:64] == h(V["sig_head_64_hex"])
    assert sig[-64:] == h(V["sig_tail_64_hex"])
    assert dregg_sig.shake256_32(sig) == h(V["sig_shake256_32"])
    assert dregg_sig.verify("128f", pk, V["msg_ascii"].encode(), sig, h(V["ctx_hex"])) is True


def test_verify_rejects_a_flipped_bit():
    sk, pk = dregg_sig.keygen(
        "128f", h(V["sk_seed_hex"]), h(V["sk_prf_hex"]), h(V["pk_seed_hex"])
    )
    sig = bytearray(dregg_sig.sign("128f", sk, V["msg_ascii"].encode()))
    sig[len(sig) // 2] ^= 0x80
    assert dregg_sig.verify("128f", pk, V["msg_ascii"].encode(), bytes(sig)) is False


def test_pk_from_sk_round_trips():
    sk, pk = dregg_sig.keygen(
        "128f", h(V["sk_seed_hex"]), h(V["sk_prf_hex"]), h(V["pk_seed_hex"])
    )
    assert dregg_sig.pk_from_sk("128f", sk) == pk


def test_keygen_from_seed_is_deterministic():
    a = dregg_sig.keygen_from_seed("128f", b"seed")
    b = dregg_sig.keygen_from_seed("128f", b"seed")
    assert a == b


def test_context_is_bound():
    sk, pk = dregg_sig.keygen(
        "128f", h(V["sk_seed_hex"]), h(V["sk_prf_hex"]), h(V["pk_seed_hex"])
    )
    sig = dregg_sig.sign("128f", sk, b"m", b"ctx-a")
    assert dregg_sig.verify("128f", pk, b"m", sig, b"ctx-a") is True
    assert dregg_sig.verify("128f", pk, b"m", sig, b"ctx-b") is False


def test_errors_are_exceptions_not_panics():
    with pytest.raises(ValueError):
        dregg_sig.pk_bytes("nope")
    with pytest.raises(ValueError):
        dregg_sig.keygen("128f", b"short", b"x" * 16, b"y" * 16)
    with pytest.raises(ValueError):
        dregg_sig.sign("128f", b"x" * 64, b"m", b"c" * 256)


def _ran_during(call):
    """Whether a second thread made progress in the middle of `call`.

    The spinner records a timestamp on every pass. A call that holds the GIL blocks the spinner
    for its whole duration, so no timestamp can fall in the middle half of the call; one that
    releases it lets the spinner run throughout. Counting ticks across the whole call is not
    enough: the interpreter hands the GIL to a waiting thread just before and just after a
    long call, so a held GIL still shows progress at the edges. The switch interval is
    shortened so those edge slices are far shorter than the window.
    """
    stamps = []
    stop = threading.Event()

    def spin():
        while not stop.is_set():
            stamps.append(time.perf_counter())

    old = sys.getswitchinterval()
    sys.setswitchinterval(1e-4)
    t = threading.Thread(target=spin)
    t.start()
    try:
        time.sleep(0.02)
        t0 = time.perf_counter()
        call()
        t1 = time.perf_counter()
    finally:
        stop.set()
        t.join()
        sys.setswitchinterval(old)
    lo = t0 + 0.25 * (t1 - t0)
    hi = t0 + 0.75 * (t1 - t0)
    return any(lo < s < hi for s in stamps)


def test_the_gil_probe_can_fail():
    """Control: a call that holds the GIL must read as no progress, or the probe proves nothing."""
    assert not _ran_during(lambda: sum(range(20_000_000)))


def test_gil_is_released_during_sign():
    """A second thread must make progress while a signature is being computed."""
    sk, _pk = dregg_sig.keygen_from_seed("128s", b"gil-release-probe-seed")
    assert _ran_during(lambda: dregg_sig.sign("128s", sk, b"gil-release-probe")), (
        "the spinner made no progress during sign: the GIL was held"
    )


def test_shake256_matches_the_keccak_vectors():
    k = KAT["keccak"]
    assert dregg_sig.shake256_32(b"") == h(k["shake256_empty_32"])
    assert dregg_sig.shake256_32(b"abc") == h(k["shake256_abc_32"])
