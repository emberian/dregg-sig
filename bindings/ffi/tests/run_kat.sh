#!/bin/sh
# Build the C ABI and run its known-answer test against the repository's own vectors.
#
# The expected bytes are read out of `tests/kat_vectors.json` here and passed to the C
# program as compile-time defines, so the C test cannot carry its own copy of the answer.
#
#   sh bindings/ffi/tests/run_kat.sh
#
# Run from the repository root.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

KAT=tests/kat_vectors.json
OUT=${OUT:-target/ffi-kat}
mkdir -p "$OUT" bindings/ffi/include

# Pull one string field out of the fips205_slh_dsa_shake_128f object.
field() {
    python3 - "$KAT" "$1" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))["fips205_slh_dsa_shake_128f"]
v = d[sys.argv[2]]
print(v if not isinstance(v, bool) else ("true" if v else "false"))
PY
}

SK_SEED=$(field sk_seed_hex)
SK_PRF=$(field sk_prf_hex)
PK_SEED=$(field pk_seed_hex)
PK_HEX=$(field pk_hex)
MSG=$(field msg_ascii)
CTX=$(field ctx_hex)
SIG_BYTES=$(field sig_bytes)
SIG_DIGEST=$(field sig_shake256_32)
SIG_HEAD=$(field sig_head_64_hex)
SIG_TAIL=$(field sig_tail_64_hex)

CARGO_TARGET_DIR=target cargo build --release --manifest-path bindings/ffi/Cargo.toml --lib
CARGO_TARGET_DIR=target cargo run --release -q --manifest-path bindings/ffi/Cargo.toml --bin dregg-sig-header > bindings/ffi/include/dregg_sig.h

cc -O2 -Wall -Wextra -Werror \
    -I bindings/ffi/include \
    -DDREGG_SIG_STATIC=1 \
    -DKAT_SK_SEED_HEX="\"$SK_SEED\"" \
    -DKAT_SK_PRF_HEX="\"$SK_PRF\"" \
    -DKAT_PK_SEED_HEX="\"$PK_SEED\"" \
    -DKAT_PK_HEX="\"$PK_HEX\"" \
    -DKAT_MSG_ASCII="\"$MSG\"" \
    -DKAT_CTX_HEX="\"$CTX\"" \
    -DKAT_SIG_BYTES="$SIG_BYTES" \
    -DKAT_SIG_SHAKE256_32="\"$SIG_DIGEST\"" \
    -DKAT_SIG_HEAD_HEX="\"$SIG_HEAD\"" \
    -DKAT_SIG_TAIL_HEX="\"$SIG_TAIL\"" \
    bindings/ffi/tests/kat.c \
    target/release/libdregg_sig_ffi.a \
    -lpthread -ldl -lm \
    -o "$OUT/kat"

"$OUT/kat"
