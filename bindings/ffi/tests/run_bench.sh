#!/bin/sh
# Build the C ABI timing program and run it beside the native baseline.
#
#   sh bindings/ffi/tests/run_bench.sh [iterations]
#
# Run from the repository root.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

ITERS=${1:-3}
OUT=${OUT:-target/ffi-kat}
mkdir -p "$OUT" bindings/ffi/include

CARGO_TARGET_DIR=target cargo build --release --manifest-path bindings/ffi/Cargo.toml --lib
CARGO_TARGET_DIR=target cargo build --release --manifest-path bindings/ffi/Cargo.toml --bin dregg-sig-native-bench
CARGO_TARGET_DIR=target cargo run --release -q --manifest-path bindings/ffi/Cargo.toml --bin dregg-sig-header > bindings/ffi/include/dregg_sig.h

cc -O2 -Wall -Wextra -Werror -I bindings/ffi/include bindings/ffi/tests/bench.c \
    target/release/libdregg_sig_ffi.a -lpthread -ldl -lm -o "$OUT/bench"

echo "# native baseline"
target/release/dregg-sig-native-bench "$ITERS"
echo "# C ABI"
"$OUT/bench" "$ITERS"
