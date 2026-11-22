#!/bin/sh
# Build the Rust static library the Go package links against.
#
#   sh bindings/go/build.sh
#   cd bindings/go && go test ./...
#
# Run from the repository root.
set -eu

ROOT=$(cd "$(dirname "$0")/../.." && pwd)
cd "$ROOT"

mkdir -p bindings/ffi/include
CARGO_TARGET_DIR=target cargo build --release --manifest-path bindings/ffi/Cargo.toml --lib
CARGO_TARGET_DIR=target cargo run --release -q --manifest-path bindings/ffi/Cargo.toml --bin dregg-sig-header > bindings/ffi/include/dregg_sig.h
echo "built target/release/libdregg_sig_ffi.a and bindings/ffi/include/dregg_sig.h"
