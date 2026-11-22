#!/bin/sh
# Build the Python extension and put it where pytest can import it.
#
#   sh bindings/python/tests/build.sh
#   PYTHONPATH=target/python python3 -m pytest bindings/python/tests -q
#
# Run from the repository root. No maturin: the cdylib is copied to the abi3 name directly.
set -eu

ROOT=$(cd "$(dirname "$0")/../../.." && pwd)
cd "$ROOT"

OUT=${OUT:-target/python}
mkdir -p "$OUT"

CARGO_TARGET_DIR=target cargo build --release --manifest-path bindings/python/Cargo.toml --lib

# The crate is built against the stable ABI (pyo3 `abi3-py39`), so the file takes the stable-ABI name: every CPython
# from 3.9 imports `dregg_sig.abi3.so`, while the interpreter-tagged name (`.cpython-314-...so`) loads only in the
# interpreter that ran this script.
cp target/release/libdregg_sig.so "$OUT/dregg_sig.abi3.so"
echo "built $OUT/dregg_sig.abi3.so"
