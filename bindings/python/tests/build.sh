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

SUFFIX=$(python3 -c "import sysconfig; print(sysconfig.get_config_var('EXT_SUFFIX'))")
cp target/release/libdregg_sig.so "$OUT/dregg_sig$SUFFIX"
echo "built $OUT/dregg_sig$SUFFIX"
