# Language bindings for `dregg-sig`

Three bindings over the stateless FIPS 205 SLH-DSA surface of `dregg-sig-core`, each in its own
workspace so the library workspace keeps its zero-crates.io-dependency rule:

| Path | What it is |
| --- | --- |
| `bindings/ffi` | `cdylib` + `staticlib` C ABI, plus a generated header |
| `bindings/go` | cgo package over the C ABI, with tests |
| `bindings/python` | pyo3 `abi3` extension, bytes in and bytes out, with pytest tests |

Nothing in `crates/` is edited. Each binding depends on `dregg-sig-core` (and the Python one on
`bindings/ffi`) by path.

## What is bound

The stateless signature core, and only that:

- `keygen` from explicit `(SK.seed, SK.prf, PK.seed)` components, and from one master seed;
- `pk_from_sk`;
- `sign` (pure SLH-DSA, deterministic, with a context string);
- `verify`;
- `shake256_32`, so a caller can reproduce the repository's signature-digest check;
- the exact byte lengths for all six official parameter sets, and the upper bounds over them.

All six `SLH-DSA-SHAKE` sets are reachable: `128s`, `128f`, `192s`, `192f`, `256s`, `256f`.

## Representation analysis

This is the part a binding gets wrong at the edges, so it is written down rather than assumed.

### Fixed-size types

| Type | Bytes | Notes |
| --- | --- | --- |
| `SlhPublicKey` | `2*n` = 32, 48 or 64 | `PK.seed ‖ PK.root`, each `n` bytes |
| `SlhSecretKey` | `4*n` = 64, 96 or 128 | `SK.seed ‖ SK.prf ‖ PK.seed ‖ PK.root` |
| `SlhBlock` | `n` = 16, 24 or 32 | one hash node; internally a `[u8; 32]` with a length |
| `Fips205Adrs` | 32 | uncompressed address, fixed layout |
| signature | `n * (1 + k*(1+a) + d*(ell+hp))` | fixed **per parameter set**, not per message |

The signature is fixed-size for a given parameter set. That is what makes a flat caller-allocated
buffer possible: the caller asks `dregg_sig_sig_bytes(param)` once and sizes the buffer once. The
six values are 7,856 / 17,088 / 16,224 / 35,664 / 29,792 / 49,856 bytes.

The secret key is fixed-size too, but it is *secret*: the C ABI wipes the caller's secret-key
output buffer on every error path, and every copy the Rust side makes (the parsed key, the
serialized bytes, the Python binding's copies of seeds and keys) is wiped when it drops. What the
foreign runtime holds is the caller's: a Go `[]byte` is not zeroed by the collector, and a Python
`bytes` is immutable and cannot be wiped at all.

### Length-carrying types

| Type | Carries | Why it cannot be a flat fixed buffer |
| --- | --- | --- |
| message | caller's length | arbitrary |
| context string | caller's length, `<= 255` | FIPS 205 limit; longer is refused, not truncated |
| `SlhParsedSignature` | `Vec` of FORS trees and hypertree layers | a *parsed* view, not a wire type; the wire form is the flat signature above |
| `BaggySig` | `Vec<BaggyLayerSig>`, and inside each, `Vec` chains and auth path | variable layer count and variable PORS+FP multiproof length |
| `PorsFpOpening` | `secrets` and `auth` vectors, with a `u16` auth count in the wire form | the multiproof length is bounded but not fixed |
| `JortsSig` | `Vec` chains and auth path | fixed for a given `JortsParams`, but the params are a runtime value |
| `FrontierFtsSignature` | `randomizer`, `grind_counter`, `chain_values` | fixed for a given profile; `Compact1122` is 1,122 bytes |

The wire encodings of the variable types are self-describing (`PorsFpOpening` writes a `u16` node
count), so a binding *could* carry them as opaque byte strings. None of them is bound here, for the
reason in the next section.

### What a stateful key would need

`Jorts` and `JortsPoseidon2` are stateful: a key signs at most `2^h` messages, and each signature
consumes an epoch. The state is not a counter in the key struct; it is a durable latch:

- `BeltLatchState { next_epoch: u64, in_flight: Option<BeltLatchRecord> }`, with a canonical
  encoding (`QSAGBLT1` magic, big-endian epoch, optional in-flight record, trailing cSHAKE256
  integrity tag) and a strict decoder that rejects truncation, trailing bytes and a bad tag;
- a `DurableWal` implementation behind it (`FsBeltWal` for a file, `MemoryWal` for tests), which
  must `sync` before a signature is released;
- `JortsSigner<W>` holds three latches (one per MPC party), the full public Merkle tree
  (`JortsKeyMaterial.levels`, `h+1` levels of `2^h` nodes), and staged windows.

A flat buffer cannot carry that. A binding would need, at minimum: a handle to a live signer
object, a durable store the binding does not own, a way to report "the WAL refused" distinctly from
"the signature is bad", and a recovery path that re-reads the latch after a crash. That is an
object-lifetime and durability contract, not a byte encoding, and it is exactly the kind of thing a
binding guesses wrong. **Stateful schemes are left out.**

`Compact1122` (`FrontierSumFts`) is also left out, and the reason is narrower: it is *almost* flat.
The signature is a fixed 1,122 bytes for the profile, but signing needs a `FrontierDpTable` (a
large precomputed table, built once per profile), a `&mut` signing key whose use counter advances,
and — outside tests — an attached `FtsEpochWal` that must durably reserve the use *before* any
signature material is computed. A key with no WAL refuses to sign. So the type is stateful in the
same sense as `Jorts`, just with a smaller state: one monotonic counter and a durable reservation.
Binding it as a flat function would either drop the durability guarantee or silently sign twice.
**Left out until there is a handle-based API.**

## The C ABI

`bindings/ffi/include/dregg_sig.h` is **generated** by `dregg-sig-header`. Its constants (parameter
identifiers, error codes, sizes) come from the crate's own values, so they cannot disagree with the
library. The function prototypes are written out by hand in the generator, and C does not check a
prototype against the symbol at link time, so a change to an `extern "C"` signature must be made in
`src/bin/header.rs` too:

```sh
cargo run --release --manifest-path bindings/ffi/Cargo.toml --bin dregg-sig-header \
    > bindings/ffi/include/dregg_sig.h
```

Rules the ABI keeps:

- **caller-allocated buffers with explicit lengths** — every output is `(ptr, len, *written)`; the
  library never allocates for the caller and never frees anything;
- **sizes exported as constants** — `DREGG_SIG_MAX_*` for the worst case over all six sets, and
  `DREGG_SIG_<SET>_{PK,SK,SIG}_BYTES` for one set, plus `dregg_sig_{pk,sk,sig}_bytes(param)` at run
  time;
- **integer error codes, never a string or a panic** — `DREGG_SIG_OK` and eight `DREGG_SIG_ERR_*`
  codes; `dregg_sig_strerror` returns a static string for diagnostics only;
- **no panic crossing the boundary** — `catch_unwind` wraps every entry point, and a caught panic
  becomes `DREGG_SIG_ERR_PANIC`;
- **secret keys zeroized** — every Rust-side copy on drop, and the caller's output buffer on every
  error path in `keygen` and `keygen_from_seed`;
- **no overlapping buffers** — an output buffer must not alias an input or another output.

A short output buffer is refused with `DREGG_SIG_ERR_BUFFER_TOO_SMALL` **and** the required length
is still written to `*written`, so a caller can retry without guessing.

## The Go package

`bindings/go` is a cgo package over the C ABI. It links the static archive by full path, so the
test binary needs no runtime search path. Every function takes and returns `[]byte`; the package
allocates the output slices and passes their pointers and lengths down.

```sh
sh bindings/go/build.sh
cd bindings/go && go test ./...
```

## The Python extension

`bindings/python` is a pyo3 `abi3` extension (`abi3-py39`). Bytes in, bytes out.

**The GIL is released for the whole of `keygen`, `keygen_from_seed`, `pk_from_sk`, `sign` and
`verify`.** That is the point of the binding: a 128f signature is tens of milliseconds of hashing,
and a Python caller must not block other threads while one runs. The test suite proves the release
with a spinner thread that must record progress in the middle half of a `sign` call, and a control
test proves the same probe reads a GIL-holding call as no progress.

```sh
sh bindings/python/tests/build.sh
PYTHONPATH=target/python python3 -m pytest bindings/python/tests -q
```

## Known-answer parity

The repository's own vector file, `tests/kat_vectors.json`, is the target. The `fips205_slh_dsa_shake_128f`
entry gives `sk_seed`, `sk_prf`, `pk_seed`, the expected public key, the message, and three
independent checks on the signature: its length, its first and last 64 bytes, and its SHAKE256-32
digest.

Each binding reads those values **out of the vector file at test time** — the C program gets them
as compile-time defines from a shell script that parses the JSON, the Go and Python tests parse the
JSON directly — so no binding carries its own copy of the answer.

All three check, byte for byte:

- the public key equals `pk_hex`;
- the signature length equals `sig_bytes`;
- the signature's first 64 bytes equal `sig_head_64_hex`;
- the signature's last 64 bytes equal `sig_tail_64_hex`;
- the signature's SHAKE256-32 digest equals `sig_shake256_32`;
- the signature verifies, and a one-bit flip does not.

## Timing

Each binding has a timing program that prints one line per operation in a fixed shape, so the
binding lines can be read beside the native baseline:

```sh
sh bindings/ffi/tests/run_bench.sh 3          # native baseline, then C ABI
cd bindings/go && go run ./cmd/bench 3        # Go
PYTHONPATH=target/python python3 bindings/python/tests/bench.py 3   # Python
```

Measured on one node, three iterations after a warm-up, release build. Milliseconds for the whole
run of three, so divide by three for a per-call figure.

| op | set | native | C ABI | Go | Python |
| --- | --- | --- | --- | --- | --- |
| keygen | 128f | 2.547 | 2.484 | 2.542 | 2.773 |
| sign | 128f | 80.602 | 66.267 | 66.746 | 67.783 |
| verify | 128f | 10.020 | 6.628 | 6.580 | 6.588 |
| keygen | 128s | 168.778 | 162.511 | 161.749 | 162.256 |
| sign | 128s | 1263.569 | 1235.064 | 1238.950 | 1233.107 |
| verify | 128s | 2.297 | 2.208 | 2.206 | 2.211 |

The bindings are within a few percent of native, and the C ABI is sometimes *faster* than the
native baseline — that is measurement noise between two processes on a shared node, not a real
speedup. No binding is anywhere near the 100x that would be a finding.

## What is not bound, and why

| Type | Why not |
| --- | --- |
| `Jorts`, `JortsPoseidon2` | stateful: durable latch, WAL, three-party latches, full Merkle tree. Needs a handle, not a buffer. |
| `Compact1122` / `FrontierSumFts` | stateful in the same sense: a use counter that must be durably reserved before signing, and a key with no WAL refuses to sign. |
| `Baggy` | stateless, but its signature carries a variable-length PORS+FP multiproof and a variable layer count; a flat buffer would need a length-prefixed encoding the core does not define for this purpose. |
| threshold / MPC types (`keccak_mpc`, `rss256`, `spdz_sweep`, `quorum`) | these are multi-party sessions with rounds and transports, not a single call. |
| `agg` (Hem) | proof objects with their own variable encodings, and a prover that is not a signature operation. |
| credentials, capabilities, policy, addresses (`cred`, `policy`, `addr`, `hd`) | a separate slice; see below. |

## A second slice, not bound here

This repository also carries `crates/cred` (blind verifiable credentials, threshold ML-DSA,
VOPRF), `crates/policy` (macaroons, PQ biscuits, transaction policy), `crates/addr` (addresses,
intent encoding, hybrid envelopes) and `crates/hd` (hierarchical-deterministic seed ceremonies).
They are not bound, because each carries state or a multi-round protocol that needs the same
handle-based design the stateful signature schemes need.

## Building

The library workspace is untouched. Each binding is its own workspace and builds by manifest path:

```sh
cargo build --release --manifest-path bindings/ffi/Cargo.toml --lib
cargo build --release --manifest-path bindings/python/Cargo.toml --lib
```

The toolchain is the repository's pinned Rust 1.99.1.
