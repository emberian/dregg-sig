// Package dreggsig is a cgo binding over the C ABI of dregg-sig-core's stateless
// FIPS 205 SLH-DSA surface.
//
// Bytes in, bytes out. Every function takes and returns []byte; there is no object graph to
// keep in sync with the Rust side. A secret key returned here lives in the Go heap; the
// garbage collector does not zero it, so a caller who needs that must overwrite the slice
// itself when done. The C ABI owns no memory for the caller: this package
// allocates the output slices and passes their pointers and lengths down.
//
// Build the Rust static library first:
//
//	sh bindings/go/build.sh
//
// then `go test ./...` from this directory.
package dreggsig

/*
#cgo CFLAGS: -I${SRCDIR}/../../bindings/ffi/include
// Link the static archive by full path: the cdylib beside it would otherwise be chosen and
// then need a runtime search path the test binary does not have.
#cgo LDFLAGS: ${SRCDIR}/../../target/release/libdregg_sig_ffi.a -lpthread -ldl -lm
#include <stdlib.h>
#include "dregg_sig.h"
*/
import "C"

import (
	"errors"
	"fmt"
	"unsafe"
)

// Parameter-set identifiers.
const (
	Param128s uint32 = C.DREGG_SIG_PARAM_128S
	Param128f uint32 = C.DREGG_SIG_PARAM_128F
	Param192s uint32 = C.DREGG_SIG_PARAM_192S
	Param192f uint32 = C.DREGG_SIG_PARAM_192F
	Param256s uint32 = C.DREGG_SIG_PARAM_256S
	Param256f uint32 = C.DREGG_SIG_PARAM_256F
)

// Upper bounds over all six parameter sets.
const (
	MaxPKBytes  = int(C.DREGG_SIG_MAX_PK_BYTES)
	MaxSKBytes  = int(C.DREGG_SIG_MAX_SK_BYTES)
	MaxSigBytes = int(C.DREGG_SIG_MAX_SIG_BYTES)
	MaxCtxBytes = int(C.DREGG_SIG_MAX_CTX_BYTES)
)

// ErrVerify is returned by Verify when the signature does not verify.
var ErrVerify = errors.New("dreggsig: signature did not verify")

// Sentinels for the other C error codes. Every non-verify error this package returns is an
// *Error, and errors.Is matches it against the sentinel for its code.
var (
	ErrNullPointer    = &Error{Code: int(C.DREGG_SIG_ERR_NULL_POINTER)}
	ErrBufferTooSmall = &Error{Code: int(C.DREGG_SIG_ERR_BUFFER_TOO_SMALL)}
	ErrInvalidParam   = &Error{Code: int(C.DREGG_SIG_ERR_INVALID_PARAM)}
	ErrInvalidLength  = &Error{Code: int(C.DREGG_SIG_ERR_INVALID_LENGTH)}
	ErrContextTooLong = &Error{Code: int(C.DREGG_SIG_ERR_CONTEXT_TOO_LONG)}
	ErrPanic          = &Error{Code: int(C.DREGG_SIG_ERR_PANIC)}
	ErrInternal       = &Error{Code: int(C.DREGG_SIG_ERR_INTERNAL)}
)

// Error carries a C ABI error code.
type Error struct {
	Code int
}

func (e *Error) Error() string {
	return fmt.Sprintf("dreggsig: %s (code %d)", C.GoString(C.dregg_sig_strerror(C.int(e.Code))), e.Code)
}

// Is reports whether target is an *Error with the same code.
func (e *Error) Is(target error) bool {
	t, ok := target.(*Error)
	return ok && t.Code == e.Code
}

// codeError turns a C error code into a Go error.
func codeError(code C.int) error {
	if code == C.DREGG_SIG_OK {
		return nil
	}
	if code == C.DREGG_SIG_ERR_VERIFY_FAILED {
		return ErrVerify
	}
	return &Error{Code: int(code)}
}

// PKBytes returns the exact public-key length for a parameter set, or 0 if unknown.
func PKBytes(param uint32) int { return int(C.dregg_sig_pk_bytes(C.uint32_t(param))) }

// SKBytes returns the exact secret-key length for a parameter set, or 0 if unknown.
func SKBytes(param uint32) int { return int(C.dregg_sig_sk_bytes(C.uint32_t(param))) }

// SigBytes returns the exact signature length for a parameter set, or 0 if unknown.
func SigBytes(param uint32) int { return int(C.dregg_sig_sig_bytes(C.uint32_t(param))) }

// bytesPtr returns a pointer to the first byte of b, or nil for an empty slice.
func bytesPtr(b []byte) *C.uint8_t {
	if len(b) == 0 {
		return nil
	}
	return (*C.uint8_t)(unsafe.Pointer(&b[0]))
}

// Keygen generates a keypair from explicit (skSeed, skPrf, pkSeed) components.
func Keygen(param uint32, skSeed, skPrf, pkSeed []byte) (sk, pk []byte, err error) {
	sk = make([]byte, SKBytes(param))
	pk = make([]byte, PKBytes(param))
	var skW, pkW C.size_t
	code := C.dregg_sig_keygen(
		C.uint32_t(param),
		bytesPtr(skSeed), C.size_t(len(skSeed)),
		bytesPtr(skPrf), C.size_t(len(skPrf)),
		bytesPtr(pkSeed), C.size_t(len(pkSeed)),
		bytesPtr(sk), C.size_t(len(sk)), &skW,
		bytesPtr(pk), C.size_t(len(pk)), &pkW,
	)
	if e := codeError(code); e != nil {
		return nil, nil, e
	}
	return sk[:int(skW)], pk[:int(pkW)], nil
}

// KeygenFromSeed generates a keypair from one master seed.
func KeygenFromSeed(param uint32, seed []byte) (sk, pk []byte, err error) {
	sk = make([]byte, SKBytes(param))
	pk = make([]byte, PKBytes(param))
	var skW, pkW C.size_t
	code := C.dregg_sig_keygen_from_seed(
		C.uint32_t(param),
		bytesPtr(seed), C.size_t(len(seed)),
		bytesPtr(sk), C.size_t(len(sk)), &skW,
		bytesPtr(pk), C.size_t(len(pk)), &pkW,
	)
	if e := codeError(code); e != nil {
		return nil, nil, e
	}
	return sk[:int(skW)], pk[:int(pkW)], nil
}

// PKFromSK derives the public key from a canonical secret key.
func PKFromSK(param uint32, sk []byte) ([]byte, error) {
	pk := make([]byte, PKBytes(param))
	var w C.size_t
	code := C.dregg_sig_pk_from_sk(
		C.uint32_t(param),
		bytesPtr(sk), C.size_t(len(sk)),
		bytesPtr(pk), C.size_t(len(pk)), &w,
	)
	if e := codeError(code); e != nil {
		return nil, e
	}
	return pk[:int(w)], nil
}

// Sign signs msg under ctx (pure SLH-DSA, deterministic).
func Sign(param uint32, sk, msg, ctx []byte) ([]byte, error) {
	sig := make([]byte, SigBytes(param))
	var w C.size_t
	code := C.dregg_sig_sign(
		C.uint32_t(param),
		bytesPtr(sk), C.size_t(len(sk)),
		bytesPtr(msg), C.size_t(len(msg)),
		bytesPtr(ctx), C.size_t(len(ctx)),
		bytesPtr(sig), C.size_t(len(sig)), &w,
	)
	if e := codeError(code); e != nil {
		return nil, e
	}
	return sig[:int(w)], nil
}

// Verify reports whether sig verifies. It returns ErrVerify when it does not.
func Verify(param uint32, pk, msg, ctx, sig []byte) error {
	code := C.dregg_sig_verify(
		C.uint32_t(param),
		bytesPtr(pk), C.size_t(len(pk)),
		bytesPtr(msg), C.size_t(len(msg)),
		bytesPtr(ctx), C.size_t(len(ctx)),
		bytesPtr(sig), C.size_t(len(sig)),
	)
	return codeError(code)
}

// Shake256_32 returns the 32-byte SHAKE256 digest of data.
func Shake256_32(data []byte) []byte {
	out := make([]byte, 32)
	var w C.size_t
	code := C.dregg_sig_shake256_32(
		bytesPtr(data), C.size_t(len(data)),
		bytesPtr(out), C.size_t(len(out)), &w,
	)
	if code != C.DREGG_SIG_OK {
		return nil
	}
	return out[:int(w)]
}
