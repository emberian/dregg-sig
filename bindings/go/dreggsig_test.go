package dreggsig

import (
	"bytes"
	"encoding/hex"
	"errors"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// kat is the repository's own known-answer vector for SLH-DSA-SHAKE-128f.
type kat struct {
	SKSeedHex    string `json:"sk_seed_hex"`
	SKPrfHex     string `json:"sk_prf_hex"`
	PKSeedHex    string `json:"pk_seed_hex"`
	PKHex        string `json:"pk_hex"`
	MsgASCII     string `json:"msg_ascii"`
	CtxHex       string `json:"ctx_hex"`
	SigBytes     int    `json:"sig_bytes"`
	SigShake256  string `json:"sig_shake256_32"`
	SigHead64Hex string `json:"sig_head_64_hex"`
	SigTail64Hex string `json:"sig_tail_64_hex"`
}

func loadKAT(t *testing.T) kat {
	t.Helper()
	path := filepath.Join("..", "..", "tests", "kat_vectors.json")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var all struct {
		V kat `json:"fips205_slh_dsa_shake_128f"`
	}
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return all.V
}

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func TestSizesMatchTheVector(t *testing.T) {
	v := loadKAT(t)
	if got := PKBytes(Param128f); got != len(mustHex(t, v.PKHex)) {
		t.Fatalf("pk size = %d, want %d", got, len(mustHex(t, v.PKHex)))
	}
	if got := SKBytes(Param128f); got != 64 {
		t.Fatalf("sk size = %d, want 64", got)
	}
	if got := SigBytes(Param128f); got != v.SigBytes {
		t.Fatalf("sig size = %d, want %d", got, v.SigBytes)
	}
}

func TestPublicKeyMatchesTheVectorByteForByte(t *testing.T) {
	v := loadKAT(t)
	sk, pk, err := Keygen(Param128f, mustHex(t, v.SKSeedHex), mustHex(t, v.SKPrfHex), mustHex(t, v.PKSeedHex))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	if !bytes.Equal(pk, mustHex(t, v.PKHex)) {
		t.Fatalf("public key mismatch:\n got %x\nwant %x", pk, mustHex(t, v.PKHex))
	}
	if len(sk) != SKBytes(Param128f) {
		t.Fatalf("secret key length = %d", len(sk))
	}
}

func TestSignatureMatchesTheVectorByteForByte(t *testing.T) {
	v := loadKAT(t)
	sk, pk, err := Keygen(Param128f, mustHex(t, v.SKSeedHex), mustHex(t, v.SKPrfHex), mustHex(t, v.PKSeedHex))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := Sign(Param128f, sk, []byte(v.MsgASCII), mustHex(t, v.CtxHex))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(sig) != v.SigBytes {
		t.Fatalf("signature length = %d, want %d", len(sig), v.SigBytes)
	}
	if !bytes.Equal(sig[:64], mustHex(t, v.SigHead64Hex)) {
		t.Fatalf("signature head mismatch:\n got %x\nwant %x", sig[:64], mustHex(t, v.SigHead64Hex))
	}
	if !bytes.Equal(sig[len(sig)-64:], mustHex(t, v.SigTail64Hex)) {
		t.Fatalf("signature tail mismatch:\n got %x\nwant %x", sig[len(sig)-64:], mustHex(t, v.SigTail64Hex))
	}
	if got := Shake256_32(sig); !bytes.Equal(got, mustHex(t, v.SigShake256)) {
		t.Fatalf("signature digest mismatch:\n got %x\nwant %x", got, mustHex(t, v.SigShake256))
	}
	if err := Verify(Param128f, pk, []byte(v.MsgASCII), mustHex(t, v.CtxHex), sig); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsAFlippedBit(t *testing.T) {
	v := loadKAT(t)
	sk, pk, err := Keygen(Param128f, mustHex(t, v.SKSeedHex), mustHex(t, v.SKPrfHex), mustHex(t, v.PKSeedHex))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := Sign(Param128f, sk, []byte(v.MsgASCII), nil)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	sig[len(sig)/2] ^= 0x80
	if err := Verify(Param128f, pk, []byte(v.MsgASCII), nil, sig); err != ErrVerify {
		t.Fatalf("verify of a flipped bit = %v, want ErrVerify", err)
	}
}

func TestPKFromSKRoundTrips(t *testing.T) {
	v := loadKAT(t)
	sk, pk, err := Keygen(Param128f, mustHex(t, v.SKSeedHex), mustHex(t, v.SKPrfHex), mustHex(t, v.PKSeedHex))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	got, err := PKFromSK(Param128f, sk)
	if err != nil {
		t.Fatalf("pk_from_sk: %v", err)
	}
	if !bytes.Equal(got, pk) {
		t.Fatalf("pk_from_sk mismatch")
	}
}

func TestContextIsBound(t *testing.T) {
	v := loadKAT(t)
	sk, pk, err := Keygen(Param128f, mustHex(t, v.SKSeedHex), mustHex(t, v.SKPrfHex), mustHex(t, v.PKSeedHex))
	if err != nil {
		t.Fatalf("keygen: %v", err)
	}
	sig, err := Sign(Param128f, sk, []byte("m"), []byte("ctx-a"))
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if err := Verify(Param128f, pk, []byte("m"), []byte("ctx-a"), sig); err != nil {
		t.Fatalf("verify with the right context: %v", err)
	}
	if err := Verify(Param128f, pk, []byte("m"), []byte("ctx-b"), sig); err != ErrVerify {
		t.Fatalf("verify with the wrong context = %v, want ErrVerify", err)
	}
}

func TestErrorsAreErrorsNotPanics(t *testing.T) {
	if _, _, err := Keygen(Param128f, []byte("short"), make([]byte, 16), make([]byte, 16)); err == nil {
		t.Fatal("short seed was accepted")
	}
	if _, err := Sign(Param128f, make([]byte, 64), []byte("m"), make([]byte, 256)); err == nil {
		t.Fatal("over-long context was accepted")
	}
	if _, _, err := Keygen(999, make([]byte, 16), make([]byte, 16), make([]byte, 16)); err == nil {
		t.Fatal("unknown parameter set was accepted")
	}
}

func TestErrorsAreTyped(t *testing.T) {
	if _, _, err := Keygen(Param128f, []byte("short"), make([]byte, 16), make([]byte, 16)); !errors.Is(err, ErrInvalidLength) {
		t.Fatalf("short seed: %v, want ErrInvalidLength", err)
	}
	if _, err := Sign(Param128f, make([]byte, 64), []byte("m"), make([]byte, 256)); !errors.Is(err, ErrContextTooLong) {
		t.Fatalf("long context: %v, want ErrContextTooLong", err)
	}
	if _, _, err := Keygen(999, make([]byte, 16), make([]byte, 16), make([]byte, 16)); !errors.Is(err, ErrInvalidParam) {
		t.Fatalf("unknown set: %v, want ErrInvalidParam", err)
	}
	if err := Verify(Param128f, make([]byte, 32), []byte("m"), nil, make([]byte, 10)); !errors.Is(err, ErrInvalidLength) || errors.Is(err, ErrVerify) {
		t.Fatalf("short signature: %v, want ErrInvalidLength and not ErrVerify", err)
	}
}

func TestShake256MatchesTheKeccakVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "tests", "kat_vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var all struct {
		K struct {
			Empty string `json:"shake256_empty_32"`
			ABC   string `json:"shake256_abc_32"`
		} `json:"keccak"`
	}
	if err := json.Unmarshal(raw, &all); err != nil {
		t.Fatal(err)
	}
	if got := Shake256_32(nil); !bytes.Equal(got, mustHex(t, all.K.Empty)) {
		t.Fatalf("shake256(\"\") = %x", got)
	}
	if got := Shake256_32([]byte("abc")); !bytes.Equal(got, mustHex(t, all.K.ABC)) {
		t.Fatalf("shake256(\"abc\") = %x", got)
	}
}
