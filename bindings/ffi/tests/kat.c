/* Known-answer test for the C ABI, driven by the repository's own vectors.
 *
 * Reads `tests/kat_vectors.json` values that are passed in as compile-time defines by
 * `run_kat.sh`, so the expected bytes come from the repo's vector file and not from this
 * program. Checks, byte for byte:
 *
 *   - the public key equals `pk_hex`;
 *   - the signature's SHAKE256-32 digest equals `sig_shake256_32`;
 *   - the signature's first 64 bytes equal `sig_head_64_hex`;
 *   - the signature's last 64 bytes equal `sig_tail_64_hex`;
 *   - the signature length equals `sig_bytes`;
 *   - the signature verifies, and a one-bit flip does not.
 *
 * Also exercises the error paths: short buffer, null pointer, bad parameter, long context.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "dregg_sig.h"

static int failures = 0;

static void check(int cond, const char *what) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", what);
        failures++;
    }
}

static size_t unhex(const char *hex, uint8_t *out, size_t cap) {
    size_t n = strlen(hex) / 2;
    if (n > cap) {
        return (size_t)-1;
    }
    for (size_t i = 0; i < n; i++) {
        unsigned v;
        if (sscanf(hex + 2 * i, "%2x", &v) != 1) {
            return (size_t)-1;
        }
        out[i] = (uint8_t)v;
    }
    return n;
}

static void tohex(const uint8_t *b, size_t n, char *out) {
    static const char *H = "0123456789abcdef";
    for (size_t i = 0; i < n; i++) {
        out[2 * i] = H[b[i] >> 4];
        out[2 * i + 1] = H[b[i] & 0xf];
    }
    out[2 * n] = '\0';
}

int main(void) {
    uint8_t sk_seed[32], sk_prf[32], pk_seed[32];
    size_t n = unhex(KAT_SK_SEED_HEX, sk_seed, sizeof sk_seed);
    check(n == 16, "sk_seed length");
    check(unhex(KAT_SK_PRF_HEX, sk_prf, sizeof sk_prf) == 16, "sk_prf length");
    check(unhex(KAT_PK_SEED_HEX, pk_seed, sizeof pk_seed) == 16, "pk_seed length");

    const char *msg = KAT_MSG_ASCII;
    size_t msg_len = strlen(msg);

    /* The vector's context string, from the vector file like everything else. */
    uint8_t ctx[255];
    size_t ctx_len = unhex(KAT_CTX_HEX, ctx, sizeof ctx);
    check(ctx_len != (size_t)-1, "ctx length");

    /* Sizes come from the library, not from this program. */
    size_t pk_len = dregg_sig_pk_bytes(DREGG_SIG_PARAM_128F);
    size_t sk_len = dregg_sig_sk_bytes(DREGG_SIG_PARAM_128F);
    size_t sig_len = dregg_sig_sig_bytes(DREGG_SIG_PARAM_128F);
    check(pk_len == 32, "pk size constant");
    check(sk_len == 64, "sk size constant");
    check(sig_len == (size_t)KAT_SIG_BYTES, "sig size constant matches the vector");

    uint8_t sk[DREGG_SIG_MAX_SK_BYTES];
    uint8_t pk[DREGG_SIG_MAX_PK_BYTES];
    uint8_t sig[DREGG_SIG_MAX_SIG_BYTES];
    size_t sk_written = 0, pk_written = 0, sig_written = 0;

    int rc = dregg_sig_keygen(DREGG_SIG_PARAM_128F, sk_seed, 16, sk_prf, 16, pk_seed, 16, sk,
                              sizeof sk, &sk_written, pk, sizeof pk, &pk_written);
    check(rc == DREGG_SIG_OK, "keygen returns OK");
    check(sk_written == sk_len, "keygen reports the secret-key length");
    check(pk_written == pk_len, "keygen reports the public-key length");

    /* Public key, byte for byte. */
    uint8_t want_pk[64];
    size_t want_pk_len = unhex(KAT_PK_HEX, want_pk, sizeof want_pk);
    check(want_pk_len == pk_len, "vector pk length");
    check(memcmp(pk, want_pk, pk_len) == 0, "public key equals the vector, byte for byte");

    rc = dregg_sig_sign(DREGG_SIG_PARAM_128F, sk, sk_len, (const uint8_t *)msg, msg_len,
                        ctx_len ? ctx : NULL, ctx_len, sig, sizeof sig, &sig_written);
    check(rc == DREGG_SIG_OK, "sign returns OK");
    check(sig_written == (size_t)KAT_SIG_BYTES, "signature length equals the vector");

    /* Signature head and tail, byte for byte. */
    uint8_t want_head[64], want_tail[64];
    size_t head_len = unhex(KAT_SIG_HEAD_HEX, want_head, sizeof want_head);
    size_t tail_len = unhex(KAT_SIG_TAIL_HEX, want_tail, sizeof want_tail);
    check(head_len == 64 && tail_len == 64, "vector head/tail lengths");
    check(memcmp(sig, want_head, 64) == 0, "signature head equals the vector, byte for byte");
    check(memcmp(sig + sig_len - 64, want_tail, 64) == 0,
          "signature tail equals the vector, byte for byte");

    /* Signature digest, byte for byte. */
    uint8_t digest[32];
    size_t digest_len = 0;
    rc = dregg_sig_shake256_32(sig, sig_len, digest, sizeof digest, &digest_len);
    check(rc == DREGG_SIG_OK, "shake256_32 returns OK");
    check(digest_len == 32, "digest length");
    char got_hex[65];
    tohex(digest, 32, got_hex);
    check(strcmp(got_hex, KAT_SIG_SHAKE256_32) == 0,
          "signature SHAKE256-32 digest equals the vector, byte for byte");

    /* Verification, and a one-bit flip. */
    rc = dregg_sig_verify(DREGG_SIG_PARAM_128F, pk, pk_len, (const uint8_t *)msg, msg_len,
                          ctx_len ? ctx : NULL, ctx_len, sig, sig_len);
    check(rc == DREGG_SIG_OK, "verify accepts the vector signature");
    sig[sig_len / 2] ^= 0x80;
    rc = dregg_sig_verify(DREGG_SIG_PARAM_128F, pk, pk_len, (const uint8_t *)msg, msg_len,
                          ctx_len ? ctx : NULL, ctx_len, sig, sig_len);
    check(rc == DREGG_SIG_ERR_VERIFY_FAILED, "verify rejects a flipped bit");
    sig[sig_len / 2] ^= 0x80;

    /* Error paths. */
    size_t small_written = 0;
    rc = dregg_sig_sign(DREGG_SIG_PARAM_128F, sk, sk_len, (const uint8_t *)msg, msg_len, NULL, 0,
                        sig, 16, &small_written);
    check(rc == DREGG_SIG_ERR_BUFFER_TOO_SMALL, "short buffer is refused");
    check(small_written == sig_len, "short buffer still reports the required length");

    rc = dregg_sig_sign(DREGG_SIG_PARAM_128F, NULL, sk_len, (const uint8_t *)msg, msg_len, NULL, 0,
                        sig, sizeof sig, &sig_written);
    check(rc == DREGG_SIG_ERR_NULL_POINTER, "null secret key is refused");

    rc = dregg_sig_sign(99, sk, sk_len, (const uint8_t *)msg, msg_len, NULL, 0, sig, sizeof sig,
                        &sig_written);
    check(rc == DREGG_SIG_ERR_INVALID_PARAM, "unknown parameter set is refused");

    uint8_t long_ctx[256];
    memset(long_ctx, 0x42, sizeof long_ctx);
    rc = dregg_sig_sign(DREGG_SIG_PARAM_128F, sk, sk_len, (const uint8_t *)msg, msg_len, long_ctx,
                        sizeof long_ctx, sig, sizeof sig, &sig_written);
    check(rc == DREGG_SIG_ERR_CONTEXT_TOO_LONG, "over-long context is refused");

    /* A public-key buffer too small fails keygen after the secret key is written: the
     * secret-key buffer must come back wiped, not holding the key. */
    {
        uint8_t small_pk[16];
        size_t small_pk_written = 0;
        memset(sk, 0, sizeof sk);
        rc = dregg_sig_keygen(DREGG_SIG_PARAM_128F, sk_seed, 16, sk_prf, 16, pk_seed, 16, sk,
                              sizeof sk, &sk_written, small_pk, sizeof small_pk,
                              &small_pk_written);
        check(rc == DREGG_SIG_ERR_BUFFER_TOO_SMALL, "short public-key buffer is refused");
        check(small_pk_written == pk_len, "short public-key buffer reports the required length");
        int sk_clear = 1;
        for (size_t i = 0; i < sizeof sk; i++) {
            if (sk[i] != 0) {
                sk_clear = 0;
                break;
            }
        }
        check(sk_clear, "a short public-key buffer leaves no secret key behind");
    }

    /* A failed keygen wipes the secret-key output buffer. */
    memset(sk, 0xAA, sizeof sk);
    rc = dregg_sig_keygen(DREGG_SIG_PARAM_128F, sk_seed, 15, sk_prf, 16, pk_seed, 16, sk, sizeof sk,
                          &sk_written, pk, sizeof pk, &pk_written);
    check(rc == DREGG_SIG_ERR_INVALID_LENGTH, "short seed is refused");
    int all_zero = 1;
    for (size_t i = 0; i < sizeof sk; i++) {
        if (sk[i] != 0) {
            all_zero = 0;
            break;
        }
    }
    check(all_zero, "failed keygen wipes the secret-key output buffer");

    if (failures == 0) {
        printf("C ABI KAT: PASS (pk, sig head/tail, sig digest, verify, error paths)\n");
        return 0;
    }
    printf("C ABI KAT: FAIL (%d checks)\n", failures);
    return 1;
}
