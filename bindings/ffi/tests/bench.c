/* Timing line for the C ABI, in the same shape as the native baseline:
 *
 *   c-abi <op> <param> <milliseconds> <iterations>
 *
 * Build and run with `sh crates/ffi/tests/run_bench.sh`.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "dregg_sig.h"

static double now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (double)ts.tv_sec * 1000.0 + (double)ts.tv_nsec / 1e6;
}

static void bench(uint32_t param, const char *label, int iters) {
    size_t n = dregg_sig_pk_bytes(param) / 2;
    uint8_t sk_seed[32], sk_prf[32], pk_seed[32];
    memset(sk_seed, 0x11, n);
    memset(sk_prf, 0x22, n);
    memset(pk_seed, 0x33, n);

    uint8_t sk[DREGG_SIG_MAX_SK_BYTES], pk[DREGG_SIG_MAX_PK_BYTES];
    uint8_t sig[DREGG_SIG_MAX_SIG_BYTES];
    size_t sk_w = 0, pk_w = 0, sig_w = 0;
    const char *msg = "dregg-sig binding timing";
    size_t msg_len = strlen(msg);

    /* Warm-up. */
    if (dregg_sig_keygen(param, sk_seed, n, sk_prf, n, pk_seed, n, sk, sizeof sk, &sk_w, pk,
                         sizeof pk, &pk_w) != DREGG_SIG_OK) {
        fprintf(stderr, "warm-up keygen failed\n");
        return;
    }
    if (dregg_sig_sign(param, sk, sk_w, (const uint8_t *)msg, msg_len, NULL, 0, sig, sizeof sig,
                       &sig_w) != DREGG_SIG_OK) {
        fprintf(stderr, "warm-up sign failed\n");
        return;
    }

    double t = now_ms();
    for (int i = 0; i < iters; i++) {
        dregg_sig_keygen(param, sk_seed, n, sk_prf, n, pk_seed, n, sk, sizeof sk, &sk_w, pk,
                         sizeof pk, &pk_w);
    }
    printf("c-abi keygen %s %.3f %d\n", label, now_ms() - t, iters);

    t = now_ms();
    for (int i = 0; i < iters; i++) {
        dregg_sig_sign(param, sk, sk_w, (const uint8_t *)msg, msg_len, NULL, 0, sig, sizeof sig,
                       &sig_w);
    }
    printf("c-abi sign %s %.3f %d\n", label, now_ms() - t, iters);

    t = now_ms();
    for (int i = 0; i < iters; i++) {
        if (dregg_sig_verify(param, pk, pk_w, (const uint8_t *)msg, msg_len, NULL, 0, sig, sig_w) !=
            DREGG_SIG_OK) {
            fprintf(stderr, "verify failed during timing\n");
            return;
        }
    }
    printf("c-abi verify %s %.3f %d\n", label, now_ms() - t, iters);
}

int main(int argc, char **argv) {
    int iters = argc > 1 ? atoi(argv[1]) : 3;
    bench(DREGG_SIG_PARAM_128F, "128f", iters);
    bench(DREGG_SIG_PARAM_128S, "128s", iters);
    return 0;
}
