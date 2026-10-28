#include "ulc_3des.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>

static int g_fail;

static void expect_mem(const char *name, const uint8_t *got, const uint8_t *exp, size_t n) {
    if (memcmp(got, exp, n) != 0) {
        printf("FAIL %s\n  got", name);
        for (size_t i = 0; i < n; i++) {
            printf(" %02x", got[i]);
        }
        printf("\n  exp");
        for (size_t i = 0; i < n; i++) {
            printf(" %02x", exp[i]);
        }
        printf("\n");
        g_fail++;
        return;
    }
    printf("OK   %s\n", name);
}

int main(void) {
    const uint8_t key[16] = {
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff
    };
    const uint8_t pt16[16] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef,
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77
    };
    const uint8_t ct16[16] = {
        0x4c, 0xd6, 0x48, 0x34, 0x7c, 0x7c, 0x41, 0xf1,
        0x46, 0xf1, 0xb8, 0xb3, 0xe8, 0x3e, 0x2c, 0xad
    };
    const uint8_t ct8[8] = {
        0xfb, 0x09, 0x75, 0x99, 0x72, 0x30, 0x1a, 0xf4
    };
    const uint8_t ct264_head[8] = {
        0xf4, 0xdc, 0xea, 0x6b, 0x36, 0x90, 0x2b, 0x8a
    };
    const uint8_t ct264_tail[8] = {
        0xa7, 0x1e, 0xd3, 0xc3, 0xb4, 0x4f, 0xe0, 0x2b
    };

    uint8_t iv[8];
    uint8_t out[264];
    uint8_t dec[264];
    uint8_t pt264[264];

    ulc_3des_init();

    memset(iv, 0, sizeof(iv));
    memset(out, 0x5a, sizeof(out));
    ulc_tdes_enc_cbc(out, pt16, sizeof(pt16), key, iv);
    expect_mem("2K3DES-CBC enc 16", out, ct16, sizeof(ct16));

    memset(iv, 0, sizeof(iv));
    ulc_tdes_dec_cbc(dec, ct16, sizeof(ct16), key, iv);
    expect_mem("2K3DES-CBC dec 16", dec, pt16, sizeof(pt16));

    memset(iv, 0, sizeof(iv));
    memset(out, 0, 8);
    ulc_tdes_enc_cbc(out, out, 8, key, iv);
    expect_mem("2K3DES-CBC enc 8 zero", out, ct8, sizeof(ct8));

    memset(out, 0, 8);
    ulc_tdes_enc_ecb(out, out, key);
    expect_mem("2K3DES-ECB enc 8 zero", out, ct8, sizeof(ct8));

    memset(pt264, 0x11, sizeof(pt264));
    memset(iv, 0, sizeof(iv));
    ulc_tdes_enc_cbc(out, pt264, sizeof(pt264), key, iv);
    expect_mem("2K3DES-CBC enc 264 head", out, ct264_head, sizeof(ct264_head));
    expect_mem("2K3DES-CBC enc 264 tail", out + 256, ct264_tail, sizeof(ct264_tail));

    memset(iv, 0, sizeof(iv));
    ulc_tdes_dec_cbc(dec, out, sizeof(pt264), key, iv);
    expect_mem("2K3DES-CBC dec 264", dec, pt264, sizeof(pt264));

    return g_fail ? 1 : 0;
}
