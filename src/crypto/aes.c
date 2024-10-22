#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include <typedefs.h>
#include <crypto/aes.h>

#ifdef WIN32
    #define bswap_32(x) _byteswap_ulong(x)
#else
    #include <byteswap.h>
#endif

#define Nb 4

static const u8 SBox[16][16] = {
    { 0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, },
    { 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, },
    { 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, },
    { 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, },
    { 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, },
    { 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, },
    { 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, },
    { 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, },
    { 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, },
    { 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, },
    { 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, },
    { 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, },
    { 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, },
    { 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, },
    { 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, },
    { 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16, },
};

static const u8 InvSBox[16][16] = {
    { 0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, },
    { 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, },
    { 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, },
    { 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, },
    { 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, },
    { 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, },
    { 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, },
    { 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, },
    { 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, },
    { 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, },
    { 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, },
    { 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, },
    { 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, },
    { 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, },
    { 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, },
    { 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d, },
};

static inline u8 xtime(u8 w)
{
    u16 x = w << 1;
    return ((x & 0x100) == 0x100) ? (u8)(x ^ 0x1B) : (u8)x;
}

static void add_round_key(u8 state[AES_BLOCK_SIZE], const u32 w[Nb])
{
    for (u32 i = 0; i < Nb; i++)
        ((u32 *)state)[i] ^= bswap_32(w[i]);
}

static void sub_bytes(u8 state[AES_BLOCK_SIZE])
{
    for (u32 i = 0; i < 4 * Nb; i++)
        state[i] = SBox[state[i] >> 4][state[i] & 0x0F];
}

static void inv_sub_bytes(u8 state[AES_BLOCK_SIZE])
{
    for (u32 i = 0; i < AES_BLOCK_SIZE; i++)
        state[i] = InvSBox[state[i] >> 4][state[i] & 0x0F];
}

static void shift_rows(u8 state[AES_BLOCK_SIZE])
{
    for (u32 i = 1; i < 4; i++) {
        u32 shiftCount = i;
        while (shiftCount > 0) {
            u8 item = state[i];
            for (u32 j = 1; j < Nb; j++)
                state[i + 4 * (j - 1)] = state[i + 4 * j];
            state[i + 4 * (Nb - 1)] = item;
            shiftCount--;
        }
    }
}

static void inv_shift_rows(u8 state[AES_BLOCK_SIZE])
{
    for (u32 i = 1; i < 4; i++) {
        u32 shiftCount = i;
        while (shiftCount > 0) {
            u8 item = state[i + 4 * (Nb - 1)];
            for (u32 j = Nb - 1; j > 0; j--)
                state[i + 4 * j] = state[i + 4 * (j - 1)];
            state[i] = item;
            shiftCount--;
        }
    }
}

static inline u8 gf_multiply(u8 a, u8 b)
{
    return (a & 0x01) * b
        ^ ((a >> 1) & 0x01) * xtime(b)
        ^ ((a >> 2) & 0x01) * xtime(xtime(b))
        ^ ((a >> 3) & 0x01) * xtime(xtime(xtime(b)))
        ^ ((a >> 4) & 0x01) * xtime(xtime(xtime(xtime(b))))
        ^ ((a >> 5) & 0x01) * xtime(xtime(xtime(xtime(xtime(b)))))
        ^ ((a >> 6) & 0x01) * xtime(xtime(xtime(xtime(xtime(xtime(b))))))
        ^ ((a >> 7) & 0x01) * xtime(xtime(xtime(xtime(xtime(xtime(xtime(b))))))); /* страшно? мы тебя предупреждали */
}

static void mix_columns(u8 state[AES_BLOCK_SIZE])
{
    u8 s0, s1, s2, s3;

    for (u32 i = 0; i < Nb; i++) {
        s0 = gf_multiply(state[4 * i], 0x02) ^ gf_multiply(state[4 * i + 1], 0x03) ^ gf_multiply(state[4 * i + 2], 0x01) ^ gf_multiply(state[4 * i + 3], 0x01);
        s1 = gf_multiply(state[4 * i], 0x01) ^ gf_multiply(state[4 * i + 1], 0x02) ^ gf_multiply(state[4 * i + 2], 0x03) ^ gf_multiply(state[4 * i + 3], 0x01);
        s2 = gf_multiply(state[4 * i], 0x01) ^ gf_multiply(state[4 * i + 1], 0x01) ^ gf_multiply(state[4 * i + 2], 0x02) ^ gf_multiply(state[4 * i + 3], 0x03);
        s3 = gf_multiply(state[4 * i], 0x03) ^ gf_multiply(state[4 * i + 1], 0x01) ^ gf_multiply(state[4 * i + 2], 0x01) ^ gf_multiply(state[4 * i + 3], 0x02);

        state[4 * i + 0] = s0;
        state[4 * i + 1] = s1;
        state[4 * i + 2] = s2;
        state[4 * i + 3] = s3;
    }
}

static void inv_mix_columns(u8 state[AES_BLOCK_SIZE])
{
    u8 s0, s1, s2, s3;

    for (u32 i = 0; i < Nb; i++) {
        s0 = gf_multiply(state[4 * i], 0x0e) ^ gf_multiply(state[4 * i + 1], 0x0b) ^ gf_multiply(state[4 * i + 2], 0x0d) ^ gf_multiply(state[4 * i + 3], 0x09);
        s1 = gf_multiply(state[4 * i], 0x09) ^ gf_multiply(state[4 * i + 1], 0x0e) ^ gf_multiply(state[4 * i + 2], 0x0b) ^ gf_multiply(state[4 * i + 3], 0x0d);
        s2 = gf_multiply(state[4 * i], 0x0d) ^ gf_multiply(state[4 * i + 1], 0x09) ^ gf_multiply(state[4 * i + 2], 0x0e) ^ gf_multiply(state[4 * i + 3], 0x0b);
        s3 = gf_multiply(state[4 * i], 0x0b) ^ gf_multiply(state[4 * i + 1], 0x0d) ^ gf_multiply(state[4 * i + 2], 0x09) ^ gf_multiply(state[4 * i + 3], 0x0e);

        state[4 * i + 0] = s0;
        state[4 * i + 1] = s1;
        state[4 * i + 2] = s2;
        state[4 * i + 3] = s3;
    }
}

static u32 sub_word(u32 w)
{
    u8 a0 = (u8)(w >> 24);
    u8 a1 = (u8)(w >> 16);
    u8 a2 = (u8)(w >> 8);
    u8 a3 = (u8)w;

    return (SBox[a0 >> 4][a0 & 0x0F] << 24)
        | (SBox[a1 >> 4][a1 & 0x0F] << 16)
        | (SBox[a2 >> 4][a2 & 0x0F] << 8)
        | SBox[a3 >> 4][a3 & 0x0F];
}

static inline u32 rot_word(u32 w)
{
    return (w << 8) | (u8)(w >> 24);
}

static void key_expansion(const u8 *key, u32 *w, u32 Nk, u32 Nr)
{
    u32 i, temp;
    u8 rcon;

    for (i = 0; i < Nk; i++)
        w[i] = bswap_32(((u32 *)key)[i]);

    for (rcon = 0x01; i < Nb * (Nr + 1); i++) {
        temp = w[i - 1];
        if (i % Nk == 0) {
            temp = sub_word(rot_word(temp)) ^ (rcon << 24);
            rcon = xtime(rcon);
        } else if (Nk > 6 && i % Nk == 4) {
            temp = sub_word(temp);
        }
        w[i] = w[i - Nk] ^ temp;
    }
}

static void cipher(u8 state[AES_BLOCK_SIZE], const u32 *w, u32 Nr)
{
    add_round_key(state, w);

    for (u32 round = 1; round < Nr; round++) {
        sub_bytes(state);
        shift_rows(state);
        mix_columns(state);
        add_round_key(state, w + round * Nb);
    }

    sub_bytes(state);
    shift_rows(state);
    add_round_key(state, w + Nr * Nb);
}

static void inv_cipher(u8 state[AES_BLOCK_SIZE], const u32 *w, u32 Nr)
{
    add_round_key(state, w + Nr * Nb);

    for (u32 round = Nr - 1; round > 0; round--) {
        inv_shift_rows(state);
        inv_sub_bytes(state);
        add_round_key(state, w + round * Nb);
        inv_mix_columns(state);
    }

    inv_shift_rows(state);
    inv_sub_bytes(state);
    add_round_key(state, w);
}

void aes_init(AES *ctx, const u8 *key, u64 size)
{
    aes_init_with_iv(ctx, NULL, key, size);
}

void aes_init_with_iv(AES *ctx, const u8 *IV, const u8 *key, u64 size)
{
    assert(size == 16 || size == 24 || size == 32);

    memset(ctx, 0, sizeof(*ctx));

    if (IV != NULL) {
        memcpy(ctx->iv, IV, AES_BLOCK_SIZE);
    }

    switch (size) {
        case 16:
            ctx->number_of_words = 4;
            ctx->number_of_rounds = 10;
            break;
        case 24:
            ctx->number_of_words = 6;
            ctx->number_of_rounds = 12;
            break;
        case 32:
            ctx->number_of_words = 8;
            ctx->number_of_rounds = 14;
            break;
    }

    ctx->key_schedule = malloc(sizeof(u32) * Nb * (ctx->number_of_rounds + 1));
    key_expansion(key, ctx->key_schedule, ctx->number_of_words, ctx->number_of_rounds);
}

static void xor_with_iv(u8 state[AES_BLOCK_SIZE], const u8 iv[AES_BLOCK_SIZE])
{
    for (u32 i = 0; i < AES_BLOCK_SIZE; i++)
        state[i] ^= iv[i];
}

void aes_cbc_encode(u8 cipherText[AES_BLOCK_SIZE], const u8 plainText[AES_BLOCK_SIZE], AES *ctx)
{
    memcpy(ctx->state, plainText, AES_BLOCK_SIZE);

    xor_with_iv(ctx->state, ctx->iv);
    cipher(ctx->state, ctx->key_schedule, ctx->number_of_rounds);

    memcpy(ctx->iv, ctx->state, AES_BLOCK_SIZE);
    memcpy(cipherText, ctx->state, AES_BLOCK_SIZE);
}

void aes_cbc_decode(u8 plainText[AES_BLOCK_SIZE], const u8 cipherText[AES_BLOCK_SIZE], AES *ctx)
{
    memcpy(ctx->state, cipherText, AES_BLOCK_SIZE);

    xor_with_iv(ctx->state, ctx->iv);
    inv_cipher(ctx->state, ctx->key_schedule, ctx->number_of_rounds);

    memcpy(ctx->iv, ctx->state, AES_BLOCK_SIZE);
    memcpy(plainText, ctx->state, AES_BLOCK_SIZE);
}

void aes_ecb_encode(u8 cipherText[AES_BLOCK_SIZE], const u8 plainText[AES_BLOCK_SIZE], AES *ctx)
{
    memcpy(ctx->state, plainText, AES_BLOCK_SIZE);

    cipher(ctx->state, ctx->key_schedule, ctx->number_of_rounds);

    memcpy(cipherText, ctx->state, AES_BLOCK_SIZE);
}

void aes_ecb_decode(u8 plainText[AES_BLOCK_SIZE], const u8 cipherText[AES_BLOCK_SIZE], AES *ctx)
{
    memcpy(ctx->state, cipherText, AES_BLOCK_SIZE);

    inv_cipher(ctx->state, ctx->key_schedule, ctx->number_of_rounds);

    memcpy(plainText, ctx->state, AES_BLOCK_SIZE);
}

void aes_free(AES *ctx)
{
    free(ctx->key_schedule);
}