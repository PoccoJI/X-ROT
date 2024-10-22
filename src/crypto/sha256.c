#ifdef _WIN32
    #include <stdlib.h>
    #define bswap_32 _byteswap_ulong
    #define bswap_64 _byteswap_uint64
#else
    #include <byteswap.h>
#endif
#include <stdbool.h>
#include <string.h>
#include <crypto/sha256.h>

static const u32 CONSTANTS[] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
};

static inline u32 CH(u32 x, u32 y, u32 z)
{
    return z ^ (x & (y ^ z));
}

static inline u32 MAJ(u32 x, u32 y, u32 z)
{
    return (x & y) | (z & (x | y));
}

static inline u32 ROTR(u32 x, u32 y)
{
    return (x >> y) | (x << (32 - y));
}

static inline u32 SIG0(u32 x)
{
    return ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22);
}

static inline u32 SIG1(u32 x)
{
    return ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25);
}

static inline u32 sig0(u32 x)
{
    return ROTR(x, 7) ^ ROTR(x, 18) ^ (x >> 3);
}

static inline u32 sig1(u32 x)
{
    return ROTR(x, 17) ^ ROTR(x, 19) ^ (x >> 10);
}

static void prepare_message_schedule(u32 schedule[64], const u8 *block)
{
    schedule[0]  = bswap_32(*(u32 *)(block + 0));
    schedule[1]  = bswap_32(*(u32 *)(block + 4));
    schedule[2]  = bswap_32(*(u32 *)(block + 8));
    schedule[3]  = bswap_32(*(u32 *)(block + 12));
    schedule[4]  = bswap_32(*(u32 *)(block + 16));
    schedule[5]  = bswap_32(*(u32 *)(block + 20));
    schedule[6]  = bswap_32(*(u32 *)(block + 24));
    schedule[7]  = bswap_32(*(u32 *)(block + 28));
    schedule[8]  = bswap_32(*(u32 *)(block + 32));
    schedule[9]  = bswap_32(*(u32 *)(block + 36));
    schedule[10] = bswap_32(*(u32 *)(block + 40));
    schedule[11] = bswap_32(*(u32 *)(block + 44));
    schedule[12] = bswap_32(*(u32 *)(block + 48));
    schedule[13] = bswap_32(*(u32 *)(block + 52));
    schedule[14] = bswap_32(*(u32 *)(block + 56));
    schedule[15] = bswap_32(*(u32 *)(block + 60));
    schedule[16] = sig1(schedule[14]) + schedule[9] + sig0(schedule[1]) + schedule[0];
    schedule[17] = sig1(schedule[15]) + schedule[10] + sig0(schedule[2]) + schedule[1];
    schedule[18] = sig1(schedule[16]) + schedule[11] + sig0(schedule[3]) + schedule[2];
    schedule[19] = sig1(schedule[17]) + schedule[12] + sig0(schedule[4]) + schedule[3];
    schedule[20] = sig1(schedule[18]) + schedule[13] + sig0(schedule[5]) + schedule[4];
    schedule[21] = sig1(schedule[19]) + schedule[14] + sig0(schedule[6]) + schedule[5];
    schedule[22] = sig1(schedule[20]) + schedule[15] + sig0(schedule[7]) + schedule[6];
    schedule[23] = sig1(schedule[21]) + schedule[16] + sig0(schedule[8]) + schedule[7];
    schedule[24] = sig1(schedule[22]) + schedule[17] + sig0(schedule[9]) + schedule[8];
    schedule[25] = sig1(schedule[23]) + schedule[18] + sig0(schedule[10]) + schedule[9];
    schedule[26] = sig1(schedule[24]) + schedule[19] + sig0(schedule[11]) + schedule[10];
    schedule[27] = sig1(schedule[25]) + schedule[20] + sig0(schedule[12]) + schedule[11];
    schedule[28] = sig1(schedule[26]) + schedule[21] + sig0(schedule[13]) + schedule[12];
    schedule[29] = sig1(schedule[27]) + schedule[22] + sig0(schedule[14]) + schedule[13];
    schedule[30] = sig1(schedule[28]) + schedule[23] + sig0(schedule[15]) + schedule[14];
    schedule[31] = sig1(schedule[29]) + schedule[24] + sig0(schedule[16]) + schedule[15];
    schedule[32] = sig1(schedule[30]) + schedule[25] + sig0(schedule[17]) + schedule[16];
    schedule[33] = sig1(schedule[31]) + schedule[26] + sig0(schedule[18]) + schedule[17];
    schedule[34] = sig1(schedule[32]) + schedule[27] + sig0(schedule[19]) + schedule[18];
    schedule[35] = sig1(schedule[33]) + schedule[28] + sig0(schedule[20]) + schedule[19];
    schedule[36] = sig1(schedule[34]) + schedule[29] + sig0(schedule[21]) + schedule[20];
    schedule[37] = sig1(schedule[35]) + schedule[30] + sig0(schedule[22]) + schedule[21];
    schedule[38] = sig1(schedule[36]) + schedule[31] + sig0(schedule[23]) + schedule[22];
    schedule[39] = sig1(schedule[37]) + schedule[32] + sig0(schedule[24]) + schedule[23];
    schedule[40] = sig1(schedule[38]) + schedule[33] + sig0(schedule[25]) + schedule[24];
    schedule[41] = sig1(schedule[39]) + schedule[34] + sig0(schedule[26]) + schedule[25];
    schedule[42] = sig1(schedule[40]) + schedule[35] + sig0(schedule[27]) + schedule[26];
    schedule[43] = sig1(schedule[41]) + schedule[36] + sig0(schedule[28]) + schedule[27];
    schedule[44] = sig1(schedule[42]) + schedule[37] + sig0(schedule[29]) + schedule[28];
    schedule[45] = sig1(schedule[43]) + schedule[38] + sig0(schedule[30]) + schedule[29];
    schedule[46] = sig1(schedule[44]) + schedule[39] + sig0(schedule[31]) + schedule[30];
    schedule[47] = sig1(schedule[45]) + schedule[40] + sig0(schedule[32]) + schedule[31];
    schedule[48] = sig1(schedule[46]) + schedule[41] + sig0(schedule[33]) + schedule[32];
    schedule[49] = sig1(schedule[47]) + schedule[42] + sig0(schedule[34]) + schedule[33];
    schedule[50] = sig1(schedule[48]) + schedule[43] + sig0(schedule[35]) + schedule[34];
    schedule[51] = sig1(schedule[49]) + schedule[44] + sig0(schedule[36]) + schedule[35];
    schedule[52] = sig1(schedule[50]) + schedule[45] + sig0(schedule[37]) + schedule[36];
    schedule[53] = sig1(schedule[51]) + schedule[46] + sig0(schedule[38]) + schedule[37];
    schedule[54] = sig1(schedule[52]) + schedule[47] + sig0(schedule[39]) + schedule[38];
    schedule[55] = sig1(schedule[53]) + schedule[48] + sig0(schedule[40]) + schedule[39];
    schedule[56] = sig1(schedule[54]) + schedule[49] + sig0(schedule[41]) + schedule[40];
    schedule[57] = sig1(schedule[55]) + schedule[50] + sig0(schedule[42]) + schedule[41];
    schedule[58] = sig1(schedule[56]) + schedule[51] + sig0(schedule[43]) + schedule[42];
    schedule[59] = sig1(schedule[57]) + schedule[52] + sig0(schedule[44]) + schedule[43];
    schedule[60] = sig1(schedule[58]) + schedule[53] + sig0(schedule[45]) + schedule[44];
    schedule[61] = sig1(schedule[59]) + schedule[54] + sig0(schedule[46]) + schedule[45];
    schedule[62] = sig1(schedule[60]) + schedule[55] + sig0(schedule[47]) + schedule[46];
    schedule[63] = sig1(schedule[61]) + schedule[56] + sig0(schedule[48]) + schedule[47];
}

static void process_message_schedule(u32 state[8], const u32 schedule[64])
{
    u32 a, b, c, d, e, f, g, h, T1, T2;

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];
    f = state[5];
    g = state[6];
    h = state[7];

    /* rounds. */
    for (i32 i = 0; i < 64; i++) {
        T1 = h + SIG1(e) + CH(e, f, g) + CONSTANTS[i] + schedule[i];
        T2 = SIG0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
    state[5] += f;
    state[6] += g;
    state[7] += h;
}

void sha256_init(SHA256 *ctx)
{
    ctx->length = 0;
    ctx->buffer_length = 0;

    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
}

void sha256_update(SHA256 *ctx, const u8 *data, u64 length)
{
    ctx->length += length;

    if (ctx->buffer_length + length < 64) {
        memcpy(ctx->buffer + ctx->buffer_length, data, length);
        ctx->buffer_length += length;
        return;
    }

    const u8 *block = data;
    u64 done = 0;
    u32 schedule[64];

    if (ctx->buffer_length > 0) {
        memcpy(ctx->buffer + ctx->buffer_length, data, 64 - ctx->buffer_length);
        block = ctx->buffer;
        done = -ctx->buffer_length;
    }

    do {
        prepare_message_schedule(schedule, block);
        process_message_schedule(ctx->state, schedule);
        done += 64;
        block = data + done;
    } while (done <= length - 64); 

    ctx->buffer_length = length - done;
    if (done < length) {
        memcpy(ctx->buffer, data + done, ctx->buffer_length);
    }
}

void sha256_complete(u8 digest[32], SHA256 *ctx)
{
    u64 bits_count = ctx->length * 8;
    u32 schedule[64];

    ctx->buffer[ctx->buffer_length++] = 0x80;

    if (ctx->buffer_length >= 56) {
        memset(ctx->buffer + ctx->buffer_length, 0, 64 - ctx->buffer_length);

        prepare_message_schedule(schedule, ctx->buffer);
        process_message_schedule(ctx->state, schedule);

        ctx->buffer_length = 0;
    }

    memset(ctx->buffer + ctx->buffer_length, 0, 56 - ctx->buffer_length);
    *(u64 *)(ctx->buffer + 56) = bswap_64(bits_count);
    
    prepare_message_schedule(schedule, ctx->buffer);
    process_message_schedule(ctx->state, schedule);

    *(u32 *)(digest + 0) = bswap_32(ctx->state[0]);
    *(u32 *)(digest + 4) = bswap_32(ctx->state[1]);
    *(u32 *)(digest + 8) = bswap_32(ctx->state[2]);
    *(u32 *)(digest + 12) = bswap_32(ctx->state[3]);
    *(u32 *)(digest + 16) = bswap_32(ctx->state[4]);
    *(u32 *)(digest + 20) = bswap_32(ctx->state[5]);
    *(u32 *)(digest + 24) = bswap_32(ctx->state[6]);
    *(u32 *)(digest + 28) = bswap_32(ctx->state[7]);

    ctx->buffer_length = 0;
}