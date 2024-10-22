#ifndef SHA256_H_
#define SHA256_H_

#include <typedefs.h>

typedef struct _SHA256
{
    u64 length;
    u64 buffer_length;
    u8 buffer[64];
    u32 state[8];
} SHA256;

void sha256_init(SHA256 *ctx);

void sha256_update(SHA256 *ctx, const u8 *data, u64 lenght);

void sha256_complete(u8 digest[32], SHA256 *ctx);

#endif