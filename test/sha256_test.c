#include <crypto/sha256.h>
#include <stdio.h>

static void print_digest(u8 digest[32])
{
    static char hex[] = "0123456789abcdef";
    for (i32 i = 0; i < 32; i++) {
        printf("%c%c", hex[(digest[i] >> 4)], hex[(digest[i] & 0x0F)]);
    }
    printf("\n");
}

i32 main()
{
    SHA256 ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, (const u8 *)"FISH", 4);

    u8 output[32];
    sha256_complete(output, &ctx);
    print_digest(output);

    return 0;
}