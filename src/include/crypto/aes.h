#ifndef AES_H_
#define AES_H_

#include <stddef.h>
#include <typedefs.h>

#define AES_BLOCK_SIZE 16

typedef struct {
    u8 number_of_rounds;
    u8 number_of_words; /* number of 32-bit words in cipher key */
    u8 iv[AES_BLOCK_SIZE];
    u32 *key_schedule;
    u8 state[AES_BLOCK_SIZE];
} AES;

void aes_init(AES *ctx, const u8 *key, u64 size);

void aes_init_with_iv(AES *ctx, const u8 *IV, const u8 *key, u64 size);

void aes_cbc_encode(u8 cipher_text[AES_BLOCK_SIZE], const u8 plain_text[AES_BLOCK_SIZE], AES *ctx);

void aes_cbc_decode(u8 plain_text[AES_BLOCK_SIZE], const u8 cipher_text[AES_BLOCK_SIZE], AES *ctx);

void aes_ecb_encode(u8 cipher_text[AES_BLOCK_SIZE], const u8 plain_text[AES_BLOCK_SIZE], AES *ctx);

void aes_ecb_decode(u8 plain_text[AES_BLOCK_SIZE], const u8 cipher_text[AES_BLOCK_SIZE], AES *ctx);

void aes_free(AES *ctx);

#endif