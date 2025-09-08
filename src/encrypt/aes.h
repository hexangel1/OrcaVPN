#ifndef AES_H_SENTRY
#define AES_H_SENTRY

#include "fwi_types.h"

#define AES_BLOCK_SIZE 16
#define AES_MAX_ROUNDS 14

typedef struct aes_key_st {
	u32 round_keys[4 * (AES_MAX_ROUNDS + 1)];
	int nrounds;
} aes_key;

/* AES encrypt round keys generation */
int aes_set_encrypt_key(const u8 *cipher_key, int bits, aes_key *key);
/* AES decrypt round keys generation */
int aes_set_decrypt_key(const u8 *cipher_key, int bits, aes_key *key);

/* AES encrypt block operation */
void aes_encrypt(const u8 in[16], u8 out[16], const aes_key *key);
/* AES decrypt block operation */
void aes_decrypt(const u8 in[16], u8 out[16], const aes_key *key);

#endif /* AES_H_SENTRY */
