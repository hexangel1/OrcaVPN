#ifndef AES_H_SENTRY
#define AES_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_MAX_ROUNDS 14

typedef struct aes_key_st {
	uint32_t round_keys[4 * (AES_MAX_ROUNDS + 1)];
	int nrounds;
} aes_key;

/* AES encrypt round keys generation */
int aes_set_encrypt_key(const uint8_t *cipher_key, int bits, aes_key *key);
/* AES decrypt round keys generation */
int aes_set_decrypt_key(const uint8_t *cipher_key, int bits, aes_key *key);

/* AES encrypt block operation */
void aes_encrypt(const uint8_t *in, uint8_t *out, const aes_key *key);
/* AES decrypt block operation */
void aes_decrypt(const uint8_t *in, uint8_t *out, const aes_key *key);

#endif /* AES_H_SENTRY */
