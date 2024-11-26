#ifndef AES_H_SENTRY
#define AES_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16
#define AES_MAX_ROUNDS 14
#define AES_STATE_COLS 4

typedef struct aes_key_st {
	uint8_t round_keys[4 * AES_STATE_COLS * (AES_MAX_ROUNDS + 1)];
	uint8_t nrounds;
	uint8_t __unused_padding[3];
} aes_key;

/* Performs AES round keys generation */
aes_key *aes_key_schedule(const uint8_t *cipher_key, uint8_t keylen);
/* Performs AES cipher operation */
void aes_cipher(const uint8_t *in, uint8_t *out, const aes_key *w);
/* Performs AES inverse cipher operation */
void aes_inv_cipher(const uint8_t *in, uint8_t *out, const aes_key *w);

#endif /* AES_H_SENTRY */
