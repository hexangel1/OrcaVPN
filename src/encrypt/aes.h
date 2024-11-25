#ifndef AES_H_SENTRY
#define AES_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define AES_BLOCK_SIZE 16

typedef struct aes_key_st {
	uint8_t *round_keys;
	uint8_t round_keys_len;
	uint8_t n_rounds;
} aes_key;

/* Performs AES round keys generation */
aes_key *aes_key_schedule(const uint8_t *key, uint8_t key_len);
/* Free AES round keys */
void aes_key_destroy(aes_key *w);
/* Performs AES cipher operation */
void aes_cipher(const uint8_t *in, uint8_t *out, const aes_key *w);
/* Performs AES inverse cipher operation */
void aes_inv_cipher(const uint8_t *in, uint8_t *out, const aes_key *w);

#endif /* AES_H_SENTRY */
