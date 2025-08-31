#ifndef CHACHA20_H_SENTRY
#define CHACHA20_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define CHACHA20_DJB_NONCE_LENGTH   8
#define CHACHA20_IETF_NONCE_LENGTH 12
#define CHACHA20_X_NONCE_LENGTH    24

typedef struct crypto_aead_ctx_st {
	uint64_t counter;
	uint8_t  key[32];
	uint8_t nonce[8];
} crypto_aead_ctxt;

/* chacha20 djb cipher */
uint64_t crypto_chacha20_djb(uint8_t *cipher_text,
	const uint8_t *plain_text, size_t text_size,
	const uint8_t key[32], const uint8_t nonce[8], uint64_t ctr);
/* chacha20 ietf cipher */
uint32_t crypto_chacha20_ietf(uint8_t *cipher_text,
	const uint8_t *plain_text, size_t text_size,
	const uint8_t key[32], const uint8_t nonce[12], uint32_t ctr);
/* chacha20 x cipher */
uint64_t crypto_chacha20_x(uint8_t *cipher_text,
	const uint8_t *plain_text, size_t text_size,
	const uint8_t key[32], const uint8_t nonce[24], uint64_t ctr);

/* init chacha20 djb context */
void crypto_aead_init_djb(crypto_aead_ctxt *ctx,
	const uint8_t key[32], const uint8_t nonce[8]);
/* init chacha20 ietf context */
void crypto_aead_init_ietf(crypto_aead_ctxt *ctx,
	const uint8_t key[32], const uint8_t nonce[12]);
/* init chacha20 x context */
void crypto_aead_init_x(crypto_aead_ctxt *ctx,
	const uint8_t key[32], const uint8_t nonce[24]);

/* encrypt message with auth */
void crypto_aead_write(crypto_aead_ctxt *ctx,
	uint8_t *cipher_text, uint8_t mac[16],
	const uint8_t *ad, size_t ad_size,
	const uint8_t *plain_text, size_t text_size);
/* decrypt message with auth */
int crypto_aead_read(crypto_aead_ctxt *ctx,
	uint8_t *plain_text, const uint8_t mac[16],
	const uint8_t *ad, size_t ad_size,
	const uint8_t *cipher_text, size_t text_size);

#endif /* CHACHA20_H_SENTRY */
