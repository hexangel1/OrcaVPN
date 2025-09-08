#ifndef CHACHA20_H_SENTRY
#define CHACHA20_H_SENTRY

#include "fwi_types.h"

#define CHACHA20_DJB_NONCE_LENGTH   8
#define CHACHA20_IETF_NONCE_LENGTH 12
#define CHACHA20_X_NONCE_LENGTH    24

typedef struct crypto_aead_ctx_st {
	u64 counter;
	u8  key[32];
	u8 nonce[8];
} crypto_aead_ctxt;

/* chacha20 djb cipher */
u64 crypto_chacha20_djb(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[8], u64 ctr);
/* chacha20 ietf cipher */
u32 crypto_chacha20_ietf(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[12], u32 ctr);
/* chacha20 x cipher */
u64 crypto_chacha20_x(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[24], u64 ctr);

/* init chacha20 djb context */
void crypto_aead_init_djb(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[8]);
/* init chacha20 ietf context */
void crypto_aead_init_ietf(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[12]);
/* init chacha20 x context */
void crypto_aead_init_x(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[24]);

/* encrypt message with auth */
void crypto_aead_write(crypto_aead_ctxt *ctx, u8 *cipher_text, u8 mac[16],
	const u8 *ad, size_t ad_size, const u8 *plain_text, size_t text_size);
/* decrypt message with auth */
int crypto_aead_read(crypto_aead_ctxt *ctx, u8 *plain_text, const u8 mac[16],
	const u8 *ad, size_t ad_size, const u8 *cipher_text, size_t text_size);

#endif /* CHACHA20_H_SENTRY */
