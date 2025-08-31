#ifndef POLY1305_H_SENTRY
#define POLY1305_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define POLY1305_MAC_LENGTH 16
#define POLY1305_MAC_HEX_LENGTH (POLY1305_MAC_LENGTH * 2 + 1)

struct poly1305_ctxt {
	uint8_t c[16];
	size_t  c_idx;
	uint32_t r[4];
	uint32_t pad[4];
	uint32_t h[5];
};

/* Init poly1305 context */
void poly1305_init(struct poly1305_ctxt *ctx, const uint8_t key[32]);
/* Evaluate poly1305 hash */
void poly1305_loop(struct poly1305_ctxt *ctx,
	const uint8_t *message, size_t message_size);
/* Write poly1305 hash result */
void poly1305_result(struct poly1305_ctxt *ctx, uint8_t mac[16]);

/* AUTH POLY1305 */
void auth_poly1305(uint8_t mac[16], const uint8_t auth_key[32],
	const uint8_t *ad, size_t ad_size,
	const uint8_t *cipher_text, size_t text_size);

#endif /* POLY1305_H_SENTRY */
