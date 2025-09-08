#ifndef POLY1305_H_SENTRY
#define POLY1305_H_SENTRY

#include "fwi_types.h"

#define POLY1305_MAC_LENGTH 16
#define POLY1305_MAC_HEX_LENGTH (POLY1305_MAC_LENGTH * 2 + 1)

struct poly1305_ctxt {
	u8 c[16];
	size_t c_idx;
	u32 r[4];
	u32 pad[4];
	u32 h[5];
};

/* Init poly1305 context */
void poly1305_init(struct poly1305_ctxt *ctx, const u8 key[32]);
/* Evaluate poly1305 hash */
void poly1305_loop(struct poly1305_ctxt *ctx,
	const u8 *message, size_t message_size);
/* Write poly1305 hash result */
void poly1305_result(struct poly1305_ctxt *ctx, u8 mac[16]);

/* AUTH POLY1305 */
void auth_poly1305(u8 mac[16], const u8 auth_key[32],
	const u8 *ad, size_t ad_size,
	const u8 *cipher_text, size_t text_size);

#endif /* POLY1305_H_SENTRY */
