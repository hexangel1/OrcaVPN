#ifndef SHA1_H_SENTRY
#define SHA1_H_SENTRY

#include "fwi_types.h"

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20
#define SHA1_DIGEST_HEX_LENGTH (SHA1_DIGEST_LENGTH * 2 + 1)

struct sha1_ctxt {
	union sha1_bytes8 {
		u8  b8[8];
		u64 b64;
	} c;
	union sha1_bytes64 {
		u8  b8[64];
		u32 b32[16];
	} m;
	union sha1_bytes20 {
		u8  b8[20];
		u32 b32[5];
	} h;
	u8 count;
};

/* Init sha1 context */
void sha1_init(struct sha1_ctxt *ctx);
/* Evaluate sha1 hash */
void sha1_loop(struct sha1_ctxt *ctx, const u8 *input, size_t len);
/* Write sha1 hash result */
void sha1_result(struct sha1_ctxt *ctx, u8 digest[20]);

/* HMAC-SHA1 */
void hmac_sha1(const u8 *text, size_t text_len,
	const u8 *key, size_t key_len, u8 hmac[20]);

#endif /* SHA1_H_SENTRY */
