#ifndef SHA1_H_SENTRY
#define SHA1_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define SHA1_BLOCK_SIZE 64
#define SHA1_DIGEST_LENGTH 20
#define SHA1_DIGEST_STRING_LENGTH (SHA1_DIGEST_LENGTH * 2 + 1)

struct sha1_ctxt {
	union sha1_bytes8 {
		uint8_t	 b8[8];
		uint64_t b64;
	} c;
	union sha1_bytes64 {
		uint8_t	 b8[64];
		uint32_t b32[16];
	} m;
	union sha1_bytes20 {
		uint8_t	 b8[20];
		uint32_t b32[5];
	} h;
	uint8_t	count;
};

/* Init sha1 context */
void sha1_init(struct sha1_ctxt *ctx);
/* Evaluate sha1 hash */
void sha1_loop(struct sha1_ctxt *ctx, const uint8_t *input, size_t len);
/* Write sha1 hash result */
void sha1_result(struct sha1_ctxt *ctx, uint8_t *digest);

/* HMAC-SHA1 */
void hmac_sha1(const uint8_t *text, size_t text_len,
	const uint8_t *key, size_t key_len, uint8_t hmac[20]);

#endif /* SHA1_H_SENTRY */
