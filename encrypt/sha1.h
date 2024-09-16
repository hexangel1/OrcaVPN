#ifndef SHA1_H_SENTRY
#define SHA1_H_SENTRY

#include <stddef.h>
#include <stdint.h>

#define SHA1_DIGEST_LENGTH 20
#define SHA1_DIGEST_STRING_LENGTH (SHA1_DIGEST_LENGTH * 2 + 1)

struct sha1_ctxt {
	union {
		uint8_t	 b8[8];
		uint64_t b64;
	} c;
	union {
		uint8_t	 b8[64];
		uint32_t b32[16];
	} m;
	union {
		uint8_t	 b8[20];
		uint32_t b32[5];
	} h;
	uint8_t	count;
};

void sha1_init(struct sha1_ctxt *ctx);
void sha1_loop(struct sha1_ctxt *ctx, const uint8_t *input, size_t len);
void sha1_result(struct sha1_ctxt *ctx, uint8_t *digest);

#endif /* SHA1_H_SENTRY */
