#include <string.h>

#include "sha1.h"
#include "endianess.h"
#include "memzero.h"

#define K0 0x5a827999U
#define K1 0x6ed9eba1U
#define K2 0x8f1bbcdcU
#define K3 0xca62c1d6U

#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d) (((b) ^ (c)) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) (((b) ^ (c)) ^ (d))

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define H(n) (ctx->h.b32[(n)])
#define W(n) (ctx->m.b32[(n)])

#define Wnext(s) ROL32(W(((s) + 13) & 0x0f) ^ W(((s) + 8) & 0x0f) ^ \
	W(((s) + 2) & 0x0f) ^ W(s), 1)

#define PUTPAD(x) \
	do { \
		ctx->m.b8[ctx->count++] = (x); \
		ctx->count &= 63; \
	} while (0)

#define TO_BIG_ENDIAN32(output, input, size) \
	do { \
		size_t i; \
		for (i = 0; i < (size); i += 4) { \
			u8 byte0 = input[i + 0]; \
			u8 byte1 = input[i + 1]; \
			output[i + 0] = input[i + 3]; \
			output[i + 1] = input[i + 2]; \
			output[i + 2] = byte1; \
			output[i + 3] = byte0; \
		} \
	} while (0)

static void sha1_step(struct sha1_ctxt *ctx)
{
	u32 a, b, c, d, e;
	u32 t, s, tmp;

#ifndef WORDS_BIGENDIAN
	TO_BIG_ENDIAN32(ctx->m.b8, ctx->m.b8, 64);
#endif

	a = H(0);
	b = H(1);
	c = H(2);
	d = H(3);
	e = H(4);

	for (t = 0; t < 20; t++) {
		s = t & 0x0f;
		if (t >= 16)
			W(s) = Wnext(s);
		tmp = ROL32(a, 5) + F0(b, c, d) + e + W(s) + K0;
		e = d;
		d = c;
		c = ROL32(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 20; t < 40; t++) {
		s = t & 0x0f;
		W(s) = Wnext(s);
		tmp = ROL32(a, 5) + F1(b, c, d) + e + W(s) + K1;
		e = d;
		d = c;
		c = ROL32(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 40; t < 60; t++) {
		s = t & 0x0f;
		W(s) = Wnext(s);
		tmp = ROL32(a, 5) + F2(b, c, d) + e + W(s) + K2;
		e = d;
		d = c;
		c = ROL32(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 60; t < 80; t++) {
		s = t & 0x0f;
		W(s) = Wnext(s);
		tmp = ROL32(a, 5) + F3(b, c, d) + e + W(s) + K3;
		e = d;
		d = c;
		c = ROL32(b, 30);
		b = a;
		a = tmp;
	}

	H(0) += a;
	H(1) += b;
	H(2) += c;
	H(3) += d;
	H(4) += e;
}

static void sha1_pad(struct sha1_ctxt *ctx)
{
	size_t padlen;

	PUTPAD(0x80);
	if (ctx->count == 0)
		sha1_step(ctx);

	padlen = 64 - ctx->count;
	if (padlen < 8) {
		memset(&ctx->m.b8[ctx->count], 0, padlen);
		ctx->count += padlen;
		ctx->count &= 63;
		sha1_step(ctx);
		padlen = 64;
	}
	memset(&ctx->m.b8[ctx->count], 0, padlen - 8);
	ctx->count += (padlen - 8);
	ctx->count &= 63;
#ifdef WORDS_BIGENDIAN
	PUTPAD(ctx->c.b8[0]);
	PUTPAD(ctx->c.b8[1]);
	PUTPAD(ctx->c.b8[2]);
	PUTPAD(ctx->c.b8[3]);
	PUTPAD(ctx->c.b8[4]);
	PUTPAD(ctx->c.b8[5]);
	PUTPAD(ctx->c.b8[6]);
	PUTPAD(ctx->c.b8[7]);
#else
	PUTPAD(ctx->c.b8[7]);
	PUTPAD(ctx->c.b8[6]);
	PUTPAD(ctx->c.b8[5]);
	PUTPAD(ctx->c.b8[4]);
	PUTPAD(ctx->c.b8[3]);
	PUTPAD(ctx->c.b8[2]);
	PUTPAD(ctx->c.b8[1]);
	PUTPAD(ctx->c.b8[0]);
#endif
	/* ctxt->count must be 0 here */
	sha1_step(ctx);
}

void sha1_init(struct sha1_ctxt *ctx)
{
	memset(ctx, 0, sizeof(struct sha1_ctxt));
	H(0) = 0x67452301;
	H(1) = 0xefcdab89;
	H(2) = 0x98badcfe;
	H(3) = 0x10325476;
	H(4) = 0xc3d2e1f0;
}

void sha1_loop(struct sha1_ctxt *ctx, const uint8_t *input, size_t len)
{
	size_t offs, written;

	for (offs = 0; offs < len; offs += written) {
		written = (64 < len - offs) ? 64 : len - offs;
		memcpy(ctx->m.b8, input + offs, written);
		ctx->c.b64 += written << 3;
		ctx->count += written;
		ctx->count &= 63;
		if (ctx->count == 0)
			sha1_step(ctx);
	}
}

void sha1_result(struct sha1_ctxt *ctx, uint8_t digest[20])
{
	sha1_pad(ctx);
#ifdef WORDS_BIGENDIAN
	memcpy(digest, ctx->h.b8, 20);
#else
	TO_BIG_ENDIAN32(digest, ctx->h.b8, 20);
#endif
	secure_memzero(ctx, sizeof(struct sha1_ctxt));
}

void hmac_sha1(const uint8_t *text, size_t text_len,
	const uint8_t *key, size_t key_len, uint8_t hmac[20])
{
	u8 k_ipad[SHA1_BLOCK_SIZE];
	u8 k_opad[SHA1_BLOCK_SIZE];
	u8 k_hash[SHA1_DIGEST_LENGTH];
	struct sha1_ctxt ctx;
	int i;

	if (key_len > SHA1_BLOCK_SIZE) {
		sha1_init(&ctx);
		sha1_loop(&ctx, key, key_len);
		sha1_result(&ctx, k_hash);
		key_len = SHA1_DIGEST_LENGTH;
		key = k_hash;
	}

	memset(k_ipad, 0, sizeof(k_ipad));
	memset(k_opad, 0, sizeof(k_opad));
	memcpy(k_ipad, key, key_len);
	memcpy(k_opad, key, key_len);
	for (i = 0; i < SHA1_BLOCK_SIZE; i++) {
		k_ipad[i] ^= 0x36;
		k_opad[i] ^= 0x5c;
	}

	/* inner */
	sha1_init(&ctx);
	sha1_loop(&ctx, k_ipad, SHA1_BLOCK_SIZE);
	sha1_loop(&ctx, text, text_len);
	sha1_result(&ctx, hmac);
	/* outer */
	sha1_init(&ctx);
	sha1_loop(&ctx, k_opad, SHA1_BLOCK_SIZE);
	sha1_loop(&ctx, hmac, SHA1_DIGEST_LENGTH);
	sha1_result(&ctx, hmac);
	/* cleanup */
	secure_memzero(k_ipad, sizeof(k_ipad));
	secure_memzero(k_opad, sizeof(k_opad));
	secure_memzero(k_hash, sizeof(k_hash));
}
