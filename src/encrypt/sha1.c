#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include "sha1.h"

#define K0 0x5a827999U
#define K1 0x6ed9eba1U
#define K2 0x8f1bbcdcU
#define K3 0xca62c1d6U

#define F0(b, c, d) (((b) & (c)) | ((~(b)) & (d)))
#define F1(b, c, d) (((b) ^ (c)) ^ (d))
#define F2(b, c, d) (((b) & (c)) | ((b) & (d)) | ((c) & (d)))
#define F3(b, c, d) (((b) ^ (c)) ^ (d))

#define ROL(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define H(n) (ctxt->h.b32[(n)])
#define W(n) (ctxt->m.b32[(n)])

#define PUTPAD(x) \
	do { \
		ctxt->m.b8[ctxt->count++] = (x); \
		ctxt->count &= 63; \
	} while (0)

#define TO_BIG_ENDIAN32(output, input, size) \
	do { \
		size_t i; \
		for (i = 0; i < (size); i += 4) { \
			uint8_t byte0 = input[i + 0]; \
			uint8_t byte1 = input[i + 1]; \
			output[i + 0] = input[i + 3]; \
			output[i + 1] = input[i + 2]; \
			output[i + 2] = byte1; \
			output[i + 3] = byte0; \
		} \
	} while (0)

static void sha1_step(struct sha1_ctxt *ctxt)
{
	uint32_t a, b, c, d, e, tmp;
	size_t t, s;

#ifndef WORDS_BIGENDIAN
	TO_BIG_ENDIAN32(ctxt->m.b8, ctxt->m.b8, 64);
#endif

	a = H(0);
	b = H(1);
	c = H(2);
	d = H(3);
	e = H(4);

	for (t = 0; t < 20; t++) {
		s = t & 0x0f;
		if (t >= 16)
			W(s) = ROL(W((s + 13) & 0x0f) ^ W((s + 8) & 0x0f) ^ W((s + 2) & 0x0f) ^ W(s), 1);
		tmp = ROL(a, 5) + F0(b, c, d) + e + W(s) + K0;
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 20; t < 40; t++) {
		s = t & 0x0f;
		W(s) = ROL(W((s + 13) & 0x0f) ^ W((s + 8) & 0x0f) ^ W((s + 2) & 0x0f) ^ W(s), 1);
		tmp = ROL(a, 5) + F1(b, c, d) + e + W(s) + K1;
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 40; t < 60; t++) {
		s = t & 0x0f;
		W(s) = ROL(W((s + 13) & 0x0f) ^ W((s + 8) & 0x0f) ^ W((s + 2) & 0x0f) ^ W(s), 1);
		tmp = ROL(a, 5) + F2(b, c, d) + e + W(s) + K2;
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}
	for (t = 60; t < 80; t++) {
		s = t & 0x0f;
		W(s) = ROL(W((s + 13) & 0x0f) ^ W((s + 8) & 0x0f) ^ W((s + 2) & 0x0f) ^ W(s), 1);
		tmp = ROL(a, 5) + F3(b, c, d) + e + W(s) + K3;
		e = d;
		d = c;
		c = ROL(b, 30);
		b = a;
		a = tmp;
	}

	H(0) = H(0) + a;
	H(1) = H(1) + b;
	H(2) = H(2) + c;
	H(3) = H(3) + d;
	H(4) = H(4) + e;

	memset(ctxt->m.b8, 0, 64);
}

static void sha1_pad(struct sha1_ctxt *ctxt)
{
	size_t padlen;

	PUTPAD(0x80);
	if (ctxt->count == 0)
		sha1_step(ctxt);

	padlen = 64 - ctxt->count;
	if (padlen < 8) {
		memset(&ctxt->m.b8[ctxt->count], 0, padlen);
		ctxt->count += padlen;
		ctxt->count &= 63;
		sha1_step(ctxt);
		padlen = 64;
	}
	memset(&ctxt->m.b8[ctxt->count], 0, padlen - 8);
	ctxt->count += (padlen - 8);
	ctxt->count &= 63;
#ifdef WORDS_BIGENDIAN
	PUTPAD(ctxt->c.b8[0]);
	PUTPAD(ctxt->c.b8[1]);
	PUTPAD(ctxt->c.b8[2]);
	PUTPAD(ctxt->c.b8[3]);
	PUTPAD(ctxt->c.b8[4]);
	PUTPAD(ctxt->c.b8[5]);
	PUTPAD(ctxt->c.b8[6]);
	PUTPAD(ctxt->c.b8[7]);
#else
	PUTPAD(ctxt->c.b8[7]);
	PUTPAD(ctxt->c.b8[6]);
	PUTPAD(ctxt->c.b8[5]);
	PUTPAD(ctxt->c.b8[4]);
	PUTPAD(ctxt->c.b8[3]);
	PUTPAD(ctxt->c.b8[2]);
	PUTPAD(ctxt->c.b8[1]);
	PUTPAD(ctxt->c.b8[0]);
#endif
	/* ctxt->count must be 0 here */
	sha1_step(ctxt);
}

void sha1_init(struct sha1_ctxt *ctxt)
{
	memset(ctxt, 0, sizeof(struct sha1_ctxt));
	H(0) = 0x67452301;
	H(1) = 0xefcdab89;
	H(2) = 0x98badcfe;
	H(3) = 0x10325476;
	H(4) = 0xc3d2e1f0;
}

void sha1_loop(struct sha1_ctxt *ctxt, const uint8_t *input, size_t len)
{
	size_t offs, written;

	for (offs = 0; offs < len; offs += written) {
		written = (64 < len - offs) ? 64 : len - offs;
		memcpy(ctxt->m.b8, input + offs, written);
		ctxt->c.b64 += written;
		ctxt->count += written;
		ctxt->count &= 63;
		if (ctxt->count == 0)
			sha1_step(ctxt);
	}
	ctxt->c.b64 <<= 3;
}

void sha1_result(struct sha1_ctxt *ctxt, uint8_t *digest)
{
	sha1_pad(ctxt);
#ifdef WORDS_BIGENDIAN
	memcpy(digest, ctxt->h.b8, 20);
#else
	TO_BIG_ENDIAN32(digest, ctxt->h.b8, 20);
#endif
}
