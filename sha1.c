#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include "sha1.h"
#include "helper.h"

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

#define COUNT (ctxt->count)

#define PUTPAD(x) \
	do { \
		ctxt->m.b8[COUNT % 64] = (x); \
		COUNT++; \
		COUNT %= 64; \
		if (COUNT == 0) \
			sha1_step(ctxt); \
	} while (0)

static void sha1_step(struct sha1_ctxt *ctxt)
{
	uint32_t a, b, c, d, e, tmp;
	size_t t, s;

#ifndef WORDS_BIGENDIAN
	to_big_endian32(ctxt->m.b8, 64, ctxt->m.b8);
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
	size_t padstart, padlen;

	PUTPAD(0x80);

	padstart = COUNT % 64;
	padlen = 64 - padstart;
	if (padlen < 8) {
		memset(&ctxt->m.b8[padstart], 0, padlen);
		COUNT += padlen;
		COUNT %= 64;
		sha1_step(ctxt);
		padstart = 0;
		padlen = 64;
	}
	memset(&ctxt->m.b8[padstart], 0, padlen - 8);
	COUNT += (padlen - 8);
	COUNT %= 64;
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
	size_t gapstart, gaplen, off, written;

	for (off = 0; off < len; off += written) {
		gapstart = COUNT % 64;
		gaplen = 64 - gapstart;

		written = (gaplen < len - off) ? gaplen : len - off;
		memcpy(&ctxt->m.b8[gapstart], &input[off], written);
		ctxt->c.b64 += written * 8;
		COUNT += written;
		COUNT %= 64;
		if (COUNT == 0)
			sha1_step(ctxt);
	}
}

void sha1_result(struct sha1_ctxt *ctxt, uint8_t *digest)
{
	sha1_pad(ctxt);
#ifdef WORDS_BIGENDIAN
	memcpy(digest, ctxt->h.b8, 20);
#else
	to_big_endian32(ctxt->h.b8, 20, digest);
#endif
}
