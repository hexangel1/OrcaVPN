#include <string.h>

#include "poly1305.h"
#include "endianess.h"
#include "memzero.h"

#define MIN(a, b) ((a) <= (b) ? (a) : (b))

static const u8 zeros[128];

static size_t gap(size_t x, size_t pow_2)
{
	return (~x + 1) & (pow_2 - 1);
}

static void poly_blocks(struct poly1305_ctxt *ctx, const u8 *in,
	size_t nb_blocks, unsigned end)
{
	const u32 r0 = ctx->r[0];
	const u32 r1 = ctx->r[1];
	const u32 r2 = ctx->r[2];
	const u32 r3 = ctx->r[3];
	const u32 rr0 = (r0 >> 2) * 5;
	const u32 rr1 = (r1 >> 2) + r1;
	const u32 rr2 = (r2 >> 2) + r2;
	const u32 rr3 = (r3 >> 2) + r3;
	const u32 rr4 = r0 & 3;
	u32 h0 = ctx->h[0];
	u32 h1 = ctx->h[1];
	u32 h2 = ctx->h[2];
	u32 h3 = ctx->h[3];
	u32 h4 = ctx->h[4];

	size_t i;
	for (i = 0; i < nb_blocks; i++) {
		u64 s0, s1, s2, s3;
		u64 x0, x1, x2, x3;
		u64 u0, u1, u2, u3;
		u32 s4, x4, u4, u5;

		s0 = (u64)h0 + load32_le(in);  in += 4;
		s1 = (u64)h1 + load32_le(in);  in += 4;
		s2 = (u64)h2 + load32_le(in);  in += 4;
		s3 = (u64)h3 + load32_le(in);  in += 4;
		s4 =      h4 + end;

		x0 = s0*r0+ s1*rr3+ s2*rr2+ s3*rr1+ s4*rr0;
		x1 = s0*r1+ s1*r0 + s2*rr3+ s3*rr2+ s4*rr1;
		x2 = s0*r2+ s1*r1 + s2*r0 + s3*rr3+ s4*rr2;
		x3 = s0*r3+ s1*r2 + s2*r1 + s3*r0 + s4*rr3;
		x4 =                                s4*rr4;

		u5 = x4 + (x3 >> 32);
		u0 = (u5 >>  2) * 5 + (x0 & 0xffffffff);
		u1 = (u0 >> 32)     + (x1 & 0xffffffff) + (x0 >> 32);
		u2 = (u1 >> 32)     + (x2 & 0xffffffff) + (x1 >> 32);
		u3 = (u2 >> 32)     + (x3 & 0xffffffff) + (x2 >> 32);
		u4 = (u3 >> 32)     + (u5 & 3);

		h0 = u0 & 0xffffffff;
		h1 = u1 & 0xffffffff;
		h2 = u2 & 0xffffffff;
		h3 = u3 & 0xffffffff;
		h4 = u4;
	}
	ctx->h[0] = h0;
	ctx->h[1] = h1;
	ctx->h[2] = h2;
	ctx->h[3] = h3;
	ctx->h[4] = h4;
}

void poly1305_init(struct poly1305_ctxt *ctx, const u8 key[32])
{
	memset(ctx->h, 0, sizeof(ctx->h));
	ctx->c_idx = 0;
	load32_le_buf(ctx->r  , key   , 4);
	load32_le_buf(ctx->pad, key+16, 4);
	ctx->r[0] &= 0x0fffffff;
	ctx->r[1] &= 0x0ffffffc;
	ctx->r[2] &= 0x0ffffffc;
	ctx->r[3] &= 0x0ffffffc;
}

void poly1305_loop(struct poly1305_ctxt *ctx,
	const u8 *message, size_t message_size)
{
	size_t i, aligned, nb_blocks;

	if (message_size == 0)
		return;

	aligned = MIN(gap(ctx->c_idx, 16), message_size);
	for (i = 0; i < aligned; i++) {
		ctx->c[ctx->c_idx] = *message;
		ctx->c_idx++;
		message++;
		message_size--;
	}

	if (ctx->c_idx == 16) {
		poly_blocks(ctx, ctx->c, 1, 1);
		ctx->c_idx = 0;
	}

	nb_blocks = message_size >> 4;
	poly_blocks(ctx, message, nb_blocks, 1);
	message      += nb_blocks << 4;
	message_size &= 15;

	for (i = 0; i < message_size; i++)  {
		ctx->c[ctx->c_idx] = message[i];
		ctx->c_idx++;
	}
}

void poly1305_result(struct poly1305_ctxt *ctx, u8 mac[16])
{
	u64 c = 5;
	int i;

	if (ctx->c_idx != 0) {
		memset(ctx->c + ctx->c_idx, 0, 16 - ctx->c_idx);
		ctx->c[ctx->c_idx] = 1;
		poly_blocks(ctx, ctx->c, 1, 0);
	}

	for (i = 0; i < 4; i++) {
		c += ctx->h[i];
		c >>= 32;
	}
	c += ctx->h[4];
	c = (c >> 2) * 5;

	for (i = 0; i < 4; i++) {
		c += (u64)ctx->h[i] + ctx->pad[i];
		store32_le(mac + i * 4, (u32)c);
		c = c >> 32;
	}
	secure_memzero(ctx, sizeof(struct poly1305_ctxt));
}

void auth_poly1305(u8 mac[16], const u8 auth_key[32],
	const u8 *ad, size_t ad_size,
	const u8 *cipher_text, size_t text_size)
{
	struct poly1305_ctxt poly_ctx;
	u8 sizes[16];

	store64_le(sizes + 0, ad_size);
	store64_le(sizes + 8, text_size);

	poly1305_init(&poly_ctx, auth_key);
	poly1305_loop(&poly_ctx, ad         , ad_size);
	poly1305_loop(&poly_ctx, zeros      , gap(ad_size, 16));
	poly1305_loop(&poly_ctx, cipher_text, text_size);
	poly1305_loop(&poly_ctx, zeros      , gap(text_size, 16));
	poly1305_loop(&poly_ctx, sizes      , 16);
	poly1305_result(&poly_ctx, mac);
}
