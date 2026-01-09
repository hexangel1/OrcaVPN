#include <string.h>

#include "chacha20.h"
#include "poly1305.h"
#include "endianess.h"
#include "memzero.h"

#define ROL32(x, n) (((x) << (n)) | ((x) >> (32 - (n))))

#define QUARTERROUND(a, b, c, d) do { \
	a += b;  d ^= a;  d = ROL32(d, 16); \
	c += d;  b ^= c;  b = ROL32(b, 12); \
	a += b;  d ^= a;  d = ROL32(d,  8); \
	c += d;  b ^= c;  b = ROL32(b,  7); \
} while (0)

static void chacha20_rounds(u32 out[16], const u32 in[16])
{
	u32 t0  = in[ 0]; u32 t1  = in[ 1]; u32 t2  = in[ 2]; u32 t3  = in[ 3];
	u32 t4  = in[ 4]; u32 t5  = in[ 5]; u32 t6  = in[ 6]; u32 t7  = in[ 7];
	u32 t8  = in[ 8]; u32 t9  = in[ 9]; u32 t10 = in[10]; u32 t11 = in[11];
	u32 t12 = in[12]; u32 t13 = in[13]; u32 t14 = in[14]; u32 t15 = in[15];

	int i;
	for (i = 0; i < 10; i++) {
		QUARTERROUND(t0, t4, t8 , t12);
		QUARTERROUND(t1, t5, t9 , t13);
		QUARTERROUND(t2, t6, t10, t14);
		QUARTERROUND(t3, t7, t11, t15);
		QUARTERROUND(t0, t5, t10, t15);
		QUARTERROUND(t1, t6, t11, t12);
		QUARTERROUND(t2, t7, t8 , t13);
		QUARTERROUND(t3, t4, t9 , t14);
	}
	out[ 0] = t0;   out[ 1] = t1;   out[ 2] = t2;   out[ 3] = t3;
	out[ 4] = t4;   out[ 5] = t5;   out[ 6] = t6;   out[ 7] = t7;
	out[ 8] = t8;   out[ 9] = t9;   out[10] = t10;  out[11] = t11;
	out[12] = t12;  out[13] = t13;  out[14] = t14;  out[15] = t15;
}

static u64 xor16(const u8 a[16], const u8 b[16])
{
	return (load64_le(a + 0) ^ load64_le(b + 0)) |
		(load64_le(a + 8) ^ load64_le(b + 8));
}

static const u8 *chacha20_constant = (const u8 *)"expand 32-byte k";

static void crypto_chacha20_h(u8 out[32], const u8 key[32], const u8 in[16])
{
	u32 block[16];
	load32_le_buf(block     , chacha20_constant, 4);
	load32_le_buf(block +  4, key              , 8);
	load32_le_buf(block + 12, in               , 4);

	chacha20_rounds(block, block);

	store32_le_buf(out     , block     , 4);
	store32_le_buf(out + 16, block + 12, 4);
	secure_memzero(block, sizeof(block));
}

static const u8 zeros[128];

u64 crypto_chacha20_djb(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[8], u64 ctr)
{
	u32 input[16];
	u32 pool[16];
	size_t i, j, nb_blocks = text_size >> 6;

	load32_le_buf(input     , chacha20_constant, 4);
	load32_le_buf(input +  4, key              , 8);
	load32_le_buf(input + 14, nonce            , 2);
	input[12] = (u32)(ctr);
	input[13] = (u32)(ctr >> 32);

	for (i = 0; i < nb_blocks; i++) {
		chacha20_rounds(pool, input);
		if (plain_text) {
			for (j = 0; j < 16; j++) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text, p ^
					load32_le(plain_text));
				cipher_text += 4;
				plain_text  += 4;
			}
		} else {
			for (j = 0; j < 16; j++) {
				u32 p = pool[j] + input[j];
				store32_le(cipher_text, p);
				cipher_text += 4;
			}
		}
		input[12]++;
		if (input[12] == 0)
			input[13]++;
	}
	text_size &= 63;

	if (text_size > 0) {
		u8 tmp[64];
		if (!plain_text)
			plain_text = zeros;
		chacha20_rounds(pool, input);
		for (i = 0; i < 16; i++)
			store32_le(tmp + i * 4, pool[i] + input[i]);
		for (i = 0; i < text_size; i++)
			cipher_text[i] = tmp[i] ^ plain_text[i];
		secure_memzero(tmp, sizeof(tmp));
	}
	ctr = input[12] + ((u64)input[13] << 32) + (text_size > 0);

	secure_memzero(pool, sizeof(pool));
	secure_memzero(input, sizeof(input));
	return ctr;
}

u32 crypto_chacha20_ietf(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[12], u32 ctr)
{
	u64 big_ctr = ctr + ((u64)load32_le(nonce) << 32);
	return (u32)crypto_chacha20_djb(cipher_text, plain_text, text_size,
		key, nonce + 4, big_ctr);
}

u64 crypto_chacha20_x(u8 *cipher_text,
	const u8 *plain_text, size_t text_size,
	const u8 key[32], const u8 nonce[24], u64 ctr)
{
	u8 sub_key[32];
	crypto_chacha20_h(sub_key, key, nonce);
	ctr = crypto_chacha20_djb(cipher_text, plain_text, text_size,
		sub_key, nonce + 16, ctr);
	secure_memzero(sub_key, sizeof(sub_key));
	return ctr;
}

void crypto_aead_init_djb(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[8])
{
	memcpy(ctx->key  , key  , 32);
	memcpy(ctx->nonce, nonce,  8);
	ctx->counter = 0;
}

void crypto_aead_init_ietf(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[12])
{
	memcpy(ctx->key  , key      , 32);
	memcpy(ctx->nonce, nonce + 4,  8);
	ctx->counter = (u64)load32_le(nonce) << 32;
}

void crypto_aead_init_x(crypto_aead_ctxt *ctx,
	const u8 key[32], const u8 nonce[24])
{
	crypto_chacha20_h(ctx->key, key, nonce);
	memcpy(ctx->nonce, nonce + 16, 8);
	ctx->counter = 0;
}

void crypto_aead_write(crypto_aead_ctxt *ctx, u8 *cipher_text, u8 mac[16],
	const u8 *ad, size_t ad_size, const u8 *plain_text, size_t text_size)
{
	u8 auth_key[64];
	crypto_chacha20_djb(auth_key, NULL, 64,
		ctx->key, ctx->nonce, ctx->counter);
	crypto_chacha20_djb(cipher_text, plain_text, text_size,
		ctx->key, ctx->nonce, ctx->counter + 1);
	auth_poly1305(mac, auth_key, ad, ad_size, cipher_text, text_size);
	memcpy(ctx->key, auth_key + 32, 32);
	secure_memzero(auth_key, sizeof(auth_key));
}

int crypto_aead_read(crypto_aead_ctxt *ctx, u8 *plain_text, const u8 mac[16],
	const u8 *ad, size_t ad_size, const u8 *cipher_text, size_t text_size)
{
	u8 auth_key[64];
	u8 real_mac[16];
	int mismatch;

	crypto_chacha20_djb(auth_key, NULL, 64,
		ctx->key, ctx->nonce, ctx->counter);
	auth_poly1305(real_mac, auth_key, ad, ad_size, cipher_text, text_size);
	mismatch = xor16(mac, real_mac) != 0;
	if (!mismatch) {
		crypto_chacha20_djb(plain_text, cipher_text, text_size,
			ctx->key, ctx->nonce, ctx->counter + 1);
		memcpy(ctx->key, auth_key + 32, 32);
	}
	secure_memzero(auth_key, sizeof(auth_key));
	secure_memzero(real_mac, sizeof(real_mac));
	return mismatch;
}
