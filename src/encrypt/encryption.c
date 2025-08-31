#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "encryption.h"
#include "chacha20.h"
#include "poly1305.h"
#include "aes.h"
#include "sha1.h"
#include "memzero.h"

struct crypto_key_st {
	uint8_t key[32];
	int keylen;
	crypto_key_type cipher;
	aes_key expanded_ekey;
	aes_key expanded_dkey;
};

/* AES HMAC-SHA1 */

static crypto_key *init_aes_hmac_sha1(const void *cipher_key, int keylen)
{
	crypto_key *crkey;
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return NULL;
	crkey = malloc(sizeof(crypto_key));
	memset(crkey, 0, sizeof(crypto_key));
	memcpy(crkey->key, cipher_key, keylen);
	crkey->keylen = keylen;
	crkey->cipher = aes_hmac_sha1;
	aes_set_encrypt_key(cipher_key, keylen * 8, &crkey->expanded_ekey);
	aes_set_decrypt_key(cipher_key, keylen * 8, &crkey->expanded_dkey);
	return crkey;
}

#define xor_with_iv(block, iv) do { \
	uint8_t i; \
	for (i = 0; i < AES_BLOCK_SIZE; i++) \
		(block)[i] ^= (iv)[i]; \
} while (0)

static void
encrypt_aes_hmac_sha1(void *mesg, size_t *len, const crypto_key *crkey)
{
	uint8_t *data = mesg;
	size_t offs, size = *len;
	size_t padded_size = ((size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	size_t message_len = padded_size + AES_BLOCK_SIZE;
	uint8_t padding = padded_size - size, *iv = data + padded_size;

	read_random(iv - padding, AES_BLOCK_SIZE + padding);
	data[padded_size - 1] = padding;
	for (offs = 0; offs < padded_size; offs += AES_BLOCK_SIZE) {
		uint8_t *aes_block = data + offs;
		xor_with_iv(aes_block, iv);
		aes_encrypt(aes_block, aes_block, &crkey->expanded_ekey);
		iv = aes_block;
	}
	hmac_sha1(data, message_len, crkey->key, crkey->keylen,
		data + message_len);
	*len += padding + AES_BLOCK_SIZE + SHA1_DIGEST_LENGTH;
}

static int
decrypt_aes_hmac_sha1(void *mesg, size_t *len, const crypto_key *crkey)
{
	uint8_t *data = mesg;
	size_t endoffs, padded_size, total_len = *len;
	uint8_t padding, *iv, *hmac;
	uint8_t real_hmac[SHA1_DIGEST_LENGTH];

	if (total_len <= SHA1_DIGEST_LENGTH)
		return 1;

	padded_size = total_len - SHA1_DIGEST_LENGTH;
	hmac = data + padded_size;

	if (padded_size % AES_BLOCK_SIZE || padded_size / AES_BLOCK_SIZE < 2)
		return 1;

	hmac_sha1(data, padded_size, crkey->key, crkey->keylen, real_hmac);
	if (memcmp(real_hmac, hmac, sizeof(real_hmac)))
		return 1;

	padded_size -= AES_BLOCK_SIZE;
	for (endoffs = padded_size; endoffs > 0; endoffs -= AES_BLOCK_SIZE) {
		uint8_t *aes_block = data + endoffs - AES_BLOCK_SIZE;
		iv = aes_block > data ?
			aes_block - AES_BLOCK_SIZE : data + padded_size;
		aes_decrypt(aes_block, aes_block, &crkey->expanded_dkey);
		xor_with_iv(aes_block, iv);
	}
	padding = data[padded_size - 1];
	if (!padding || padding > AES_BLOCK_SIZE)
		return 1;

	*len = padded_size - padding;
	return 0;
}

/* XCHACHA20 POLY1305 */

static crypto_key *init_xchacha20_poly1305(const void *cipher_key, int keylen)
{
	crypto_key *crkey;
	if (keylen != 32)
		return NULL;
	crkey = malloc(sizeof(crypto_key));
	memset(crkey, 0, sizeof(crypto_key));
	memcpy(crkey->key, cipher_key, keylen);
	crkey->keylen = keylen;
	crkey->cipher = xchacha20_poly1305;
	return crkey;
}

static void
encrypt_xchacha20_poly1305(void *mesg, size_t *len, const crypto_key *crkey)
{
	size_t text_size = *len;
	uint8_t *data  = mesg;
	uint8_t *nonce = data  + text_size;
	uint8_t *mac   = nonce + CHACHA20_X_NONCE_LENGTH;
	crypto_aead_ctxt ctx;

	read_random(nonce, CHACHA20_X_NONCE_LENGTH);
	crypto_aead_init_x(&ctx, crkey->key, nonce);
	crypto_aead_write(&ctx, data, mac, NULL, 0, data, text_size);
	secure_memzero(&ctx, sizeof(ctx));
	*len += CHACHA20_X_NONCE_LENGTH + POLY1305_MAC_LENGTH;
}

static int
decrypt_xchacha20_poly1305(void *mesg, size_t *len, const crypto_key *crkey)
{
	size_t text_size, total_len = *len;
	uint8_t *data = mesg;
	uint8_t *nonce, *mac;
	crypto_aead_ctxt ctx;
	int result;

	if (total_len < CHACHA20_X_NONCE_LENGTH + POLY1305_MAC_LENGTH)
		return 1;

	text_size = total_len - CHACHA20_X_NONCE_LENGTH - POLY1305_MAC_LENGTH;

	nonce = data  + text_size;
	mac   = nonce + CHACHA20_X_NONCE_LENGTH;

	crypto_aead_init_x(&ctx, crkey->key, nonce);
	result = crypto_aead_read(&ctx, data, mac, NULL, 0, data, text_size);
	secure_memzero(&ctx, sizeof(ctx));
	if (!result)
		*len = text_size;
	return result;
}

static int get_urandom_fd(void)
{
	static int urandom_fd = -1;

	if (urandom_fd < 0) {
		urandom_fd = open("/dev/urandom", O_RDONLY);
		if (urandom_fd < 0) {
			perror("open urandom");
			return -1;
		}
	}
	return urandom_fd;
}

static void close_urandom_fd(void)
{
	close(get_urandom_fd());
}

void init_encryption(void)
{
	srand((unsigned int)time(NULL));
	if (get_urandom_fd() < 0)
		exit(EXIT_FAILURE);
	atexit(close_urandom_fd);
}

int read_random(void *buf, size_t len)
{
	ssize_t res;
	size_t rc = 0;
	int urandom_fd = get_urandom_fd();

	while (rc < len) {
		res = read(urandom_fd, ((char *)buf) + rc, len - rc);
		if (res < 1) {
			if (res < 0 && errno == EINTR)
				continue;
			return -1;
		}
		rc += res;
	}
	return 0;
}

crypto_key *crypto_key_create(const void *cipher_key, int keylen,
	crypto_key_type cipher)
{
	switch (cipher) {
	case aes_hmac_sha1:
		return init_aes_hmac_sha1(cipher_key, keylen);
	case xchacha20_poly1305:
		return init_xchacha20_poly1305(cipher_key, keylen);
	}
	return NULL;
}

void crypto_key_destroy(crypto_key *crkey)
{
	secure_memzero(crkey, sizeof(crypto_key));
	free(crkey);
}

crypto_key_type crypto_key_parse_cipher(const char *str)
{
	if (!str)
		return -1;
	if (!strcmp(str, "aes-hmac-sha1"))
		return aes_hmac_sha1;
	if (!strcmp(str, "xchacha20-poly1305"))
		return xchacha20_poly1305;
	return -1;
}

void encrypt_message(void *mesg, size_t *len, const crypto_key *crkey)
{
	switch (crkey->cipher) {
	case aes_hmac_sha1:
		encrypt_aes_hmac_sha1(mesg, len, crkey);
		break;
	case xchacha20_poly1305:
		encrypt_xchacha20_poly1305(mesg, len, crkey);
		break;
	}
}

int decrypt_message(void *mesg, size_t *len, const crypto_key *crkey)
{
	switch (crkey->cipher) {
	case aes_hmac_sha1:
		return decrypt_aes_hmac_sha1(mesg, len, crkey);
	case xchacha20_poly1305:
		return decrypt_xchacha20_poly1305(mesg, len, crkey);
	}
	return 1;
}
