#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "encryption.h"
#include "aes.h"
#include "sha1.h"

#define memxor(a, b, len) do { \
	size_t i; \
	for (i = 0; i < (len); i++) \
		(a)[i] ^= (b)[i]; \
} while (0)

static int generate_rand(int min, int max)
{
	return min + (int)((double)rand() / (RAND_MAX + 1.0) * (max - min + 1));
}

void read_random(void *buf, size_t n)
{
	uint8_t *dst = buf;
	size_t i;

	for (i = 0; i < n; i++)
		dst[i] = generate_rand(0, 255);
}

void init_encryption(size_t key_size)
{
	unsigned int seed = time(NULL);
	srand(seed);
	aes_init(key_size);
}

void *get_expanded_key(const void *key)
{
	return aes_key_expansion(key, NULL);
}

void encrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t offs, size = *len;
	size_t padded_size = ((size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	uint8_t padding = padded_size - size, *iv = data + padded_size;

	read_random(iv, AES_BLOCK_SIZE);
	memset(data + size, padding, padding);
	for (offs = 0; offs < padded_size; offs += AES_BLOCK_SIZE) {
		memxor(data + offs, iv, AES_BLOCK_SIZE);
		aes_cipher(data + offs, data + offs, key);
		iv = data + offs;
	}
	*len += padding + AES_BLOCK_SIZE;
}

void decrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t endoffs, offs, padded_size = *len;
	uint8_t padding, *iv;

	if (padded_size % AES_BLOCK_SIZE || padded_size / AES_BLOCK_SIZE < 2) {
		*len = 0;
		return;
	}
	padded_size -= AES_BLOCK_SIZE;
	for (endoffs = padded_size; endoffs > 0; endoffs -= AES_BLOCK_SIZE) {
		offs = endoffs - AES_BLOCK_SIZE;
		iv = offs > 0 ? data + offs - AES_BLOCK_SIZE : data + padded_size;
		aes_inv_cipher(data + offs, data + offs, key);
		memxor(data + offs, iv, AES_BLOCK_SIZE);
	}
	padding = data[padded_size - 1];
	if (!padding || padding > AES_BLOCK_SIZE)
		*len = 0;
	else
		*len -= padding + AES_BLOCK_SIZE;
}

void sign_packet(void *packet, size_t *len)
{
	uint8_t *data = packet;
	size_t size = *len;
	struct sha1_ctxt ctxt;

	sha1_init(&ctxt);
	sha1_loop(&ctxt, data, size);
	sha1_result(&ctxt, data + size);
	*len += SHA1_DIGEST_LENGTH;
}

int check_signature(const void *packet, size_t *len)
{
	const uint8_t *data = packet;
	size_t size = *len;
	uint8_t digest[SHA1_DIGEST_LENGTH];
	struct sha1_ctxt ctxt;

	if (size <= SHA1_DIGEST_LENGTH)
		return 0;
	size -= SHA1_DIGEST_LENGTH;
	sha1_init(&ctxt);
	sha1_loop(&ctxt, data, size);
	sha1_result(&ctxt, digest);
	*len -= SHA1_DIGEST_LENGTH;
	return !memcmp(data + size, digest, sizeof(digest));
}
