#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include "encryption.h"
#include "aes.h"
#include "sha1.h"

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
	size_t size = *len;
	size_t offs, padded_size = ((size / 16) + 1) * 16;
	uint8_t padding = padded_size - size;
	read_random(data + size, padding);
	data[padded_size - 1] = padding;
	for (offs = 0; offs < padded_size; offs += 16)
		aes_cipher(data + offs, data + offs, key);
	*len += padding;
}

void decrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t offs, padded_size = *len;
	uint8_t padding;
	if (!padded_size || padded_size % 16 != 0) {
		*len = 0;
		return;
	}
	for (offs = 0; offs < padded_size; offs += 16)
		aes_inv_cipher(data + offs, data + offs, key);
	padding = data[padded_size - 1];
	if (!padding || padding > 16)
		*len = 0;
	else
		*len -= padding;
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
