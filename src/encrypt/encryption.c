#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>

#include "encryption.h"
#include "aes.h"
#include "sha1.h"

#define ENCRYPT 0
#define DECRYPT 1

#define xor_with_iv(block, iv) do { \
	uint8_t i; \
	for (i = 0; i < AES_BLOCK_SIZE; i++) \
		(block)[i] ^= (iv)[i]; \
} while (0)

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

void *gen_encrypt_key(const void *cipher_key, unsigned char keylen)
{
	aes_key *keys;
	if (keylen != 16 && keylen != 24 && keylen != 32)
		return NULL;
	keys = malloc(sizeof(aes_key) * 2);
	aes_set_encrypt_key(cipher_key, keylen * 8, &keys[ENCRYPT]);
	aes_set_decrypt_key(cipher_key, keylen * 8, &keys[DECRYPT]);
	return keys;
}

void encrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t offs, size = *len;
	size_t padded_size = ((size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	uint8_t padding = padded_size - size, *iv = data + padded_size;
	const aes_key *w = key;

	read_random(iv - padding, AES_BLOCK_SIZE + padding);
	data[padded_size - 1] = padding;
	for (offs = 0; offs < padded_size; offs += AES_BLOCK_SIZE) {
		uint8_t *aes_block = data + offs;
		xor_with_iv(aes_block, iv);
		aes_encrypt(aes_block, aes_block, &w[ENCRYPT]);
		iv = aes_block;
	}
	*len += padding + AES_BLOCK_SIZE;
}

void decrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t endoffs, padded_size = *len;
	uint8_t padding, *iv;
	const aes_key *w = key;

	if (padded_size % AES_BLOCK_SIZE || padded_size / AES_BLOCK_SIZE < 2) {
		*len = 0;
		return;
	}
	padded_size -= AES_BLOCK_SIZE;
	for (endoffs = padded_size; endoffs > 0; endoffs -= AES_BLOCK_SIZE) {
		uint8_t *aes_block = data + endoffs - AES_BLOCK_SIZE;
		iv = aes_block > data ?
			aes_block - AES_BLOCK_SIZE : data + padded_size;
		aes_decrypt(aes_block, aes_block, &w[DECRYPT]);
		xor_with_iv(aes_block, iv);
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
