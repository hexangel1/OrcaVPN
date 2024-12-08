#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <time.h>
#include <sys/types.h>

#include "encryption.h"
#include "aes.h"
#include "sha1.h"

#define memxor(a, b, len) do { \
	size_t i; \
	for (i = 0; i < (len); i++) \
		(a)[i] ^= (b)[i]; \
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
	unsigned int seed = time(NULL);
	srand(seed);
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
	return aes_key_schedule(cipher_key, keylen);
}

void encrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t offs, size = *len;
	size_t padded_size = ((size / AES_BLOCK_SIZE) + 1) * AES_BLOCK_SIZE;
	uint8_t padding = padded_size - size, *iv = data + padded_size;
	const aes_key *w = key;

	read_random(iv, AES_BLOCK_SIZE);
	memset(data + size, padding, padding);
	for (offs = 0; offs < padded_size; offs += AES_BLOCK_SIZE) {
		memxor(data + offs, iv, AES_BLOCK_SIZE);
		aes_cipher(data + offs, data + offs, w);
		iv = data + offs;
	}
	*len += padding + AES_BLOCK_SIZE;
}

void decrypt_packet(void *packet, size_t *len, const void *key)
{
	uint8_t *data = packet;
	size_t endoffs, offs, padded_size = *len;
	uint8_t padding, *iv;
	const aes_key *w = key;

	if (padded_size % AES_BLOCK_SIZE || padded_size / AES_BLOCK_SIZE < 2) {
		*len = 0;
		return;
	}
	padded_size -= AES_BLOCK_SIZE;
	for (endoffs = padded_size; endoffs > 0; endoffs -= AES_BLOCK_SIZE) {
		offs = endoffs - AES_BLOCK_SIZE;
		iv = data + (offs > 0 ? offs - AES_BLOCK_SIZE : padded_size);
		aes_inv_cipher(data + offs, data + offs, w);
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
