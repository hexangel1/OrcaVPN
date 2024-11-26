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

#define URANDOM_BUFFER_SIZE 262144

static int urandom_fd = -1;
static size_t urandom_read_pos = 0;
static uint8_t *urandom_buffer = NULL;

static void fill_urandom_buffer(void)
{
	ssize_t res;
	size_t rc = 0;

	urandom_read_pos = 0;
	while (rc < URANDOM_BUFFER_SIZE) {
		res = read(urandom_fd, urandom_buffer + rc, URANDOM_BUFFER_SIZE - rc);
		if (res < 1) {
			if (res < 0 && errno == EINTR)
				continue;
			perror("fill_urandom_buffer");
			return;
		}
		rc += res;
	}
}

static void init_urandom_buffer(void)
{
	urandom_fd = open("/dev/urandom", O_RDONLY);
	if (urandom_fd == -1) {
		perror("init_urandom_buffer");
		exit(EXIT_FAILURE);
	}
	urandom_buffer = malloc(URANDOM_BUFFER_SIZE);
	memset(urandom_buffer, 0, URANDOM_BUFFER_SIZE);
	fill_urandom_buffer();
}

static void free_urandom_buffer(void)
{
	close(urandom_fd);
	free(urandom_buffer);
}

void init_encryption(void)
{
	unsigned int seed = time(NULL);
	srand(seed);
	init_urandom_buffer();
	atexit(free_urandom_buffer);
}

void read_random(void *buf, size_t n)
{
	size_t urandom_avail, len, rc;

	for (rc = 0; rc < n; rc += len, urandom_read_pos += len) {
		urandom_avail = URANDOM_BUFFER_SIZE - urandom_read_pos;
		if (!urandom_avail) {
			fill_urandom_buffer();
			urandom_avail = URANDOM_BUFFER_SIZE;
		}
		len = n - rc < urandom_avail ? n - rc : urandom_avail;
		memcpy((uint8_t *)buf + rc, urandom_buffer + urandom_read_pos, len);
	}
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
