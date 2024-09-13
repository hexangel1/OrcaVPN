#include <string.h>
#include "encryption.h"
#include "aes.h"
#include "sha1.h"

void init_encryption(size_t key_size)
{
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
	memset(data + size, 0, padding);
	data[padded_size - 1] = padding;
	for (offs = 0; offs < padded_size / 16; offs += 16)
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
	padding = data[padded_size - 1];
	for (offs = 0; offs < padded_size / 16; offs += 16)
		aes_inv_cipher(data + offs, data + offs, key);
	*len -= padding;
}

void sign_packet(void *packet, size_t *len, const void *salt)
{
	uint8_t *data = packet;
	size_t size = *len;
	struct sha1_ctxt ctxt;
	(void)salt;
	sha1_init(&ctxt);
	sha1_loop(&ctxt, data, size);
	sha1_result(&ctxt, data + size);
	*len += SHA1_DIGEST_LENGTH;
}

int check_signature(const void *packet, size_t len, const void *salt)
{
	const uint8_t *data = packet;
	size_t size = len - SHA1_DIGEST_LENGTH;
	uint8_t digest[SHA1_DIGEST_LENGTH];
	struct sha1_ctxt ctxt;
	(void)salt;
	if (size > len)
		return 0;
	sha1_init(&ctxt);
	sha1_loop(&ctxt, data, size);
	sha1_result(&ctxt, digest);
	return !memcmp(data + size, digest, SHA1_DIGEST_LENGTH);
}