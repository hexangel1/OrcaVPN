#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

#define PACKET_SIGNATURE_LEN 20

void init_encryption(void);

void read_random(void *buf, size_t n);

void *gen_encrypt_key(const void *cipher_key, unsigned char keylen);

void encrypt_packet(void *packet, size_t *len, const void *key);
void decrypt_packet(void *packet, size_t *len, const void *key);

void sign_packet(void *packet, size_t *len);
int check_signature(const void *packet, size_t *len);

#endif /* ENCRYPTION_H_SENTRY */
