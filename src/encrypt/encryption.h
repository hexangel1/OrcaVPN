#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

#define CIPHER_KEY_LEN 24
#define CIPHER_KEY_HEX_LEN 2 * CIPHER_KEY_LEN
#define PACKET_SIGNATURE_LEN 20

void init_encryption(void);

void read_random(void *buf, size_t n);
void *get_expanded_key(const void *key);

void encrypt_packet(void *packet, size_t *len, const void *key);
void decrypt_packet(void *packet, size_t *len, const void *key);

void sign_packet(void *packet, size_t *len);
int check_signature(const void *packet, size_t *len);

#endif /* ENCRYPTION_H_SENTRY */
