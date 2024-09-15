#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

void init_encryption(size_t key_size);
void *get_expanded_key(const void *key);

void encrypt_packet(void *packet, size_t *len, const void *key);
void decrypt_packet(void *packet, size_t *len, const void *key);

void sign_packet(void *packet, size_t *len);
int check_signature(const void *packet, size_t len);

#endif /* ENCRYPTION_H_SENTRY */
