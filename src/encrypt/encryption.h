#ifndef ENCRYPTION_H_SENTRY
#define ENCRYPTION_H_SENTRY

#include <stddef.h>

#define PACKET_SIGNATURE_LEN 20

/* Init encryption module */
void init_encryption(void);

/* Read random bytes from /dev/urandom to buffer */
int read_random(void *buf, size_t len);

/* Generate encryption round keys */
void *gen_encrypt_key(const void *cipher_key, unsigned char keylen);

/* Encrypt packet */
void encrypt_packet(void *packet, size_t *len, const void *key);
/* Decrypt packet */
void decrypt_packet(void *packet, size_t *len, const void *key);

/* Append signature bytes to packet */
void sign_packet(void *packet, size_t *len);
/* Check and trim packet signature */
int check_signature(const void *packet, size_t *len);

#endif /* ENCRYPTION_H_SENTRY */
